//! An NVMe driver, serving the `block` interface
//! (`superior_objects::interfaces::block`).
//!
//! A class driver: it opens the first PCI function of class 01:08:02 (mass
//! storage, non-volatile memory, NVM Express), whoever made it. Like the
//! virtio driver it holds only what the manifest gives it: the PCI bus
//! server, its service endpoint, a notification for the interrupt and a
//! little memory for DMA pages. The device's IOMMU domain arrives with the
//! open, so the controller reaches only its queues, the identify page and,
//! while a request is in flight, the caller's frame, which the caller lends
//! with the call and the driver deletes before replying.
//!
//! On start (and so after every restart) it disables the controller, sets
//! up the admin queues, enables it, identifies the controller and
//! namespace 1, and creates one I/O queue pair whose completions raise
//! MSI-X vector 0. Requests are served one at a time, each a single
//! command with one PRP entry (a request is at most one page).
//!
//! Slots: 0 the bus server, 1 the `block` endpoint (receive), 2 a
//! notification, 3 untyped memory (32 KiB). `arg 1` turns on
//! fault-injection operations for tests: a crash, and a read aimed at
//! memory outside the domain.

#![no_std]
#![no_main]

use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_address, dma_barrier, io_map};
use superior_objects::abi::{CapTransfer, Syscall};
use superior_objects::interfaces::{Status, block};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const MSI: u64 = 4;
const DOMAIN: u64 = 5;
const ADMIN_SQ: u64 = 6;
const ADMIN_CQ: u64 = 7;
const IO_SQ: u64 = 8;
const IO_CQ: u64 = 9;
const IDENTIFY: u64 = 10;
/// A page of the driver's own, never mapped for DMA (fault injection).
const CANARY: u64 = 11;
/// Where a caller's frame arrives.
const BUFFER: u64 = 12;
const BAR_SLOTS: u64 = 16;
const MAX_BAR_PAGES: u64 = 16;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const CANARY_VA: u64 = DMA_VA + 0x10_0000;

/// Fault injection (with `arg 1`): crash on receipt.
const OP_CRASH: u64 = 0xdead;
/// Fault injection: program the controller to DMA into a page outside its
/// domain, reply whether the page was touched, then crash (the controller
/// may be wedged), so the driver restarts on a freshly reset one.
const OP_STRAY: u64 = 0x57a7;
const CANARY_WORD: u64 = 0xcafe_f00d_cafe_f00d;

/// PCI class 01 (mass storage), subclass 08 (NVM), interface 02 (NVMe).
const CLASS: u32 = 0x01_08_02;
const CAP_MSIX: u8 = 0x11;

// Controller registers (NVMe base specification, 3.1).
const CAP: u64 = 0x00;
const CC: u64 = 0x14;
const CSTS: u64 = 0x1c;
const AQA: u64 = 0x24;
const ASQ: u64 = 0x28;
const ACQ: u64 = 0x30;
const DOORBELLS: u64 = 0x1000;

const CC_EN: u32 = 1;
/// I/O submission entries of 2^6 bytes, completion entries of 2^4.
const CC_IOSQES: u32 = 6 << 16;
const CC_IOCQES: u32 = 4 << 20;
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 2;

// Admin commands.
const CREATE_IO_SQ: u8 = 0x01;
const CREATE_IO_CQ: u8 = 0x05;
const IDENTIFY_CMD: u8 = 0x06;
const SET_FEATURES: u8 = 0x09;
const FEATURE_QUEUES: u32 = 0x07;
// NVM commands.
const FLUSH: u8 = 0x00;
const WRITE: u8 = 0x01;
const READ: u8 = 0x02;

/// Entries in each queue (admin and I/O): the driver has one command
/// outstanding at a time, so a handful is plenty; each queue is one page.
const ENTRIES: u16 = 16;
const SQE: u64 = 64;
const CQE: u64 = 16;

/// Ticks (10 ms) a command may take before the driver gives up on it.
const COMMAND_TICKS: u64 = 500;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("nvme: {}", format_args!($($t)*))) };
}

/// A submission queue and its completion queue.
struct Queue {
    qid: u16,
    sq: DmaPage,
    cq: DmaPage,
    tail: u16,
    head: u16,
    /// The phase tag that marks a new completion entry.
    phase: bool,
    cid: u16,
}

impl Queue {
    fn new(qid: u16, sq: u64, cq: u64) -> Result<Queue, Failure> {
        let n = qid as u64 * 2;
        Ok(Queue {
            qid,
            sq: DmaPage::new(UNTYPED, sq, DMA_VA + n * 0x1000, DOMAIN)?,
            cq: DmaPage::new(UNTYPED, cq, DMA_VA + (n + 1) * 0x1000, DOMAIN)?,
            tail: 0,
            head: 0,
            phase: true,
            cid: 0,
        })
    }
}

struct Controller {
    regs: Mmio,
    /// Bytes between doorbells.
    stride: u64,
    admin: Queue,
    io: Queue,
    identify: DmaPage,
    /// Namespace 1: its size in logical blocks and their size (log2).
    blocks: u64,
    lba_shift: u32,
    /// The controller has a volatile write cache, emptied by a flush.
    cache: bool,
}

/// A command: opcode, namespace, the data's device address, CDW10..15.
struct Command {
    op: u8,
    nsid: u32,
    prp: u64,
    cdw: [u32; 6],
}

impl Command {
    fn admin(op: u8, prp: u64, cdw10: u32, cdw11: u32) -> Command {
        Command {
            op,
            nsid: 0,
            prp,
            cdw: [cdw10, cdw11, 0, 0, 0, 0],
        }
    }
}

/// How a command ended: its status field (0 for success), or never.
enum Outcome {
    Done(u16),
    TimedOut,
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// Maps the BAR pages a range needs, one slot each.
struct Bars {
    pci: Pci,
    mapped: [u16; 6],
    next_slot: u64,
}

impl Bars {
    fn va(bar: u64, off: u64) -> u64 {
        BAR_VA + bar * 0x10_0000 + off
    }

    fn map(&mut self, bar: u64, off: u64, len: u64) -> Result<u64, Failure> {
        if bar >= 6 || off + len > MAX_BAR_PAGES * 4096 {
            return Err(("a register block outside what the driver maps", bar));
        }
        for page in off / 4096..=(off + len.max(1) - 1) / 4096 {
            if self.mapped[bar as usize] & 1 << page != 0 {
                continue;
            }
            if self.next_slot == BAR_SLOTS + MAX_BAR_PAGES {
                return Err(("too many BAR pages", 0));
            }
            self.pci
                .map_bar_page(bar, page, self.next_slot, Self::va(bar, page * 4096))?;
            self.next_slot += 1;
            self.mapped[bar as usize] |= 1 << page;
        }
        Ok(Self::va(bar, off))
    }
}

/// Waits (yielding) until `CSTS.RDY` is `ready`, for at most the
/// controller's own timeout (`CAP.TO`, in 500 ms units).
fn wait_ready(regs: &Mmio, ready: bool, to: u64) -> Result<(), Failure> {
    let start = ticks();
    loop {
        let csts = regs.read32(CSTS);
        if csts & CSTS_CFS != 0 && ready {
            return Err(("the controller reported a fatal status", csts as u64));
        }
        if (csts & CSTS_RDY != 0) == ready {
            return Ok(());
        }
        if ticks() > start + to.max(1) * 50 {
            return Err((
                if ready {
                    "the controller did not become ready"
                } else {
                    "the controller did not stop"
                },
                csts as u64,
            ));
        }
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

fn start() -> Result<Controller, Failure> {
    let pci = Pci { slot: PCI };
    let (bdf, bars_present) = pci.open_class(CLASS, 0, DOMAIN)?;
    if bars_present & 1 == 0 {
        return Err(("no BAR 0", bars_present));
    }
    let mut bars = Bars {
        pci: Pci { slot: PCI },
        mapped: [0; 6],
        next_slot: BAR_SLOTS,
    };
    // The registers, and the doorbells of queues 0 and 1.
    let regs = Mmio {
        base: bars.map(0, 0, 0x1000)?,
    };
    let cap = regs.read64(CAP);
    let stride = 4u64 << (cap >> 32 & 0xf);
    let timeout = cap >> 24 & 0xff;
    let max_entries = (cap & 0xffff) + 1;
    let (mps_min, css) = (cap >> 48 & 0xf, cap >> 37 & 0xff);
    if mps_min != 0 || css & 1 == 0 || max_entries < ENTRIES as u64 {
        return Err(("a controller this driver cannot drive (CAP)", cap));
    }
    bars.map(0, DOORBELLS, 4 * stride)?;

    // Stop it (the bus server's reset may not have), then the admin queues.
    if regs.read32(CC) & CC_EN != 0 {
        regs.write32(CC, 0);
    }
    wait_ready(&regs, false, timeout)?;
    let admin = Queue::new(0, ADMIN_SQ, ADMIN_CQ)?;
    let n = (ENTRIES - 1) as u32;
    regs.write32(AQA, n << 16 | n);
    regs.write64(ASQ, admin.sq.dma);
    regs.write64(ACQ, admin.cq.dma);

    // One MSI-X vector: the admin queue's (always vector 0) and the I/O
    // queue's.
    let msix = pci.find_capability(CAP_MSIX, 0)?.ok_or(("no MSI-X", 0))?;
    let table = pci.config_read(msix + 4)? as u64;
    let entry = Mmio {
        base: bars.map(table & 7, table & !7, 16)?,
    };
    let (address, data) = pci.msi_vector(0, MSI, NOTIFY, DOMAIN)?;
    entry.write32(0, address as u32);
    entry.write32(4, (address >> 32) as u32);
    entry.write32(8, data as u32);
    entry.write32(12, 0); // unmasked
    pci.msix(true)?;
    pci.bus_master(true)?;

    // Enable: NVM command set, 4 KiB pages, round-robin arbitration.
    dma_barrier();
    regs.write32(CC, CC_IOSQES | CC_IOCQES | CC_EN);
    wait_ready(&regs, true, timeout)?;

    let mut c = Controller {
        regs,
        stride,
        io: Queue::new(1, IO_SQ, IO_CQ)?,
        admin,
        identify: DmaPage::new(UNTYPED, IDENTIFY, DMA_VA + 0x4000, DOMAIN)?,
        blocks: 0,
        lba_shift: 9,
        cache: false,
    };
    let id = c.identify.dma;
    // The controller: its model, and whether it has a write cache.
    c.admin_command(Command::admin(IDENTIFY_CMD, id, 1, 0))?;
    let page = c.identify_page();
    let model = core::str::from_utf8(&page[24..64]).unwrap_or("").trim_end();
    let model = model.trim_end_matches('\0').trim_end();
    c.cache = page[525] & 1 != 0;
    let mut name = [0u8; 40];
    let len = model.len().min(40);
    name[..len].copy_from_slice(&model.as_bytes()[..len]);
    // Namespace 1: its size and its logical block size.
    c.admin_command(Command {
        nsid: 1,
        ..Command::admin(IDENTIFY_CMD, id, 0, 0)
    })?;
    let page = c.identify_page();
    let word = |at: usize| u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
    c.blocks = word(0);
    let format = (page[26] & 0xf) as usize;
    c.lba_shift = page[128 + 4 * format + 2] as u32;
    if !(9..=12).contains(&c.lba_shift) || c.blocks == 0 {
        return Err((
            "namespace 1 has a block size this driver cannot use",
            c.lba_shift as u64,
        ));
    }
    // One I/O queue pair, completions on vector 0.
    c.admin_command(Command::admin(SET_FEATURES, 0, FEATURE_QUEUES, 0))?;
    let (cq, sq) = (c.io.cq.dma, c.io.sq.dma);
    c.admin_command(Command::admin(CREATE_IO_CQ, cq, n << 16 | 1, 1 << 1 | 1))?;
    c.admin_command(Command::admin(CREATE_IO_SQ, sq, n << 16 | 1, 1 << 16 | 1))?;
    say!(
        "ready: {:02x}:{:02x}.{} \"{}\", namespace 1: {} blocks of {} bytes{}, interrupts on MSI-X vector 0 (message data {data:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
        core::str::from_utf8(&name[..len]).unwrap_or(""),
        c.blocks,
        1u64 << c.lba_shift,
        if c.cache { ", write cache" } else { "" },
    );
    Ok(c)
}

impl Controller {
    fn identify_page(&self) -> &'static [u8] {
        dma_barrier();
        // SAFETY: the identify page is mapped at its va for good.
        unsafe { core::slice::from_raw_parts(self.identify.va as *const u8, 4096) }
    }

    fn doorbell(&self, qid: u16, completion: bool, value: u16) {
        let n = 2 * qid as u64 + completion as u64;
        self.regs.write32(DOORBELLS + n * self.stride, value as u32);
    }

    /// Puts `c` in queue `admin` or I/O's submission queue and rings its
    /// doorbell. Returns the command identifier.
    fn submit(&mut self, admin: bool, c: Command) -> u16 {
        let q = if admin { &mut self.admin } else { &mut self.io };
        q.cid = q.cid.wrapping_add(1);
        let cid = q.cid;
        let at = q.sq.va + q.tail as u64 * SQE;
        let mut words = [0u32; 16];
        words[0] = c.op as u32 | (cid as u32) << 16;
        words[1] = c.nsid;
        words[6] = c.prp as u32;
        words[7] = (c.prp >> 32) as u32;
        words[10..16].copy_from_slice(&c.cdw);
        for (i, w) in words.iter().enumerate() {
            // SAFETY: inside the submission queue page.
            unsafe { ((at + 4 * i as u64) as *mut u32).write_volatile(*w) };
        }
        q.tail = (q.tail + 1) % ENTRIES;
        let (qid, tail) = (q.qid, q.tail);
        dma_barrier();
        self.doorbell(qid, false, tail);
        cid
    }

    /// The next completion in the queue, if posted: (command identifier,
    /// status field).
    fn take(&mut self, admin: bool) -> Option<(u16, u16)> {
        let q = if admin { &mut self.admin } else { &mut self.io };
        dma_barrier();
        // SAFETY: inside the completion queue page.
        let dw3 = unsafe { ((q.cq.va + q.head as u64 * CQE + 12) as *const u32).read_volatile() };
        if (dw3 >> 16 & 1 != 0) != q.phase {
            return None;
        }
        q.head = (q.head + 1) % ENTRIES;
        if q.head == 0 {
            q.phase = !q.phase;
        }
        let (qid, head) = (q.qid, q.head);
        self.doorbell(qid, true, head);
        Some((dw3 as u16, (dw3 >> 17 & 0x7fff) as u16))
    }

    /// Runs `c` to completion. With `interrupts`, sleeps on the vector
    /// between looks; otherwise yields (fault injection's stray command:
    /// the controller may never finish it).
    fn run(&mut self, admin: bool, c: Command, interrupts: bool) -> Outcome {
        let cid = self.submit(admin, c);
        let start = ticks();
        loop {
            while let Some((id, status)) = self.take(admin) {
                if id == cid {
                    return Outcome::Done(status);
                }
            }
            if ticks() > start + COMMAND_TICKS {
                return Outcome::TimedOut;
            }
            if interrupts {
                syscall(Syscall::Wait, NOTIFY, [0; 4]);
                syscall(Syscall::IrqAck, MSI, [0; 4]);
            } else {
                syscall(Syscall::Yield, 0, [0; 4]);
            }
        }
    }

    fn admin_command(&mut self, c: Command) -> Result<(), Failure> {
        let op = c.op;
        match self.run(true, c, true) {
            Outcome::Done(0) => Ok(()),
            Outcome::Done(s) => Err(("an admin command failed", (op as u64) << 16 | s as u64)),
            Outcome::TimedOut => Err(("an admin command timed out", op as u64)),
        }
    }

    /// Reads or writes `count` 512-byte sectors from `sector` at the
    /// device address `buffer`; or flushes.
    fn io(&mut self, op: u8, sector: u64, count: u64, buffer: u64, interrupts: bool) -> Outcome {
        let per = self.lba_shift - 9;
        let (lba, blocks) = (sector >> per, count >> per);
        let c = Command {
            op,
            nsid: 1,
            prp: buffer,
            cdw: [
                lba as u32,
                (lba >> 32) as u32,
                if op == FLUSH { 0 } else { blocks as u32 - 1 },
                0,
                0,
                0,
            ],
        };
        self.run(false, c, interrupts)
    }

    fn status(&mut self, op: u8, sector: u64, count: u64, buffer: u64) -> Status {
        match self.io(op, sector, count, buffer, true) {
            Outcome::Done(0) => Status::Ok,
            _ => Status::DeviceError,
        }
    }

    /// Capacity in 512-byte sectors.
    fn sectors(&self) -> u64 {
        self.blocks << (self.lba_shift - 9)
    }

    /// Aims a read at a page of the driver's own that is not in the
    /// controller's domain. Returns (page untouched, command completed,
    /// its status field).
    fn stray(&mut self) -> Result<(bool, bool, u16, u64), Failure> {
        let made = syscall(
            Syscall::Retype,
            UNTYPED,
            [
                superior_objects::abi::ObjectType::Frame as u64,
                0,
                CANARY,
                0,
            ],
        );
        if made.status != 0 {
            return Err(("no memory for the canary page", made.status));
        }
        superior_driver::map(CANARY, CANARY_VA, true).map_err(|e| ("mapping the canary", e))?;
        // SAFETY: the canary page is mapped at CANARY_VA.
        let page = unsafe { core::slice::from_raw_parts_mut(CANARY_VA as *mut u64, 512) };
        page.fill(CANARY_WORD);
        dma_barrier();
        let pa = dma_address(CANARY)?;
        let count = 4096 >> 9;
        let outcome = self.io(READ, 0, count, pa, false);
        dma_barrier();
        let untouched = page.iter().all(|&w| w == CANARY_WORD);
        Ok(match outcome {
            Outcome::Done(s) => (untouched, true, s, pa),
            Outcome::TimedOut => (untouched, false, 0, pa),
        })
    }

    fn serve(&mut self, m: [u64; 4], lent: bool, faults: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            block::INFO if m[1] == block::VERSION => {
                [Status::Ok as u64, self.sectors(), block::SECTOR, 0]
            }
            block::FLUSH if self.cache => status(self.status(FLUSH, 0, 0, 0)),
            // No volatile write cache: every completed write is durable.
            block::FLUSH => status(Status::Ok),
            block::READ | block::WRITE => {
                let (sector, count) = (m[1], m[2]);
                let per = self.lba_shift - 9;
                let aligned = (sector | count) & ((1 << per) - 1) == 0;
                if !lent
                    || !aligned
                    || count == 0
                    || count > block::MAX_SECTORS
                    || sector
                        .checked_add(count)
                        .is_none_or(|end| end > self.sectors())
                {
                    return status(Status::Invalid);
                }
                // Reachable by the controller only until it is deleted,
                // before the reply; for a write, only for reading.
                let write = m[0] == block::WRITE;
                let op = if write { WRITE } else { READ };
                match io_map(BUFFER, DOMAIN, !write) {
                    Ok(buffer) => status(self.status(op, sector, count, buffer)),
                    Err(_) => status(Status::Invalid),
                }
            }
            OP_CRASH if faults => crash(),
            OP_STRAY if faults => match self.stray() {
                Ok((untouched, done, st, page)) => {
                    let (reported, report) = superior_driver::stray_reported(DOMAIN, page);
                    say!(
                        "stray DMA: page {}, command {} (status {st:#x}); {report}",
                        if untouched { "untouched" } else { "WRITTEN" },
                        if done { "completed" } else { "never completed" }
                    );
                    [Status::Ok as u64, (untouched && reported) as u64, done as u64, st as u64]
                }
                Err((what, code)) => {
                    say!("[fail] {what} ({code})");
                    status(Status::DeviceError)
                }
            },
            _ => status(Status::Invalid),
        }
    }
}

fn crash() -> ! {
    say!("crashing (fault injection)");
    // SAFETY: deliberately not: nothing is mapped here, so this faults.
    let v = unsafe { ((USER_BASE + 0x6000_0000) as *const u64).read_volatile() };
    say!("[fail] read {v:#x} from a hole");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let mut dev = match start() {
        Ok(d) => d,
        Err((what, code)) => {
            say!("[fail] {what} ({code:#x})");
            loop {
                syscall(Syscall::Yield, 0, [0; 4]);
            }
        }
    };
    let accept = CapTransfer {
        grant: None,
        accept: Some(BUFFER as u16),
    };
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        let lent = r.cap == Some(BUFFER as u16);
        let reply = dev.serve(r.msg, lent, arg == 1);
        if lent {
            // The caller's frame goes back (and out of the domain) before
            // the reply.
            syscall(Syscall::CapDelete, BUFFER, [0; 4]);
        }
        if arg == 1 && r.msg[0] == OP_STRAY {
            syscall(Syscall::Reply, 0, reply);
            crash();
        }
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, accept);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
