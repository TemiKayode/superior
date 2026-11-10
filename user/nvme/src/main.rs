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
//! up the admin queues, enables it, identifies the controller and every
//! active namespace, and creates up to [`QUEUES`] I/O queue pairs, as many
//! as the controller grants. Each pair has its own MSI-X vector and its own
//! thread: the first is the driver's main thread, the others are threads
//! it makes in its address space, each with a small CSpace of its own
//! holding the same slots. All of them receive on the one `block`
//! endpoint, so as many requests as there are queues are in flight at once,
//! each a single command with one PRP entry (a request is at most one
//! page).
//!
//! Namespaces are the interface's units: unit 0 is the first active
//! namespace, unit 1 the next, and so on.
//!
//! Slots: 0 the bus server, 1 the `block` endpoint (receive), 2 a
//! notification, 3 untyped memory (64 KiB). `arg 1` turns on
//! fault-injection and test operations: a crash, a read aimed at memory
//! outside the domain, and the queues' statistics.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_address, dma_barrier, io_map};
use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::interfaces::{Status, block};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

// Slots every serving thread has (the main thread's CSpace, and each
// queue thread's own, laid out the same).
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const MSI: u64 = 4;
const DOMAIN: u64 = 5;
/// A page of the driver's own, never mapped for DMA (fault injection).
const CANARY: u64 = 11;
/// Where a caller's frame arrives.
const BUFFER: u64 = 12;
// The main thread's alone.
const PCI: u64 = 0;
const UNTYPED: u64 = 3;
const ADMIN_SQ: u64 = 6;
const ADMIN_CQ: u64 = 7;
const IDENTIFY: u64 = 10;
const BAR_SLOTS: u64 = 16;
const MAX_BAR_PAGES: u64 = 16;
/// Queue `q`'s submission and completion pages; for queue threads (q >=
/// 1), their thread, notification, MSI vector and stack pages.
const fn q_slot(q: usize, what: u64) -> u64 {
    32 + 8 * q as u64 + what
}
const Q_SQ: u64 = 0;
const Q_CQ: u64 = 1;
const Q_THREAD: u64 = 2;
const Q_NOTIFY: u64 = 3;
const Q_MSI: u64 = 4;
const Q_STACK: u64 = 5;
const STACK_PAGES: u64 = 3;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const CANARY_VA: u64 = DMA_VA + 0x10_0000;
const STACK_VA: u64 = USER_BASE + 0x5800_0000;

/// Fault injection (with `arg 1`): crash on receipt.
const OP_CRASH: u64 = 0xdead;
/// Fault injection: program the controller to DMA into a page outside its
/// domain, reply whether the page was touched, then crash (the controller
/// may be wedged), so the driver restarts on a freshly reset one.
const OP_STRAY: u64 = 0x57a7;
/// Test operation: `[OP_QUEUES]`, reply `[Ok, I/O queues, most commands
/// ever in flight at once, mask of the queues that have run a command]`.
const OP_QUEUES: u64 = 0x9e5e;
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
/// Identify's CNS values: a namespace, the controller, the active
/// namespace IDs.
const CNS_NAMESPACE: u32 = 0;
const CNS_CONTROLLER: u32 = 1;
const CNS_ACTIVE: u32 = 2;
// NVM commands.
const FLUSH: u8 = 0x00;
const WRITE: u8 = 0x01;
const READ: u8 = 0x02;

/// I/O queue pairs (and threads) the driver asks for.
const QUEUES: usize = 2;
/// Namespaces it serves.
const MAX_NS: usize = 4;
/// Entries in each queue (admin and I/O): each thread has one command
/// outstanding at a time, so a handful is plenty; each queue is one page.
const ENTRIES: u16 = 16;
const SQE: u64 = 64;
const CQE: u64 = 16;

/// Ticks (10 ms) a command may take before the driver gives up on it.
const COMMAND_TICKS: u64 = 500;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("nvme: {}", format_args!($($t)*))) };
}

/// A submission queue and its completion queue, with the doorbells.
struct Queue {
    qid: u16,
    sq: DmaPage,
    cq: DmaPage,
    regs: Mmio,
    stride: u64,
    tail: u16,
    head: u16,
    /// The phase tag that marks a new completion entry.
    phase: bool,
    cid: u16,
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

/// How a command ended: its status field (0 for success) and completion
/// dword 0, or never.
enum Outcome {
    Done(u16, u32),
    TimedOut,
}

impl Queue {
    fn new(qid: u16, sq: u64, cq: u64, regs: Mmio, stride: u64) -> Result<Queue, Failure> {
        let n = qid as u64 * 2;
        Ok(Queue {
            qid,
            sq: DmaPage::new(UNTYPED, sq, DMA_VA + n * 0x1000, DOMAIN)?,
            cq: DmaPage::new(UNTYPED, cq, DMA_VA + (n + 1) * 0x1000, DOMAIN)?,
            regs,
            stride,
            tail: 0,
            head: 0,
            phase: true,
            cid: 0,
        })
    }

    fn doorbell(&self, completion: bool, value: u16) {
        let n = 2 * self.qid as u64 + completion as u64;
        self.regs.write32(DOORBELLS + n * self.stride, value as u32);
    }

    /// Puts `c` in the submission queue and rings its doorbell. Returns
    /// the command identifier.
    fn submit(&mut self, c: Command) -> u16 {
        self.cid = self.cid.wrapping_add(1);
        let cid = self.cid;
        let at = self.sq.va + self.tail as u64 * SQE;
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
        self.tail = (self.tail + 1) % ENTRIES;
        dma_barrier();
        self.doorbell(false, self.tail);
        cid
    }

    /// The next completion in the queue, if posted: (command identifier,
    /// status field, dword 0).
    fn take(&mut self) -> Option<(u16, u16, u32)> {
        dma_barrier();
        let entry = self.cq.va + self.head as u64 * CQE;
        // SAFETY: inside the completion queue page.
        let (dw0, dw3) = unsafe {
            (
                (entry as *const u32).read_volatile(),
                ((entry + 12) as *const u32).read_volatile(),
            )
        };
        if (dw3 >> 16 & 1 != 0) != self.phase {
            return None;
        }
        self.head = (self.head + 1) % ENTRIES;
        if self.head == 0 {
            self.phase = !self.phase;
        }
        self.doorbell(true, self.head);
        Some((dw3 as u16, (dw3 >> 17 & 0x7fff) as u16, dw0))
    }

    /// Runs `c` to completion. With `interrupts`, sleeps on the queue's
    /// vector between looks; otherwise yields (fault injection's stray
    /// command: the controller may never finish it).
    fn run(&mut self, c: Command, interrupts: bool) -> Outcome {
        let cid = self.submit(c);
        let start = ticks();
        if interrupts {
            // Wake up even if no interrupt ever comes.
            syscall(Syscall::TimerSignal, NOTIFY, [COMMAND_TICKS + 1, 0, 0, 0]);
        }
        loop {
            while let Some((id, status, dw0)) = self.take() {
                if id == cid {
                    if interrupts {
                        syscall(Syscall::TimerSignal, NOTIFY, [0; 4]);
                    }
                    return Outcome::Done(status, dw0);
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

    /// Runs an admin command; its completion dword 0 if it succeeded.
    fn admin(&mut self, c: Command) -> Result<u32, Failure> {
        let op = c.op;
        match self.run(c, true) {
            Outcome::Done(0, dw0) => Ok(dw0),
            Outcome::Done(s, _) => Err(("an admin command failed", (op as u64) << 16 | s as u64)),
            Outcome::TimedOut => Err(("an admin command timed out", op as u64)),
        }
    }
}

/// A namespace: its ID, size in logical blocks and their size (log2).
#[derive(Clone, Copy)]
struct Namespace {
    nsid: u32,
    blocks: u64,
    lba_shift: u32,
}

impl Namespace {
    /// Capacity in 512-byte sectors.
    fn sectors(&self) -> u64 {
        self.blocks << (self.lba_shift - 9)
    }
}

/// What every serving thread shares, fixed once the driver is up.
struct Shared {
    namespaces: [Option<Namespace>; MAX_NS],
    /// The controller has a volatile write cache, emptied by a flush.
    cache: bool,
    queues: usize,
    faults: bool,
}

static mut SHARED: Shared = Shared {
    namespaces: [None; MAX_NS],
    cache: false,
    queues: 0,
    faults: false,
};
/// Each I/O queue, used only by its own thread once the driver is up.
static mut IO: [Option<Queue>; QUEUES] = [const { None }; QUEUES];

/// Commands in flight across the queues now, the most ever, and how many
/// each queue has run.
/// Set (fault injection) once a serving thread has answered the stray-DMA
/// request and is about to crash: a request any other serving thread then
/// receives crashes it too, unserved, so the client's next request reaches
/// the restarted driver (or fails with `PeerRestarted` and is retried),
/// however the CPUs interleave the threads.
static CRASHING: AtomicBool = AtomicBool::new(false);
static IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static RUN: [AtomicU64; QUEUES] = [const { AtomicU64::new(0) }; QUEUES];

fn shared() -> &'static Shared {
    // SAFETY: written only by `start`, before any queue thread runs.
    unsafe { &*(&raw const SHARED) }
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

fn retype(ty: ObjectType, slot: u64) -> Result<(), Failure> {
    match syscall(Syscall::Retype, UNTYPED, [ty as u64, 0, slot, 0]).status {
        0 => Ok(()),
        e => Err(("out of memory", e)),
    }
}

fn identify_page(page: &DmaPage) -> &'static [u8] {
    dma_barrier();
    // SAFETY: the identify page is mapped at its va for good.
    unsafe { core::slice::from_raw_parts(page.va as *const u8, 4096) }
}

/// Brings the controller up and returns its admin queue, with the I/O
/// queues in `IO` and everything else in `SHARED`.
fn start(faults: bool) -> Result<(), Failure> {
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
    // The registers, and the doorbells of the admin and I/O queues.
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
    bars.map(0, DOORBELLS, 2 * (QUEUES as u64 + 1) * stride)?;

    // Stop it (the bus server's reset may not have), then the admin queues.
    if regs.read32(CC) & CC_EN != 0 {
        regs.write32(CC, 0);
    }
    wait_ready(&regs, false, timeout)?;
    let mut admin = Queue::new(0, ADMIN_SQ, ADMIN_CQ, regs, stride)?;
    let n = (ENTRIES - 1) as u32;
    regs.write32(AQA, n << 16 | n);
    regs.write64(ASQ, admin.sq.dma);
    regs.write64(ACQ, admin.cq.dma);

    // An MSI-X vector per I/O queue; vector 0 is also the admin queue's.
    let msix = pci.find_capability(CAP_MSIX, 0)?.ok_or(("no MSI-X", 0))?;
    let table = pci.config_read(msix + 4)? as u64;
    let table = bars.map(table & 7, table & !7, 16 * QUEUES as u64)?;
    let mut data0 = 0;
    for q in 0..QUEUES {
        let (irq, ntfn) = if q == 0 {
            (MSI, NOTIFY)
        } else {
            retype(ObjectType::Notification, q_slot(q, Q_NOTIFY))?;
            (q_slot(q, Q_MSI), q_slot(q, Q_NOTIFY))
        };
        let (address, data) = pci.msi_vector(q as u64, irq, ntfn, DOMAIN)?;
        let entry = Mmio {
            base: table + 16 * q as u64,
        };
        entry.write32(0, address as u32);
        entry.write32(4, (address >> 32) as u32);
        entry.write32(8, data as u32);
        entry.write32(12, 0); // unmasked
        if q == 0 {
            data0 = data;
        }
    }
    pci.msix(true)?;
    pci.bus_master(true)?;

    // Enable: NVM command set, 4 KiB pages, round-robin arbitration.
    dma_barrier();
    regs.write32(CC, CC_IOSQES | CC_IOCQES | CC_EN);
    wait_ready(&regs, true, timeout)?;

    let identify = DmaPage::new(UNTYPED, IDENTIFY, DMA_VA + 0xf_0000, DOMAIN)?;
    let id = identify.dma;
    // The controller: its model, and whether it has a write cache.
    admin.admin(Command::admin(IDENTIFY_CMD, id, CNS_CONTROLLER, 0))?;
    let page = identify_page(&identify);
    let mut name = [0u8; 40];
    name.copy_from_slice(&page[24..64]);
    let model = core::str::from_utf8(&name).unwrap_or("");
    let model = model.trim_end_matches(['\0', ' ']);
    let cache = page[525] & 1 != 0;

    // The active namespaces, each with its size and logical block size.
    admin.admin(Command::admin(IDENTIFY_CMD, id, CNS_ACTIVE, 0))?;
    let mut ids = [0u32; MAX_NS];
    for (i, nsid) in ids.iter_mut().enumerate() {
        *nsid = u32::from_le_bytes(identify_page(&identify)[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut namespaces = [None; MAX_NS];
    let mut count = 0;
    for nsid in ids.into_iter().take_while(|&n| n != 0) {
        admin.admin(Command {
            nsid,
            ..Command::admin(IDENTIFY_CMD, id, CNS_NAMESPACE, 0)
        })?;
        let page = identify_page(&identify);
        let blocks = u64::from_le_bytes(page[0..8].try_into().unwrap());
        let format = (page[26] & 0xf) as usize;
        let lba_shift = page[128 + 4 * format + 2] as u32;
        if !(9..=12).contains(&lba_shift) || blocks == 0 {
            say!("namespace {nsid}: a block size this driver cannot use (2^{lba_shift}); skipped");
            continue;
        }
        namespaces[count] = Some(Namespace {
            nsid,
            blocks,
            lba_shift,
        });
        count += 1;
    }
    if count == 0 {
        return Err(("no namespace this driver can use", 0));
    }

    // The I/O queues: as many as asked for and granted (0-based counts).
    let want = (QUEUES - 1) as u32;
    let granted = admin.admin(Command::admin(SET_FEATURES, 0, FEATURE_QUEUES, want << 16 | want))?;
    let queues = QUEUES.min(1 + (granted & 0xffff).min(granted >> 16) as usize);
    for q in 0..queues {
        let qid = q as u16 + 1;
        let io = Queue::new(qid, q_slot(q, Q_SQ), q_slot(q, Q_CQ), regs, stride)?;
        let (cq, sq) = (io.cq.dma, io.sq.dma);
        let (qid, vector) = (qid as u32, q as u32);
        // Completion queue `qid`: physically contiguous, interrupts on,
        // on vector `q`; its submission queue feeds it.
        admin.admin(Command::admin(CREATE_IO_CQ, cq, n << 16 | qid, vector << 16 | 1 << 1 | 1))?;
        admin.admin(Command::admin(CREATE_IO_SQ, sq, n << 16 | qid, qid << 16 | 1))?;
        // SAFETY: no queue thread runs yet.
        unsafe { (*(&raw mut IO))[q] = Some(io) };
    }
    // SAFETY: as above.
    unsafe {
        *(&raw mut SHARED) = Shared {
            namespaces,
            cache,
            queues,
            faults,
        }
    };
    if faults {
        // The fault-injection page, made now so every thread can use it.
        retype(ObjectType::Frame, CANARY)?;
        superior_driver::map(CANARY, CANARY_VA, true).map_err(|e| ("mapping the canary", e))?;
    }

    say!(
        "ready: {:02x}:{:02x}.{} \"{model}\"{}, {queues} I/O queues, interrupts on MSI-X vectors 0-{} (vector 0's message data {data0:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
        if cache { ", write cache" } else { "" },
        queues - 1,
    );
    for (unit, ns) in namespaces.iter().flatten().enumerate() {
        say!(
            "unit {unit}: namespace {}, {} blocks of {} bytes",
            ns.nsid,
            ns.blocks,
            1u64 << ns.lba_shift
        );
    }
    for q in 1..queues {
        spawn(q)?;
    }
    Ok(())
}

/// Starts queue `q`'s thread, with its own CSpace laid out like the main
/// thread's serving slots.
fn spawn(q: usize) -> Result<(), Failure> {
    let tcb = q_slot(q, Q_THREAD);
    retype(ObjectType::Thread, tcb)?;
    let stack = STACK_VA + 0x1_0000 * q as u64;
    for p in 0..STACK_PAGES {
        let slot = q_slot(q, Q_STACK) + p;
        retype(ObjectType::Frame, slot)?;
        superior_driver::map(slot, stack + 0x1000 * p, true).map_err(|e| ("mapping a stack page", e))?;
    }
    let mut copies = [
        (SERVICE, SERVICE),
        (DOMAIN, DOMAIN),
        (q_slot(q, Q_NOTIFY), NOTIFY),
        (q_slot(q, Q_MSI), MSI),
        (CANARY, CANARY),
    ];
    let n = if shared().faults { 5 } else { 4 };
    for (from, to) in &mut copies[..n] {
        let r = syscall(Syscall::ThreadCopyCap, tcb, [*from, *to, 0xff, 0]);
        if r.status != 0 {
            return Err(("giving a queue thread its capabilities", r.status));
        }
    }
    let entry = queue_thread as *const () as u64;
    let top = stack + 0x1000 * STACK_PAGES;
    // At the driver's own priority: the highest a thread it makes may have.
    let configured = (0..=255u64).rev().any(|prio| {
        syscall(Syscall::ThreadConfigure, tcb, [entry, top, q as u64, prio]).status == 0
    });
    if !configured || syscall(Syscall::ThreadResume, tcb, [0; 4]).status != 0 {
        return Err(("starting a queue thread", q as u64));
    }
    Ok(())
}

/// Serves `block` calls on I/O queue `q` until the driver dies.
fn serve_forever(q: usize) -> ! {
    // SAFETY: queue `q` is this thread's alone once the driver is up.
    let queue = unsafe { (*(&raw mut IO))[q].as_mut().unwrap() };
    let mut w = Worker { q, queue };
    let accept = CapTransfer {
        grant: None,
        accept: Some(BUFFER as u16),
    };
    let faults = shared().faults;
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        if CRASHING.load(Ordering::Acquire) {
            crash();
        }
        let lent = r.cap == Some(BUFFER as u16);
        let reply = w.serve(r.msg, lent, faults);
        if lent {
            // The caller's frame goes back (and out of the domain) before
            // the reply.
            syscall(Syscall::CapDelete, BUFFER, [0; 4]);
        }
        if faults && r.msg[0] == OP_STRAY {
            CRASHING.store(true, Ordering::Release);
            syscall(Syscall::Reply, 0, reply);
            crash();
        }
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, accept);
    }
}

extern "C" fn queue_thread(q: u64) -> ! {
    serve_forever(q as usize)
}

/// A serving thread and its I/O queue.
struct Worker {
    q: usize,
    queue: &'static mut Queue,
}

impl Worker {
    /// Reads or writes `count` 512-byte sectors from `sector` of `ns` at
    /// the device address `buffer`; or flushes it.
    fn io(&mut self, ns: Namespace, op: u8, sector: u64, count: u64, buffer: u64, interrupts: bool) -> Outcome {
        let per = ns.lba_shift - 9;
        let (lba, blocks) = (sector >> per, count >> per);
        let c = Command {
            op,
            nsid: ns.nsid,
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
        let now = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK.fetch_max(now, Ordering::SeqCst);
        RUN[self.q].fetch_add(1, Ordering::SeqCst);
        let outcome = self.queue.run(c, interrupts);
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    fn status(&mut self, ns: Namespace, op: u8, sector: u64, count: u64, buffer: u64) -> Status {
        match self.io(ns, op, sector, count, buffer, true) {
            Outcome::Done(0, _) => Status::Ok,
            _ => Status::DeviceError,
        }
    }

    /// Aims a read at a page of the driver's own that is not in the
    /// controller's domain. Returns (page untouched, command completed,
    /// its status field).
    fn stray(&mut self, ns: Namespace) -> Result<(bool, bool, u16, u64), Failure> {
        // SAFETY: the canary page is mapped at CANARY_VA.
        let page = unsafe { core::slice::from_raw_parts_mut(CANARY_VA as *mut u64, 512) };
        page.fill(CANARY_WORD);
        dma_barrier();
        let pa = dma_address(CANARY)?;
        let count = 4096 >> 9;
        let outcome = self.io(ns, READ, 0, count, pa, false);
        dma_barrier();
        let untouched = page.iter().all(|&w| w == CANARY_WORD);
        Ok(match outcome {
            Outcome::Done(s, _) => (untouched, true, s, pa),
            Outcome::TimedOut => (untouched, false, 0, pa),
        })
    }

    fn serve(&mut self, m: [u64; 4], lent: bool, faults: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        let s = shared();
        let unit = |u: u64| s.namespaces.get(u as usize).copied().flatten();
        let units = s.namespaces.iter().flatten().count() as u64;
        match m[0] {
            block::INFO if m[1] == block::VERSION => match unit(m[2]) {
                Some(ns) => [Status::Ok as u64, ns.sectors(), block::SECTOR, units],
                None => status(Status::NotFound),
            },
            block::FLUSH if s.cache => {
                for ns in s.namespaces.iter().flatten() {
                    if self.status(*ns, FLUSH, 0, 0, 0) != Status::Ok {
                        return status(Status::DeviceError);
                    }
                }
                status(Status::Ok)
            }
            // No volatile write cache: every completed write is durable.
            block::FLUSH => status(Status::Ok),
            block::READ | block::WRITE => {
                let Some(ns) = unit(m[3]) else {
                    return status(Status::NotFound);
                };
                let (sector, count) = (m[1], m[2]);
                let per = ns.lba_shift - 9;
                let aligned = (sector | count) & ((1 << per) - 1) == 0;
                if !lent
                    || !aligned
                    || count == 0
                    || count > block::MAX_SECTORS
                    || sector
                        .checked_add(count)
                        .is_none_or(|end| end > ns.sectors())
                {
                    return status(Status::Invalid);
                }
                // Reachable by the controller only until it is deleted,
                // before the reply; for a write, only for reading.
                let write = m[0] == block::WRITE;
                let op = if write { WRITE } else { READ };
                match io_map(BUFFER, DOMAIN, !write) {
                    Ok(buffer) => status(self.status(ns, op, sector, count, buffer)),
                    Err(_) => status(Status::Invalid),
                }
            }
            OP_CRASH if faults => crash(),
            OP_QUEUES if faults => {
                let used = (0..s.queues)
                    .filter(|&q| RUN[q].load(Ordering::SeqCst) > 0)
                    .fold(0, |m, q| m | 1 << q);
                [Status::Ok as u64, s.queues as u64, PEAK.load(Ordering::SeqCst), used]
            }
            OP_STRAY if faults => match self.stray(unit(0).unwrap()) {
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
    superior_sys::park()
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    if let Err((what, code)) = start(arg == 1) {
        say!("[fail] {what} ({code:#x})");
        superior_sys::park()
    }
    serve_forever(0)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
