//! An AHCI (SATA) driver, serving the `block` interface
//! (`superior_objects::interfaces::block`).
//!
//! A class driver: it opens the first PCI function of class 01:06:01 (mass
//! storage, SATA, AHCI 1.0), whoever made it, and drives the first port
//! with an ATA disk on it. Like the other disk drivers it holds only what
//! the manifest gives it: the PCI bus server, its service endpoint, a
//! notification for the interrupt and a little memory for DMA pages. The
//! controller's IOMMU domain arrives with the open, so it reaches only the
//! port's command list, received-FIS area and command table, the identify
//! page and, while a request is in flight, the caller's frame, which the
//! caller lends with the call and the driver deletes before replying.
//!
//! On start (and so after every restart) it resets the whole controller
//! (the bus server can reset only functions with a Function Level Reset),
//! switches it to AHCI mode, sets up the port, identifies the disk and
//! takes its interrupt as plain MSI. Requests are served one at a time in
//! command slot 0, each one READ DMA EXT, WRITE DMA EXT or FLUSH CACHE EXT
//! with a single PRD entry (a request is at most one page).
//!
//! Slots: 0 the bus server, 1 the `block` endpoint (receive), 2 a
//! notification, 3 untyped memory. `arg 1` turns on fault-injection
//! operations for tests: a crash, and a read aimed at memory outside the
//! domain.

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
/// The port's command list (1 KiB) and received-FIS area (256 bytes).
const LIST: u64 = 6;
/// Command table 0: the command FIS, then the PRD table.
const TABLE: u64 = 7;
const IDENTIFY: u64 = 8;
/// A page of the driver's own, never mapped for DMA (fault injection).
const CANARY: u64 = 9;
/// Where a caller's frame arrives.
const BUFFER: u64 = 10;
const BAR_SLOTS: u64 = 16;
const MAX_BAR_PAGES: u64 = 4;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const CANARY_VA: u64 = DMA_VA + 0x10_0000;

/// Fault injection (with `arg 1`): crash on receipt.
const OP_CRASH: u64 = 0xdead;
/// Fault injection: aim a read at a page outside the domain, reply whether
/// the page was touched, then crash, so the driver restarts on a freshly
/// reset controller.
const OP_STRAY: u64 = 0x57a7;
const CANARY_WORD: u64 = 0xcafe_f00d_cafe_f00d;

/// PCI class 01 (mass storage), subclass 06 (SATA), interface 01 (AHCI).
const CLASS: u32 = 0x01_06_01;
/// The AHCI base address (ABAR) is BAR 5.
const ABAR: u64 = 5;

// Generic host control (AHCI 1.3.1, 3.1).
const CAP: u64 = 0x00;
const GHC: u64 = 0x04;
const IS: u64 = 0x08;
const PI: u64 = 0x0c;
const GHC_HR: u32 = 1;
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;
const CAP_S64A: u32 = 1 << 31;

// Port registers, at 0x100 + 0x80 * port (3.3).
const PORTS: u64 = 0x100;
const P_CLB: u64 = 0x00;
const P_FB: u64 = 0x08;
const P_IS: u64 = 0x10;
const P_IE: u64 = 0x14;
const P_CMD: u64 = 0x18;
const P_TFD: u64 = 0x20;
const P_SIG: u64 = 0x24;
const P_SSTS: u64 = 0x28;
const P_SERR: u64 = 0x30;
const P_CI: u64 = 0x38;
const CMD_ST: u32 = 1;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const TFD_ERR: u32 = 1;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;
/// Port interrupts: device-to-host register FIS, PIO setup, DMA setup,
/// set device bits, and the task-file error.
const IE_ALL: u32 = 0xf | 1 << 30;
const IS_TFES: u32 = 1 << 30;
/// A SATA device present and communication established.
const DET_PRESENT: u32 = 3;
/// The signature of an ATA disk (not ATAPI, a port multiplier or a bridge).
const SIG_ATA: u32 = 0x0000_0101;

// ATA commands.
const ATA_IDENTIFY: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_EXT: u8 = 0xea;
/// FIS type: register, host to device.
const FIS_H2D: u8 = 0x27;

/// Ticks (10 ms) a command or a reset may take before the driver gives up.
const COMMAND_TICKS: u64 = 500;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("ahci: {}", format_args!($($t)*))) };
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// Waits (yielding) until `done()`, for at most `COMMAND_TICKS`.
fn wait(what: &'static str, mut done: impl FnMut() -> bool) -> Result<(), Failure> {
    let start = ticks();
    while !done() {
        if ticks() > start + COMMAND_TICKS {
            return Err((what, 0));
        }
        syscall(Syscall::Yield, 0, [0; 4]);
    }
    Ok(())
}

struct Disk {
    hba: Mmio,
    port: Mmio,
    n: u64,
    list: DmaPage,
    table: DmaPage,
    identify: DmaPage,
    sectors: u64,
    /// The disk's write cache is on: a flush empties it.
    cache: bool,
}

/// How a command ended.
enum Outcome {
    Done,
    /// The disk reported an error (task file status).
    Failed(u32),
    TimedOut,
}

fn start() -> Result<Disk, Failure> {
    let pci = Pci { slot: PCI };
    let (bdf, bars) = pci.open_class(CLASS, 0, DOMAIN)?;
    if bars & 1 << ABAR == 0 {
        return Err(("no ABAR (BAR 5)", bars));
    }
    let mut slot = BAR_SLOTS;
    let mut pages = 1;
    let size = pci.map_bar_page(ABAR, 0, slot, BAR_VA)?;
    slot += 1;
    let hba = Mmio { base: BAR_VA };

    // Reset the controller, then AHCI mode.
    hba.write32(GHC, GHC_AE);
    hba.write32(GHC, GHC_AE | GHC_HR);
    wait("the controller did not finish its reset", || {
        hba.read32(GHC) & GHC_HR == 0
    })?;
    hba.write32(GHC, GHC_AE);
    let cap = hba.read32(CAP);
    let implemented = hba.read32(PI);

    // The port's memory, the interrupt and DMA, before any port receives a
    // FIS.
    let list = DmaPage::new(UNTYPED, LIST, DMA_VA, DOMAIN)?;
    let table = DmaPage::new(UNTYPED, TABLE, DMA_VA + 0x1000, DOMAIN)?;
    let identify = DmaPage::new(UNTYPED, IDENTIFY, DMA_VA + 0x2000, DOMAIN)?;
    let top = list.dma.max(table.dma).max(identify.dma);
    if cap & CAP_S64A == 0 && top >> 32 != 0 {
        return Err(("DMA pages above 4 GiB, and no 64-bit addressing", top));
    }
    // Plain MSI (this controller has no MSI-X).
    let (_, data) = pci.msi_vector(0, MSI, NOTIFY, DOMAIN)?;
    pci.msi(true)?;
    pci.bus_master(true)?;

    // The first port with an ATA disk on it. A port's signature arrives
    // with the disk's first FIS, so each port with a link is brought up
    // (FIS receive on) before its signature is read.
    let mut found = None;
    for n in 0..32u64 {
        if implemented & 1 << n == 0 {
            continue;
        }
        let at = PORTS + 0x80 * n;
        while at + 0x80 > pages * 4096 {
            if pages * 4096 >= size || pages == MAX_BAR_PAGES {
                return Err(("a port beyond what the driver maps", n));
            }
            pci.map_bar_page(ABAR, pages, slot, BAR_VA + pages * 4096)?;
            slot += 1;
            pages += 1;
        }
        let port = Mmio { base: BAR_VA + at };
        // The reset may leave the link coming up for a moment.
        if wait("", || port.read32(P_SSTS) & 0xf == DET_PRESENT).is_err() {
            continue;
        }
        // Stop the port, give it its memory, receive FISes.
        port.write32(P_CMD, port.read32(P_CMD) & !(CMD_ST | CMD_FRE));
        wait("a port did not stop", || {
            port.read32(P_CMD) & (CMD_CR | CMD_FR) == 0
        })?;
        port.write32(P_CLB, list.dma as u32);
        port.write32(P_CLB + 4, (list.dma >> 32) as u32);
        port.write32(P_FB, (list.dma + 1024) as u32);
        port.write32(P_FB + 4, ((list.dma + 1024) >> 32) as u32);
        port.write32(P_SERR, !0);
        port.write32(P_IS, !0);
        port.write32(P_CMD, port.read32(P_CMD) | CMD_FRE);
        let ready = wait("", || port.read32(P_TFD) & (TFD_BSY | TFD_DRQ) == 0).is_ok();
        if ready && port.read32(P_SIG) == SIG_ATA {
            found = Some((n, port));
            break;
        }
        // Not a disk this driver serves: FIS receive off again.
        port.write32(P_CMD, port.read32(P_CMD) & !CMD_FRE);
        let _ = wait("", || port.read32(P_CMD) & CMD_FR == 0);
    }
    let (n, port) = found.ok_or(("no ATA disk on any port", implemented as u64))?;
    port.write32(P_IS, !0);
    hba.write32(IS, !0);
    port.write32(P_IE, IE_ALL);
    hba.write32(GHC, GHC_AE | GHC_IE);
    port.write32(P_CMD, port.read32(P_CMD) | CMD_ST);

    let mut d = Disk {
        hba,
        port,
        n,
        list,
        table,
        identify,
        sectors: 0,
        cache: false,
    };
    match d.run(ATA_IDENTIFY, 0, 0, d.identify.dma, 512, true) {
        Outcome::Done => {}
        Outcome::Failed(tfd) => return Err(("IDENTIFY DEVICE failed", tfd as u64)),
        Outcome::TimedOut => return Err(("IDENTIFY DEVICE timed out", 0)),
    }
    dma_barrier();
    // SAFETY: the identify page is mapped; IDENTIFY wrote 256 words.
    let w = unsafe { core::slice::from_raw_parts(d.identify.va as *const u16, 256) };
    if w[83] & 1 << 10 == 0 {
        return Err(("the disk has no 48-bit addressing", w[83] as u64));
    }
    d.sectors = (0..4).fold(0, |s, i| s | (w[100 + i] as u64) << (16 * i));
    d.cache = w[85] & 1 << 5 != 0;
    // The model: 40 ASCII bytes, two to a word, high byte first.
    let mut model = [0u8; 40];
    for i in 0..20 {
        model[2 * i] = (w[27 + i] >> 8) as u8;
        model[2 * i + 1] = w[27 + i] as u8;
    }
    let model = core::str::from_utf8(&model).unwrap_or("").trim_end();
    say!(
        "ready: {:02x}:{:02x}.{} port {n} \"{model}\", {} sectors{}, interrupts on MSI (message data {data:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
        d.sectors,
        if d.cache { ", write cache" } else { "" },
    );
    Ok(d)
}

impl Disk {
    /// Starts ATA command `op` on `count` sectors from `lba`, moving
    /// `bytes` at device address `buffer` (none for a flush), in slot 0.
    fn submit(&mut self, op: u8, lba: u64, count: u64, buffer: u64, bytes: u64) {
        let fis = [
            FIS_H2D,
            0x80, // a command, not a control register update
            op,
            0,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            1 << 6, // LBA mode
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            0,
            count as u8,
            (count >> 8) as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let t = self.table.va;
        // SAFETY: the command table page is mapped at `t`: the FIS at 0,
        // the PRD table at 0x80.
        unsafe {
            for (i, b) in fis.iter().enumerate() {
                ((t + i as u64) as *mut u8).write_volatile(*b);
            }
            ((t + 0x80) as *mut u64).write_volatile(buffer);
            ((t + 0x88) as *mut u32).write_volatile(0);
            ((t + 0x8c) as *mut u32).write_volatile((bytes.max(1) - 1) as u32);
        }
        let prds = if bytes == 0 { 0 } else { 1 };
        let write = if op == ATA_WRITE_DMA_EXT { 1 << 6 } else { 0 };
        let l = self.list.va;
        // SAFETY: the command list page is mapped at `l`; header 0 is at 0.
        unsafe {
            (l as *mut u32).write_volatile(prds << 16 | write | 5);
            ((l + 4) as *mut u32).write_volatile(0);
            ((l + 8) as *mut u64).write_volatile(self.table.dma);
        }
        self.port.write32(P_IS, !0);
        dma_barrier();
        self.port.write32(P_CI, 1);
    }

    /// Runs a command to completion. With `interrupts`, sleeps on the MSI
    /// between looks; otherwise yields (fault injection's stray read).
    fn run(
        &mut self,
        op: u8,
        lba: u64,
        count: u64,
        buffer: u64,
        bytes: u64,
        interrupts: bool,
    ) -> Outcome {
        self.submit(op, lba, count, buffer, bytes);
        let start = ticks();
        loop {
            let is = self.port.read32(P_IS);
            self.port.write32(P_IS, is);
            self.hba.write32(IS, 1 << self.n);
            if is & IS_TFES != 0 {
                let tfd = self.port.read32(P_TFD);
                // Restart the port to clear the error (AHCI 6.2.2.1).
                self.port.write32(P_CMD, self.port.read32(P_CMD) & !CMD_ST);
                let _ = wait("", || self.port.read32(P_CMD) & CMD_CR == 0);
                self.port.write32(P_SERR, !0);
                self.port.write32(P_CMD, self.port.read32(P_CMD) | CMD_ST);
                return Outcome::Failed(tfd);
            }
            if self.port.read32(P_CI) & 1 == 0 {
                dma_barrier();
                let tfd = self.port.read32(P_TFD);
                return if tfd & TFD_ERR != 0 {
                    Outcome::Failed(tfd)
                } else {
                    Outcome::Done
                };
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

    fn status(&mut self, op: u8, lba: u64, count: u64, buffer: u64) -> Status {
        match self.run(op, lba, count, buffer, count * block::SECTOR, true) {
            Outcome::Done => Status::Ok,
            _ => Status::DeviceError,
        }
    }

    /// Aims a read at a page of the driver's own that is not in the
    /// controller's domain. Returns (page untouched, command completed,
    /// the task file status if it failed).
    fn stray(&mut self) -> Result<(bool, bool, u32, u64), Failure> {
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
        let outcome = self.run(ATA_READ_DMA_EXT, 0, 8, pa, 4096, false);
        dma_barrier();
        let untouched = page.iter().all(|&w| w == CANARY_WORD);
        Ok(match outcome {
            Outcome::Done => (untouched, true, 0, pa),
            Outcome::Failed(tfd) => (untouched, true, tfd, pa),
            Outcome::TimedOut => (untouched, false, 0, pa),
        })
    }

    fn serve(&mut self, m: [u64; 4], lent: bool, faults: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            // One unit: the disk.
            block::INFO if m[1] == block::VERSION && m[2] == 0 => {
                [Status::Ok as u64, self.sectors, block::SECTOR, 1]
            }
            block::INFO | block::READ | block::WRITE if m[if m[0] == block::INFO { 2 } else { 3 }] != 0 => {
                status(Status::NotFound)
            }
            block::FLUSH if self.cache => status(self.status(ATA_FLUSH_EXT, 0, 0, 0)),
            // No write cache: every completed write is already durable.
            block::FLUSH => status(Status::Ok),
            block::READ | block::WRITE => {
                let (sector, count) = (m[1], m[2]);
                if !lent
                    || count == 0
                    || count > block::MAX_SECTORS
                    || sector
                        .checked_add(count)
                        .is_none_or(|end| end > self.sectors)
                {
                    return status(Status::Invalid);
                }
                // Reachable by the controller only until it is deleted,
                // before the reply; for a write, only for reading.
                let write = m[0] == block::WRITE;
                let op = if write {
                    ATA_WRITE_DMA_EXT
                } else {
                    ATA_READ_DMA_EXT
                };
                match io_map(BUFFER, DOMAIN, !write) {
                    Ok(buffer) => status(self.status(op, sector, count, buffer)),
                    Err(_) => status(Status::Invalid),
                }
            }
            OP_CRASH if faults => crash(),
            OP_STRAY if faults => match self.stray() {
                Ok((untouched, done, tfd, page)) => {
                    let (reported, report) = superior_driver::stray_reported(DOMAIN, page);
                    say!(
                        "stray DMA: page {}, command {} (task file {tfd:#x}); {report}",
                        if untouched { "untouched" } else { "WRITTEN" },
                        if done { "completed" } else { "never completed" }
                    );
                    [Status::Ok as u64, (untouched && reported) as u64, done as u64, tfd as u64]
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
    let mut disk = match start() {
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
        let reply = disk.serve(r.msg, lent, arg == 1);
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
