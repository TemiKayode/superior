//! An AHCI (SATA) driver, serving the `block` interface
//! (`superior_objects::interfaces::block`).
//!
//! A class driver: it opens the first PCI function of class 01:06:01 (mass
//! storage, SATA, AHCI 1.0), whoever made it, and serves every port with
//! an ATA disk on it, each a unit of `block` (in port order). Like the
//! other disk drivers it holds only what the manifest gives it: the PCI
//! bus server, its service endpoint, a notification for the interrupt and
//! a little memory for DMA pages. The controller's IOMMU domain arrives
//! with the open, so it reaches only the ports' command lists, received-FIS
//! areas and command tables, the identify page and, while a request is in
//! flight, the caller's frame, which the caller lends with the call and
//! the driver deletes before replying.
//!
//! On start (and so after every restart) it resets the whole controller
//! (the bus server can reset only functions with a Function Level Reset),
//! switches it to AHCI mode, sets up each port with a disk, identifies the
//! disks and takes the controller's interrupt as plain MSI.
//!
//! Requests are served by [`TAGS`] threads at once, each with a command
//! slot of its own on every port. Where the controller and the disk do
//! native command queuing, reads and writes are READ/WRITE FPDMA QUEUED
//! with the thread's slot as the tag, so the disk has several in hand at
//! once; otherwise READ/WRITE DMA EXT, one at a time per port. FLUSH CACHE
//! EXT (which may not overlap queued commands) and the fault-injection read
//! take the port for themselves. The main thread does not serve: with one
//! vector for the whole controller, it waits for the interrupt, works out
//! which slots finished (or that a port reported an error, which it clears
//! by restarting the port) and wakes their threads. Each command has
//! [`COMMAND_TICKS`] to finish; one that does not means the controller is
//! wedged, and the driver crashes so it is restarted on a reset one.
//!
//! Slots: 0 the bus server, 1 the `block` endpoint (receive), 2 a
//! notification, 3 untyped memory. `arg 1` turns on fault-injection and
//! test operations: a crash, a read aimed at memory outside the domain,
//! and the command slots' statistics.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_address, dma_barrier, io_map};
use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::interfaces::{Status, block};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

// Slots every serving thread has (each in its own CSpace).
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const DOMAIN: u64 = 5;
/// A page of the driver's own, never mapped for DMA (fault injection).
const CANARY: u64 = 9;
/// Where a caller's frame arrives.
const BUFFER: u64 = 10;
// The main thread's.
const PCI: u64 = 0;
const UNTYPED: u64 = 3;
const MSI: u64 = 4;
const IDENTIFY: u64 = 8;
const BAR_SLOTS: u64 = 16;
const MAX_BAR_PAGES: u64 = 4;
/// Port `i`'s command list and received-FIS page, and its command tables.
const fn port_slot(i: usize, table: bool) -> u64 {
    24 + 2 * i as u64 + table as u64
}
/// Serving thread `t`'s thread, notification and stack pages.
const fn tag_slot(t: usize, what: u64) -> u64 {
    40 + 8 * t as u64 + what
}
const T_THREAD: u64 = 0;
const T_NOTIFY: u64 = 1;
const T_STACK: u64 = 2;
const STACK_PAGES: u64 = 3;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const CANARY_VA: u64 = DMA_VA + 0x10_0000;
const STACK_VA: u64 = USER_BASE + 0x5800_0000;

/// Fault injection (with `arg 1`): crash on receipt.
const OP_CRASH: u64 = 0xdead;
/// Fault injection: aim a read at a page outside the domain, reply whether
/// the page was touched, then crash, so the driver restarts on a freshly
/// reset controller.
const OP_STRAY: u64 = 0x57a7;
/// Test operation: `[OP_QUEUES]`, reply `[Ok, command slots, most
/// commands ever in flight at once, mask of the slots that have run a
/// command]`.
const OP_QUEUES: u64 = 0x9e5e;
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
const CAP_SNCQ: u32 = 1 << 30;

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
const P_SACT: u64 = 0x34;
const P_CI: u64 = 0x38;
const CMD_ST: u32 = 1;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const TFD_ERR: u32 = 1;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;
/// Port interrupts: device-to-host register FIS, PIO setup, DMA setup,
/// set device bits (queued completions), and the task-file error.
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
const ATA_READ_FPDMA: u8 = 0x60;
const ATA_WRITE_FPDMA: u8 = 0x61;
const ATA_FLUSH_EXT: u8 = 0xea;
/// FIS type: register, host to device.
const FIS_H2D: u8 = 0x27;

/// Serving threads, each with its own command slot (and NCQ tag).
const TAGS: usize = 2;
/// Ports (disks) served.
const MAX_DISKS: usize = 4;
/// Bytes between command tables in a port's table page: the FIS at 0,
/// the one-entry PRD table at 0x80.
const TABLE_STRIDE: u64 = 0x100;

/// Ticks (10 ms) the links may take to come up after the reset.
const LINK_TICKS: u64 = 10;
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

/// A port with a disk.
#[derive(Clone, Copy)]
struct Disk {
    n: u64,
    port: Mmio,
    list: DmaPage,
    tables: DmaPage,
    sectors: u64,
    /// The disk's write cache is on: a flush empties it.
    cache: bool,
    /// Reads and writes are queued (NCQ).
    ncq: bool,
}

/// What every thread shares, fixed once the driver is up.
struct Shared {
    hba: Mmio,
    disks: [Option<Disk>; MAX_DISKS],
    faults: bool,
}

static mut SHARED: Shared = Shared {
    hba: Mmio { base: 0 },
    disks: [None; MAX_DISKS],
    faults: false,
};

fn shared() -> &'static Shared {
    // SAFETY: written only by `start`, before any other thread runs.
    unsafe { &*(&raw const SHARED) }
}

/// Per disk: the slots with a command in flight (set by the thread that
/// issued it, cleared by the main thread when it ends), and a count of
/// queued commands with `EXCLUSIVE` set while one thread has the port.
static IN_FLIGHT: [AtomicU32; MAX_DISKS] = [const { AtomicU32::new(0) }; MAX_DISKS];
static USERS: [AtomicU32; MAX_DISKS] = [const { AtomicU32::new(0) }; MAX_DISKS];
const EXCLUSIVE: u32 = 1 << 31;
/// Per slot: how its last command ended (`PENDING` until it does).
static RESULT: [AtomicU32; TAGS] = [const { AtomicU32::new(PENDING) }; TAGS];
const PENDING: u32 = u32::MAX;
const FAILED_BIT: u32 = 1 << 30;
/// Commands in flight across the slots now, the most ever, and how many
/// each slot has run.
static NOW: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static RUN: [AtomicU64; TAGS] = [const { AtomicU64::new(0) }; TAGS];

fn retype(ty: ObjectType, slot: u64) -> Result<(), Failure> {
    match syscall(Syscall::Retype, UNTYPED, [ty as u64, 0, slot, 0]).status {
        0 => Ok(()),
        e => Err(("out of memory", e)),
    }
}

/// Writes command slot `tag`'s header and table on `d` for ATA command
/// `op` on `count` sectors from `lba`, moving `bytes` at device address
/// `buffer` (none for a flush or an identify's fixed 512).
fn prepare(d: &Disk, tag: usize, op: u8, lba: u64, count: u64, buffer: u64, bytes: u64) {
    let queued = op == ATA_READ_FPDMA || op == ATA_WRITE_FPDMA;
    // Queued commands carry the count in the features field and the tag
    // in the count field.
    let (features, sector_count) = if queued {
        (count, (tag as u64) << 3)
    } else {
        (0, count)
    };
    let fis = [
        FIS_H2D,
        0x80, // a command, not a control register update
        op,
        features as u8,
        lba as u8,
        (lba >> 8) as u8,
        (lba >> 16) as u8,
        1 << 6, // LBA mode
        (lba >> 24) as u8,
        (lba >> 32) as u8,
        (lba >> 40) as u8,
        (features >> 8) as u8,
        sector_count as u8,
        (sector_count >> 8) as u8,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let t = d.tables.va + TABLE_STRIDE * tag as u64;
    // SAFETY: the table page is mapped; this slot's table is ours alone.
    unsafe {
        for (i, b) in fis.iter().enumerate() {
            ((t + i as u64) as *mut u8).write_volatile(*b);
        }
        ((t + 0x80) as *mut u64).write_volatile(buffer);
        ((t + 0x88) as *mut u32).write_volatile(0);
        ((t + 0x8c) as *mut u32).write_volatile((bytes.max(1) - 1) as u32);
    }
    let prds = if bytes == 0 { 0 } else { 1 };
    let write = if op == ATA_WRITE_DMA_EXT || op == ATA_WRITE_FPDMA {
        1 << 6
    } else {
        0
    };
    let h = d.list.va + 32 * tag as u64;
    // SAFETY: the command list is mapped; header `tag` is ours alone.
    unsafe {
        (h as *mut u32).write_volatile(prds << 16 | write | 5);
        ((h + 4) as *mut u32).write_volatile(0);
        ((h + 8) as *mut u64).write_volatile(d.tables.dma + TABLE_STRIDE * tag as u64);
    }
    dma_barrier();
}

/// Restarts port `d` to clear an error (AHCI 6.2.2.1): every command on it
/// is dropped.
fn restart_port(d: &Disk) {
    d.port.write32(P_CMD, d.port.read32(P_CMD) & !CMD_ST);
    let _ = wait("", || d.port.read32(P_CMD) & CMD_CR == 0);
    d.port.write32(P_SERR, !0);
    d.port.write32(P_IS, !0);
    d.port.write32(P_CMD, d.port.read32(P_CMD) | CMD_ST);
}

fn start(faults: bool) -> Result<(), Failure> {
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

    let identify = DmaPage::new(UNTYPED, IDENTIFY, DMA_VA + 0xf_0000, DOMAIN)?;
    // Plain MSI (this controller has no MSI-X).
    let (_, data) = pci.msi_vector(0, MSI, NOTIFY, DOMAIN)?;
    pci.msi(true)?;
    pci.bus_master(true)?;

    // The reset restarts every link: give them a moment (at most
    // `LINK_TICKS`) to come up or report no device, together, so empty
    // ports cost nothing.
    let det = |n: u64| {
        let at = PORTS + 0x80 * n;
        // Only the ABAR's first page is mapped yet (ports 0-29); later
        // ports' pages are mapped below, before they are used.
        if at + 0x80 > 4096 {
            return DET_PRESENT;
        }
        Mmio { base: BAR_VA + at }.read32(P_SSTS) & 0xf
    };
    let settled = ticks();
    while (0..32)
        .filter(|&n| implemented & 1 << n != 0)
        .any(|n| !matches!(det(n), 0 | DET_PRESENT))
        && ticks() < settled + LINK_TICKS
    {
        syscall(Syscall::Yield, 0, [0; 4]);
    }

    // Every port with an ATA disk on it. A port's signature arrives with
    // the disk's first FIS, so each port with a link is brought up (FIS
    // receive on) before its signature is read.
    let mut disks = [None; MAX_DISKS];
    let mut count = 0;
    for n in 0..32u64 {
        if implemented & 1 << n == 0 || count == MAX_DISKS {
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
        if port.read32(P_SSTS) & 0xf != DET_PRESENT {
            continue;
        }
        // Stop the port, give it its memory, receive FISes.
        port.write32(P_CMD, port.read32(P_CMD) & !(CMD_ST | CMD_FRE));
        wait("a port did not stop", || {
            port.read32(P_CMD) & (CMD_CR | CMD_FR) == 0
        })?;
        let va = DMA_VA + 0x2000 * count as u64;
        let list = DmaPage::new(UNTYPED, port_slot(count, false), va, DOMAIN)?;
        let tables = DmaPage::new(UNTYPED, port_slot(count, true), va + 0x1000, DOMAIN)?;
        if cap & CAP_S64A == 0 && (list.dma.max(tables.dma).max(identify.dma)) >> 32 != 0 {
            return Err(("DMA pages above 4 GiB, and no 64-bit addressing", list.dma));
        }
        port.write32(P_CLB, list.dma as u32);
        port.write32(P_CLB + 4, (list.dma >> 32) as u32);
        port.write32(P_FB, (list.dma + 1024) as u32);
        port.write32(P_FB + 4, ((list.dma + 1024) >> 32) as u32);
        port.write32(P_SERR, !0);
        port.write32(P_IS, !0);
        port.write32(P_CMD, port.read32(P_CMD) | CMD_FRE);
        let ready = wait("", || port.read32(P_TFD) & (TFD_BSY | TFD_DRQ) == 0).is_ok();
        if !(ready && port.read32(P_SIG) == SIG_ATA) {
            // Not a disk this driver serves: FIS receive off again (its
            // pages stay, unused).
            port.write32(P_CMD, port.read32(P_CMD) & !CMD_FRE);
            let _ = wait("", || port.read32(P_CMD) & CMD_FR == 0);
            continue;
        }
        port.write32(P_IS, !0);
        port.write32(P_CMD, port.read32(P_CMD) | CMD_ST);
        let mut d = Disk {
            n,
            port,
            list,
            tables,
            sectors: 0,
            cache: false,
            ncq: false,
        };
        // IDENTIFY DEVICE, polled: interrupts are not on yet.
        prepare(&d, 0, ATA_IDENTIFY, 0, 0, identify.dma, 512);
        port.write32(P_CI, 1);
        wait("IDENTIFY DEVICE timed out", || {
            port.read32(P_CI) & 1 == 0 || port.read32(P_IS) & IS_TFES != 0
        })?;
        if port.read32(P_IS) & IS_TFES != 0 || port.read32(P_TFD) & TFD_ERR != 0 {
            return Err(("IDENTIFY DEVICE failed", port.read32(P_TFD) as u64));
        }
        dma_barrier();
        // SAFETY: the identify page is mapped; IDENTIFY wrote 256 words.
        let w = unsafe { core::slice::from_raw_parts(identify.va as *const u16, 256) };
        if w[83] & 1 << 10 == 0 {
            say!("port {n}: no 48-bit addressing; skipped");
            continue;
        }
        d.sectors = (0..4).fold(0, |s, i| s | (w[100 + i] as u64) << (16 * i));
        d.cache = w[85] & 1 << 5 != 0;
        // NCQ: the controller and the disk both, deep enough for every
        // slot.
        d.ncq = cap & CAP_SNCQ != 0 && w[76] & 1 << 8 != 0 && (w[75] & 0x1f) as usize + 1 >= TAGS;
        // The model: 40 ASCII bytes, two to a word, high byte first.
        let mut model = [0u8; 40];
        for i in 0..20 {
            model[2 * i] = (w[27 + i] >> 8) as u8;
            model[2 * i + 1] = w[27 + i] as u8;
        }
        let model = core::str::from_utf8(&model).unwrap_or("").trim_end();
        say!(
            "unit {count}: port {n} \"{model}\", {} sectors{}{}",
            d.sectors,
            if d.cache { ", write cache" } else { "" },
            if d.ncq { ", NCQ" } else { "" },
        );
        port.write32(P_IS, !0);
        port.write32(P_IE, IE_ALL);
        disks[count] = Some(d);
        count += 1;
    }
    if count == 0 {
        return Err(("no ATA disk on any port", implemented as u64));
    }
    hba.write32(IS, !0);
    hba.write32(GHC, GHC_AE | GHC_IE);
    // SAFETY: no other thread runs yet.
    unsafe {
        *(&raw mut SHARED) = Shared { hba, disks, faults };
    }
    if faults {
        // The fault-injection page, made now so every thread can use it.
        retype(ObjectType::Frame, CANARY)?;
        superior_driver::map(CANARY, CANARY_VA, true).map_err(|e| ("mapping the canary", e))?;
    }
    say!(
        "ready: {:02x}:{:02x}.{}, {count} disks, {TAGS} command slots, interrupts on MSI (message data {data:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
    );
    for t in 0..TAGS {
        spawn(t)?;
    }
    Ok(())
}

/// Starts serving thread `t`, with its own CSpace laid out like the
/// serving slots above.
fn spawn(t: usize) -> Result<(), Failure> {
    let tcb = tag_slot(t, T_THREAD);
    retype(ObjectType::Thread, tcb)?;
    retype(ObjectType::Notification, tag_slot(t, T_NOTIFY))?;
    let stack = STACK_VA + 0x1_0000 * t as u64;
    for p in 0..STACK_PAGES {
        let slot = tag_slot(t, T_STACK) + p;
        retype(ObjectType::Frame, slot)?;
        superior_driver::map(slot, stack + 0x1000 * p, true).map_err(|e| ("mapping a stack page", e))?;
    }
    let copies = [
        (SERVICE, SERVICE),
        (DOMAIN, DOMAIN),
        (tag_slot(t, T_NOTIFY), NOTIFY),
        (CANARY, CANARY),
    ];
    let n = if shared().faults { 4 } else { 3 };
    for (from, to) in &copies[..n] {
        let r = syscall(Syscall::ThreadCopyCap, tcb, [*from, *to, 0xff, 0]);
        if r.status != 0 {
            return Err(("giving a serving thread its capabilities", r.status));
        }
    }
    let entry = serving_thread as *const () as u64;
    let top = stack + 0x1000 * STACK_PAGES;
    // At the driver's own priority: the highest a thread it makes may have.
    let configured = (0..=255u64).rev().any(|prio| {
        syscall(Syscall::ThreadConfigure, tcb, [entry, top, t as u64, prio]).status == 0
    });
    if !configured || syscall(Syscall::ThreadResume, tcb, [0; 4]).status != 0 {
        return Err(("starting a serving thread", t as u64));
    }
    Ok(())
}

/// The main thread, once the driver is up: takes the interrupt, and wakes
/// each thread whose command ended.
fn dispatch() -> ! {
    let s = shared();
    let mut again = false;
    loop {
        if !again {
            syscall(Syscall::Wait, NOTIFY, [0; 4]);
        }
        for (i, d) in s.disks.iter().enumerate() {
            let Some(d) = d else { continue };
            let is = d.port.read32(P_IS);
            d.port.write32(P_IS, is);
            s.hba.write32(IS, 1 << d.n);
            let mut failed = 0;
            if is & IS_TFES != 0 {
                // Every command on the port is lost with the restart.
                say!("port {}: task file error {:#x}; port restarted", d.n, d.port.read32(P_TFD));
                failed = IN_FLIGHT[i].load(Ordering::SeqCst);
                restart_port(d);
            }
            let busy = d.port.read32(P_SACT) | d.port.read32(P_CI);
            let tfd = d.port.read32(P_TFD);
            let flight = IN_FLIGHT[i].load(Ordering::SeqCst);
            for t in 0..TAGS {
                let bit = 1 << t;
                if flight & bit == 0 || (busy & bit != 0 && failed & bit == 0) {
                    continue;
                }
                IN_FLIGHT[i].fetch_and(!bit, Ordering::SeqCst);
                let result = if failed & bit != 0 || tfd & TFD_ERR != 0 {
                    FAILED_BIT | tfd
                } else {
                    0
                };
                RESULT[t].store(result, Ordering::SeqCst);
                syscall(Syscall::Signal, tag_slot(t, T_NOTIFY), [0; 4]);
            }
        }
        syscall(Syscall::IrqAck, MSI, [0; 4]);
        // A command that ended after its port was read but before the
        // acknowledgement may have raised no new message: look again.
        again = s.disks.iter().flatten().any(|d| d.port.read32(P_IS) != 0);
    }
}

extern "C" fn serving_thread(t: u64) -> ! {
    let t = t as usize;
    let mut w = Worker { tag: t };
    let accept = CapTransfer {
        grant: None,
        accept: Some(BUFFER as u16),
    };
    let faults = shared().faults;
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        let lent = r.cap == Some(BUFFER as u16);
        let reply = w.serve(r.msg, lent, faults);
        if lent {
            // The caller's frame goes back (and out of the domain) before
            // the reply.
            syscall(Syscall::CapDelete, BUFFER, [0; 4]);
        }
        if faults && r.msg[0] == OP_STRAY {
            syscall(Syscall::Reply, 0, reply);
            crash("crashing (fault injection)");
        }
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, accept);
    }
}

/// How a command ended.
enum Outcome {
    Done,
    /// The disk reported an error (task file status).
    Failed(u32),
    /// Never, in the fault injection's polled read.
    TimedOut,
}

/// A serving thread and its command slot.
struct Worker {
    tag: usize,
}

impl Worker {
    /// Takes disk `i` for a queued command (shared), or for itself.
    fn enter(&self, i: usize, exclusive: bool) {
        loop {
            let users = USERS[i].load(Ordering::SeqCst);
            let next = match (exclusive, users) {
                (false, u) if u & EXCLUSIVE == 0 => u + 1,
                (true, 0) => EXCLUSIVE,
                _ => {
                    syscall(Syscall::Yield, 0, [0; 4]);
                    continue;
                }
            };
            if USERS[i]
                .compare_exchange(users, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return;
            }
        }
    }

    fn leave(&self, i: usize, exclusive: bool) {
        if exclusive {
            USERS[i].store(0, Ordering::SeqCst);
        } else {
            USERS[i].fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Runs ATA command `op` on disk `i` in this thread's slot and waits
    /// for the main thread to say it ended. With `interrupts` false
    /// (fault injection), polls the port instead.
    fn run(&mut self, i: usize, op: u8, lba: u64, count: u64, buffer: u64, interrupts: bool) -> Outcome {
        let d = shared().disks[i].unwrap();
        let queued = op == ATA_READ_FPDMA || op == ATA_WRITE_FPDMA;
        self.enter(i, !queued);
        let bit = 1u32 << self.tag;
        let bytes = if op == ATA_FLUSH_EXT { 0 } else { count * block::SECTOR };
        prepare(&d, self.tag, op, lba, count, buffer, bytes);
        let now = NOW.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK.fetch_max(now, Ordering::SeqCst);
        RUN[self.tag].fetch_add(1, Ordering::SeqCst);
        RESULT[self.tag].store(PENDING, Ordering::SeqCst);
        if interrupts {
            IN_FLIGHT[i].fetch_or(bit, Ordering::SeqCst);
            syscall(Syscall::TimerSignal, NOTIFY, [COMMAND_TICKS, 0, 0, 0]);
        }
        if queued {
            d.port.write32(P_SACT, bit);
        }
        d.port.write32(P_CI, bit);
        let start = ticks();
        let outcome = loop {
            if interrupts {
                let r = RESULT[self.tag].load(Ordering::SeqCst);
                if r != PENDING {
                    syscall(Syscall::TimerSignal, NOTIFY, [0; 4]);
                    break if r & FAILED_BIT != 0 {
                        Outcome::Failed(r & !FAILED_BIT)
                    } else {
                        Outcome::Done
                    };
                }
                if ticks() > start + COMMAND_TICKS {
                    // The controller is wedged: start again on a reset one.
                    crash("a command never finished");
                }
                syscall(Syscall::Wait, NOTIFY, [0; 4]);
            } else {
                // The main thread leaves this slot alone: poll it.
                if d.port.read32(P_CI) & bit == 0 {
                    let tfd = d.port.read32(P_TFD);
                    break if tfd & TFD_ERR != 0 { Outcome::Failed(tfd) } else { Outcome::Done };
                }
                if ticks() > start + COMMAND_TICKS {
                    break Outcome::TimedOut;
                }
                syscall(Syscall::Yield, 0, [0; 4]);
            }
        };
        NOW.fetch_sub(1, Ordering::SeqCst);
        self.leave(i, !queued);
        outcome
    }

    fn status(&mut self, i: usize, op: u8, lba: u64, count: u64, buffer: u64) -> Status {
        match self.run(i, op, lba, count, buffer, true) {
            Outcome::Done => Status::Ok,
            _ => Status::DeviceError,
        }
    }

    /// Aims a read at a page of the driver's own that is not in the
    /// controller's domain. Returns (page untouched, command completed,
    /// the task file status if it failed).
    fn stray(&mut self) -> Result<(bool, bool, u32, u64), Failure> {
        // SAFETY: the canary page is mapped at CANARY_VA.
        let page = unsafe { core::slice::from_raw_parts_mut(CANARY_VA as *mut u64, 512) };
        page.fill(CANARY_WORD);
        dma_barrier();
        let pa = dma_address(CANARY)?;
        let outcome = self.run(0, ATA_READ_DMA_EXT, 0, 8, pa, false);
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
        let s = shared();
        let units = s.disks.iter().flatten().count() as u64;
        let unit = |u: u64| (u < units).then_some(u as usize);
        match m[0] {
            block::INFO if m[1] == block::VERSION => match unit(m[2]) {
                Some(i) => [Status::Ok as u64, s.disks[i].unwrap().sectors, block::SECTOR, units],
                None => status(Status::NotFound),
            },
            block::FLUSH => {
                for i in 0..units as usize {
                    if s.disks[i].unwrap().cache && self.status(i, ATA_FLUSH_EXT, 0, 0, 0) != Status::Ok {
                        return status(Status::DeviceError);
                    }
                }
                status(Status::Ok)
            }
            block::READ | block::WRITE => {
                let Some(i) = unit(m[3]) else {
                    return status(Status::NotFound);
                };
                let d = s.disks[i].unwrap();
                let (sector, count) = (m[1], m[2]);
                if !lent
                    || count == 0
                    || count > block::MAX_SECTORS
                    || sector.checked_add(count).is_none_or(|end| end > d.sectors)
                {
                    return status(Status::Invalid);
                }
                // Reachable by the controller only until it is deleted,
                // before the reply; for a write, only for reading.
                let write = m[0] == block::WRITE;
                let op = match (write, d.ncq) {
                    (false, true) => ATA_READ_FPDMA,
                    (true, true) => ATA_WRITE_FPDMA,
                    (false, false) => ATA_READ_DMA_EXT,
                    (true, false) => ATA_WRITE_DMA_EXT,
                };
                match io_map(BUFFER, DOMAIN, !write) {
                    Ok(buffer) => status(self.status(i, op, sector, count, buffer)),
                    Err(_) => status(Status::Invalid),
                }
            }
            OP_CRASH if faults => crash("crashing (fault injection)"),
            OP_QUEUES if faults => {
                let used = (0..TAGS)
                    .filter(|&t| RUN[t].load(Ordering::SeqCst) > 0)
                    .fold(0, |m, t| m | 1 << t);
                [Status::Ok as u64, TAGS as u64, PEAK.load(Ordering::SeqCst), used]
            }
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

fn crash(why: &str) -> ! {
    say!("{why}");
    // SAFETY: deliberately not: nothing is mapped here, so this faults.
    let v = unsafe { ((USER_BASE + 0x6000_0000) as *const u64).read_volatile() };
    say!("[fail] read {v:#x} from a hole");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    if let Err((what, code)) = start(arg == 1) {
        say!("[fail] {what} ({code:#x})");
        loop {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
    }
    dispatch()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
