//! The Linux Driver Environment (spec section 5): hosts an unmodified
//! Linux device driver in a component of its own.
//!
//! The driver is Linux's source file, compiled as it is against this
//! crate's headers (`include/`), which give it Linux's kernel API by
//! name; `c/lde.c` implements that API for one PCI device and one network
//! interface; and this file is the host under both: it holds the
//! component's capabilities and does what touches the system. The driver
//! gets no more than a native one: the one function the PCI bus server
//! gives it (found from the driver's own ID table), that function's BAR
//! pages and interrupt line, and an IOMMU domain holding only this
//! component's memory pool.
//!
//! - Memory: a fixed pool of pages, made at the start and mapped both
//!   here and into the device's domain, so any buffer the driver hands
//!   the device (`dma_map_single`) already has a device address. Blocks
//!   of up to 2 KiB come from size classes and never cross a page; larger
//!   ones are whole pages in a row.
//! - Interrupts: the device's legacy line (`pci::INTX`), bound to the
//!   component's notification. The loop calls the driver's handler, then
//!   unmasks the line; the driver's NAPI poll runs from the loop, only
//!   while the receive queue has room for what it may deliver.
//! - One thread: handler, poll and transmit never run at once, so Linux's
//!   locks are empty.
//!
//! The component serves the `nic` interface by calls (`RECV`, `SEND`);
//! frame rings are still to come. Slots: 0 the bus server, 1 the `nic`
//! endpoint (receive), 2 a notification, 3 untyped memory (512 KiB), in a
//! CSpace of 2^7 slots.

#![no_std]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use superior_driver::{DmaPage, Failure, Pci, dma_barrier, irq_ack};
use superior_objects::abi::{CapTransfer, Error, Syscall, TICK_HZ};
use superior_objects::interfaces::{Status, nic};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const IRQ: u64 = 4;
const DOMAIN: u64 = 5;
/// Where a caller's frame arrives.
const LENT: u64 = 6;
/// The notification the caller attached.
const LISTENER: u64 = 7;
const BAR_SLOTS: u64 = 8;
const MAX_BAR_PAGES: u64 = 16;
const POOL: u64 = BAR_SLOTS + MAX_BAR_PAGES;
const POOL_PAGES: usize = 96;
const _: () = assert!(POOL + POOL_PAGES as u64 <= 128);
/// Every right, for keeping a granted capability.
const ALL: u64 = 0x1f;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const POOL_VA: u64 = USER_BASE + 0x5000_0000;
const LENT_VA: u64 = USER_BASE + 0x6000_0000;
const PAGE: usize = 4096;

/// Linux's `HZ` in the headers is the kernel's tick rate.
const _: () = assert!(TICK_HZ == 100);

// Linux's error numbers, as the headers have them.
const EBUSY: c_int = 16;
const EIO: c_int = 5;

unsafe extern "C" {
    fn lde_module_init() -> c_int;
    fn lde_device_id(i: c_uint, vendor: *mut u16, device: *mut u16) -> c_int;
    fn lde_probe(vendor: u16, device: u16, bars: u32) -> c_int;
    fn lde_open() -> c_int;
    fn lde_interrupt();
    fn lde_poll_pending() -> c_int;
    fn lde_poll_weight() -> c_int;
    fn lde_poll();
    fn lde_xmit(frame: *const c_void, len: usize) -> c_int;
    fn lde_tick();
    fn lde_mac(mac: *mut u8);
    fn lde_carrier() -> c_int;
}

/// Block sizes of the pool's classes: powers of two, so a block is
/// aligned to its size and lies within one page.
const CLASSES: [usize; 6] = [64, 128, 256, 512, 1024, 2048];
/// What a pool page is used for.
#[derive(Clone, Copy, PartialEq)]
enum Use {
    Free,
    /// Cut into blocks of class `.0`.
    Blocks(u8),
    /// The first of `.0` pages allocated together.
    Run(u16),
    /// A later page of a run.
    RunMore,
}

/// Received frames waiting for the caller.
const RX_FRAMES: usize = 32;
const RX_BYTES: usize = 1536;
const _: () = assert!(nic::MAX_FRAME as usize <= RX_BYTES);

struct Host {
    name: &'static str,
    /// The device: where it is, its memory BARs.
    location: u32,
    bars: u64,
    /// Each BAR's size, and whether its pages are mapped; pages mapped in
    /// all.
    bar_size: [u64; 6],
    bar_mapped: [bool; 6],
    bar_pages: u64,
    irq_taken: bool,
    /// The pool: each page's device address and use, and each class's
    /// list of free blocks (linked through their first words).
    dma: [u64; POOL_PAGES],
    used: [Use; POOL_PAGES],
    free: [*mut u8; CLASSES.len()],
    /// The receive queue: frames `rx_head .. rx_tail`.
    rx: [[u8; RX_BYTES]; RX_FRAMES],
    rx_len: [u16; RX_FRAMES],
    rx_head: usize,
    rx_tail: usize,
    rx_dropped: u64,
    attached: bool,
}

struct Cell(UnsafeCell<Host>);
// SAFETY: the component has one thread.
unsafe impl Sync for Cell {}
static HOST: Cell = Cell(UnsafeCell::new(Host {
    name: "",
    location: 0,
    bars: 0,
    bar_size: [0; 6],
    bar_mapped: [false; 6],
    bar_pages: 0,
    irq_taken: false,
    dma: [0; POOL_PAGES],
    used: [Use::Free; POOL_PAGES],
    free: [core::ptr::null_mut(); CLASSES.len()],
    rx: [[0; RX_BYTES]; RX_FRAMES],
    rx_len: [0; RX_FRAMES],
    rx_head: 0,
    rx_tail: 0,
    rx_dropped: 0,
    attached: false,
}));

/// The host's state. The driver calls back into the host while the host
/// calls the driver, so no reference from here is held across a call into
/// C: each use takes it afresh.
fn host() -> &'static mut Host {
    // SAFETY: one thread, and no caller keeps the reference across a call
    // that could take it again.
    unsafe { &mut *HOST.0.get() }
}

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("lde {}: {}", host().name, format_args!($($t)*))) };
}

fn pci() -> Pci {
    Pci { slot: PCI }
}

impl Host {
    fn page_of(&self, p: *const u8) -> Option<usize> {
        let at = (p as u64).checked_sub(POOL_VA)? as usize;
        (at < POOL_PAGES * PAGE).then_some(at / PAGE)
    }

    fn alloc(&mut self, size: usize) -> *mut u8 {
        let p = match CLASSES.iter().position(|&c| size <= c) {
            Some(class) => self.alloc_block(class),
            None => self.alloc_run(size.div_ceil(PAGE)),
        };
        if !p.is_null() {
            // SAFETY: `p` is a block or run of at least `size` bytes.
            unsafe { core::ptr::write_bytes(p, 0, size) };
        }
        p
    }

    fn alloc_block(&mut self, class: usize) -> *mut u8 {
        if self.free[class].is_null() {
            // Blocks take pages from the top, runs from the bottom, so
            // the runs find pages in a row.
            let Some(page) = (0..POOL_PAGES).rev().find(|&p| self.used[p] == Use::Free) else {
                return core::ptr::null_mut();
            };
            self.used[page] = Use::Blocks(class as u8);
            let base = POOL_VA as usize + page * PAGE;
            for at in (0..PAGE).step_by(CLASSES[class]) {
                self.release_block(class, (base + at) as *mut u8);
            }
        }
        let p = self.free[class];
        // SAFETY: a free block's first word is the next free block.
        self.free[class] = unsafe { (p as *mut *mut u8).read() };
        p
    }

    fn release_block(&mut self, class: usize, p: *mut u8) {
        // SAFETY: `p` is a whole free block of this class.
        unsafe { (p as *mut *mut u8).write(self.free[class]) };
        self.free[class] = p;
    }

    fn alloc_run(&mut self, pages: usize) -> *mut u8 {
        let fits = |first: usize| (first..first + pages).all(|p| self.used[p] == Use::Free);
        let Some(first) = (0..=POOL_PAGES.saturating_sub(pages)).find(|&p| fits(p)) else {
            return core::ptr::null_mut();
        };
        self.used[first] = Use::Run(pages as u16);
        for p in first + 1..first + pages {
            self.used[p] = Use::RunMore;
        }
        (POOL_VA as usize + first * PAGE) as *mut u8
    }

    fn release(&mut self, p: *mut u8) {
        let Some(page) = self.page_of(p) else {
            return;
        };
        match self.used[page] {
            Use::Blocks(class) => {
                let class = class as usize;
                // The start of the block, whatever in it `p` points at.
                let block = p as usize & !(CLASSES[class] - 1);
                self.release_block(class, block as *mut u8);
            }
            Use::Run(pages) => {
                for q in page..page + pages as usize {
                    self.used[q] = Use::Free;
                }
            }
            Use::Free | Use::RunMore => {}
        }
    }

    /// The device's address for `size` bytes at `p`, if they are in the
    /// pool and in a row for the device too.
    fn dma_of(&self, p: *const u8, size: usize) -> Option<u64> {
        let first = self.page_of(p)?;
        let last = self.page_of(p.wrapping_add(size.max(1) - 1))?;
        for q in first..last {
            if self.dma[q + 1] != self.dma[q] + PAGE as u64 {
                return None;
            }
        }
        Some(self.dma[first] + (p as u64 & (PAGE as u64 - 1)))
    }

    fn rx_waiting(&self) -> usize {
        self.rx_tail - self.rx_head
    }
}

// ---- what lde.c asks of the host (lde/host.h)

#[unsafe(no_mangle)]
extern "C" fn lde_host_alloc(size: usize) -> *mut c_void {
    host().alloc(size) as *mut c_void
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_free(p: *const c_void) {
    host().release(p as *mut u8)
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_dma(p: *const c_void, size: usize) -> u64 {
    host().dma_of(p as *const u8, size).unwrap_or(u64::MAX)
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_log(line: *const c_char, len: usize) {
    // SAFETY: lde.c passes `len` bytes of its line buffer.
    let bytes = unsafe { core::slice::from_raw_parts(line as *const u8, len) };
    say!("{}", core::str::from_utf8(bytes).unwrap_or("(a line that is not text)"));
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_config_read(offset: c_uint) -> u32 {
    pci().config_read(offset as u64 & !3).unwrap_or(!0)
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_location() -> u32 {
    host().location
}

fn bar_va(bar: usize) -> u64 {
    BAR_VA + bar as u64 * MAX_BAR_PAGES * PAGE as u64
}

/// Maps memory BAR `bar` whole, once. False if it cannot be.
fn map_bar(bar: usize) -> bool {
    if bar >= 6 || host().bars & 1 << bar == 0 {
        return false;
    }
    if host().bar_mapped[bar] {
        return true;
    }
    let mut page = 0;
    loop {
        let at = host().bar_pages;
        if at == MAX_BAR_PAGES {
            say!("[fail] BAR {bar} needs more than {MAX_BAR_PAGES} pages mapped");
            return false;
        }
        match pci().map_bar_page(bar as u64, page, BAR_SLOTS + at, bar_va(bar) + page * PAGE as u64) {
            Ok(size) => {
                let h = host();
                h.bar_pages += 1;
                h.bar_size[bar] = size;
                page += 1;
                if page * PAGE as u64 >= size {
                    h.bar_mapped[bar] = true;
                    return true;
                }
            }
            Err((what, code)) => {
                say!("[fail] BAR {bar}: {what} ({code:#x})");
                return false;
            }
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_bar_size(bar: c_uint) -> u64 {
    if map_bar(bar as usize) { host().bar_size[bar as usize] } else { 0 }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_bar_map(bar: c_uint) -> *mut c_void {
    if map_bar(bar as usize) {
        bar_va(bar as usize) as *mut c_void
    } else {
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_bus_master(on: c_int) -> c_int {
    match pci().bus_master(on != 0) {
        Ok(()) => 0,
        Err(_) => -EIO,
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_irq(on: c_int) -> c_int {
    if on == 0 || host().irq_taken {
        // Released lines stay bound: nothing calls the handler lde.c
        // has dropped.
        return 0;
    }
    match pci().intx(IRQ, NOTIFY) {
        Ok(wire) => {
            host().irq_taken = true;
            say!("the device's legacy interrupt line (wire {wire}) is the driver's");
            0
        }
        Err((what, code)) => {
            say!("[fail] the interrupt line: {what} ({code:#x})");
            -EBUSY
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_jiffies() -> c_ulong {
    superior_sys::ticks() as c_ulong
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_sleep(ticks: c_ulong) {
    let end = superior_sys::ticks() + ticks as u64;
    // The interrupt's notification may cut a sleep short.
    while superior_sys::ticks() < end {
        superior_sys::sleep(end - superior_sys::ticks());
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_udelay(usecs: c_ulong) {
    // No clock is fine enough: spin for at least as long on any machine
    // these run on.
    for _ in 0..usecs as u64 * 200 {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_wmb() {
    dma_barrier();
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_rx(frame: *const c_void, len: usize) {
    let h = host();
    if !(14..=nic::MAX_FRAME as usize).contains(&len) || h.rx_waiting() == RX_FRAMES {
        h.rx_dropped += 1;
        return;
    }
    let i = h.rx_tail % RX_FRAMES;
    // SAFETY: lde.c passes `len` bytes of a socket buffer; they fit.
    unsafe { core::ptr::copy_nonoverlapping(frame as *const u8, h.rx[i].as_mut_ptr(), len) };
    h.rx_len[i] = len as u16;
    h.rx_tail += 1;
}

// ---- the component

fn start() -> Result<(), Failure> {
    // SAFETY: the driver's module initialisation, once, first.
    if unsafe { lde_module_init() } != 0 {
        return Err(("the driver's module initialisation failed", 0));
    }
    // The device: the first the bus server has of those the driver's own
    // table names.
    let mut found = None;
    for i in 0.. {
        let (mut vendor, mut device) = (0u16, 0u16);
        // SAFETY: both pointers are to locals.
        if unsafe { lde_device_id(i, &mut vendor, &mut device) } == 0 {
            break;
        }
        match pci().open(vendor, device, 0, DOMAIN) {
            Ok((location, bars)) => {
                found = Some((vendor, device, location, bars));
                break;
            }
            Err((_, code)) if code == Status::NotFound as u64 => {}
            Err(e) => return Err(e),
        }
    }
    let Some((vendor, device, location, bars)) = found else {
        return Err(("the bus server has no device this driver names", 0));
    };
    {
        let h = host();
        h.location = location as u32;
        h.bars = bars;
    }
    for p in 0..POOL_PAGES {
        let va = POOL_VA + (p * PAGE) as u64;
        host().dma[p] = DmaPage::new(UNTYPED, POOL + p as u64, va, DOMAIN)?.dma;
    }
    say!(
        "{vendor:04x}:{device:04x} at {:02x}:{:02x}.{} opened; {} KiB for the driver, all of it and nothing else in the device's IOMMU domain",
        location >> 8,
        location >> 3 & 0x1f,
        location & 7,
        POOL_PAGES * PAGE / 1024
    );
    // SAFETY: the driver's probe, after its module initialisation.
    let rc = unsafe { lde_probe(vendor, device, bars as u32) };
    if rc != 0 {
        return Err(("the driver's probe failed, errno", -rc as u64));
    }
    // SAFETY: the interface the probe registered is brought up.
    let rc = unsafe { lde_open() };
    if rc != 0 {
        return Err(("the driver could not bring the interface up, errno", -rc as u64));
    }
    Ok(())
}

fn mac() -> u64 {
    let mut m = [0u8; 6];
    // SAFETY: six bytes.
    unsafe { lde_mac(m.as_mut_ptr()) };
    m.iter().fold(0, |a, &b| a << 8 | b as u64)
}

/// Runs the driver's receive poll while it has work and the queue has
/// room for all one poll may deliver, then tells the caller of frames.
fn pump() {
    let before = host().rx_waiting();
    // SAFETY: lde.c's, from the one thread.
    unsafe {
        let weight = lde_poll_weight() as usize;
        while lde_poll_pending() != 0 && host().rx_waiting() + weight <= RX_FRAMES {
            lde_poll();
        }
    }
    let h = host();
    if h.attached && h.rx_waiting() > before {
        syscall(Syscall::Signal, LISTENER, [0; 4]);
    }
}

fn recv() -> [u64; 4] {
    let attached = host().attached as u64;
    let h = host();
    if h.rx_waiting() == 0 {
        return [Status::Empty as u64, 0, attached, 0];
    }
    if syscall(Syscall::FrameMap, LENT, [LENT_VA, 1, 0, 0]).status != 0 {
        return [Status::Invalid as u64, 0, attached, 0];
    }
    let i = h.rx_head % RX_FRAMES;
    let len = h.rx_len[i] as usize;
    // SAFETY: the lent page is mapped and a frame fits in it.
    unsafe { core::ptr::copy_nonoverlapping(h.rx[i].as_ptr(), LENT_VA as *mut u8, len) };
    h.rx_head += 1;
    [Status::Ok as u64, len as u64, attached, 0]
}

fn send(len: u64) -> Status {
    if !(14..=nic::MAX_FRAME).contains(&len) {
        return Status::Invalid;
    }
    if syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
        return Status::Invalid;
    }
    for attempt in 0..2 {
        // SAFETY: the lent page is mapped; lde.c copies the frame.
        match unsafe { lde_xmit(LENT_VA as *const c_void, len as usize) } {
            0 => return Status::Ok,
            1 if attempt == 0 => {
                // The driver's queue is full: let it see what the device
                // has sent since its last interrupt, and try once more.
                // SAFETY: lde.c's, from the one thread.
                unsafe {
                    lde_interrupt();
                    lde_tick();
                }
            }
            1 => return Status::NoSpace,
            _ => return Status::DeviceError,
        }
    }
    Status::NoSpace
}

fn serve(m: [u64; 4], lent: bool, cap: Option<u16>) -> [u64; 4] {
    let status = |s: Status| [s as u64, 0, 0, 0];
    match m[0] {
        nic::INFO if m[1] == nic::VERSION => [Status::Ok as u64, mac(), nic::MAX_FRAME, 0],
        nic::ATTACH if cap == Some(LISTENER as u16) => {
            host().attached = true;
            // Frames may already be waiting.
            if host().rx_waiting() > 0 {
                syscall(Syscall::Signal, LISTENER, [0; 4]);
            }
            status(Status::Ok)
        }
        nic::RECV if lent => recv(),
        nic::SEND if lent => status(send(m[1])),
        _ => status(Status::Invalid),
    }
}

/// Runs the Linux driver linked into this component, serving `nic`.
/// `name` is the driver's, for the log.
pub fn run(name: &'static str) -> ! {
    host().name = name;
    if let Err((what, code)) = start() {
        say!("[fail] {what} ({code:#x})");
        superior_sys::park()
    }
    let m = mac();
    say!(
        "Linux's {name} driver runs the interface: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
        m >> 40 & 0xff,
        m >> 32 & 0xff,
        m >> 24 & 0xff,
        m >> 16 & 0xff,
        m >> 8 & 0xff,
        m & 0xff,
        // SAFETY: lde.c's, from the one thread.
        if unsafe { lde_carrier() } != 0 { "up" } else { "down" }
    );
    // The interrupt wakes the same `Recv` that waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the interrupt's notification");
    }
    // A call may lend a frame (RECV, SEND) or grant a notification
    // (ATTACH): either arrives in LENT.
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut reply: Option<[u64; 4]> = None;
    loop {
        pump();
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            // The driver's handler quiets the device (it masks what it
            // leaves for the poll), so the line can be unmasked after.
            // SAFETY: lde.c's, from the one thread.
            unsafe { lde_interrupt() };
            irq_ack(IRQ);
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let mut cap = r.cap;
        if r.msg[0] == nic::ATTACH && cap == Some(LENT as u16) {
            // Keep the notification (replacing an earlier one).
            syscall(Syscall::CapDelete, LISTENER, [0; 4]);
            let kept = syscall(Syscall::CapMint, LENT, [LISTENER, ALL, 0, 0]).status == 0;
            syscall(Syscall::CapDelete, LENT, [0; 4]);
            cap = kept.then_some(LISTENER as u16);
        }
        let lent = cap == Some(LENT as u16);
        let m = serve(r.msg, lent, cap);
        if lent {
            // The caller's frame goes back before the reply.
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}
