//! The Linux Driver Environment (spec section 5): hosts an unmodified
//! Linux device driver in a component of its own.
//!
//! The driver is Linux's source file, compiled as it is against this
//! crate's headers (`include/`), which give it Linux's kernel API by
//! name; `c/` implements that API (`lde.c` for every driver, `lde-net.c`
//! for a network driver's interface, `lde-drm.c` for a display driver's
//! DRM device); and this crate is the host under them: it holds the
//! component's capabilities and does what touches the system. The driver
//! gets no more than a native one: the one function the PCI bus server
//! gives it (found from the driver's own ID table), that function's BARs
//! and interrupt line, and an IOMMU domain holding only this component's
//! memory pool.
//!
//! - Memory: a fixed pool of pages, made at the start and mapped both
//!   here and into the device's domain, so any buffer the driver hands
//!   the device (`dma_map_single`) already has a device address. Blocks
//!   of up to 2 KiB come from size classes and never cross a page; larger
//!   ones are whole pages in a row.
//! - Registers: a BAR of up to 16 pages is mapped a page at a time; a
//!   larger one (a video card's memory) whole, as one frame (`pci::BAR_FRAME`).
//! - Interrupts: the device's legacy line (`pci::INTX`), bound to the
//!   component's notification. The loop calls the driver's handler, then
//!   unmasks the line.
//! - One thread: the driver's handler and every call into it run one
//!   after another, so Linux's locks are empty. Its kernel timers and work
//!   run from the loop too: it sleeps no longer than until the next timer
//!   is due.
//! - What there is none of fails as Linux would have it fail: firmware
//!   files (`request_firmware` finds none), ethtool and MII ioctls, legacy
//!   I/O ports.
//!
//! What the component serves depends on the driver's class: a network
//! driver serves `nic` ([`run`], in [`net`]), a display driver serves
//! `display` ([`run_display`], in [`display`]). Slots: 0 the bus server, 1
//! the endpoint it serves (receive), 2 a notification, 3 untyped memory
//! (1 MiB); the rest are the host's.

#![no_std]

mod display;
mod net;

pub use display::run as run_display;
pub use net::run;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use superior_driver::{DmaPage, Failure, Pci, dma_barrier};
use superior_objects::abi::TICK_HZ;
use superior_objects::interfaces::Status;
use superior_sys::{USER_BASE, print_line};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const IRQ: u64 = 4;
const DOMAIN: u64 = 5;
/// Where a caller's lent page or granted capability arrives.
const LENT: u64 = 6;
/// The notification a caller attached.
const LISTENER: u64 = 7;
const BAR_SLOTS: u64 = 8;
const MAX_BAR_PAGES: u64 = 16;
const POOL: u64 = BAR_SLOTS + MAX_BAR_PAGES;
/// Enough for a driver that keeps 256 receive buffers of 2 KiB (e100).
const POOL_PAGES: usize = 192;
/// A whole-BAR frame for each BAR mapped whole.
const BIG_BARS: u64 = POOL + POOL_PAGES as u64;
/// The first slot the class's host ([`net`], [`display`]) has to itself.
const CLASS_SLOTS: u64 = BIG_BARS + 6;
/// Every right, for keeping a granted capability.
const ALL: u64 = 0x1f;
const WRITE: u64 = 2;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const POOL_VA: u64 = USER_BASE + 0x5000_0000;
/// Where the class's host maps what it is lent.
const LENT_VA: u64 = USER_BASE + 0x6000_0000;
const CLASS_VA: u64 = USER_BASE + 0x7000_0000;
/// BARs mapped whole: 1 GiB apart, the largest a device frame may be.
const BIG_BAR_VA: u64 = USER_BASE + 0x1_0000_0000;
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
    fn lde_interrupt();
    fn lde_run_timers();
    fn lde_next_timer() -> c_ulong;
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

struct Host {
    name: &'static str,
    /// The device: where it is, its memory BARs.
    location: u32,
    bars: u64,
    /// Each BAR's size, and how many of its pages are mapped; pages
    /// mapped in all; the BARs mapped whole.
    bar_size: [u64; 6],
    bar_mapped: [u64; 6],
    bar_pages: u64,
    bar_whole: u8,
    irq_taken: bool,
    /// What `udelay` counts: cycle-counter steps in a microsecond.
    cycles_per_usec: u64,
    /// The pool: each page's device address and use, and each class's
    /// list of free blocks (linked through their first words).
    dma: [u64; POOL_PAGES],
    used: [Use; POOL_PAGES],
    free: [*mut u8; CLASSES.len()],
}

struct Cell(UnsafeCell<Host>);
// SAFETY: the component has one thread.
unsafe impl Sync for Cell {}
static HOST: Cell = Cell(UnsafeCell::new(Host {
    name: "",
    location: 0,
    bars: 0,
    bar_size: [0; 6],
    bar_mapped: [0; 6],
    bar_pages: 0,
    bar_whole: 0,
    irq_taken: false,
    cycles_per_usec: 0,
    dma: [0; POOL_PAGES],
    used: [Use::Free; POOL_PAGES],
    free: [core::ptr::null_mut(); CLASSES.len()],
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
    ($($t:tt)*) => { $crate::print_line(format_args!("lde {}: {}", $crate::host().name, format_args!($($t)*))) };
}
pub(crate) use say;

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
    // 16 MiB apart: the six stay clear of the pool's addresses.
    BAR_VA + bar as u64 * 0x100_0000
}

/// Maps memory BAR `bar` as far as its page `upto` (to the end of the BAR
/// with `None`), a page at a time, unless it is already. False if it
/// cannot be.
fn map_bar(bar: usize, upto: Option<u64>) -> bool {
    if bar >= 6 || host().bars & 1 << bar == 0 {
        return false;
    }
    loop {
        let h = host();
        let page = h.bar_mapped[bar];
        // The size is known once the first page is mapped.
        let pages = if page == 0 { 1 } else { h.bar_size[bar].div_ceil(PAGE as u64) };
        if page >= upto.map_or(pages, |u| (u + 1).min(pages)) {
            return true;
        }
        let at = h.bar_pages;
        if at == MAX_BAR_PAGES {
            say!("[fail] BAR {bar} needs more than {MAX_BAR_PAGES} pages mapped");
            return false;
        }
        match pci().map_bar_page(bar as u64, page, BAR_SLOTS + at, bar_va(bar) + page * PAGE as u64) {
            Ok(size) => {
                let h = host();
                h.bar_pages += 1;
                h.bar_size[bar] = size;
                h.bar_mapped[bar] += 1;
            }
            Err((what, code)) => {
                say!("[fail] BAR {bar}: {what} ({code:#x})");
                return false;
            }
        }
    }
}

/// Where all of memory BAR `bar` is mapped, mapping it first: a page at
/// a time if it is small, else whole, as one frame.
fn bar_base(bar: usize) -> Option<u64> {
    // Its first page tells the size.
    if !map_bar(bar, Some(0)) {
        return None;
    }
    if host().bar_size[bar] <= MAX_BAR_PAGES * PAGE as u64 {
        return map_bar(bar, None).then(|| bar_va(bar));
    }
    let va = BIG_BAR_VA + ((bar as u64) << 30);
    if host().bar_whole & 1 << bar == 0 {
        match pci().map_bar(bar as u64, BIG_BARS + bar as u64, va) {
            Ok(size) => {
                host().bar_whole |= 1 << bar;
                say!("BAR {bar} ({} KiB) mapped whole, as one frame", size / 1024);
            }
            Err((what, code)) => {
                say!("[fail] BAR {bar}: {what} ({code:#x})");
                return None;
            }
        }
    }
    Some(va)
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_bar_size(bar: c_uint) -> u64 {
    // Its first page tells the size; the rest is mapped when asked for.
    if map_bar(bar as usize, Some(0)) { host().bar_size[bar as usize] } else { 0 }
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_bar_map(bar: c_uint) -> *mut c_void {
    bar_base(bar as usize).map_or(core::ptr::null_mut(), |va| va as *mut c_void)
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
    // The tick is too coarse: the cycle counter, measured against it
    // at the start.
    let per_usec = host().cycles_per_usec.max(1);
    let end = superior_sys::cycles().wrapping_add(usecs as u64 * per_usec);
    while (end.wrapping_sub(superior_sys::cycles()) as i64) > 0 {}
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_wmb() {
    dma_barrier();
}

// ---- the component

/// Measures the cycle counter against the tick: from one tick's edge to
/// the next but one.
fn calibrate() {
    let edge = |from: u64| loop {
        let t = superior_sys::ticks();
        if t != from {
            break (t, superior_sys::cycles());
        }
    };
    let (t0, c0) = edge(superior_sys::ticks());
    let (_, c1) = edge(t0 + 1);
    let (_, c1) = if c1 == c0 { edge(t0 + 2) } else { (0, c1) };
    // Two ticks of 1,000,000 / TICK_HZ microseconds each.
    host().cycles_per_usec = c1.wrapping_sub(c0) / (2 * 1_000_000 / TICK_HZ);
}

/// Loads the driver and runs its probe on the first device the bus server
/// has of those the driver's own table names.
fn start(name: &'static str) -> Result<(), Failure> {
    host().name = name;
    calibrate();
    // SAFETY: the driver's module initialisation, once, first.
    if unsafe { lde_module_init() } != 0 {
        return Err(("the driver's module initialisation failed", 0));
    }
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
    // A driver killed in the middle of something (reading the EEPROM a
    // bit at a time, say) leaves the device there, and there is no reset
    // to give it: the probe that runs into that fails, and in failing
    // ends what was left open. So a failed probe is tried once more.
    let mut rc = 0;
    for attempt in 0..2 {
        // SAFETY: the driver's probe, after its module initialisation.
        rc = unsafe { lde_probe(vendor, device, bars as u32) };
        if rc == 0 {
            break;
        }
        if attempt == 0 {
            say!("the driver's probe failed (errno {}): trying once more", -rc);
        }
    }
    if rc != 0 {
        return Err(("the driver's probe failed, errno", -rc as u64));
    }
    Ok(())
}
