//! A virtio GPU driver (virtio 1.x over PCI, 2D only), serving the
//! `display` interface (`superior_objects::idl::display`) with a cursor
//! plane.
//!
//! The caller's surface is the scanout's memory itself: each page it lends
//! (`ATTACH`) is mapped into the device's IOMMU domain, read-only, and
//! `SET_MODE` makes a host resource of the mode's size backed by them and
//! shows it on scanout 0. A `FLUSH` has the device copy the rectangle from
//! the pages into its resource and show it (`TRANSFER_TO_HOST_2D`, then
//! `RESOURCE_FLUSH`): nothing is copied by the driver, and the screen
//! changes whole, so there is one framebuffer, not two.
//!
//! The cursor plane is the device's cursor queue: a 64x64 resource whose
//! backing is four pages of the driver's own, into which `CURSOR` copies
//! the caller's 32x32 picture; `MOVE_CURSOR` moves it, or hides it, with
//! no flush. The host draws it over the scanout (a screenshot of the
//! scanout does not show it).
//!
//! Commands run one at a time on each queue, the driver waiting for the
//! device to hand the buffers back (it polls: no interrupt is needed).
//! On start, and so after every restart, it resets the device itself, as
//! virtio requires, which forgets every resource; the caller lends its
//! surface again when a flush is refused.
//!
//! Slots: 0 the bus server, 1 the `display` endpoint (receive), 2 a
//! notification (unused), 3 untyped memory.

#![no_std]
#![no_main]

use superior_driver::virtq::{self, Queue};
use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_barrier, io_map, map};
use superior_objects::abi::{CapTransfer, Syscall};
use superior_objects::idl::display;
use superior_objects::interfaces::Status;
use superior_sys::{USER_BASE, print_line, syscall, syscall_x, ticks};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 3;
const CONTROLQ: u64 = 4;
const CURSORQ: u64 = 5;
const REQUEST: u64 = 6;
const DOMAIN: u64 = 7;
/// Four pages of backing entries (256 a page: the surface's 1024 pages).
const ENTRIES: u64 = 8;
const ENTRY_PAGES: u64 = 4;
/// Four pages of the cursor's 64x64 picture.
const IMAGE: u64 = ENTRIES + ENTRY_PAGES;
const IMAGE_PAGES: u64 = 4;
/// Where a lent page arrives.
const LENT: u64 = IMAGE + IMAGE_PAGES;
const BAR_SLOTS: u64 = 20;
const MAX_BAR_PAGES: u64 = 16;
/// The surface's pages, kept while it is attached.
const SURFACE: u64 = 64;
const _: () = assert!(BAR_SLOTS + MAX_BAR_PAGES <= SURFACE);
const _: () = assert!(SURFACE + display::SURFACE_PAGES <= 2048);

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const QUEUE_VA: u64 = USER_BASE + 0x5000_0000;
const CURSORQ_VA: u64 = QUEUE_VA + 0x1000;
const REQUEST_VA: u64 = QUEUE_VA + 0x2000;
const ENTRIES_VA: u64 = QUEUE_VA + 0x3000;
const IMAGE_VA: u64 = ENTRIES_VA + ENTRY_PAGES * 0x1000;
const LENT_VA: u64 = IMAGE_VA + IMAGE_PAGES * 0x1000;

/// All rights, for a copy of a lent page.
const ALL: u64 = 0x1f;
const PAGE: u64 = 4096;
/// Ticks to wait for the device to hand a buffer back.
const TIMEOUT: u64 = 500;

// virtio PCI capabilities (vendor-specific, id 9) and their types.
const CAP_VENDOR: u8 = 0x09;
const COMMON: u8 = 1;
const NOTIFY_CFG: u8 = 2;

// The common configuration structure.
const DEVICE_FEATURE_SELECT: u64 = 0;
const DEVICE_FEATURE: u64 = 4;
const DRIVER_FEATURE_SELECT: u64 = 8;
const DRIVER_FEATURE: u64 = 12;
const CONFIG_MSIX_VECTOR: u64 = 16;
const DEVICE_STATUS: u64 = 20;
const QUEUE_SELECT: u64 = 22;
const QUEUE_SIZE: u64 = 24;
const QUEUE_MSIX_VECTOR: u64 = 26;
const QUEUE_ENABLE: u64 = 28;
const QUEUE_NOTIFY_OFF: u64 = 30;
const QUEUE_DESC: u64 = 32;
const QUEUE_DRIVER: u64 = 40;
const QUEUE_DEVICE: u64 = 48;

const ACKNOWLEDGE: u8 = 1;
const DRIVER: u8 = 2;
const DRIVER_OK: u8 = 4;
const FEATURES_OK: u8 = 8;
const NO_VECTOR: u16 = 0xffff;
/// Feature 33, in the high feature word.
const ACCESS_PLATFORM: u32 = 1 << 1;

// virtio-gpu commands (virtio 1.2, 5.7.6) and responses.
const GET_DISPLAY_INFO: u32 = 0x0100;
const RESOURCE_CREATE_2D: u32 = 0x0101;
const RESOURCE_UNREF: u32 = 0x0102;
const SET_SCANOUT: u32 = 0x0103;
const RESOURCE_FLUSH: u32 = 0x0104;
const TRANSFER_TO_HOST_2D: u32 = 0x0105;
const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const UPDATE_CURSOR: u32 = 0x0300;
const MOVE_CURSOR: u32 = 0x0301;
const OK_NODATA: u32 = 0x1100;
const OK_DISPLAY_INFO: u32 = 0x1101;
/// Pixel formats: XRGB8888 and ARGB8888 as little-endian words are these
/// bytes in order.
const B8G8R8X8: u32 = 2;
const B8G8R8A8: u32 = 1;

/// The resources: the scanout's and the cursor's.
const SCANOUT_RESOURCE: u32 = 1;
const CURSOR_RESOURCE: u32 = 2;
/// The device's cursor size.
const CURSOR_DEVICE_SIDE: u64 = 64;

/// Where in the request page a control command goes, its response, and a
/// cursor command.
const COMMAND: u64 = 0;
const RESPONSE: u64 = 2048;
const CURSOR_COMMAND: u64 = 3072;
/// A command header's size.
const HEADER: u64 = 24;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("virtio-gpu: {}", format_args!($($t)*))) };
}

struct Gpu {
    pci: Pci,
    common: Mmio,
    notify_base: u64,
    multiplier: u64,
    control: Queue,
    control_notify: u64,
    cursor: Queue,
    cursor_notify: u64,
    request: DmaPage,
    entries: [DmaPage; ENTRY_PAGES as usize],
    image: [DmaPage; IMAGE_PAGES as usize],
    /// Scanout 0's size.
    width: u32,
    height: u32,
    /// The surface's pages attached, and their device addresses.
    pages: u64,
    dma: [u64; display::SURFACE_PAGES as usize],
    /// The mode shown (the scanout resource exists), and flushes since.
    shown: bool,
    flushes: u64,
    /// The cursor: its picture set, its hot spot, where its point is,
    /// whether it is shown, and moves so far.
    has_cursor: bool,
    hot: (u32, u32),
    at: (u32, u32),
    cursor_shown: bool,
    moves: u64,
}

/// Maps BAR pages as needed, one slot each.
struct Bars {
    pci: Pci,
    mapped: [u16; 6],
    next_slot: u64,
}

impl Bars {
    fn va(bar: u64, off: u64) -> u64 {
        BAR_VA + bar * 0x10_0000 + off
    }

    /// Maps `len` bytes at `off` in BAR `bar`; returns their address.
    fn map(&mut self, bar: u64, off: u64, len: u64) -> Result<u64, Failure> {
        if bar >= 6 || off + len > 16 * PAGE {
            return Err(("a register block outside what the driver maps", bar));
        }
        for page in off / PAGE..=(off + len.max(1) - 1) / PAGE {
            if self.mapped[bar as usize] & 1 << page != 0 {
                continue;
            }
            if self.next_slot == BAR_SLOTS + MAX_BAR_PAGES {
                return Err(("too many BAR pages", 0));
            }
            self.pci.map_bar_page(bar, page, self.next_slot, Self::va(bar, page * PAGE))?;
            self.next_slot += 1;
            self.mapped[bar as usize] |= 1 << page;
        }
        Ok(Self::va(bar, off))
    }
}

/// The word at `off` in the page mapped at `va`.
fn put32(va: u64, off: u64, v: u32) {
    // SAFETY: callers pass a page of the driver's own and an offset in it.
    unsafe { ((va + off) as *mut u32).write_volatile(v) }
}

fn put64(va: u64, off: u64, v: u64) {
    // SAFETY: as for `put32`.
    unsafe { ((va + off) as *mut u64).write_volatile(v) }
}

fn get32(va: u64, off: u64) -> u32 {
    // SAFETY: as for `put32`.
    unsafe { ((va + off) as *const u32).read_volatile() }
}

fn start() -> Result<Gpu, Failure> {
    let pci = Pci { slot: PCI };
    // virtio device 16: the GPU.
    let (bdf, _) = pci.open(0x1af4, 0x1050, 0, DOMAIN)?;
    let mut bars = Bars { pci: Pci { slot: PCI }, mapped: [0; 6], next_slot: BAR_SLOTS };
    let (mut common, mut notify) = (None, None);
    let mut at = 0;
    while let Some(cap) = pci.find_capability(CAP_VENDOR, at)? {
        at = cap;
        let kind = pci.config_read8(cap + 3)?;
        let bar = pci.config_read8(cap + 4)? as u64;
        let off = pci.config_read(cap + 8)? as u64;
        let len = pci.config_read(cap + 12)? as u64;
        match kind {
            COMMON => common = Some(bars.map(bar, off, len)?),
            NOTIFY_CFG => {
                let multiplier = pci.config_read(cap + 16)? as u64;
                notify = Some((bars.map(bar, off, len)?, multiplier));
            }
            _ => {}
        }
    }
    let (Some(common), Some((notify_base, multiplier))) = (common, notify) else {
        return Err(("not a virtio 1.x device", 0));
    };
    let control = Queue::new(DmaPage::new(UNTYPED, CONTROLQ, QUEUE_VA, DOMAIN)?);
    let cursor = Queue::new(DmaPage::new(UNTYPED, CURSORQ, CURSORQ_VA, DOMAIN)?);
    let request = DmaPage::new(UNTYPED, REQUEST, REQUEST_VA, DOMAIN)?;
    let mut entries = [request; ENTRY_PAGES as usize];
    for (k, e) in entries.iter_mut().enumerate() {
        *e = DmaPage::new(UNTYPED, ENTRIES + k as u64, ENTRIES_VA + k as u64 * PAGE, DOMAIN)?;
    }
    let mut image = [request; IMAGE_PAGES as usize];
    for (k, p) in image.iter_mut().enumerate() {
        *p = DmaPage::new(UNTYPED, IMAGE + k as u64, IMAGE_VA + k as u64 * PAGE, DOMAIN)?;
    }
    let mut gpu = Gpu {
        pci,
        common: Mmio { base: common },
        notify_base,
        multiplier,
        control,
        control_notify: 0,
        cursor,
        cursor_notify: 0,
        request,
        entries,
        image,
        width: 0,
        height: 0,
        pages: 0,
        dma: [0; display::SURFACE_PAGES as usize],
        shown: false,
        flushes: 0,
        has_cursor: false,
        hot: (0, 0),
        at: (0, 0),
        cursor_shown: false,
        moves: 0,
    };
    gpu.init()?;
    say!(
        "ready: {:02x}:{:02x}.{}, scanout 0 is {}x{}, a 64x64 cursor plane",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
        gpu.width,
        gpu.height
    );
    Ok(gpu)
}

impl Gpu {
    /// Resets the device and brings it up (virtio 1.x, 3.1.1), then asks
    /// for scanout 0's size and makes the cursor's resource.
    fn init(&mut self) -> Result<(), Failure> {
        let common = self.common;
        common.write8(DEVICE_STATUS, 0);
        while common.read8(DEVICE_STATUS) != 0 {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        common.write8(DEVICE_STATUS, ACKNOWLEDGE);
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER);
        common.write32(DEVICE_FEATURE_SELECT, 1);
        if common.read32(DEVICE_FEATURE) & 1 == 0 {
            return Err(("the device does not offer VERSION_1", 0));
        }
        // VERSION_1 (feature 32) and ACCESS_PLATFORM (33) if offered; none
        // of the GPU's own (no 3D, no EDID).
        let high = common.read32(DEVICE_FEATURE) & ACCESS_PLATFORM;
        common.write32(DRIVER_FEATURE_SELECT, 0);
        common.write32(DRIVER_FEATURE, 0);
        common.write32(DRIVER_FEATURE_SELECT, 1);
        common.write32(DRIVER_FEATURE, 1 | high);
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        if common.read8(DEVICE_STATUS) & FEATURES_OK == 0 {
            return Err(("the device refused the features", 0));
        }
        common.write16(CONFIG_MSIX_VECTOR, NO_VECTOR);
        for q in 0..2u16 {
            let queue = if q == 0 { &mut self.control } else { &mut self.cursor };
            queue.reset();
            common.write16(QUEUE_SELECT, q);
            let max = common.read16(QUEUE_SIZE);
            if max < virtq::SIZE {
                return Err(("a queue is too small", max as u64));
            }
            common.write16(QUEUE_SIZE, virtq::SIZE);
            common.write16(QUEUE_MSIX_VECTOR, NO_VECTOR);
            let (desc, driver, used) = queue.addresses();
            common.write64(QUEUE_DESC, desc);
            common.write64(QUEUE_DRIVER, driver);
            common.write64(QUEUE_DEVICE, used);
            let at = self.notify_base + common.read16(QUEUE_NOTIFY_OFF) as u64 * self.multiplier;
            if q == 0 {
                self.control_notify = at;
            } else {
                self.cursor_notify = at;
            }
            common.write16(QUEUE_ENABLE, 1);
        }
        self.pci.bus_master(true)?;
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK);

        self.header(GET_DISPLAY_INFO);
        self.command(HEADER, 0, OK_DISPLAY_INFO)?;
        // The first of 16 displays: a rectangle, then whether it is on.
        let r = self.request.va + RESPONSE + HEADER;
        (self.width, self.height) = (get32(r, 8), get32(r, 12));
        if get32(r, 16) == 0 || self.width == 0 || self.height == 0 {
            return Err(("scanout 0 is off", 0));
        }

        // The cursor's resource, backed by the driver's four pages.
        self.create(CURSOR_RESOURCE, B8G8R8A8, CURSOR_DEVICE_SIDE as u32, CURSOR_DEVICE_SIDE as u32)?;
        let image = self.image;
        self.attach_backing(CURSOR_RESOURCE, image.iter().map(|p| p.dma), IMAGE_PAGES)?;
        (self.shown, self.has_cursor, self.cursor_shown) = (false, false, false);
        Ok(())
    }

    /// Starts a command in the request page: its header, type `kind`.
    fn header(&self, kind: u32) {
        let va = self.request.va + COMMAND;
        for off in (0..HEADER).step_by(8) {
            put64(va, off, 0);
        }
        put32(va, 0, kind);
    }

    /// Runs the control command in the request page (`len` bytes), with
    /// `entries` bytes of backing entries after it: whether the device
    /// answered `want`.
    fn command(&mut self, len: u64, entries: u64, want: u32) -> Result<(), Failure> {
        let r = self.request;
        put32(r.va, RESPONSE, 0);
        let q = &mut self.control;
        q.set(0, r.dma + COMMAND, len as u32, virtq::NEXT);
        let mut d = 1;
        let mut left = entries;
        for page in self.entries {
            if left == 0 {
                break;
            }
            let n = left.min(PAGE);
            q.set(d, page.dma, n as u32, virtq::NEXT);
            (d, left) = (d + 1, left - n);
        }
        q.set(d, r.dma + RESPONSE, (PAGE - RESPONSE - 1024) as u32, virtq::WRITE);
        q.submit(0);
        Mmio { base: self.control_notify }.write16(0, 0);
        let kind = get32(r.va, COMMAND);
        wait(&mut self.control, "a command", kind)?;
        dma_barrier();
        let got = get32(r.va, RESPONSE);
        if got != want {
            return Err(("the device refused a command", (kind as u64) << 32 | got as u64));
        }
        Ok(())
    }

    /// `RESOURCE_CREATE_2D`.
    fn create(&mut self, id: u32, format: u32, w: u32, h: u32) -> Result<(), Failure> {
        self.header(RESOURCE_CREATE_2D);
        let va = self.request.va + COMMAND;
        put32(va, 24, id);
        put32(va, 28, format);
        put32(va, 32, w);
        put32(va, 36, h);
        self.command(40, 0, OK_NODATA)
    }

    /// `RESOURCE_ATTACH_BACKING`: resource `id` backed by the `n` pages at
    /// `pages` (device addresses).
    fn attach_backing(&mut self, id: u32, pages: impl Iterator<Item = u64>, n: u64) -> Result<(), Failure> {
        for (k, a) in pages.enumerate() {
            let k = k as u64;
            let page = self.entries[(k / 256) as usize];
            put64(page.va, k % 256 * 16, a);
            put32(page.va, k % 256 * 16 + 8, PAGE as u32);
            put32(page.va, k % 256 * 16 + 12, 0);
        }
        self.header(RESOURCE_ATTACH_BACKING);
        let va = self.request.va + COMMAND;
        put32(va, 24, id);
        put32(va, 28, n as u32);
        self.command(32, n * 16, OK_NODATA)
    }

    /// A rectangle (x, y, width, height) at `off` in the command.
    fn rect(&self, off: u64, (x, y, w, h): (u32, u32, u32, u32)) {
        let va = self.request.va + COMMAND;
        put32(va, off, x);
        put32(va, off + 4, y);
        put32(va, off + 8, w);
        put32(va, off + 12, h);
    }

    /// `TRANSFER_TO_HOST_2D` of `r` from resource `id`'s backing, whose
    /// rows are `pitch` bytes apart.
    fn transfer(&mut self, id: u32, r: (u32, u32, u32, u32), pitch: u64) -> Result<(), Failure> {
        self.header(TRANSFER_TO_HOST_2D);
        self.rect(24, r);
        let va = self.request.va + COMMAND;
        put64(va, 40, r.1 as u64 * pitch + r.0 as u64 * 4);
        put32(va, 48, id);
        put32(va, 52, 0);
        self.command(56, 0, OK_NODATA)
    }

    /// Lets go of the surface: the scanout's resource first (the device
    /// lets go of its backing), then each page (deleting its capability
    /// takes it out of the domain).
    fn drop_surface(&mut self) {
        self.drop_scanout();
        for p in 0..self.pages {
            syscall(Syscall::CapDelete, SURFACE + p, [0; 4]);
        }
        self.pages = 0;
    }

    /// Takes the scanout's resource off scanout 0 and away.
    fn drop_scanout(&mut self) {
        if self.shown {
            self.header(SET_SCANOUT);
            self.rect(24, (0, 0, 0, 0));
            let va = self.request.va + COMMAND;
            put32(va, 40, 0);
            put32(va, 44, 0);
            let _ = self.command(48, 0, OK_NODATA);
            self.header(RESOURCE_UNREF);
            put32(va, 24, SCANOUT_RESOURCE);
            put32(va, 28, 0);
            let _ = self.command(32, 0, OK_NODATA);
            self.shown = false;
        }
    }

    /// `ATTACH`: keeps page `page` of the caller's surface, readable by
    /// the device.
    fn attach(&mut self, page: u64, lent: bool) -> Status {
        if !lent || page >= display::SURFACE_PAGES {
            return Status::Invalid;
        }
        if page == 0 {
            self.drop_surface();
        }
        if page != self.pages {
            return Status::Invalid;
        }
        if syscall(Syscall::CapMint, LENT, [SURFACE + page, ALL, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        match io_map(SURFACE + page, DOMAIN, false) {
            Ok(a) => self.dma[page as usize] = a,
            Err(_) => {
                syscall(Syscall::CapDelete, SURFACE + page, [0; 4]);
                return Status::Invalid;
            }
        }
        self.pages += 1;
        Status::Ok
    }

    /// `SET_MODE`: a resource of the scanout's size backed by the surface,
    /// shown on scanout 0.
    fn set_mode(&mut self, i: u64) -> Result<[u64; 4], Status> {
        let (w, h) = (self.width, self.height);
        let pitch = w as u64 * 4;
        let pages = (pitch * h as u64).div_ceil(PAGE);
        if i != 0 || self.pages < pages {
            return Err(Status::Invalid);
        }
        // A mode shown again: the old resource goes first.
        self.drop_scanout();
        let fail = |(what, code): Failure| {
            say!("[fail] {what} ({code:#x})");
            Status::DeviceError
        };
        self.create(SCANOUT_RESOURCE, B8G8R8X8, w, h).map_err(fail)?;
        let dma = self.dma;
        self.attach_backing(SCANOUT_RESOURCE, dma[..pages as usize].iter().copied(), pages)
            .map_err(fail)?;
        self.header(SET_SCANOUT);
        self.rect(24, (0, 0, w, h));
        let va = self.request.va + COMMAND;
        put32(va, 40, 0);
        put32(va, 44, SCANOUT_RESOURCE);
        self.command(48, 0, OK_NODATA).map_err(fail)?;
        (self.shown, self.flushes) = (true, 0);
        say!("{w}x{h} shown on scanout 0 from the caller's {pages} pages, pitch {pitch}");
        Ok([Status::Ok as u64, pitch, 0, 0])
    }

    /// `FLUSH`: the device takes the rectangle from the surface and shows
    /// it.
    fn flush(&mut self, rect: u64) -> Result<[u64; 4], Status> {
        if !self.shown {
            return Err(Status::Invalid);
        }
        let (x, y) = (rect as u32 & 0xffff, (rect >> 16) as u32 & 0xffff);
        let (w, h) = ((rect >> 32) as u32 & 0xffff, (rect >> 48) as u32 & 0xffff);
        if w == 0 || h == 0 || x + w > self.width || y + h > self.height {
            return Err(Status::Invalid);
        }
        let fail = |(what, code): Failure| {
            say!("[fail] {what} ({code:#x})");
            Status::DeviceError
        };
        let pitch = self.width as u64 * 4;
        self.transfer(SCANOUT_RESOURCE, (x, y, w, h), pitch).map_err(fail)?;
        self.header(RESOURCE_FLUSH);
        self.rect(24, (x, y, w, h));
        let va = self.request.va + COMMAND;
        put32(va, 40, SCANOUT_RESOURCE);
        put32(va, 44, 0);
        self.command(48, 0, OK_NODATA).map_err(fail)?;
        self.flushes += 1;
        let n = self.flushes;
        if n <= 4 || n.is_power_of_two() {
            say!("flush {n}: {w}x{h} at ({x}, {y}) shown");
        }
        Ok([Status::Ok as u64, 0, n, 0])
    }

    /// Runs a cursor command: `kind`, the cursor's resource (0 hides it).
    fn cursor_command(&mut self, kind: u32, resource: u32) -> Result<(), Failure> {
        let r = self.request;
        let va = r.va + CURSOR_COMMAND;
        for off in (0..56).step_by(8) {
            put64(va, off, 0);
        }
        put32(va, 0, kind);
        // Scanout 0, the point, then the resource and its hot spot.
        put32(va, 28, self.at.0);
        put32(va, 32, self.at.1);
        put32(va, 40, resource);
        put32(va, 44, self.hot.0);
        put32(va, 48, self.hot.1);
        let q = &mut self.cursor;
        q.set(0, r.dma + CURSOR_COMMAND, 56, 0);
        q.submit(0);
        Mmio { base: self.cursor_notify }.write16(0, 1);
        wait(&mut self.cursor, "a cursor command", kind)
    }

    /// `CURSOR`: the lent page's 32x32 picture into the cursor's resource,
    /// shown with hot spot `hot`.
    fn set_cursor(&mut self, hot: u64, lent: bool) -> Result<[u64; 4], Status> {
        let side = display::CURSOR_SIDE;
        let (hx, hy) = (hot as u32 & 0xffff, (hot >> 16) as u32 & 0xffff);
        if !lent || hx as u64 >= side || hy as u64 >= side {
            return Err(Status::Invalid);
        }
        if map(LENT, LENT_VA, false).is_err() {
            return Err(Status::Invalid);
        }
        // Row y of the device's picture is in page y / 16 (64 pixels of 4
        // bytes a row); the rest of each row and the rows below are clear.
        for y in 0..CURSOR_DEVICE_SIDE {
            let page = self.image[(y / 16) as usize].va;
            for x in 0..CURSOR_DEVICE_SIDE {
                let p = if x < side && y < side {
                    // SAFETY: the lent page is mapped, one picture of
                    // `side` squared words.
                    unsafe { ((LENT_VA + (y * side + x) * 4) as *const u32).read() }
                } else {
                    0
                };
                put32(page, (y % 16 * CURSOR_DEVICE_SIDE + x) * 4, p);
            }
        }
        let fail = |(what, code): Failure| {
            say!("[fail] {what} ({code:#x})");
            Status::DeviceError
        };
        let s = CURSOR_DEVICE_SIDE as u32;
        self.transfer(CURSOR_RESOURCE, (0, 0, s, s), CURSOR_DEVICE_SIDE * 4).map_err(fail)?;
        self.hot = (hx, hy);
        self.has_cursor = true;
        // Shown once `MOVE_CURSOR` has put it somewhere.
        if self.cursor_shown {
            self.cursor_command(UPDATE_CURSOR, CURSOR_RESOURCE).map_err(fail)?;
        }
        say!("cursor picture set: 32x32, its point at ({hx}, {hy})");
        Ok([Status::Ok as u64, 0, 0, 0])
    }

    /// `MOVE_CURSOR`.
    fn move_cursor(&mut self, x: u64, y: u64, shown: u64) -> Result<[u64; 4], Status> {
        if x >= self.width as u64 || y >= self.height as u64 || shown > 1 {
            return Err(Status::Invalid);
        }
        let fail = |(what, code): Failure| {
            say!("[fail] {what} ({code:#x})");
            Status::DeviceError
        };
        let was = self.cursor_shown;
        (self.at, self.cursor_shown) = ((x as u32, y as u32), shown == 1);
        if self.has_cursor {
            match (was, shown == 1) {
                (true, true) => self.cursor_command(MOVE_CURSOR, CURSOR_RESOURCE),
                (_, true) => self.cursor_command(UPDATE_CURSOR, CURSOR_RESOURCE),
                (_, false) => self.cursor_command(UPDATE_CURSOR, 0),
            }
            .map_err(fail)?;
        }
        self.moves += 1;
        if shown == 1 {
            say!("cursor at ({x}, {y})");
        } else {
            say!("cursor hidden");
        }
        Ok([Status::Ok as u64, self.moves, 0, 0])
    }

    fn serve(&mut self, m: [u64; 4], lent: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        let r = match m[0] {
            // One mode: the scanout's size, whatever the host made it.
            display::INFO if m[1] == display::VERSION => Ok([Status::Ok as u64, 1, 0, 0]),
            display::MODE if m[1] == 0 => Ok([Status::Ok as u64, self.width as u64, self.height as u64, 60]),
            display::MODE => Err(Status::NotFound),
            display::ATTACH => Ok(status(self.attach(m[1], lent))),
            display::SET_MODE => self.set_mode(m[1]),
            display::FLUSH => self.flush(m[1]),
            display::CURSOR => self.set_cursor(m[1], lent),
            display::MOVE_CURSOR => self.move_cursor(m[1], m[2], m[3]),
            _ => Err(Status::Invalid),
        };
        r.unwrap_or_else(status)
    }
}

/// Waits for `q`'s buffer to come back from the device.
fn wait(q: &mut Queue, what: &'static str, kind: u32) -> Result<(), Failure> {
    let start = ticks();
    while q.take_used().is_none() {
        if ticks() - start > TIMEOUT {
            return Err((what, kind as u64));
        }
        syscall(Syscall::Yield, 0, [0; 4]);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    let mut gpu = match start() {
        Ok(g) => g,
        Err((what, code)) => {
            say!("[fail] {what} ({code:#x})");
            superior_sys::park()
        }
    };
    let accept = CapTransfer { grant: None, accept: Some(LENT as u16) };
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        let lent = r.cap == Some(LENT as u16);
        let reply = gpu.serve(r.msg, lent);
        if lent {
            // What was lent goes back before the reply (a surface page's
            // copy stays).
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, accept);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
