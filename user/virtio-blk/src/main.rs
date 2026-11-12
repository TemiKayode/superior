//! A virtio block driver (virtio 1.x over PCI), serving the `block`
//! interface (`superior_objects::interfaces::block`).
//!
//! It holds nothing but what the manifest gives it: the PCI bus server
//! (through which it opens its one device and gets that device's BAR pages
//! and an MSI vector), its service endpoint, a notification for the
//! interrupt, and a little memory for DMA pages. The device's IOMMU domain
//! arrives with the open: the device reaches only the driver's queue and
//! request pages and, while a read is in flight, the caller's frame, which
//! the caller lends with the call. The driver maps it into the domain and
//! deletes it before replying, which unmaps it.
//!
//! On start (and so after every restart) it resets the device itself, as
//! virtio requires, after the bus server has already turned its decoding
//! and bus mastering off.
//!
//! Suspend (`power`, from the Component Manager): it resets the device and
//! turns bus mastering off, answers clients `Unreachable` meanwhile, and on
//! resume runs the whole initialization again on the same pages.
//!
//! Slots: 0 the bus server, 1 the `block` endpoint (receive), 2 a
//! notification, 3 untyped memory. `arg 1` turns on fault-injection
//! operations for tests: a crash, and a read aimed at memory outside the
//! domain.

#![no_std]
#![no_main]

use superior_driver::virtq::{self, Queue};
use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_address, dma_barrier, io_map};
use superior_objects::abi::{CapTransfer, Syscall};
use superior_objects::interfaces::{Status, block, power};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const MSI: u64 = 4;
const QUEUE: u64 = 5;
const REQUEST: u64 = 6;
const DOMAIN: u64 = 7;
const BAR_SLOTS: u64 = 8;
const MAX_BAR_PAGES: u64 = 16;
/// Where a caller's frame arrives.
const BUFFER: u64 = BAR_SLOTS + MAX_BAR_PAGES;
/// A page of the driver's own, never mapped for DMA (fault injection).
const CANARY: u64 = BUFFER + 1;
/// Fault injection: a second MSI vector, routed to no device, and copies
/// of the notification badged for it and for a timeout.
const FORGED_IRQ: u64 = CANARY + 1;
const FORGED_NTFN: u64 = CANARY + 2;
const TIMEOUT_NTFN: u64 = CANARY + 3;
/// And a copy badged for the IOMMU's report of a blocked request.
const FAULT_NTFN: u64 = CANARY + 4;
const FORGED_BIT: u64 = 2;
const TIMEOUT_BIT: u64 = 4;
const FAULT_BIT: u64 = 8;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const QUEUE_VA: u64 = USER_BASE + 0x5000_0000;
const REQUEST_VA: u64 = QUEUE_VA + 0x1000;
const CANARY_VA: u64 = QUEUE_VA + 0x2000;

/// Fault injection (with `arg 1`): crash on receipt.
const OP_CRASH: u64 = 0xdead;
/// Fault injection: program the device to raise an MSI vector it was not
/// given, then to DMA into a page outside its domain; reply whether
/// either landed, then crash (the device may be wedged), so the driver
/// restarts on a freshly reset one.
const OP_STRAY: u64 = 0x57a7;
const CANARY_WORD: u64 = 0xcafe_f00d_cafe_f00d;

// virtio PCI capabilities (vendor-specific, id 9) and their types.
const CAP_VENDOR: u8 = 0x09;
const CAP_MSIX: u8 = 0x11;
const COMMON: u8 = 1;
const NOTIFY_CFG: u8 = 2;
const DEVICE: u8 = 4;

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

/// virtio-blk request types.
const IN: u32 = 0;
const OUT: u32 = 1;
const FLUSH: u32 = 4;
/// Feature 9: the device has a write cache that `FLUSH` empties.
const F_FLUSH: u32 = 1 << 9;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("virtio-blk: {}", format_args!($($t)*))) };
}

struct Device {
    pci: Pci,
    bdf: u64,
    /// The common and device-specific register blocks, and where queue
    /// notifications go (base, multiplier).
    common: Mmio,
    device: Mmio,
    notify_base: u64,
    multiplier: u64,
    /// The device has a write cache, emptied by a flush.
    flush: bool,
    notify: u64,
    queue: Queue,
    request: DmaPage,
    capacity: u64,
    /// The MSI-X table entry for queue 0, and the message it holds.
    msix: Mmio,
    message: (u64, u64),
    /// With fault injection: the message of a vector the driver holds but
    /// that is routed to no device.
    forged: Option<(u64, u64)>,
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
        if bar >= 6 || off + len > 16 * 4096 {
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

fn start(faults: bool) -> Result<Device, Failure> {
    let pci = Pci { slot: PCI };
    let (bdf, _) = pci.open(0x1af4, 0x1042, 0, DOMAIN)?;
    let mut bars = Bars {
        pci: Pci { slot: PCI },
        mapped: [0; 6],
        next_slot: BAR_SLOTS,
    };
    // Find the register blocks.
    let (mut common, mut device, mut notify) = (None, None, None);
    let mut at = 0;
    while let Some(cap) = pci.find_capability(CAP_VENDOR, at)? {
        at = cap;
        let kind = pci.config_read8(cap + 3)?;
        let bar = pci.config_read8(cap + 4)? as u64;
        let off = pci.config_read(cap + 8)? as u64;
        let len = pci.config_read(cap + 12)? as u64;
        match kind {
            COMMON => common = Some(bars.map(bar, off, len)?),
            DEVICE => device = Some(bars.map(bar, off, len)?),
            NOTIFY_CFG => {
                let multiplier = pci.config_read(cap + 16)? as u64;
                notify = Some((bars.map(bar, off, len)?, multiplier));
            }
            _ => {}
        }
    }
    let (Some(common), Some(device), Some((notify_base, multiplier))) = (common, device, notify)
    else {
        return Err(("not a virtio 1.x device", 0));
    };
    let (common, device) = (Mmio { base: common }, Mmio { base: device });

    // One MSI-X vector, for queue 0.
    let msix = pci.find_capability(CAP_MSIX, 0)?.ok_or(("no MSI-X", 0))?;
    let table = pci.config_read(msix + 4)? as u64;
    let entry = Mmio {
        base: bars.map(table & 7, table & !7, 16)?,
    };
    let (address, data) = pci.msi_vector(0, MSI, NOTIFY, DOMAIN)?;
    let forged = if faults { Some(forge_vector(&pci)?) } else { None };

    // Queue 0, in one DMA page; requests' headers and status in another.
    let queue = Queue::new(DmaPage::new(UNTYPED, QUEUE, QUEUE_VA, DOMAIN)?);
    let request = DmaPage::new(UNTYPED, REQUEST, REQUEST_VA, DOMAIN)?;
    let mut dev = Device {
        pci,
        bdf: bdf as u64,
        common,
        device,
        notify_base,
        multiplier,
        flush: false,
        notify: 0,
        queue,
        request,
        capacity: 0,
        msix: entry,
        message: (address, data),
        forged,
    };
    dev.init()?;
    Ok(dev)
}

/// Takes a second MSI vector, bound to the notification with its own bit
/// but routed to no device, and returns its message.
fn forge_vector(pci: &Pci) -> Result<(u64, u64), Failure> {
    pci.take_msi_vector(1, FORGED_IRQ)?;
    let m = superior_driver::msi_message(FORGED_IRQ, None)?;
    for (slot, badge) in [(FORGED_NTFN, FORGED_BIT), (TIMEOUT_NTFN, TIMEOUT_BIT), (FAULT_NTFN, FAULT_BIT)] {
        if syscall(Syscall::CapMint, NOTIFY, [slot, 0xff, badge, 0]).status != 0 {
            return Err(("minting a copy of the notification", badge));
        }
    }
    if syscall(Syscall::IrqSetNotification, FORGED_IRQ, [FORGED_NTFN, 0, 0, 0]).status != 0 {
        return Err(("binding the second vector", 0));
    }
    Ok(m)
}

impl Device {
    /// Resets the device and brings it up (virtio 1.x, 3.1.1): at start,
    /// and again on `power::RESUME`.
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
        // VERSION_1 (feature 32), ACCESS_PLATFORM (33) if offered (the
        // device's DMA goes through the IOMMU) and FLUSH (9) if offered.
        let high = common.read32(DEVICE_FEATURE) & ACCESS_PLATFORM;
        common.write32(DEVICE_FEATURE_SELECT, 0);
        let low = common.read32(DEVICE_FEATURE) & F_FLUSH;
        common.write32(DRIVER_FEATURE_SELECT, 0);
        common.write32(DRIVER_FEATURE, low);
        common.write32(DRIVER_FEATURE_SELECT, 1);
        common.write32(DRIVER_FEATURE, 1 | high);
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        if common.read8(DEVICE_STATUS) & FEATURES_OK == 0 {
            return Err(("the device refused the features", 0));
        }
        self.flush = low != 0;

        self.program_msix(self.message);
        self.pci.msix(true)?;
        common.write16(CONFIG_MSIX_VECTOR, NO_VECTOR);

        self.queue.reset();
        common.write16(QUEUE_SELECT, 0);
        let max = common.read16(QUEUE_SIZE);
        // The rings are laid out for exactly virtq::SIZE entries.
        if max < virtq::SIZE {
            return Err(("queue 0 is too small", max as u64));
        }
        common.write16(QUEUE_SIZE, virtq::SIZE);
        common.write16(QUEUE_MSIX_VECTOR, 0);
        if common.read16(QUEUE_MSIX_VECTOR) != 0 {
            return Err(("the device refused the MSI-X vector", 0));
        }
        let (desc, driver, used) = self.queue.addresses();
        common.write64(QUEUE_DESC, desc);
        common.write64(QUEUE_DRIVER, driver);
        common.write64(QUEUE_DEVICE, used);
        self.notify = self.notify_base + common.read16(QUEUE_NOTIFY_OFF) as u64 * self.multiplier;
        common.write16(QUEUE_ENABLE, 1);
        self.pci.bus_master(true)?;
        common.write8(
            DEVICE_STATUS,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );
        self.capacity = self.device.read64(0);
        let (bdf, data) = (self.bdf, self.message.1);
        say!(
            "ready: {:02x}:{:02x}.{}, {} sectors, interrupts on MSI-X vector 0 (message data {data:#x})",
            bdf >> 8,
            bdf >> 3 & 0x1f,
            bdf & 7,
            self.capacity
        );
        Ok(())
    }

    /// `power::SUSPEND`: requests are run to completion one at a time, so
    /// none is in flight; reset the device (it forgets its queue) and
    /// stop its DMA.
    fn quiesce(&mut self) -> Result<(), Failure> {
        self.common.write8(DEVICE_STATUS, 0);
        while self.common.read8(DEVICE_STATUS) != 0 {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        self.pci.bus_master(false)
    }

    /// Starts reading `count` sectors from `sector` into the frame at
    /// `buffer` (a device address).
    fn submit(&mut self, sector: u64, count: u64, buffer: u64) {
        self.submit_op(IN, sector, count, buffer);
    }

    /// Starts request `kind` (`IN`, `OUT` or `FLUSH`); `count` sectors at
    /// `buffer`, none for a flush.
    fn submit_op(&mut self, kind: u32, sector: u64, count: u64, buffer: u64) {
        let r = self.request;
        // SAFETY: the request page is mapped at `r.va`; the header takes
        // 16 bytes and the status byte follows.
        unsafe {
            (r.va as *mut u32).write_volatile(kind);
            ((r.va + 4) as *mut u32).write_volatile(0);
            ((r.va + 8) as *mut u64).write_volatile(sector);
            ((r.va + 16) as *mut u8).write_volatile(0xff);
        }
        let q = &mut self.queue;
        q.set(0, r.dma, 16, virtq::NEXT);
        let status = if kind == FLUSH {
            1
        } else {
            // The device writes the buffer on a read, reads it on a write.
            let flags = if kind == IN { virtq::WRITE } else { 0 };
            q.set(
                1,
                buffer,
                (count * block::SECTOR) as u32,
                virtq::NEXT | flags,
            );
            2
        };
        q.set(status, r.dma + 16, 1, virtq::WRITE);
        q.submit(0);
        Mmio { base: self.notify }.write16(0, 0);
    }

    /// The request's status byte: 0 for success.
    fn request_status(&self) -> u8 {
        dma_barrier();
        // SAFETY: the request page is mapped; the status follows the header.
        unsafe { ((self.request.va + 16) as *const u8).read_volatile() }
    }

    /// Reads `count` sectors from `sector` into the frame at `buffer` (a
    /// device address), waiting for the interrupt.
    fn read(&mut self, sector: u64, count: u64, buffer: u64) -> Status {
        self.run(IN, sector, count, buffer)
    }

    /// Runs request `kind` to completion, waiting for the interrupt.
    fn run(&mut self, kind: u32, sector: u64, count: u64, buffer: u64) -> Status {
        self.submit_op(kind, sector, count, buffer);
        loop {
            if self.queue.take_used().is_some() {
                break;
            }
            syscall(Syscall::Wait, NOTIFY, [0; 4]);
            syscall(Syscall::IrqAck, MSI, [0; 4]);
        }
        match self.request_status() {
            0 => Status::Ok,
            _ => Status::DeviceError,
        }
    }

    /// Points the device's MSI-X entry at `message`.
    fn program_msix(&self, (address, data): (u64, u64)) {
        self.msix.write32(12, 1); // masked while it changes
        self.msix.write32(0, address as u32);
        self.msix.write32(4, (address >> 32) as u32);
        self.msix.write32(8, data as u32);
        self.msix.write32(12, 0);
    }

    /// Has the device raise the vector routed to no device: points its
    /// MSI-X entry at that vector's message and runs a read. Returns (the
    /// vector was raised, the read completed, interrupt messages the
    /// IOMMU reported blocking).
    fn forge(&mut self, message: (u64, u64)) -> Result<(bool, bool, u64), Failure> {
        // Start the count afresh.
        superior_driver::io_faults(DOMAIN)?;
        self.program_msix(message);
        let buffer = self.request.dma + 512;
        self.submit(0, 1, buffer);
        let start = ticks();
        let mut done = false;
        while ticks() < start + 100 {
            if self.queue.take_used().is_some() {
                done = true;
                break;
            }
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        // Give a stray interrupt time to arrive, then see which bits the
        // notification collected.
        syscall(Syscall::TimerSignal, TIMEOUT_NTFN, [10, 0, 0, 0]);
        let mut bits = 0;
        while bits & TIMEOUT_BIT == 0 {
            bits |= syscall(Syscall::Wait, NOTIFY, [0; 4]).badge;
        }
        self.program_msix(self.message);
        let blocked = superior_driver::io_faults(DOMAIN)?.interrupts;
        Ok((bits & FORGED_BIT != 0, done, blocked))
    }

    /// Aims a read at a page of the driver's own that is not in the
    /// device's domain. Returns (page untouched, request completed, its
    /// status byte).
    /// Also returns whether the IOMMU's report reached the driver as a
    /// signal, without it asking.
    fn stray(&mut self) -> Result<(bool, bool, u8, u64, bool), Failure> {
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
        superior_driver::io_fault_notify(DOMAIN, Some(FAULT_NTFN))?;
        self.submit(0, 8, pa);
        // The device either fails the request or never finishes it; give
        // it a second either way.
        let start = ticks();
        let mut done = false;
        while ticks() < start + 100 {
            if self.queue.take_used().is_some() {
                done = true;
                break;
            }
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        dma_barrier();
        let untouched = page.iter().all(|&w| w == CANARY_WORD);
        // The signal came at the fault (an interrupt) or will at the next
        // tick at the latest: see which bits a short wait collects.
        syscall(Syscall::TimerSignal, TIMEOUT_NTFN, [10, 0, 0, 0]);
        let mut bits = 0;
        while bits & TIMEOUT_BIT == 0 {
            bits |= syscall(Syscall::Wait, NOTIFY, [0; 4]).badge;
        }
        superior_driver::io_fault_notify(DOMAIN, None)?;
        Ok((untouched, done, self.request_status(), pa, bits & FAULT_BIT != 0))
    }

    /// The forged interrupt, then the stray DMA. Returns whether the
    /// interrupt was held back (and, where the IOMMU reports interrupts,
    /// reported), and the stray DMA's result.
    fn forge_then_stray(&mut self) -> Result<(bool, (bool, bool, u8, u64, bool)), Failure> {
        let message = self.forged.ok_or(("no second vector", 0))?;
        let (raised, done, blocked) = self.forge(message)?;
        // VT-d records blocked interrupts; the ITS drops them silently.
        let must_report = cfg!(target_arch = "x86_64");
        say!(
            "forged MSI: a vector routed to no device was {}, request {}; {}",
            if raised { "RAISED" } else { "not raised" },
            if done { "completed" } else { "never completed" },
            match (blocked, must_report) {
                (0, true) => "the IOMMU reported NOTHING",
                (_, true) => "the IOMMU reported the blocked interrupt",
                (_, false) => "the ITS mapped it for no device",
            }
        );
        let held = !raised && done && (blocked > 0 || !must_report);
        Ok((held, self.stray()?))
    }

    fn serve(&mut self, m: [u64; 4], lent: bool, faults: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            // One unit: the disk.
            block::INFO if m[1] == block::VERSION && m[2] == 0 => {
                [Status::Ok as u64, self.capacity, block::SECTOR, 1]
            }
            block::INFO | block::READ | block::WRITE if m[if m[0] == block::INFO { 2 } else { 3 }] != 0 => {
                status(Status::NotFound)
            }
            block::FLUSH if self.flush => status(self.run(FLUSH, 0, 0, 0)),
            // No write cache: every completed write is already durable.
            block::FLUSH => status(Status::Ok),
            block::READ | block::WRITE => {
                let (sector, count) = (m[1], m[2]);
                if !lent
                    || count == 0
                    || count > block::MAX_SECTORS
                    || sector
                        .checked_add(count)
                        .is_none_or(|end| end > self.capacity)
                {
                    return status(Status::Invalid);
                }
                // Reachable by the device only until it is deleted, before
                // the reply; for a write, only for reading.
                let write = m[0] == block::WRITE;
                match io_map(BUFFER, DOMAIN, !write) {
                    Ok(buffer) if write => status(self.run(OUT, sector, count, buffer)),
                    Ok(buffer) => status(self.read(sector, count, buffer)),
                    Err(_) => status(Status::Invalid),
                }
            }
            OP_CRASH if faults => crash(),
            OP_STRAY if faults => match self.forge_then_stray() {
                Ok((held, (untouched, done, st, page, signalled))) => {
                    let (reported, report) = superior_driver::stray_reported(DOMAIN, page);
                    say!(
                        "stray DMA: page {}, request {} (status {st:#x}); {report}; {}",
                        if untouched { "untouched" } else { "WRITTEN" },
                        if done { "completed" } else { "never completed" },
                        if signalled { "the driver was signalled" } else { "the driver was NOT signalled" }
                    );
                    let ok = held && untouched && reported && signalled;
                    [Status::Ok as u64, ok as u64, done as u64, st as u64]
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

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
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
    let mut dev = match start(arg == 1) {
        Ok(d) => d,
        Err((what, code)) => {
            say!("[fail] {what} ({code})");
            superior_sys::park()
        }
    };
    let accept = CapTransfer {
        grant: None,
        accept: Some(BUFFER as u16),
    };
    let mut suspended = false;
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        let lent = r.cap == Some(BUFFER as u16);
        // Badge 0 is the Component Manager's own (manifest `power`).
        let manager = r.badge == 0;
        let reply = match r.msg[0] {
            power::SUSPEND if manager => {
                let s = match dev.quiesce() {
                    Ok(()) => {
                        suspended = true;
                        say!("suspended: device reset, bus mastering off");
                        Status::Ok
                    }
                    Err((what, code)) => {
                        say!("could not suspend: {what} ({code})");
                        Status::DeviceError
                    }
                };
                [s as u64, 0, 0, 0]
            }
            power::RESUME if manager => {
                let s = match dev.init() {
                    Ok(()) => {
                        suspended = false;
                        say!("resumed: device initialized again");
                        Status::Ok
                    }
                    Err((what, code)) => {
                        say!("could not resume: {what} ({code})");
                        Status::DeviceError
                    }
                };
                [s as u64, 0, 0, 0]
            }
            // Asleep: the client retries after the resume.
            _ if suspended => [Status::Unreachable as u64, 0, 0, 0],
            _ => dev.serve(r.msg, lent, arg == 1),
        };
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
    superior_sys::park()
}
