//! A virtio network driver (virtio 1.x over PCI), serving the `nic`
//! interface (`superior_objects::interfaces::nic`) to the network server.
//!
//! It holds only what the manifest gives it: the PCI bus server, its
//! service endpoint, a notification for the interrupt and a little memory
//! for DMA pages. The device's IOMMU domain arrives with the open, and the
//! device reaches only the two queues and the driver's receive and
//! transmit buffers: frames are copied between those and the page the
//! caller lends with each call, so the caller's memory never goes to the
//! device.
//!
//! Receive buffers are offered to the device up front; when frames arrive
//! the interrupt (bound to the driver's thread, so one `Recv` waits for
//! calls and interrupts) makes the driver signal the notification its
//! caller attached. A restart loses that notification, which `RECV` tells
//! the caller.
//!
//! Frame rings (`nic::ring`): once the caller has attached its ring pages
//! and started the ring, received frames go into the receive ring as the
//! interrupt brings them, and the frames the caller puts in the transmit
//! ring go to the device, with no call for either. The driver signals the
//! caller's notification only when the caller said it sleeps, and is woken
//! by the doorbell (a badged copy of its own notification) only when it
//! said so itself. If the device has no free transmit buffer the driver
//! asks for an interrupt when one is sent, and only then. The ring's
//! pages are the caller's, shared: nothing in them is trusted, and the
//! device never sees them. `RECV` and `SEND` go on working for a caller
//! with no ring.
//!
//! Slots: 0 the bus server, 1 the `nic` endpoint (receive), 2 a
//! notification, 3 untyped memory (64 KiB).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering, fence};
use superior_driver::virtq::{self, Queue};
use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_barrier};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::interfaces::nic::ring;
use superior_objects::interfaces::{Status, nic};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const MSI: u64 = 4;
const DOMAIN: u64 = 5;
const RX_QUEUE: u64 = 6;
const TX_QUEUE: u64 = 7;
/// Receive buffer pages, then transmit buffer pages: two buffers a page.
const RX_PAGES: u64 = 8;
const TX_PAGES: u64 = RX_PAGES + BUFFERS / 2;
/// Where a caller's frame arrives.
const LENT: u64 = TX_PAGES + BUFFERS / 2;
/// The notification the caller attached.
const LISTENER: u64 = LENT + 1;
/// The doorbell: this driver's notification, to signal only, granted to
/// the ring's caller.
const DOORBELL: u64 = LISTENER + 1;
const BAR_SLOTS: u64 = 24;
/// The caller's ring pages.
const RING: u64 = BAR_SLOTS + MAX_BAR_PAGES;
const _: () = assert!(RING + ring::PAGES <= 64);
const WRITE: u64 = 2;
const MAX_BAR_PAGES: u64 = 16;
/// Every right, for keeping a granted capability.
const ALL: u64 = 0x1f;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const LENT_VA: u64 = USER_BASE + 0x6000_0000;
const RING_VA: u64 = USER_BASE + 0x7000_0000;

/// Buffers in each direction (at most `virtq::SIZE`), 2 KiB each.
const BUFFERS: u64 = 8;
const BUFFER: u64 = 2048;
/// The header virtio puts before each frame (with VERSION_1, 12 bytes).
const HEADER: u64 = 12;

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
/// Feature 5: the device has a MAC address in its configuration.
const F_MAC: u32 = 1 << 5;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("virtio-net: {}", format_args!($($t)*))) };
}

struct Nic {
    rx: Queue,
    tx: Queue,
    rx_notify: u64,
    tx_notify: u64,
    /// Buffer `i`'s (address for the driver, address for the device).
    rx_buf: [(u64, u64); BUFFERS as usize],
    tx_buf: [(u64, u64); BUFFERS as usize],
    /// Transmit buffers the device has not finished with.
    tx_busy: [bool; BUFFERS as usize],
    mac: u64,
    attached: bool,
    sent: u64,
    received: u64,
    /// Ring pages attached so far, and whether the ring is started.
    ring_pages: u64,
    ring: bool,
    /// The driver's own ends of the rings: where the next received frame
    /// goes, and the next frame to send.
    rx_tail: u32,
    tx_head: u32,
    /// Frames that went through the rings (of `sent` and `received`).
    by_ring: u64,
}

/// Word `off` of the ring's header page.
fn hdr(off: usize) -> &'static AtomicU32 {
    // SAFETY: only used while the ring is started, its header mapped.
    unsafe { &*((RING_VA + off as u64) as *const AtomicU32) }
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

/// Buffers `2 * pages` of 2 KiB in DMA pages from `slot`, mapped at `va`.
fn buffers(slot: u64, va: u64) -> Result<[(u64, u64); BUFFERS as usize], Failure> {
    let mut b = [(0, 0); BUFFERS as usize];
    for p in 0..BUFFERS / 2 {
        let page = DmaPage::new(UNTYPED, slot + p, va + p * 4096, DOMAIN)?;
        b[2 * p as usize] = (page.va, page.dma);
        b[2 * p as usize + 1] = (page.va + BUFFER, page.dma + BUFFER);
    }
    Ok(b)
}

fn start() -> Result<Nic, Failure> {
    let pci = Pci { slot: PCI };
    let (bdf, _) = pci.open(0x1af4, 0x1041, 0, DOMAIN)?;
    let mut bars = Bars {
        pci: Pci { slot: PCI },
        mapped: [0; 6],
        next_slot: BAR_SLOTS,
    };
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

    // Reset, then the initialization sequence (virtio 1.x, 3.1.1).
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
    // VERSION_1, ACCESS_PLATFORM if offered, and MAC: no offloads, no
    // merged receive buffers, no control queue.
    let high = common.read32(DEVICE_FEATURE) & ACCESS_PLATFORM;
    common.write32(DEVICE_FEATURE_SELECT, 0);
    let low = common.read32(DEVICE_FEATURE) & F_MAC;
    if low == 0 {
        return Err(("the device has no MAC address", 0));
    }
    common.write32(DRIVER_FEATURE_SELECT, 0);
    common.write32(DRIVER_FEATURE, low);
    common.write32(DRIVER_FEATURE_SELECT, 1);
    common.write32(DRIVER_FEATURE, 1 | high);
    common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
    if common.read8(DEVICE_STATUS) & FEATURES_OK == 0 {
        return Err(("the device refused the features", 0));
    }

    // One MSI-X vector for both queues. The transmit queue asks for no
    // interrupts (sent buffers are reaped when the next frame needs one)
    // except while frames in the transmit ring wait for a buffer.
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
    common.write16(CONFIG_MSIX_VECTOR, NO_VECTOR);

    let rx = Queue::new(DmaPage::new(UNTYPED, RX_QUEUE, DMA_VA, DOMAIN)?);
    let tx = Queue::new(DmaPage::new(UNTYPED, TX_QUEUE, DMA_VA + 0x1000, DOMAIN)?);
    let mut notify_at = [0; 2];
    for (q, queue, vector) in [(0u16, &rx, 0u16), (1, &tx, 0)] {
        common.write16(QUEUE_SELECT, q);
        if common.read16(QUEUE_SIZE) < virtq::SIZE {
            return Err(("a queue is too small", q as u64));
        }
        common.write16(QUEUE_SIZE, virtq::SIZE);
        common.write16(QUEUE_MSIX_VECTOR, vector);
        if common.read16(QUEUE_MSIX_VECTOR) != vector {
            return Err(("the device refused the MSI-X vector", q as u64));
        }
        let (desc, driver, used) = queue.addresses();
        common.write64(QUEUE_DESC, desc);
        common.write64(QUEUE_DRIVER, driver);
        common.write64(QUEUE_DEVICE, used);
        notify_at[q as usize] = notify_base + common.read16(QUEUE_NOTIFY_OFF) as u64 * multiplier;
        common.write16(QUEUE_ENABLE, 1);
    }
    let mut nic = Nic {
        rx,
        tx,
        rx_notify: notify_at[0],
        tx_notify: notify_at[1],
        rx_buf: buffers(RX_PAGES, DMA_VA + 0x2000)?,
        tx_buf: buffers(TX_PAGES, DMA_VA + 0x2000 + 4096 * (BUFFERS / 2))?,
        tx_busy: [false; BUFFERS as usize],
        mac: (0..6).fold(0, |m, i| m << 8 | device.read8(i) as u64),
        attached: false,
        sent: 0,
        received: 0,
        ring_pages: 0,
        ring: false,
        rx_tail: 0,
        tx_head: 0,
        by_ring: 0,
    };
    // Sent frames are reaped when a buffer is wanted: no interrupts for
    // them unless frames wait for one (`Nic::before_sleep`).
    nic.tx.interrupts(false);
    if syscall(Syscall::CapMint, NOTIFY, [DOORBELL, WRITE, 2, 0]).status != 0 {
        return Err(("making the doorbell", 0));
    }
    pci.bus_master(true)?;
    common.write8(
        DEVICE_STATUS,
        ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
    );
    // Every receive buffer to the device.
    for i in 0..BUFFERS as u16 {
        nic.offer(i);
    }
    let m = nic.mac;
    say!(
        "ready: {:02x}:{:02x}.{}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, interrupts on MSI-X vector 0 (message data {data:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7,
        m >> 40 & 0xff,
        m >> 32 & 0xff,
        m >> 24 & 0xff,
        m >> 16 & 0xff,
        m >> 8 & 0xff,
        m & 0xff,
    );
    Ok(nic)
}

impl Nic {
    /// Gives receive buffer `i` (descriptor `i`) to the device.
    fn offer(&mut self, i: u16) {
        self.rx
            .set(i, self.rx_buf[i as usize].1, BUFFER as u32, virtq::WRITE);
        self.rx.submit(i);
        Mmio {
            base: self.rx_notify,
        }
        .write16(0, 0);
    }

    /// The caller's frame, mapped: false if it cannot be.
    fn map_lent(&self, writable: bool) -> bool {
        syscall(Syscall::FrameMap, LENT, [LENT_VA, writable as u64, 0, 0]).status == 0
    }

    fn recv(&mut self) -> [u64; 4] {
        let attached = self.attached as u64;
        if self.ring {
            // Frames go to the ring, in order.
            self.pump_rx();
            return [Status::Empty as u64, 0, attached, 1];
        }
        let Some((i, len)) = self.rx.take_used() else {
            return [Status::Empty as u64, 0, attached, 0];
        };
        let len = (len as u64).saturating_sub(HEADER).min(nic::MAX_FRAME);
        let reply = if self.map_lent(true) {
            // SAFETY: the buffer and the lent page are both mapped; `len`
            // fits in each.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.rx_buf[i as usize].0 + HEADER) as *const u8,
                    LENT_VA as *mut u8,
                    len as usize,
                );
            }
            self.received += 1;
            [Status::Ok as u64, len, attached, 0]
        } else {
            [Status::Invalid as u64, 0, attached, 0]
        };
        self.offer(i);
        reply
    }

    /// A transmit buffer the device is not using, taking back those it
    /// has sent.
    fn free_buffer(&mut self) -> Option<usize> {
        while let Some((i, _)) = self.tx.take_used() {
            if let Some(b) = self.tx_busy.get_mut(i as usize) {
                *b = false;
            }
        }
        self.tx_busy.iter().position(|b| !b)
    }

    fn send(&mut self, len: u64) -> Status {
        if len < 14 || len > nic::MAX_FRAME {
            return Status::Invalid;
        }
        let Some(i) = self.free_buffer() else {
            return Status::NoSpace;
        };
        if !self.map_lent(false) {
            return Status::Invalid;
        }
        self.transmit(i, LENT_VA, len);
        Status::Ok
    }

    /// Sends the `len` bytes (14 to `MAX_FRAME`) at `from` through free
    /// transmit buffer `i`.
    fn transmit(&mut self, i: usize, from: u64, len: u64) {
        let (va, dma) = self.tx_buf[i];
        // SAFETY: the buffer and the page at `from` are both mapped; the
        // header and `len` bytes fit in the 2 KiB buffer.
        unsafe {
            core::ptr::write_bytes(va as *mut u8, 0, HEADER as usize);
            core::ptr::copy_nonoverlapping(from as *const u8, (va + HEADER) as *mut u8, len as usize);
        }
        self.tx_busy[i] = true;
        self.tx.set(i as u16, dma, (HEADER + len) as u32, 0);
        dma_barrier();
        self.tx.submit(i as u16);
        Mmio {
            base: self.tx_notify,
        }
        .write16(0, 1);
        self.sent += 1;
        if self.sent.is_power_of_two() && self.sent >= 64 {
            say!(
                "{} frames sent, {} received ({} of them through the rings)",
                self.sent,
                self.received,
                self.by_ring
            );
        }
    }

    /// `RING_ATTACH`: keeps and maps page `page` of the caller's ring.
    fn ring_attach(&mut self, page: u64, lent: bool) -> Status {
        if !lent || page >= ring::PAGES {
            return Status::Invalid;
        }
        if page == 0 {
            self.ring_drop();
        }
        if self.ring || page != self.ring_pages {
            return Status::Invalid;
        }
        // A copy of what was lent: the lent capability goes after the call.
        if syscall(Syscall::CapMint, LENT, [RING + page, ALL, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        let va = RING_VA + page * 4096;
        if syscall(Syscall::FrameMap, RING + page, [va, 1, 0, 0]).status != 0 {
            syscall(Syscall::CapDelete, RING + page, [0; 4]);
            return Status::Invalid;
        }
        self.ring_pages += 1;
        Status::Ok
    }

    /// Lets go of the ring: its pages, and the caller's doorbell.
    fn ring_drop(&mut self) {
        self.ring = false;
        for p in 0..self.ring_pages {
            // Deleting the capability unmaps the page.
            syscall(Syscall::CapDelete, RING + p, [0; 4]);
        }
        self.ring_pages = 0;
        syscall(Syscall::CapRevoke, DOORBELL, [0; 4]);
        self.tx.interrupts(false);
    }

    /// `RING_START`: the rings begin empty. The reply grants DOORBELL.
    fn ring_start(&mut self) -> Status {
        if self.ring || self.ring_pages != ring::PAGES {
            return Status::Invalid;
        }
        for off in (0..4096).step_by(4) {
            hdr(off).store(0, Ordering::Relaxed);
        }
        fence(Ordering::SeqCst);
        (self.rx_tail, self.tx_head) = (0, 0);
        self.ring = true;
        say!("frame rings started");
        Status::Ok
    }

    /// Where frame `i` of a ring whose slots start at page `page` lies.
    fn slot(page: u64, i: u32, slots: u32) -> u64 {
        RING_VA + page * 4096 + (i % slots) as u64 * ring::SLOT
    }

    /// Moves received frames from the device's buffers into the receive
    /// ring, as many as it has room for, and tells a sleeping caller.
    fn pump_rx(&mut self) {
        let mut moved = false;
        while self.ring {
            let head = hdr(ring::RX_HEAD).load(Ordering::Acquire);
            if ring::waiting(head, self.rx_tail, ring::RX_SLOTS) == ring::RX_SLOTS {
                // Full: the rest wait in the device's buffers
                // (`before_sleep` tells the caller).
                break;
            }
            let Some((i, len)) = self.rx.take_used() else {
                break;
            };
            let Some(&(buf, _)) = self.rx_buf.get(i as usize) else {
                continue;
            };
            let len = (len as u64).saturating_sub(HEADER).min(nic::MAX_FRAME);
            let at = self.rx_tail % ring::RX_SLOTS;
            // SAFETY: the buffer and the ring's pages are mapped; `len`
            // fits in the buffer and in a slot.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (buf + HEADER) as *const u8,
                    Self::slot(ring::RX_PAGE, self.rx_tail, ring::RX_SLOTS) as *mut u8,
                    len as usize,
                );
            }
            hdr(ring::RX_LEN + 4 * at as usize).store(len as u32, Ordering::Relaxed);
            self.rx_tail = self.rx_tail.wrapping_add(1);
            hdr(ring::RX_TAIL).store(self.rx_tail, Ordering::Release);
            self.received += 1;
            self.by_ring += 1;
            self.offer(i);
            moved = true;
        }
        if moved {
            fence(Ordering::SeqCst);
            if hdr(ring::CALLER_SLEEPS).swap(0, Ordering::SeqCst) != 0 && self.attached {
                syscall(Syscall::Signal, LISTENER, [0; 4]);
            }
        }
    }

    /// Sends the frames waiting in the transmit ring. True if some are
    /// left because the device has every transmit buffer.
    fn pump_tx(&mut self) -> bool {
        while self.ring {
            let tail = hdr(ring::TX_TAIL).load(Ordering::Acquire);
            if ring::waiting(self.tx_head, tail, ring::TX_SLOTS) == 0 {
                break;
            }
            let Some(i) = self.free_buffer() else {
                return true;
            };
            let at = self.tx_head % ring::TX_SLOTS;
            // Read once: the caller may change it at any time.
            let len = hdr(ring::TX_LEN + 4 * at as usize).load(Ordering::Relaxed) as u64;
            let from = Self::slot(ring::TX_PAGE, self.tx_head, ring::TX_SLOTS);
            self.tx_head = self.tx_head.wrapping_add(1);
            hdr(ring::TX_HEAD).store(self.tx_head, Ordering::Release);
            if (14..=nic::MAX_FRAME).contains(&len) {
                self.transmit(i, from, len);
                self.by_ring += 1;
            }
        }
        false
    }

    /// Before the driver waits: empties the rings as far as it can, says
    /// it sleeps, and looks once more, so that nothing put in a ring
    /// meanwhile is left there with nobody to signal.
    fn before_sleep(&mut self) {
        while self.ring {
            self.pump_rx();
            let stuck = self.pump_tx();
            hdr(ring::DRIVER_SLEEPS).store(1, Ordering::SeqCst);
            // Frames still with the device were kept from a full ring:
            // the caller rings the doorbell once it has taken some.
            let held = self.rx.has_used();
            hdr(ring::RX_STALLED).store(held as u32, Ordering::SeqCst);
            fence(Ordering::SeqCst);
            // With frames stuck behind a full device, its interrupt when
            // one is sent is what wakes the driver.
            self.tx.interrupts(stuck);
            let tail = hdr(ring::TX_TAIL).load(Ordering::Acquire);
            let to_send = ring::waiting(self.tx_head, tail, ring::TX_SLOTS) != 0;
            let head = hdr(ring::RX_HEAD).load(Ordering::Acquire);
            let room = ring::waiting(head, self.rx_tail, ring::RX_SLOTS) < ring::RX_SLOTS;
            let more = (to_send && (!stuck || self.tx.has_used())) || (room && self.rx.has_used());
            if !more {
                break;
            }
            hdr(ring::DRIVER_SLEEPS).store(0, Ordering::SeqCst);
        }
    }

    fn serve(&mut self, m: [u64; 4], lent: bool, cap: Option<u16>) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            nic::INFO if m[1] == nic::VERSION => [Status::Ok as u64, self.mac, nic::MAX_FRAME, 0],
            nic::ATTACH if cap == Some(LISTENER as u16) => {
                self.attached = true;
                // Frames may already be waiting.
                if self.rx.has_used() {
                    syscall(Syscall::Signal, LISTENER, [0; 4]);
                }
                status(Status::Ok)
            }
            nic::RECV if lent => self.recv(),
            nic::SEND if lent => status(self.send(m[1])),
            nic::RING_ATTACH => status(self.ring_attach(m[1], lent)),
            nic::RING_START => status(self.ring_start()),
            _ => status(Status::Invalid),
        }
    }

    /// The interrupt (frames arrived, or with a ring, some were sent),
    /// or the doorbell. Without a ring: tell the listener. With one,
    /// `before_sleep` does the work.
    fn interrupt(&mut self) {
        syscall(Syscall::IrqAck, MSI, [0; 4]);
        if self.ring {
            hdr(ring::DRIVER_SLEEPS).store(0, Ordering::SeqCst);
        } else if self.attached && self.rx.has_used() {
            syscall(Syscall::Signal, LISTENER, [0; 4]);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut nic = match start() {
        Ok(n) => n,
        Err((what, code)) => {
            say!("[fail] {what} ({code:#x})");
            superior_sys::park()
        }
    };
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
    let mut reply: Option<([u64; 4], bool)> = None;
    loop {
        nic.before_sleep();
        let r = match reply.take() {
            Some((m, doorbell)) => {
                let x = CapTransfer {
                    grant: doorbell.then_some(DOORBELL as u16),
                    ..accept
                };
                syscall_x(Syscall::ReplyRecv, SERVICE, m, x)
            }
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            nic.interrupt();
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
        let m = nic.serve(r.msg, lent, cap);
        if lent {
            // The caller's frame goes back before the reply.
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some((m, r.msg[0] == nic::RING_START && m[0] == 0));
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
