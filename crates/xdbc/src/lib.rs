//! The xHCI Debug Capability (xHCI 1.2, section 7.6): a USB device built
//! into the host controller, on one of its USB 3 root ports, which a
//! second machine (the debug host) sees over a USB 3 debug cable as a
//! device with one bulk OUT and one bulk IN endpoint. It works without the
//! host controller running or any driver for it, so the kernel can send its
//! log over it from early boot, on a laptop with no serial port.
//!
//! This crate is the part with no hardware in it: finding the capability
//! in the controller's extended capability list, taking the controller
//! from the firmware's USB legacy support, laying out the DbC's data
//! structures in two pages of DMA memory, and running its event ring and
//! OUT transfer ring. The registers come through [`Regs`], so the host
//! tests drive it against a simulated controller.
//!
//! Only the OUT direction is used: the log goes out, nothing comes in.
//! The debug host sees vendor 0x1d6b, product 0x0010, protocol 1: the IDs
//! Linux's own DbC uses, which Linux's `usb_debug` driver binds as a
//! serial port (`/dev/ttyUSB0`).
//!
//! DMA memory is taken to be coherent with the CPU's caches (x86-64; the
//! PCI Express of Arm machines with an SMMU is, as QEMU's is).

#![no_std]

#[cfg(test)]
extern crate std;

use core::sync::atomic::{Ordering, fence};

/// Extended capability IDs (xHCI 7): USB legacy support, and the DbC.
pub const CAP_LEGACY: u32 = 1;
pub const CAP_DBC: u32 = 10;

/// The extended capabilities from `HCCPARAMS1` (capability register
/// 0x10), as offsets into the controller's registers: each one's offset
/// and ID. `read` reads a 32-bit register at an offset; `len` is the
/// registers' size, which no capability may run past.
pub fn capabilities(read: impl Fn(u64) -> u32, len: u64) -> impl Iterator<Item = (u64, u32)> {
    let mut at = ((read(0x10) >> 16) as u64) << 2;
    let mut left = 256;
    core::iter::from_fn(move || {
        if at == 0 || at + 4 > len || left == 0 {
            return None;
        }
        left -= 1;
        let v = read(at);
        let here = at;
        let next = ((v >> 8) & 0xff) as u64;
        at = if next == 0 { 0 } else { at + (next << 2) };
        Some((here, v & 0xff))
    })
}

/// Takes the controller from the firmware: sets USB legacy support's OS
/// owned semaphore (bit 24) at `cap` and waits up to `tries` reads for the
/// firmware's (bit 16) to clear, then turns off its SMI enables. True if
/// the firmware let go (or there was no legacy support to take).
pub fn take_from_firmware(read: impl Fn(u64) -> u32, write: impl Fn(u64, u32), cap: Option<u64>, tries: u32) -> bool {
    let Some(cap) = cap else { return true };
    write(cap, read(cap) | 1 << 24);
    for _ in 0..tries {
        if read(cap) & 1 << 16 == 0 {
            // USBLEGCTLSTS: SMI enables off, SMI change bits written to clear.
            write(cap + 4, (read(cap + 4) & !0x0001_e01f) | 0xe000_0000);
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// The DbC's registers, as offsets from its capability.
pub mod reg {
    pub const DCID: u64 = 0x00;
    pub const DCDB: u64 = 0x04;
    pub const DCERSTSZ: u64 = 0x08;
    pub const DCERSTBA: u64 = 0x10;
    pub const DCERDP: u64 = 0x18;
    pub const DCCTRL: u64 = 0x20;
    pub const DCST: u64 = 0x24;
    pub const DCPORTSC: u64 = 0x28;
    pub const DCCP: u64 = 0x30;
    pub const DCDDI1: u64 = 0x38;
    pub const DCDDI2: u64 = 0x3c;

    /// DCCTRL: DbC Run (the debug host configured it), Link Status Event
    /// Enable, Halt OUT TR, Halt IN TR, DbC Run Change, DbC Enable.
    pub const RUN: u32 = 1 << 0;
    pub const LSE: u32 = 1 << 1;
    pub const HALT_OUT: u32 = 1 << 2;
    pub const HALT_IN: u32 = 1 << 3;
    pub const RUN_CHANGE: u32 = 1 << 4;
    pub const ENABLE: u32 = 1 << 31;

    /// DCPORTSC: Current Connect Status, and the change bits (written 1
    /// to clear): connect, reset, link state, config error.
    pub const CCS: u32 = 1 << 0;
    pub const CHANGES: u32 = 1 << 17 | 1 << 21 | 1 << 22 | 1 << 23;
}

/// The DbC's registers.
pub trait Regs {
    fn read32(&self, off: u64) -> u32;
    fn write32(&self, off: u64, v: u32);
    fn write64(&self, off: u64, v: u64) {
        self.write32(off, v as u32);
        self.write32(off + 4, (v >> 32) as u32);
    }
}

/// A page of DMA memory: where the CPU reaches it, and its address on the
/// bus (physical: the kernel sets the DbC up before any IOMMU is on).
#[derive(Clone, Copy)]
pub struct Page {
    pub va: *mut u8,
    pub pa: u64,
}

pub const PAGE: usize = 4096;

/// The layout of the structures page.
mod at {
    /// Event Ring Segment Table: one entry.
    pub const ERST: usize = 0x000;
    /// The event ring's one segment.
    pub const EVENTS: usize = 0x040;
    /// The DbC context: the info context, then the OUT and IN endpoints'
    /// (64 bytes each, whatever the controller's context size).
    pub const CONTEXT: usize = 0x200;
    /// String descriptors: language IDs, manufacturer, product, serial.
    pub const STRINGS: usize = 0x400;
    pub const STRING: usize = 0x40;
    /// Transfer rings.
    pub const OUT_RING: usize = 0x800;
    pub const IN_RING: usize = 0xa00;
}

/// TRBs in each ring (the last of a transfer ring is a link back).
pub const RING_TRBS: usize = 16;
pub const EVENT_TRBS: usize = 16;

/// TRB types (xHCI 6.4.6).
pub mod trb {
    pub const NORMAL: u32 = 1;
    pub const LINK: u32 = 6;
    pub const TRANSFER_EVENT: u32 = 32;
    pub const PORT_STATUS_CHANGE: u32 = 34;
    /// Control word bits: cycle, toggle cycle (link), interrupt on
    /// completion.
    pub const CYCLE: u32 = 1 << 0;
    pub const TOGGLE: u32 = 1 << 1;
    pub const IOC: u32 = 1 << 5;
}

/// What the debug host sees.
pub const VENDOR: u16 = 0x1d6b;
pub const PRODUCT: u16 = 0x0010;
pub const PROTOCOL: u8 = 1;
pub const MANUFACTURER: &str = "Superior";
pub const PRODUCT_NAME: &str = "Superior kernel log";
pub const SERIAL: &str = "0";

/// Where the DbC stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Enabled, waiting for a debug host: no cable, or not configured yet.
    Waiting,
    /// A debug host configured it: data can go out.
    Running,
    /// Its OUT endpoint halted (a host error); nothing more goes out.
    Halted,
    /// Turned off.
    Off,
}

pub struct Dbc<R: Regs> {
    regs: R,
    page: Page,
    data: Page,
    /// The OUT ring's enqueue slot and producer cycle.
    out_at: usize,
    out_cycle: bool,
    /// The event ring's dequeue slot and consumer cycle.
    event_at: usize,
    event_cycle: bool,
    /// Bytes of the data page in flight (one transfer at a time).
    in_flight: usize,
    pub sent: u64,
    pub state: State,
}

// SAFETY: the pages are the DbC's alone; the kernel keeps it behind a lock.
unsafe impl<R: Regs + Send> Send for Dbc<R> {}

impl<R: Regs> Dbc<R> {
    /// Lays out the DbC's structures in `page` (zeroed first), with `data`
    /// the page transfers go from, programs its registers and enables it.
    /// It then waits, without blocking, for a debug host ([`Dbc::poll`]).
    pub fn new(regs: R, page: Page, data: Page) -> Dbc<R> {
        // SAFETY: the caller hands over both pages.
        unsafe { core::ptr::write_bytes(page.va, 0, PAGE) };
        let d = Dbc { regs, page, data, out_at: 0, out_cycle: true, event_at: 0, event_cycle: true, in_flight: 0, sent: 0, state: State::Waiting };
        // The event ring: one segment, its table's one entry.
        d.put64(at::ERST, page.pa + at::EVENTS as u64);
        d.put32(at::ERST + 8, EVENT_TRBS as u32);
        // Strings, each a USB string descriptor: length, type 3, then the
        // language ID (US English) or UTF-16 text.
        let mut lengths = 0u32;
        let mut string = |i: usize, units: &mut dyn Iterator<Item = u16>| {
            let o = at::STRINGS + i * at::STRING;
            let mut n = 0;
            for (k, u) in units.take((at::STRING - 2) / 2).enumerate() {
                d.put16(o + 2 + 2 * k, u);
                n += 1;
            }
            let len = 2 + 2 * n as u32;
            d.put8(o, len as u8);
            d.put8(o + 1, 3);
            lengths |= len << (8 * i);
        };
        string(0, &mut [0x0409u16].into_iter());
        string(1, &mut MANUFACTURER.encode_utf16());
        string(2, &mut PRODUCT_NAME.encode_utf16());
        string(3, &mut SERIAL.encode_utf16());
        // The info context: the strings' addresses, then their lengths.
        for i in 0..4 {
            d.put64(at::CONTEXT + 8 * i, page.pa + (at::STRINGS + i * at::STRING) as u64);
        }
        d.put32(at::CONTEXT + 32, lengths);
        // The endpoints: bulk OUT (type 2) and bulk IN (type 6), 1024-byte
        // packets, the burst the controller says, three retries; each ring
        // dequeued from its start, cycle 1.
        let burst = (d.regs.read32(reg::DCCTRL) >> 16) & 0xff;
        for (ctx, kind, ring) in [(at::CONTEXT + 0x40, 2, at::OUT_RING), (at::CONTEXT + 0x80, 6, at::IN_RING)] {
            d.put32(ctx + 4, 3 << 1 | kind << 3 | burst << 8 | 1024 << 16);
            d.put64(ctx + 8, page.pa + ring as u64 | 1);
            d.put32(ctx + 16, 1024);
            // A link at the ring's end, back to its start, toggling cycle.
            let link = ring + 16 * (RING_TRBS - 1);
            d.put64(link, page.pa + ring as u64);
            d.put32(link + 12, trb::LINK << 10 | trb::TOGGLE);
        }
        fence(Ordering::SeqCst);
        let r = &d.regs;
        r.write32(reg::DCDDI1, (VENDOR as u32) << 16 | PROTOCOL as u32);
        r.write32(reg::DCDDI2, PRODUCT as u32);
        r.write32(reg::DCERSTSZ, 1);
        r.write64(reg::DCERSTBA, page.pa + at::ERST as u64);
        r.write64(reg::DCERDP, page.pa + at::EVENTS as u64);
        r.write64(reg::DCCP, page.pa + at::CONTEXT as u64);
        r.write32(reg::DCCTRL, reg::ENABLE | reg::LSE);
        d
    }

    /// The root port the DbC shares (DCST), once enabled; 0 until it says.
    pub fn port(&self) -> u32 {
        self.regs.read32(reg::DCST) >> 24
    }

    /// Reads where it stands, clearing what changed, and takes any events:
    /// a finished transfer frees the data page.
    pub fn poll(&mut self) -> State {
        if self.state == State::Off {
            return State::Off;
        }
        let ctrl = self.regs.read32(reg::DCCTRL);
        if ctrl & reg::RUN_CHANGE != 0 {
            self.regs.write32(reg::DCCTRL, ctrl & (reg::ENABLE | reg::LSE) | reg::RUN_CHANGE);
        }
        let port = self.regs.read32(reg::DCPORTSC);
        if port & reg::CHANGES != 0 {
            self.regs.write32(reg::DCPORTSC, port & reg::CHANGES);
        }
        self.events();
        self.state = if ctrl & reg::HALT_OUT != 0 {
            State::Halted
        } else if ctrl & reg::RUN != 0 && port & reg::CCS != 0 {
            State::Running
        } else {
            // Unplugged or reset: what was in flight is gone.
            self.in_flight = 0;
            State::Waiting
        };
        self.state
    }

    /// True while a transfer is in flight.
    pub fn busy(&self) -> bool {
        self.in_flight > 0
    }

    /// Queues up to a page of `bytes` on the OUT ring, if the debug host
    /// has configured the DbC and no transfer is in flight. Returns how
    /// many were taken.
    pub fn send(&mut self, bytes: &[u8]) -> usize {
        if self.state != State::Running || self.busy() || bytes.is_empty() {
            return 0;
        }
        let n = bytes.len().min(PAGE);
        // SAFETY: the data page is the DbC's, and no transfer reads it now.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.data.va, n) };
        let slot = at::OUT_RING + 16 * self.out_at;
        self.put64(slot, self.data.pa);
        self.put32(slot + 8, n as u32);
        fence(Ordering::SeqCst);
        // The cycle bit last: the controller owns the TRB from then.
        self.put32(slot + 12, trb::NORMAL << 10 | trb::IOC | self.out_cycle as u32);
        self.out_at += 1;
        if self.out_at == RING_TRBS - 1 {
            // Hand the link over too, and go round with the other cycle.
            let link = at::OUT_RING + 16 * (RING_TRBS - 1);
            fence(Ordering::SeqCst);
            self.put32(link + 12, trb::LINK << 10 | trb::TOGGLE | self.out_cycle as u32);
            self.out_at = 0;
            self.out_cycle = !self.out_cycle;
        }
        fence(Ordering::SeqCst);
        self.in_flight = n;
        // Doorbell: target 0, the OUT endpoint.
        self.regs.write32(reg::DCDB, 0);
        n
    }

    /// Takes the events the controller has written, moving the dequeue
    /// pointer past them.
    fn events(&mut self) {
        let mut took = false;
        loop {
            let slot = at::EVENTS + 16 * self.event_at;
            let control = self.get32(slot + 12);
            if (control & trb::CYCLE != 0) != self.event_cycle {
                break;
            }
            // A transfer event ends the one transfer in flight, whatever
            // its completion code: the log is best effort.
            if (control >> 10) & 0x3f == trb::TRANSFER_EVENT {
                if self.in_flight > 0 {
                    self.sent += self.in_flight as u64;
                    self.in_flight = 0;
                }
            }
            took = true;
            self.event_at += 1;
            if self.event_at == EVENT_TRBS {
                self.event_at = 0;
                self.event_cycle = !self.event_cycle;
            }
        }
        if took {
            self.regs.write64(reg::DCERDP, self.page.pa + (at::EVENTS + 16 * self.event_at) as u64);
        }
    }

    /// Turns the DbC off: the debug host sees it unplugged.
    pub fn disable(&mut self) {
        self.regs.write32(reg::DCCTRL, 0);
        self.state = State::Off;
        self.in_flight = 0;
    }

    fn ptr(&self, o: usize) -> *mut u8 {
        // SAFETY: offsets within the structures page.
        unsafe { self.page.va.add(o) }
    }
    fn put8(&self, o: usize, v: u8) {
        // SAFETY: the structures page, the DbC's.
        unsafe { core::ptr::write_volatile(self.ptr(o), v) }
    }
    fn put16(&self, o: usize, v: u16) {
        for (i, b) in v.to_le_bytes().into_iter().enumerate() {
            self.put8(o + i, b);
        }
    }
    fn put32(&self, o: usize, v: u32) {
        // SAFETY: as above; every offset used is 4-byte aligned.
        unsafe { core::ptr::write_volatile(self.ptr(o) as *mut u32, v.to_le()) }
    }
    fn put64(&self, o: usize, v: u64) {
        self.put32(o, v as u32);
        self.put32(o + 4, (v >> 32) as u32);
    }
    fn get32(&self, o: usize) -> u32 {
        // SAFETY: as above.
        u32::from_le(unsafe { core::ptr::read_volatile(self.ptr(o) as *const u32) })
    }
}

#[cfg(test)]
mod tests;
