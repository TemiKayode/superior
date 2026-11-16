//! The kernel's log over USB, through the xHCI Debug Capability
//! ([`superior_xdbc`]), for machines with no serial port: a second machine
//! on a USB 3 debug cable reads it (Linux's `usb_debug` driver makes it
//! `/dev/ttyUSB0`).
//!
//! From the first line printed, the log is kept in a backlog. At boot the
//! kernel looks for an xHCI controller on the buses as the firmware
//! numbered them, takes it from the firmware's USB legacy support and
//! enables its DbC; the backlog then goes out once a debug host configures
//! it, and each line after as it is printed. If there is no DbC, the
//! backlog is dropped and nothing more is kept.
//!
//! The DbC is closed before the IOMMU comes on, which would block its DMA,
//! and before user space starts, where the PCI bus server moves the
//! controller's registers and its driver resets it.

use core::fmt::{self, Write};
use spin::Mutex;
use superior_xdbc::{self as xdbc, Dbc, Page, Regs, State};

/// What the architecture gives: configuration space of the buses the
/// firmware numbered (bus, device << 3 | function, offset), its device
/// memory, and free pages of RAM.
pub struct Pci<'a> {
    pub read: &'a dyn Fn(u8, u8, u16) -> u32,
    pub write: &'a dyn Fn(u8, u8, u16, u32),
    /// Buses the configuration space reaches.
    pub buses: usize,
    /// The kernel's address for device memory at `pa`, mapped if need be.
    pub map: &'a dyn Fn(u64) -> Option<u64>,
    /// A free page of RAM: its physical and kernel addresses.
    pub page: &'a dyn Fn() -> Option<(u64, *mut u8)>,
}

/// The DbC's registers, where the kernel maps them.
pub struct Mmio(u64);

impl Regs for Mmio {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: the DbC's registers, mapped as device memory.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
    }
    fn write32(&self, off: u64, v: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, v) }
    }
}

const BACKLOG: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Before the kernel has looked: kept.
    Keeping,
    /// A DbC is enabled: kept, and sent when it can be.
    Open,
    /// No DbC, or closed: nothing kept.
    Shut,
}

struct Console {
    mode: Mode,
    dbc: Option<Dbc<Mmio>>,
    backlog: [u8; BACKLOG],
    /// Bytes kept, from the start of the backlog; and how many of them
    /// have gone out.
    kept: usize,
    sent: usize,
    /// Bytes that did not fit.
    dropped: u64,
}

static CONSOLE: Mutex<Console> = Mutex::new(Console { mode: Mode::Keeping, dbc: None, backlog: [0; BACKLOG], kept: 0, sent: 0, dropped: 0 });

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.mode == Mode::Shut {
            return Ok(());
        }
        // Room is made by moving what is left to send to the front.
        if self.kept + s.len() > BACKLOG && self.sent > 0 {
            self.backlog.copy_within(self.sent..self.kept, 0);
            self.kept -= self.sent;
            self.sent = 0;
        }
        let n = s.len().min(BACKLOG - self.kept);
        self.backlog[self.kept..self.kept + n].copy_from_slice(&s.as_bytes()[..n]);
        self.kept += n;
        self.dropped += (s.len() - n) as u64;
        self.pump();
        Ok(())
    }
}

impl Console {
    /// Sends what it can: one transfer at a time, once a debug host has
    /// configured the DbC.
    fn pump(&mut self) -> State {
        let Some(d) = self.dbc.as_mut() else { return State::Off };
        let state = d.poll();
        if state == State::Running && !d.busy() && self.sent < self.kept {
            self.sent += d.send(&self.backlog[self.sent..self.kept]);
            if self.sent == self.kept {
                self.sent = 0;
                self.kept = 0;
            }
        }
        state
    }
}

/// Keeps (and, once open, sends) a piece of the log. Called with the
/// architecture's console lock held and interrupts off.
pub fn print(args: fmt::Arguments) {
    if let Some(mut c) = CONSOLE.try_lock() {
        let _ = c.write_fmt(args);
    }
}

/// Finds an xHCI controller with a Debug Capability and enables it,
/// saying what it found. `serial` names the log's other way out.
pub fn init(pci: &Pci, serial: &str) {
    let mut found = None;
    let mut first = None;
    scan(pci, 0, 0, &mut |bus, devfn| {
        if found.is_none() {
            first.get_or_insert((bus, devfn));
            found = open(pci, bus, devfn);
        }
    });
    let at = |(bus, devfn): (u8, u8)| (bus, devfn >> 3, devfn & 7);
    match (found, first) {
        (Some(Ok((place, d))), _) => {
            let (b, dv, f) = at(place);
            let port = d.port();
            {
                let mut c = CONSOLE.lock();
                c.dbc = Some(d);
                c.mode = Mode::Open;
            }
            crate::kprintln!(
                "[ok] USB debug: xHCI at {b:02x}:{dv:02x}.{f}, its Debug Capability on root port {port}: this log goes out over USB once a debug host configures it (as {:04x}:{:04x}), until the IOMMU comes on",
                xdbc::VENDOR,
                xdbc::PRODUCT
            );
        }
        (Some(Err((place, why))), _) => {
            shut();
            let (b, dv, f) = at(place);
            // Unassigned registers are no fault: booted with no firmware
            // to set PCI up (QEMU's -kernel), as the bus server does later.
            let level = if why == UNASSIGNED { "ok" } else { "warn" };
            crate::kprintln!("[{level}] USB debug: xHCI at {b:02x}:{dv:02x}.{f}: {why}; the log stays on {serial}");
        }
        (None, Some(place)) => {
            shut();
            let (b, dv, f) = at(place);
            crate::kprintln!("[ok] USB debug: no xHCI with a Debug Capability (the first, at {b:02x}:{dv:02x}.{f}, has none); the log stays on {serial}");
        }
        (None, None) => {
            shut();
            crate::kprintln!("[ok] USB debug: no xHCI controller; the log stays on {serial}");
        }
    }
}

fn shut() {
    let mut c = CONSOLE.lock();
    c.mode = Mode::Shut;
    c.kept = 0;
    c.sent = 0;
}

/// Calls `found` for each xHCI function (class 0c:03:30) on `bus` and
/// the buses behind its bridges, as the firmware numbered them.
fn scan(pci: &Pci, bus: u8, depth: usize, found: &mut dyn FnMut(u8, u8)) {
    if bus as usize >= pci.buses || depth > 8 {
        return;
    }
    for dev in 0..32u8 {
        for func in 0..8u8 {
            let devfn = dev << 3 | func;
            if (pci.read)(bus, devfn, 0) & 0xffff == 0xffff {
                if func == 0 {
                    break;
                }
                continue;
            }
            let header = (pci.read)(bus, devfn, 0x0c) >> 16 & 0xff;
            if (pci.read)(bus, devfn, 0x08) >> 8 == 0x0c_0330 {
                found(bus, devfn);
            }
            if header & 0x7f == 1 {
                let secondary = ((pci.read)(bus, devfn, 0x18) >> 8) as u8;
                if secondary > bus {
                    scan(pci, secondary, depth + 1, found);
                }
            }
            if func == 0 && header & 0x80 == 0 {
                break;
            }
        }
    }
}

const UNASSIGNED: &str = "no firmware assigned its registers";

type Opened = Result<((u8, u8), Dbc<Mmio>), ((u8, u8), &'static str)>;

/// The DbC of the xHCI at `bus`, `devfn`, enabled; None if it has none.
fn open(pci: &Pci, bus: u8, devfn: u8) -> Option<Opened> {
    let place = (bus, devfn);
    let low = (pci.read)(bus, devfn, 0x10);
    if low & 1 != 0 {
        return Some(Err((place, "its registers are I/O ports, not memory")));
    }
    let high = if low >> 1 & 3 == 2 { (pci.read)(bus, devfn, 0x14) } else { 0 };
    let base = (low & !0xf) as u64 | (high as u64) << 32;
    if base == 0 {
        return Some(Err((place, UNASSIGNED)));
    }
    let read = |off: u64| (pci.map)(base + off).map_or(0, |va| Mmio(va).read32(0));
    let write = |off: u64, v: u32| {
        if let Some(va) = (pci.map)(base + off) {
            Mmio(va).write32(0, v);
        }
    };
    if (pci.map)(base).is_none() {
        return Some(Err((place, "its registers are where the kernel cannot map them")));
    }
    // The registers are at least 64 KiB on every controller; the
    // capability list stays within them.
    let caps = || xdbc::capabilities(read, 0x1_0000);
    let dbc = caps().find(|c| c.1 == xdbc::CAP_DBC)?.0;
    // Memory decoding and bus mastering on: the DbC reads and writes RAM.
    let command = (pci.read)(bus, devfn, 0x04);
    (pci.write)(bus, devfn, 0x04, command & 0xffff | 0b110);
    let legacy = caps().find(|c| c.1 == xdbc::CAP_LEGACY).map(|c| c.0);
    if !xdbc::take_from_firmware(read, write, legacy, 1_000_000) {
        return Some(Err((place, "the firmware would not give it up (USB legacy support)")));
    }
    let Some(va) = (pci.map)(base + dbc).filter(|_| (pci.map)(base + dbc + 0x3c).is_some()) else {
        return Some(Err((place, "its Debug Capability's registers are where the kernel cannot map them")));
    };
    let (Some(page), Some(data)) = ((pci.page)(), (pci.page)()) else {
        return Some(Err((place, "no RAM for its rings")));
    };
    let [page, data] = [page, data].map(|(pa, va)| Page { va, pa });
    Some(Ok((place, Dbc::new(Mmio(va), page, data))))
}

/// Closes the DbC: what is kept goes out first if a debug host is there
/// (for as long as `spins` polls allow), then it is turned off, the debug
/// host seeing it unplugged. Says how it went.
pub fn close(why: &str) {
    let mut c = CONSOLE.lock();
    if c.mode != Mode::Open {
        c.mode = Mode::Shut;
        return;
    }
    // A last line, sent with the rest.
    let _ = writeln!(c, "[ok] USB debug: closed: {why}");
    let mut spins = 0u64;
    while c.sent < c.kept && spins < 50_000_000 {
        if c.pump() != State::Running {
            break;
        }
        spins += 1;
    }
    while c.dbc.as_ref().is_some_and(|d| d.busy()) && spins < 50_000_000 {
        c.pump();
        spins += 1;
    }
    let state = c.dbc.as_ref().map(|d| d.state);
    let sent = c.dbc.as_ref().map_or(0, |d| d.sent);
    let (left, dropped) = (c.kept - c.sent, c.dropped);
    if let Some(d) = c.dbc.as_mut() {
        d.disable();
    }
    c.mode = Mode::Shut;
    drop(c);
    match state {
        Some(State::Running) => {
            crate::kprintln!("[ok] USB debug: closed ({why}): {sent} bytes went out, {left} were left and {dropped} did not fit")
        }
        Some(State::Halted) => crate::kprintln!("[warn] USB debug: closed ({why}): the debug host halted it, after {sent} bytes"),
        _ => crate::kprintln!("[ok] USB debug: closed ({why}): no debug host configured it"),
    }
}

/// After a panic: sends what is kept, if it can, before the machine
/// stops.
pub fn flush() {
    if let Some(mut c) = CONSOLE.try_lock() {
        let mut spins = 0u64;
        while c.mode == Mode::Open && (c.sent < c.kept || c.dbc.as_ref().is_some_and(|d| d.busy())) && spins < 50_000_000 {
            if c.pump() != State::Running {
                break;
            }
            spins += 1;
        }
    }
}
