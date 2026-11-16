//! The PCI bus server (spec section 5): the only component that touches
//! PCI configuration space.
//!
//! It finds the functions on bus 0 and behind every bridge (below), and
//! serves the `pci` interface
//! (`superior_objects::interfaces::pci`) to drivers. A driver opens one
//! function; from then on it is that function's only owner and gets only
//! that function's BAR pages (device frames made from the BAR window) and
//! MSI vectors. Configuration writes go through here, and only the few a
//! driver needs are offered: bus mastering, MSI-X enable.
//!
//! DMA: each opened function gets its own I/O address space (IOMMU domain),
//! bound to its requester ID and granted to the driver with the `OPEN`
//! reply. The device can reach only frames the driver maps into it, and
//! nothing until it does. Without an IOMMU there is no domain, and bus
//! mastering is refused: a device that could DMA anywhere is not handed
//! out.
//!
//! Opening resets the function first. The last owner's domain is revoked
//! (every copy of it, so its DMA is blocked before anything else happens),
//! then decoding and bus mastering go off, every BAR page and MSI vector
//! the last owner held is revoked, MSI-X goes off, and a Function Level
//! Reset follows if the function has one. A restarted driver (same badge)
//! reopens its device this way, so it always starts from a quiet device
//! and a fresh, empty domain. A device without FLR is left to the
//! driver's own reset routine (virtio: writing 0 to the device status).
//!
//! Suspend (`power`, from the Component Manager, badge 0): on `SUSPEND`
//! it keeps every function's configuration header, and on `RESUME` it
//! writes it back, bridges before what is behind them: a suspend to RAM
//! resets every device, losing its BARs, bus numbers and windows, which
//! the drivers' own resume needs in place. (MSI and MSI-X are the
//! drivers', which program them again.)
//!
//! Bridges: a PCI-to-PCI bridge (a PCIe root port, say) is not handed out
//! but configured here. The scan gives it the next bus number, walks the
//! bus behind it (and any bridges there); then everything found behind
//! it gets its BARs next to each other, and the bridge's windows are set
//! to just those ranges (below). Buses are numbered up to
//! `abi::PCI_BUSES`: every bus on x86-64, the 16 the ECAM window holds
//! on AArch64.
//! A function behind a bridge has a requester ID of its own only on PCI
//! Express: behind a conventional bridge its DMA and interrupts carry the
//! bridge's ID, so no domain could isolate it, and it gets none (and so
//! no bus mastering).
//!
//! Windows: a bridge has three, for memory, prefetchable memory and I/O
//! ports, and each is set to exactly what the BARs of that kind behind
//! it take (in megabytes, or 4 KiB of ports), a bridge's ranges lying
//! inside those of the bridge above it; one with nothing of a kind
//! behind it keeps that window shut.
//!
//! I/O BARs get ports from a range the manifest may give (`device pci-io
//! 88`). A driver does not get the ports themselves: it reads and writes
//! its BAR through this server (`pci::IO_READ`, `pci::IO_WRITE`), which
//! keeps each access inside the BAR. `pci::CLOSE` gives a function back.
//!
//! Hot-plug: a PCI Express port on bus 0 whose slot can take a card
//! while the machine runs is looked at five times a second (if the
//! manifest gives this server a notification for the timer). A card that
//! appears is powered, found, and given addresses (new ones: the port's
//! windows move to them), and can be opened like any other. One whose
//! attention button is pressed (the request to take it out), or that is
//! gone, loses everything first: its functions' domains, BAR pages and
//! interrupts are revoked, whoever held them, and the functions
//! forgotten; then the slot is powered off, which lets the card go. A
//! bridge plugged in is not configured.
//!
//! Legacy interrupts: a function with no MSI gets the interrupt line
//! its pin is wired to (`pci::INTX`), one function a line. A bridge passes
//! the pins of what is behind it on rotated by their device numbers; the
//! root-bus device and pin that comes out on reach the line the kernel
//! says (`IntxLine`), as the firmware routes them: any wiring, not just
//! four rotated wires.
//!
//! Slots: 0 the `pci` endpoint (receive), 1 configuration space (I/O ports
//! on x86-64, ECAM device memory on AArch64), 2 the BAR window (device
//! memory), 3.. the MSI vectors, then the IOMMU-control capability (empty
//! without an IOMMU) and untyped memory for the domains; from 80, if the
//! manifest gives them (`device intx 80`), the (up to 8) legacy PCI interrupt
//! lines. Its CSpace has 2^7 slots.

#![no_std]
#![no_main]

use superior_driver::dma_address;
use superior_objects::abi::{CapTransfer, Error, ObjectType, PCI_BUSES, Syscall, root};
use superior_objects::interfaces::{Status, pci, power};
use superior_sys::{print_line, syscall, syscall_x};

const SERVICE: u64 = 0;
const CONFIG: u64 = 1;
const WINDOW: u64 = 2;
const MSI: u64 = 3;
const MSI_COUNT: usize = root::MSI_COUNT as usize;
const IOMMU: u64 = MSI + MSI_COUNT as u64;
const UNTYPED: u64 = IOMMU + 1;
const SCRATCH: u64 = UNTYPED + 1;
/// One ECAM page per function found (AArch64).
const FUNC_SLOTS: u64 = SCRATCH + 1;
const MAX_FUNCS: usize = 32;
/// The original of every BAR page handed out.
const BAR_SLOTS: u64 = FUNC_SLOTS + MAX_FUNCS as u64;
const MAX_BAR_PAGES: usize = 24;
/// Functions open at once, each with a block of untyped memory its domain
/// is made from (revoking the block destroys the domain and every copy),
/// and the domain itself.
const MAX_OPEN: usize = 4;
const DOMAIN_MEMORY: u64 = BAR_SLOTS + MAX_BAR_PAGES as u64;
const DOMAINS: u64 = DOMAIN_MEMORY + MAX_OPEN as u64;
const DOMAIN_BITS: u64 = 16;
/// A notification, if the manifest gives one (`notification 78`): its
/// timer has the hot-plug slots looked at.
const NOTIFY: u64 = 78;
/// Ticks between looks at the hot-plug slots (200 ms).
const SLOT_POLL: u64 = 20;
/// The legacy interrupt lines (up to 8).
const INTX: u64 = 80;
/// The I/O port range (ports on x86-64, a window of device memory on
/// AArch64), and on AArch64 a slot for each page of it.
const IO_PORTS: u64 = 88;
#[cfg(target_arch = "aarch64")]
const IO_PAGE_SLOTS: u64 = 89;
#[cfg(target_arch = "aarch64")]
const IO_PAGES: u64 = 16;
const _: () = assert!(DOMAINS + MAX_OPEN as u64 <= INTX);
const INTX_COUNT: usize = root::INTX_COUNT as usize;

// Configuration space.
const COMMAND: u64 = 0x04;
const CMD_IO: u32 = 1 << 0;
const CMD_MEMORY: u32 = 1 << 1;
const CMD_BUS_MASTER: u32 = 1 << 2;
const CMD_INTX_DISABLE: u32 = 1 << 10;
const CAP_PCIE: u8 = 0x10;
const CAP_MSIX: u8 = 0x11;
const CAP_MSI: u8 = 0x05;
// A bridge's own registers (header type 1).
const BUS_NUMBERS: u64 = 0x18;
const IO_WINDOW: u64 = 0x1c;
const MEMORY_WINDOW: u64 = 0x20;
const PREFETCH_WINDOW: u64 = 0x24;
const PREFETCH_BASE_UPPER: u64 = 0x28;
const PREFETCH_LIMIT_UPPER: u64 = 0x2c;
const IO_WINDOW_UPPER: u64 = 0x30;
// A PCI Express port's slot registers, from its capability.
const SLOT_CAPABILITIES: u64 = 0x14;
const SLOT_CONTROL: u64 = 0x18;
const SLOT_STATUS: u64 = 0x1a;
/// Status: the attention button was pressed (asking for the card to be
/// let go); a card is present; and the events, cleared by writing them.
const SLOT_ATTENTION: u32 = 1 << 0;
const SLOT_PRESENT: u32 = 1 << 6;
const SLOT_EVENTS: u32 = 0x11f;
/// Control: the power indicator (both bits: off; the low one: on), and
/// power off.
const SLOT_INDICATOR: u32 = 3 << 8;
const SLOT_INDICATOR_ON: u32 = 1 << 8;
const SLOT_POWER_OFF: u32 = 1 << 10;
/// A bridge's memory window is in whole megabytes.
const MEGABYTE: u64 = 1 << 20;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("pci: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy)]
struct Bar {
    /// A memory address in the BAR window, or for an I/O BAR a port.
    addr: u64,
    size: u64,
    is64: bool,
    io: bool,
}

/// A bridge's windows, for the log: "memory A to B, prefetchable C to D,
/// I/O E to F", those that are open; "none" if all are shut.
struct Windows([Option<(u64, u64)>; 3]);

impl core::fmt::Display for Windows {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut any = false;
        for (range, name) in self.0.iter().zip(["memory", "prefetchable", "I/O"]) {
            if let Some((a, b)) = range {
                write!(f, "{}{name} {a:#x} to {b:#x}", if any { ", " } else { "" })?;
                any = true;
            }
        }
        if any { Ok(()) } else { write!(f, "none") }
    }
}

/// The three kinds of address a BAR asks for, each with a window of its
/// own in a bridge.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Memory = 0,
    Prefetch = 1,
    Io = 2,
}

#[derive(Clone, Copy)]
struct Func {
    bus: u8,
    dev: u8,
    func: u8,
    ids: u32,
    class: u32,
    /// The owning client's badge; 0 if none.
    owner: u64,
    bars: [Option<Bar>; 6],
    sized: bool,
    /// MSI vectors given to it: indexes into the pool.
    msi: [Option<u8>; MSI_COUNT],
    /// Its domain: an index into the domain slots.
    domain: Option<u8>,
    /// It has a live domain, so it may master the bus.
    dma: bool,
    /// A bridge: configured by the scan, never handed out.
    bridge: bool,
    /// Its requester ID is its own (it is on bus 0, or only PCI Express
    /// bridges lie between), so a domain can isolate it.
    isolated: bool,
    /// The kernel would not bind it to a domain: the DMAR puts it under
    /// no IOMMU unit the kernel drives, so nothing can hold its DMA.
    uncovered: bool,
    /// For a bridge: the bus behind it and the last bus behind that (0:
    /// it was given none), whether it is a PCI Express port, and its
    /// memory, prefetchable and I/O windows (first and last address).
    secondary: u8,
    subordinate: u8,
    express: bool,
    windows: [Option<(u64, u64)>; 3],
}

struct Bus {
    funcs: [Option<Func>; MAX_FUNCS],
    /// Each function's configuration header, kept across a suspend.
    saved: [[u32; 16]; MAX_FUNCS],
    /// (function, BAR, page) of each BAR page original.
    bar_pages: [Option<(u8, u8, u16)>; MAX_BAR_PAGES],
    msi_owner: [Option<u8>; MSI_COUNT],
    /// The function that has each legacy interrupt line.
    intx_owner: [Option<u8>; INTX_COUNT],
    /// The function each domain slot belongs to, and whether the slot's
    /// block of memory has been made (it is kept when its function goes).
    domain_owner: [Option<u8>; MAX_OPEN],
    domain_made: [bool; MAX_OPEN],
    /// Finding what was plugged in: bridges are left alone.
    hot: bool,
    window_base: u64,
    window_next: u64,
    /// The ports I/O BARs are given: the next free, and the end (both 0
    /// if the manifest gave no port range).
    io_next: u64,
    io_end: u64,
    /// The next bus number to give a bridge.
    next_bus: u16,
}

// ---- I/O ports ------------------------------------------------------------

/// The port range I/O BARs are given, and access to it: real ports on
/// x86-64; on AArch64 the machine's window of device memory that stands
/// for them, a page of it mapped when first touched.
#[cfg(target_arch = "x86_64")]
mod ports {
    use super::*;
    /// QEMU's q35 leaves these to PCI (0xcf8 to 0xcff, below, are
    /// configuration space's own).
    const FIRST: u64 = 0xd000;
    const END: u64 = 0x1_0000;

    pub fn range() -> Option<(u64, u64)> {
        // An empty slot: the manifest gave no port range.
        (syscall(Syscall::IoPortIn, IO_PORTS, [FIRST, 1, 0, 0]).status == 0).then_some((FIRST, END))
    }

    pub fn access(port: u64, width: u64, value: Option<u64>) -> Option<u64> {
        let r = match value {
            Some(v) => syscall(Syscall::IoPortOut, IO_PORTS, [port, width, v, 0]),
            None => syscall(Syscall::IoPortIn, IO_PORTS, [port, width, 0, 0]),
        };
        (r.status == 0).then_some(r.msg[0])
    }
}

#[cfg(target_arch = "aarch64")]
mod ports {
    use super::*;
    use superior_driver::{Mmio, map};
    use superior_sys::USER_BASE;

    const IO_VA: u64 = USER_BASE + 0x5000_0000;
    /// Port 0 means "none" to some devices: start a page up.
    const FIRST: u64 = 0x1000;
    const END: u64 = IO_PAGES * 4096;

    /// Maps the page of the window with `port` in it, once.
    fn page(port: u64) -> bool {
        let p = port / 4096;
        let slot = IO_PAGE_SLOTS + p;
        // Mapped already if the slot is taken.
        p < IO_PAGES
            && (syscall(Syscall::DeviceFrame, IO_PORTS, [p * 4096, slot, 0, 0]).status != 0
                || map(slot, IO_VA + p * 4096, true).is_ok())
    }

    pub fn range() -> Option<(u64, u64)> {
        let slot = IO_PAGE_SLOTS + FIRST / 4096;
        let there = syscall(Syscall::DeviceFrame, IO_PORTS, [FIRST, slot, 0, 0]).status == 0
            && map(slot, IO_VA + FIRST, true).is_ok();
        there.then_some((FIRST, END))
    }

    pub fn access(port: u64, width: u64, value: Option<u64>) -> Option<u64> {
        if !page(port) {
            return None;
        }
        let m = Mmio { base: IO_VA };
        Some(match (value, width) {
            (None, 1) => m.read8(port) as u64,
            (None, 2) => m.read16(port) as u64,
            (None, _) => m.read32(port) as u64,
            (Some(v), 1) => {
                m.write8(port, v as u8);
                0
            }
            (Some(v), 2) => {
                m.write16(port, v as u16);
                0
            }
            (Some(v), _) => {
                m.write32(port, v as u32);
                0
            }
        })
    }
}

// ---- configuration space access -----------------------------------------

#[cfg(target_arch = "x86_64")]
mod config {
    use super::*;
    fn address(f: &Func, off: u64) -> u64 {
        0x8000_0000
            | (f.bus as u64) << 16
            | (f.dev as u64) << 11
            | (f.func as u64) << 8
            | (off & 0xfc)
    }
    pub fn read(_i: usize, f: &Func, off: u64) -> u32 {
        syscall(Syscall::IoPortOut, CONFIG, [0xcf8, 4, address(f, off), 0]);
        syscall(Syscall::IoPortIn, CONFIG, [0xcfc, 4, 0, 0]).msg[0] as u32
    }
    pub fn write(_i: usize, f: &Func, off: u64, v: u32, width: u64) {
        syscall(Syscall::IoPortOut, CONFIG, [0xcf8, 4, address(f, off), 0]);
        syscall(
            Syscall::IoPortOut,
            CONFIG,
            [0xcfc + (off & 3), width, v as u64, 0],
        );
    }
    /// Nothing to map with ports.
    pub fn attach(_i: usize, _f: &Func) -> bool {
        true
    }
    pub fn detach(_i: usize) {}
}

#[cfg(target_arch = "aarch64")]
mod config {
    use super::*;
    use superior_driver::{Mmio, map};
    use superior_sys::USER_BASE;

    const ECAM_VA: u64 = USER_BASE + 0x4000_0000;

    fn regs(i: usize) -> Mmio {
        Mmio {
            base: ECAM_VA + i as u64 * 4096,
        }
    }
    pub fn read(i: usize, _f: &Func, off: u64) -> u32 {
        regs(i).read32(off & !3)
    }
    pub fn write(i: usize, _f: &Func, off: u64, v: u32, width: u64) {
        match width {
            1 => regs(i).write8(off, v as u8),
            2 => regs(i).write16(off, v as u16),
            _ => regs(i).write32(off & !3, v),
        }
    }
    /// Maps the function's ECAM page into its slot.
    pub fn attach(i: usize, f: &Func) -> bool {
        let off = (f.bus as u64) << 20 | (f.dev as u64) << 15 | (f.func as u64) << 12;
        let slot = FUNC_SLOTS + i as u64;
        syscall(Syscall::DeviceFrame, CONFIG, [off, slot, 0, 0]).status == 0
            && map(slot, ECAM_VA + i as u64 * 4096, true).is_ok()
    }
    pub fn detach(i: usize) {
        let slot = FUNC_SLOTS + i as u64;
        syscall(Syscall::FrameUnmap, slot, [0; 4]);
        syscall(Syscall::CapDelete, slot, [0; 4]);
    }
}

impl Bus {
    fn read(&self, i: usize, off: u64) -> u32 {
        config::read(i, self.funcs[i].as_ref().unwrap(), off)
    }

    fn write(&self, i: usize, off: u64, v: u32, width: u64) {
        config::write(i, self.funcs[i].as_ref().unwrap(), off, v, width)
    }

    fn read8(&self, i: usize, off: u64) -> u8 {
        (self.read(i, off & !3) >> (8 * (off & 3))) as u8
    }

    fn read16(&self, i: usize, off: u64) -> u16 {
        (self.read(i, off & !3) >> (8 * (off & 2))) as u16
    }

    fn set_command(&self, i: usize, set: u32, clear: u32) {
        let cmd = self.read16(i, COMMAND) as u32;
        self.write(i, COMMAND, (cmd | set) & !clear, 2);
    }

    fn capability(&self, i: usize, id: u8) -> Option<u64> {
        if self.read(i, 0x04) >> 16 & 0x10 == 0 {
            return None;
        }
        let mut at = self.read8(i, 0x34) as u64 & !3;
        for _ in 0..48 {
            if at == 0 {
                return None;
            }
            if self.read8(i, at) == id {
                return Some(at);
            }
            at = self.read8(i, at + 1) as u64 & !3;
        }
        None
    }

    /// Finds the functions on `bus` and, through its bridges, behind it,
    /// numbering the buses as it goes. `isolated`: functions here have
    /// requester IDs of their own.
    fn scan(&mut self, bus: u8, isolated: bool) {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let Some(n) = self.funcs.iter().position(Option::is_none) else {
                    say!("more than {MAX_FUNCS} functions: the rest are left alone");
                    return;
                };
                let mut f = Func {
                    bus,
                    dev,
                    func,
                    ids: 0,
                    class: 0,
                    owner: 0,
                    bars: [None; 6],
                    sized: false,
                    msi: [None; MSI_COUNT],
                    domain: None,
                    dma: false,
                    bridge: false,
                    isolated,
                    uncovered: false,
                    secondary: 0,
                    subordinate: 0,
                    express: false,
                    windows: [None; 3],
                };
                if !config::attach(n, &f) {
                    return;
                }
                let id = config::read(n, &f, 0);
                if id & 0xffff == 0xffff {
                    config::detach(n);
                    if func == 0 {
                        break; // no device here
                    }
                    continue;
                }
                f.ids = (id & 0xffff) << 16 | id >> 16;
                f.class = config::read(n, &f, 0x08) >> 8;
                let header = config::read(n, &f, 0x0c) >> 16;
                f.bridge = header & 0x7f == 1;
                say!(
                    "{:02x}:{:02x}.{} {:04x}:{:04x} class {:06x}{}",
                    f.bus,
                    dev,
                    func,
                    f.ids >> 16,
                    f.ids & 0xffff,
                    f.class,
                    if f.bridge { ", a bridge" } else { "" }
                );
                self.funcs[n] = Some(f);
                // Nothing decodes or masters the bus until it is laid
                // out and, for a device, opened.
                self.set_command(n, 0, CMD_MEMORY | CMD_BUS_MASTER | CMD_IO);
                if f.bridge {
                    // Firmware may have numbered the buses its own way:
                    // until this bridge is given a number below, it must
                    // answer for none.
                    let latency = self.read(n, BUS_NUMBERS) & 0xff00_0000;
                    self.write(n, BUS_NUMBERS, latency, 4);
                }
                if func == 0 && header & 0x80 == 0 {
                    break;
                }
            }
        }
        // Every bridge on this bus now forwards nothing, so each can be
        // given its bus in turn.
        for n in 0..MAX_FUNCS {
            if matches!(self.funcs[n], Some(f) if f.bridge && f.bus == bus && f.secondary == 0) {
                self.bridge(n, isolated);
            }
        }
    }

    /// Numbers the bus behind bridge `n` and finds what is on it (and
    /// behind any bridges there). Its windows stay shut until `layout`.
    fn bridge(&mut self, n: usize, isolated: bool) {
        let f = self.funcs[n].unwrap();
        if self.hot {
            say!("{:02x}:{:02x}.{}: a bridge plugged in is not configured", f.bus, f.dev, f.func);
            return;
        }
        if self.next_bus as u64 >= PCI_BUSES {
            say!(
                "{:02x}:{:02x}.{}: no bus number left for what is behind it",
                f.bus,
                f.dev,
                f.func
            );
            return;
        }
        let secondary = self.next_bus as u8;
        self.next_bus += 1;
        // Only a PCI Express port passes requester IDs on unchanged; one
        // that bridges to conventional PCI (type 7) answers for all
        // behind it, as a conventional bridge does.
        let express = self
            .capability(n, CAP_PCIE)
            .is_some_and(|c| self.read16(n, c + 2) >> 4 & 0xf != 7);
        // Configuration cycles for any bus from `secondary` up go
        // through, until the last bus behind it is known.
        let latency = self.read(n, BUS_NUMBERS) & 0xff00_0000;
        let numbers = |subordinate: u8| {
            latency | (subordinate as u32) << 16 | (secondary as u32) << 8 | f.bus as u32
        };
        self.write(n, BUS_NUMBERS, numbers(0xff), 4);
        for kind in [Kind::Memory, Kind::Prefetch, Kind::Io] {
            self.window(n, kind, None);
        }
        self.scan(secondary, isolated && express);
        let subordinate = (self.next_bus - 1) as u8;
        self.write(n, BUS_NUMBERS, numbers(subordinate), 4);
        let f = self.funcs[n].as_mut().unwrap();
        (f.secondary, f.subordinate, f.express) = (secondary, subordinate, express);
    }

    /// Where the next BAR of `kind` goes.
    fn cursor(&mut self, kind: Kind) -> &mut u64 {
        match kind {
            Kind::Io => &mut self.io_next,
            _ => &mut self.window_next,
        }
    }

    /// Sets (or with `None` shuts) bridge `n`'s window of `kind`:
    /// `range` is its first and last address.
    fn window(&mut self, n: usize, kind: Kind, range: Option<(u64, u64)>) {
        match (kind, range) {
            // Shut: base above limit.
            (Kind::Memory, None) => self.write(n, MEMORY_WINDOW, 0x0000_fff0, 4),
            (Kind::Prefetch, None) => {
                self.write(n, PREFETCH_WINDOW, 0x0000_fff0, 4);
                self.write(n, PREFETCH_BASE_UPPER, 0, 4);
                self.write(n, PREFETCH_LIMIT_UPPER, 0, 4);
            }
            (Kind::Io, None) => {
                self.write(n, IO_WINDOW, 0x00f0, 2);
                self.write(n, IO_WINDOW_UPPER, 0, 4);
            }
            // Memory windows are in megabytes: the registers hold the
            // top twelve bits of the first and last megabyte's address.
            (Kind::Memory | Kind::Prefetch, Some((a, b))) => {
                let (base, limit) = ((a >> 16) as u32 & 0xfff0, (b >> 16) as u32 & 0xfff0);
                if kind == Kind::Memory {
                    self.write(n, MEMORY_WINDOW, limit << 16 | base, 4);
                } else {
                    self.write(n, PREFETCH_WINDOW, limit << 16 | base, 4);
                    self.write(n, PREFETCH_BASE_UPPER, (a >> 32) as u32, 4);
                    self.write(n, PREFETCH_LIMIT_UPPER, (b >> 32) as u32, 4);
                }
            }
            // I/O windows are in 4 KiB of ports: the top four bits of
            // the first and last, and the bits above 16 apart.
            (Kind::Io, Some((a, b))) => {
                let (base, limit) = ((a >> 8) as u32 & 0xf0, (b >> 8) as u32 & 0xf0);
                self.write(n, IO_WINDOW, limit << 8 | base, 2);
                self.write(n, IO_WINDOW_UPPER, (b >> 16) as u32 & 0xffff_0000 | (a >> 16) as u32, 4);
            }
        }
    }

    /// Gives everything behind bridge `n` its addresses of `kind`, side
    /// by side, bridges behind it included (each a range inside this
    /// one), and sets `n`'s window of that kind to exactly the range, in
    /// the window's own grain; a bridge with nothing of the kind behind
    /// it keeps that window shut.
    fn layout(&mut self, n: usize, kind: Kind) {
        let f = self.funcs[n].unwrap();
        if f.secondary == 0 {
            return; // it was given no bus
        }
        let grain = if kind == Kind::Io { 0x1000 } else { MEGABYTE };
        let start = self.cursor(kind).next_multiple_of(grain);
        *self.cursor(kind) = start;
        for i in 0..MAX_FUNCS {
            match self.funcs[i] {
                Some(c) if c.bus == f.secondary && c.bridge => self.layout(i, kind),
                Some(c) if c.bus == f.secondary => self.size_bars(i, kind),
                _ => {}
            }
        }
        let end = self.cursor(kind).next_multiple_of(grain);
        *self.cursor(kind) = end;
        let range = if end == start {
            None
        } else if kind != Kind::Io && end > 1 << 32 {
            // These windows' registers are written as 32 bits wide.
            say!("[fail] the BAR window is above 4 GiB: nothing behind a bridge is reachable");
            None
        } else {
            Some((start, end - 1))
        };
        self.window(n, kind, range);
        self.funcs[n].as_mut().unwrap().windows[kind as usize] = range;
    }

    /// Lays out what is behind every bridge on bus 0, lets the bridges
    /// pass accesses down (and DMA and MSIs up), and says what each
    /// bridge got.
    fn layout_all(&mut self) {
        for kind in [Kind::Memory, Kind::Prefetch, Kind::Io] {
            for n in 0..MAX_FUNCS {
                if matches!(self.funcs[n], Some(f) if f.bridge && f.bus == 0) {
                    self.layout(n, kind);
                }
            }
        }
        // What is behind a bridge has every address it will get.
        for f in self.funcs.iter_mut().flatten().filter(|f| f.bus != 0) {
            f.sized = true;
        }
        for n in 0..MAX_FUNCS {
            let Some(f) = self.funcs[n].filter(|f| f.bridge && f.secondary != 0) else {
                continue;
            };
            self.set_command(n, CMD_MEMORY | CMD_BUS_MASTER | CMD_IO, 0);
            let behind = self
                .funcs
                .iter()
                .flatten()
                .filter(|c| (f.secondary..=f.subordinate).contains(&c.bus))
                .count();
            say!(
                "{:02x}:{:02x}.{} bridges to bus {:02x} (to {:02x}), {behind} functions behind it; {}",
                f.bus,
                f.dev,
                f.func,
                f.secondary,
                f.subordinate,
                if f.express {
                    "a PCI Express port"
                } else {
                    "a conventional bridge, so what is behind it shares its requester ID and gets no DMA"
                }
            );
            say!("{:02x}:{:02x}.{} windows: {}", f.bus, f.dev, f.func, Windows(f.windows));
        }
    }

    /// Bridge `n`'s PCI Express capability, if it is a port on bus 0
    /// with a slot that takes cards while the machine runs.
    fn hot_slot(&self, n: usize) -> Option<u64> {
        let f = self.funcs[n].filter(|f| f.bridge && f.bus == 0 && f.secondary != 0)?;
        let cap = self.capability(n, CAP_PCIE).filter(|_| f.express)?;
        // A slot is implemented, and it is hot-plug capable.
        (self.read16(n, cap + 2) & 1 << 8 != 0 && self.read(n, cap + SLOT_CAPABILITIES) & 1 << 6 != 0)
            .then_some(cap)
    }

    /// Looks at every hot-plug slot: a card that appeared is taken in,
    /// one asked out (or gone) is let go.
    fn poll_slots(&mut self) {
        for n in 0..MAX_FUNCS {
            let Some(cap) = self.hot_slot(n) else {
                continue;
            };
            let status = self.read16(n, cap + SLOT_STATUS) as u32;
            // The events are acknowledged by writing them back.
            if status & SLOT_EVENTS != 0 {
                self.write(n, cap + SLOT_STATUS, status & SLOT_EVENTS, 2);
            }
            let secondary = self.funcs[n].unwrap().secondary;
            let occupied = self.funcs.iter().flatten().any(|c| c.bus == secondary);
            let present = status & SLOT_PRESENT != 0;
            let control = self.read16(n, cap + SLOT_CONTROL) as u32;
            if occupied && (status & SLOT_ATTENTION != 0 || !present) {
                self.unplug(n);
                // Power and its indicator off: the card may be taken out.
                self.write(n, cap + SLOT_CONTROL, control | SLOT_INDICATOR | SLOT_POWER_OFF, 2);
            } else if present && !occupied {
                // Power on, its indicator on; then see what it is.
                let on = control & !(SLOT_INDICATOR | SLOT_POWER_OFF) | SLOT_INDICATOR_ON;
                self.write(n, cap + SLOT_CONTROL, on, 2);
                self.plug(n);
            }
        }
    }

    /// Finds what was plugged in behind port `n` and gives it addresses.
    fn plug(&mut self, n: usize) {
        let f = self.funcs[n].unwrap();
        self.hot = true;
        self.scan(f.secondary, f.isolated && f.express);
        self.hot = false;
        if !self.funcs.iter().flatten().any(|c| c.bus == f.secondary) {
            return; // not answering yet: looked at again next time
        }
        for kind in [Kind::Memory, Kind::Prefetch, Kind::Io] {
            self.layout(n, kind);
        }
        for c in self.funcs.iter_mut().flatten().filter(|c| c.bus == f.secondary) {
            c.sized = true;
        }
        let f = self.funcs[n].unwrap();
        say!(
            "{:02x}:{:02x}.{}: a card was plugged in (bus {:02x}); windows: {}",
            f.bus,
            f.dev,
            f.func,
            f.secondary,
            Windows(f.windows)
        );
    }

    /// Lets go of what is behind port `n`: every function there loses
    /// what its driver held and is forgotten, and the port's windows are
    /// shut.
    fn unplug(&mut self, n: usize) {
        let f = self.funcs[n].unwrap();
        for i in 0..MAX_FUNCS {
            if matches!(self.funcs[i], Some(c) if c.bus == f.secondary) {
                self.remove(i);
            }
        }
        for kind in [Kind::Io, Kind::Prefetch, Kind::Memory] {
            // The last range given out can be given out again.
            if let Some((a, b)) = f.windows[kind as usize] {
                if *self.cursor(kind) == b + 1 {
                    *self.cursor(kind) = a;
                }
            }
            self.window(n, kind, None);
            self.funcs[n].as_mut().unwrap().windows[kind as usize] = None;
        }
        say!("{:02x}:{:02x}.{}: its card is let go (bus {:02x})", f.bus, f.dev, f.func, f.secondary);
    }

    /// Forgets function `i`, which is going: its owner's domain, BAR
    /// pages and interrupts are revoked first.
    fn remove(&mut self, i: usize) {
        let f = self.funcs[i].unwrap();
        self.reset(i);
        if let Some(d) = f.domain {
            // Every copy of the domain goes; its memory is kept for the
            // next function to need one.
            syscall(Syscall::CapRevoke, DOMAIN_MEMORY + d as u64, [0; 4]);
            self.domain_owner[d as usize] = None;
        }
        for (p, page) in self.bar_pages.iter_mut().enumerate() {
            if matches!(page, Some((owner, _, _)) if *owner as usize == i) {
                syscall(Syscall::CapDelete, BAR_SLOTS + p as u64, [0; 4]);
                *page = None;
            }
        }
        for owner in self.msi_owner.iter_mut() {
            if *owner == Some(i as u8) {
                *owner = None;
            }
        }
        say!(
            "{:02x}:{:02x}.{} {:04x}:{:04x} removed{}",
            f.bus,
            f.dev,
            f.func,
            f.ids >> 16,
            f.ids & 0xffff,
            if f.owner != 0 { "; what its driver held is revoked" } else { "" }
        );
        config::detach(i);
        self.funcs[i] = None;
    }

    /// Sizes function `i`'s BARs of `kind` and gives each an address:
    /// memory ones (prefetchable or not) from the BAR window, I/O ones
    /// from the port range, if there is one.
    fn size_bars(&mut self, i: usize, kind: Kind) {
        let mut b = 0;
        while b < 6 {
            let off = 0x10 + 4 * b as u64;
            let orig = self.read(i, off);
            let io = orig & 1 != 0;
            let is64 = !io && orig >> 1 & 3 == 2;
            let this = match (io, orig & 8 != 0) {
                (true, _) => Kind::Io,
                (false, true) => Kind::Prefetch,
                (false, false) => Kind::Memory,
            };
            if this != kind || self.funcs[i].unwrap().bars[b].is_some() {
                b += if is64 { 2 } else { 1 };
                continue;
            }
            self.write(i, off, 0xffff_ffff, 4);
            let lo = self.read(i, off) & if io { !3 } else { !0xf };
            self.write(i, off, orig, 4);
            let hi = if is64 {
                let orig_hi = self.read(i, off + 4);
                self.write(i, off + 4, 0xffff_ffff, 4);
                let h = self.read(i, off + 4);
                self.write(i, off + 4, orig_hi, 4);
                h
            } else {
                0xffff_ffff
            };
            // An I/O BAR may decode 16 bits only.
            let mask = if io && lo >> 16 == 0 {
                !0xffff | lo as u64
            } else {
                (hi as u64) << 32 | lo as u64
            };
            if lo != 0 {
                let size = (!mask).wrapping_add(1);
                let align = if io { size } else { size.max(4096) };
                let addr = (*self.cursor(kind) + align - 1) & !(align - 1);
                // Ports are few: a BAR that does not fit gets none.
                if !io || addr + size <= self.io_end {
                    *self.cursor(kind) = addr + size;
                    let f = self.funcs[i].as_mut().unwrap();
                    f.bars[b] = Some(Bar {
                        addr,
                        size,
                        is64,
                        io,
                    });
                }
            }
            b += if is64 { 2 } else { 1 };
        }
    }

    /// Sizes all of function `i`'s BARs (one on bus 0: nothing has to be
    /// side by side with anything).
    fn size_all(&mut self, i: usize) {
        if !self.funcs[i].unwrap().sized {
            for kind in [Kind::Memory, Kind::Prefetch, Kind::Io] {
                self.size_bars(i, kind);
            }
            self.funcs[i].as_mut().unwrap().sized = true;
        }
    }

    fn program_bars(&self, i: usize) {
        let f = self.funcs[i].unwrap();
        for (b, bar) in f.bars.iter().enumerate() {
            if let Some(bar) = bar {
                let off = 0x10 + 4 * b as u64;
                let flags = self.read(i, off) & if bar.io { 3 } else { 0xf };
                self.write(i, off, bar.addr as u32 | flags, 4);
                if bar.is64 {
                    self.write(i, off + 4, (bar.addr >> 32) as u32, 4);
                }
            }
        }
    }

    /// Reads (or with `value` writes) `width` bytes at `offset` in
    /// function `i`'s I/O BAR `bar`: ports only this server can reach, so
    /// a driver's accesses stay inside its own BAR.
    fn io(&mut self, i: usize, bar: u64, offset: u64, width: u64, value: Option<u64>) -> Result<u64, Status> {
        let b = self.funcs[i]
            .unwrap()
            .bars
            .get(bar as usize)
            .copied()
            .flatten()
            .filter(|b| b.io)
            .ok_or(Status::NotFound)?;
        if !matches!(width, 1 | 2 | 4) || offset % width != 0 || offset.checked_add(width).is_none_or(|e| e > b.size) {
            return Err(Status::Invalid);
        }
        ports::access(b.addr + offset, width, value).ok_or(Status::DeviceError)
    }

    /// Quiets function `i` and takes back everything its last owner had.
    /// Returns how it was reset.
    fn reset(&mut self, i: usize) -> &'static str {
        self.set_command(i, 0, CMD_MEMORY | CMD_BUS_MASTER | 1);
        for (p, page) in self.bar_pages.iter().enumerate() {
            if matches!(page, Some((f, _, _)) if *f as usize == i) {
                syscall(Syscall::CapRevoke, BAR_SLOTS + p as u64, [0; 4]);
            }
        }
        for v in self.funcs[i].unwrap().msi.iter().flatten() {
            syscall(Syscall::CapRevoke, MSI + *v as u64, [0; 4]);
        }
        for (w, owner) in self.intx_owner.iter_mut().enumerate() {
            if *owner == Some(i as u8) {
                syscall(Syscall::CapRevoke, INTX + w as u64, [0; 4]);
                *owner = None;
            }
        }
        if let Some(cap) = self.capability(i, CAP_MSIX) {
            let ctl = self.read16(i, cap + 2) as u32;
            self.write(i, cap + 2, ctl & !(1 << 15), 2);
        }
        if let Some(cap) = self.capability(i, CAP_MSI) {
            let ctl = self.read16(i, cap + 2) as u32;
            self.write(i, cap + 2, ctl & !1, 2);
        }
        let flr = self
            .capability(i, CAP_PCIE)
            .filter(|&cap| self.read(i, cap + 4) & 1 << 28 != 0);
        let Some(cap) = flr else {
            return "decoding and bus mastering off; no FLR, so the driver resets it";
        };
        let ctl = self.read16(i, cap + 8) as u32;
        self.write(i, cap + 8, ctl | 1 << 15, 2);
        // The function may take 100 ms to come back.
        let start = ticks();
        while ticks() < start + 10 || self.read(i, 0) & 0xffff == 0xffff {
            if ticks() > start + 100 {
                return "Function Level Reset (did not come back)";
            }
            superior_sys::sleep(1);
        }
        "Function Level Reset"
    }

    /// Destroys function `i`'s domain (blocking its DMA) and makes it a
    /// new, empty one, bound to its requester ID. Returns the domain's
    /// slot, or `None` without an IOMMU.
    fn new_domain(&mut self, i: usize) -> Result<Option<u64>, Status> {
        let d = match self.funcs[i].unwrap().domain {
            Some(d) => d as usize,
            None => {
                let d = self
                    .domain_owner
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Status::InUse)?;
                if !self.domain_made[d] {
                    let made = syscall(
                        Syscall::Retype,
                        UNTYPED,
                        [
                            ObjectType::Untyped as u64,
                            DOMAIN_BITS,
                            DOMAIN_MEMORY + d as u64,
                            0,
                        ],
                    );
                    if made.status != 0 {
                        return Err(Status::DeviceError);
                    }
                    self.domain_made[d] = true;
                }
                self.domain_owner[d] = Some(i as u8);
                self.funcs[i].as_mut().unwrap().domain = Some(d as u8);
                d
            }
        };
        // Every copy of the old domain goes, the driver's too: the kernel
        // unbinds the function first, so its DMA stops here.
        syscall(Syscall::CapRevoke, DOMAIN_MEMORY + d as u64, [0; 4]);
        let slot = DOMAINS + d as u64;
        let made = syscall(
            Syscall::Retype,
            DOMAIN_MEMORY + d as u64,
            [ObjectType::IoSpace as u64, DOMAIN_BITS, slot, 0],
        );
        if made.status != 0 {
            return Ok(None); // no IOMMU
        }
        let f = self.funcs[i].unwrap();
        let rid = (f.bus as u64) << 8 | (f.dev as u64) << 3 | f.func as u64;
        let bound = syscall(Syscall::IoSpaceBind, slot, [IOMMU, rid, 0, 0]).status;
        if bound == Error::InvalidArgument.code() {
            // No IOMMU unit the kernel drives covers the function (the
            // DMAR puts it under one the kernel cannot use): no domain can
            // hold its DMA, so it gets none, and no bus mastering.
            syscall(Syscall::CapRevoke, DOMAIN_MEMORY + d as u64, [0; 4]);
            self.domain_owner[d] = None;
            let f = self.funcs[i].as_mut().unwrap();
            f.domain = None;
            f.uncovered = true;
            return Ok(None);
        }
        if bound != 0 {
            return Err(Status::DeviceError);
        }
        Ok(Some(slot))
    }

    /// Opens the `instance`th function with these IDs (or, if `class`, of
    /// this class).
    fn open(
        &mut self,
        badge: u64,
        class: bool,
        ids: u64,
        instance: u64,
    ) -> ([u64; 4], Option<u64>) {
        let found = (0..MAX_FUNCS)
            .filter(|&i| {
                matches!(self.funcs[i], Some(f)
                    if !f.bridge && (if class { f.class } else { f.ids }) as u64 == ids)
            })
            .nth(instance as usize);
        let Some(i) = found else {
            return ([Status::NotFound as u64, 0, 0, 0], None);
        };
        let f = self.funcs[i].unwrap();
        if f.owner != 0 && f.owner != badge {
            say!(
                "client {badge} may not have {:02x}:{:02x}.{}: client {} has it",
                f.bus,
                f.dev,
                f.func,
                f.owner
            );
            return ([Status::InUse as u64, 0, 0, 0], None);
        }
        // Behind a conventional bridge its requester ID is the bridge's:
        // no domain of its own, so no DMA.
        let domain = match self.new_domain(i) {
            _ if !f.isolated => None,
            Ok(d) => d,
            Err(s) => return ([s as u64, 0, 0, 0], None),
        };
        let how = self.reset(i);
        self.size_all(i);
        self.program_bars(i);
        let has_io = self.funcs[i].unwrap().bars.iter().flatten().any(|b| b.io);
        self.set_command(i, CMD_MEMORY | CMD_INTX_DISABLE | if has_io { CMD_IO } else { 0 }, 0);
        let f = self.funcs[i].as_mut().unwrap();
        let again = f.owner == badge;
        f.owner = badge;
        f.dma = domain.is_some();
        let f = *f;
        say!(
            "{:02x}:{:02x}.{} {} client {badge} (reset: {how}; {})",
            f.bus,
            f.dev,
            f.func,
            if again { "reopened by" } else { "given to" },
            if domain.is_some() {
                "new, empty IOMMU domain"
            } else if !f.isolated {
                "behind a conventional bridge, so no bus mastering"
            } else if f.uncovered {
                "under no IOMMU unit the kernel drives, so no bus mastering"
            } else {
                "no IOMMU, so no bus mastering"
            }
        );
        let mask = |io: bool| {
            f.bars
                .iter()
                .enumerate()
                .filter(|(_, b)| b.is_some_and(|b| b.io == io))
                .fold(0, |m, (b, _)| m | 1 << b)
        };
        let bdf = (f.bus as u64) << 8 | (f.dev as u64) << 3 | f.func as u64;
        ([Status::Ok as u64, bdf, mask(false), mask(true)], domain)
    }

    /// The function `badge` owns.
    fn owned(&self, badge: u64) -> Option<usize> {
        (0..MAX_FUNCS).find(|&i| matches!(self.funcs[i], Some(f) if f.owner == badge))
    }

    /// The original of BAR page (i, bar, page), made if need be.
    fn bar_page(&mut self, i: usize, bar: u64, page: u64) -> Result<(u64, u64), Status> {
        let b = self.funcs[i]
            .unwrap()
            .bars
            .get(bar as usize)
            .copied()
            .flatten()
            .filter(|b| !b.io)
            .ok_or(Status::NotFound)?;
        if page.checked_mul(4096).is_none_or(|o| o >= b.size) {
            return Err(Status::NotFound);
        }
        let key = (i as u8, bar as u8, page as u16);
        if let Some(p) = self.bar_pages.iter().position(|&k| k == Some(key)) {
            return Ok((BAR_SLOTS + p as u64, b.size));
        }
        let p = self
            .bar_pages
            .iter()
            .position(Option::is_none)
            .ok_or(Status::Invalid)?;
        let offset = b.addr + page * 4096 - self.window_base;
        let slot = BAR_SLOTS + p as u64;
        if syscall(Syscall::DeviceFrame, WINDOW, [offset, slot, 0, 0]).status != 0 {
            return Err(Status::Invalid);
        }
        self.bar_pages[p] = Some(key);
        Ok((slot, b.size))
    }

    /// The original of the frame over all of BAR (i, bar), made if need
    /// be: a power of two of pages, so it covers the BAR (at least a page).
    fn bar_frame(&mut self, i: usize, bar: u64) -> Result<(u64, u64), Status> {
        let b = self.funcs[i]
            .unwrap()
            .bars
            .get(bar as usize)
            .copied()
            .flatten()
            .filter(|b| !b.io)
            .ok_or(Status::NotFound)?;
        // A page number no BAR_PAGE can ask for marks the whole BAR.
        let key = (i as u8, bar as u8, u16::MAX);
        if let Some(p) = self.bar_pages.iter().position(|&k| k == Some(key)) {
            return Ok((BAR_SLOTS + p as u64, b.size));
        }
        let p = self
            .bar_pages
            .iter()
            .position(Option::is_none)
            .ok_or(Status::Invalid)?;
        let bits = (b.size.max(4096).next_power_of_two().trailing_zeros()) as u64;
        let offset = b.addr - self.window_base;
        let slot = BAR_SLOTS + p as u64;
        if syscall(Syscall::DeviceFrame, WINDOW, [offset, slot, bits, 0]).status != 0 {
            return Err(Status::Invalid);
        }
        self.bar_pages[p] = Some(key);
        Ok((slot, b.size))
    }

    /// Programs function `i`'s MSI capability with its vector 0's message
    /// and enables it (one vector), or disables it.
    fn msi(&mut self, i: usize, on: bool) -> Result<(), Status> {
        let cap = self.capability(i, CAP_MSI).ok_or(Status::NotFound)?;
        // Enable off, one vector (multiple message enable 0).
        let ctl = self.read16(i, cap + 2) as u32 & !(1 | 7 << 4);
        self.write(i, cap + 2, ctl, 2);
        if !on {
            return Ok(());
        }
        let f = self.funcs[i].unwrap();
        let v = f.msi[0].ok_or(Status::Invalid)?;
        // Raisable by this function alone, where interrupts are remapped.
        let source = match f.domain {
            Some(d) if f.dma => DOMAINS + d as u64,
            _ => u64::MAX,
        };
        let r = syscall(Syscall::IrqMsiMessage, MSI + v as u64, [source, 0, 0, 0]);
        if r.status != 0 {
            return Err(Status::DeviceError);
        }
        let (address, data) = (r.msg[0], r.msg[1] as u32);
        let wide = ctl & 1 << 7 != 0;
        if !wide && address >> 32 != 0 {
            return Err(Status::Invalid);
        }
        self.write(i, cap + 4, address as u32, 4);
        let data_at = if wide {
            self.write(i, cap + 8, (address >> 32) as u32, 4);
            cap + 12
        } else {
            cap + 8
        };
        self.write(i, data_at, data & 0xffff, 2);
        self.write(i, cap + 2, ctl | 1, 2);
        Ok(())
    }

    fn msi_vector(&mut self, i: usize, n: u64) -> Result<u64, Status> {
        let n = n as usize;
        if n >= MSI_COUNT {
            return Err(Status::NotFound);
        }
        if let Some(v) = self.funcs[i].unwrap().msi[n] {
            return Ok(MSI + v as u64);
        }
        let v = self
            .msi_owner
            .iter()
            .position(Option::is_none)
            .ok_or(Status::NotFound)?;
        self.msi_owner[v] = Some(i as u8);
        self.funcs[i].as_mut().unwrap().msi[n] = Some(v as u8);
        Ok(MSI + v as u64)
    }

    /// Serves one call. Returns the reply and a capability to grant.
    /// The interrupt line function `i`'s pin reaches: its index among the
    /// lines, as the kernel says the firmware routes the root-bus device
    /// and pin it comes out on.
    fn wire(&self, i: usize) -> Option<usize> {
        let f = self.funcs[i].unwrap();
        let pin = self.read8(i, 0x3d) as usize;
        if !(1..=4).contains(&pin) {
            return None;
        }
        let (mut bus, mut dev, mut pin) = (f.bus, f.dev as usize, pin - 1);
        // Up through each bridge: the pin comes out rotated by the
        // device number.
        while bus != 0 {
            let up = (0..MAX_FUNCS).find(|&b| {
                matches!(self.funcs[b], Some(g) if g.bridge)
                    && (self.read(b, BUS_NUMBERS) >> 8) as u8 == bus
            })?;
            pin = (pin + dev) % 4;
            let g = self.funcs[up].unwrap();
            (bus, dev) = (g.bus, g.dev as usize);
        }
        let r = syscall(Syscall::IntxLine, dev as u64, [pin as u64 + 1, 0, 0, 0]);
        (r.status == 0 && r.msg[0] < INTX_COUNT as u64).then_some(r.msg[0] as usize)
    }

    /// Gives function `i` its legacy interrupt line: the slot of the
    /// capability to grant, and the wire.
    fn intx(&mut self, i: usize) -> Result<(u64, u64), Status> {
        let w = self.wire(i).ok_or(Status::NotFound)?;
        match self.intx_owner[w] {
            Some(o) if o as usize != i => return Err(Status::InUse),
            _ => {}
        }
        // An empty slot: the manifest gave no lines, or the kernel does
        // not know this machine's routing.
        if syscall(Syscall::IrqAck, INTX + w as u64, [0; 4]).status != 0 {
            return Err(Status::NotFound);
        }
        self.intx_owner[w] = Some(i as u8);
        self.set_command(i, 0, CMD_INTX_DISABLE);
        Ok((INTX + w as u64, w as u64))
    }

    /// `power::SUSPEND`: keeps every function's configuration header (its
    /// first 64 bytes).
    fn suspend(&mut self) -> usize {
        let mut n = 0;
        for i in 0..MAX_FUNCS {
            if self.funcs[i].is_some() {
                for k in 0..16 {
                    self.saved[i][k] = self.read(i, 4 * k as u64);
                }
                n += 1;
            }
        }
        n
    }

    /// `power::RESUME`: writes back what [`Bus::suspend`] kept, in the
    /// order the scan found the functions (a bridge before the bus behind
    /// it, whose functions answer only once its bus numbers are back):
    /// the BARs, bus numbers, windows and interrupt line, then the cache
    /// line size, then the command register (decoding, bus mastering).
    /// Returns how many functions answered.
    fn resume(&mut self) -> usize {
        let mut n = 0;
        for i in 0..MAX_FUNCS {
            if self.funcs[i].is_none() || self.read(i, 0) != self.saved[i][0] {
                continue;
            }
            for k in 4..16 {
                self.write(i, 4 * k as u64, self.saved[i][k], 4);
            }
            self.write(i, 0x0c, self.saved[i][3] & 0xffff, 2);
            self.write(i, 0x04, self.saved[i][1] & 0xffff, 2);
            n += 1;
        }
        n
    }

    fn serve(&mut self, badge: u64, m: [u64; 4]) -> ([u64; 4], Option<u64>) {
        let status = |s: Status| ([s as u64, 0, 0, 0], None);
        if badge == 0 && m[0] == power::SUSPEND {
            let n = self.suspend();
            say!("suspended: {n} functions' configuration kept");
            return status(Status::Ok);
        }
        if badge == 0 && m[0] == power::RESUME {
            let n = self.resume();
            say!("resumed: {n} functions' configuration written back");
            return status(Status::Ok);
        }
        if m[0] == pci::OPEN || m[0] == pci::OPEN_CLASS {
            if m[1] != pci::VERSION {
                return status(Status::Invalid);
            }
            return self.open(badge, m[0] == pci::OPEN_CLASS, m[2], m[3]);
        }
        let Some(i) = self.owned(badge) else {
            return status(Status::Denied);
        };
        match m[0] {
            pci::BAR_PAGE => match self.bar_page(i, m[1], m[2]) {
                Ok((slot, size)) => ([Status::Ok as u64, size, 0, 0], Some(slot)),
                Err(s) => status(s),
            },
            pci::BAR_FRAME => match self.bar_frame(i, m[1]) {
                Ok((slot, size)) => ([Status::Ok as u64, size, 0, 0], Some(slot)),
                Err(s) => status(s),
            },
            pci::CONFIG_READ if m[1] < 256 && m[1] % 4 == 0 => {
                ([Status::Ok as u64, self.read(i, m[1]) as u64, 0, 0], None)
            }
            // Without a domain the device could reach all of memory.
            pci::BUS_MASTER if m[1] != 0 && !self.funcs[i].unwrap().dma => status(Status::Denied),
            pci::BUS_MASTER => {
                if m[1] != 0 {
                    self.set_command(i, CMD_BUS_MASTER, 0);
                } else {
                    self.set_command(i, 0, CMD_BUS_MASTER);
                }
                status(Status::Ok)
            }
            pci::MSIX => match self.capability(i, CAP_MSIX) {
                Some(cap) => {
                    let ctl = self.read16(i, cap + 2) as u32 & !(1 << 14 | 1 << 15);
                    let on = if m[1] != 0 { 1 << 15 } else { 0 };
                    self.write(i, cap + 2, ctl | on, 2);
                    status(Status::Ok)
                }
                None => status(Status::NotFound),
            },
            pci::MSI => match self.msi(i, m[1] != 0) {
                Ok(()) => status(Status::Ok),
                Err(s) => status(s),
            },
            pci::MSI_VECTOR => match self.msi_vector(i, m[1]) {
                Ok(slot) => ([Status::Ok as u64, 0, 0, 0], Some(slot)),
                Err(s) => status(s),
            },
            pci::IO_READ => match self.io(i, m[1], m[2], m[3], None) {
                Ok(v) => ([Status::Ok as u64, v, 0, 0], None),
                Err(s) => status(s),
            },
            pci::IO_WRITE => match self.io(i, m[1] & 0xff, m[2], m[1] >> 8, Some(m[3])) {
                Ok(_) => status(Status::Ok),
                Err(s) => status(s),
            },
            pci::CLOSE => {
                // Given back: quiet, and anyone's to open.
                self.reset(i);
                let f = self.funcs[i].as_mut().unwrap();
                say!("{:02x}:{:02x}.{} given back by client {badge}", f.bus, f.dev, f.func);
                f.owner = 0;
                f.dma = false;
                status(Status::Ok)
            }
            pci::INTX => match self.intx(i) {
                Ok((slot, wire)) => ([Status::Ok as u64, wire, 0, 0], Some(slot)),
                Err(s) => status(s),
            },
            _ => status(Status::Invalid),
        }
    }
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    // Where the BAR window starts: the device address of its first page.
    let base = if syscall(Syscall::DeviceFrame, WINDOW, [0, SCRATCH, 0, 0]).status == 0 {
        let b = dma_address(SCRATCH).unwrap_or(0);
        syscall(Syscall::CapDelete, SCRATCH, [0; 4]);
        b
    } else {
        0
    };
    let mut bus = Bus {
        funcs: [None; MAX_FUNCS],
        saved: [[0; 16]; MAX_FUNCS],
        bar_pages: [None; MAX_BAR_PAGES],
        msi_owner: [None; MSI_COUNT],
        intx_owner: [None; INTX_COUNT],
        domain_owner: [None; MAX_OPEN],
        domain_made: [false; MAX_OPEN],
        hot: false,
        window_base: base,
        window_next: base,
        io_next: 0,
        io_end: 0,
        next_bus: 1,
    };
    if let Some((first, end)) = ports::range() {
        (bus.io_next, bus.io_end) = (first, end);
        say!("BAR window at {base:#x}, I/O ports {first:#x} to {:#x}; scanning bus 0", end - 1);
    } else {
        say!("BAR window at {base:#x}; scanning bus 0");
    }
    bus.scan(0, true);
    bus.layout_all();
    // With a notification, its timer wakes the same `Recv` that waits for
    // calls, and the hot-plug slots are looked at.
    let polling = syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status == 0;
    if polling {
        syscall(Syscall::TimerSignal, NOTIFY, [SLOT_POLL, 0, 0, 0]);
        let slots = (0..MAX_FUNCS).filter(|&n| bus.hot_slot(n).is_some()).count();
        say!("{slots} hot-plug slots, looked at every {} ms", SLOT_POLL * 10);
    }
    let mut reply: Option<([u64; 4], Option<u64>)> = None;
    loop {
        let r = match reply.take() {
            Some((m, grant)) => {
                let x = CapTransfer {
                    grant: grant.map(|s| s as u16),
                    accept: None,
                };
                syscall_x(Syscall::ReplyRecv, SERVICE, m, x)
            }
            None => syscall(Syscall::Recv, SERVICE, [0; 4]),
        };
        if r.status == Error::Notified.code() {
            bus.poll_slots();
            syscall(Syscall::TimerSignal, NOTIFY, [SLOT_POLL, 0, 0, 0]);
            continue;
        }
        reply = Some(if r.status == 0 {
            bus.serve(r.badge, r.msg)
        } else {
            ([Status::Invalid as u64, 0, 0, 0], None)
        });
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
