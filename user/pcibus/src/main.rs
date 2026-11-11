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
//! Bridges: a PCI-to-PCI bridge (a PCIe root port, say) is not handed out
//! but configured here. The scan gives it the next bus number, walks the
//! bus behind it (and any bridges there), assigns the BARs of everything
//! found behind it next to each other, and sets the bridge's memory
//! window to just that range, in whole megabytes; its I/O and
//! prefetchable windows stay shut. Buses are numbered up to
//! `abi::PCI_BUSES`, which is as far as the kernel's IOMMU tables reach.
//! A function behind a bridge has a requester ID of its own only on PCI
//! Express: behind a conventional bridge its DMA and interrupts carry the
//! bridge's ID, so no domain could isolate it, and it gets none (and so
//! no bus mastering).
//!
//! Legacy interrupts: a function with no MSI gets the interrupt line
//! its pin is wired to (`pci::INTX`), one function a line: the wire of a
//! function on bus 0 is `(device + pin - 1) % 4`, and a bridge passes
//! the pins of what is behind it on rotated by their device numbers.
//!
//! Slots: 0 the `pci` endpoint (receive), 1 configuration space (I/O ports
//! on x86-64, ECAM device memory on AArch64), 2 the BAR window (device
//! memory), 3.. the MSI vectors, then the IOMMU-control capability (empty
//! without an IOMMU) and untyped memory for the domains; from 64, if the
//! manifest gives them (`device intx 64`, in a CSpace of 2^7 slots), the
//! four legacy PCI interrupt lines.

#![no_std]
#![no_main]

use superior_driver::dma_address;
use superior_objects::abi::{CapTransfer, ObjectType, PCI_BUSES, Syscall, root};
use superior_objects::interfaces::{Status, pci};
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
const MAX_FUNCS: usize = 16;
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
const _: () = assert!(DOMAINS + MAX_OPEN as u64 <= 64);
/// The legacy interrupt lines, one per wire.
const INTX: u64 = 64;
const INTX_COUNT: usize = root::INTX_COUNT as usize;

// Configuration space.
const COMMAND: u64 = 0x04;
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
/// A bridge's memory window is in whole megabytes.
const MEGABYTE: u64 = 1 << 20;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("pci: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy)]
struct Bar {
    addr: u64,
    size: u64,
    is64: bool,
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
}

struct Bus {
    funcs: [Option<Func>; MAX_FUNCS],
    /// (function, BAR, page) of each BAR page original.
    bar_pages: [Option<(u8, u8, u16)>; MAX_BAR_PAGES],
    msi_owner: [Option<u8>; MSI_COUNT],
    /// The function that has each legacy interrupt line.
    intx_owner: [Option<u8>; INTX_COUNT],
    /// The function each domain slot belongs to.
    domain_owner: [Option<u8>; MAX_OPEN],
    window_base: u64,
    window_next: u64,
    /// Functions found, and the next bus number to give a bridge.
    found: usize,
    next_bus: u8,
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

    /// Finds the functions on `bus` and, through its bridges, behind it.
    /// `isolated`: functions here have requester IDs of their own.
    fn scan(&mut self, bus: u8, isolated: bool) {
        let first = self.found;
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let n = self.found;
                if n == MAX_FUNCS {
                    say!("more than {MAX_FUNCS} functions: the rest are left alone");
                    return;
                }
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
                self.found += 1;
                if f.bridge {
                    // Firmware may have numbered the buses its own way:
                    // until this bridge is given a number below, it must
                    // answer for none.
                    let latency = self.read(n, BUS_NUMBERS) & 0xff00_0000;
                    self.write(n, BUS_NUMBERS, latency, 4);
                    self.set_command(n, 0, CMD_MEMORY | CMD_BUS_MASTER | 1);
                }
                if func == 0 && header & 0x80 == 0 {
                    break;
                }
            }
        }
        // Every bridge on this bus now forwards nothing, so each can be
        // given its bus in turn.
        for n in first..self.found {
            if matches!(self.funcs[n], Some(f) if f.bridge && f.bus == bus) {
                self.bridge(n, isolated);
            }
        }
    }

    /// Configures bridge `n`: a bus number, everything behind it found
    /// and given addresses, and a memory window over exactly those.
    fn bridge(&mut self, n: usize, isolated: bool) {
        let f = self.funcs[n].unwrap();
        if self.next_bus as u64 >= PCI_BUSES {
            say!(
                "{:02x}:{:02x}.{}: no bus number left for what is behind it",
                f.bus,
                f.dev,
                f.func
            );
            return;
        }
        let secondary = self.next_bus;
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
        // No I/O and no prefetchable window: base above limit.
        self.write(n, IO_WINDOW, 0x00f0, 2);
        self.write(n, PREFETCH_WINDOW, 0x0000_fff0, 4);
        self.write(n, PREFETCH_BASE_UPPER, 0, 4);
        self.write(n, PREFETCH_LIMIT_UPPER, 0, 4);
        let start = self.window_next.next_multiple_of(MEGABYTE);
        self.window_next = start;
        let first = self.found;
        self.scan(secondary, isolated && express);
        // What is behind it gets its addresses now, side by side: the
        // window must cover them all and nothing else.
        for i in first..self.found {
            if matches!(self.funcs[i], Some(c) if !c.bridge) {
                self.set_command(i, 0, CMD_MEMORY | CMD_BUS_MASTER | 1);
                self.size_bars(i);
            }
        }
        let end = self.window_next.next_multiple_of(MEGABYTE);
        self.window_next = end;
        let subordinate = self.next_bus - 1;
        self.write(n, BUS_NUMBERS, numbers(subordinate), 4);
        let window = if end == start {
            self.write(n, MEMORY_WINDOW, 0x0000_fff0, 4);
            None
        } else if end > 1 << 32 {
            // The window's registers are 32 bits wide.
            say!("[fail] the BAR window is above 4 GiB: nothing behind a bridge is reachable");
            self.write(n, MEMORY_WINDOW, 0x0000_fff0, 4);
            None
        } else {
            let (base, limit) = ((start >> 16) as u32 & 0xfff0, ((end - 1) >> 16) as u32 & 0xfff0);
            self.write(n, MEMORY_WINDOW, limit << 16 | base, 4);
            Some((start, end - 1))
        };
        // The bridge passes memory accesses down, and DMA and MSIs up.
        self.set_command(n, CMD_MEMORY | CMD_BUS_MASTER, 0);
        let kind = if express {
            "a PCI Express port"
        } else {
            "a conventional bridge, so what is behind it shares its requester ID and gets no DMA"
        };
        match window {
            Some((a, b)) => say!(
                "{:02x}:{:02x}.{} bridges to bus {secondary:02x} (to {subordinate:02x}), {} functions behind it, memory window {a:#x} to {b:#x}; {kind}",
                f.bus,
                f.dev,
                f.func,
                self.found - first
            ),
            None => say!(
                "{:02x}:{:02x}.{} bridges to bus {secondary:02x} (to {subordinate:02x}), {} functions behind it, no memory window; {kind}",
                f.bus,
                f.dev,
                f.func,
                self.found - first
            ),
        }
    }

    /// Sizes the function's memory BARs (with decoding off) and assigns
    /// each an address in the window, aligned to its size.
    fn size_bars(&mut self, i: usize) {
        let mut b = 0;
        while b < 6 {
            let off = 0x10 + 4 * b as u64;
            let orig = self.read(i, off);
            if orig & 1 != 0 {
                b += 1; // I/O BAR: drivers get memory BARs only
                continue;
            }
            let is64 = orig >> 1 & 3 == 2;
            self.write(i, off, 0xffff_ffff, 4);
            let lo = self.read(i, off) & !0xf;
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
            let mask = (hi as u64) << 32 | lo as u64;
            if lo != 0 {
                let size = (!mask).wrapping_add(1);
                let align = size.max(4096);
                let addr = (self.window_next + align - 1) & !(align - 1);
                self.window_next = addr + size;
                let f = self.funcs[i].as_mut().unwrap();
                f.bars[b] = Some(Bar { addr, size, is64 });
            }
            b += if is64 { 2 } else { 1 };
        }
        self.funcs[i].as_mut().unwrap().sized = true;
    }

    fn program_bars(&self, i: usize) {
        let f = self.funcs[i].unwrap();
        for (b, bar) in f.bars.iter().enumerate() {
            if let Some(bar) = bar {
                let off = 0x10 + 4 * b as u64;
                let flags = self.read(i, off) & 0xf;
                self.write(i, off, bar.addr as u32 | flags, 4);
                if bar.is64 {
                    self.write(i, off + 4, (bar.addr >> 32) as u32, 4);
                }
            }
        }
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
        if syscall(Syscall::IoSpaceBind, slot, [IOMMU, rid, 0, 0]).status != 0 {
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
        if !self.funcs[i].unwrap().sized {
            self.size_bars(i);
        }
        self.program_bars(i);
        self.set_command(i, CMD_MEMORY | CMD_INTX_DISABLE, 0);
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
            } else {
                "no IOMMU, so no bus mastering"
            }
        );
        let mask = f
            .bars
            .iter()
            .enumerate()
            .filter(|(_, b)| b.is_some())
            .fold(0, |m, (b, _)| m | 1 << b);
        let bdf = (f.bus as u64) << 8 | (f.dev as u64) << 3 | f.func as u64;
        ([Status::Ok as u64, bdf, mask, 0], domain)
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
    /// The interrupt wire function `i`'s pin drives.
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
        // On QEMU's q35 the slots from 25 up are the chipset's, wired
        // their own way.
        if cfg!(target_arch = "x86_64") && dev >= 25 {
            return None;
        }
        Some((pin + dev) % 4)
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

    fn serve(&mut self, badge: u64, m: [u64; 4]) -> ([u64; 4], Option<u64>) {
        let status = |s: Status| ([s as u64, 0, 0, 0], None);
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
        bar_pages: [None; MAX_BAR_PAGES],
        msi_owner: [None; MSI_COUNT],
        intx_owner: [None; INTX_COUNT],
        domain_owner: [None; MAX_OPEN],
        window_base: base,
        window_next: base,
        found: 0,
        next_bus: 1,
    };
    say!("BAR window at {base:#x}; scanning bus 0");
    bus.scan(0, true);
    let mut r = syscall(Syscall::Recv, SERVICE, [0; 4]);
    loop {
        let (reply, grant) = if r.status == 0 {
            bus.serve(r.badge, r.msg)
        } else {
            ([Status::Invalid as u64, 0, 0, 0], None)
        };
        let x = CapTransfer {
            grant: grant.map(|s| s as u16),
            accept: None,
        };
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, x);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
