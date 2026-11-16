//! The machine the kernel drives, as its firmware describes it: from the
//! device tree, or from ACPI's tables ([`super::acpi`]). Read once at boot,
//! before the console is up: each part is optional here, and once the
//! console is (if it was found) whatever is missing is reported and the
//! kernel stops.
//!
//! - the GICv3: distributor, redistributors (one frame set per CPU, CPU
//!   `n`'s the `n`th) and ITS;
//! - the EL1 virtual timer's interrupt;
//! - the console, a PL011 (or the SBSA generic UART, a subset of it): its
//!   registers and interrupt;
//! - PCI: bus 0's configuration space (ECAM, at least the 16 buses the bus
//!   server drives), the window of 32-bit memory BARs are assigned from
//!   (PCI addresses the CPU reaches at the same addresses), and the window
//!   standing for I/O ports from 0;
//! - the SMMUv3, if any;
//! - PSCI's conduit, and how many CPUs to start.
//!
//! - how PCI's interrupt pins on bus 0 reach the GIC: the device tree's
//!   `interrupt-map` (with its mask) on the PCI host, or the root bridge's
//!   `_PRT`; each distinct interrupt a line ([`Intx`]).

use super::{acpi, fdt};

/// Legacy PCI interrupt lines at most (the root task's slots for them).
pub const MAX_INTX: usize = 8;

/// PCI's interrupt pins: the lines (GIC interrupt IDs, level-triggered,
/// active high), and for each device on bus 0 and pin INTA to INTD, which
/// line it reaches (its index plus one; 0 for none).
#[derive(Clone, Copy)]
pub struct Intx {
    /// What said so: "the device tree's interrupt-map", or "_PRT".
    pub from: &'static str,
    pub lines: [u8; MAX_INTX],
    pub used: usize,
    pub pin: [[u8; 4]; 32],
    /// Pins routed, and pins left without a line (an interrupt that is
    /// not level-high, above 255, or past [`MAX_INTX`] lines).
    pub pins: usize,
    pub left: usize,
}

impl Intx {
    /// From `route(device, pin)`: the interrupt ID pin `pin` (1 to 4) of
    /// device `device` reaches, if it is a level-high one. None if no pin
    /// is routed.
    fn build(from: &'static str, route: impl Fn(u8, u8) -> Option<Option<u32>>) -> Option<Intx> {
        let mut x = Intx { from, lines: [0; MAX_INTX], used: 0, pin: [[0; 4]; 32], pins: 0, left: 0 };
        for device in 0..32u8 {
            for pin in 1..=4u8 {
                // Not mentioned: no pin to route. Mentioned, but nothing the
                // kernel can take: left without.
                let Some(id) = route(device, pin) else { continue };
                let line = id.filter(|&id| (32..256).contains(&id)).and_then(|id| {
                    let id = id as u8;
                    match x.lines[..x.used].iter().position(|&l| l == id) {
                        Some(w) => Some(w),
                        None if x.used < MAX_INTX => {
                            x.lines[x.used] = id;
                            x.used += 1;
                            Some(x.used - 1)
                        }
                        None => None,
                    }
                });
                match line {
                    Some(w) => {
                        x.pin[device as usize][pin as usize - 1] = w as u8 + 1;
                        x.pins += 1;
                    }
                    None => x.left += 1,
                }
            }
        }
        (x.used > 0).then_some(x)
    }

    /// The line pin `pin` (1 to 4) of bus 0's device `device` reaches.
    pub fn line(&self, device: u8, pin: u8) -> Option<usize> {
        let w = *self.pin.get(device as usize)?.get((pin as usize).checked_sub(1)?)?;
        (w != 0).then(|| w as usize - 1)
    }
}

/// The PCI host's `interrupt-map`: entries of a child unit address (three
/// cells, the device in bits 11 to 15 of the first), a child interrupt
/// (one cell, the pin), the parent's phandle, its unit address and its
/// interrupt (the GIC's: SPI or PPI, number, flags); looked up with the
/// child's address and pin under `interrupt-map-mask`.
fn interrupt_map(dtb: u64) -> Option<Intx> {
    let host = b"pci-host-ecam-generic";
    let map = fdt::prop(dtb, host, b"interrupt-map")?;
    let mask = fdt::prop(dtb, host, b"interrupt-map-mask");
    let child_int = fdt::prop(dtb, host, b"#interrupt-cells").and_then(|p| p.cell(0)).unwrap_or(1);
    let gic = b"arm,gic-v3";
    let gic_phandle = fdt::prop(dtb, gic, b"phandle")?.cell(0)?;
    let gic_int = fdt::prop(dtb, gic, b"#interrupt-cells")?.cell(0)?;
    // An interrupt parent with no #address-cells has none in the map.
    let gic_addr = fdt::prop(dtb, gic, b"#address-cells").and_then(|p| p.cell(0)).unwrap_or(0);
    if map.own_cells.0 != 3 || child_int != 1 || gic_int < 3 || gic_addr > 2 {
        return None;
    }
    let m = |i: u64| mask.and_then(|p| p.cell(i)).unwrap_or(!0);
    let entry = (3 + 1 + 1 + gic_addr + gic_int) as u64;
    Intx::build("the device tree's interrupt-map", |device, pin| {
        let (hi, pin) = (((device as u32) << 11) & m(0), pin as u32 & m(3));
        let mut i = 0;
        while map.cell(i + entry - 1).is_some() {
            let cell = |k: u64| map.cell(i + k).unwrap_or(0);
            if cell(0) == hi && cell(1) & m(1) == 0 && cell(2) & m(2) == 0 && cell(3) == pin {
                if cell(4) != gic_phandle {
                    return Some(None);
                }
                let at = 5 + gic_addr as u64;
                let (kind, number, flags) = (cell(at), cell(at + 1), cell(at + 2));
                // Level-triggered, active high (flags 4): what PCI's pins
                // are once the host bridge has inverted them.
                let base = match kind {
                    0 => 32,
                    1 => 16,
                    _ => return Some(None),
                };
                return Some((flags & 0xf == 4).then_some(base + number));
            }
            i += entry;
        }
        None
    })
}

/// The root bridge's `_PRT`, as the AML reader found it.
fn prt(routes: &crate::aml::Routes) -> Option<Intx> {
    Intx::build("_PRT", |device, pin| {
        let r = routes[device as usize][pin as usize - 1]?;
        Some((r.level && !r.active_low).then_some(r.gsi))
    })
}

/// The largest block of `2^bits` bytes, aligned to its size, within
/// `[base, base + len)`; no bigger than `2^max` nor smaller than a page.
fn block(base: u64, len: u64, max: u8) -> Option<(u64, u8)> {
    (12..=max).rev().find_map(|bits| {
        let size = 1u64 << bits;
        let start = base.checked_add(size - 1)? & !(size - 1);
        (start.checked_add(size)? <= base.checked_add(len)?).then_some((start, bits))
    })
}

#[derive(Clone, Copy, Default)]
pub struct Platform {
    /// "device tree" or "ACPI".
    pub source: &'static str,
    pub gicd: Option<u64>,
    pub gicr: Option<u64>,
    pub its: Option<u64>,
    pub timer: Option<u32>,
    pub uart: Option<(u64, u32)>,
    /// Bus 0's configuration space.
    pub ecam: Option<u64>,
    /// BARs' memory: base and size, as a power of two.
    pub pci_mem: Option<(u64, u8)>,
    /// Where I/O port 0 is, and how many ports, as a power of two.
    pub pci_io: Option<(u64, u8)>,
    pub smmu: Option<(u64, Option<u32>)>,
    pub psci_smc: bool,
    /// CPUs to start at most (ACPI's MADT says how many there are; with a
    /// device tree, PSCI is asked until it refuses).
    pub cpus: Option<usize>,
    /// PCI's interrupt pins, if the firmware says where they go.
    pub intx: Option<Intx>,
}

impl Platform {
    pub fn from_device_tree(dtb: u64) -> Platform {
        let mut p = Platform { source: "device tree", ..Default::default() };
        p.gicd = fdt::reg(dtb, b"arm,gic-v3", 0).map(|r| r.0);
        p.gicr = fdt::reg(dtb, b"arm,gic-v3", 1).map(|r| r.0);
        p.its = fdt::reg(dtb, b"arm,gic-v3-its", 0).map(|r| r.0);
        // Secure, non-secure physical, virtual, hypervisor: the third.
        p.timer = fdt::irq(dtb, b"arm,armv8-timer", 2);
        for uart in [&b"arm,pl011"[..], b"arm,sbsa-uart"] {
            if let (Some((base, _)), Some(irq)) = (fdt::reg(dtb, uart, 0), fdt::irq(dtb, uart, 0)) {
                p.uart = Some((base, irq));
                break;
            }
        }
        let host = b"pci-host-ecam-generic";
        let first_bus = fdt::prop(dtb, host, b"bus-range").and_then(|r| r.cell(0)).unwrap_or(0);
        if let Some((base, size)) = fdt::reg(dtb, host, 0) {
            if first_bus == 0 && size >= 16 << 20 {
                p.ecam = Some(base);
            }
        }
        // `ranges`: (PCI address: three cells, the first saying which
        // space), CPU address, size.
        if let Some(r) = fdt::prop(dtb, host, b"ranges") {
            let (pa, _) = r.parent_cells;
            let (ca, cs) = r.own_cells;
            let entry = (ca + pa + cs) as u64;
            if ca == 3 && (1..=2).contains(&pa) && (1..=2).contains(&cs) {
                let mut i = 0;
                while let (Some(hi), Some(pci), Some(cpu), Some(len)) =
                    (r.cell(i), r.cells(i + 1, 2), r.cells(i + 3, pa), r.cells(i + 3 + pa as u64, cs))
                {
                    match (hi >> 24) & 3 {
                        1 if pci == 0 && p.pci_io.is_none() => p.pci_io = block(cpu, len, 16),
                        2 if pci == cpu && p.pci_mem.is_none() => p.pci_mem = block(cpu, len, 32),
                        _ => {}
                    }
                    i += entry;
                }
            }
        }
        p.smmu = fdt::find_device(dtb, b"arm,smmu-v3");
        p.psci_smc = fdt::device_prop_is(dtb, b"arm,psci-0.2", b"method", b"smc");
        p.intx = interrupt_map(dtb);
        p
    }

    pub fn from_acpi(m: &acpi::Machine) -> Platform {
        let mut p = Platform { source: "ACPI", ..Default::default() };
        if matches!(m.gic_version, 0 | 3) {
            p.gicd = Some(m.gicd);
            p.gicr = m.gicr;
            p.its = m.its;
        }
        p.timer = m.timer;
        // SPCR interface types 3 (PL011) and 0x0e (SBSA generic UART).
        p.uart = m.uart.filter(|u| matches!(u.0, 3 | 0x0e)).map(|u| (u.1, u.2));
        if let Some((base, 0, last)) = m.ecam {
            if last >= 15 {
                p.ecam = Some(base);
            }
        }
        for w in &m.windows[..m.window_count] {
            if w.io && w.pci == 0 && p.pci_io.is_none() {
                p.pci_io = block(w.cpu, w.len, 16);
            } else if !w.io && w.pci == w.cpu && w.cpu < 1 << 32 && p.pci_mem.is_none() {
                p.pci_mem = block(w.cpu, w.len, 32);
            }
        }
        p.smmu = m.smmu;
        p.psci_smc = m.psci == Some(false);
        p.cpus = Some(if m.psci.is_some() { m.cpus } else { 1 });
        p.intx = m.routes.as_ref().and_then(prt);
        p
    }

    /// The first thing the kernel needs that the firmware did not say.
    pub fn missing(&self) -> Option<&'static str> {
        Some(if self.gicd.is_none() || self.gicr.is_none() {
            "no GICv3 (distributor and redistributors)"
        } else if self.timer.is_none() {
            "no interrupt for the EL1 virtual timer"
        } else if !self.uart.is_some_and(|u| u.1 < 256) {
            "no PL011 console, or its interrupt is above 255"
        } else if self.ecam.is_none() {
            "no PCI configuration space (ECAM) from bus 0 to bus 15"
        } else if self.pci_mem.is_none() {
            "no window of 32-bit PCI memory the CPU reaches at the same addresses"
        } else {
            return None;
        })
    }
}
