//! The machine as ACPI describes it, for firmware that offers ACPI tables
//! rather than a device tree (the UEFI loader passes the RSDP's address).
//! Read once at boot, before any RAM is handed out, from the tables' own
//! memory, which the firmware's memory map keeps out of the kernel's RAM:
//!
//! - MADT: the CPUs (each GIC CPU interface's MPIDR), the GICv3
//!   distributor, redistributors and ITS;
//! - GTDT: the generic timer's interrupt;
//! - SPCR: the serial console;
//! - MCFG: PCI Express configuration space (ECAM);
//! - IORT: the SMMUv3, its interrupt, and how requester IDs reach it as
//!   stream IDs;
//! - FADT: whether PSCI is there, and called by `hvc` or `smc`.
//!
//! Every table must lie in the RAM the kernel maps (the second GiB), have
//! a valid checksum and be long enough for what is read of it.

use super::vm::KERNEL_RAM;

/// What the tables say.
pub struct Machine {
    /// The RSDP's address.
    pub rsdp: u64,
    /// Enabled CPUs, numbered by their MPIDR affinity 0 (0 to `cpus` - 1).
    pub cpus: usize,
    /// PSCI is there and called by `hvc` (the kernel's only conduit).
    pub psci_hvc: bool,
    /// The GIC: its version (0 if unstated), distributor, first
    /// redistributor and ITS.
    pub gic_version: u8,
    pub gicd: u64,
    pub gicr: Option<u64>,
    pub its: Option<u64>,
    /// The EL1 virtual timer's interrupt ID.
    pub timer: Option<u32>,
    /// The serial console (SPCR): its interface type, registers and
    /// interrupt ID.
    pub uart: Option<(u8, u64, u32)>,
    /// Segment 0's ECAM: base and first and last bus.
    pub ecam: Option<(u64, u8, u8)>,
    /// The SMMUv3: registers and event queue interrupt ID.
    pub smmu: Option<(u64, Option<u32>)>,
}

fn byte(a: u64) -> u8 {
    // SAFETY: callers check `a` lies in a table inside the kernel's RAM,
    // which is identity-mapped.
    unsafe { (a as *const u8).read_volatile() }
}

fn le(a: u64, n: u64) -> u64 {
    (0..n).rev().fold(0, |v, i| v << 8 | byte(a + i) as u64)
}

fn u16_at(a: u64) -> u64 {
    le(a, 2)
}

fn u32_at(a: u64) -> u64 {
    le(a, 4)
}

fn u64_at(a: u64) -> u64 {
    le(a, 8)
}

fn mapped(a: u64, len: u64) -> bool {
    a >= KERNEL_RAM.start && a.checked_add(len).is_some_and(|e| e <= KERNEL_RAM.end)
}

fn sums_to_zero(a: u64, len: u64) -> bool {
    (0..len).fold(0u8, |s, i| s.wrapping_add(byte(a + i))) == 0
}

/// The tables the XSDT lists: each one's address and length, once its
/// header is in the kernel's RAM, its whole length too, and its checksum
/// is right.
struct Tables {
    xsdt: u64,
    count: u64,
}

impl Tables {
    fn find(&self, sig: &[u8; 4]) -> Result<Option<(u64, u64)>, &'static str> {
        for i in 0..self.count {
            let t = u64_at(self.xsdt + 36 + 8 * i);
            if !mapped(t, 36) {
                return Err("an ACPI table lies outside the RAM the kernel maps");
            }
            if (0..4).any(|j| byte(t + j) != sig[j as usize]) {
                continue;
            }
            let len = u32_at(t + 4);
            if len < 36 || !mapped(t, len) {
                return Err("an ACPI table's length is wrong, or it lies outside the RAM the kernel maps");
            }
            if !sums_to_zero(t, len) {
                return Err("an ACPI table's checksum is wrong");
            }
            return Ok(Some((t, len)));
        }
        Ok(None)
    }
}

pub fn read(rsdp: u64) -> Result<Machine, &'static str> {
    if !mapped(rsdp, 36) || (0..8).any(|i| byte(rsdp + i) != b"RSD PTR "[i as usize]) {
        return Err("no ACPI RSDP where the loader says");
    }
    if byte(rsdp + 15) < 2 || !sums_to_zero(rsdp, 20) || !sums_to_zero(rsdp, 36) {
        return Err("the ACPI RSDP is not a valid ACPI 2.0 one");
    }
    let xsdt = u64_at(rsdp + 24);
    if !mapped(xsdt, 36) || (0..4).any(|i| byte(xsdt + i) != b"XSDT"[i as usize]) {
        return Err("no XSDT where the RSDP says");
    }
    let len = u32_at(xsdt + 4);
    if len < 36 || !mapped(xsdt, len) || !sums_to_zero(xsdt, len) {
        return Err("the XSDT's length or checksum is wrong");
    }
    let tables = Tables { xsdt, count: (len - 36) / 8 };
    let mut m = Machine {
        rsdp,
        cpus: 0,
        psci_hvc: false,
        gic_version: 0,
        gicd: 0,
        gicr: None,
        its: None,
        timer: None,
        uart: None,
        ecam: None,
        smmu: None,
    };

    // MADT: interrupt controller structures from offset 44.
    let (madt, len) = tables.find(b"APIC")?.ok_or("no MADT")?;
    let mut affinities = 0u64;
    let mut gicc_gicr = None;
    let mut p = madt + 44;
    while p + 2 <= madt + len {
        let (kind, n) = (byte(p), byte(p + 1) as u64);
        if n < 2 || p + n > madt + len {
            return Err("the MADT's entries overrun it");
        }
        match kind {
            // GIC CPU interface: enabled, and its MPIDR.
            0x0b if n >= 76 => {
                if u32_at(p + 12) & 1 != 0 {
                    let mpidr = u64_at(p + 68);
                    let aff0 = mpidr & 0xff;
                    if mpidr & 0xff_00ff_ff00 != 0 || aff0 >= 64 {
                        return Err("a CPU's MPIDR has affinity above level 0; the kernel numbers CPUs by affinity 0 alone");
                    }
                    affinities |= 1 << aff0;
                    m.cpus += 1;
                    if gicc_gicr.is_none() && u64_at(p + 60) != 0 {
                        gicc_gicr = Some(u64_at(p + 60));
                    }
                }
            }
            // Distributor.
            0x0c if n >= 24 => {
                m.gicd = u64_at(p + 8);
                m.gic_version = byte(p + 20);
            }
            // Redistributor discovery range.
            0x0e if n >= 16 => {
                m.gicr.get_or_insert(u64_at(p + 4));
            }
            // ITS.
            0x0f if n >= 20 => {
                m.its.get_or_insert(u64_at(p + 8));
            }
            _ => {}
        }
        p += n;
    }
    if m.gicr.is_none() {
        m.gicr = gicc_gicr;
    }
    if m.cpus == 0 || affinities != (1u64 << m.cpus) - 1 {
        return Err("the MADT's CPUs are not numbered 0 up by MPIDR affinity 0");
    }
    if m.gicd == 0 {
        return Err("the MADT has no GIC distributor");
    }

    // FADT: ARM boot architecture flags (PSCI compliant, by HVC).
    if let Some((fadt, len)) = tables.find(b"FACP")? {
        m.psci_hvc = len >= 131 && u16_at(fadt + 129) & 3 == 3;
    }

    // GTDT: the EL1 virtual timer's GSIV.
    if let Some((gtdt, len)) = tables.find(b"GTDT")? {
        if len >= 68 {
            m.timer = Some(u32_at(gtdt + 64) as u32);
        }
    }

    // SPCR: interface type, the register address (a generic address
    // structure at 40) and the GSIV.
    if let Some((spcr, len)) = tables.find(b"SPCR")? {
        if len >= 58 {
            m.uart = Some((byte(spcr + 36), u64_at(spcr + 44), u32_at(spcr + 54) as u32));
        }
    }

    // MCFG: 16-byte allocations from 44; segment 0's.
    if let Some((mcfg, len)) = tables.find(b"MCFG")? {
        let mut p = mcfg + 44;
        while p + 16 <= mcfg + len {
            if u16_at(p + 8) == 0 {
                m.ecam = Some((u64_at(p), byte(p + 10), byte(p + 11)));
                break;
            }
            p += 16;
        }
    }

    // IORT: the first SMMUv3 node, and every root complex mapping into it
    // must keep the requester ID as the stream ID (the SMMU driver's
    // stream table is indexed by requester ID).
    if let Some((iort, len)) = tables.find(b"IORT")? {
        let nodes = u32_at(iort + 36);
        let first = iort + u32_at(iort + 40);
        let node = |p: u64| -> Option<(u8, u64)> {
            let n = u16_at(p + 1);
            (p + 16 <= iort + len && n >= 16 && p + n <= iort + len).then_some((byte(p), n))
        };
        let mut smmu_node = None;
        let mut p = first;
        for _ in 0..nodes {
            let (kind, n) = node(p).ok_or("the IORT's nodes overrun it")?;
            if kind == 4 && n >= 60 && smmu_node.is_none() {
                let event = u32_at(p + 44) as u32;
                m.smmu = Some((u64_at(p + 16), (event != 0).then_some(event)));
                smmu_node = Some(p - iort);
            }
            p += n;
        }
        if let Some(target) = smmu_node {
            let mut p = first;
            for _ in 0..nodes {
                let (kind, n) = node(p).ok_or("the IORT's nodes overrun it")?;
                if kind == 2 {
                    let (count, at) = (u32_at(p + 8), u32_at(p + 12));
                    for i in 0..count {
                        let e = p + at + 20 * i;
                        if e + 20 > p + n {
                            return Err("an IORT root complex's ID mappings overrun it");
                        }
                        if u32_at(e + 12) == target && u32_at(e) != u32_at(e + 8) {
                            return Err("the IORT gives PCI functions stream IDs other than their requester IDs, which the SMMU driver takes them to be");
                        }
                    }
                }
                p += n;
            }
        }
    }
    Ok(m)
}
