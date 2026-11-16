//! ACPI tables, as the firmware leaves them: found from the RSDP the
//! bootloader passes, read through the kernel's map of physical memory.
//!
//! What the kernel needs from them, in place of assuming QEMU's layout:
//!
//! - MCFG: PCI Express configuration space (ECAM), so that the window PCI
//!   BARs are assigned from stays clear of it. Firmware puts it in
//!   different places: SeaBIOS at 0xb000_0000 on QEMU's q35, OVMF (UEFI)
//!   at 0xe000_0000; QEMU's `pc` machine has none.
//! - MADT: the CPUs, by local APIC ID (which need not run 0, 1, 2, ...:
//!   hybrid and multi-socket machines leave gaps), and the I/O APICs.
//! - DMAR: the VT-d remapping units and the PCI functions each covers:
//!   those its device scopes name (one on bus 0, or everything behind a
//!   bridge there), or, for the one so flagged, every function no other
//!   unit names. A function no unit the kernel drives covers cannot be
//!   bound, so it never gets DMA unisolated.
//!   And the requester ID each I/O APIC's interrupts carry, which
//!   interrupt remapping checks. And its reserved memory regions: memory
//!   a function keeps using whatever it is told, which binding it maps.
//! - The MADT's interrupt source overrides: which GSI each ISA IRQ arrives
//!   on, and how it signals.
//! - The DSDT (through the FADT): the PCI root bridge's `_PRT`, which says
//!   which GSI each slot's interrupt pins reach ([`crate::aml`]).

use super::aml;
use super::vm::phys_ptr;
use crate::{kprint, kprintln};
use crate::smp::MAX_CPUS;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The ECAM window of PCI segment 0: start and end (0 if there is none).
static ECAM_START: AtomicU64 = AtomicU64::new(0);
static ECAM_END: AtomicU64 = AtomicU64::new(0);

fn read<const N: usize>(pa: u64) -> [u8; N] {
    let mut b = [0u8; N];
    // SAFETY: firmware tables are in RAM the kernel maps whole; reads only.
    unsafe { core::ptr::copy_nonoverlapping(phys_ptr(pa), b.as_mut_ptr(), N) };
    b
}

fn u32_at(pa: u64) -> u32 {
    u32::from_le_bytes(read::<4>(pa))
}

fn u64_at(pa: u64) -> u64 {
    u64::from_le_bytes(read::<8>(pa))
}

/// Whether the `len` bytes at `pa` add up to 0, as every ACPI table's do.
fn sums_to_zero(pa: u64, len: u64) -> bool {
    (0..len).fold(0u8, |s, i| s.wrapping_add(read::<1>(pa + i)[0])) == 0
}

/// Every table with signature `sig`, from the RSDP at `rsdp`, in the
/// order the root table lists them: each one's address and length, if it
/// is whole.
fn tables(rsdp: u64, sig: &[u8; 4]) -> impl Iterator<Item = (u64, u64)> {
    let root = (&read::<8>(rsdp) == b"RSD PTR " && sums_to_zero(rsdp, 20))
        .then(|| {
            // ACPI 2.0 and later: the XSDT, with 64-bit entries; else the
            // RSDT.
            if read::<1>(rsdp + 15)[0] >= 2 && u64_at(rsdp + 24) != 0 {
                (u64_at(rsdp + 24), 8)
            } else {
                (u32_at(rsdp + 16) as u64, 4)
            }
        })
        .and_then(|(root, entry)| {
            let len = u32_at(root + 4) as u64;
            ((36..=1 << 16).contains(&len) && sums_to_zero(root, len)).then_some((root, entry, (len - 36) / entry))
        });
    let (root, entry, count) = root.unwrap_or((0, 4, 0));
    let sig = *sig;
    (0..count).filter_map(move |i| {
        let at = root + 36 + i * entry;
        let table = if entry == 8 { u64_at(at) } else { u32_at(at) as u64 };
        let tlen = u32_at(table + 4) as u64;
        (read::<4>(table) == sig && (36..1 << 20).contains(&tlen) && sums_to_zero(table, tlen)).then_some((table, tlen))
    })
}

/// The (first) table with signature `sig`: its address and length, if it
/// is there and whole.
fn find(rsdp: u64, sig: &[u8; 4]) -> Option<(u64, u64)> {
    tables(rsdp, sig).next()
}

/// The enabled CPUs' local APIC IDs, in the MADT's order (up to
/// `MAX_CPUS`), and how many CPUs the MADT lists in all (0 without one).
static CPU_APIC: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static CPUS_KEPT: AtomicUsize = AtomicUsize::new(0);
static CPUS_LISTED: AtomicUsize = AtomicUsize::new(0);

/// The VT-d units of PCI segment 0 (up to 4), in the DMAR's order: each
/// one's register base (0: none), whether it covers every function no
/// other unit names, which functions on bus 0 it names (a bit per device
/// and function), and whether it names a bridge there (and so covers the
/// buses behind it).
pub const MAX_UNITS: usize = 4;
static UNIT_BASE: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
static UNIT_ALL: [AtomicBool; MAX_UNITS] = [const { AtomicBool::new(false) }; MAX_UNITS];
static UNIT_BUS0: [[AtomicU64; 4]; MAX_UNITS] = [const { [const { AtomicU64::new(0) }; 4] }; MAX_UNITS];
static UNIT_BRIDGES: [AtomicBool; MAX_UNITS] = [const { AtomicBool::new(false) }; MAX_UNITS];

/// The I/O APICs (up to 4): register base | first GSI << 32 (0: none),
/// and their APIC IDs.
static IOAPIC: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static IOAPIC_ID: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// The DMAR's I/O APIC device scopes (up to 4): bit 31 set, the unit
/// that names it << 24, APIC ID << 16, requester ID.
static IOAPIC_SID: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// The DMAR's reserved memory regions (up to 8): each one's first byte
/// and end (exclusive; 0 for no region), and the requester IDs of up to 4
/// functions it names (bit 31 set).
const MAX_RESERVED: usize = 8;
static RESERVED: [[AtomicU64; 2]; MAX_RESERVED] = [const { [const { AtomicU64::new(0) }; 2] }; MAX_RESERVED];
static RESERVED_SID: [[AtomicU32; 4]; MAX_RESERVED] = [const { [const { AtomicU32::new(0) }; 4] }; MAX_RESERVED];
/// ISA IRQ overrides: bit 31 set, the MPS flags << 24, the GSI.
static ISA: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
/// The root bus's interrupt routes, from `_PRT`.
static ROUTES: spin::Once<aml::Routes> = spin::Once::new();

/// The structures of `table` (`len` bytes) after its 36-byte header and
/// `skip` more: each one's (address, type, length), with a byte type and
/// length as in the MADT, or (`wide`) two-byte ones as in the DMAR.
fn structures(table: u64, len: u64, skip: u64, wide: bool) -> impl Iterator<Item = (u64, u16, u64)> {
    let mut at = table + 36 + skip;
    let end = table + len;
    let head = if wide { 4 } else { 2 };
    core::iter::from_fn(move || {
        if at + head > end {
            return None;
        }
        let (kind, n) = if wide {
            let [a, b, c, d] = read::<4>(at);
            (u16::from_le_bytes([a, b]), u16::from_le_bytes([c, d]) as u64)
        } else {
            let [a, b] = read::<2>(at);
            (a as u16, b as u64)
        };
        if n < head || at + n > end {
            return None;
        }
        let here = at;
        at += n;
        Some((here, kind, n))
    })
}

/// An address, written " at 0x..." (nothing for 0).
struct At(u64);

impl core::fmt::Display for At {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.0 != 0 {
            write!(f, " at {:#x}", self.0)?;
        }
        Ok(())
    }
}

fn madt(rsdp: u64) {
    let Some((t, len)) = find(rsdp, b"APIC") else {
        kprintln!("[ok] ACPI: no MADT (CPUs are looked for by APIC ID)");
        return;
    };
    let (mut listed, mut kept, mut ioapics, mut first_ioapic, mut overrides) = (0, 0, 0, 0, 0);
    // 8 bytes after the header: the local APICs' address and flags.
    for (e, kind, n) in structures(t, len, 8, false) {
        let cpu = match (kind, n) {
            // A processor's local APIC: its UID, APIC ID and flags.
            (0, 8..) => Some((read::<1>(e + 3)[0] as u32, u32_at(e + 4))),
            // The same with an x2APIC ID.
            (9, 16..) => Some((u32_at(e + 4), u32_at(e + 8))),
            // An I/O APIC: its ID, address and first interrupt.
            (1, 12..) => {
                let base = u32_at(e + 4) as u64;
                if let (Some(slot), Some(id)) = (IOAPIC.get(ioapics), IOAPIC_ID.get(ioapics)) {
                    slot.store(base | (u32_at(e + 8) as u64) << 32, Ordering::Relaxed);
                    id.store(read::<1>(e + 2)[0] as u32, Ordering::Relaxed);
                }
                ioapics += 1;
                if first_ioapic == 0 {
                    first_ioapic = base;
                }
                None
            }
            // An interrupt source override: bus 0 (ISA), IRQ, GSI, flags.
            (2, 10..) => {
                let [_, irq] = read::<2>(e + 2);
                let flags = u16::from_le_bytes(read::<2>(e + 8)) as u32 & 0xf;
                if let Some(slot) = ISA.get(irq as usize) {
                    slot.store(1 << 31 | flags << 24 | u32_at(e + 4) & 0xff_ffff, Ordering::Relaxed);
                    overrides += 1;
                }
                None
            }
            _ => None,
        };
        if let Some((apic, flags)) = cpu {
            listed += 1;
            // Enabled (bit 0); one that is only "online capable" is not
            // there yet.
            if flags & 1 != 0 && kept < MAX_CPUS {
                CPU_APIC[kept].store(apic, Ordering::Relaxed);
                kept += 1;
            }
        }
    }
    CPUS_KEPT.store(kept, Ordering::Relaxed);
    CPUS_LISTED.store(listed, Ordering::Relaxed);
    let mut ids = [0u32; MAX_CPUS];
    for (i, id) in ids.iter_mut().enumerate().take(kept) {
        *id = CPU_APIC[i].load(Ordering::Relaxed);
    }
    kprintln!(
        "[ok] ACPI: {kept} of {listed} CPUs listed taken, APIC IDs {:?}; {ioapics} I/O APIC{}{}; {overrides} ISA IRQ override{}",
        &ids[..kept],
        if ioapics == 1 { "" } else { "s" },
        At(first_ioapic),
        if overrides == 1 { "" } else { "s" },
    );
}

/// The device scopes of the DMAR structure at `e` (`n` bytes), whose
/// scopes start `skip` bytes in: each one's type, enumeration ID, start
/// bus, and its path (device, function pairs down the bridges from that
/// bus) as an address and length.
fn scopes(e: u64, n: u64, skip: u64) -> impl Iterator<Item = (u8, u8, u8, u64, u64)> {
    let mut s = e + skip;
    core::iter::from_fn(move || {
        if s + 6 > e + n {
            return None;
        }
        let [kind, sl, _, _, id, bus] = read::<6>(s);
        if sl < 6 || s + sl as u64 > e + n {
            return None;
        }
        let here = s;
        s += sl as u64;
        Some((kind, id, bus, here + 6, sl as u64 - 6))
    })
}

fn dmar(rsdp: u64) {
    if find(rsdp, b"DMAR").is_none() {
        kprintln!("[ok] ACPI: no DMAR (no VT-d)");
        return;
    }
    // Firmware lists one DMAR; QEMU's tests add a second, with what
    // QEMU's own cannot say (a second unit, reserved memory). Every one is
    // read, a unit listed twice merging into one.
    let (mut units, mut other_segments) = (0, 0);
    for (t, len) in tables(rsdp, b"DMAR") {
        // 12 bytes after the header: address width, flags, reserved.
        for (e, kind, n) in structures(t, len, 12, true) {
            // A remapping unit: flags (bit 0: every PCI function no other
            // unit names), reserved, segment, register base, then device
            // scopes.
            if kind != 0 || n < 16 {
                continue;
            }
            let [flags, _, s0, s1] = read::<4>(e + 4);
            let base = u64_at(e + 8);
            if u16::from_le_bytes([s0, s1]) != 0 {
                other_segments += 1;
                continue;
            }
            // Its slot: the one it already has, or the first free one.
            let u = match (0..MAX_UNITS).find(|&u| [0, base].contains(&UNIT_BASE[u].load(Ordering::Relaxed))) {
                Some(u) => u,
                None => {
                    units += 1;
                    continue;
                }
            };
            if UNIT_BASE[u].swap(base, Ordering::Relaxed) == 0 {
                units += 1;
            }
            if flags & 1 != 0 {
                UNIT_ALL[u].store(true, Ordering::Relaxed);
            }
            for (kind, id, bus, path, plen) in scopes(e, n, 16) {
                if plen != 2 {
                    continue;
                }
                let [dev, func] = read::<2>(path);
                let sid = (bus as u32) << 8 | (dev as u32 & 31) << 3 | func as u32 & 7;
                let devfn = (sid & 0xff) as usize;
                match kind {
                    // A function on bus 0 itself (a path of one), or a
                    // bridge there. Named twice (firmware never does; a
                    // test's second DMAR moves one), it is the last unit's.
                    1 | 2 if bus == 0 => {
                        for v in 0..MAX_UNITS {
                            UNIT_BUS0[v][devfn / 64].fetch_and(!(1 << (devfn % 64)), Ordering::Relaxed);
                        }
                        UNIT_BUS0[u][devfn / 64].fetch_or(1 << (devfn % 64), Ordering::Relaxed);
                        if kind == 2 {
                            UNIT_BRIDGES[u].store(true, Ordering::Relaxed);
                        }
                    }
                    // An I/O APIC: the requester ID its interrupts carry,
                    // and the unit they go through.
                    3 => {
                        if let Some(slot) = IOAPIC_SID.iter().find(|s| s.load(Ordering::Relaxed) == 0) {
                            slot.store(1 << 31 | (u as u32) << 24 | (id as u32) << 16 | sid, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let (reserved, kept) = reserved_regions(rsdp);
    kprintln!(
        "[ok] ACPI: {units} VT-d unit{}{}; {reserved} reserved memory region{}",
        if units == 1 { "" } else { "s" },
        match (units > MAX_UNITS, other_segments) {
            (true, _) => " (only the first 4 are used)",
            (_, 0) => "",
            _ => " (and some on other PCI segments, not used)",
        },
        if reserved == 1 { "" } else { "s" },
    );
    for (u, base) in vtd_units() {
        if UNIT_ALL[u].load(Ordering::Relaxed) {
            kprintln!("[ok] ACPI: VT-d unit at {base:#x}: every PCI function no other unit names");
            continue;
        }
        let named: u32 = UNIT_BUS0[u].iter().map(|w| w.load(Ordering::Relaxed).count_ones()).sum();
        kprintln!(
            "[ok] ACPI: VT-d unit at {base:#x}: {named} function{} it names on bus 0{}",
            if named == 1 { "" } else { "s" },
            if UNIT_BRIDGES[u].load(Ordering::Relaxed) { " and what is behind its bridges" } else { "" }
        );
    }
    for i in 0..kept {
        let [start, end] = [0, 1].map(|j| RESERVED[i][j].load(Ordering::Relaxed));
        kprint!("[ok] ACPI: reserved memory {start:#x} to {:#x}, for", end - 1);
        let mut any = false;
        for sid in RESERVED_SID[i].iter().map(|s| s.load(Ordering::Relaxed)).filter(|s| s >> 31 == 1) {
            kprint!(" {:02x}:{:02x}.{}", sid >> 8 & 0xff, sid >> 3 & 31, sid & 7);
            any = true;
        }
        kprintln!("{}", if any { "" } else { " no function the kernel can name" });
        // Firmware should mark it reserved; if it left any of it usable,
        // the kernel may have given those pages to anyone, so the function
        // does not get them.
        let usable = (start..end).step_by(4096).filter(|&pa| crate::memory::is_ram(pa)).count();
        if usable > 0 {
            kprintln!("[warn] ACPI: {usable} of its pages are usable RAM too: they are not mapped for it");
        }
    }
}

/// Reads the reserved memory regions of every DMAR the firmware lists
/// (it lists one; QEMU's tests add a second, with the regions QEMU's own
/// lacks): ranges a device keeps using whatever it is told, such as a USB
/// controller's legacy keyboard emulation or a GPU's stolen memory. Each
/// function a region names must find it mapped where it is in its I/O
/// space. Returns how many there are, and how many were kept (segment 0,
/// whole pages, up to `MAX_RESERVED`).
fn reserved_regions(rsdp: u64) -> (usize, usize) {
    let (mut found, mut kept) = (0, 0);
    for (t, len) in tables(rsdp, b"DMAR") {
        for (e, kind, n) in structures(t, len, 12, true) {
            // Type 1, a reserved region: reserved, segment, base, limit
            // (its last byte), then device scopes.
            if kind != 1 || n < 24 {
                continue;
            }
            found += 1;
            let [_, _, s0, s1] = read::<4>(e + 4);
            let (base, limit) = (u64_at(e + 8), u64_at(e + 16));
            if u16::from_le_bytes([s0, s1]) != 0 || base & 0xfff != 0 || limit & 0xfff != 0xfff || limit < base || kept == MAX_RESERVED {
                continue;
            }
            let mut sids = 0;
            for (kind, _, bus, path, plen) in scopes(e, n, 24) {
                // An endpoint on its start bus (a path of one), as the
                // functions firmware reserves memory for are: integrated
                // USB controllers and graphics, on bus 0.
                if kind == 1 && plen == 2 && sids < 4 {
                    let [dev, func] = read::<2>(path);
                    let sid = (bus as u32) << 8 | (dev as u32 & 31) << 3 | func as u32 & 7;
                    RESERVED_SID[kept][sids].store(1 << 31 | sid, Ordering::Relaxed);
                    sids += 1;
                }
            }
            RESERVED[kept][0].store(base, Ordering::Relaxed);
            RESERVED[kept][1].store(limit + 1, Ordering::Relaxed);
            kept += 1;
        }
    }
    (found, kept)
}

/// The reserved memory regions the DMAR names requester `sid` in: each
/// one's first byte and end (exclusive).
pub fn reserved_for(sid: u16) -> impl Iterator<Item = (u64, u64)> {
    (0..MAX_RESERVED).filter_map(move |i| {
        let end = RESERVED[i][1].load(Ordering::Relaxed);
        let named = RESERVED_SID[i].iter().any(|s| s.load(Ordering::Relaxed) == 1 << 31 | sid as u32);
        (end != 0 && named).then(|| (RESERVED[i][0].load(Ordering::Relaxed), end))
    })
}

/// The VT-d unit requester ID `sid` (bus, device, function) goes through:
/// one that names it (on bus 0), or names a bridge (for the buses behind
/// one), else the one for every function no other unit names. `None` if
/// no unit covers it.
pub fn vtd_unit(sid: u16) -> Option<usize> {
    let (bus, devfn) = (sid >> 8, (sid & 0xff) as usize);
    let present = |u: &usize| UNIT_BASE[*u].load(Ordering::Relaxed) != 0;
    let all = |u: usize| UNIT_ALL[u].load(Ordering::Relaxed);
    let names = |u: usize| {
        if bus == 0 {
            UNIT_BUS0[u][devfn / 64].load(Ordering::Relaxed) & 1 << (devfn % 64) != 0
        } else {
            UNIT_BRIDGES[u].load(Ordering::Relaxed)
        }
    };
    (0..MAX_UNITS)
        .filter(present)
        .find(|&u| !all(u) && names(u))
        .or_else(|| (0..MAX_UNITS).filter(present).find(|&u| all(u)))
}

/// The VT-d units: each one's index and register base.
pub fn vtd_units() -> impl Iterator<Item = (usize, u64)> {
    (0..MAX_UNITS).filter_map(|u| Some((u, UNIT_BASE[u].load(Ordering::Relaxed))).filter(|&(_, b)| b != 0))
}

/// The enabled CPUs' local APIC IDs from the MADT (up to `MAX_CPUS`), or
/// `None` without a MADT.
pub fn cpus() -> Option<impl Iterator<Item = u32>> {
    (CPUS_LISTED.load(Ordering::Relaxed) > 0)
        .then(|| (0..CPUS_KEPT.load(Ordering::Relaxed)).map(|i| CPU_APIC[i].load(Ordering::Relaxed)))
}

/// The I/O APICs: APIC ID, register base and first GSI.
pub fn ioapics() -> impl Iterator<Item = (u32, u64, u32)> {
    (0..IOAPIC.len()).map_while(|i| {
        let v = IOAPIC[i].load(Ordering::Relaxed);
        (v != 0).then(|| (IOAPIC_ID[i].load(Ordering::Relaxed), v & 0xffff_ffff, (v >> 32) as u32))
    })
}

/// The requester ID of I/O APIC `id`'s interrupts, and the VT-d unit they
/// go through, from the DMAR.
pub fn ioapic_sid(id: u32) -> Option<(u16, usize)> {
    IOAPIC_SID.iter().map(|s| s.load(Ordering::Relaxed)).find_map(|v| {
        (v >> 31 == 1 && (v >> 16) & 0xff == id).then_some((v as u16, (v >> 24 & 0x7f) as usize))
    })
}

/// Where ISA IRQ `irq` arrives: its GSI, whether it is level-triggered,
/// and whether active low. ISA's own way (edge, active high, GSI = IRQ)
/// unless the MADT overrides it.
pub fn isa_irq(irq: u8) -> aml::Route {
    let v = ISA.get(irq as usize).map_or(0, |s| s.load(Ordering::Relaxed));
    if v >> 31 == 0 {
        return aml::Route { gsi: irq as u32, level: false, active_low: false };
    }
    let flags = v >> 24 & 0xf;
    aml::Route { gsi: v & 0xff_ffff, level: flags >> 2 == 3, active_low: flags & 3 == 3 }
}

/// The root bus's interrupt routes from the DSDT's `_PRT`, if they could
/// be read.
pub fn pci_routes() -> Option<&'static aml::Routes> {
    ROUTES.get()
}

/// Reads the root bridge's `_PRT` from the DSDT the FADT points to.
fn dsdt(rsdp: u64) {
    let dsdt = find(rsdp, b"FACP").and_then(|(f, len)| {
        // X_DSDT (64 bits, at 140) where the FADT has it, else DSDT (at 40).
        let x = if len >= 148 { u64_at(f + 140) } else { 0 };
        let d = if x != 0 { x } else { u32_at(f + 40) as u64 };
        let dlen = u32_at(d + 4) as u64;
        (d != 0 && &read::<4>(d) == b"DSDT" && (36..1 << 24).contains(&dlen) && sums_to_zero(d, dlen)).then_some((d, dlen))
    });
    let Some((d, len)) = dsdt else {
        kprintln!("[ok] ACPI: no DSDT (legacy PCI interrupt routing unknown)");
        return;
    };
    // SAFETY: the DSDT lies in RAM the kernel maps whole; read only.
    let bytes = unsafe { core::slice::from_raw_parts(phys_ptr(d) as *const u8, len as usize) };
    match aml::root_routes(bytes) {
        Some((routes, entries)) => {
            let r = ROUTES.call_once(|| routes);
            let slot0 = |pin: usize| r[0][pin].map_or(-1, |r| r.gsi as i64);
            kprintln!(
                "[ok] ACPI: the PCI root bridge's _PRT: {entries} routes to the I/O APIC (slot 0's pins at GSIs {}, {}, {}, {})",
                slot0(0),
                slot0(1),
                slot0(2),
                slot0(3)
            );
        }
        None => kprintln!("[ok] ACPI: no _PRT the kernel can read in the DSDT ({len} bytes): legacy PCI interrupt routing unknown"),
    }
}

/// Reads the tables from the RSDP at `rsdp` (if the bootloader found one).
pub fn init(rsdp: Option<u64>) {
    let Some(rsdp) = rsdp else {
        kprintln!("[ok] ACPI: no RSDP");
        return;
    };
    madt(rsdp);
    dmar(rsdp);
    dsdt(rsdp);
    // MCFG: 44 bytes of header, then 16 bytes for each segment's window:
    // its base, segment number, and first and last bus.
    let mcfg = find(rsdp, b"MCFG").and_then(|(t, len)| {
        (0..(len.saturating_sub(44)) / 16).find_map(|i| {
            let e = t + 44 + i * 16;
            let [s0, s1, first, last] = read::<4>(e + 8);
            (u16::from_le_bytes([s0, s1]) == 0 && last >= first).then(|| {
                // The window covers bus 0 up, whatever bus it starts at.
                let base = u64_at(e);
                (base, base + ((last as u64 + 1) << 20), first, last)
            })
        })
    });
    match mcfg {
        Some((start, end, first, last)) => {
            ECAM_START.store(start, Ordering::Relaxed);
            ECAM_END.store(end, Ordering::Relaxed);
            kprintln!("[ok] ACPI: PCI Express configuration space at {start:#x} (buses {first} to {last})");
        }
        None => kprintln!("[ok] ACPI: no MCFG (no PCI Express configuration space)"),
    }
}

/// The ECAM window of PCI segment 0, if the firmware describes one.
pub fn ecam() -> Option<core::ops::Range<u64>> {
    let (s, e) = (ECAM_START.load(Ordering::Relaxed), ECAM_END.load(Ordering::Relaxed));
    (e > s).then_some(s..e)
}
