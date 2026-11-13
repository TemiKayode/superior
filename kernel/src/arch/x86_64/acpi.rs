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
//! - DMAR: the VT-d remapping unit to use and the PCI functions it covers:
//!   the one flagged as covering every function, or else (QEMU's way) the
//!   only unit, covering just the functions its device scopes name (one
//!   on bus 0, or everything behind a bridge there). A function no unit
//!   in use covers cannot be bound, so it never gets DMA unisolated.

use super::vm::phys_ptr;
use crate::kprintln;
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

/// The table with signature `sig`, from the RSDP at `rsdp`: its address
/// and length, if it is there and whole.
fn find(rsdp: u64, sig: &[u8; 4]) -> Option<(u64, u64)> {
    if &read::<8>(rsdp) != b"RSD PTR " || !sums_to_zero(rsdp, 20) {
        return None;
    }
    // ACPI 2.0 and later: the XSDT, with 64-bit entries; else the RSDT.
    let (root, entry) = if read::<1>(rsdp + 15)[0] >= 2 && u64_at(rsdp + 24) != 0 {
        (u64_at(rsdp + 24), 8)
    } else {
        (u32_at(rsdp + 16) as u64, 4)
    };
    let len = u32_at(root + 4) as u64;
    if len < 36 || len > 1 << 16 || !sums_to_zero(root, len) {
        return None;
    }
    (0..(len - 36) / entry).find_map(|i| {
        let at = root + 36 + i * entry;
        let table = if entry == 8 { u64_at(at) } else { u32_at(at) as u64 };
        let tlen = u32_at(table + 4) as u64;
        (&read::<4>(table) == sig && (36..1 << 20).contains(&tlen) && sums_to_zero(table, tlen)).then_some((table, tlen))
    })
}

/// The enabled CPUs' local APIC IDs, in the MADT's order (up to
/// `MAX_CPUS`), and how many CPUs the MADT lists in all (0 without one).
static CPU_APIC: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static CPUS_KEPT: AtomicUsize = AtomicUsize::new(0);
static CPUS_LISTED: AtomicUsize = AtomicUsize::new(0);

/// The base of the VT-d unit in use (0 if none), whether it covers every
/// PCI function, and if not, which functions on bus 0 it covers (a bit
/// per device and function) and whether it covers everything behind a
/// bridge.
static VTD: AtomicU64 = AtomicU64::new(0);
static VTD_ALL: AtomicBool = AtomicBool::new(false);
static VTD_BUS0: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static VTD_BRIDGES: AtomicBool = AtomicBool::new(false);

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
    let (mut listed, mut kept, mut ioapics, mut first_ioapic) = (0, 0, 0, 0);
    // 8 bytes after the header: the local APICs' address and flags.
    for (e, kind, n) in structures(t, len, 8, false) {
        let cpu = match (kind, n) {
            // A processor's local APIC: its UID, APIC ID and flags.
            (0, 8..) => Some((read::<1>(e + 3)[0] as u32, u32_at(e + 4))),
            // The same with an x2APIC ID.
            (9, 16..) => Some((u32_at(e + 4), u32_at(e + 8))),
            // An I/O APIC: its ID, address and first interrupt.
            (1, 12..) => {
                ioapics += 1;
                if first_ioapic == 0 {
                    first_ioapic = u32_at(e + 4) as u64;
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
        "[ok] ACPI: {kept} of {listed} CPUs listed taken, APIC IDs {:?}; {ioapics} I/O APIC{}{}",
        &ids[..kept],
        if ioapics == 1 { "" } else { "s" },
        At(first_ioapic)
    );
}

fn dmar(rsdp: u64) {
    let Some((t, len)) = find(rsdp, b"DMAR") else {
        kprintln!("[ok] ACPI: no DMAR (no VT-d)");
        return;
    };
    let (mut units, mut reserved, mut all, mut scoped) = (0, 0, 0, None);
    // 12 bytes after the header: address width, flags, reserved.
    for (e, kind, n) in structures(t, len, 12, true) {
        match (kind, n) {
            // A remapping unit: flags (bit 0: every PCI function not under
            // another unit), segment, register base, then device scopes.
            (0, 16..) => {
                units += 1;
                let [flags, _, s0, s1] = read::<4>(e + 4);
                if u16::from_le_bytes([s0, s1]) != 0 {
                    continue;
                }
                if flags & 1 != 0 {
                    all = u64_at(e + 8);
                } else if scoped.is_none() {
                    scoped = Some((e, n));
                }
            }
            // A memory range a device keeps using (a USB controller's
            // legacy emulation, a GPU's stolen memory).
            (1, _) => reserved += 1,
            _ => {}
        }
    }
    let mut named = 0;
    if all != 0 {
        VTD.store(all, Ordering::Relaxed);
        VTD_ALL.store(true, Ordering::Relaxed);
    } else if let (1, Some((e, n))) = (units, scoped) {
        VTD.store(u64_at(e + 8), Ordering::Relaxed);
        // Device scopes: type, length, 2 reserved, enumeration ID, start
        // bus, then (device, function) pairs down the bridges from it.
        let mut s = e + 16;
        while s + 8 <= e + n {
            let [kind, sl, _, _, _, bus, dev, func] = read::<8>(s);
            if sl < 8 || s + sl as u64 > e + n {
                break;
            }
            // A function on bus 0 itself (path of one), or a bridge there.
            if bus == 0 && sl == 8 && dev < 32 && func < 8 {
                let devfn = (dev as usize) << 3 | func as usize;
                match kind {
                    1 => {
                        VTD_BUS0[devfn / 64].fetch_or(1 << (devfn % 64), Ordering::Relaxed);
                        named += 1;
                    }
                    2 => {
                        VTD_BUS0[devfn / 64].fetch_or(1 << (devfn % 64), Ordering::Relaxed);
                        VTD_BRIDGES.store(true, Ordering::Relaxed);
                        named += 1;
                    }
                    _ => {}
                }
            }
            s += sl as u64;
        }
    }
    let vtd = VTD.load(Ordering::Relaxed);
    kprintln!(
        "[ok] ACPI: {units} VT-d unit{}; {}{}; {reserved} reserved memory region{}",
        if units == 1 { "" } else { "s" },
        match (vtd, VTD_ALL.load(Ordering::Relaxed)) {
            (0, _) => "none used",
            (_, true) => "one for every PCI function",
            _ => "one for the PCI functions it names",
        },
        At(vtd),
        if reserved == 1 { "" } else { "s" },
    );
    if named > 0 {
        kprintln!(
            "[ok] ACPI: VT-d covers {named} function{} named on bus 0{}",
            if named == 1 { "" } else { "s" },
            if VTD_BRIDGES.load(Ordering::Relaxed) { " and what is behind its bridges" } else { "" }
        );
    }
}

/// Whether the VT-d unit in use covers requester ID `sid` (bus, device,
/// function).
pub fn vtd_covers(sid: u16) -> bool {
    if VTD_ALL.load(Ordering::Relaxed) {
        return true;
    }
    let (bus, devfn) = (sid >> 8, (sid & 0xff) as usize);
    if bus == 0 {
        VTD_BUS0[devfn / 64].load(Ordering::Relaxed) & 1 << (devfn % 64) != 0
    } else {
        VTD_BRIDGES.load(Ordering::Relaxed)
    }
}

/// The enabled CPUs' local APIC IDs from the MADT (up to `MAX_CPUS`), or
/// `None` without a MADT.
pub fn cpus() -> Option<impl Iterator<Item = u32>> {
    (CPUS_LISTED.load(Ordering::Relaxed) > 0)
        .then(|| (0..CPUS_KEPT.load(Ordering::Relaxed)).map(|i| CPU_APIC[i].load(Ordering::Relaxed)))
}

/// The register base of the VT-d unit in use, if the DMAR describes one
/// the kernel can use.
pub fn vtd() -> Option<u64> {
    Some(VTD.load(Ordering::Relaxed)).filter(|&b| b != 0)
}

/// Reads the tables from the RSDP at `rsdp` (if the bootloader found one).
pub fn init(rsdp: Option<u64>) {
    let Some(rsdp) = rsdp else {
        kprintln!("[ok] ACPI: no RSDP");
        return;
    };
    madt(rsdp);
    dmar(rsdp);
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
