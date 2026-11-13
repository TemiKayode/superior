//! ACPI tables, as the firmware leaves them: found from the RSDP the
//! bootloader passes, read through the kernel's map of physical memory.
//!
//! Only what the kernel needs so far: the MCFG table's PCI Express
//! configuration space (ECAM), so that the window PCI BARs are assigned
//! from stays clear of it. Firmware put it in different places: SeaBIOS
//! at 0xb000_0000 on QEMU's q35, OVMF (UEFI) at 0xe000_0000; QEMU's `pc`
//! machine has none.

use super::vm::phys_ptr;
use crate::kprintln;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Reads the tables from the RSDP at `rsdp` (if the bootloader found one).
pub fn init(rsdp: Option<u64>) {
    let Some(rsdp) = rsdp else {
        kprintln!("[ok] ACPI: no RSDP");
        return;
    };
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
