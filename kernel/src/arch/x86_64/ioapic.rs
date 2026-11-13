//! The I/O APICs, which carry the interrupts of devices with no MSI (ISA's
//! serial port, PCI's legacy pins) to the local APICs: one redirection
//! entry per GSI, each the vector, trigger mode, polarity and destination
//! of its input. Where they are and which GSIs each has come from ACPI's
//! MADT ([`super::acpi::ioapics`]).
//!
//! Every entry starts masked. An entry is written whole when its line is
//! unmasked: sent to the boot CPU's local APIC (physical destination);
//! or, where VT-d remaps interrupts, as a remappable-format interrupt that
//! names an entry of the remapping table, which only this I/O APIC's
//! requester ID may raise (the compatibility format is blocked there).

use super::{acpi, iommu, vm};
use crate::kprintln;
use spin::Mutex;
use x86_64::PhysAddr;

#[derive(Clone, Copy)]
struct Chip {
    /// Where its registers are mapped.
    regs: usize,
    id: u32,
    first: u32,
    count: u32,
}

static CHIPS: Mutex<[Option<Chip>; 4]> = Mutex::new([None; 4]);

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const VERSION: u32 = 0x01;
const MASKED: u32 = 1 << 16;
const LEVEL: u32 = 1 << 15;
const ACTIVE_LOW: u32 = 1 << 13;

fn read(c: &Chip, reg: u32) -> u32 {
    // SAFETY: `regs` maps the chip's register page (in `init`); the
    // select-then-access pair runs under CHIPS's lock.
    unsafe {
        core::ptr::write_volatile((c.regs + IOREGSEL) as *mut u32, reg);
        core::ptr::read_volatile((c.regs + IOWIN) as *const u32)
    }
}

fn write(c: &Chip, reg: u32, value: u32) {
    // SAFETY: as in `read`.
    unsafe {
        core::ptr::write_volatile((c.regs + IOREGSEL) as *mut u32, reg);
        core::ptr::write_volatile((c.regs + IOWIN) as *mut u32, value);
    }
}

/// Maps every I/O APIC the MADT lists and masks all their entries.
/// Returns whether there is any.
pub fn init() -> bool {
    let mut chips = CHIPS.lock();
    let mut n = 0;
    for (id, base, first) in acpi::ioapics() {
        let Ok(va) = vm::map_mmio(PhysAddr::new(base)) else { continue };
        let mut c = Chip { regs: va.as_u64() as usize, id, first, count: 0 };
        // VERSION: the highest entry's number in bits 16-23.
        c.count = (read(&c, VERSION) >> 16 & 0xff) + 1;
        for pin in 0..c.count {
            write(&c, 0x10 + 2 * pin, MASKED);
            write(&c, 0x11 + 2 * pin, 0);
        }
        kprintln!(
            "[ok] I/O APIC {id} at {base:#x}: GSIs {} to {}",
            first,
            first + c.count - 1
        );
        if let Some(slot) = chips.get_mut(n) {
            *slot = Some(c);
            n += 1;
        }
    }
    n > 0
}

/// The chip with `gsi`, and the GSI's entry number there.
fn find(chips: &[Option<Chip>; 4], gsi: u32) -> Option<(Chip, u32)> {
    chips
        .iter()
        .flatten()
        .find(|c| (c.first..c.first + c.count).contains(&gsi))
        .map(|c| (*c, gsi - c.first))
}

/// Whether some I/O APIC has `gsi`.
pub fn has(gsi: u32) -> bool {
    find(&CHIPS.lock(), gsi).is_some()
}

/// Masks `gsi`'s entry.
pub fn mask(gsi: u32) {
    let chips = CHIPS.lock();
    if let Some((c, pin)) = find(&chips, gsi) {
        let low = read(&c, 0x10 + 2 * pin);
        write(&c, 0x10 + 2 * pin, low | MASKED);
    }
}

/// Writes `gsi`'s entry, unmasked: `vector` at the boot CPU, with the
/// trigger mode and polarity given. Where interrupts are remapped, through
/// remapping table entry `index`.
pub fn unmask(gsi: u32, vector: u8, level: bool, active_low: bool, index: u16) {
    let chips = CHIPS.lock();
    let Some((c, pin)) = find(&chips, gsi) else { return };
    let mut low = vector as u32;
    if level {
        low |= LEVEL;
    }
    if active_low {
        low |= ACTIVE_LOW;
    }
    let high = if iommu::remapping() {
        iommu::route_line(index, vector, level, acpi::ioapic_sid(c.id));
        // Remappable format: bit 48 set, the entry's index in bits 49-63
        // and bit 11. The vector stays, for the EOI the local APIC sends.
        low |= (index as u32 >> 15 & 1) << 11;
        1 << 16 | (index as u32 & 0x7fff) << 17
    } else {
        (super::boot_apic() & 0xff) << 24
    };
    write(&c, 0x10 + 2 * pin, low | MASKED);
    write(&c, 0x11 + 2 * pin, high);
    write(&c, 0x10 + 2 * pin, low);
}
