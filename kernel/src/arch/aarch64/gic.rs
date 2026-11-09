//! The GICv2 interrupt controller on QEMU's `virt` machine: a distributor
//! routing interrupts to the one CPU, and that CPU's interface.

const GICD: u64 = 0x0800_0000;
const GICC: u64 = 0x0801_0000;

const GICD_CTLR: u64 = 0x000;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;
/// The GICv2m MSI frame: a device raises SPI `n` by writing `n` to
/// `SETSPI_NS`. `TYPER` says which SPIs are the frame's.
const V2M: u64 = 0x0802_0000;
const V2M_TYPER: u64 = 0x008;
const V2M_SETSPI_NS: u64 = 0x040;
const GICC_CTLR: u64 = 0x000;
const GICC_PMR: u64 = 0x004;
const GICC_IAR: u64 = 0x00c;
const GICC_EOIR: u64 = 0x010;

/// Interrupt IDs of 1020 and up are special (1023: spurious).
const FIRST_SPECIAL: u32 = 1020;
/// Interrupts the kernel may enable: PPIs and the first SPIs.
/// Interrupt IDs the kernel manages (it keeps lines as `u8`).
const MAX_ID: u32 = 256;

fn write32(addr: u64, v: u32) {
    // SAFETY: GIC registers, identity-mapped as device memory.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}

fn read32(addr: u64) -> u32 {
    // SAFETY: as in `write32`.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn write8(addr: u64, v: u8) {
    // SAFETY: as in `write32`; priority and target registers are
    // byte-accessible.
    unsafe { core::ptr::write_volatile(addr as *mut u8, v) }
}

pub fn init() {
    write32(GICD + GICD_CTLR, 0);
    for id in 0..MAX_ID {
        write32(GICD + GICD_ICENABLER + 4 * (id / 32) as u64, 1 << (id % 32));
        write8(GICD + GICD_IPRIORITYR + id as u64, 0x80);
        if id >= 32 {
            // Shared interrupts go to CPU 0.
            write8(GICD + GICD_ITARGETSR + id as u64, 1);
        }
    }
    // MSIs are edges: a write, not a level held up.
    let (first, count) = msi_spis();
    for id in first..first + count {
        let reg = GICD + GICD_ICFGR + 4 * (id / 16) as u64;
        write32(reg, read32(reg) | 2 << (2 * (id % 16)));
    }
    write32(GICD + GICD_CTLR, 1);
    write32(GICC + GICC_PMR, 0xff);
    write32(GICC + GICC_CTLR, 1);
}

pub fn unmask(id: u32) {
    if id < MAX_ID {
        write32(GICD + GICD_ISENABLER + 4 * (id / 32) as u64, 1 << (id % 32));
    }
}

pub fn mask(id: u32) {
    if id < MAX_ID {
        write32(GICD + GICD_ICENABLER + 4 * (id / 32) as u64, 1 << (id % 32));
    }
}

/// Acknowledges the highest-priority pending interrupt: its raw IAR value
/// (for [`end_of_interrupt`]) and ID, or `None` if spurious.
pub fn acknowledge() -> Option<(u32, u32)> {
    let iar = read32(GICC + GICC_IAR);
    let id = iar & 0x3ff;
    (id < FIRST_SPECIAL).then_some((iar, id))
}

pub fn end_of_interrupt(iar: u32) {
    write32(GICC + GICC_EOIR, iar);
}

/// The interrupt IDs the GICv2m frame raises, as (first, count), clipped
/// to the IDs the kernel manages.
pub fn msi_spis() -> (u32, u32) {
    let typer = read32(V2M + V2M_TYPER);
    let first = (typer >> 16) & 0x3ff;
    let count = typer & 0x3ff;
    let count = count.min(MAX_ID.saturating_sub(first));
    (first, count)
}

/// The doorbell a device writes an MSI's interrupt ID to.
pub const MSI_DOORBELL: u64 = V2M + V2M_SETSPI_NS;
