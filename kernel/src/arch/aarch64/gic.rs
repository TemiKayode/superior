//! The GICv3 interrupt controller on QEMU's `virt` machine
//! (`gic-version=3`): a distributor for shared interrupts (all routed to
//! CPU 0), each CPU's redistributor for its private ones (CPU 0's for
//! LPIs too), the system-register CPU interface, and an ITS that turns
//! device MSIs into LPIs. CPUs interrupt each other with SGIs.
//!
//! The ITS is what makes MSIs safe to hand to user-space drivers. A
//! device raises an MSI by writing an event ID to the ITS's translation
//! register; the ITS looks the event up in a table of the writing
//! device's own (keyed by its requester ID, which the device cannot
//! choose), and only an event mapped there becomes an interrupt. Each MSI
//! line is mapped for one device at a time ([`route`]); any other write,
//! from any device, raises nothing. GICv2m, which this replaces, raised
//! whichever interrupt ID a device wrote.

use crate::memory;
use superior_objects::abi::PCI_BUSES;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// The distributor, the first CPU's redistributor and the ITS (0 if
/// none), as the firmware says, and the redistributors' stride.
static GICD_BASE: AtomicU64 = AtomicU64::new(0);
static GICR_BASE: AtomicU64 = AtomicU64::new(0);
static GITS_BASE: AtomicU64 = AtomicU64::new(0);
static STRIDE: AtomicU64 = AtomicU64::new(0x2_0000);
/// Where the GIC is: before [`init`].
pub(super) fn set_bases(gicd: u64, gicr: u64, its: Option<u64>) {
    GICD_BASE.store(gicd, Ordering::Relaxed);
    GICR_BASE.store(gicr, Ordering::Relaxed);
    GITS_BASE.store(its.unwrap_or(0), Ordering::Relaxed);
}

fn gicd() -> u64 {
    GICD_BASE.load(Ordering::Relaxed)
}

/// CPU 0's redistributor: its control frame, then its SGI/PPI frame (and,
/// on a GICv4, two more). The next CPU's follows.
fn gicr0() -> u64 {
    GICR_BASE.load(Ordering::Relaxed)
}

fn gits() -> u64 {
    GITS_BASE.load(Ordering::Relaxed)
}
/// The SGIs CPUs send each other: a kick, and a shootdown request.
pub const KICK_SGI: u32 = 1;
pub const SHOOTDOWN_SGI: u32 = 2;

/// CPU `cpu`'s redistributor control frame and SGI/PPI frame.
fn gicr(cpu: usize) -> u64 {
    gicr0() + cpu as u64 * STRIDE.load(Ordering::Relaxed)
}

fn sgi(cpu: usize) -> u64 {
    gicr(cpu) + 0x1_0000
}

const GICD_CTLR: u64 = 0x000;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ICFGR: u64 = 0xc00;
const GICD_IROUTER: u64 = 0x6000;
/// Single security state (the machine has none): affinity routing,
/// group 0 and group 1 enabled; and the register-write-pending bit.
const GICD_CTLR_ARE: u32 = 1 << 4;
const GICD_CTLR_GRP1: u32 = 1 << 1;
const CTLR_RWP: u32 = 1 << 31;

const GICR_CTLR: u64 = 0x00;
const GICR_TYPER: u64 = 0x08;
const GICR_WAKER: u64 = 0x14;
const GICR_PROPBASER: u64 = 0x70;
const GICR_PENDBASER: u64 = 0x78;
/// GICR_CTLR's register-write-pending bit.
const GICR_RWP: u32 = 1 << 3;
const WAKER_SLEEP: u32 = 1 << 1;
const WAKER_ASLEEP: u32 = 1 << 2;

const GITS_CTLR: u64 = 0x00;
const GITS_TYPER: u64 = 0x08;
const GITS_CBASER: u64 = 0x80;
const GITS_CWRITER: u64 = 0x88;
const GITS_CREADR: u64 = 0x90;
const GITS_BASER: u64 = 0x100;
const GITS_QUIESCENT: u32 = 1 << 31;
/// The register devices write event IDs to.
/// The ITS's translation register, which devices write MSIs to.
fn translater() -> u64 {
    gits() + 0x1_0040
}

/// Table and queue attributes: valid, inner write-back cacheable,
/// inner-shareable.
const VALID: u64 = 1 << 63;
const INNER_WB: u64 = 0b111 << 59;
const RD_INNER_WB: u64 = 0b111 << 7;
const SHAREABLE: u64 = 0b01 << 10;

const CMD_SYNC: u64 = 0x05;
const CMD_MAPD: u64 = 0x08;
const CMD_MAPC: u64 = 0x09;
const CMD_MAPTI: u64 = 0x0a;
const CMD_INVALL: u64 = 0x0d;
const CMD_DISCARD: u64 = 0x0f;

/// Interrupt IDs of 1020 to 1023 are special (1023: spurious).
const FIRST_SPECIAL: u32 = 1020;
/// SPIs the kernel manages (it keeps lines as `u8`).
const MAX_SPI: u32 = 256;
/// The first LPI. LPI `FIRST_LPI + n` is MSI line `MSI_LINE_BASE + n`.
const FIRST_LPI: u32 = 8192;
/// LPI ID bits: 14, the fewest that reach past 8192.
const LPI_ID_BITS: u64 = 14;
/// MSI lines: kernel line numbers for LPIs, clear of the SPIs in use.
pub const MSI_LINE_BASE: u8 = 64;
pub const MSI_COUNT: u8 = 8;
/// Event IDs per device: one per MSI line, so 3 bits.
const EVENT_BITS: u64 = 3;
/// Devices with an interrupt translation table at once.
const MAX_DEVICES: usize = 32;
/// Device IDs the ITS's device table holds (one page of entries).
static MAX_DEVICE_ID: AtomicU64 = AtomicU64::new(0);

/// The ITS's command queue (0 if there is no ITS) and the LPI
/// configuration table.
static CMDQ: AtomicU64 = AtomicU64::new(0);
static PROP: AtomicU64 = AtomicU64::new(0);
/// The value for a command's RDbase field: CPU 0's redistributor.
static RDBASE: AtomicU64 = AtomicU64::new(0);

/// Who may raise each MSI line, and each device's translation table.
struct Routes {
    line: [Option<u16>; MSI_COUNT as usize],
    /// (device ID, table address, mapped in the ITS).
    devices: [Option<(u16, u64, bool)>; MAX_DEVICES],
    cmd_tail: u64,
}

static ROUTES: Mutex<Routes> = Mutex::new(Routes {
    line: [None; MSI_COUNT as usize],
    devices: [None; MAX_DEVICES],
    cmd_tail: 0,
});

fn write32(addr: u64, v: u32) {
    // SAFETY: GIC registers, identity-mapped as device memory.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}

fn read32(addr: u64) -> u32 {
    // SAFETY: as in `write32`.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn write64(addr: u64, v: u64) {
    // SAFETY: as in `write32`.
    unsafe { core::ptr::write_volatile(addr as *mut u64, v) }
}

fn read64(addr: u64) -> u64 {
    // SAFETY: as in `write32`.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

fn write8(addr: u64, v: u8) {
    // SAFETY: as in `write32`; priority registers are byte-accessible.
    unsafe { core::ptr::write_volatile(addr as *mut u8, v) }
}

fn wait_rwp(ctlr: u64) {
    while read32(ctlr) & CTLR_RWP != 0 {
        core::hint::spin_loop();
    }
}

fn zero(pa: u64, bytes: u64) {
    // SAFETY: freshly carved RAM, identity-mapped.
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, bytes as usize) };
}

fn dsb() {
    // SAFETY: a barrier.
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

pub fn init() {
    // GICv4 redistributors have four 64 KiB frames, not two (VLPIS).
    if read64(gicr0() + GICR_TYPER) & 2 != 0 {
        STRIDE.store(0x4_0000, Ordering::Relaxed);
    }
    // Distributor: off while shared interrupts are set up, all group 1,
    // all disabled, routed to CPU 0.
    write32(gicd() + GICD_CTLR, 0);
    wait_rwp(gicd() + GICD_CTLR);
    for id in (32..MAX_SPI).step_by(32) {
        write32(gicd() + GICD_ICENABLER + id as u64 / 8, !0);
        write32(gicd() + GICD_IGROUPR + id as u64 / 8, !0);
    }
    for id in 32..MAX_SPI {
        write8(gicd() + GICD_IPRIORITYR + id as u64, 0x80);
        write64(gicd() + GICD_IROUTER + 8 * id as u64, 0);
    }
    write32(gicd() + GICD_CTLR, GICD_CTLR_ARE | GICD_CTLR_GRP1);
    wait_rwp(gicd() + GICD_CTLR);
    init_cpu(0);
    init_its();
}

/// This CPU's redistributor and CPU interface: private interrupts group 1
/// and disabled but for the SGIs from other CPUs.
pub fn init_cpu(cpu: usize) {
    let (rd, sgi) = (gicr(cpu), sgi(cpu));
    write32(rd + GICR_WAKER, read32(rd + GICR_WAKER) & !WAKER_SLEEP);
    while read32(rd + GICR_WAKER) & WAKER_ASLEEP != 0 {
        core::hint::spin_loop();
    }
    write32(sgi + GICD_ICENABLER, !0);
    write32(sgi + GICD_IGROUPR, !0);
    for id in 0..32 {
        write8(sgi + GICD_IPRIORITYR + id, 0x80);
    }
    write32(sgi + GICD_ISENABLER, 1 << KICK_SGI | 1 << SHOOTDOWN_SGI);
    while read32(rd + GICR_CTLR) & GICR_RWP != 0 {
        core::hint::spin_loop();
    }

    // CPU interface, through system registers: every priority unmasked,
    // group 1 on.
    // SAFETY: ICC_SRE_EL1, ICC_PMR_EL1 and ICC_IGRPEN1_EL1, at EL1.
    unsafe {
        core::arch::asm!(
            "mrs {t}, S3_0_C12_C12_5",
            "orr {t}, {t}, #1",
            "msr S3_0_C12_C12_5, {t}",
            "isb",
            "mov {t}, #0xff",
            "msr S3_0_C4_C6_0, {t}",
            "mov {t}, #1",
            "msr S3_0_C12_C12_7, {t}",
            "isb",
            t = out(reg) _,
            options(nostack)
        )
    };
}

/// Sends SGI `id` to CPU `cpu` (affinity 0 = `cpu`, the rest 0).
pub fn send_sgi(cpu: usize, id: u32) {
    let v = (id as u64) << 24 | 1 << cpu;
    // SAFETY: writing ICC_SGI1R_EL1 raises the SGI at the target.
    unsafe {
        core::arch::asm!("dsb ish", "msr S3_0_C12_C11_5, {}", "isb", in(reg) v, options(nostack))
    };
}

/// LPIs and the ITS, if the machine has one; without, MSI lines raise
/// nothing.
fn init_its() {
    if gits() == 0 {
        return; // the firmware lists none
    }
    let typer = read64(gits() + GITS_TYPER);
    if typer == 0 || typer == u64::MAX || read64(gicr0() + GICR_TYPER) & 1 == 0 {
        return; // no ITS, or the redistributor has no LPIs
    }
    let (Some(prop), Some(pend), Some(cmdq)) = (
        memory::carve(LPI_ID_BITS as u8 - 1), // one byte per LPI: 8 KiB
        memory::carve(16),                    // 64 KiB-aligned pending bits
        memory::carve(12),
    ) else {
        return;
    };
    // Every MSI LPI enabled at priority 0xa0: an LPI is a message, raised
    // only by the device its line is routed to, so there is no level to
    // mask while a driver handles it.
    zero(prop, 1 << (LPI_ID_BITS - 1));
    for n in 0..MSI_COUNT as u64 {
        // SAFETY: inside the table just carved.
        unsafe { ((prop + n) as *mut u8).write_volatile(0xa0 | 1) };
    }
    zero(pend, 1 << 16);
    zero(cmdq, 4096);
    dsb();
    write64(
        gicr0() + GICR_PROPBASER,
        prop | RD_INNER_WB | SHAREABLE | (LPI_ID_BITS - 1),
    );
    write64(gicr0() + GICR_PENDBASER, pend | RD_INNER_WB | SHAREABLE | 1 << 62);
    write32(gicr0() + GICR_CTLR, read32(gicr0() + GICR_CTLR) | 1);

    // The ITS: off while its tables are set up.
    write32(gits() + GITS_CTLR, 0);
    while read32(gits() + GITS_CTLR) & GITS_QUIESCENT == 0 {
        core::hint::spin_loop();
    }
    for n in 0..8 {
        let reg = gits() + GITS_BASER + 8 * n;
        let baser = read64(reg);
        let kind = (baser >> 56) & 7;
        if kind == 0 {
            continue;
        }
        // Flat tables of 4 KiB pages: one page, but for the device
        // table (kind 1) enough for every function of `PCI_BUSES` buses.
        let entry = ((baser >> 48) & 0x1f) + 1;
        let bits = if kind == 1 {
            (((PCI_BUSES << 8) * entry).next_power_of_two().trailing_zeros() as u8).max(12)
        } else {
            12
        };
        let Some(table) = memory::carve(bits) else { return };
        zero(table, 1 << bits);
        let pages = (1u64 << bits) / 4096;
        write64(
            reg,
            VALID | INNER_WB | (baser & (0x1f << 48)) | kind << 56 | table | SHAREABLE | (pages - 1),
        );
        if kind == 1 {
            MAX_DEVICE_ID.store((1 << bits) / entry, Ordering::Relaxed);
        }
    }
    // Physical target addresses, or processor numbers.
    let rdbase = if typer & 1 << 19 != 0 { gicr0() } else { 0 };
    RDBASE.store(rdbase, Ordering::Relaxed);
    write64(gits() + GITS_CBASER, VALID | INNER_WB | SHAREABLE | cmdq);
    write64(gits() + GITS_CWRITER, 0);
    write32(gits() + GITS_CTLR, 1);
    PROP.store(prop, Ordering::Relaxed);
    CMDQ.store(cmdq, Ordering::Relaxed);
    let mut routes = ROUTES.lock();
    command(&mut routes, &[[CMD_MAPC, 0, VALID | rdbase, 0]]);
    command(&mut routes, &[[CMD_INVALL, 0, 0, 0]]);
}

/// Queues ITS commands and a SYNC, and waits until the ITS has carried
/// them out.
fn command(routes: &mut Routes, cmds: &[[u64; 4]]) {
    let q = CMDQ.load(Ordering::Relaxed);
    let sync = [CMD_SYNC, 0, RDBASE.load(Ordering::Relaxed), 0];
    for c in cmds.iter().chain(core::iter::once(&sync)) {
        let at = q + routes.cmd_tail;
        for (i, w) in c.iter().enumerate() {
            // SAFETY: a slot of our one-page queue the ITS has consumed:
            // each batch is waited for before the next.
            unsafe { ((at + 8 * i as u64) as *mut u64).write_volatile(*w) };
        }
        routes.cmd_tail = (routes.cmd_tail + 32) % 4096;
    }
    dsb();
    write64(gits() + GITS_CWRITER, routes.cmd_tail);
    loop {
        let read = read64(gits() + GITS_CREADR);
        if read & 1 != 0 {
            panic!("the ITS stalled on a command at {:#x}", read & !0x1f);
        }
        if read == routes.cmd_tail {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Whether device IDs and MSI lines can be routed.
pub fn its_present() -> bool {
    CMDQ.load(Ordering::Relaxed) != 0
}

/// Maps MSI line `line` (a kernel line number) for device `source` alone,
/// or for no device, and returns the message (address, data) that raises
/// it. `None` if it is not an MSI line, or there is no ITS.
pub fn route(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    if !(MSI_LINE_BASE..MSI_LINE_BASE + MSI_COUNT).contains(&line) || !its_present() {
        return None;
    }
    let event = (line - MSI_LINE_BASE) as u64;
    let lpi = FIRST_LPI as u64 + event;
    let mut routes = ROUTES.lock();
    let mut cmds = [[0u64; 4]; 3];
    let mut n = 0;
    if let Some(old) = routes.line[event as usize].take() {
        cmds[n] = [CMD_DISCARD | (old as u64) << 32, event, 0, 0];
        n += 1;
    }
    if let Some(dev) = source {
        if dev as u64 >= MAX_DEVICE_ID.load(Ordering::Relaxed) {
            command(&mut routes, &cmds[..n]);
            return None;
        }
        let slot = match routes.devices.iter().position(|d| matches!(d, Some((id, ..)) if *id == dev)) {
            Some(s) => s,
            None => {
                let s = routes.devices.iter().position(Option::is_none)?;
                let itt = memory::carve(12)?;
                zero(itt, 4096);
                routes.devices[s] = Some((dev, itt, false));
                s
            }
        };
        let (_, itt, mapped) = routes.devices[slot].unwrap();
        if !mapped {
            cmds[n] = [CMD_MAPD | (dev as u64) << 32, EVENT_BITS - 1, VALID | itt, 0];
            n += 1;
            routes.devices[slot] = Some((dev, itt, true));
        }
        cmds[n] = [CMD_MAPTI | (dev as u64) << 32, event | lpi << 32, 0, 0];
        n += 1;
        routes.line[event as usize] = Some(dev);
    }
    command(&mut routes, &cmds[..n]);
    Some((translater(), event))
}

/// Unmaps device `dev` from the ITS: none of its writes raise anything.
pub fn unroute(dev: u16) {
    if !its_present() {
        return;
    }
    let mut routes = ROUTES.lock();
    let mut any = false;
    for l in routes.line.iter_mut() {
        if *l == Some(dev) {
            *l = None;
        }
    }
    for d in routes.devices.iter_mut() {
        if let Some((id, itt, true)) = *d {
            if id == dev {
                *d = Some((id, itt, false));
                any = true;
            }
        }
    }
    if any {
        command(&mut routes, &[[CMD_MAPD | (dev as u64) << 32, 0, 0, 0]]);
    }
}

/// The kernel line for interrupt ID `id`.
pub fn line_of(id: u32) -> u32 {
    if id >= FIRST_LPI {
        MSI_LINE_BASE as u32 + (id - FIRST_LPI)
    } else {
        id
    }
}

/// Turns on shared interrupt `id` (an SPI) for the kernel itself, edge
/// triggered: one a device pulses rather than holds (the SMMU's).
pub fn enable_edge_spi(id: u32) {
    if !(32..MAX_SPI).contains(&id) {
        return;
    }
    let reg = gicd() + GICD_ICFGR + 4 * (id / 16) as u64;
    write32(reg, read32(reg) | 2 << (2 * (id % 16)));
    write32(gicd() + GICD_ISENABLER + 4 * (id / 32) as u64, 1 << (id % 32));
}

pub fn unmask(line: u32) {
    match line {
        0..32 => write32(sgi(super::cpu_id()) + GICD_ISENABLER, 1 << line),
        l if is_msi(l) => {} // LPIs stay enabled
        l if l < MAX_SPI => write32(gicd() + GICD_ISENABLER + 4 * (l / 32) as u64, 1 << (l % 32)),
        _ => {}
    }
}

pub fn mask(line: u32) {
    match line {
        0..32 => write32(sgi(super::cpu_id()) + GICD_ICENABLER, 1 << line),
        l if is_msi(l) => {}
        l if l < MAX_SPI => write32(gicd() + GICD_ICENABLER + 4 * (l / 32) as u64, 1 << (l % 32)),
        _ => {}
    }
}

fn is_msi(line: u32) -> bool {
    (MSI_LINE_BASE as u32..(MSI_LINE_BASE + MSI_COUNT) as u32).contains(&line)
}

/// Acknowledges the highest-priority pending interrupt: its ID (for
/// [`end_of_interrupt`]), or `None` if spurious.
pub fn acknowledge() -> Option<u32> {
    let id: u64;
    // SAFETY: reading ICC_IAR1_EL1 acknowledges the interrupt.
    unsafe { core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) id, options(nostack)) };
    let id = id as u32 & 0xff_ffff;
    (!(FIRST_SPECIAL..FIRST_LPI).contains(&id)).then_some(id)
}

pub fn end_of_interrupt(id: u32) {
    // SAFETY: writing ICC_EOIR1_EL1 drops priority and deactivates `id`.
    unsafe { core::arch::asm!("msr S3_0_C12_C12_1, {}", "isb", in(reg) id as u64, options(nostack)) };
}

/// The page holding the translation register, which every device's I/O
/// address space maps so its MSI writes get through the SMMU (none
/// without an ITS).
pub fn msi_doorbell() -> Option<u64> {
    (gits() != 0).then(translater)
}
