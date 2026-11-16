//! Intel VT-d (DMA remapping), as QEMU's `intel-iommu` emulates it on the
//! q35 machine and laptops have it: every remapping unit ACPI's DMAR table
//! lists (up to four), each covering the PCI functions it names, or every
//! function no other unit names. A laptop has two: one for its integrated
//! graphics alone, and one for everything else; QEMU has one. Each unit
//! the kernel can drive gets register-based or queued invalidation,
//! legacy-mode root and context tables, and 3-level second-level page
//! tables (39-bit I/O addresses). A function goes through exactly one
//! unit ([`super::acpi::vtd_unit`]), and its context entry is in that
//! unit's tables.
//!
//! Once translation is on, a function with no context entry can reach no
//! memory at all; one bound to an I/O address space reaches only what is
//! mapped in it. A function under a unit the kernel cannot drive cannot be
//! bound at all (the bus server then keeps it from mastering the bus).
//!
//! Interrupts are remapped too (when every unit can): an MSI is a DMA
//! write like any other, and without remapping a device could write any
//! vector to the local APIC. Each MSI vector has an entry in the interrupt
//! remapping table of the unit its device is under, naming the one
//! requester ID allowed to raise it ([`route`]); the same entry in every
//! other unit's table is empty. A message in the old compatibility format,
//! or for an entry naming another device (or none), is blocked.
//! Invalidation then goes through the invalidation queue, since the
//! interrupt entry cache has no register to flush it.
//!
//! Blocked requests are logged in each unit's fault recording registers,
//! and the units' fault event interrupts (a message to CPU 0's local APIC
//! on [`super::apic::IOMMU_VECTOR`], never itself remapped) have the
//! kernel drain them at once ([`take_faults`]); the timer tick drains them
//! too. A record freed while others are pending raises the event again.

use super::acpi::{self, MAX_UNITS};
use super::vm;
use crate::iommu::IoFault;
use crate::kprintln;
use crate::memory;
use superior_objects::abi::PCI_BUSES;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::PhysAddr;

const VER: u64 = 0x00;
const CAP: u64 = 0x08;
const ECAP: u64 = 0x10;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1c;
const RTADDR: u64 = 0x20;
const CCMD: u64 = 0x28;
const FSTS: u64 = 0x34;
const FECTL: u64 = 0x38;
const FEDATA: u64 = 0x3c;
const FEADDR: u64 = 0x40;
const FEUADDR: u64 = 0x44;
const IQH: u64 = 0x80;
const IQT: u64 = 0x88;
const IQA: u64 = 0x90;
const IRTA: u64 = 0xb8;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_QIE: u32 = 1 << 26;
const GCMD_IRE: u32 = 1 << 25;
const GCMD_SIRTP: u32 = 1 << 24;
const ECAP_QI: u64 = 1 << 1;
const ECAP_IR: u64 = 1 << 3;
/// FSTS: invalidation queue error.
const FSTS_IQE: u32 = 1 << 4;
/// Invalidation descriptors: context cache, IOTLB and interrupt entry
/// cache (each global), and an invalidation wait that writes a status
/// word once everything before it is done.
const INV_CONTEXT_GLOBAL: u64 = 1 | 1 << 4;
const INV_IOTLB_GLOBAL: u64 = 2 | 1 << 4 | 1 << 6 | 1 << 7;
const INV_IEC_GLOBAL: u64 = 4;
const INV_WAIT_STATUS: u64 = 5 | 1 << 5 | 1 << 32;
/// Queue entries (one page of 16-byte descriptors).
const QUEUE_LEN: u64 = 256;
/// The interrupt remapping table's size field: 2^(7+1) = 256 entries, one
/// page.
const IRT_SIZE: u64 = 7;
/// GSTS bits that are persistent settings, not one-shot commands.
const GSTS_PERSISTENT: u32 = 0x96ff_ffff;
const CCMD_ICC: u64 = 1 << 63;
const CCMD_GLOBAL: u64 = 1 << 61;
const IOTLB_IVT: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_DRAIN: u64 = (1 << 49) | (1 << 48);
/// CAP.SAGAW bit for 3-level (39-bit) tables, and the context entry's
/// matching address width.
const SAGAW_39: u64 = 1 << 9;
const AW_39: u64 = 1;
/// FSTS: primary fault overflow (write 1 to clear).
const FSTS_PFO: u32 = 1;
/// A fault recording register's high half: valid (write 1 to clear), and
/// the request was a read.
const FRCD_F: u64 = 1 << 63;
const FRCD_READ: u64 = 1 << 62;

const NONE: AtomicU64 = AtomicU64::new(0);
/// Each unit's registers' kernel virtual address (0 if the kernel does not
/// drive it), and its root table's physical address.
static REGS: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
static ROOT: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
/// Each unit's invalidation queue page, its next free index, and a page
/// whose first word invalidation waits write (0 while the queue is off).
static QUEUE: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
static QUEUE_TAIL: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
static QUEUE_STATUS: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
/// Each unit's interrupt remapping table (0 if interrupts are not
/// remapped).
static IRT: [AtomicU64; MAX_UNITS] = [NONE; MAX_UNITS];
/// Whether interrupts are remapped (by every unit the kernel drives).
static REMAPPING: AtomicBool = AtomicBool::new(false);

fn r32(u: usize, off: u64) -> u32 {
    // SAFETY: the unit's register page is mapped (uncached) by `init`.
    unsafe { ((REGS[u].load(Ordering::Relaxed) + off) as *const u32).read_volatile() }
}

fn w32(u: usize, off: u64, v: u32) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS[u].load(Ordering::Relaxed) + off) as *mut u32).write_volatile(v) }
}

fn r64(u: usize, off: u64) -> u64 {
    // SAFETY: as in `r32`.
    unsafe { ((REGS[u].load(Ordering::Relaxed) + off) as *const u64).read_volatile() }
}

fn w64(u: usize, off: u64, v: u64) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS[u].load(Ordering::Relaxed) + off) as *mut u64).write_volatile(v) }
}

/// The units the kernel drives.
fn units() -> impl Iterator<Item = usize> {
    (0..MAX_UNITS).filter(|&u| REGS[u].load(Ordering::Relaxed) != 0)
}

/// The unit the kernel drives that requester `sid` goes through.
fn unit_of(sid: u16) -> Option<usize> {
    acpi::vtd_unit(sid).filter(|&u| REGS[u].load(Ordering::Relaxed) != 0)
}

/// Issues a one-shot or persistent global command to unit `u` and waits
/// for its status bit.
fn command(u: usize, bit: u32) {
    let persistent = r32(u, GSTS) & GSTS_PERSISTENT;
    w32(u, GCMD, persistent | bit);
    while r32(u, GSTS) & bit == 0 {
        core::hint::spin_loop();
    }
}

fn iotlb_reg(u: usize) -> u64 {
    ((r64(u, ECAP) >> 8) & 0x3ff) * 16 + 8
}

/// Finds the units, and turns on every one the kernel can drive, with
/// nothing mapped for anyone. Returns a description, or `None` if the
/// machine has no unit the kernel can drive.
pub fn init() -> Option<&'static str> {
    // First which units answer as VT-d does, with tables the kernel makes.
    let mut remap = true;
    for (u, base) in acpi::vtd_units() {
        let Ok(va) = vm::map_mmio(PhysAddr::new(base)) else { continue };
        REGS[u].store(va.as_u64(), Ordering::Relaxed);
        let (ver, cap) = (r32(u, VER), r64(u, CAP));
        // Version 1.0 and up (the register reads all ones, or nothing,
        // where there is no unit).
        if ver == u32::MAX || ver >> 4 == 0 || cap == u64::MAX || cap & SAGAW_39 == 0 {
            REGS[u].store(0, Ordering::Relaxed);
            kprintln!(
                "[warn] IOMMU: the VT-d unit at {base:#x} cannot be driven (version {ver:#x}, capabilities {cap:#x}): no function under it can be bound"
            );
            continue;
        }
        let ecap = r64(u, ECAP);
        remap &= ecap & ECAP_QI != 0 && ecap & ECAP_IR != 0;
    }
    if units().next().is_none() {
        return None;
    }
    for u in units() {
        start(u, remap)?;
    }
    REMAPPING.store(remap, Ordering::Relaxed);
    Some(if remap {
        "Intel VT-d, interrupt remapping"
    } else {
        "Intel VT-d"
    })
}

/// Turns on unit `u`: its root table (every bus's entry not present, so
/// it blocks everything until a function is bound), invalidation queue,
/// fault events, interrupt remapping (if `remap`), then translation.
fn start(u: usize, remap: bool) -> Option<()> {
    // A bus's context table is made when a function on it is first bound
    // (`context_entry`).
    let root = memory::carve(12)?;
    vm::zero_frame(root);
    ROOT[u].store(root, Ordering::Relaxed);
    w64(u, RTADDR, root);
    command(u, GCMD_SRTP);
    if r64(u, ECAP) & ECAP_QI != 0 {
        start_queue(u)?;
    }
    flush_context(u);
    flush_unit(u);
    // Fault events: a fixed-delivery message to CPU 0 (physical
    // destination), then unmasked.
    w32(u, FEDATA, super::apic::IOMMU_VECTOR as u32);
    w32(u, FEADDR, 0xfee0_0000 | (super::apic::id() as u32) << 12);
    w32(u, FEUADDR, 0);
    w32(u, FECTL, 0);
    if remap {
        // Every entry starts not present: no device raises anything until
        // a vector is routed to it. Compatibility-format MSIs stay
        // blocked (GCMD.CFI clear).
        let irt = memory::carve(12)?;
        vm::zero_frame(irt);
        w64(u, IRTA, irt | IRT_SIZE);
        command(u, GCMD_SIRTP);
        invalidate(u, &[INV_IEC_GLOBAL]);
        IRT[u].store(irt, Ordering::Relaxed);
        command(u, GCMD_IRE);
    }
    command(u, GCMD_TE);
    Some(())
}

/// After S3, which resets the units: turns each on again with the tables
/// it had (they are in RAM), the queue from its start, fault events,
/// interrupt remapping and translation, and invalidates every cache.
pub fn resume() {
    let remap = remapping();
    for u in units() {
        w64(u, RTADDR, ROOT[u].load(Ordering::Relaxed));
        command(u, GCMD_SRTP);
        let queue = QUEUE[u].load(Ordering::Relaxed);
        if queue != 0 {
            QUEUE_TAIL[u].store(0, Ordering::Relaxed);
            w64(u, IQT, 0);
            w64(u, IQA, queue);
            command(u, GCMD_QIE);
        }
        flush_context(u);
        flush_unit(u);
        w32(u, FEDATA, super::apic::IOMMU_VECTOR as u32);
        w32(u, FEADDR, 0xfee0_0000 | (super::apic::id() as u32) << 12);
        w32(u, FEUADDR, 0);
        w32(u, FECTL, 0);
        if remap {
            w64(u, IRTA, IRT[u].load(Ordering::Relaxed) | IRT_SIZE);
            command(u, GCMD_SIRTP);
            invalidate(u, &[INV_IEC_GLOBAL]);
            command(u, GCMD_IRE);
        }
        command(u, GCMD_TE);
    }
}

/// Turns on unit `u`'s invalidation queue, which then replaces its context
/// and IOTLB command registers.
fn start_queue(u: usize) -> Option<()> {
    let queue = memory::carve(12)?;
    let status = memory::carve(12)?;
    vm::zero_frame(queue);
    vm::zero_frame(status);
    w64(u, IQT, 0);
    w64(u, IQA, queue); // size 0: one page, 256 descriptors of 128 bits
    command(u, GCMD_QIE);
    QUEUE_STATUS[u].store(status, Ordering::Relaxed);
    QUEUE[u].store(queue, Ordering::Relaxed);
    Some(())
}

/// Queues `descriptors` and an invalidation wait on unit `u`, and waits
/// until it has carried them all out.
fn invalidate(u: usize, descriptors: &[u64]) {
    let queue = QUEUE[u].load(Ordering::Relaxed);
    let status = QUEUE_STATUS[u].load(Ordering::Relaxed);
    let word = vm::phys_ptr(status) as *mut u32;
    // SAFETY: the status page is ours; the unit writes it only for a wait
    // descriptor we queue.
    unsafe { word.write_volatile(0) };
    let mut tail = QUEUE_TAIL[u].load(Ordering::Relaxed);
    let mut put = |lo: u64, hi: u64| {
        let d = vm::phys_ptr(queue + 16 * tail) as *mut u64;
        // SAFETY: a slot of our queue page the unit has consumed: each
        // batch is waited for before the next is queued.
        unsafe {
            d.write_volatile(lo);
            d.add(1).write_volatile(hi);
        }
        tail = (tail + 1) % QUEUE_LEN;
    };
    for &lo in descriptors {
        put(lo, 0);
    }
    put(INV_WAIT_STATUS, status);
    QUEUE_TAIL[u].store(tail, Ordering::Relaxed);
    w64(u, IQT, tail << 4);
    // SAFETY: as above.
    while unsafe { word.read_volatile() } != 1 {
        if r32(u, FSTS) & FSTS_IQE != 0 {
            panic!("VT-d unit {u} refused an invalidation descriptor (IQH {:#x})", r64(u, IQH));
        }
        core::hint::spin_loop();
    }
}

/// Whether MSIs are remapped (and so need [`route`]).
pub fn remapping() -> bool {
    REMAPPING.load(Ordering::Relaxed)
}

fn irte(u: usize, index: u16) -> *mut u64 {
    vm::phys_ptr(IRT[u].load(Ordering::Relaxed) + 16 * index as u64) as *mut u64
}

/// Writes remapping table entry `index` of every unit: (`lo`, `hi`) in
/// unit `to`'s, empty in the others'. Invalidates each table it changed.
fn set_entry(index: u16, to: Option<usize>, lo: u64, hi: u64) {
    for u in units() {
        let (lo, hi) = if Some(u) == to { (lo, hi) } else { (0, 0) };
        set_entry_in(u, index, lo, hi);
    }
}

/// Points interrupt remapping table entry `index` at `vector` on the boot
/// CPU's local APIC (physical destination its APIC ID, fixed, edge),
/// raisable only by requester `source`, in the table of the unit `source`
/// goes through; with no source (or none the kernel drives), by nobody.
/// Returns the remappable-format message (address, data) that raises it.
pub fn route(index: u16, vector: u8, source: Option<u16>) -> (u64, u64) {
    let to = source.and_then(unit_of);
    // SVT = 01: the request's requester ID must equal SID.
    let hi = source.map_or(0, |sid| sid as u64 | 1 << 18);
    let lo = 1 | (vector as u64) << 16 | (super::boot_apic() as u64 & 0xff) << 40;
    set_entry(index, to, lo, hi);
    let index = index as u64;
    let address = 0xfee0_0000 | (index & 0x7fff) << 5 | 1 << 4 | (index >> 15 & 1) << 2;
    (address, 0)
}

/// Points remapping table entry `index` at `vector` on the boot CPU for an
/// I/O APIC's input, level-triggered or edge, raisable only by the I/O
/// APIC's requester ID (`source`: its ID and its unit, from the DMAR), in
/// that unit's table. If the DMAR does not say, by any requester, in every
/// unit's table. An entry already so leaves the cache alone.
pub fn route_line(index: u16, vector: u8, level: bool, source: Option<(u16, usize)>) {
    let lo = 1 | (level as u64) << 4 | (vector as u64) << 16 | (super::boot_apic() as u64 & 0xff) << 40;
    match source {
        Some((sid, unit)) => set_entry(index, Some(unit), lo, sid as u64 | 1 << 18),
        None => {
            for u in units() {
                set_entry_in(u, index, lo, 0);
            }
        }
    }
}

/// Writes remapping table entry `index` of unit `u` alone.
fn set_entry_in(u: usize, index: u16, lo: u64, hi: u64) {
    let e = irte(u, index);
    // SAFETY: an entry of the unit's table, which has room for 256. Not
    // present while it changes.
    unsafe {
        if e.read_volatile() == lo && e.add(1).read_volatile() == hi {
            return;
        }
        e.write_volatile(0);
        e.add(1).write_volatile(hi);
        e.write_volatile(lo);
    }
    invalidate(u, &[INV_IEC_GLOBAL]);
}

/// Takes every vector routed to requester `sid` away from it.
fn unroute(sid: u16) {
    if !remapping() {
        return;
    }
    for u in units() {
        let mut any = false;
        for index in 0..1u16 << (IRT_SIZE + 1) {
            let e = irte(u, index);
            // SAFETY: as in `set_entry_in`.
            unsafe {
                if e.read_volatile() & 1 != 0 && e.add(1).read_volatile() as u16 == sid {
                    e.write_volatile(0);
                    any = true;
                }
            }
        }
        if any {
            invalidate(u, &[INV_IEC_GLOBAL]);
        }
    }
}

pub fn present() -> bool {
    units().next().is_some()
}

pub fn levels() -> usize {
    3
}

pub fn table_entry(pa: u64) -> u64 {
    pa | 3
}

pub fn leaf_entry(pa: u64, write: bool) -> u64 {
    pa | 1 | (write as u64) << 1
}

/// The remapping units snoop the CPU's caches; nothing to do.
pub fn sync_tables() {}

/// Pages every I/O address space maps (none: MSIs are not translated).
pub fn fixed_pages() -> &'static [u64] {
    &[]
}

/// The pages requester `sid` keeps using whatever it is given (the DMAR's
/// reserved memory regions for it), to be mapped where they are before
/// its DMA is translated. Any the firmware left usable RAM are left out:
/// the kernel may have given them to anyone.
pub fn reserved_pages(sid: u16) -> impl Iterator<Item = u64> {
    acpi::reserved_for(sid)
        .flat_map(|(start, end)| (start..end).step_by(4096))
        .filter(|&pa| !crate::memory::is_ram(pa))
}

/// Prepares a new space's header page (unused on VT-d).
pub fn init_space(_header: u64, _root: u64, _domain: u16) {}

/// Requester `sid`'s context entry, in the tables of the unit it goes
/// through, and that unit.
fn context_entry(sid: u16) -> Option<(*mut u64, usize)> {
    if !valid_sid(sid) {
        return None;
    }
    let u = unit_of(sid)?;
    // SAFETY: the root table is ours; its entries are 16 bytes, one per
    // bus, written only here, under the kernel lock.
    let root = vm::phys_ptr(ROOT[u].load(Ordering::Relaxed) + 16 * (sid >> 8) as u64) as *mut u64;
    let mut entry = unsafe { root.read_volatile() };
    if entry & 1 == 0 {
        // The bus's first function to be bound: its context table, every
        // entry not present, so nothing else on the bus gets through.
        let ctx = memory::carve(12)?;
        vm::zero_frame(ctx);
        entry = ctx | 1;
        // SAFETY: as above. A root entry going from not present to
        // present needs no invalidation.
        unsafe { root.write_volatile(entry) };
    }
    Some((vm::phys_ptr((entry & !0xfff) + 16 * (sid & 0xff) as u64) as *mut u64, u))
}

/// Whether requester ID `sid` can be bound: on a bus the tables reach,
/// and under a unit the kernel drives (from ACPI's DMAR).
pub fn valid_sid(sid: u16) -> bool {
    ((sid >> 8) as u64) < PCI_BUSES && unit_of(sid).is_some()
}

/// Translates requester `sid`'s DMA through the tables under `root`.
pub fn attach(sid: u16, domain: u16, _header: u64, root: u64) {
    let Some((e, u)) = context_entry(sid) else { return };
    // SAFETY: a context table entry of ours.
    unsafe {
        e.add(1).write_volatile(AW_39 | (domain as u64) << 8);
        e.write_volatile(root | 1);
    }
    flush_context(u);
    flush_unit(u);
}

/// Blocks requester `sid`'s DMA altogether, interrupts included.
pub fn detach(sid: u16) {
    unroute(sid);
    let Some((e, u)) = context_entry(sid) else { return };
    // SAFETY: as in `attach`.
    unsafe {
        e.write_volatile(0);
        e.add(1).write_volatile(0);
    }
    flush_context(u);
    flush_unit(u);
}

fn flush_context(u: usize) {
    if QUEUE[u].load(Ordering::Relaxed) != 0 {
        return invalidate(u, &[INV_CONTEXT_GLOBAL]);
    }
    w64(u, CCMD, CCMD_ICC | CCMD_GLOBAL);
    while r64(u, CCMD) & CCMD_ICC != 0 {
        core::hint::spin_loop();
    }
}

/// Forgets unit `u`'s cached translations, waiting until it has.
fn flush_unit(u: usize) {
    if QUEUE[u].load(Ordering::Relaxed) != 0 {
        return invalidate(u, &[INV_IOTLB_GLOBAL]);
    }
    let reg = iotlb_reg(u);
    w64(u, reg, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN);
    while r64(u, reg) & IOTLB_IVT != 0 {
        core::hint::spin_loop();
    }
}

/// Forgets every unit's cached translations, waiting until they have.
pub fn flush() {
    for u in units() {
        flush_unit(u);
    }
}

/// Hands each request a unit blocked since the last call to `f`, as
/// (requester ID, what it was), and frees its record. Returns whether
/// records were lost to overflow.
pub fn take_faults(mut f: impl FnMut(u16, IoFault)) -> bool {
    let mut lost = false;
    for u in units() {
        let status = r32(u, FSTS);
        if status & 3 == 0 {
            continue;
        }
        let cap = r64(u, CAP);
        let records = ((cap >> 40) & 0xff) + 1;
        let first = ((cap >> 24) & 0x3ff) * 16;
        // Records fill from the index FSTS names, wrapping; any may be
        // valid.
        for i in 0..records {
            let at = first + 16 * i;
            let hi = r64(u, at + 8);
            if hi & FRCD_F == 0 {
                continue;
            }
            let lo = r64(u, at);
            // Fault reasons from 0x20 up are interrupt remapping's.
            let fault = if (hi >> 32) & 0xff >= 0x20 {
                IoFault::Interrupt
            } else if hi & FRCD_READ != 0 {
                IoFault::Read(lo & !0xfff)
            } else {
                IoFault::Write(lo & !0xfff)
            };
            f(hi as u16, fault);
            w64(u, at + 8, FRCD_F);
        }
        if status & FSTS_PFO != 0 {
            w32(u, FSTS, FSTS_PFO);
            lost = true;
        }
    }
    lost
}
