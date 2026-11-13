//! Intel VT-d (DMA remapping), as QEMU's `intel-iommu` emulates it on the
//! q35 machine: the one remapping unit ACPI's DMAR table says covers every
//! PCI function (at 0xfed9_0000 on QEMU), register-based invalidation, legacy-mode root and context
//! tables, and 3-level second-level page tables (39-bit I/O addresses).
//!
//! Once translation is on, a function with no context entry can reach no
//! memory at all; one bound to an I/O address space reaches only what is
//! mapped in it.
//!
//! Interrupts are remapped too (when the unit can): an MSI is a DMA write
//! like any other, and without remapping a device could write any vector
//! to the local APIC. Each MSI vector has an entry in the interrupt
//! remapping table that names the one requester ID allowed to raise it
//! ([`route`]); a message in the old compatibility format, or for an
//! entry naming another device (or none), is blocked. Invalidation then
//! goes through the invalidation queue, since the interrupt entry cache
//! has no register to flush it.
//!
//! Blocked requests are logged in the unit's fault recording registers,
//! and the unit's fault event interrupt (a message to CPU 0's local APIC on
//! [`super::apic::IOMMU_VECTOR`], never itself remapped) has the kernel
//! drain them at once ([`take_faults`]); the timer tick drains them too.
//! A record freed while others are pending raises the event again.

use super::vm;
use crate::iommu::IoFault;
use crate::memory;
use superior_objects::abi::PCI_BUSES;
use core::sync::atomic::{AtomicU64, Ordering};
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

/// Kernel virtual address of the registers (0 if there is no IOMMU), and
/// the root table's physical address.
static REGS: AtomicU64 = AtomicU64::new(0);
static ROOT: AtomicU64 = AtomicU64::new(0);
/// The invalidation queue's page, its next free index, and a page whose
/// first word invalidation waits write (0 while the queue is off).
static QUEUE: AtomicU64 = AtomicU64::new(0);
static QUEUE_TAIL: AtomicU64 = AtomicU64::new(0);
static QUEUE_STATUS: AtomicU64 = AtomicU64::new(0);
/// The interrupt remapping table (0 if interrupts are not remapped).
static IRT: AtomicU64 = AtomicU64::new(0);

fn r32(off: u64) -> u32 {
    // SAFETY: the register page is mapped (uncached) by `init`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *const u32).read_volatile() }
}

fn w32(off: u64, v: u32) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *mut u32).write_volatile(v) }
}

fn r64(off: u64) -> u64 {
    // SAFETY: as in `r32`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *const u64).read_volatile() }
}

fn w64(off: u64, v: u64) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *mut u64).write_volatile(v) }
}

/// Issues a one-shot or persistent global command and waits for its
/// status bit.
fn command(bit: u32) {
    let persistent = r32(GSTS) & GSTS_PERSISTENT;
    w32(GCMD, persistent | bit);
    while r32(GSTS) & bit == 0 {
        core::hint::spin_loop();
    }
}

fn iotlb_reg() -> u64 {
    ((r64(ECAP) >> 8) & 0x3ff) * 16 + 8
}

/// Finds and turns on the remapping unit, with nothing mapped for anyone.
/// Returns its description, or `None` if the machine has none.
pub fn init() -> Option<&'static str> {
    let base = super::acpi::vtd()?;
    let va = vm::map_mmio(PhysAddr::new(base)).ok()?.as_u64();
    REGS.store(va, Ordering::Relaxed);
    let cap = r64(CAP);
    if r32(VER) != 0x10 || cap == u64::MAX || cap & SAGAW_39 == 0 {
        REGS.store(0, Ordering::Relaxed);
        return None;
    }
    // The root table: an entry for each of the 256 buses, none present.
    // A bus's context table is made when a function on it is first bound
    // (`context_entry`); until then VT-d blocks everything from it.
    let root = memory::carve(12)?;
    vm::zero_frame(root);
    ROOT.store(root, Ordering::Relaxed);
    w64(RTADDR, root);
    command(GCMD_SRTP);
    let ecap = r64(ECAP);
    if ecap & ECAP_QI != 0 {
        start_queue()?;
    }
    flush_context();
    flush();
    // Fault events: a fixed-delivery message to CPU 0 (physical
    // destination), then unmasked.
    w32(FEDATA, super::apic::IOMMU_VECTOR as u32);
    w32(FEADDR, 0xfee0_0000 | (super::apic::id() as u32) << 12);
    w32(FEUADDR, 0);
    w32(FECTL, 0);
    let remapping = ecap & ECAP_QI != 0 && ecap & ECAP_IR != 0;
    if remapping {
        // Every entry starts not present: no device raises anything until
        // a vector is routed to it. Compatibility-format MSIs stay
        // blocked (GCMD.CFI clear).
        let irt = memory::carve(12)?;
        vm::zero_frame(irt);
        w64(IRTA, irt | IRT_SIZE);
        command(GCMD_SIRTP);
        invalidate(&[INV_IEC_GLOBAL]);
        IRT.store(irt, Ordering::Relaxed);
        command(GCMD_IRE);
    }
    command(GCMD_TE);
    Some(if remapping {
        "Intel VT-d, interrupt remapping"
    } else {
        "Intel VT-d"
    })
}

/// Turns on the invalidation queue, which then replaces the context and
/// IOTLB command registers.
fn start_queue() -> Option<()> {
    let queue = memory::carve(12)?;
    let status = memory::carve(12)?;
    vm::zero_frame(queue);
    vm::zero_frame(status);
    w64(IQT, 0);
    w64(IQA, queue); // size 0: one page, 256 descriptors of 128 bits
    command(GCMD_QIE);
    QUEUE_STATUS.store(status, Ordering::Relaxed);
    QUEUE.store(queue, Ordering::Relaxed);
    Some(())
}

/// Queues `descriptors` and an invalidation wait, and waits until the
/// unit has carried them all out.
fn invalidate(descriptors: &[u64]) {
    let queue = QUEUE.load(Ordering::Relaxed);
    let status = QUEUE_STATUS.load(Ordering::Relaxed);
    let word = vm::phys_ptr(status) as *mut u32;
    // SAFETY: the status page is ours; the unit writes it only for a wait
    // descriptor we queue.
    unsafe { word.write_volatile(0) };
    let mut tail = QUEUE_TAIL.load(Ordering::Relaxed);
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
    QUEUE_TAIL.store(tail, Ordering::Relaxed);
    w64(IQT, tail << 4);
    // SAFETY: as above.
    while unsafe { word.read_volatile() } != 1 {
        if r32(FSTS) & FSTS_IQE != 0 {
            panic!("VT-d refused an invalidation descriptor (IQH {:#x})", r64(IQH));
        }
        core::hint::spin_loop();
    }
}

/// Whether MSIs are remapped (and so need [`route`]).
pub fn remapping() -> bool {
    IRT.load(Ordering::Relaxed) != 0
}

fn irte(index: u16) -> *mut u64 {
    vm::phys_ptr(IRT.load(Ordering::Relaxed) + 16 * index as u64) as *mut u64
}

/// Points interrupt remapping table entry `index` at `vector` on the boot
/// CPU's local APIC (physical destination its APIC ID, fixed, edge),
/// raisable only
/// by requester `source`; with no source, by nobody. Returns the
/// remappable-format message (address, data) that raises it.
pub fn route(index: u16, vector: u8, source: Option<u16>) -> (u64, u64) {
    let e = irte(index);
    // SAFETY: an entry of our table, which has room for 256. Not present
    // while it changes.
    unsafe {
        e.write_volatile(0);
        if let Some(sid) = source {
            // SVT = 01: the request's requester ID must equal SID.
            e.add(1).write_volatile(sid as u64 | 1 << 18);
            e.write_volatile(1 | (vector as u64) << 16 | (super::boot_apic() as u64 & 0xff) << 40);
        } else {
            e.add(1).write_volatile(0);
        }
    }
    invalidate(&[INV_IEC_GLOBAL]);
    let index = index as u64;
    let address = 0xfee0_0000 | (index & 0x7fff) << 5 | 1 << 4 | (index >> 15 & 1) << 2;
    (address, 0)
}

/// Takes every vector routed to requester `sid` away from it.
fn unroute(sid: u16) {
    if !remapping() {
        return;
    }
    let mut any = false;
    for index in 0..1u16 << (IRT_SIZE + 1) {
        let e = irte(index);
        // SAFETY: as in `route`.
        unsafe {
            if e.read_volatile() & 1 != 0 && e.add(1).read_volatile() as u16 == sid {
                e.write_volatile(0);
                any = true;
            }
        }
    }
    if any {
        invalidate(&[INV_IEC_GLOBAL]);
    }
}

pub fn present() -> bool {
    REGS.load(Ordering::Relaxed) != 0
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

/// The remapping unit snoops the CPU's caches; nothing to do.
pub fn sync_tables() {}

/// Pages every I/O address space maps (none: MSIs are not translated).
pub fn fixed_pages() -> &'static [u64] {
    &[]
}

/// Prepares a new space's header page (unused on VT-d).
pub fn init_space(_header: u64, _root: u64, _domain: u16) {}

fn context_entry(sid: u16) -> Option<*mut u64> {
    if !valid_sid(sid) {
        return None;
    }
    // SAFETY: the root table is ours; its entries are 16 bytes, one per
    // bus, written only here, under the kernel lock.
    let root = vm::phys_ptr(ROOT.load(Ordering::Relaxed) + 16 * (sid >> 8) as u64) as *mut u64;
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
    Some(vm::phys_ptr((entry & !0xfff) + 16 * (sid & 0xff) as u64) as *mut u64)
}

/// Whether requester ID `sid` can be bound: on a bus the tables reach,
/// and covered by the unit in use (ACPI's DMAR).
pub fn valid_sid(sid: u16) -> bool {
    ((sid >> 8) as u64) < PCI_BUSES && super::acpi::vtd_covers(sid)
}

/// Translates requester `sid`'s DMA through the tables under `root`.
pub fn attach(sid: u16, domain: u16, _header: u64, root: u64) {
    let Some(e) = context_entry(sid) else { return };
    // SAFETY: a context table entry of ours.
    unsafe {
        e.add(1).write_volatile(AW_39 | (domain as u64) << 8);
        e.write_volatile(root | 1);
    }
    flush_context();
    flush();
}

/// Blocks requester `sid`'s DMA altogether, interrupts included.
pub fn detach(sid: u16) {
    unroute(sid);
    let Some(e) = context_entry(sid) else { return };
    // SAFETY: as in `attach`.
    unsafe {
        e.write_volatile(0);
        e.add(1).write_volatile(0);
    }
    flush_context();
    flush();
}

fn flush_context() {
    if QUEUE.load(Ordering::Relaxed) != 0 {
        return invalidate(&[INV_CONTEXT_GLOBAL]);
    }
    w64(CCMD, CCMD_ICC | CCMD_GLOBAL);
    while r64(CCMD) & CCMD_ICC != 0 {
        core::hint::spin_loop();
    }
}

/// Forgets every cached translation, waiting until the unit has.
pub fn flush() {
    if !present() {
        return;
    }
    if QUEUE.load(Ordering::Relaxed) != 0 {
        return invalidate(&[INV_IOTLB_GLOBAL]);
    }
    let reg = iotlb_reg();
    w64(reg, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN);
    while r64(reg) & IOTLB_IVT != 0 {
        core::hint::spin_loop();
    }
}

/// Hands each request the unit blocked since the last call to `f`, as
/// (requester ID, what it was), and frees its record. Returns whether
/// records were lost to overflow.
pub fn take_faults(mut f: impl FnMut(u16, IoFault)) -> bool {
    if !present() {
        return false;
    }
    let status = r32(FSTS);
    if status & 3 == 0 {
        return false;
    }
    let cap = r64(CAP);
    let records = ((cap >> 40) & 0xff) + 1;
    let first = ((cap >> 24) & 0x3ff) * 16;
    // Records fill from the index FSTS names, wrapping; any may be valid.
    for i in 0..records {
        let at = first + 16 * i;
        let hi = r64(at + 8);
        if hi & FRCD_F == 0 {
            continue;
        }
        let lo = r64(at);
        // Fault reasons from 0x20 up are interrupt remapping's.
        let fault = if (hi >> 32) & 0xff >= 0x20 {
            IoFault::Interrupt
        } else if hi & FRCD_READ != 0 {
            IoFault::Read(lo & !0xfff)
        } else {
            IoFault::Write(lo & !0xfff)
        };
        f(hi as u16, fault);
        w64(at + 8, FRCD_F);
    }
    let lost = status & FSTS_PFO != 0;
    if lost {
        w32(FSTS, FSTS_PFO);
    }
    lost
}
