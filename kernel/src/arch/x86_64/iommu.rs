//! Intel VT-d (DMA remapping), as QEMU's `intel-iommu` emulates it on the
//! q35 machine: one remapping unit at 0xfed9_0000 covering every PCI
//! function, register-based invalidation, legacy-mode root and context
//! tables, and 3-level second-level page tables (39-bit I/O addresses).
//!
//! Once translation is on, a function with no context entry can reach no
//! memory at all; one bound to an I/O address space reaches only what is
//! mapped in it. Interrupt remapping is not used: MSI writes go straight
//! to the local APIC.
//!
//! Blocked requests are logged in the unit's fault recording registers;
//! the kernel drains them on every timer tick ([`take_faults`]), with the
//! fault event interrupt left masked.

use super::vm;
use crate::memory;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;

const BASE: u64 = 0xfed9_0000;
const VER: u64 = 0x00;
const CAP: u64 = 0x08;
const ECAP: u64 = 0x10;
const GCMD: u64 = 0x18;
const GSTS: u64 = 0x1c;
const RTADDR: u64 = 0x20;
const CCMD: u64 = 0x28;
const FSTS: u64 = 0x34;
const FECTL: u64 = 0x38;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
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
/// FECTL: fault event interrupt masked.
const FECTL_IM: u32 = 1 << 31;
/// A fault recording register's high half: valid (write 1 to clear), and
/// the request was a read.
const FRCD_F: u64 = 1 << 63;
const FRCD_READ: u64 = 1 << 62;

/// Kernel virtual address of the registers (0 if there is no IOMMU), and
/// the root table's physical address.
static REGS: AtomicU64 = AtomicU64::new(0);
static ROOT: AtomicU64 = AtomicU64::new(0);

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
    let va = vm::map_mmio(PhysAddr::new(BASE)).ok()?.as_u64();
    REGS.store(va, Ordering::Relaxed);
    let cap = r64(CAP);
    if r32(VER) != 0x10 || cap == u64::MAX || cap & SAGAW_39 == 0 {
        REGS.store(0, Ordering::Relaxed);
        return None;
    }
    // The root table, and one context table for bus 0 (where every
    // function the bus server hands out lives).
    let root = memory::carve(12)?;
    let ctx = memory::carve(12)?;
    vm::zero_frame(root);
    vm::zero_frame(ctx);
    // SAFETY: freshly carved RAM, reachable through the physical map.
    unsafe { (vm::phys_ptr(root) as *mut u64).write_volatile(ctx | 1) };
    ROOT.store(root, Ordering::Relaxed);
    w64(RTADDR, root);
    command(GCMD_SRTP);
    flush_context();
    flush();
    w32(FECTL, FECTL_IM);
    command(GCMD_TE);
    Some("Intel VT-d")
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
    // Only bus 0 has a context table.
    if sid >> 8 != 0 {
        return None;
    }
    // SAFETY: the root table is ours; its bus-0 entry is set in `init`.
    let ctx = unsafe { (vm::phys_ptr(ROOT.load(Ordering::Relaxed)) as *const u64).read_volatile() }
        & !0xfff;
    Some(vm::phys_ptr(ctx + 16 * (sid & 0xff) as u64) as *mut u64)
}

/// Whether requester ID `sid` can be bound.
pub fn valid_sid(sid: u16) -> bool {
    sid >> 8 == 0
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

/// Blocks requester `sid`'s DMA altogether.
pub fn detach(sid: u16) {
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
    let reg = iotlb_reg();
    w64(reg, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN);
    while r64(reg) & IOTLB_IVT != 0 {
        core::hint::spin_loop();
    }
}

/// Hands each request the unit blocked since the last call to `f`, as
/// (requester ID, page address, whether it was a write), and frees its
/// record. Returns whether records were lost to overflow.
pub fn take_faults(mut f: impl FnMut(u16, u64, bool)) -> bool {
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
        f(hi as u16, lo & !0xfff, hi & FRCD_READ == 0);
        w64(at + 8, FRCD_F);
    }
    let lost = status & FSTS_PFO != 0;
    if lost {
        w32(FSTS, FSTS_PFO);
    }
    lost
}
