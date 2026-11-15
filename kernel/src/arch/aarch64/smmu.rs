//! Arm SMMUv3, as QEMU's `virt` machine emulates it with `iommu=smmuv3`:
//! one SMMU in front of the PCI host bridge, whose stream IDs are PCI
//! requester IDs. The kernel uses a linear stream table (256 entries, bus
//! 0), one command queue, and stage-1 translation: each bound function's
//! stream table entry points at a context descriptor in its I/O address
//! space's header page, whose table base is that space's 3-level, 4 KiB
//! granule tables (39-bit I/O addresses).
//!
//! Once the SMMU is on, a stream whose entry is not valid can reach no
//! memory at all. Faults go to the event queue, whose interrupt (the
//! wired SPI the device tree names first) has the kernel drain it at once
//! ([`take_faults`]); the timer tick drains it too, in case one is missed.

use super::{gic, vm};
use crate::iommu::IoFault;
use crate::{kprintln, memory};
use superior_objects::abi::PCI_BUSES;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const IDR0: u64 = 0x00;
const CR0: u64 = 0x20;
const CR0ACK: u64 = 0x24;
const CR1: u64 = 0x28;
const STRTAB_BASE: u64 = 0x80;
const STRTAB_BASE_CFG: u64 = 0x88;
const CMDQ_BASE: u64 = 0x90;
const CMDQ_PROD: u64 = 0x98;
const CMDQ_CONS: u64 = 0x9c;
const EVTQ_BASE: u64 = 0xa0;
const IRQ_CTRL: u64 = 0x50;
const IRQ_CTRLACK: u64 = 0x54;
const IRQ_EVTQ: u32 = 1 << 2;
/// The event queue's indices live in the second register page.
const EVTQ_PROD: u64 = 0x1_00a8;
const EVTQ_CONS: u64 = 0x1_00ac;

const CR0_SMMUEN: u32 = 1;
const CR0_EVTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;
/// Table and queue walks: inner-shareable, write-back cacheable.
const CR1_WB_ISH: u32 = 1 | (1 << 2) | (3 << 4) | (1 << 6) | (1 << 8) | (3 << 10);
const READ_ALLOCATE: u64 = 1 << 62;

/// Stream table: an entry of 64 bytes for every function of `PCI_BUSES`
/// buses (2^12 entries, 256 KiB).
const STRTAB_LOG2: u64 = 8 + PCI_BUSES.trailing_zeros() as u64;
const _: () = assert!(PCI_BUSES.is_power_of_two());
/// Command queue: 2^5 commands of 16 bytes.
const CMDQ_LOG2: u32 = 5;
/// Event queue: 2^7 events of 32 bytes (one page).
const EVTQ_LOG2: u32 = 7;
/// Queue index overflow flag.
const Q_OVERFLOW: u32 = 1 << 31;

const CMD_CFGI_STE: u64 = 0x03;
const CMD_TLBI_NSNH_ALL: u64 = 0x30;
const CMD_SYNC: u64 = 0x46;

/// Register base (0 if there is no SMMU), stream table and command queue.
static REGS: AtomicU64 = AtomicU64::new(0);
static STRTAB: AtomicU64 = AtomicU64::new(0);
static CMDQ: AtomicU64 = AtomicU64::new(0);
static EVTQ: AtomicU64 = AtomicU64::new(0);
/// The event queue's interrupt ID, or 0 if it has none.
static IRQ: AtomicU32 = AtomicU32::new(0);

/// The interrupt ID of the event queue's interrupt, if it is on.
pub fn fault_irq() -> Option<u32> {
    Some(IRQ.load(Ordering::Relaxed)).filter(|&id| id != 0)
}

fn r32(off: u64) -> u32 {
    // SAFETY: the SMMU's registers lie in the kernel's device identity map.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *const u32).read_volatile() }
}

fn w32(off: u64, v: u32) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *mut u32).write_volatile(v) }
}

fn w64(off: u64, v: u64) {
    // SAFETY: as in `r32`.
    unsafe { ((REGS.load(Ordering::Relaxed) + off) as *mut u64).write_volatile(v) }
}

fn dsb() {
    // SAFETY: a barrier only.
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

fn set_cr0(v: u32) {
    w32(CR0, v);
    while r32(CR0ACK) != v {
        core::hint::spin_loop();
    }
}

/// Queues one command and waits until the SMMU has consumed it.
fn command(dw0: u64, dw1: u64) {
    let q = CMDQ.load(Ordering::Relaxed);
    let prod = r32(CMDQ_PROD);
    let slot = (prod & ((1 << CMDQ_LOG2) - 1)) as u64;
    // SAFETY: the queue page is ours, identity-mapped RAM.
    unsafe {
        let e = (q + 16 * slot) as *mut u64;
        e.write_volatile(dw0);
        e.add(1).write_volatile(dw1);
    }
    dsb();
    let next = (prod + 1) & ((2 << CMDQ_LOG2) - 1);
    w32(CMDQ_PROD, next);
    for _ in 0..1_000_000 {
        if r32(CMDQ_CONS) & ((2 << CMDQ_LOG2) - 1) == next {
            return;
        }
        core::hint::spin_loop();
    }
    kprintln!("[warn] SMMU: command {dw0:#x} not consumed");
}

fn sync() {
    command(CMD_SYNC, 0);
}

/// Finds and turns on the SMMU, with no stream able to reach anything.
/// `base` is its register page, `irq` its event queue's interrupt ID (from
/// the device tree or ACPI's IORT).
pub fn init(base: u64, irq: Option<u32>) -> Option<&'static str> {
    REGS.store(base, Ordering::Relaxed);
    let idr0 = r32(IDR0);
    // Stage 1, AArch64 tables.
    if idr0 & 2 == 0 || (idr0 >> 2) & 2 == 0 {
        REGS.store(0, Ordering::Relaxed);
        return None;
    }
    let strtab = memory::carve(STRTAB_LOG2 as u8 + 6)?;
    for p in 0..(64 << STRTAB_LOG2) / 4096 {
        vm::zero_frame(strtab + p * 4096);
    }
    let cmdq = memory::carve(12)?;
    vm::zero_frame(cmdq);
    let evtq = memory::carve(12)?;
    vm::zero_frame(evtq);
    EVTQ.store(evtq, Ordering::Relaxed);
    STRTAB.store(strtab, Ordering::Relaxed);
    CMDQ.store(cmdq, Ordering::Relaxed);
    set_cr0(0);
    w32(CR1, CR1_WB_ISH);
    w64(STRTAB_BASE, strtab | READ_ALLOCATE);
    w32(STRTAB_BASE_CFG, STRTAB_LOG2 as u32);
    w64(CMDQ_BASE, cmdq | READ_ALLOCATE | CMDQ_LOG2 as u64);
    w32(CMDQ_PROD, 0);
    w32(CMDQ_CONS, 0);
    w64(EVTQ_BASE, evtq | READ_ALLOCATE | EVTQ_LOG2 as u64);
    w32(EVTQ_PROD, 0);
    w32(EVTQ_CONS, 0);
    set_cr0(CR0_CMDQEN | CR0_EVTQEN);
    command(CMD_TLBI_NSNH_ALL, 0);
    sync();
    set_cr0(CR0_CMDQEN | CR0_EVTQEN | CR0_SMMUEN);
    if let Some(id) = irq {
        w32(IRQ_CTRL, IRQ_EVTQ);
        while r32(IRQ_CTRLACK) != IRQ_EVTQ {
            core::hint::spin_loop();
        }
        gic::enable_edge_spi(id);
        IRQ.store(id, Ordering::Relaxed);
    }
    Some("Arm SMMUv3")
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

/// A page: access flag set, inner-shareable, read/write or read-only at
/// any privilege.
pub fn leaf_entry(pa: u64, write: bool) -> u64 {
    let ap = if write { 0b01 } else { 0b11 };
    pa | 3 | (1 << 10) | (3 << 8) | ap << 6
}

/// Makes table writes visible to the SMMU's walks.
pub fn sync_tables() {
    dsb();
}

/// Pages every I/O address space maps: the ITS's translation register, so
/// the function's MSI writes get through (the ITS then decides whether
/// they raise anything).
pub fn fixed_pages() -> &'static [u64] {
    const PAGES: [u64; 1] = [gic::MSI_DOORBELL & !0xfff];
    &PAGES
}

/// Pages a function keeps using whatever it is given: none known here
/// (on Arm they would come from IORT's reserved memory ranges, or a
/// device tree's `iommu-addresses`, neither of which QEMU's virt has).
pub fn reserved_pages(_sid: u16) -> core::iter::Empty<u64> {
    core::iter::empty()
}

/// Writes a new space's context descriptor into its header page: stage-1
/// translation through the tables at `root`, 39-bit inputs, 40-bit
/// outputs, ASID = `domain`.
pub fn init_space(header: u64, root: u64, domain: u16) {
    let cd = header as *mut u64;
    let dw0 = 25 // T0SZ: 39-bit inputs
        | 1 << 8 // IR0: write-back
        | 1 << 10 // OR0: write-back
        | 3 << 12 // SH0: inner shareable
        | 1 << 30 // EPD1: no second table
        | 1 << 31 // V
        | 2 << 32 // IPS: 40 bits
        | 1 << 41 // AA64
        | 1 << 45 // R: faults are recorded in the event queue
        | 1 << 46 // A: aborts are reported, not stalled
        | (domain as u64) << 48;
    // SAFETY: the header page belongs to the new space, identity-mapped.
    unsafe {
        cd.add(1).write_volatile(root);
        cd.add(3).write_volatile(0xff);
        cd.write_volatile(dw0);
    }
    dsb();
}

pub fn valid_sid(sid: u16) -> bool {
    (sid as u64) < 1 << STRTAB_LOG2
}

fn ste(sid: u16) -> *mut u64 {
    (STRTAB.load(Ordering::Relaxed) + 64 * sid as u64) as *mut u64
}

/// Translates stream `sid`'s DMA through the space whose context
/// descriptor is at `header`.
pub fn attach(sid: u16, _domain: u16, header: u64, _root: u64) {
    if !valid_sid(sid) {
        return;
    }
    let e = ste(sid);
    // SAFETY: an entry of our stream table.
    unsafe {
        // Cache attributes for the descriptor fetch (inner/outer
        // write-back, inner shareable), then valid last.
        e.add(1).write_volatile(1 << 2 | 1 << 4 | 3 << 6);
        dsb();
        e.write_volatile(1 | 0b101 << 1 | header);
    }
    dsb();
    command(CMD_CFGI_STE | (sid as u64) << 32, 1);
    flush();
}

/// Blocks stream `sid`'s DMA altogether, interrupts included.
pub fn detach(sid: u16) {
    gic::unroute(sid);
    if !valid_sid(sid) {
        return;
    }
    // SAFETY: as in `attach`.
    unsafe { ste(sid).write_volatile(0) };
    dsb();
    command(CMD_CFGI_STE | (sid as u64) << 32, 1);
    flush();
}

/// Forgets every cached translation, waiting until the SMMU has.
pub fn flush() {
    if !present() {
        return;
    }
    command(CMD_TLBI_NSNH_ALL, 0);
    sync();
}

/// Hands each fault event since the last call to `f`, as (stream ID,
/// what it was), and consumes it. Returns whether events were lost to
/// overflow.
pub fn take_faults(mut f: impl FnMut(u16, IoFault)) -> bool {
    if !present() {
        return false;
    }
    let q = EVTQ.load(Ordering::Relaxed);
    let mask = (2u32 << EVTQ_LOG2) - 1;
    let prod = r32(EVTQ_PROD);
    let mut cons = r32(EVTQ_CONS) & mask;
    if prod & mask == cons {
        return false;
    }
    dsb();
    while prod & mask != cons {
        let slot = (cons & ((1 << EVTQ_LOG2) - 1)) as u64;
        // SAFETY: the queue page is ours, identity-mapped RAM, and the SMMU
        // wrote this entry before moving PROD past it.
        let e = unsafe { core::slice::from_raw_parts((q + 32 * slot) as *const u64, 4) };
        let (dw0, dw1, addr) = unsafe {
            (
                core::ptr::read_volatile(&e[0]),
                core::ptr::read_volatile(&e[1]),
                core::ptr::read_volatile(&e[2]),
            )
        };
        // Translation, address size, access flag and permission faults
        // carry the address; any other event (a bad stream table entry,
        // say) is reported at address 0.
        let kind = dw0 & 0xff;
        let addr = if (0x10..=0x13).contains(&kind) { addr & !0xfff } else { 0 };
        let fault = if dw1 & 1 << 34 != 0 {
            IoFault::Read(addr)
        } else {
            IoFault::Write(addr)
        };
        f((dw0 >> 32) as u16, fault);
        cons = (cons + 1) & mask;
    }
    let lost = prod & Q_OVERFLOW != r32(EVTQ_CONS) & Q_OVERFLOW;
    // Acknowledge the overflow, if any, along with the entries read.
    w32(EVTQ_CONS, cons | (prod & Q_OVERFLOW));
    lost
}
