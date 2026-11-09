//! I/O page tables, shared by both IOMMUs the kernel drives (Intel VT-d
//! second-level tables on x86-64, SMMUv3 stage-1 tables on AArch64).
//!
//! Both are radix trees of 4 KiB tables of 512 eight-byte entries, indexed
//! by 9 bits of the I/O address per level; only the entry encodings and
//! the depth differ, and those come from the architecture's `iommu`
//! module. The tables live in the I/O-space object's own memory
//! ([`TablePool::Own`]), like an address space's.

use crate::arch::{iommu, vm};
use crate::memory::TablePool;

/// Why a mapping failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoMapError {
    /// Something is already mapped at the address.
    InUse,
    /// No memory left in the space for a table.
    OutOfMemory,
    /// The address is beyond what the tables cover.
    TooHigh,
}

fn entry(table: u64, index: u64) -> *mut u64 {
    vm::phys_ptr(table + 8 * index) as *mut u64
}

fn index(iova: u64, level: usize, levels: usize) -> u64 {
    (iova >> (12 + 9 * (levels - 1 - level))) & 511
}

/// Maps the page at `pa` at I/O address `iova` in the tables under `root`.
pub fn map(
    root: u64,
    iova: u64,
    pa: u64,
    write: bool,
    pool: &mut TablePool,
) -> Result<(), IoMapError> {
    let levels = iommu::levels();
    if iova >> (12 + 9 * levels) != 0 {
        return Err(IoMapError::TooHigh);
    }
    let mut table = root;
    for level in 0..levels - 1 {
        let e = entry(table, index(iova, level, levels));
        // SAFETY: `table` is a page table of this space, reachable through
        // the kernel's view of physical memory.
        let v = unsafe { e.read_volatile() };
        table = if v & 1 != 0 {
            v & 0x000f_ffff_ffff_f000
        } else {
            let t = pool.alloc(vm::zero_frame).ok_or(IoMapError::OutOfMemory)?;
            // SAFETY: as above.
            unsafe { e.write_volatile(iommu::table_entry(t)) };
            t
        };
    }
    let e = entry(table, index(iova, levels - 1, levels));
    // SAFETY: as above.
    unsafe {
        if e.read_volatile() & 1 != 0 {
            return Err(IoMapError::InUse);
        }
        e.write_volatile(iommu::leaf_entry(pa, write));
    }
    iommu::sync_tables();
    Ok(())
}

/// Unmaps the page at `iova`. The caller flushes the IOMMU's caches.
pub fn unmap(root: u64, iova: u64) {
    let levels = iommu::levels();
    let mut table = root;
    for level in 0..levels - 1 {
        // SAFETY: as in `map`.
        let v = unsafe { entry(table, index(iova, level, levels)).read_volatile() };
        if v & 1 == 0 {
            return;
        }
        table = v & 0x000f_ffff_ffff_f000;
    }
    // SAFETY: as in `map`.
    unsafe { entry(table, index(iova, levels - 1, levels)).write_volatile(0) };
    iommu::sync_tables();
}
