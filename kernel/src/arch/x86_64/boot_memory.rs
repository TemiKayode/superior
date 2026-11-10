//! The bootloader's memory map, handed to [`crate::memory`].

use crate::memory::{add_region, Summary};
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};

/// Leave the first 1 MiB alone: on BIOS machines it holds firmware
/// structures that "usable" does not always protect.
const LOW_MEMORY_END: u64 = 0x10_0000;

/// A usable page below 1 MiB (and above the real-mode interrupt table),
/// where other CPUs can start in real mode.
pub fn startup_page(regions: &MemoryRegions) -> Option<u64> {
    regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .find_map(|r| {
            let start = r.start.max(0x1000).next_multiple_of(0x1000);
            (start + 0x1000 <= r.end.min(0x9_f000)).then_some(start)
        })
}

pub fn init(regions: &MemoryRegions) -> Summary {
    let mut s = Summary::default();
    for r in regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        add_region(&mut s, r.start.max(LOW_MEMORY_END), r.end);
    }
    s
}
