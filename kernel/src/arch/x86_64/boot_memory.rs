//! The bootloader's memory map, handed to [`crate::memory`].

use crate::memory::{add_region, Summary};
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};

/// Leave the first 1 MiB alone: on BIOS machines it holds firmware
/// structures that "usable" does not always protect.
const LOW_MEMORY_END: u64 = 0x10_0000;

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
