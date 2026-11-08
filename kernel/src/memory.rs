//! Boot-time memory hand-off.
//!
//! The kernel keeps no heap. At boot it turns every usable physical region
//! into naturally aligned untyped blocks and places one capability per
//! block in the root task's CNode. From then on, all memory — including the
//! memory for kernel objects — is allocated by user space retyping those
//! capabilities.

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use spin::Mutex;
use superior_objects::cap::{CNode, Capability, Object, Rights};
use superior_objects::untyped::split_region;

pub const ROOT_CNODE_SLOTS: usize = 1024;
const LOW_MEMORY_END: u64 = 0x10_0000;

/// The root task's capability space. Owned by the kernel until the root
/// task starts.
/// Carves a `2^size_bits` byte block from the root task's untyped memory,
/// for the kernel to hand to a user thread as a fresh untyped capability.
pub fn carve(size_bits: u8) -> Option<u64> {
    let mut cnode = ROOT_CNODE.lock();
    (0..ROOT_CNODE_SLOTS).find_map(|slot| cnode.retype(slot, size_bits).ok())
}

pub static ROOT_CNODE: Mutex<CNode<ROOT_CNODE_SLOTS>> = Mutex::new(CNode::new());

pub struct Summary {
    pub regions: usize,
    pub untyped_caps: usize,
    pub usable_bytes: u64,
    pub largest_block_bits: u8,
    /// Usable memory that did not fit in the root CNode.
    pub dropped_bytes: u64,
}

pub fn init(regions: &MemoryRegions) -> Summary {
    let mut cnode = ROOT_CNODE.lock();
    let mut s = Summary {
        regions: 0,
        untyped_caps: 0,
        usable_bytes: 0,
        largest_block_bits: 0,
        dropped_bytes: 0,
    };
    let mut next_slot = 0usize;

    for r in regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        // Leave the first 1 MiB alone: on BIOS machines it holds firmware
        // structures that "usable" does not always protect.
        let start = r.start.max(LOW_MEMORY_END);
        if start >= r.end {
            continue;
        }
        s.regions += 1;
        split_region(start, r.end, |block| {
            s.usable_bytes += block.size();
            let cap = Capability::new(
                Object::Untyped {
                    base: block.base,
                    size_bits: block.size_bits,
                },
                Rights::ALL,
            );
            if cnode.insert_root(next_slot, cap).is_ok() {
                next_slot += 1;
                s.untyped_caps += 1;
                s.largest_block_bits = s.largest_block_bits.max(block.size_bits);
            } else {
                s.dropped_bytes += block.size();
            }
        });
    }
    s
}
