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

/// The root task's capability space. Owned by the kernel until the root
/// task starts.
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
        s.regions += 1;
        split_region(r.start, r.end, |block| {
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
