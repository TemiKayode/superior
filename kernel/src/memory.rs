//! Boot-time memory hand-off.
//!
//! The kernel keeps no heap. At boot the architecture code reports each
//! usable physical region, and this module turns it into naturally aligned
//! untyped blocks, one capability per block in the root CNode. From then on
//! all memory, including memory for kernel objects and page tables, is
//! allocated by retyping those capabilities.

use spin::Mutex;
use superior_objects::cap::{CNode, Capability, Object, Rights};
use superior_objects::untyped::split_region;

pub const ROOT_CNODE_SLOTS: usize = 1024;

/// The root task's capability space, owned by the kernel.
pub static ROOT_CNODE: Mutex<CNode<ROOT_CNODE_SLOTS>> = Mutex::new(CNode::new());

/// Carves a `2^size_bits` byte block from the root task's untyped memory,
/// for the kernel to hand to a user thread as a fresh untyped capability.
pub fn carve(size_bits: u8) -> Option<u64> {
    let mut cnode = ROOT_CNODE.lock();
    (0..ROOT_CNODE_SLOTS).find_map(|slot| cnode.retype(slot, size_bits).ok())
}

/// The root task's arena: one block carved once, from which the kernel
/// makes everything of the root task's own (its page tables, the pages of
/// its image, stack and boot bundle). A fast reboot destroys the root task
/// and hands the whole arena out again, from the start, to the next one.
struct Arena {
    start: u64,
    next: u64,
    end: u64,
    /// Kernel-built address spaces take their pages from here (while the
    /// root task is being built).
    on: bool,
}

static ARENA: Mutex<Arena> = Mutex::new(Arena {
    start: 0,
    next: 0,
    end: 0,
    on: false,
});

/// Size of the root task's arena, in bits.
pub const ARENA_BITS: u8 = 23;

/// Carves the root task's arena, once: before spare RAM is given away
/// (see [`take_spare`]), so that a block of its size, aligned, is still
/// whole. UEFI firmware leaves RAM in many more pieces than a BIOS does.
/// False if there is no memory for it.
pub fn reserve_arena() -> bool {
    let mut a = ARENA.lock();
    if a.end == 0 {
        let Some(base) = carve(ARENA_BITS) else {
            return false;
        };
        a.start = base;
        a.end = base + (1 << ARENA_BITS);
    }
    true
}

/// Starts (or, after a fast reboot, starts again) handing out the root
/// task's arena: from now until [`arena_off`], [`user_page`] takes pages
/// from it. False if there is no memory for it.
pub fn arena_on() -> bool {
    if !reserve_arena() {
        return false;
    }
    let mut a = ARENA.lock();
    a.next = a.start;
    a.on = true;
    true
}

/// Whether the root task is being built (see [`arena_on`]).
pub fn arena_active() -> bool {
    ARENA.lock().on
}

pub fn arena_off() {
    ARENA.lock().on = false;
}

/// A page from the root task's arena (not zeroed).
pub fn arena_page() -> Option<u64> {
    let mut a = ARENA.lock();
    if a.next >= a.end {
        return None;
    }
    let pa = a.next;
    a.next += 4096;
    Some(pa)
}

/// A page (not zeroed) for an address space the kernel builds: from the
/// root task's arena while it is being built, else from the root CNode.
pub fn user_page() -> Option<u64> {
    if ARENA.lock().on {
        return arena_page();
    }
    carve(12)
}

#[derive(Default)]
pub struct Summary {
    pub regions: usize,
    pub untyped_caps: usize,
    pub usable_bytes: u64,
    pub largest_block_bits: u8,
    /// Usable memory that did not fit in the root CNode.
    pub dropped_bytes: u64,
}

/// The usable RAM ranges reported at boot, so the kernel can tell a frame
/// of RAM from one of device memory.
const MAX_RAM_RANGES: usize = 16;
static RAM: Mutex<([(u64, u64); MAX_RAM_RANGES], usize)> =
    Mutex::new(([(0, 0); MAX_RAM_RANGES], 0));

/// Bytes of usable RAM reported at boot.
pub fn ram_bytes() -> u64 {
    let ram = RAM.lock();
    ram.0[..ram.1].iter().map(|&(s, e)| e - s).sum()
}

/// Whether the page at `pa` is usable RAM.
pub fn is_ram(pa: u64) -> bool {
    let ram = RAM.lock();
    ram.0[..ram.1].iter().any(|&(s, e)| (s..e).contains(&pa))
}

/// Places the usable physical range `[start, end)` in the root CNode.
pub fn add_region(s: &mut Summary, start: u64, end: u64) {
    if start >= end {
        return;
    }
    {
        let mut ram = RAM.lock();
        let n = ram.1;
        if n < MAX_RAM_RANGES {
            ram.0[n] = (start, end);
            ram.1 = n + 1;
        }
    }
    let mut cnode = ROOT_CNODE.lock();
    s.regions += 1;
    split_region(start, end, |block| {
        s.usable_bytes += block.size();
        let cap = Capability::new(
            Object::Untyped {
                base: block.base,
                size_bits: block.size_bits,
            },
            Rights::ALL,
        );
        if cnode.insert_root(s.untyped_caps, cap).is_ok() {
            s.untyped_caps += 1;
            s.largest_block_bits = s.largest_block_bits.max(block.size_bits);
        } else {
            s.dropped_bytes += block.size();
        }
    });
}

/// Hands out what is left of RAM: every untyped block's uncarved part,
/// cut into naturally aligned blocks, each carved (so the kernel never
/// uses it) and passed to `out`, which says whether it took it. The first
/// blocks, `keep` bytes or more, stay with the kernel for its own later
/// needs. Returns the bytes handed out.
pub fn take_spare(keep: u64, mut out: impl FnMut(u64, u8) -> bool) -> u64 {
    let mut cnode = ROOT_CNODE.lock();
    let (mut kept, mut given, mut full) = (0, 0, false);
    for slot in 0..ROOT_CNODE_SLOTS {
        let Some((base, bits)) = cnode.get(slot).and_then(|c| c.object.untyped()) else {
            continue;
        };
        let free = cnode.untyped_free(slot).unwrap_or(0);
        if free < 4096 || full {
            continue;
        }
        if kept < keep {
            kept += free;
            continue;
        }
        let end = base + (1u64 << bits);
        split_region(end - free, end, |block| {
            if full || block.size_bits < 12 {
                return;
            }
            // Carved in order, so each lands exactly on its block.
            match cnode.retype(slot, block.size_bits) {
                Ok(pa) if pa == block.base && out(pa, block.size_bits) => given += block.size(),
                _ => full = true,
            }
        });
    }
    given
}

/// Where an address space's page tables come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TablePool {
    /// The root CNode's untyped memory: address spaces the kernel builds
    /// at boot.
    Kernel,
    /// The root task's arena (see [`arena_on`]): its own address space.
    Arena,
    /// Pages `next..end` of the address-space object's own memory, handed
    /// out in order. Nothing is freed until the whole object is.
    Own { next: u64, end: u64 },
}

impl TablePool {
    /// A zeroed 4 KiB frame for a page table, by physical address.
    pub fn alloc(&mut self, zero: impl Fn(u64)) -> Option<u64> {
        let pa = match self {
            TablePool::Kernel => user_page()?,
            TablePool::Arena => arena_page()?,
            TablePool::Own { next, end } => {
                if *next >= *end {
                    return None;
                }
                let pa = *next;
                *next += 4096;
                pa
            }
        };
        zero(pa);
        Some(pa)
    }
}

/// Why mapping a frame failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Something is already mapped at the address.
    InUse,
    /// No memory for an intermediate page table.
    OutOfMemory,
}
