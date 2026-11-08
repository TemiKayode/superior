//! Untyped memory: physical memory handed out as naturally aligned
//! power-of-two blocks (the seL4 model).
//!
//! The kernel never allocates for itself. Every kernel object is made by
//! retyping an untyped block that some user-level component holds a
//! capability to, which makes memory accounting exact and kernel OOM
//! impossible.

/// Smallest block we hand out: one 4 KiB page.
pub const MIN_BITS: u8 = 12;
/// Largest block we hand out (128 TiB), well past any desktop's RAM.
pub const MAX_BITS: u8 = 47;

/// A naturally aligned block of physical memory: `base` is a multiple of
/// `1 << size_bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UntypedBlock {
    pub base: u64,
    pub size_bits: u8,
}

impl UntypedBlock {
    pub const fn size(&self) -> u64 {
        1u64 << self.size_bits
    }

    pub const fn end(&self) -> u64 {
        self.base + self.size()
    }
}

const fn align_up(x: u64, align: u64) -> u64 {
    (x + align - 1) & !(align - 1)
}

const fn align_down(x: u64, align: u64) -> u64 {
    x & !(align - 1)
}

/// Splits the physical range `[start, end)` into the fewest naturally
/// aligned power-of-two blocks, each at least one page, and calls `emit`
/// for each in ascending address order. Partial pages at either edge are
/// dropped. Returns the number of blocks emitted.
pub fn split_region(start: u64, end: u64, mut emit: impl FnMut(UntypedBlock)) -> usize {
    let page = 1u64 << MIN_BITS;
    let mut cur = align_up(start, page);
    let end = align_down(end, page);
    let mut count = 0;
    while cur < end {
        let align_bits = if cur == 0 {
            MAX_BITS as u32
        } else {
            cur.trailing_zeros()
        };
        let fit_bits = 63 - (end - cur).leading_zeros();
        let bits = align_bits.min(fit_bits).min(MAX_BITS as u32) as u8;
        let block = UntypedBlock {
            base: cur,
            size_bits: bits,
        };
        emit(block);
        count += 1;
        cur = block.end();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn split(start: u64, end: u64) -> Vec<UntypedBlock> {
        let mut v = Vec::new();
        split_region(start, end, |b| v.push(b));
        v
    }

    #[test]
    fn aligned_power_of_two_is_one_block() {
        assert_eq!(
            split(0x10_0000, 0x20_0000),
            [UntypedBlock {
                base: 0x10_0000,
                size_bits: 20
            }]
        );
    }

    #[test]
    fn blocks_are_aligned_contiguous_and_cover_range() {
        let (start, end) = (0x9_f000, 0x7fe_0000);
        let blocks = split(start, end);
        let mut cur = start;
        for b in &blocks {
            assert_eq!(b.base, cur, "contiguous");
            assert_eq!(b.base % b.size(), 0, "naturally aligned");
            assert!(b.size_bits >= MIN_BITS);
            cur = b.end();
        }
        assert_eq!(cur, end);
    }

    #[test]
    fn partial_pages_are_dropped() {
        let blocks = split(0x1001, 0x3fff);
        assert_eq!(
            blocks,
            [UntypedBlock {
                base: 0x2000,
                size_bits: 12
            }]
        );
    }

    #[test]
    fn sub_page_range_yields_nothing() {
        assert!(split(0x1000, 0x1fff).is_empty());
        assert!(split(0x5000, 0x5000).is_empty());
    }

    #[test]
    fn block_count_is_logarithmic() {
        // An awkward 4 GiB-ish range still needs only a few dozen blocks.
        let blocks = split(0x1000, 0xffff_f000);
        assert!(blocks.len() <= 2 * 32, "got {}", blocks.len());
    }
}
