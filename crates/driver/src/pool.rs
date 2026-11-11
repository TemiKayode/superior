//! DMA buffer pools: a fixed number of equal buffers the device can
//! reach, taken and given back in constant time.
//!
//! A [`Pool`] makes its pages once (each mapped for the driver and into
//! the device's IOMMU domain) and cuts them into buffers that never cross
//! a page, so every buffer has one device address. A driver takes a
//! buffer for a request and gives it back when the device has finished
//! with it; taking from an empty pool, or giving back what is not out,
//! is refused rather than undone later.

use crate::{DmaPage, Failure};

/// Which of `N` things are free: the bookkeeping of a [`Pool`], kept
/// apart so it can be tested on the host.
pub struct FreeList<const N: usize> {
    /// The free indexes, the last taken first.
    free: [u16; N],
    count: usize,
    out: [bool; N],
}

impl<const N: usize> Default for FreeList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FreeList<N> {
    /// All free.
    pub const fn new() -> Self {
        let mut free = [0; N];
        let mut i = 0;
        while i < N {
            // Index 0 is the first taken.
            free[i] = (N - 1 - i) as u16;
            i += 1;
        }
        FreeList {
            free,
            count: N,
            out: [false; N],
        }
    }

    pub fn free(&self) -> usize {
        self.count
    }

    /// Takes a free index.
    pub fn take(&mut self) -> Option<usize> {
        self.count = self.count.checked_sub(1)?;
        let i = self.free[self.count] as usize;
        self.out[i] = true;
        Some(i)
    }

    /// Gives `i` back. False (and nothing changes) if it is not out: a
    /// device naming a buffer twice must not put it in the pool twice.
    pub fn give(&mut self, i: usize) -> bool {
        if !self.out.get(i).copied().unwrap_or(false) {
            return false;
        }
        self.out[i] = false;
        self.free[self.count] = i as u16;
        self.count += 1;
        true
    }

    pub fn is_out(&self, i: usize) -> bool {
        self.out.get(i).copied().unwrap_or(false)
    }
}

/// One buffer of a pool: where the driver sees it and the address the
/// device uses for it.
#[derive(Clone, Copy)]
pub struct Buffer {
    pub index: usize,
    pub va: u64,
    pub dma: u64,
}

/// `N` DMA buffers of `size` bytes each.
pub struct Pool<const N: usize> {
    buffers: [(u64, u64); N],
    list: FreeList<N>,
    pub size: u64,
}

impl<const N: usize> Pool<N> {
    /// Makes the pool's pages from the untyped memory in `untyped`, into
    /// slots from `slot` (one a page), mapped from `va` and into the
    /// IOMMU domain in `domain`. `size` divides a page.
    pub fn new(untyped: u64, slot: u64, va: u64, domain: u64, size: u64) -> Result<Self, Failure> {
        if size == 0 || 4096 % size != 0 {
            return Err(("a pool's buffers must divide a page", size));
        }
        let per_page = (4096 / size) as usize;
        let mut buffers = [(0, 0); N];
        for (p, chunk) in buffers.chunks_mut(per_page).enumerate() {
            let p = p as u64;
            let page = DmaPage::new(untyped, slot + p, va + p * 4096, domain)?;
            for (k, b) in chunk.iter_mut().enumerate() {
                *b = (page.va + k as u64 * size, page.dma + k as u64 * size);
            }
        }
        Ok(Pool {
            buffers,
            list: FreeList::new(),
            size,
        })
    }

    /// Slots (and pages) a pool of `N` buffers of `size` bytes takes.
    pub const fn pages(size: u64) -> u64 {
        (N as u64 * size).div_ceil(4096)
    }

    /// Buffer `index`, free or not.
    pub fn buffer(&self, index: usize) -> Option<Buffer> {
        let &(va, dma) = self.buffers.get(index)?;
        Some(Buffer { index, va, dma })
    }

    /// Takes a free buffer.
    pub fn take(&mut self) -> Option<Buffer> {
        let i = self.list.take()?;
        self.buffer(i)
    }

    /// Gives buffer `index` back; false if it was not out.
    pub fn give(&mut self, index: usize) -> bool {
        self.list.give(index)
    }

    pub fn free(&self) -> usize {
        self.list.free()
    }
}

#[cfg(test)]
mod tests {
    use super::FreeList;

    #[test]
    fn every_index_once_then_none() {
        let mut l = FreeList::<5>::new();
        let mut seen = [false; 5];
        for left in (0..5).rev() {
            let i = l.take().unwrap();
            assert!(!seen[i] && l.is_out(i));
            seen[i] = true;
            assert_eq!(l.free(), left);
        }
        assert_eq!(l.take(), None);
        assert_eq!(l.take(), None);
        assert_eq!(l.free(), 0);
    }

    #[test]
    fn the_first_taken_is_index_0() {
        let mut l = FreeList::<4>::new();
        assert_eq!((l.take(), l.take()), (Some(0), Some(1)));
    }

    #[test]
    fn what_is_given_back_is_taken_next() {
        let mut l = FreeList::<4>::new();
        let (a, b) = (l.take().unwrap(), l.take().unwrap());
        assert!(l.give(a));
        assert_eq!(l.take(), Some(a));
        assert!(l.give(b) && l.give(a));
        assert_eq!(l.free(), 4);
    }

    #[test]
    fn giving_back_what_is_not_out_is_refused() {
        let mut l = FreeList::<3>::new();
        // Never taken, out of range, and given back twice.
        assert!(!l.give(1));
        assert!(!l.give(3));
        let a = l.take().unwrap();
        assert!(l.give(a));
        assert!(!l.give(a));
        assert_eq!(l.free(), 3);
        // The pool still holds each index once.
        let mut got = [l.take().unwrap(), l.take().unwrap(), l.take().unwrap()];
        got.sort();
        assert_eq!(got, [0, 1, 2]);
        assert_eq!(l.take(), None);
    }

    #[test]
    fn a_long_run_never_loses_or_doubles_a_buffer() {
        let mut l = FreeList::<8>::new();
        let mut out = [false; 8];
        let mut seed = 0x2545_f491u32;
        for _ in 0..10_000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            if seed & 1 == 0 {
                match l.take() {
                    Some(i) => {
                        assert!(!out[i]);
                        out[i] = true;
                    }
                    None => assert!(out.iter().all(|&o| o)),
                }
            } else {
                let i = (seed >> 8) as usize % 8;
                assert_eq!(l.give(i), out[i]);
                out[i] = false;
            }
            assert_eq!(l.free(), out.iter().filter(|&&o| !o).count());
        }
    }
}
