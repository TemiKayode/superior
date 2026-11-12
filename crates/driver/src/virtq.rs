//! Split virtqueues (virtio 1.x, section 2.7), laid out in one DMA page:
//! the descriptor table, then the driver ("available") ring, then the
//! device ("used") ring. One request in flight at a time is all v1 needs.

use crate::{DmaPage, dma_barrier};

/// Entries in the queue (the device may offer more; we use this many).
pub const SIZE: u16 = 16;
const DESC: u64 = 0;
const AVAIL: u64 = 16 * SIZE as u64;
const USED: u64 = 512;
const _: () = assert!(AVAIL + 6 + 2 * SIZE as u64 <= USED);
const _: () = assert!(USED + 6 + 8 * SIZE as u64 <= 4096);

/// Descriptor flags.
pub const NEXT: u16 = 1;
pub const WRITE: u16 = 2;

pub struct Queue {
    page: DmaPage,
    next_avail: u16,
    last_used: u16,
}

impl Queue {
    /// A queue in `page` (zeroed: rings start empty).
    pub fn new(page: DmaPage) -> Queue {
        Queue {
            page,
            next_avail: 0,
            last_used: 0,
        }
    }

    /// Empties the queue for a device starting afresh (after a reset):
    /// zeroes its page and starts its counts again.
    pub fn reset(&mut self) {
        // SAFETY: the queue owns its whole page, mapped at `page.va`.
        unsafe { core::ptr::write_bytes(self.page.va as *mut u8, 0, 4096) };
        self.next_avail = 0;
        self.last_used = 0;
    }

    /// The addresses to give the device: (descriptors, driver ring,
    /// device ring).
    pub fn addresses(&self) -> (u64, u64, u64) {
        let d = self.page.dma;
        (d + DESC, d + AVAIL, d + USED)
    }

    fn at<T>(&self, off: u64) -> *mut T {
        (self.page.va + off) as *mut T
    }

    /// Fills descriptor `i`: `addr`, `len` bytes, `flags`, chained to
    /// `i + 1` if `flags` has [`NEXT`].
    pub fn set(&mut self, i: u16, addr: u64, len: u32, flags: u16) {
        let d = DESC + 16 * i as u64;
        // SAFETY: descriptor `i < SIZE` lies in the queue page.
        unsafe {
            self.at::<u64>(d).write_volatile(addr);
            self.at::<u32>(d + 8).write_volatile(len);
            self.at::<u16>(d + 12).write_volatile(flags);
            self.at::<u16>(d + 14).write_volatile(i + 1);
        }
    }

    /// Offers the chain starting at descriptor `head` to the device.
    pub fn submit(&mut self, head: u16) {
        let slot = self.next_avail % SIZE;
        // SAFETY: ring entries are inside the queue page.
        unsafe {
            self.at::<u16>(AVAIL + 4 + 2 * slot as u64)
                .write_volatile(head);
            dma_barrier();
            self.next_avail = self.next_avail.wrapping_add(1);
            self.at::<u16>(AVAIL + 2).write_volatile(self.next_avail);
        }
        dma_barrier();
    }

    /// Asks the device to interrupt (or not) when it finishes a chain: a
    /// hint (`VIRTQ_AVAIL_F_NO_INTERRUPT`), so look at the ring again
    /// after asking for interrupts.
    pub fn interrupts(&mut self, on: bool) {
        // SAFETY: the flags word starts the driver ring, in the queue page.
        unsafe { self.at::<u16>(AVAIL).write_volatile(!on as u16) };
        dma_barrier();
    }

    /// Whether the device has finished a chain not yet taken.
    pub fn has_used(&self) -> bool {
        dma_barrier();
        // SAFETY: as in `submit`.
        unsafe { self.at::<u16>(USED + 2).read_volatile() != self.last_used }
    }

    /// The next chain the device finished, if any: (head, bytes written).
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        // SAFETY: as in `submit`.
        let idx = unsafe { self.at::<u16>(USED + 2).read_volatile() };
        if idx == self.last_used {
            return None;
        }
        dma_barrier();
        let e = USED + 4 + 8 * (self.last_used % SIZE) as u64;
        self.last_used = self.last_used.wrapping_add(1);
        // SAFETY: as in `submit`.
        unsafe {
            Some((
                self.at::<u32>(e).read_volatile() as u16,
                self.at::<u32>(e + 4).read_volatile(),
            ))
        }
    }
}
