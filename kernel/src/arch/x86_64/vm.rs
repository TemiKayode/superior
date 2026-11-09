//! Address spaces and the user ELF loader.
//!
//! Every page-table frame and every user page comes from untyped memory in
//! the root CNode (retyped one page at a time), never from a kernel heap.
//!
//! User code lives in one 512 GiB window: PML4 slot [`USER_PML4_INDEX`].
//! Each new address space copies the kernel's other PML4 entries
//! (supervisor-only), so the kernel is mapped everywhere and user code
//! cannot touch it.

pub use crate::memory::MapError;
use crate::memory::{TablePool, ROOT_CNODE, ROOT_CNODE_SLOTS};
use superior_objects::elf::{Elf, Machine};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    mapper::MapToError, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags as F, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

pub const USER_PML4_INDEX: usize = 224;
pub const USER_BASE: u64 = (USER_PML4_INDEX as u64) << 39; // 0x7000_0000_0000
pub const USER_END: u64 = USER_BASE + (1 << 39);
pub const USER_STACK_TOP: u64 = USER_BASE + 0x8000_0000;
const USER_STACK_PAGES: u64 = 16;
const PAGE: u64 = 4096;

static mut PHYS_OFFSET: u64 = 0;
/// The kernel's own PML4 (the boot page tables), which every address
/// space copies its kernel half from.
static mut KERNEL_PML4: u64 = 0;

pub fn init(physical_memory_offset: u64) {
    // SAFETY: written once at boot before any other use.
    unsafe {
        (&raw mut PHYS_OFFSET).write(physical_memory_offset);
        (&raw mut KERNEL_PML4).write(Cr3::read().0.start_address().as_u64());
    }
}

fn kernel_pml4() -> PhysFrame {
    // SAFETY: only written once, in init.
    PhysFrame::containing_address(PhysAddr::new(unsafe { (&raw const KERNEL_PML4).read() }))
}

fn phys_offset() -> u64 {
    // SAFETY: only written once, in init.
    unsafe { (&raw const PHYS_OFFSET).read() }
}

/// The kernel's pointer to physical address `pa` (RAM or a mapped
/// device page).
pub fn phys_ptr(pa: u64) -> *mut u8 {
    phys_to_virt(PhysAddr::new(pa))
}

fn phys_to_virt(pa: PhysAddr) -> *mut u8 {
    (phys_offset() + pa.as_u64()) as *mut u8
}

/// Hands out zeroed 4 KiB frames by retyping untyped caps in the root CNode.
pub struct UntypedFrames;

// SAFETY: retype never returns the same memory twice, and frames are
// zeroed before use.
unsafe impl FrameAllocator<Size4KiB> for UntypedFrames {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut cnode = ROOT_CNODE.lock();
        let pa = (0..ROOT_CNODE_SLOTS).find_map(|slot| cnode.retype(slot, 12).ok())?;
        let frame = PhysFrame::containing_address(PhysAddr::new(pa));
        // SAFETY: the frame is fresh untyped memory, mapped at PHYS_OFFSET.
        unsafe { core::ptr::write_bytes(phys_to_virt(frame.start_address()), 0, PAGE as usize) };
        Some(frame)
    }
}

/// Hands out page-table frames from an address space's [`TablePool`].
struct PoolFrames<'a>(&'a mut TablePool);

// SAFETY: the pool hands out each frame once, zeroed.
unsafe impl FrameAllocator<Size4KiB> for PoolFrames<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let pa = self.0.alloc(zero_frame)?;
        Some(PhysFrame::containing_address(PhysAddr::new(pa)))
    }
}

/// An address space: the physical frame of its PML4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace(pub PhysFrame);

impl AddressSpace {
    pub fn new() -> Result<Self, &'static str> {
        let frame = UntypedFrames
            .allocate_frame()
            .ok_or("out of memory for PML4")?;
        Self::new_in(frame.start_address().as_u64())
    }

    /// Builds an address space whose top-level table is the frame at `pa`
    /// (owned by the caller, zeroed here).
    pub fn new_in(pa: u64) -> Result<Self, &'static str> {
        zero_frame(pa);
        let frame = PhysFrame::containing_address(PhysAddr::new(pa));
        let kernel_pml4 = kernel_pml4();
        // SAFETY: both frames are page tables mapped through PHYS_OFFSET.
        let (new, kernel) = unsafe { (table(frame), table(kernel_pml4)) };
        if !kernel[USER_PML4_INDEX].is_unused() {
            return Err("kernel already uses the user PML4 slot");
        }
        for i in 0..512 {
            if i != USER_PML4_INDEX {
                new[i] = kernel[i].clone();
            }
        }
        Ok(AddressSpace(frame))
    }

    fn mapper(&self) -> OffsetPageTable<'static> {
        // SAFETY: the PML4 frame belongs to this address space and all
        // physical memory is mapped at PHYS_OFFSET.
        unsafe { OffsetPageTable::new(table(self.0), VirtAddr::new(phys_offset())) }
    }

    /// Returns the frame backing `page`, mapping a fresh zeroed one with
    /// `flags` if it is not mapped yet.
    fn ensure_page(&self, page: Page, flags: F) -> Result<PhysFrame, &'static str> {
        let mut mapper = self.mapper();
        if let Ok(frame) = mapper.translate_page(page) {
            return Ok(frame);
        }
        let frame = UntypedFrames
            .allocate_frame()
            .ok_or("out of memory for user page")?;
        let parent = F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE;
        // SAFETY: the page is in the user window and unmapped; the frame is fresh.
        unsafe {
            mapper
                .map_to_with_table_flags(page, frame, flags, parent, &mut UntypedFrames)
                .map_err(|_| "mapping user page failed")?
                .ignore(); // not the active address space yet: no TLB entry to flush
        }
        Ok(frame)
    }

    /// Maps the segments of a static x86-64 ELF executable and returns its
    /// entry point. All segments must land inside the user window.
    /// Position-independent images are loaded at [`USER_BASE`] and relocated.
    pub fn load_elf(&self, image: &[u8]) -> Result<u64, &'static str> {
        let elf = Elf::parse(image).map_err(|_| "user image is not a valid static ELF")?;
        if elf.machine != Machine::X86_64 {
            return Err("user image is not for x86-64");
        }
        let bias = if elf.pie { USER_BASE } else { 0 };
        let entry = elf.entry.wrapping_add(bias);
        if !(USER_BASE..USER_END).contains(&entry) {
            return Err("entry point outside user window");
        }
        for seg in elf.segments() {
            let seg = seg.map_err(|_| "malformed ELF segment")?;
            if seg.mem_size == 0 {
                continue;
            }
            let vaddr = seg
                .vaddr
                .checked_add(bias)
                .ok_or("segment address overflows")?;
            if vaddr < USER_BASE || vaddr + seg.mem_size > USER_END {
                return Err("segment outside user window");
            }
            let mut flags = F::PRESENT | F::USER_ACCESSIBLE;
            if seg.writable {
                flags |= F::WRITABLE;
            }
            if !seg.executable {
                flags |= F::NO_EXECUTE;
            }
            let bytes = elf.file_bytes(&seg);
            let first = vaddr & !(PAGE - 1);
            let last = (vaddr + seg.mem_size + PAGE - 1) & !(PAGE - 1);
            for page_va in (first..last).step_by(PAGE as usize) {
                let page = Page::containing_address(VirtAddr::new(page_va));
                let frame = self.ensure_page(page, flags)?;
                // Copy the part of the file bytes that lands in this page.
                let lo = page_va.max(vaddr);
                let hi = (page_va + PAGE).min(vaddr + seg.file_size);
                if lo < hi {
                    let src = &bytes[(lo - vaddr) as usize..(hi - vaddr) as usize];
                    let dst = phys_to_virt(frame.start_address() + (lo - page_va));
                    // SAFETY: dst..dst+len lies within the frame just mapped.
                    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
                }
            }
        }
        // Apply relocations after every segment is in place, writing
        // through the physical map so read-only targets work too.
        let relocs = elf
            .relocations()
            .map_err(|_| "unsupported ELF relocations")?;
        for r in relocs {
            let target = r.offset.checked_add(bias).ok_or("relocation overflows")?;
            let value = r.addend.wrapping_add(bias);
            self.copy_to_user(target, &value.to_le_bytes())
                .map_err(|_| "relocation target not mapped")?;
        }
        Ok(entry)
    }

    /// Maps a read-only, non-executable copy of `data` at page-aligned `va`.
    pub fn map_data(&self, va: u64, data: &[u8]) -> Result<(), &'static str> {
        let flags = F::PRESENT | F::USER_ACCESSIBLE | F::NO_EXECUTE;
        for (i, chunk) in data.chunks(PAGE as usize).enumerate() {
            let page = Page::containing_address(VirtAddr::new(va + i as u64 * PAGE));
            let frame = self.ensure_page(page, flags)?;
            // SAFETY: the frame was just mapped and is PAGE bytes long.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    phys_to_virt(frame.start_address()),
                    chunk.len(),
                )
            };
        }
        Ok(())
    }

    /// Maps a zeroed, non-executable stack ending at [`USER_STACK_TOP`],
    /// with an unmapped guard page below it. Returns the stack top.
    pub fn map_stack(&self) -> Result<u64, &'static str> {
        let flags = F::PRESENT | F::USER_ACCESSIBLE | F::WRITABLE | F::NO_EXECUTE;
        for i in 1..=USER_STACK_PAGES {
            let page = Page::containing_address(VirtAddr::new(USER_STACK_TOP - i * PAGE));
            self.ensure_page(page, flags)?;
        }
        Ok(USER_STACK_TOP)
    }

    /// Copies user memory into `buf`, checking every page is mapped in the
    /// user window. Never dereferences a user pointer directly.
    pub fn copy_from_user(&self, va: u64, buf: &mut [u8]) -> Result<(), ()> {
        self.for_user_range(va, buf.len(), |kva, done, n| {
            // SAFETY: kva..kva+n lies within one mapped frame.
            unsafe { core::ptr::copy_nonoverlapping(kva, buf[done..].as_mut_ptr(), n) }
        })
    }

    /// Copies `data` into user memory at `va`, same checks as
    /// [`copy_from_user`](Self::copy_from_user).
    pub fn copy_to_user(&self, va: u64, data: &[u8]) -> Result<(), ()> {
        self.for_user_range(va, data.len(), |kva, done, n| {
            // SAFETY: kva..kva+n lies within one mapped frame.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), kva, n) }
        })
    }

    /// Calls `f(kernel_ptr, offset, len)` for each page-sized piece of the
    /// user range `[va, va + len)`.
    fn for_user_range(
        &self,
        va: u64,
        len: usize,
        mut f: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), ()> {
        let end = va.checked_add(len as u64).ok_or(())?;
        if va < USER_BASE || end > USER_END {
            return Err(());
        }
        let mapper = self.mapper();
        let mut done = 0usize;
        while done < len {
            let cur = va + done as u64;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(cur));
            let frame = mapper.translate_page(page).map_err(|_| ())?;
            let in_page = (cur % PAGE) as usize;
            let n = (PAGE as usize - in_page).min(len - done);
            f(
                phys_to_virt(frame.start_address() + in_page as u64),
                done,
                n,
            );
            done += n;
        }
        Ok(())
    }

    pub fn activate(&self) {
        let (current, flags) = Cr3::read();
        if current != self.0 {
            // SAFETY: the address space maps the kernel identically.
            unsafe { Cr3::write(self.0, flags) };
        }
    }
}

/// Zeroes the 4 KiB frame at `pa`, so memory handed to a new owner never
/// carries a previous owner's data.
pub fn zero_frame(pa: u64) {
    // SAFETY: all physical memory is mapped at PHYS_OFFSET, and the caller
    // owns this frame (just carved from untyped memory).
    unsafe { core::ptr::write_bytes(phys_to_virt(PhysAddr::new(pa)), 0, PAGE as usize) };
}

impl AddressSpace {
    /// Maps the frame at `pa` at user address `va` (page-aligned, in the
    /// user window), writable or executable but never both. Intermediate
    /// page tables come from `pool`.
    pub fn map_frame(
        &self,
        va: u64,
        pa: u64,
        writable: bool,
        executable: bool,
        pool: &mut TablePool,
    ) -> Result<(), MapError> {
        debug_assert!(!(writable && executable));
        debug_assert!(va.is_multiple_of(PAGE) && (USER_BASE..USER_END).contains(&va));
        let mut mapper = self.mapper();
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        if mapper.translate_page(page).is_ok() {
            return Err(MapError::InUse);
        }
        let frame = PhysFrame::containing_address(PhysAddr::new(pa));
        let mut flags = F::PRESENT | F::USER_ACCESSIBLE;
        if writable {
            flags |= F::WRITABLE;
        }
        if !executable {
            flags |= F::NO_EXECUTE;
        }
        let parent = F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE;
        // SAFETY: the page is in the user window and unmapped; the frame
        // is a user frame object, never kernel memory.
        let flush = unsafe {
            mapper
                .map_to_with_table_flags(page, frame, flags, parent, &mut PoolFrames(pool))
                .map_err(|e| match e {
                    MapToError::FrameAllocationFailed => MapError::OutOfMemory,
                    _ => MapError::InUse,
                })?
        };
        // A new mapping needs no flush (nothing was cached for it).
        flush.ignore();
        Ok(())
    }

    /// Removes the mapping at user address `va`, flushing the TLB entry if
    /// this address space is the active one. (Other address spaces have no
    /// cached user entries: switching CR3 flushes non-global entries.)
    pub fn unmap(&self, va: u64) {
        let mut mapper = self.mapper();
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        if let Ok((_, flush)) = mapper.unmap(page) {
            if Cr3::read().0 == self.0 {
                flush.flush();
            } else {
                flush.ignore();
            }
        }
    }
}

/// Makes the 4 KiB device page at `pa` reachable at `PHYS_OFFSET + pa` in
/// the kernel's page tables (uncached, not executable, supervisor only)
/// and returns that address. The bootloader maps only RAM there, so
/// device memory usually needs a new mapping.
///
/// Call before creating address spaces: they copy the kernel's top-level
/// entries, so a mapping that needs a new top-level table would be missed.
pub fn map_mmio(pa: PhysAddr) -> Result<VirtAddr, &'static str> {
    use x86_64::structures::paging::Translate;
    let va = VirtAddr::new(phys_offset() + pa.as_u64());
    let (kernel_pml4, _) = Cr3::read();
    // SAFETY: the active PML4, with physical memory mapped at PHYS_OFFSET.
    let mut mapper =
        unsafe { OffsetPageTable::new(table(kernel_pml4), VirtAddr::new(phys_offset())) };
    if mapper.translate_addr(va).is_some() {
        return Ok(va);
    }
    let page = Page::<Size4KiB>::containing_address(va);
    let frame = PhysFrame::containing_address(pa);
    let flags = F::PRESENT | F::WRITABLE | F::NO_CACHE | F::WRITE_THROUGH | F::NO_EXECUTE;
    // SAFETY: the page was unmapped, and the frame is device memory that
    // nothing else maps.
    unsafe {
        mapper
            .map_to_with_table_flags(
                page,
                frame,
                flags,
                F::PRESENT | F::WRITABLE,
                &mut UntypedFrames,
            )
            .map_err(|_| "mapping device memory failed")?
            .flush();
    }
    Ok(va)
}

/// # Safety
/// `frame` must hold a page table and physical memory must be mapped at PHYS_OFFSET.
unsafe fn table(frame: PhysFrame) -> &'static mut PageTable {
    unsafe { &mut *(phys_to_virt(frame.start_address()) as *mut PageTable) }
}
