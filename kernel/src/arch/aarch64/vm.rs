//! Address spaces, page tables and the user ELF loader for AArch64.
//!
//! The kernel's tables, built in `_start` before the MMU is on, map the
//! first GiB of physical memory (devices) and the second (RAM) with 1 GiB
//! blocks that only EL1 can touch, at [`KERNEL_OFFSET`] above where they
//! are. The kernel runs there, in the high half (TTBR1), which every
//! address space shares; the identity map the same tables give through
//! TTBR0 is only for the jump there at boot. An address space is a
//! top-level table for the low half (TTBR0), all of it user space: its
//! entry [`USER_L0_INDEX`] is the user window, the same 512 GiB at the same
//! address as on x86-64, and entry 0 the low one ([`LOW_BASE`]).
//!
//! Page tables and user pages are retyped from untyped memory in the root
//! CNode, never from a kernel heap. The kernel reaches any physical page at
//! [`phys_ptr`].

use crate::memory::{MapError, TablePool};
use superior_objects::elf::{Elf, Machine};

pub const USER_L0_INDEX: usize = 224;
pub const USER_BASE: u64 = (USER_L0_INDEX as u64) << 39; // 0x7000_0000_0000
pub const USER_END: u64 = USER_BASE + (1 << 39);
pub const USER_STACK_TOP: u64 = USER_BASE + 0x8000_0000;

/// The low user window: the first 512 GiB but its first 64 KiB (as
/// Linux's `mmap_min_addr`, so a null pointer always faults), where
/// fixed-address programs are linked (4 MiB, usually). Like the window at
/// [`USER_BASE`], each address space has its own.
pub const LOW_BASE: u64 = 0x1_0000;
pub const LOW_END: u64 = 1 << 39;

/// Whether `va` is in a user window.
pub fn is_user(va: u64) -> bool {
    (LOW_BASE..LOW_END).contains(&va) || (USER_BASE..USER_END).contains(&va)
}

/// Whether `va..end` lies inside one user window (`end` may be its end).
pub fn is_user_range(va: u64, end: u64) -> bool {
    va <= end && (LOW_BASE <= va && end <= LOW_END || USER_BASE <= va && end <= USER_END)
}
/// The root task's stack: 256 KiB (the Component Manager keeps its state,
/// manifests included, on it).
const USER_STACK_PAGES: u64 = 64;
const PAGE: u64 = 4096;
/// Where the kernel sees physical address 0: the start of the high half.
pub const KERNEL_OFFSET: u64 = 0xffff_0000_0000_0000;
/// The kernel maps RAM only in the second GiB.
pub const KERNEL_RAM: core::ops::Range<u64> = 0x4000_0000..0x8000_0000;

// Descriptor bits.
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // at levels 0-2; at level 3, "page"
const ATTR_DEVICE: u64 = 0 << 2;
const ATTR_NORMAL: u64 = 1 << 2;
const AP_EL0: u64 = 1 << 6; // user accessible
const AP_RO: u64 = 1 << 7;
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

/// The kernel's identity map: devices below 1 GiB, RAM from 1 GiB to 2 GiB.
pub const KERNEL_DEVICE_BLOCK: u64 = VALID | ATTR_DEVICE | AF | PXN | UXN;
pub const KERNEL_RAM_BLOCK: u64 = 0x4000_0000 | VALID | ATTR_NORMAL | SH_INNER | AF | UXN;
/// Attribute 0: Device-nGnRE; attribute 1: Normal, write-back, allocating.
pub const MAIR: u64 = 0xff04;
/// T0SZ and T1SZ = 16 (48-bit VAs in each half), inner/outer write-back
/// walks, inner shareable, 4 KiB granules, IPS = 40 bits.
pub const TCR: u64 = 16
    | (1 << 8)
    | (1 << 10)
    | (3 << 12)
    | (16 << 16)
    | (1 << 24)
    | (1 << 26)
    | (3 << 28)
    | (2 << 30)
    | (2 << 32);
/// MMU, D- and I-caches, SP alignment checks at EL1 and EL0; EL0 may use
/// `dc zva`, read CTR_EL0, do cache maintenance; `wfe` from EL0 is allowed
/// but `wfi` traps (nTWI clear). Bits 11, 20, 22, 23, 28, 29 are RES1.
pub const SCTLR: u64 = (1 << 0)
    | (1 << 2)
    | (1 << 3)
    | (1 << 4)
    | (1 << 11)
    | (1 << 12)
    | (1 << 14)
    | (1 << 15)
    | (1 << 18)
    | (1 << 20)
    | (1 << 22)
    | (1 << 23)
    | (1 << 26)
    | (1 << 28)
    | (1 << 29);

#[repr(C, align(4096))]
pub struct Table([u64; 512]);

#[no_mangle]
pub static mut KERNEL_L0: Table = Table([0; 512]);
#[no_mangle]
pub static mut KERNEL_L1: Table = Table([0; 512]);

/// RAM reported by the device tree (clipped to what the kernel maps):
/// frames outside it are device memory.
static mut RAM: (u64, u64) = (0, 0);

/// Records a RAM range from the device tree.
pub fn note_ram(start: u64, end: u64) {
    let (start, end) = (start.max(KERNEL_RAM.start), end.min(KERNEL_RAM.end));
    // SAFETY: written only at boot, single-threaded.
    unsafe {
        let r = &raw mut RAM;
        let (s, e) = r.read();
        r.write(if s == e {
            (start, end)
        } else {
            (s.min(start), e.max(end))
        });
    }
}

fn is_ram(pa: u64) -> bool {
    // SAFETY: only written at boot.
    let (s, e) = unsafe { (&raw const RAM).read() };
    (s..e).contains(&pa)
}

fn dsb() {
    // SAFETY: a barrier has no other effect.
    unsafe { core::arch::asm!("dsb ish", options(nostack)) };
}

/// The top-level table this CPU has loaded.
pub fn current_root() -> u64 {
    let v: u64;
    // SAFETY: reading TTBR0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) v, options(nostack, nomem)) };
    v
}

/// Loads the kernel's own tables (no user window), dropping what the TLB
/// held of the previous ones.
pub fn load_kernel_root() {
    let l0 = core::ptr::addr_of!(KERNEL_L0) as u64 - KERNEL_OFFSET;
    // SAFETY: the kernel runs in the high half, the same in every space.
    unsafe { core::arch::asm!("msr ttbr0_el1, {}", "isb", in(reg) l0, options(nostack)) };
    flush_tlb();
}

/// Drops this CPU's TLB entries.
pub fn flush_local() {
    flush_tlb();
}

fn flush_tlb() {
    // SAFETY: invalidating the TLB only forces fresh table walks.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            options(nostack)
        )
    };
}

/// A zeroed 4 KiB frame retyped from the root CNode's untyped memory.
fn alloc_frame() -> Option<u64> {
    let pa = crate::memory::user_page()?;
    zero_frame(pa);
    Some(pa)
}

/// Zeroes the 4 KiB frame at `pa`, so memory handed to a new owner never
/// carries a previous owner's data.
/// Maps the GiB holding device `pa` into the kernel's identity map, as
/// device memory (the first GiB is from boot). False if it cannot be: in
/// the GiB of RAM, or beyond the first 512 GiB, which one top-level entry
/// covers.
pub fn map_device(pa: u64) -> bool {
    let i = (pa >> 30) as usize;
    if i >= 512 || (KERNEL_RAM.start >> 30..KERNEL_RAM.end >> 30).contains(&(i as u64)) {
        return false;
    }
    // SAFETY: the kernel's own table; an entry is only ever set from
    // invalid, by the boot CPU before others start or under the
    // scheduler's lock (rtc), and to the same block whoever sets it.
    unsafe {
        let l1 = &raw mut KERNEL_L1;
        if (*l1).0[i] & VALID == 0 {
            (*l1).0[i] = (i as u64) << 30 | KERNEL_DEVICE_BLOCK;
            core::arch::asm!("dsb ishst", "isb", options(nostack));
        }
    }
    true
}

/// The kernel's pointer to physical address `pa`: RAM and devices (those
/// [`map_device`] has mapped) are at [`KERNEL_OFFSET`] above it.
pub fn phys_ptr(pa: u64) -> *mut u8 {
    (pa + KERNEL_OFFSET) as *mut u8
}

pub fn zero_frame(pa: u64) {
    // SAFETY: the kernel maps RAM, and the caller owns the frame.
    unsafe { core::ptr::write_bytes(phys_ptr(pa), 0, PAGE as usize) };
}

/// # Safety
/// `pa` must be a page-table frame.
unsafe fn table(pa: u64) -> &'static mut [u64; 512] {
    unsafe { &mut *(phys_ptr(pa) as *mut [u64; 512]) }
}

/// An address space: the physical address of its top-level table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace(pub u64);

impl AddressSpace {
    pub fn new() -> Result<Self, &'static str> {
        let pa = alloc_frame().ok_or("out of memory for a top-level table")?;
        Self::new_in(pa)
    }

    /// Builds an address space whose top-level table is the frame at `pa`
    /// (owned by the caller, zeroed here): nothing of the kernel's, which
    /// is in the other half.
    pub fn new_in(pa: u64) -> Result<Self, &'static str> {
        zero_frame(pa);
        dsb();
        Ok(AddressSpace(pa))
    }

    /// The level-3 entry for `va`, creating tables from `pool` on the way
    /// if one is given.
    fn entry(
        &self,
        va: u64,
        mut pool: Option<&mut TablePool>,
    ) -> Result<Option<*mut u64>, MapError> {
        let mut t = self.0;
        for shift in [39u32, 30, 21] {
            let i = ((va >> shift) & 511) as usize;
            // SAFETY: `t` is one of this address space's table frames.
            let e = unsafe { &mut table(t)[i] };
            if *e & VALID == 0 {
                let Some(pool) = pool.as_deref_mut() else {
                    return Ok(None);
                };
                let new = pool.alloc(zero_frame).ok_or(MapError::OutOfMemory)?;
                *e = new | VALID | TABLE;
            } else if *e & TABLE == 0 {
                return Err(MapError::InUse); // a block mapping
            }
            t = *e & ADDR_MASK;
        }
        // SAFETY: as above.
        Ok(Some(unsafe {
            &mut table(t)[((va >> 12) & 511) as usize] as *mut u64
        }))
    }

    fn translate(&self, va: u64) -> Option<u64> {
        let e = self.entry(va, None).ok()??;
        // SAFETY: a valid entry pointer from `entry`.
        let d = unsafe { *e };
        (d & VALID != 0).then_some(d & ADDR_MASK)
    }

    fn map(&self, va: u64, pa: u64, desc_bits: u64, pool: &mut TablePool) -> Result<(), MapError> {
        let e = self.entry(va, Some(pool))?.ok_or(MapError::OutOfMemory)?;
        // SAFETY: a valid entry pointer from `entry`.
        unsafe {
            if *e & VALID != 0 {
                return Err(MapError::InUse);
            }
            *e = (pa & ADDR_MASK) | desc_bits;
        }
        dsb();
        Ok(())
    }

    /// User page bits: normal memory unless `pa` is a device, never
    /// executable by the kernel.
    fn user_bits(pa: u64, writable: bool, executable: bool) -> u64 {
        let mut b = VALID | TABLE | AP_EL0 | AF | NG | PXN;
        b |= if is_ram(pa) {
            ATTR_NORMAL | SH_INNER
        } else {
            ATTR_DEVICE | UXN
        };
        if !writable {
            b |= AP_RO;
        }
        if !executable {
            b |= UXN;
        }
        b
    }

    /// The frame backing `va`, mapping a fresh zeroed one if needed.
    fn ensure_page(&self, va: u64, writable: bool, executable: bool) -> Result<u64, &'static str> {
        if let Some(pa) = self.translate(va) {
            return Ok(pa);
        }
        let pa = alloc_frame().ok_or("out of memory for user page")?;
        self.map(
            va,
            pa,
            Self::user_bits(pa, writable, executable),
            &mut TablePool::Kernel,
        )
        .map_err(|_| "mapping user page failed")?;
        Ok(pa)
    }

    /// Maps the segments of a static AArch64 ELF executable and returns its
    /// entry point; see the x86-64 loader.
    pub fn load_elf(&self, image: &[u8]) -> Result<u64, &'static str> {
        let elf = Elf::parse(image).map_err(|_| "user image is not a valid static ELF")?;
        if elf.machine != Machine::Aarch64 {
            return Err("user image is not for AArch64");
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
            let bytes = elf.file_bytes(&seg);
            let first = vaddr & !(PAGE - 1);
            let last = (vaddr + seg.mem_size + PAGE - 1) & !(PAGE - 1);
            for page_va in (first..last).step_by(PAGE as usize) {
                let pa = self.ensure_page(page_va, seg.writable, seg.executable)?;
                let lo = page_va.max(vaddr);
                let hi = (page_va + PAGE).min(vaddr + seg.file_size);
                if lo < hi {
                    let src = &bytes[(lo - vaddr) as usize..(hi - vaddr) as usize];
                    let dst = phys_ptr(pa + (lo - page_va));
                    // SAFETY: dst..dst+len lies within the frame just mapped.
                    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
                }
                if seg.executable {
                    sync_icache(pa);
                }
            }
        }
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

    /// Maps a zeroed, non-executable stack ending at [`USER_STACK_TOP`],
    /// with an unmapped guard page below it.
    pub fn map_stack(&self) -> Result<u64, &'static str> {
        for i in 1..=USER_STACK_PAGES {
            self.ensure_page(USER_STACK_TOP - i * PAGE, true, false)?;
        }
        Ok(USER_STACK_TOP)
    }

    pub fn copy_from_user(&self, va: u64, buf: &mut [u8]) -> Result<(), ()> {
        self.for_user_range(va, buf.len(), |kva, done, n| {
            // SAFETY: kva..kva+n lies within one mapped frame.
            unsafe { core::ptr::copy_nonoverlapping(kva, buf[done..].as_mut_ptr(), n) }
        })
    }

    pub fn copy_to_user(&self, va: u64, data: &[u8]) -> Result<(), ()> {
        self.for_user_range(va, data.len(), |kva, done, n| {
            // SAFETY: kva..kva+n lies within one mapped frame.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), kva, n) }
        })
    }

    fn for_user_range(
        &self,
        va: u64,
        len: usize,
        mut f: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), ()> {
        let end = va.checked_add(len as u64).ok_or(())?;
        if !is_user_range(va, end) {
            return Err(());
        }
        let mut done = 0usize;
        while done < len {
            let cur = va + done as u64;
            let pa = self.translate(cur & !(PAGE - 1)).ok_or(())?;
            if !is_ram(pa) {
                return Err(()); // never copy through device memory
            }
            let in_page = (cur % PAGE) as usize;
            let n = (PAGE as usize - in_page).min(len - done);
            f(phys_ptr(pa + in_page as u64), done, n);
            done += n;
        }
        Ok(())
    }

    /// The physical address of the top-level table.
    pub fn root_pa(&self) -> u64 {
        self.0
    }

    pub fn activate(&self) {
        let cur: u64;
        // SAFETY: reading TTBR0 has no side effect.
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) cur, options(nostack, nomem)) };
        if cur != self.0 {
            // SAFETY: the kernel is in the high half, not in any space.
            unsafe {
                core::arch::asm!("msr ttbr0_el1, {}", "isb", in(reg) self.0, options(nostack))
            };
            // No ASIDs: drop the previous space's user entries.
            flush_tlb();
        }
    }

    /// Maps the frame at `pa` at user address `va`, writable or executable
    /// but never both; device memory (never executable) if `pa` is not
    /// RAM. Intermediate tables come from `pool`.
    pub fn map_frame(
        &self,
        va: u64,
        pa: u64,
        writable: bool,
        executable: bool,
        pool: &mut TablePool,
    ) -> Result<(), MapError> {
        debug_assert!(va.is_multiple_of(PAGE) && is_user(va));
        debug_assert!(!(writable && executable));
        if executable && is_ram(pa) {
            // The loader wrote the code through its own mapping.
            sync_icache(pa);
        }
        self.map(va, pa, Self::user_bits(pa, writable, executable), pool)
    }

    /// Maps a read-only, non-executable copy of `data` at page-aligned `va`.
    pub fn map_data(&self, va: u64, data: &[u8]) -> Result<(), &'static str> {
        for (i, chunk) in data.chunks(PAGE as usize).enumerate() {
            let pa = self.ensure_page(va + i as u64 * PAGE, false, false)?;
            // SAFETY: the frame was just mapped and is PAGE bytes long.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_ptr(pa), chunk.len()) };
        }
        Ok(())
    }

    /// Removes the mapping at user address `va`.
    pub fn unmap(&self, va: u64) {
        if let Ok(Some(e)) = self.entry(va, None) {
            // SAFETY: a valid entry pointer from `entry`.
            unsafe { *e = 0 };
            flush_tlb();
        }
    }
}

/// Makes code just written to the frame at `pa` visible to instruction
/// fetch: clean the data cache to the point of unification, then
/// invalidate the instruction cache.
fn sync_icache(pa: u64) {
    const LINE: u64 = 64;
    let va = phys_ptr(pa) as u64;
    for a in (va..va + PAGE).step_by(LINE as usize) {
        // SAFETY: cleaning a cache line changes no memory contents.
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) a, options(nostack)) };
    }
    // Every CPU's instruction cache (inner shareable): another CPU may
    // run the code next.
    // SAFETY: invalidating the instruction cache only forces refetches.
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack)) };
}
