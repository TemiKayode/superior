//! The Memory Server (spec sections 3 and 4): the pool of RAM components
//! draw pages from, under quotas the Component Manager sets.
//!
//! It holds untyped memory, all the RAM the kernel and the Component
//! Manager do not keep (`untyped spare` in its manifest, plus a block of
//! its own), and makes frames from it as they are needed, keeping the
//! original of every frame it hands out in its own CSpace. So a page it
//! gives can always be taken back: revoking the original removes every
//! copy and every mapping of it. Untyped memory cannot be given back a
//! page at a time, so a page that comes back is zeroed and kept for the
//! next request.
//!
//! - A component's capability is badged with its number and its quota
//!   (`mem::badge`), so it cannot claim more. `FRAME` grants a zeroed
//!   page; `FREE` takes one back; `INFO` reports quota and use.
//! - Heaps: the Component Manager, every component's fault handler, asks
//!   (`FAULT`, lending the component's address space) for a zeroed page
//!   where a component touched its heap, charged to its quota.
//! - `RELEASE`: the manager stops a component, and every page it held
//!   comes back.
//! - Copy-on-write cloning: `SHARE` makes a component's heap pages
//!   read-only and shared; `CLONE` maps them, read-only, at the same
//!   addresses in another component (a copy of each page's original
//!   capability per mapping, so revoking the original still takes every
//!   one). A write faults, and `FAULT` gives the writer its own copy, or
//!   the frame itself once no one else maps it. Each mapping is charged to
//!   its holder, so breaking the sharing never needs more quota.
//!
//! Its books (`superior_objects::pages`) take a few bytes a slot, more
//! than its image can hold for a CSpace sized to RAM, so it makes pages
//! for them from the pool first and maps them at [`BOOKS_VA`].
//!
//! Slots: 0 the `mem` endpoint (receive), 1 a pool block of its own
//! (untyped memory), 2 where the manager's lent address space arrives, 3
//! a page being granted whose own slot is past what a transfer can name,
//! [`SPARE`] on the spare blocks, then the books' pages, then pages to the
//! end of the CSpace. `arg`: the CSpace's size in bits.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, MAP_WRITE, ObjectType, Syscall, root};
use superior_objects::interfaces::{Status, mem};
use superior_objects::pages::{self, Book, Frames};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const SERVICE: u64 = 0;
const POOL: u64 = 1;
const VSPACE: u64 = 2;
const GRANT: u64 = 3;
/// The spare blocks, as many as the manager had (the rest empty).
const SPARE: u64 = 8;
const SPARE_COUNT: u64 = root::SPARE_COUNT;
/// The books' pages, then the pages handed out.
const BOOK_PAGES: u64 = SPARE + SPARE_COUNT;
const MAX_CLIENTS: usize = superior_objects::manifest::MAX_COMPONENTS + 1;
/// Where a page is mapped while it is zeroed.
const SCRATCH_VA: u64 = USER_BASE + 0x4000_0000;
/// Where the books are mapped.
const BOOKS_VA: u64 = USER_BASE + 0x5000_0000;
const PAGE: u64 = 4096;
/// Every right, for the copies of a page's original (a byte mask).
const ALL_RIGHTS: u64 = 0x1f;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("mem: {}", format_args!($($t)*))) };
}

/// The kernel, as the page bookkeeping in `superior_objects::pages` sees
/// it: system calls on this server's own CSpace. Pages are made from the
/// pool blocks in turn.
struct Kernel {
    pools: [u64; 1 + SPARE_COUNT as usize],
    count: usize,
    /// The block pages are made from now; the ones before are spent.
    current: usize,
}

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> u64 {
    syscall(nr, a0, m).status
}

/// The pool block in `slot`: its pages still free, if it is one.
fn free_pages(slot: u64) -> Option<u64> {
    let r = syscall(Syscall::UntypedInfo, slot, [0; 4]);
    (r.status == 0).then_some(r.msg[1] / PAGE)
}

impl Frames for Kernel {
    fn make(&mut self, s: u64) -> bool {
        while self.current < self.count {
            let block = self.pools[self.current];
            if sys(Syscall::Retype, block, [ObjectType::Frame as u64, 0, s, 0]) == 0 {
                return true;
            }
            self.current += 1;
        }
        false
    }
    fn map_lent(&mut self, s: u64, va: u64, writable: bool) -> bool {
        let flags = if writable { MAP_WRITE } else { 0 };
        sys(Syscall::FrameMapInto, s, [va, flags, VSPACE, 0]) == 0
    }
    fn unmap(&mut self, s: u64) {
        sys(Syscall::FrameUnmap, s, [0; 4]);
    }
    fn revoke(&mut self, s: u64) {
        sys(Syscall::CapRevoke, s, [0; 4]);
    }
    fn delete(&mut self, s: u64) {
        sys(Syscall::CapDelete, s, [0; 4]);
    }
    fn copy_cap(&mut self, from: u64, to: u64) -> bool {
        sys(Syscall::CapMint, from, [to, ALL_RIGHTS, 0, 0]) == 0
    }
    fn zero(&mut self, s: u64) -> bool {
        if sys(Syscall::FrameMap, s, [SCRATCH_VA, 1, 0, 0]) != 0 {
            say!("[fail] could not zero page {s}; it is retired");
            return false;
        }
        // SAFETY: the page was just mapped at SCRATCH_VA, writable.
        unsafe { core::ptr::write_bytes(SCRATCH_VA as *mut u8, 0, PAGE as usize) };
        sys(Syscall::FrameUnmap, s, [0; 4]);
        true
    }
    fn copy_page(&mut self, from: u64, to: u64) -> bool {
        let src = SCRATCH_VA + PAGE;
        let ok = sys(Syscall::FrameMap, from, [src, 0, 0, 0]) == 0
            && sys(Syscall::FrameMap, to, [SCRATCH_VA, 1, 0, 0]) == 0;
        if ok {
            // SAFETY: both pages were just mapped here, `to` writable.
            unsafe {
                core::ptr::copy_nonoverlapping(src as *const u8, SCRATCH_VA as *mut u8, PAGE as usize)
            };
        }
        sys(Syscall::FrameUnmap, from, [0; 4]);
        sys(Syscall::FrameUnmap, to, [0; 4]);
        ok
    }
}

type Server = pages::Server<'static, Kernel, MAX_CLIENTS>;

/// Finds the pool blocks, makes and maps pages for the books, and builds
/// the server over the rest of the CSpace.
fn start(cspace_bits: u64) -> Result<Server, &'static str> {
    let mut k = Kernel {
        pools: [0; 1 + SPARE_COUNT as usize],
        count: 0,
        current: 0,
    };
    let mut pool = 0;
    for slot in [POOL].into_iter().chain(SPARE..SPARE + SPARE_COUNT) {
        if let Some(n) = free_pages(slot) {
            k.pools[k.count] = slot;
            k.count += 1;
            pool += n;
        }
    }
    let slots = 1u64 << cspace_bits;
    if slots <= BOOK_PAGES {
        return Err("a CSpace too small for any page");
    }
    // Books for every slot past the books' own pages: sized for all of
    // them past BOOK_PAGES, which is a little more than will be needed.
    let most = (slots - BOOK_PAGES) as usize;
    let books_bytes = (most * Server::BOOK_BYTES).next_multiple_of(8);
    let bytes = books_bytes + Server::index_len(most) * 4;
    let book_pages = (bytes as u64).div_ceil(PAGE);
    let first = BOOK_PAGES + book_pages;
    if first >= slots || book_pages > pool {
        return Err("no room for the books");
    }
    for p in 0..book_pages {
        let s = BOOK_PAGES + p;
        if !k.make(s) || sys(Syscall::FrameMap, s, [BOOKS_VA + p * PAGE, 1, 0, 0]) != 0 {
            return Err("could not make the books' pages");
        }
    }
    let n = (slots - first) as usize;
    // SAFETY: the pages just made are mapped there, writable, zeroed, this
    // thread's alone, and kept for its whole life; the books and the index
    // lie in them without overlapping (the books take at most
    // `books_bytes`), each 8-aligned.
    let (books, index) = unsafe {
        (
            core::slice::from_raw_parts_mut(BOOKS_VA as *mut Book, n),
            core::slice::from_raw_parts_mut(
                (BOOKS_VA + books_bytes as u64) as *mut u32,
                Server::index_len(n),
            ),
        )
    };
    say!(
        "pool of {} pages ({} MiB) in {} blocks, room for {} at once (books in {} pages)",
        pool - book_pages,
        (pool - book_pages) * PAGE >> 20,
        k.count,
        n,
        book_pages
    );
    Ok(Server::new(k, books, index, first, pool - book_pages))
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let cspace_bits = (arg & 0xff).min(superior_objects::manifest::CSPACE_MAX_BITS as u64);
    let mut srv = match start(cspace_bits) {
        Ok(s) => s,
        Err(e) => {
            say!("[fail] {e}");
            superior_sys::park()
        }
    };
    let accept = CapTransfer {
        grant: None,
        accept: Some(VSPACE as u16),
    };
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        // The copy a grant went out through is not needed once it has.
        sys(Syscall::CapDelete, GRANT, [0; 4]);
        let (reply, grant) = if r.status == 0 {
            let lent = r.cap == Some(VSPACE as u16);
            let out = srv.serve(r.badge, r.msg, lent);
            if lent {
                sys(Syscall::CapDelete, VSPACE, [0; 4]);
            }
            if r.badge == 0 && r.msg[0] == mem::RELEASE && out.0[1] > 0 {
                say!(
                    "component {}: {} pages back in the pool",
                    r.msg[1],
                    out.0[1]
                );
            }
            let refused = [Status::Denied as u64, Status::InUse as u64].contains(&out.0[0]);
            if r.badge == 0 && r.msg[0] == mem::FAULT && refused {
                say!(
                    "client {}: heap page refused ({} pages is its quota)",
                    r.msg[1],
                    r.msg[2]
                );
            }
            out
        } else {
            ([Status::Invalid as u64, 0, 0, 0], None)
        };
        // A transfer names a slot in 16 bits: a page past that goes out
        // through a copy in GRANT, derived from its original, so revoking
        // the original still takes what the client got.
        let grant = match grant {
            Some(s) if s > u16::MAX as u64 => {
                (sys(Syscall::CapMint, s, [GRANT, ALL_RIGHTS, 0, 0]) == 0).then_some(GRANT)
            }
            g => g,
        };
        let x = CapTransfer {
            grant: grant.map(|s| s as u16),
            accept: Some(VSPACE as u16),
        };
        r = syscall_x(Syscall::ReplyRecv, SERVICE, reply, x);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
