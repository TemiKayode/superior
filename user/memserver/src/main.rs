//! The Memory Server (spec sections 3 and 4): the pool of RAM components
//! draw pages from, under quotas the Component Manager sets.
//!
//! It holds a block of untyped memory and makes frames from it as they
//! are needed, keeping the original of every frame it hands out in its
//! own CSpace. So a page it gives can always be taken back: revoking the
//! original removes every copy and every mapping of it. Untyped memory
//! cannot be given back a page at a time, so a page that comes back is
//! zeroed and kept for the next request.
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
//! Slots: 0 the `mem` endpoint (receive), 1 the pool (untyped memory), 2
//! where the manager's lent address space arrives. Pages are kept from
//! [`FIRST_PAGE`] to the end of the CSpace. `arg`: CSpace size in bits,
//! plus the pool's size in bits shifted left by 8.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, MAP_WRITE, ObjectType, Syscall};
use superior_objects::interfaces::{Status, mem};
use superior_objects::pages::{self, FIRST_PAGE, Frames};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const SERVICE: u64 = 0;
const POOL: u64 = 1;
const VSPACE: u64 = 2;
const MAX_SLOTS: usize = 1 << superior_objects::manifest::CSPACE_MAX_BITS;
const MAX_CLIENTS: usize = superior_objects::manifest::MAX_COMPONENTS + 1;
/// Where a page is mapped while it is zeroed.
const SCRATCH_VA: u64 = USER_BASE + 0x4000_0000;
const PAGE: u64 = 4096;
/// Every right, for the copies of a page's original (a byte mask).
const ALL_RIGHTS: u64 = 0x1f;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("mem: {}", format_args!($($t)*))) };
}

/// The kernel, as the page bookkeeping in `superior_objects::pages` sees
/// it: system calls on this server's own CSpace.
struct Kernel;

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> u64 {
    syscall(nr, a0, m).status
}

impl Frames for Kernel {
    fn make(&mut self, s: u64) -> bool {
        sys(Syscall::Retype, POOL, [ObjectType::Frame as u64, 0, s, 0]) == 0
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

type Server = pages::Server<Kernel, MAX_SLOTS, MAX_CLIENTS>;

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let cspace_bits = (arg & 0xff).min(superior_objects::manifest::CSPACE_MAX_BITS as u64);
    let pool_bits = arg >> 8 & 0xff;
    let pool = if pool_bits >= 12 { 1 << (pool_bits - 12) } else { 0 };
    // Static: the books are too big for the stack.
    static mut SERVER: Option<Server> = None;
    // SAFETY: this thread is the server's only one; set once, here.
    let srv = unsafe { (*(&raw mut SERVER)).insert(Server::new(Kernel, 1 << cspace_bits, pool)) };
    say!(
        "pool of {} pages, room for {} at once",
        pool,
        srv.slots().end - FIRST_PAGE
    );
    let accept = CapTransfer {
        grant: None,
        accept: Some(VSPACE as u16),
    };
    let mut r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
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
