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
//!
//! Slots: 0 the `mem` endpoint (receive), 1 the pool (untyped memory), 2
//! where the manager's lent address space arrives. Pages are kept from
//! [`FIRST_PAGE`] to the end of the CSpace. `arg`: CSpace size in bits,
//! plus the pool's size in bits shifted left by 8.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, MAP_WRITE, ObjectType, Syscall};
use superior_objects::interfaces::{Status, mem};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const SERVICE: u64 = 0;
const POOL: u64 = 1;
const VSPACE: u64 = 2;
const FIRST_PAGE: u64 = 8;
const MAX_SLOTS: usize = 1 << superior_objects::manifest::CSPACE_MAX_BITS;
const MAX_CLIENTS: usize = superior_objects::manifest::MAX_COMPONENTS + 1;
/// Where a page is mapped while it is zeroed.
const SCRATCH_VA: u64 = USER_BASE + 0x4000_0000;
const PAGE: u64 = 4096;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("mem: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    /// Not made yet.
    Unmade,
    /// Made, zeroed, nobody's.
    Free,
    /// Mapped in the owner's heap (by this server's original).
    Heap(u16),
    /// Granted to the owner.
    Given(u16),
}

struct Server {
    pages: [Page; MAX_SLOTS],
    /// Slots in use for pages: FIRST_PAGE..end.
    end: u64,
    /// Pages the pool can still make.
    pool_left: u64,
    used: [u64; MAX_CLIENTS],
}

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> u64 {
    syscall(nr, a0, m).status
}

impl Server {
    /// A zeroed page nobody holds, made if need be.
    fn take(&mut self) -> Option<u64> {
        if let Some(s) = (FIRST_PAGE..self.end).find(|&s| self.pages[s as usize] == Page::Free) {
            return Some(s);
        }
        if self.pool_left == 0 {
            return None;
        }
        let s = (FIRST_PAGE..self.end).find(|&s| self.pages[s as usize] == Page::Unmade)?;
        // Fresh frames come zeroed from the kernel.
        if sys(Syscall::Retype, POOL, [ObjectType::Frame as u64, 0, s, 0]) != 0 {
            self.pool_left = 0;
            return None;
        }
        self.pool_left -= 1;
        self.pages[s as usize] = Page::Free;
        Some(s)
    }

    fn free_pages(&self) -> u64 {
        let free = (FIRST_PAGE..self.end)
            .filter(|&s| self.pages[s as usize] == Page::Free)
            .count() as u64;
        let unmade = (FIRST_PAGE..self.end)
            .filter(|&s| self.pages[s as usize] == Page::Unmade)
            .count() as u64;
        free + self.pool_left.min(unmade)
    }

    /// Takes page `s` back from whoever has it: every copy and mapping
    /// goes, and it is zeroed for the next owner.
    fn reclaim(&mut self, s: u64) {
        sys(Syscall::FrameUnmap, s, [0; 4]);
        sys(Syscall::CapRevoke, s, [0; 4]);
        if sys(Syscall::FrameMap, s, [SCRATCH_VA, 1, 0, 0]) == 0 {
            // SAFETY: the page was just mapped at SCRATCH_VA, writable.
            unsafe { core::ptr::write_bytes(SCRATCH_VA as *mut u8, 0, PAGE as usize) };
            sys(Syscall::FrameUnmap, s, [0; 4]);
            self.pages[s as usize] = Page::Free;
        } else {
            say!("[fail] could not zero page {s}; it is retired");
        }
    }

    /// Charges a page to `client` if its quota allows.
    fn charge(&mut self, client: u64, quota: u64) -> Result<u64, Status> {
        let c = client as usize;
        if c == 0 || c >= MAX_CLIENTS {
            return Err(Status::Invalid);
        }
        if self.used[c] >= quota {
            return Err(Status::Denied);
        }
        let s = self.take().ok_or(Status::InUse)?;
        self.used[c] += 1;
        Ok(s)
    }

    fn info(&self, client: u64, quota: u64) -> [u64; 4] {
        let used = self.used.get(client as usize).copied().unwrap_or(0);
        [Status::Ok as u64, quota, used, self.free_pages()]
    }

    fn frame(&mut self, client: u64, quota: u64) -> Result<u64, Status> {
        let s = self.charge(client, quota)?;
        self.pages[s as usize] = Page::Given(client as u16);
        Ok(s)
    }

    fn free(&mut self, client: u64, handle: u64) -> Status {
        if !(FIRST_PAGE..self.end).contains(&handle)
            || self.pages[handle as usize] != Page::Given(client as u16)
        {
            return Status::Invalid;
        }
        self.reclaim(handle);
        self.used[client as usize] -= 1;
        Status::Ok
    }

    /// Maps a zeroed page at `addr` in the lent address space.
    fn fault(&mut self, client: u64, quota: u64, addr: u64, lent: bool) -> Status {
        if !lent {
            return Status::Invalid;
        }
        let s = match self.charge(client, quota) {
            Ok(s) => s,
            Err(e) => {
                say!("client {client}: heap page refused ({quota} pages is its quota)");
                return e;
            }
        };
        let va = addr & !(PAGE - 1);
        if sys(Syscall::FrameMapInto, s, [va, MAP_WRITE, VSPACE, 0]) != 0 {
            self.used[client as usize] -= 1;
            return Status::Invalid;
        }
        self.pages[s as usize] = Page::Heap(client as u16);
        Status::Ok
    }

    fn release(&mut self, client: u64) -> u64 {
        let mut n = 0;
        for s in FIRST_PAGE..self.end {
            if matches!(self.pages[s as usize], Page::Heap(o) | Page::Given(o) if o as u64 == client)
            {
                self.reclaim(s);
                n += 1;
            }
        }
        if let Some(u) = self.used.get_mut(client as usize) {
            *u = 0;
        }
        n
    }

    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], Option<u64>) {
        let status = |s: Status| ([s as u64, 0, 0, 0], None);
        let manager = badge == 0;
        let (client, quota) = mem::from_badge(badge);
        match m[0] {
            mem::INFO if m[1] == mem::VERSION && !manager => (self.info(client, quota), None),
            mem::FRAME if !manager => match self.frame(client, quota) {
                Ok(s) => ([Status::Ok as u64, s, 0, 0], Some(s)),
                Err(e) => status(e),
            },
            mem::FREE if !manager => status(self.free(client, m[1])),
            mem::FAULT if manager => status(self.fault(m[1], m[2], m[3], lent)),
            mem::RELEASE if manager => ([Status::Ok as u64, self.release(m[1]), 0, 0], None),
            mem::FAULT | mem::RELEASE => status(Status::Denied),
            _ => status(Status::Invalid),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let cspace_bits = (arg & 0xff).min(superior_objects::manifest::CSPACE_MAX_BITS as u64);
    let pool_bits = arg >> 8 & 0xff;
    let mut srv = Server {
        pages: [Page::Unmade; MAX_SLOTS],
        end: 1 << cspace_bits,
        pool_left: if pool_bits >= 12 {
            1 << (pool_bits - 12)
        } else {
            0
        },
        used: [0; MAX_CLIENTS],
    };
    say!(
        "pool of {} pages, room for {} at once",
        srv.pool_left,
        srv.end - FIRST_PAGE
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
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
