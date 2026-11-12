//! The Component Manager: Superior's root task.
//!
//! The kernel starts this one program, with every capability the system
//! has (memory, the timer, the console UART and its interrupt, QEMU's exit
//! device) and the boot bundle mapped read-only. Everything else is a
//! component it builds from the manifest in that bundle (spec section 4):
//!
//! - **Its own address space and CSpace.** Each component instance gets
//!   an untyped block of its own (`memory` bits), and everything the
//!   instance is made of is retyped from it: an address-space object, a
//!   64-slot CNode, a thread, the frames its executable is loaded into,
//!   its stack. Revoking that block destroys the instance completely.
//! - **Only the capabilities its manifest names**, placed in the slots it
//!   names: services it provides or uses, devices, notifications, untyped
//!   memory, and a control endpoint to the manager.
//! - **Endpoints outlive instances.** The manager makes every service
//!   endpoint itself and keeps the original. A provider gets a copy of
//!   the receive side; each client a copy badged with its own number.
//! - **Lazy start (the launchd model).** A `start lazy` component is not
//!   started at boot. A watcher thread waits on each of its service
//!   endpoints; the first call wakes it, it asks the manager to start the
//!   component, then forwards the call (under the client's badge) and
//!   relays the reply, so the first client never sees the difference.
//! - **Faults come here.** Every component's fault handler is the
//!   manager's control endpoint, badged with its number.
//! - **Supervision.** A component that faults is restarted by its
//!   `restart` policy: `one-for-one` rebuilds just it; `rest-for-one`
//!   also rebuilds every running component after it in the manifest;
//!   `never` leaves it stopped. Rebuilding revokes the instance's untyped
//!   block (the kernel fails any call it was serving with
//!   `PeerRestarted`) and builds a new instance from the same block,
//!   attached to the same endpoints. More than five restarts within
//!   sixty seconds and the manager gives up: the component stays down and
//!   a tombstone answers its services with `SERVICE_UNAVAILABLE`, so
//!   clients fail fast instead of hanging.
//! - **State is external.** A `state` capability is component `i`'s page
//!   of the kernel's state store (`root::STATE_STORE + i`), handed to
//!   every instance, so a new instance finds what the last one wrote (a
//!   journal of the requests it applied, say), even after a fast reboot.
//! - **Memory.** The component providing `mem` is the Memory Server. A
//!   component's capability to it carries the component's `quota` in its
//!   badge. A page fault in a component's `heap` is not a crash: the
//!   manager asks the Memory Server for a zeroed page there (lending it
//!   the component's address space) and resumes the thread, unless the
//!   quota is spent. Stopping a component gives every page it held back
//!   to the Memory Server first. The Memory Server itself cannot be
//!   restarted in place (spec section 4).
//! - **Fast reboot.** If the Memory Server fails, the manager asks the
//!   kernel for a fast reboot (`Reboot`); if the manager itself fails, the
//!   kernel does it unasked. Either way every object is destroyed and this
//!   program starts again from the boot bundle, rebuilding every
//!   component; the state store keeps its contents, so state survives.
//! - **Copy-on-write clones.** A component may ask (`OP_CLONE`) for a
//!   `start clone` component with the same image to be started with a
//!   copy-on-write copy of its heap: the Memory Server makes the sender's
//!   heap pages read-only and maps them in the clone too, and the first
//!   write to a page by either gives the writer its own copy. This is the
//!   address-space cloning a POSIX `fork` is built on; the clone runs from
//!   its entry with its own stack. A clone is not restarted.
//!
//! Capabilities from the kernel are in `superior_objects::abi::root`.

#![no_std]
#![no_main]

use superior_objects::abi::{
    CapTransfer, FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType, SERVICE_UNAVAILABLE,
    Syscall, TICK_HZ, root,
};
use superior_objects::bundle::{Bundle, BundleError};
use superior_objects::elf::{Elf, Machine};
use superior_objects::interfaces::{Status as Reply, mem, power};
use superior_objects::manifest::{CapKind, Component, MAX_COMPONENTS, Manifest, Restart, Start};
use superior_sys::{Ret, USER_BASE, syscall, syscall_x};

// Rights masks.
const READ: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;
const GRANT: u64 = 1 << 2;
const GRANT_REPLY: u64 = 1 << 3;
const ALL: u64 = 0x1f;

// ---- slots in the manager's own CSpace ---------------------------------

/// The control endpoint: reports, faults and watcher requests arrive here.
const CONTROL: u64 = root::FIRST_FREE;
/// Service endpoints, one per service in the manifest, in order.
const SERVICES: u64 = CONTROL + 8;
const MAX_SERVICES: usize = 32;
/// Watcher threads, one per service of a lazy component, with their
/// stacks, a scratch slot for forwarding, and their control capability.
const WATCHER_TCB: u64 = SERVICES + MAX_SERVICES as u64;
const WATCHER_STACK: u64 = WATCHER_TCB + MAX_SERVICES as u64;
const WATCHER_SCRATCH: u64 = WATCHER_STACK + 2 * MAX_SERVICES as u64;
const WATCHER_CONTROL: u64 = WATCHER_SCRATCH + MAX_SERVICES as u64;
/// Each component's fault-handler capability (control, badged).
const FAULT_CAP: u64 = WATCHER_CONTROL + MAX_SERVICES as u64;
/// Tombstone threads, one per service of a component given up on, and
/// their stacks.
const TOMB_TCB: u64 = FAULT_CAP + MAX_COMPONENTS as u64;
const TOMB_STACK: u64 = TOMB_TCB + MAX_SERVICES as u64;
/// Pages components share with servers (`shared`): made once, handed out
/// from here in manifest order, outliving every instance on both sides.
const SHARED_PAGES: u64 = TOMB_STACK + 2 * MAX_SERVICES as u64;
const SHARED_SLOTS: u64 = 128;
const _: () = assert!(SHARED_PAGES + SHARED_SLOTS <= BLOCKS);
/// Each component's block of slots: its untyped memory, then the objects
/// of its current instance.
const BLOCKS: u64 = 512;
const BLOCK: u64 = 96;
const B_UNTYPED: u64 = 0;
const B_VSPACE: u64 = 1;
const B_CNODE: u64 = 2;
const B_THREAD: u64 = 3;
const B_IMAGE: u64 = 4;
const IMAGE_PAGES: u64 = 76;
const B_STACK: u64 = B_IMAGE + IMAGE_PAGES;
const STACK_PAGES: u64 = 16;
const _: () = assert!(B_STACK + STACK_PAGES <= BLOCK);
const _: () = assert!(BLOCKS + BLOCK * MAX_COMPONENTS as u64 <= 1 << root::CNODE_BITS);

// ---- badges on the control endpoint ------------------------------------

const BADGE_REPORT: u64 = 0x100;
const BADGE_FAULT: u64 = 0x200;
const BADGE_WATCHER: u64 = 0x300;
/// Reports a component may send (msg[0]).
const OP_SHUTDOWN: u64 = 2;
/// `[OP_KILL, component index]`, from a `fault-injector` only: kill the
/// component as if it had crashed (supervision restarts it).
const OP_KILL: u64 = 3;
/// `[OP_CLONE, component index]`: start that component (`start clone`) as
/// a copy-on-write clone of the sender's heap. Reply `[status]`.
const OP_CLONE: u64 = 4;
/// `[OP_EXIT, failures]`: stop the sender for good (no restart).
const OP_EXIT: u64 = 5;
/// `[OP_CRASH_MANAGER]`, from a `fault-injector` only: the manager itself
/// faults (the kernel's fast reboot follows).
const OP_CRASH_MANAGER: u64 = 6;

// ---- the manager's own address space -----------------------------------

const BUNDLE_VA: u64 = USER_BASE + root::BUNDLE_OFFSET;
/// Where an executable being loaded is mapped while the manager writes it.
const SCRATCH_VA: u64 = USER_BASE + 0x2_0000_0000;
/// Watcher stacks, 64 KiB apart (two pages each, the rest unmapped).
const WATCHER_STACKS_VA: u64 = USER_BASE + 0x3_0000_0000;
/// Tombstone stacks, laid out the same way.
const TOMB_STACKS_VA: u64 = USER_BASE + 0x3_1000_0000;

// ---- in a component's address space ------------------------------------

const PAGE: u64 = 4096;
const STACK_TOP: u64 = USER_BASE + 0x8000_0000;

const WATCHER_PRIORITY: u64 = root::PRIORITY as u64 - 1;

// ---- restart intensity (spec section 4) ---------------------------------

/// More than this many restarts of one component...
const MAX_RESTARTS: usize = 5;
/// ...within this many ticks, and the manager gives up on it.
const RESTART_WINDOW: u64 = 60 * TICK_HZ;

// ---- system calls -------------------------------------------------------

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> Result<Ret, u64> {
    let r = syscall(nr, a0, m);
    if r.status == 0 { Ok(r) } else { Err(r.status) }
}

fn retype(ut: u64, ty: ObjectType, bits: u64, slot: u64) -> Result<(), u64> {
    sys(Syscall::Retype, ut, [ty as u64, bits, slot, 0]).map(drop)
}

/// Retypes into index `index` of the CNode in slot `cnode`.
fn retype_into(ut: u64, ty: ObjectType, bits: u64, cnode: u64, index: u64) -> Result<(), u64> {
    sys(Syscall::Retype, ut, [ty as u64, bits, index, cnode + 1]).map(drop)
}

fn cnode_copy(cnode: u64, index: u64, src: u64, mask: u64, badge: u64) -> Result<(), u64> {
    sys(Syscall::CNodeCopy, cnode, [index, src, mask, badge]).map(drop)
}

fn mint(src: u64, dst: u64, mask: u64, badge: u64) -> Result<(), u64> {
    sys(Syscall::CapMint, src, [dst, mask, badge, 0]).map(drop)
}

// ---- output -------------------------------------------------------------

macro_rules! say {
    ($($t:tt)*) => { superior_sys::print_line(format_args!("[cm] {}", format_args!($($t)*))) };
}

/// What failed, and the kernel's error code (0 if not a system call).
type Failure = (&'static str, u64);

// ---- state --------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    NotStarted,
    Running,
    Stopped,
    /// Given up on: too many restarts. Its services are tombstoned.
    Failed,
}

struct Manager<'a> {
    bundle: Bundle<'a>,
    manifest: Manifest<'a>,
    status: [Status; MAX_COMPONENTS],
    /// Services in manifest order: (name, providing component).
    services: [Option<(&'a str, usize)>; MAX_SERVICES],
    /// Whether the component's untyped block (and state page) exist yet.
    made: [bool; MAX_COMPONENTS],
    /// Where each component's shared pages start, once made.
    shared: [u64; MAX_COMPONENTS],
    /// The next free slot for shared pages.
    shared_next: u64,
    /// The ticks of each component's last [`MAX_RESTARTS`] restarts, as a
    /// ring indexed by the restart count.
    restarts: [[u64; MAX_RESTARTS]; MAX_COMPONENTS],
    restart_count: [usize; MAX_COMPONENTS],
}

impl<'a> Manager<'a> {
    fn service_index(&self, name: &str) -> Option<usize> {
        self.services
            .iter()
            .position(|s| matches!(s, Some((n, _)) if *n == name))
    }

    fn component(&self, i: usize) -> &Component<'a> {
        self.manifest.components[i].as_ref().unwrap()
    }

    /// Builds and starts an instance of component `i`.
    fn start(&mut self, i: usize) -> Result<(), Failure> {
        self.build(i)?;
        self.resume(i)
    }

    /// Starts the thread of component `i`, built by [`Manager::build`].
    fn resume(&mut self, i: usize) -> Result<(), Failure> {
        let tcb = BLOCKS + i as u64 * BLOCK + B_THREAD;
        sys(Syscall::ThreadResume, tcb, [0; 4]).map_err(|e| ("resume", e))?;
        self.status[i] = Status::Running;
        Ok(())
    }

    /// Builds an instance of component `i`, its thread not yet started.
    /// Its untyped block (and state page) are made the first time and
    /// kept: a later instance is built from the same block once
    /// [`Manager::stop`] has emptied it.
    fn build(&mut self, i: usize) -> Result<(), Failure> {
        let c = *self.component(i);
        let block = BLOCKS + i as u64 * BLOCK;
        let ut = block + B_UNTYPED;
        let (vspace, cnode, tcb) = (block + B_VSPACE, block + B_CNODE, block + B_THREAD);
        if !self.made[i] {
            retype(root::UNTYPED, ObjectType::Untyped, c.memory_bits as u64, ut)
                .map_err(|e| ("no memory for the component", e))?;
            if let Some(n) = c.caps().find_map(|x| match x.kind {
                CapKind::Shared(n) => Some(n as u64),
                _ => None,
            }) {
                if self.shared_next + n > SHARED_PAGES + SHARED_SLOTS {
                    return Err(("no room for shared pages", 0));
                }
                self.shared[i] = self.shared_next;
                for p in 0..n {
                    retype(root::UNTYPED, ObjectType::Frame, 0, self.shared_next + p)
                        .map_err(|e| ("no memory for shared pages", e))?;
                }
                self.shared_next += n;
            }
            self.made[i] = true;
        }
        // The CNode first: the largest object, aligned to its size, so a
        // big one (the Memory Server's) wastes none of the block.
        retype(ut, ObjectType::CNode, c.cspace_bits as u64, cnode).map_err(|e| ("CNode", e))?;
        retype(ut, ObjectType::AddressSpace, c.vspace_bits as u64, vspace)
            .map_err(|e| ("address space", e))?;
        retype(ut, ObjectType::Thread, 0, tcb).map_err(|e| ("thread", e))?;
        let image = self
            .bundle
            .get(c.image)
            .ok_or(("image not in the bundle", 0))?;
        let entry = load(image, ut, block, vspace)?;
        for p in 0..STACK_PAGES {
            let f = block + B_STACK + p;
            retype(ut, ObjectType::Frame, 0, f).map_err(|e| ("stack", e))?;
            map_into(f, STACK_TOP - (p + 1) * PAGE, MAP_WRITE, vspace).map_err(|e| ("stack", e))?;
        }
        for cap in c.caps() {
            let slot = cap.slot as u64;
            let r = match cap.kind {
                CapKind::Provides(s) => {
                    let ep = SERVICES + self.service_index(s).unwrap() as u64;
                    cnode_copy(cnode, slot, ep, READ | WRITE | GRANT_REPLY, 0)
                }
                CapKind::Uses(s) => {
                    let ep = SERVICES + self.service_index(s).unwrap() as u64;
                    // The Memory Server learns the client's quota from
                    // the badge, which the client cannot change.
                    let badge = if s == "mem" {
                        mem::badge(i, c.quota_pages)
                    } else {
                        i as u64 + 1
                    };
                    // Grant: a client may lend the server a capability
                    // (a buffer frame to DMA into, say).
                    cnode_copy(cnode, slot, ep, WRITE | GRANT | GRANT_REPLY, badge)
                }
                CapKind::Device(d) => match device(d) {
                    Some((src, count)) => {
                        let r = (0..count)
                            .try_for_each(|k| cnode_copy(cnode, slot + k, src + k, ALL, 0));
                        // A machine without an IOMMU has none to give: the
                        // slot stays empty, and the component copes.
                        if d == "iommu" || d == "intx" { Ok(()) } else { r }
                    }
                    None => return Err(("unknown device", 0)),
                },
                CapKind::Notification => retype_into(ut, ObjectType::Notification, 0, cnode, slot),
                CapKind::Untyped(bits) => {
                    retype_into(ut, ObjectType::Untyped, bits as u64, cnode, slot)
                }
                CapKind::Control => {
                    cnode_copy(cnode, slot, CONTROL, WRITE, BADGE_REPORT + i as u64)
                }
                CapKind::State => cnode_copy(cnode, slot, root::STATE_STORE + i as u64, ALL, 0),
                CapKind::Shared(n) => (0..n as u64)
                    .try_for_each(|p| cnode_copy(cnode, slot + p, self.shared[i] + p, ALL, 0)),
                // Each spare block the kernel gave, made over whole as a
                // child of the manager's, so stopping the component takes
                // it all back (`stop`).
                CapKind::Spare => (0..root::SPARE_COUNT)
                    .map_while(|k| {
                        let r = syscall(Syscall::UntypedInfo, root::SPARE + k, [0; 4]);
                        (r.status == 0).then_some((k, r.msg[0]))
                    })
                    .try_for_each(|(k, bits)| {
                        retype_into(root::SPARE + k, ObjectType::Untyped, bits, cnode, slot + k)
                    }),
            };
            r.map_err(|e| ("placing a capability", e))?;
        }
        sys(
            Syscall::ThreadConfigure,
            tcb,
            [entry, STACK_TOP, c.arg, c.priority as u64],
        )
        .map_err(|e| ("configuring the thread", e))?;
        sys(Syscall::ThreadSetVSpace, tcb, [vspace, 0, 0, 0])
            .map_err(|e| ("set address space", e))?;
        sys(Syscall::ThreadSetSpace, tcb, [cnode, 0, 0, 0]).map_err(|e| ("set CSpace", e))?;
        let fault = FAULT_CAP + i as u64;
        sys(Syscall::ThreadSetFaultHandler, tcb, [fault, 0, 0, 0])
            .map_err(|e| ("set fault handler", e))?;
        // Built: stopping it now must take its pages and objects back.
        self.status[i] = Status::Stopped;
        Ok(())
    }

    /// `[OP_CLONE, t]` from component `i`: starts component `t` (`start
    /// clone`, the same image and heap size) with a copy-on-write copy of
    /// `i`'s heap. Its image, stack and capabilities are its own, built
    /// fresh from the manifest; it runs from its entry with its own `arg`.
    fn clone_into(&mut self, i: usize, t: usize) -> Result<(), Reply> {
        let ok = t < MAX_COMPONENTS
            && t != i
            && self.manifest.components[t].is_some()
            && self.status[t] != Status::Running
            && self.status[t] != Status::Failed;
        if !ok {
            return Err(Reply::Invalid);
        }
        let (c, p) = (*self.component(t), *self.component(i));
        if c.start != Start::Clone || c.image != p.image || c.heap_pages != p.heap_pages {
            return Err(Reply::Denied);
        }
        let ep = self.memory_server().ok_or(Reply::Unreachable)?;
        if let Err((what, code)) = self.build(t) {
            say!("could not build {}: {what} (error {code})", c.name);
            self.stop(t);
            return Err(Reply::NoSpace);
        }
        let lend = |j: usize, m: [u64; 4]| {
            let vspace = BLOCKS + j as u64 * BLOCK + B_VSPACE;
            let x = CapTransfer {
                grant: Some(vspace as u16),
                accept: None,
            };
            let r = syscall_x(Syscall::Call, ep, m, x);
            match Reply::from_u64(r.msg[0]) {
                Reply::Ok if r.status == 0 => Ok(r.msg[1]),
                _ if r.status != 0 => Err(Reply::DeviceError),
                e => Err(e),
            }
        };
        let (pi, ti) = (i as u64 + 1, t as u64 + 1);
        let r = lend(i, [mem::SHARE, pi, 0, 0])
            .and_then(|_| lend(t, [mem::CLONE, pi, ti, c.quota_pages]));
        let pages = match r {
            Ok(n) => n,
            Err(e) => {
                self.stop(t);
                return Err(e);
            }
        };
        if let Err((what, code)) = self.resume(t) {
            say!("could not start {}: {what} (error {code})", c.name);
            self.stop(t);
            return Err(Reply::DeviceError);
        }
        say!("started {} (a clone of {}, sharing {pages} heap pages)", c.name, p.name);
        Ok(())
    }

    fn start_logged(&mut self, i: usize, why: &str) {
        let name = self.component(i).name;
        match self.start(i) {
            Ok(()) => say!("started {name} ({why})"),
            Err((what, code)) => {
                self.status[i] = Status::Stopped;
                say!("could not start {name}: {what} (error {code})");
            }
        }
    }

    /// Destroys component `i`'s current instance by revoking everything
    /// made from its untyped block. A call the instance was serving fails
    /// with `PeerRestarted`; calls still queued on its endpoints wait for
    /// the next instance.
    fn stop(&mut self, i: usize) {
        // Its pages go back to the Memory Server while its address space
        // still exists, so they are unmapped from it cleanly.
        if self.status[i] != Status::NotStarted {
            if let Some(ep) = self.memory_server().filter(|_| !self.is_memory_server(i)) {
                let r = syscall(Syscall::Call, ep, [mem::RELEASE, i as u64 + 1, 0, 0]);
                if r.status == 0 && r.msg[1] > 0 {
                    say!(
                        "{}: {} pages back to the Memory Server",
                        self.component(i).name,
                        r.msg[1]
                    );
                }
            }
        }
        if self.made[i] {
            let ut = BLOCKS + i as u64 * BLOCK + B_UNTYPED;
            let _ = sys(Syscall::CapRevoke, ut, [0; 4]);
            if self.component(i).caps().any(|c| c.kind == CapKind::Spare) {
                for k in 0..root::SPARE_COUNT {
                    let _ = sys(Syscall::CapRevoke, root::SPARE + k, [0; 4]);
                }
            }
        }
        self.status[i] = Status::Stopped;
    }

    /// Records a restart of component `i` now. False if it would be more
    /// than [`MAX_RESTARTS`] within [`RESTART_WINDOW`].
    fn may_restart(&mut self, i: usize) -> bool {
        let now = ticks();
        let n = self.restart_count[i];
        // The oldest of the last MAX_RESTARTS restarts, overwritten now.
        let oldest = &mut self.restarts[i][n % MAX_RESTARTS];
        if n >= MAX_RESTARTS && now.saturating_sub(*oldest) < RESTART_WINDOW {
            return false;
        }
        *oldest = now;
        self.restart_count[i] = n + 1;
        true
    }

    /// Component `i` faulted (its thread is stopped): applies its restart
    /// policy. A kill by a fault injector (`injected`) does not count
    /// towards the restart limit, which is there to stop crash loops.
    fn supervise(&mut self, i: usize, injected: bool) {
        let c = *self.component(i);
        let name = c.name;
        let policy = match c.restart {
            Restart::Never => {
                self.stop(i);
                say!("{name} stays stopped (restart never)");
                return;
            }
            Restart::OneForOne => "one-for-one",
            Restart::RestForOne => "rest-for-one",
        };
        if !injected && !self.may_restart(i) {
            self.stop(i);
            self.status[i] = Status::Failed;
            say!("{name}: more than {MAX_RESTARTS} restarts in 60 s; giving up");
            self.tombstone(i);
            return;
        }
        // Who goes down with it: for rest-for-one, every running component
        // after it. They stop last-started first, and start in order.
        let mut group = [false; MAX_COMPONENTS];
        group[i] = true;
        if c.restart == Restart::RestForOne {
            for (j, g) in group.iter_mut().enumerate().skip(i + 1) {
                *g = self.status[j] == Status::Running;
            }
        }
        for j in (0..MAX_COMPONENTS).rev().filter(|&j| group[j]) {
            self.stop(j);
        }
        let others = group.iter().filter(|g| **g).count() - 1;
        if others == 0 {
            say!("restarting {name} ({policy})");
        } else {
            say!("restarting {name} and {others} after it ({policy})");
        }
        for j in (0..MAX_COMPONENTS).filter(|&j| group[j]) {
            if self.component(j).start == Start::Clone {
                // Its heap came from a parent: a fresh one would not be it.
                say!("{} stays stopped (a clone is not restarted)", self.component(j).name);
                continue;
            }
            self.start_logged(j, "restart");
        }
    }

    /// The manager's capability to the Memory Server, if the manifest has
    /// one and it is running.
    fn memory_server(&self) -> Option<u64> {
        let s = self.service_index("mem")?;
        let (_, owner) = self.services[s]?;
        (self.status[owner] == Status::Running).then_some(SERVICES + s as u64)
    }

    fn is_memory_server(&self, i: usize) -> bool {
        self.component(i).provides().any(|s| s == "mem")
    }

    /// Component `i` took a page fault at `addr`: if that is in its heap,
    /// has the Memory Server map a page there. True if it did.
    fn page_in(&self, i: usize, addr: u64) -> Result<bool, Reply> {
        let c = self.component(i);
        let heap = USER_BASE + mem::HEAP_OFFSET;
        if c.heap_pages == 0 || !(heap..heap + c.heap_pages * PAGE).contains(&addr) {
            return Ok(false);
        }
        let Some(ep) = self.memory_server() else {
            return Ok(false);
        };
        let vspace = BLOCKS + i as u64 * BLOCK + B_VSPACE;
        let lend = CapTransfer {
            grant: Some(vspace as u16),
            accept: None,
        };
        let r = syscall_x(
            Syscall::Call,
            ep,
            [mem::FAULT, i as u64 + 1, c.quota_pages, addr],
            lend,
        );
        match Reply::from_u64(r.msg[0]) {
            Reply::Ok if r.status == 0 => Ok(true),
            _ if r.status != 0 => Err(Reply::DeviceError),
            s => Err(s),
        }
    }

    /// Calls `power` component `i`'s first service, unbadged, with `op`.
    fn power_call(&self, i: usize, op: u64) -> Reply {
        let Some(s) = self.services.iter().position(|x| matches!(x, Some((_, o)) if *o == i)) else {
            return Reply::Unreachable;
        };
        let r = syscall(Syscall::Call, SERVICES + s as u64, [op, 0, 0, 0]);
        if r.status != 0 { Reply::Unreachable } else { Reply::from_u64(r.msg[0]) }
    }

    /// `[OP_SUSPEND, ticks]` from a `power-control` component: tells
    /// every running `power` component to quiesce, last in the manifest
    /// first, has the kernel suspend the machine to idle for `ticks`,
    /// then tells them to resume in manifest order. A component that
    /// refuses to suspend calls the suspend off (those already suspended
    /// resume); one that fails to resume is restarted.
    fn suspend(&mut self, ticks: u64) -> Reply {
        let mut quiet = [false; MAX_COMPONENTS];
        let mut result = Reply::Ok;
        for i in (0..MAX_COMPONENTS).rev() {
            if self.status[i] != Status::Running || !self.component(i).power {
                continue;
            }
            let r = self.power_call(i, power::SUSPEND);
            if r != Reply::Ok {
                say!("{} refused to suspend (status {}); suspend called off", self.component(i).name, r as u64);
                result = r;
                break;
            }
            quiet[i] = true;
        }
        if result == Reply::Ok {
            say!("every power component quiesced; suspending for {ticks} ticks");
            let r = syscall(Syscall::Suspend, root::UNTYPED, [ticks, 0, 0, 0]);
            if r.status != 0 {
                say!("the kernel refused to suspend (error {})", r.status);
                result = Reply::Denied;
            } else {
                say!("resumed");
            }
        }
        for i in 0..MAX_COMPONENTS {
            if !quiet[i] {
                continue;
            }
            let r = self.power_call(i, power::RESUME);
            if r != Reply::Ok {
                say!("{} failed to resume (status {}); restarting it", self.component(i).name, r as u64);
                self.status[i] = Status::Stopped;
                self.supervise(i, false);
            }
        }
        result
    }

    /// Answers every service of component `i` with `SERVICE_UNAVAILABLE`
    /// from now on.
    fn tombstone(&mut self, i: usize) {
        for s in 0..MAX_SERVICES {
            if let Some((name, owner)) = self.services[s] {
                if owner == i && start_tombstone(s as u64).is_err() {
                    say!("could not tombstone service {name}");
                }
            }
        }
    }
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// The manager's slot holding the device capability called `name`.
/// `msi` is all the MSI vectors, in consecutive slots from the one named;
/// `intx` the legacy PCI interrupt lines likewise (absent where the
/// kernel does not know the machine's routing: those slots stay empty);
/// the rest are one capability each (`iommu` may be absent). Returns
/// (first slot, count).
fn device(name: &str) -> Option<(u64, u64)> {
    Some(match name {
        "uart" => (root::UART, 1),
        "uart-irq" => (root::UART_IRQ, 1),
        "timer" => (root::TIMER, 1),
        "exit" => (root::EXIT_PORT, 1),
        "pci-config" => (root::PCI_CONFIG, 1),
        "pci-mmio" => (root::PCI_MMIO, 1),
        "msi" => (root::MSI, root::MSI_COUNT),
        "iommu" => (root::IOMMU, 1),
        "intx" => (root::INTX, root::INTX_COUNT),
        "pci-io" => (root::PCI_IO, 1),
        _ => return None,
    })
}

fn map_into(frame: u64, va: u64, flags: u64, vspace: u64) -> Result<(), u64> {
    sys(Syscall::FrameMapInto, frame, [va, flags, vspace, 0]).map(drop)
}

/// Loads a static position-independent executable into the address space
/// in slot `vspace`, from frames retyped from `ut` into the image slots of
/// `block`. Each page is written through a scratch mapping in the
/// manager's own address space, relocated, then mapped into the component
/// with its segment's permissions (writable or executable, never both).
fn load(image: &[u8], ut: u64, block: u64, vspace: u64) -> Result<u64, Failure> {
    let elf = Elf::parse(image).map_err(|_| ("not a valid executable", 0))?;
    let machine = if cfg!(target_arch = "x86_64") {
        Machine::X86_64
    } else {
        Machine::Aarch64
    };
    if elf.machine != machine || !elf.pie {
        return Err(("wrong machine, or not position-independent", 0));
    }
    let bias = USER_BASE;
    let (mut lo, mut hi) = (u64::MAX, 0);
    for seg in elf.segments() {
        let seg = seg.map_err(|_| ("bad segment", 0))?;
        if seg.mem_size > 0 {
            lo = lo.min(seg.vaddr & !(PAGE - 1));
            hi = hi.max((seg.vaddr + seg.mem_size + PAGE - 1) & !(PAGE - 1));
        }
    }
    if lo >= hi {
        return Err(("nothing to load", 0));
    }
    let pages = (hi - lo) / PAGE;
    if pages > IMAGE_PAGES {
        return Err(("executable too large", 0));
    }
    for p in 0..pages {
        let f = block + B_IMAGE + p;
        retype(ut, ObjectType::Frame, 0, f).map_err(|e| ("no memory for the image", e))?;
        sys(Syscall::FrameMap, f, [SCRATCH_VA + p * PAGE, 1, 0, 0])
            .map_err(|e| ("scratch map", e))?;
    }
    // Copy each segment's file bytes (the rest is zero: frames are zeroed).
    for seg in elf.segments().flatten() {
        let bytes = elf.file_bytes(&seg);
        let dst = (SCRATCH_VA + seg.vaddr - lo) as *mut u8;
        // SAFETY: the scratch window maps every page of [lo, hi), and the
        // segment lies inside it.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    }
    for r in elf
        .relocations()
        .map_err(|_| ("unsupported relocations", 0))?
    {
        if r.offset < lo || r.offset + 8 > hi {
            return Err(("relocation outside the image", 0));
        }
        let dst = (SCRATCH_VA + r.offset - lo) as *mut u64;
        // SAFETY: checked inside the scratch window above.
        unsafe { dst.write_unaligned(r.addend.wrapping_add(bias)) };
    }
    for p in 0..pages {
        let f = block + B_IMAGE + p;
        sys(Syscall::FrameUnmap, f, [0; 4]).map_err(|e| ("scratch unmap", e))?;
        let page = lo + p * PAGE;
        let (mut covered, mut write, mut exec) = (false, false, false);
        for seg in elf.segments().flatten() {
            if seg.mem_size > 0 && seg.vaddr < page + PAGE && seg.vaddr + seg.mem_size > page {
                covered = true;
                write |= seg.writable;
                exec |= seg.executable;
            }
        }
        if !covered {
            continue;
        }
        if write && exec {
            return Err(("a page would be writable and executable", 0));
        }
        let flags = if write {
            MAP_WRITE
        } else if exec {
            MAP_EXEC
        } else {
            0
        };
        map_into(f, page + bias, flags, vspace).map_err(|e| ("mapping the image", e))?;
    }
    Ok(elf.entry + bias)
}

// ---- watchers -----------------------------------------------------------

/// Waits for the first call to service `s` of a lazy component, has the
/// manager start the component, forwards the call to it under the
/// client's badge, and relays the reply. Then it is done: from now on
/// clients' calls go straight to the component.
extern "C" fn watcher(s: u64) -> ! {
    let ep = SERVICES + s;
    let first = syscall(Syscall::Recv, ep, [0; 4]);
    if first.status == 0 {
        let started = syscall(Syscall::Call, WATCHER_CONTROL + s, [s, 0, 0, 0]);
        let scratch = WATCHER_SCRATCH + s;
        let reply = if started.status == 0
            && started.msg[0] == 0
            && mint(ep, scratch, WRITE | GRANT_REPLY, first.badge).is_ok()
        {
            let r = syscall(Syscall::Call, scratch, first.msg);
            let _ = syscall(Syscall::CapDelete, scratch, [0; 4]);
            r.msg
        } else {
            [u64::MAX; 4]
        };
        syscall(Syscall::Reply, 0, reply);
    }
    syscall(Syscall::ThreadSuspend, WATCHER_TCB + s, [0; 4]);
    superior_sys::park()
}

fn start_watcher(s: u64) -> Result<(), u64> {
    let tcb = WATCHER_TCB + s;
    let stack = WATCHER_STACKS_VA + s * 0x1_0000;
    retype(root::UNTYPED, ObjectType::Thread, 0, tcb)?;
    for p in 0..2 {
        let f = WATCHER_STACK + 2 * s + p;
        retype(root::UNTYPED, ObjectType::Frame, 0, f)?;
        sys(Syscall::FrameMap, f, [stack + p * PAGE, 1, 0, 0])?;
    }
    mint(CONTROL, WATCHER_CONTROL + s, WRITE, BADGE_WATCHER + s)?;
    let entry = watcher as *const () as u64;
    sys(
        Syscall::ThreadConfigure,
        tcb,
        [entry, stack + 2 * PAGE, s, WATCHER_PRIORITY],
    )?;
    // It shares the manager's CSpace (and, by default, address space).
    sys(Syscall::ThreadSetSpace, tcb, [root::SELF_CNODE, 0, 0, 0])?;
    sys(Syscall::ThreadResume, tcb, [0; 4]).map(drop)
}

/// Serves service `s` of a component the manager gave up on: every call
/// fails fast with `SERVICE_UNAVAILABLE`.
extern "C" fn tombstone(s: u64) -> ! {
    let ep = SERVICES + s;
    let reply = [SERVICE_UNAVAILABLE, 0, 0, 0];
    syscall(Syscall::Recv, ep, [0; 4]);
    loop {
        syscall(Syscall::ReplyRecv, ep, reply);
    }
}

fn start_tombstone(s: u64) -> Result<(), u64> {
    let tcb = TOMB_TCB + s;
    let stack = TOMB_STACKS_VA + s * 0x1_0000;
    retype(root::UNTYPED, ObjectType::Thread, 0, tcb)?;
    for p in 0..2 {
        let f = TOMB_STACK + 2 * s + p;
        retype(root::UNTYPED, ObjectType::Frame, 0, f)?;
        sys(Syscall::FrameMap, f, [stack + p * PAGE, 1, 0, 0])?;
    }
    let entry = tombstone as *const () as u64;
    sys(
        Syscall::ThreadConfigure,
        tcb,
        [entry, stack + 2 * PAGE, s, WATCHER_PRIORITY],
    )?;
    sys(Syscall::ThreadSetSpace, tcb, [root::SELF_CNODE, 0, 0, 0])?;
    sys(Syscall::ThreadResume, tcb, [0; 4]).map(drop)
}

/// Names for messages. (No `{:?}`: on AArch64 the prebuilt core library's
/// Debug machinery cannot be linked into a position-independent program.)
fn fault_name(kind: u64) -> &'static str {
    match FaultKind::from_u64(kind) {
        Some(FaultKind::PageFault) => "page fault",
        Some(FaultKind::GeneralProtection) => "general protection fault",
        Some(FaultKind::InvalidOpcode) => "invalid instruction",
        Some(FaultKind::DivideError) => "divide error",
        None => "unknown fault",
    }
}

fn bundle_error(e: BundleError) -> &'static str {
    match e {
        BundleError::BadMagic => "not a bundle",
        BundleError::Truncated => "truncated",
        BundleError::BadEntry(_) => "an entry lies outside it",
    }
}

// ---- main ---------------------------------------------------------------

/// The fast reboot (spec section 4): the kernel destroys everything and
/// starts this program again; only the state store survives.
fn reboot() -> ! {
    let r = syscall(Syscall::Reboot, root::UNTYPED, [0; 4]);
    say!("[fail] fast reboot refused (error {})", r.status);
    shutdown(false)
}

fn shutdown(pass: bool) -> ! {
    // QEMU's isa-debug-exit: (value << 1) | 1; 0x10 is the pass code.
    let value = if pass { 0x10 } else { 0x11 };
    syscall(Syscall::IoPortOut, root::EXIT_PORT, [0xf4, 4, value, 0]);
    superior_sys::park()
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let bundle_len = arg & ((1 << root::REBOOTS_SHIFT) - 1);
    let reboots = arg >> root::REBOOTS_SHIFT;
    // SAFETY: the kernel mapped the bundle read-only at BUNDLE_VA, and it
    // stays mapped for as long as this program runs.
    let bytes = unsafe { core::slice::from_raw_parts(BUNDLE_VA as *const u8, bundle_len as usize) };
    let bundle = match Bundle::parse(bytes) {
        Ok(b) => b,
        Err(e) => {
            say!("bad boot bundle: {}", bundle_error(e));
            shutdown(false)
        }
    };
    let text = bundle
        .get("manifest")
        .and_then(|m| core::str::from_utf8(m).ok())
        .unwrap_or("");
    let manifest = match Manifest::parse(text) {
        Ok(m) => m,
        Err(e) => {
            say!("manifest line {}: {} ({})", e.line, e.what, e.word);
            shutdown(false)
        }
    };
    let mut m = Manager {
        bundle,
        manifest,
        status: [Status::NotStarted; MAX_COMPONENTS],
        services: [None; MAX_SERVICES],
        made: [false; MAX_COMPONENTS],
        shared: [0; MAX_COMPONENTS],
        shared_next: SHARED_PAGES,
        restarts: [[0; MAX_RESTARTS]; MAX_COMPONENTS],
        restart_count: [0; MAX_COMPONENTS],
    };
    if reboots > 0 {
        say!("started again after fast reboot {reboots}; state store kept");
    }
    say!(
        "manifest: {} components, bundle of {} files",
        m.manifest.len(),
        m.bundle.len()
    );
    if retype(root::UNTYPED, ObjectType::Endpoint, 0, CONTROL).is_err() {
        say!("could not make the control endpoint");
        shutdown(false);
    }
    // Every service endpoint, made and kept by the manager.
    let mut n = 0;
    for (i, c) in m.manifest.iter() {
        for s in c.provides() {
            if n == MAX_SERVICES
                || retype(root::UNTYPED, ObjectType::Endpoint, 0, SERVICES + n as u64).is_err()
            {
                say!("could not make the endpoint for service {s}");
                shutdown(false);
            }
            m.services[n] = Some((s, i));
            n += 1;
        }
        if mint(CONTROL, FAULT_CAP + i as u64, WRITE, BADGE_FAULT + i as u64).is_err() {
            say!("could not make a fault capability");
            shutdown(false);
        }
    }
    // Watchers for lazy components' services, then boot components.
    for s in 0..n {
        let (name, owner) = m.services[s].unwrap();
        if m.component(owner).start == Start::Lazy && start_watcher(s as u64).is_err() {
            say!("could not start the watcher for service {name}");
            shutdown(false);
        }
    }
    for i in 0..MAX_COMPONENTS {
        if matches!(m.manifest.components[i], Some(c) if c.start == Start::Boot) {
            m.start_logged(i, "boot");
        }
    }

    let mut msg = syscall(Syscall::Recv, CONTROL, [0; 4]);
    loop {
        let (badge, kind, i) = (msg.badge, msg.badge & !0xff, (msg.badge & 0xff) as usize);
        // A page fault in a component's heap is paged in, not supervised.
        let paged = (kind == BADGE_FAULT
            && i < MAX_COMPONENTS
            && msg.msg[0] == FaultKind::PageFault as u64)
            .then(|| m.page_in(i, msg.msg[1]));
        let reply = match kind {
            BADGE_WATCHER => {
                let (service, owner) = m.services.get(i).copied().flatten().unwrap_or(("?", 0));
                if m.status[owner] == Status::NotStarted {
                    m.start_logged(owner, "lazy: first call to its service");
                    let _ = service;
                }
                Some([(m.status[owner] != Status::Running) as u64, 0, 0, 0])
            }
            BADGE_FAULT if paged == Some(Ok(true)) => {
                // A heap page arrived: run the instruction again.
                Some([FaultReply::Retry as u64, 0, 0, 0])
            }
            BADGE_FAULT if i < MAX_COMPONENTS => {
                let name = m.component(i).name;
                if let Some(Err(why)) = paged {
                    say!(
                        "{name} is out of memory: heap page at {:#x} refused ({}), quota {} pages",
                        msg.msg[1],
                        match why {
                            Reply::Denied => "quota spent",
                            Reply::InUse => "pool empty",
                            _ => "Memory Server error",
                        },
                        m.component(i).quota_pages
                    );
                }
                let what = fault_name(msg.msg[0]);
                say!(
                    "{name} faulted: {what} at pc {:#x}, address {:#x}",
                    msg.msg[2],
                    msg.msg[1]
                );
                // Answer the fault first (the thread stops), so the manager
                // owes no reply to an instance about to be destroyed.
                syscall(Syscall::Reply, 0, [FaultReply::Stop as u64, 0, 0, 0]);
                m.status[i] = Status::Stopped;
                if m.is_memory_server(i) {
                    // Every component's memory is in its hands: no
                    // restart in place (spec section 4).
                    say!("the Memory Server failed; fast reboot");
                    reboot();
                }
                m.supervise(i, false);
                None
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS && msg.msg[0] == OP_KILL && m.component(i).injector =>
            {
                let t = msg.msg[1] as usize;
                let killable = t < MAX_COMPONENTS
                    && t != i
                    && m.manifest.components[t].is_some()
                    && m.status[t] == Status::Running;
                if killable && m.is_memory_server(t) {
                    // As if it had failed: a fast reboot.
                    say!("fault injection: killing {}", m.component(t).name);
                    syscall(Syscall::Reply, 0, [0; 4]);
                    say!("the Memory Server failed; fast reboot");
                    reboot();
                }
                if killable {
                    say!("fault injection: killing {}", m.component(t).name);
                    m.status[t] = Status::Stopped;
                    m.supervise(t, true);
                }
                Some([!killable as u64, 0, 0, 0])
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS && msg.msg[0] == OP_CRASH_MANAGER && m.component(i).injector =>
            {
                say!("fault injection: the Component Manager crashes");
                syscall(Syscall::Reply, 0, [0; 4]);
                // SAFETY: deliberately not: nothing is mapped at 0, so this
                // faults, and the kernel's fast reboot takes over.
                let v = unsafe { core::ptr::read_volatile(core::ptr::null::<u64>()) };
                say!("[fail] read {v:#x} at address 0");
                reboot()
            }
            BADGE_REPORT if i < MAX_COMPONENTS && msg.msg[0] == OP_CLONE => {
                let r = m.clone_into(i, msg.msg[1] as usize);
                if let Err(e) = r {
                    say!("{} could not clone itself into component {}: status {}", m.component(i).name, msg.msg[1], e as u64);
                }
                Some([r.err().unwrap_or(Reply::Ok) as u64, 0, 0, 0])
            }
            BADGE_REPORT if i < MAX_COMPONENTS && msg.msg[0] == OP_EXIT => {
                // Answer first, so the manager owes no reply to an
                // instance about to be destroyed.
                syscall(Syscall::Reply, 0, [0; 4]);
                say!("{} exited", m.component(i).name);
                m.stop(i);
                None
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS
                    && msg.msg[0] == power::OP_SUSPEND
                    && m.component(i).power_control =>
            {
                Some([m.suspend(msg.msg[1]) as u64, 0, 0, 0])
            }
            BADGE_REPORT if i < MAX_COMPONENTS && msg.msg[0] == OP_SHUTDOWN => {
                let name = m.component(i).name;
                let pass = msg.msg[1] == 0;
                say!(
                    "{name} asked to shut down ({})",
                    if pass { "pass" } else { "fail" }
                );
                for (j, c) in m.manifest.iter() {
                    if m.status[j] == Status::NotStarted {
                        say!("never started: {} (nothing used it)", c.name);
                    }
                }
                shutdown(pass);
            }
            _ => {
                say!("unexpected message, badge {badge:#x}");
                Some([u64::MAX, 0, 0, 0])
            }
        };
        msg = match reply {
            Some(r) => syscall(Syscall::ReplyRecv, CONTROL, r),
            None => syscall(Syscall::Recv, CONTROL, [0; 4]),
        };
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    // The manager failed: the fast reboot starts everything again.
    reboot()
}
