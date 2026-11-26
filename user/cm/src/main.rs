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
use superior_objects::bundle::{Bundle, BundleError, Signed};
use superior_objects::image::Image;
use superior_objects::elf::{Elf, Machine};
use superior_objects::ab::{self, Record};
use superior_objects::interfaces::{Status as Reply, block, install, launch, mem, power, update};
use superior_objects::package;
use superior_objects::manifest::{CapKind, Component, MANAGER_BADGE, MAX_COMPONENTS, Manifest, Restart, Start};
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
/// (The busiest manifest shares 29 pages.)
const SHARED_SLOTS: u64 = 120;
const _: () = assert!(SHARED_PAGES + SHARED_SLOTS <= BLOCKS);
/// Each component's block of slots: its untyped memory, then the objects
/// of its current instance.
const BLOCKS: u64 = 512;
const BLOCK: u64 = 97;
const B_UNTYPED: u64 = 0;
const B_VSPACE: u64 = 1;
const B_CNODE: u64 = 2;
const B_THREAD: u64 = 3;
const B_IMAGE: u64 = 4;
const IMAGE_PAGES: u64 = 76;
const B_STACK: u64 = B_IMAGE + IMAGE_PAGES;
const STACK_PAGES: u64 = 16;
/// Its scheduling context, if the manifest gives it a `budget`.
const B_SCHED: u64 = B_STACK + STACK_PAGES;
const _: () = assert!(B_SCHED + 1 <= BLOCK);
/// The system slots (`system` in the manifest, A/B updates): a badged
/// capability to the system disk's block service for the manager's own
/// reads and writes, a page it lends the driver for each, and the pages
/// the system bundle is read into (kept: components are built from it).
const SYSTEM_BLOCK: u64 = BLOCKS + BLOCK * MAX_COMPONENTS as u64;
const IO_PAGE: u64 = SYSTEM_BLOCK + 1;
const SYSTEM_PAGES: u64 = SYSTEM_BLOCK + 2;
const SYSTEM_MAX_PAGES: u64 = ab::SLOT_BYTES.div_ceil(4096) as u64;
/// Pages holding each installed package, [`PACKAGE_MAX_PAGES`] slots for
/// each store slot.
const PACKAGE_PAGES: u64 = SYSTEM_PAGES + SYSTEM_MAX_PAGES;
const PACKAGE_MAX_PAGES: u64 = package::BYTES.div_ceil(4096) as u64;
/// Where each page of a `file` is made before it goes to the component.
const FILE_SCRATCH: u64 = (1 << root::CNODE_BITS) - 1;
/// Where each second-level CNode of a two-level CSpace is made and filled
/// before it goes into the root.
const LEAF_SCRATCH: u64 = FILE_SCRATCH - 1;
const _: () = assert!(PACKAGE_PAGES + PACKAGE_MAX_PAGES * package::COUNT as u64 <= LEAF_SCRATCH);
/// The manager's badge on the system disk (clients' are their numbers).
const BADGE_SYSTEM_DISK: u64 = 0x1000;

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
/// The page lent for system disk I/O, and the system bundle.
const IO_VA: u64 = USER_BASE + 0x3_2000_0000;
const SYSTEM_VA: u64 = USER_BASE + 0x3_4000_0000;
/// Where store slot k's package is mapped: a MiB each.
const PACKAGE_VA: u64 = USER_BASE + 0x3_6000_0000;
const PACKAGE_SPAN: u64 = 0x10_0000;
const _: () = assert!(PACKAGE_MAX_PAGES * PAGE <= PACKAGE_SPAN);

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

/// Where a component's capabilities go while it is built: the CNode in
/// slot `cnode`, which holds its slots `lo` to `lo + size - 1` (all of a
/// one-level CSpace, or one second-level CNode of a two-level one). Slots
/// outside it are left for another pass.
#[derive(Clone, Copy)]
struct Dest {
    cnode: u64,
    lo: u64,
    size: u64,
}

impl Dest {
    /// The CNode index of the component's slot `slot`, if this holds it.
    fn index(&self, slot: u64) -> Option<u64> {
        slot.checked_sub(self.lo).filter(|&i| i < self.size)
    }

    fn copy(&self, slot: u64, src: u64, mask: u64, badge: u64) -> Result<(), u64> {
        self.index(slot).map_or(Ok(()), |i| cnode_copy(self.cnode, i, src, mask, badge))
    }

    fn retype(&self, ut: u64, ty: ObjectType, bits: u64, slot: u64) -> Result<(), u64> {
        self.index(slot).map_or(Ok(()), |i| retype_into(ut, ty, bits, self.cnode, i))
    }
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
    /// The system bundle, once loaded from a slot (`system`).
    system: Option<Bundle<'a>>,
    manifest: Manifest<'a>,
    /// Service endpoints made so far.
    service_count: usize,
    /// The boot record as last written, and the slot booted, its version
    /// and whether it was not the slot tried first.
    record: Record,
    booted: Option<(u8, u64, bool)>,
    /// System pages made so far.
    system_pages: u64,
    /// Whether the manager's capability to the system disk is made.
    disk: bool,
    /// Each store slot's installed package (bundle and version), and the
    /// pages made for it so far.
    packages: [Option<(Bundle<'a>, u64)>; package::COUNT],
    package_pages: [u64; package::COUNT],
    /// The store slot each component was installed from, if any.
    origin: [Option<usize>; MAX_COMPONENTS],
    /// Where the next installed component goes (indices are not reused).
    next_component: usize,
    status: [Status; MAX_COMPONENTS],
    /// Services in manifest order: (name, providing component).
    services: [Option<(&'a str, usize)>; MAX_SERVICES],
    /// Whether the component's untyped block (and state page) exist yet.
    made: [bool; MAX_COMPONENTS],
    /// Whether its untyped block exists yet ([`Manager::make_blocks`]
    /// makes the boot components' first).
    block_made: [bool; MAX_COMPONENTS],
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

    /// Makes the boot components' untyped blocks before anything else is
    /// made from the manager's memory, the largest first. Memory is handed
    /// out in order, each block aligned to its size: in this order none
    /// leaves a gap, where in the manifest's a large block after small ones
    /// would be put past a gap nearly as large as itself (a 64 MiB one in
    /// 128 MiB leaving no room after it). One there is no room for is left
    /// for [`Manager::build`] to try, and report.
    fn make_blocks(&mut self) {
        let boot = |c: &Option<Component>| matches!(c, Some(c) if c.start == Start::Boot);
        for bits in (0..64u8).rev() {
            for i in 0..MAX_COMPONENTS {
                let c = self.manifest.components[i];
                if boot(&c) && c.is_some_and(|c| c.memory_bits == bits) && !self.block_made[i] {
                    let ut = BLOCKS + i as u64 * BLOCK + B_UNTYPED;
                    self.block_made[i] = retype(root::UNTYPED, ObjectType::Untyped, bits as u64, ut).is_ok();
                }
            }
        }
    }

    /// Starts the thread of component `i`, built by [`Manager::build`].
    fn resume(&mut self, i: usize) -> Result<(), Failure> {
        let tcb = BLOCKS + i as u64 * BLOCK + B_THREAD;
        sys(Syscall::ThreadResume, tcb, [0; 4]).map_err(|e| ("resume", e))?;
        self.status[i] = Status::Running;
        Ok(())
    }

    /// Places component `i`'s capabilities (manifest `c`) that `to` holds.
    fn place(&self, i: usize, c: &Component, ut: u64, to: Dest) -> Result<(), Failure> {
        for cap in c.caps() {
            let slot = cap.slot as u64;
            let r = match cap.kind {
                CapKind::Provides(s) => {
                    let ep = SERVICES + self.service_index(s).unwrap() as u64;
                    to.copy(slot, ep, READ | WRITE | GRANT_REPLY, 0)
                }
                CapKind::Uses(s) | CapKind::Manages(s) => {
                    let ep = SERVICES + self.service_index(s).unwrap() as u64;
                    // The Memory Server learns the client's quota from
                    // the badge, which the client cannot change; a manager
                    // is known by its badge's mark.
                    let badge = if s == "mem" {
                        mem::badge(i, c.quota_pages)
                    } else if matches!(cap.kind, CapKind::Manages(_)) {
                        (i as u64 + 1) | MANAGER_BADGE
                    } else {
                        i as u64 + 1
                    };
                    // Grant: a client may lend the server a capability
                    // (a buffer frame to DMA into, say).
                    to.copy(slot, ep, WRITE | GRANT | GRANT_REPLY, badge)
                }
                CapKind::Device(d) => match device(d) {
                    Some((src, count)) => {
                        let r = (0..count)
                            .try_for_each(|k| to.copy(slot + k, src + k, ALL, 0));
                        // A machine without an IOMMU (or a PS/2 controller,
                        // or a boot framebuffer) has none to give: the slot
                        // stays empty, and the component copes.
                        if matches!(d, "iommu" | "intx" | "ps2" | "framebuffer") { Ok(()) } else { r }
                    }
                    None => return Err(("unknown device", 0)),
                },
                CapKind::Notification => to.retype(ut, ObjectType::Notification, 0, slot),
                CapKind::Untyped(bits) => {
                    to.retype(ut, ObjectType::Untyped, bits as u64, slot)
                }
                CapKind::Control => {
                    to.copy(slot, CONTROL, WRITE, BADGE_REPORT + i as u64)
                }
                CapKind::State => to.copy(slot, root::STATE_STORE + i as u64, ALL, 0),
                // Its root CNode, made first (`build`).
                CapKind::Root => to.copy(slot, BLOCKS + i as u64 * BLOCK + B_CNODE, ALL, 0),
                CapKind::File(name) => match self.file(i, name) {
                    Some(bytes) => copy_file(bytes, ut, to, slot),
                    None => return Err(("file not in the bundle", 0)),
                },
                CapKind::Shared(n) => (0..n as u64)
                    .try_for_each(|p| to.copy(slot + p, self.shared[i] + p, ALL, 0)),
                // Each spare block the kernel gave, made over whole as a
                // child of the manager's, so stopping the component takes
                // it all back (`stop`).
                CapKind::Spare => (0..root::SPARE_COUNT)
                    .map_while(|k| {
                        let r = syscall(Syscall::UntypedInfo, root::SPARE + k, [0; 4]);
                        (r.status == 0).then_some((k, r.msg[0]))
                    })
                    .try_for_each(|(k, bits)| {
                        to.retype(root::SPARE + k, ObjectType::Untyped, bits, slot + k)
                    }),
            };
            r.map_err(|e| ("placing a capability", e))?;
        }
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
            if !self.block_made[i] {
                retype(root::UNTYPED, ObjectType::Untyped, c.memory_bits as u64, ut)
                    .map_err(|e| ("no memory for the component", e))?;
                self.block_made[i] = true;
            }
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
        // big one (the Memory Server's) wastes none of the block. With two
        // levels, this is the root, and each CNode under it is made as its
        // capabilities are placed (`place`).
        let leaf = c.cspace_leaf_bits as u64;
        let root_bits = c.cspace_bits as u64 - leaf;
        retype(ut, ObjectType::CNode, root_bits, cnode).map_err(|e| ("CNode", e))?;
        retype(ut, ObjectType::AddressSpace, c.vspace_bits as u64, vspace)
            .map_err(|e| ("address space", e))?;
        retype(ut, ObjectType::Thread, 0, tcb).map_err(|e| ("thread", e))?;
        let image = self.file(i, c.image).ok_or(("image not in the bundle", 0))?;
        let entry = load(image, ut, block, vspace)?;
        for p in 0..STACK_PAGES {
            let f = block + B_STACK + p;
            retype(ut, ObjectType::Frame, 0, f).map_err(|e| ("stack", e))?;
            map_into(f, STACK_TOP - (p + 1) * PAGE, MAP_WRITE, vspace).map_err(|e| ("stack", e))?;
        }
        if leaf == 0 {
            let all = Dest { cnode, lo: 0, size: 1 << c.cspace_bits };
            self.place(i, &c, ut, all)?;
        } else {
            // Each second-level CNode is made and filled in a slot of the
            // manager's, copied into the root and that slot emptied: the
            // root's copy is then the only one, so emptying the root (when
            // the component stops) destroys it. Only those for the slots
            // the manifest says to make: the component fills the rest.
            let made = if c.cspace_made_bits == 0 { c.cspace_bits } else { c.cspace_made_bits } as u64;
            for r in 0..1u64 << (made - leaf) {
                retype(ut, ObjectType::CNode, leaf, LEAF_SCRATCH).map_err(|e| ("CNode", e))?;
                let part = Dest { cnode: LEAF_SCRATCH, lo: r << leaf, size: 1 << leaf };
                let placed = self
                    .place(i, &c, ut, part)
                    .and_then(|()| cnode_copy(cnode, r, LEAF_SCRATCH, ALL, 0).map_err(|e| ("CNode", e)));
                let _ = syscall(Syscall::CapDelete, LEAF_SCRATCH, [0; 4]);
                placed?;
            }
        }
        sys(
            Syscall::ThreadConfigure,
            tcb,
            [entry, STACK_TOP, c.arg, c.priority as u64],
        )
        .map_err(|e| ("configuring the thread", e))?;
        // A budget: a context of its own, made from its block (so stopping
        // it destroys the context), which every thread it makes shares.
        // Without one it shares the manager's, unlimited.
        if let Some((budget, period)) = c.budget {
            let sc = block + B_SCHED;
            retype(ut, ObjectType::SchedContext, 0, sc).map_err(|e| ("scheduling context", e))?;
            sys(
                Syscall::SchedControlConfigure,
                root::SCHED_CONTROL,
                [sc, budget as u64, period as u64, 0],
            )
            .map_err(|e| ("budget", e))?;
            sys(Syscall::SchedContextBind, tcb, [sc, 0, 0, 0]).map_err(|e| ("budget", e))?;
            say!("{}: budget {} ticks in {}", c.name, budget, period);
        }
        sys(Syscall::ThreadSetVSpace, tcb, [vspace, 0, 0, 0])
            .map_err(|e| ("set address space", e))?;
        let depth = if leaf == 0 { 0 } else { c.cspace_bits as u64 };
        sys(Syscall::ThreadSetSpace, tcb, [cnode, depth, 0, 0]).map_err(|e| ("set CSpace", e))?;
        if leaf != 0 {
            let made = if c.cspace_made_bits == 0 { c.cspace_bits } else { c.cspace_made_bits } as u64;
            say!(
                "{}: CSpace in two levels, {} CNodes of {} slots (a root of {})",
                c.name,
                1u64 << (made - leaf),
                1u64 << leaf,
                1u64 << root_bits
            );
        }
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

    /// The `k`th component with `start launch`.
    /// Component `i`'s file `name`: a package's files are its own;
    /// otherwise the system bundle's first, then the boot bundle's.
    fn file(&self, i: usize, name: &str) -> Option<&'a [u8]> {
        match self.origin[i] {
            Some(k) => self.packages[k].and_then(|(b, _)| b.get(name)),
            None => self.system.and_then(|b| b.get(name)).or_else(|| self.bundle.get(name)),
        }
    }

    /// `[OP_ICON_PIXELS, k, from]`: pixels of the image file launcher
    /// `k`'s icon names.
    fn icon_pixels(&self, k: usize, from: usize) -> [u64; 4] {
        let image = self
            .launcher(k)
            .and_then(|i| self.file(i, self.component(i).icon))
            .and_then(|b| Image::parse(b).ok())
            .filter(|im| (im.width, im.height) == (launch::ICON_SIDE, launch::ICON_SIDE));
        match image.map(|im| launch::icon_words(&im, from)) {
            None => [Reply::NotFound as u64, 0, 0, 0],
            Some(None) => [Reply::Invalid as u64, 0, 0, 0],
            Some(Some(w)) => [Reply::Ok as u64, w[0], w[1], w[2]],
        }
    }

    fn launcher(&self, k: usize) -> Option<usize> {
        self.manifest.iter().filter(|(_, c)| c.start == Start::Launch).nth(k).map(|(i, _)| i)
    }

    /// `[OP_LAUNCH, name]` from a launcher: starts the component of that
    /// name if it is `start launch` and not running.
    fn launch(&mut self, w: [u64; 3]) -> Reply {
        let (name, n) = launch::name(w);
        let Some((i, c)) = self.manifest.iter().find(|(_, c)| c.name.as_bytes() == &name[..n]) else {
            return Reply::NotFound;
        };
        if c.start != Start::Launch {
            return Reply::Denied;
        }
        if self.status[i] == Status::Running {
            return Reply::InUse;
        }
        // What an instance that exited or failed left is taken back first.
        self.stop(i);
        self.start_logged(i, "launched");
        if self.status[i] == Status::Running { Reply::Ok } else { Reply::DeviceError }
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

    /// Makes the endpoints for the services of components `from` on (the
    /// manager keeps the originals) and their fault capabilities, starts
    /// watchers for the lazy ones' services and starts the boot ones.
    fn wire(&mut self, from: usize) {
        let first_service = self.service_count;
        for i in from..MAX_COMPONENTS {
            let Some(c) = self.manifest.components[i] else { continue };
            for s in c.provides() {
                let n = self.service_count;
                if n == MAX_SERVICES
                    || retype(root::UNTYPED, ObjectType::Endpoint, 0, SERVICES + n as u64).is_err()
                {
                    say!("could not make the endpoint for service {s}");
                    shutdown(false);
                }
                self.services[n] = Some((s, i));
                self.service_count += 1;
            }
            if mint(CONTROL, FAULT_CAP + i as u64, WRITE, BADGE_FAULT + i as u64).is_err() {
                say!("could not make a fault capability");
                shutdown(false);
            }
        }
        for s in first_service..self.service_count {
            let (name, owner) = self.services[s].unwrap();
            if self.component(owner).start == Start::Lazy && start_watcher(s as u64).is_err() {
                say!("could not start the watcher for service {name}");
                shutdown(false);
            }
        }
        for i in from..MAX_COMPONENTS {
            if matches!(self.manifest.components[i], Some(c) if c.start == Start::Boot) {
                self.start_logged(i, "boot");
            }
        }
    }

    /// The key the system must be signed with: the boot bundle's
    /// `trust.key` (the kernel verified the boot bundle).
    fn trust_key(&self) -> Option<[u8; 32]> {
        self.bundle.get("trust.key").and_then(|k| <[u8; 32]>::try_from(k).ok())
    }

    /// Makes the manager's capability to the system disk, behind
    /// `service`, and its I/O page, once.
    fn open_disk(&mut self, service: &str) {
        if self.disk {
            return;
        }
        let s = SERVICES + self.service_index(service).unwrap() as u64;
        let io = mint(s, SYSTEM_BLOCK, WRITE | GRANT | GRANT_REPLY, BADGE_SYSTEM_DISK)
            .and_then(|_| retype(root::UNTYPED, ObjectType::Frame, 0, IO_PAGE))
            .and_then(|_| sys(Syscall::FrameMap, IO_PAGE, [IO_VA, 1, 0, 0]).map(drop));
        if let Err(e) = io {
            say!("could not reach the system disk (error {e})");
            shutdown(false);
        }
        self.disk = true;
    }

    /// `system <service>`: reads the boot record from that service's
    /// disk, chooses a slot (`ab::plan`), loads and checks the system
    /// bundle in it (signed with the boot bundle's key, no older than the
    /// record's floor), and starts its components as if their manifest
    /// followed the boot manifest. With no slot to boot, stops the machine.
    fn load_system(&mut self, boot_text: &'a str) {
        let Some(service) = self.manifest.system else { return };
        let Some(key) = self.trust_key() else {
            say!("the boot bundle has no trust.key to check the system with");
            shutdown(false)
        };
        self.open_disk(service);
        let record = match disk_read(ab::RECORD_SECTOR, 1) {
            Ok(b) => Record::decode(b[..ab::SECTOR].try_into().unwrap()),
            Err(e) => {
                say!("could not read the boot record (status {})", e as u64);
                shutdown(false)
            }
        };
        let plan = ab::plan(record);
        if let Some(p) = plan.dropped {
            say!("the update in slot {} never confirmed it came up; dropped it", ab::slot_name(p));
        }
        self.record = plan.write.unwrap_or(record);
        if plan.write.is_some() && write_record(&self.record).is_err() {
            say!("could not write the boot record");
            shutdown(false);
        }
        let mut chosen = None;
        for (k, slot) in plan.order.iter().flatten().enumerate() {
            match self.load_slot(*slot, &key) {
                Ok((bundle, version)) => {
                    chosen = Some((*slot, version, bundle, k > 0 || plan.dropped.is_some()));
                    break;
                }
                Err(why) => say!("system slot {} refused: {why}", ab::slot_name(*slot)),
            }
        }
        let Some((slot, version, bundle, fell_back)) = chosen else {
            say!("no system slot to boot");
            shutdown(false)
        };
        let text = bundle.get("manifest").and_then(|m| core::str::from_utf8(m).ok()).unwrap_or("");
        // SAFETY: only this thread touches the buffer, filled once here; the
        // manifest borrows from it for as long as the program runs.
        let joined: &'a str = unsafe {
            let buf = &mut *(&raw mut SYSTEM_MANIFEST);
            let len = boot_text.len() + 1 + text.len();
            if len > buf.len() {
                say!("the boot and system manifests are too long together");
                shutdown(false);
            }
            buf[..boot_text.len()].copy_from_slice(boot_text.as_bytes());
            buf[boot_text.len()] = 10; // a newline
            buf[boot_text.len() + 1..len].copy_from_slice(text.as_bytes());
            core::str::from_utf8_unchecked(&buf[..len])
        };
        let manifest = match Manifest::parse(joined) {
            Ok(m) => m,
            Err(e) => {
                say!("system manifest line {}: {} ({})", e.line, e.what, e.word);
                shutdown(false)
            }
        };
        let from = self.manifest.len();
        say!(
            "booting system slot {} (version {version}{}): {} more components",
            ab::slot_name(slot),
            if fell_back { ", fell back" } else { "" },
            manifest.len() - from
        );
        self.manifest = manifest;
        self.system = Some(bundle);
        self.booted = Some((slot, version, fell_back));
        self.wire(from);
    }

    /// Reads slot `slot`'s bundle into the system pages and checks it.
    fn load_slot(&mut self, slot: u8, key: &[u8; 32]) -> Result<(Bundle<'a>, u64), &'static str> {
        let first = ab::SLOT_FIRST[slot as usize];
        let header = disk_read(first, 1).map_err(|_| "unreadable")?;
        let len = ab::slot_length(header[..ab::SECTOR].try_into().unwrap()).ok_or("empty")?;
        let bytes = fill(&mut self.system_pages, SYSTEM_PAGES, SYSTEM_VA, first + 1, len)?;
        let signed = Signed::split(bytes).ok_or("not signed")?;
        if !signed.verify(key) {
            return Err("its signature does not verify");
        }
        if signed.version < self.record.floor {
            return Err("older than the rollback floor");
        }
        let bundle = Bundle::parse(signed.payload).map_err(bundle_error)?;
        Ok((bundle, signed.version))
    }

    /// `[OP_BOOT_INFO]`.
    fn boot_info(&self) -> [u64; 4] {
        match self.booted {
            Some((slot, version, fell_back)) => [
                Reply::Ok as u64,
                slot as u64 | if fell_back { update::FELL_BACK } else { 0 },
                version,
                self.record.floor,
            ],
            None => [Reply::NotFound as u64, 0, 0, 0],
        }
    }

    /// `[OP_BOOT_OK]`: the booted slot becomes the active one.
    fn boot_ok(&mut self) -> Reply {
        let Some((slot, version, _)) = self.booted else { return Reply::NotFound };
        let r = ab::confirmed(self.record, slot, version);
        if r != self.record {
            if write_record(&r).is_err() {
                return Reply::DeviceError;
            }
            say!("system slot {} confirmed: active, rollback floor {}", ab::slot_name(slot), r.floor);
        }
        self.record = r;
        Reply::Ok
    }

    /// `[OP_UPDATE_SLOT]`: the slot not booted.
    fn update_slot(&self) -> [u64; 4] {
        match self.booted {
            Some((slot, ..)) => {
                let other = 1 - slot;
                [Reply::Ok as u64, other as u64, ab::SLOT_FIRST[other as usize], ab::SLOT_SECTORS]
            }
            None => [Reply::NotFound as u64, 0, 0, 0],
        }
    }

    /// `[OP_UPDATE_READY]`: checks the update in the slot not booted,
    /// reading it a page at a time (the system pages hold the running
    /// system), and stages it.
    fn update_ready(&mut self) -> Reply {
        let (Some((slot, ..)), Some(key)) = (self.booted, self.trust_key()) else {
            return Reply::NotFound;
        };
        let other = 1 - slot;
        match check_slot(other, &key, self.record.floor) {
            Ok(version) => {
                let r = ab::staged(self.record, other);
                if write_record(&r).is_err() {
                    return Reply::DeviceError;
                }
                self.record = r;
                say!(
                    "update staged in slot {} (version {version}): the next boot tries it once",
                    ab::slot_name(other)
                );
                Reply::Ok
            }
            Err((why, status)) => {
                say!("update in slot {} refused: {why}", ab::slot_name(other));
                status
            }
        }
    }

    /// The key packages must be signed with: the system bundle's
    /// `packages.key`, or else the boot bundle's.
    fn publisher_key(&self) -> Option<[u8; 32]> {
        self.system
            .and_then(|b| b.get(package::KEY_FILE))
            .or_else(|| self.bundle.get(package::KEY_FILE))
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
    }

    /// `packages <service>`: installs every package in the store, clearing
    /// any it refuses.
    fn load_packages(&mut self) {
        self.next_component = self.manifest.iter().map(|(i, _)| i + 1).max().unwrap_or(0);
        let Some(service) = self.manifest.packages else { return };
        if self.manifest.system.is_some_and(|s| s != service) {
            say!("the package store must be on the system disk");
            shutdown(false);
        }
        self.open_disk(service);
        for k in 0..package::COUNT {
            match disk_read(package::first(k), 1) {
                Ok(h) if package::length(h[..ab::SECTOR].try_into().unwrap()).is_none() => continue,
                Ok(_) => {}
                Err(_) => {
                    say!("package store slot {k} unreadable");
                    continue;
                }
            }
            // An upgrade cut short leaves two versions: the newer stays.
            let _ = self.install(k, Mode::Boot);
        }
        let count = self.installed().count_ones();
        say!("package store: {count} installed");
    }

    /// Checks the package in store slot `k` and starts its components,
    /// replacing an older version as `mode` allows; clears the slot if it
    /// refuses it. The number of components and the slot replaced.
    fn install(&mut self, k: usize, mode: Mode) -> Result<(usize, Option<usize>), Reply> {
        if k >= package::COUNT {
            return Err(Reply::Invalid);
        }
        if self.packages[k].is_some() {
            return Err(Reply::InUse);
        }
        match self.admit(k, mode) {
            Ok((bundle, version, pkg, replaced)) => {
                if let Some(j) = replaced {
                    let old = self.packages[j].map_or(0, |(_, v)| v);
                    say!("package in store slot {k} (version {version}) replaces slot {j}'s (version {old})");
                    if self.uninstall(j) != Reply::Ok {
                        say!("could not clear package store slot {j}");
                    }
                }
                let from = self.next_component;
                let mut names = [""; MAX_COMPONENTS];
                let mut n = 0;
                for (_, c) in pkg.iter() {
                    self.manifest.components[from + n] = Some(*c);
                    self.origin[from + n] = Some(k);
                    names[n] = c.name;
                    n += 1;
                }
                self.next_component += n;
                self.packages[k] = Some((bundle, version));
                say!("installed package in store slot {k} (version {version}): {}", Names(&names[..n]));
                self.wire(from);
                Ok((n, replaced))
            }
            Err((why, word, status)) => {
                if word.is_empty() {
                    say!("package in store slot {k} refused: {why}");
                } else {
                    say!("package in store slot {k} refused: {why} ({word})");
                }
                if write_sector(package::first(k), &[0; ab::SECTOR]).is_err() {
                    say!("could not clear package store slot {k}");
                }
                Err(status)
            }
        }
    }

    /// Reads store slot `k`'s package into its pages and checks it: the
    /// publisher's signature, then what it asks for, then (as `mode`
    /// allows) whether it replaces an installed package, which it must be
    /// newer than. The package, its version, and the slot it replaces.
    #[allow(clippy::type_complexity)]
    fn admit(
        &mut self,
        k: usize,
        mode: Mode,
    ) -> Result<(Bundle<'a>, u64, Manifest<'a>, Option<usize>), (&'static str, &'a str, Reply)> {
        let denied = |why| (why, "", Reply::Denied);
        let invalid = |why| (why, "", Reply::Invalid);
        let key = self.publisher_key().ok_or(denied("no publisher key to check it with"))?;
        let first = package::first(k);
        let header = disk_read(first, 1).map_err(|_| (("unreadable"), "", Reply::DeviceError))?;
        let len = package::length(header[..ab::SECTOR].try_into().unwrap()).ok_or(("empty", "", Reply::NotFound))?;
        let va = PACKAGE_VA + k as u64 * PACKAGE_SPAN;
        let base = PACKAGE_PAGES + k as u64 * PACKAGE_MAX_PAGES;
        let bytes = fill(&mut self.package_pages[k], base, va, first + 1, len).map_err(invalid)?;
        let signed = Signed::split(bytes).ok_or(denied("not signed"))?;
        if !signed.verify(&key) {
            return Err(denied("its signature does not verify"));
        }
        let bundle = Bundle::parse(signed.payload).map_err(|e| invalid(bundle_error(e)))?;
        let text = bundle.get("manifest").and_then(|m| core::str::from_utf8(m).ok()).ok_or(invalid("no manifest"))?;
        let pkg = Manifest::parse_unchecked(text).map_err(|e| (e.what, e.word, Reply::Invalid))?;
        // The installed package whose components it names, if they are
        // all one package's.
        let mut replaced = None;
        let mut one = true;
        for (_, c) in pkg.iter() {
            for (i, h) in self.manifest.iter() {
                if h.name == c.name {
                    match self.origin[i] {
                        Some(j) if replaced.is_none_or(|r| r == j) => replaced = Some(j),
                        _ => one = false,
                    }
                }
            }
        }
        let replaced = replaced.filter(|_| one && mode != Mode::Install);
        if mode == Mode::Upgrade && replaced.is_none() && one {
            return Err(("no installed package for it to replace", "", Reply::NotFound));
        }
        package::admit_replacing(&pkg, &self.manifest, |i| replaced.is_some() && self.origin[i] == replaced)
            .map_err(|r| (r.why, r.word, if r.taken { Reply::InUse } else { Reply::Invalid }))?;
        if let Some((_, old)) = replaced.and_then(|j| self.packages[j]) {
            if signed.version <= old {
                return Err(("no newer than the installed one", "", Reply::Denied));
            }
        }
        for (_, c) in pkg.iter() {
            if bundle.get(c.image).is_none() {
                return Err(("its image is not in it", c.image, Reply::Invalid));
            }
        }
        if self.next_component + pkg.len() > MAX_COMPONENTS {
            return Err(("no room for more components", "", Reply::InUse));
        }
        Ok((bundle, signed.version, pkg, replaced))
    }

    /// `[OP_UNINSTALL, k]`: stops store slot `k`'s components, forgets
    /// them, and clears the slot.
    fn uninstall(&mut self, k: usize) -> Reply {
        if k >= package::COUNT || self.packages[k].is_none() {
            return Reply::NotFound;
        }
        let mut names = [""; MAX_COMPONENTS];
        let mut n = 0;
        for i in 0..MAX_COMPONENTS {
            if self.origin[i] == Some(k) {
                self.stop(i);
                names[n] = self.component(i).name;
                n += 1;
                self.manifest.components[i] = None;
                self.origin[i] = None;
            }
        }
        self.packages[k] = None;
        if write_sector(package::first(k), &[0; ab::SECTOR]).is_err() {
            return Reply::DeviceError;
        }
        say!("uninstalled package in store slot {k}: {}", Names(&names[..n]));
        Reply::Ok
    }

    /// `[OP_PACKAGE_SLOT]`.
    fn package_slot(&self) -> [u64; 4] {
        match (0..package::COUNT).find(|&k| self.packages[k].is_none()) {
            Some(k) if self.disk => [Reply::Ok as u64, k as u64, package::first(k), package::SECTORS],
            Some(_) => [Reply::NotFound as u64, 0, 0, 0],
            None => [Reply::InUse as u64, 0, 0, 0],
        }
    }

    /// `[OP_PACKAGES]`.
    fn installed(&self) -> u64 {
        (0..package::COUNT).filter(|&k| self.packages[k].is_some()).map(|k| 1 << k).sum()
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

/// How a package may be installed: beside the others only (`OP_INSTALL`),
/// only in place of an older version (`OP_UPGRADE`), or either (from the
/// store at boot).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Install,
    Upgrade,
    Boot,
}

/// The two manifests together, once the system's is loaded.
static mut SYSTEM_MANIFEST: [u8; 16384] = [0; 16384];

/// Reads `count` sectors (up to a page) from the system disk into the I/O
/// page; returns them.
fn disk_read(sector: u64, count: u64) -> Result<&'static [u8], Reply> {
    let lend = CapTransfer { grant: Some(IO_PAGE as u16), accept: None };
    let r = syscall_x(Syscall::Call, SYSTEM_BLOCK, [block::READ, sector, count, 0], lend);
    match Reply::from_u64(r.msg[0]) {
        // SAFETY: the I/O page is mapped at IO_VA.
        Reply::Ok if r.status == 0 => Ok(unsafe {
            core::slice::from_raw_parts(IO_VA as *const u8, count as usize * ab::SECTOR)
        }),
        _ if r.status != 0 => Err(Reply::DeviceError),
        e => Err(e),
    }
}

/// Component names, for the log.
struct Names<'b, 'a>(&'b [&'a str]);

impl core::fmt::Display for Names<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (k, n) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            f.write_str(n)?;
        }
        Ok(())
    }
}

/// Reads `len` bytes from the system disk, from sector `first` on, into
/// pages mapped at `va` (cap slots from `base`, `made` of them made so
/// far; more are made as needed). Returns them.
fn fill<'a>(made: &mut u64, base: u64, va: u64, first: u64, len: usize) -> Result<&'a [u8], &'static str> {
    let pages = len.div_ceil(4096) as u64;
    while *made < pages {
        let p = *made;
        retype(root::UNTYPED, ObjectType::Frame, 0, base + p)
            .and_then(|_| sys(Syscall::FrameMap, base + p, [va + p * 4096, 1, 0, 0]).map(drop))
            .map_err(|_| "no memory for it")?;
        *made += 1;
    }
    for p in 0..pages {
        let sectors = (len - p as usize * 4096).div_ceil(ab::SECTOR).min(8) as u64;
        let data = disk_read(first + p * 8, sectors).map_err(|_| "unreadable")?;
        // SAFETY: page p is mapped at this address.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), (va + p * 4096) as *mut u8, sectors as usize * ab::SECTOR);
        }
    }
    // SAFETY: the pages just filled, mapped for as long as this runs.
    Ok(unsafe { core::slice::from_raw_parts(va as *const u8, len) })
}

/// Writes the boot record and flushes it to stable storage.
fn write_record(r: &Record) -> Result<(), Reply> {
    write_sector(ab::RECORD_SECTOR, &r.encode())
}

/// Writes one sector of the system disk and flushes it to stable storage.
fn write_sector(sector: u64, data: &[u8; ab::SECTOR]) -> Result<(), Reply> {
    // SAFETY: the I/O page is mapped at IO_VA, a page long.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), IO_VA as *mut u8, ab::SECTOR) };
    let lend = CapTransfer { grant: Some(IO_PAGE as u16), accept: None };
    let w = syscall_x(Syscall::Call, SYSTEM_BLOCK, [block::WRITE, sector, 1, 0], lend);
    let f = syscall(Syscall::Call, SYSTEM_BLOCK, [block::FLUSH, 0, 0, 0]);
    let ok = |r: &Ret| r.status == 0 && r.msg[0] == Reply::Ok as u64;
    if ok(&w) && ok(&f) { Ok(()) } else { Err(Reply::DeviceError) }
}

/// Checks the signed bundle in slot `slot` without holding it all: the
/// trailer first, then the signed part streamed through the verifier.
/// Returns its version.
fn check_slot(slot: u8, key: &[u8; 32], floor: u64) -> Result<u64, (&'static str, Reply)> {
    use superior_objects::bundle::{SIG_MAGIC, TRAILER};
    use superior_objects::crypto::ed25519::Verifier;
    let unreadable = |_| ("unreadable", Reply::DeviceError);
    let first = ab::SLOT_FIRST[slot as usize] + 1;
    let header = disk_read(first - 1, 1).map_err(unreadable)?;
    let len = ab::slot_length(header[..ab::SECTOR].try_into().unwrap()).ok_or(("empty", Reply::Invalid))?;
    if len < TRAILER {
        return Err(("not signed", Reply::Denied));
    }
    // The trailer, in the one or two sectors at the end.
    let at = len - TRAILER;
    let s0 = (at / ab::SECTOR) as u64;
    let s1 = ((len - 1) / ab::SECTOR) as u64;
    let data = disk_read(first + s0, s1 - s0 + 1).map_err(unreadable)?;
    let off = at - s0 as usize * ab::SECTOR;
    let mut trailer = [0u8; TRAILER];
    trailer.copy_from_slice(&data[off..off + TRAILER]);
    if &trailer[..8] != SIG_MAGIC {
        return Err(("not signed", Reply::Denied));
    }
    let version = u64::from_le_bytes(trailer[8..16].try_into().unwrap());
    let signature: [u8; 64] = trailer[16..].try_into().unwrap();
    let mut v = Verifier::new(key, &signature);
    let signed = len - 64;
    let mut done = 0;
    while done < signed {
        let sectors = (signed - done).div_ceil(ab::SECTOR).min(8);
        let data = disk_read(first + (done / ab::SECTOR) as u64, sectors as u64).map_err(unreadable)?;
        let n = (signed - done).min(sectors * ab::SECTOR);
        v.update(&data[..n]);
        done += n;
    }
    if !v.finish() {
        return Err(("its signature does not verify", Reply::Denied));
    }
    if version < floor {
        return Err(("older than the rollback floor", Reply::Invalid));
    }
    Ok(version)
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// The manager's slot holding the device capability called `name`.
/// `msi` is all the MSI vectors, in consecutive slots from the one named;
/// `intx` the legacy PCI interrupt lines likewise (absent where the
/// kernel does not know the machine's routing: those slots stay empty);
/// `ps2` the controller's two ports; the rest are one capability each
/// (`iommu`, `ps2` and `framebuffer` may be absent). Returns
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
        "ps2" => (root::PS2, root::PS2_COUNT),
        "framebuffer" => (root::FRAMEBUFFER, 1),
        _ => return None,
    })
}

fn map_into(frame: u64, va: u64, flags: u64, vspace: u64) -> Result<(), u64> {
    sys(Syscall::FrameMapInto, frame, [va, flags, vspace, 0]).map(drop)
}

/// Copies `bytes` into pages retyped from `ut` (a `file` directive), placed
/// in consecutive indexes of the CNode in slot `cnode` from `index`. Each
/// page is written through the scratch mapping; the component's copy is
/// the only capability left to it.
fn copy_file(bytes: &[u8], ut: u64, to: Dest, index: u64) -> Result<(), u64> {
    for (p, chunk) in bytes.chunks(PAGE as usize).enumerate() {
        if to.index(index + p as u64).is_none() {
            continue;
        }
        retype(ut, ObjectType::Frame, 0, FILE_SCRATCH)?;
        let r = sys(Syscall::FrameMap, FILE_SCRATCH, [SCRATCH_VA, 1, 0, 0])
            .map(|_| {
                // SAFETY: the page was just mapped at SCRATCH_VA, writable,
                // and a chunk is at most a page.
                unsafe {
                    core::ptr::copy_nonoverlapping(chunk.as_ptr(), SCRATCH_VA as *mut u8, chunk.len())
                }
            })
            .and_then(|_| sys(Syscall::FrameUnmap, FILE_SCRATCH, [0; 4]))
            .and_then(|_| to.copy(index + p as u64, FILE_SCRATCH, ALL, 0));
        let _ = syscall(Syscall::CapDelete, FILE_SCRATCH, [0; 4]);
        r?;
    }
    Ok(())
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
        Some(FaultKind::ForeignSyscall) => "foreign system call",
        Some(FaultKind::Timeout) => "caller's budget ran out mid-request",
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
        system: None,
        manifest,
        service_count: 0,
        record: Record::default(),
        booted: None,
        system_pages: 0,
        disk: false,
        packages: [None; package::COUNT],
        package_pages: [0; package::COUNT],
        origin: [None; MAX_COMPONENTS],
        next_component: 0,
        status: [Status::NotStarted; MAX_COMPONENTS],
        services: [None; MAX_SERVICES],
        made: [false; MAX_COMPONENTS],
        block_made: [false; MAX_COMPONENTS],
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
    m.make_blocks();
    if retype(root::UNTYPED, ObjectType::Endpoint, 0, CONTROL).is_err() {
        say!("could not make the control endpoint");
        shutdown(false);
    }
    // Every service endpoint, made and kept by the manager; then the
    // boot components; then the system in the A/B slots, if any.
    m.wire(0);
    m.load_system(text);
    m.load_packages();

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
            BADGE_REPORT
                if i < MAX_COMPONENTS && m.component(i).update_control && msg.msg[0] == update::OP_RESTART =>
            {
                say!("{} asked to restart the machine", m.component(i).name);
                reboot()
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS
                    && m.component(i).update_control
                    && (update::OP_BOOT_INFO..=update::OP_UPDATE_READY).contains(&msg.msg[0]) =>
            {
                Some(match msg.msg[0] {
                    update::OP_BOOT_INFO => m.boot_info(),
                    update::OP_BOOT_OK => [m.boot_ok() as u64, 0, 0, 0],
                    update::OP_UPDATE_SLOT => m.update_slot(),
                    _ => [m.update_ready() as u64, 0, 0, 0],
                })
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS
                    && m.component(i).install_control
                    && ((install::OP_PACKAGES..=install::OP_UNINSTALL).contains(&msg.msg[0])
                        || msg.msg[0] == install::OP_UPGRADE) =>
            {
                Some(match msg.msg[0] {
                    install::OP_PACKAGES => [Reply::Ok as u64, m.installed(), 0, 0],
                    install::OP_PACKAGE_SLOT => m.package_slot(),
                    install::OP_INSTALL | install::OP_UPGRADE => {
                        let mode = if msg.msg[0] == install::OP_INSTALL { Mode::Install } else { Mode::Upgrade };
                        match m.install(msg.msg[1] as usize, mode) {
                            Ok((n, j)) => [Reply::Ok as u64, n as u64, j.map_or(u64::MAX, |j| j as u64), 0],
                            Err(e) => [e as u64, 0, 0, 0],
                        }
                    }
                    _ => [m.uninstall(msg.msg[1] as usize) as u64, 0, 0, 0],
                })
            }
            BADGE_REPORT
                if i < MAX_COMPONENTS
                    && m.component(i).launch_control
                    && ((launch::OP_LAUNCHERS..=launch::OP_ICON_PIXELS).contains(&msg.msg[0])
                        || msg.msg[0] == launch::OP_LAUNCHER_OF) =>
            {
                Some(if msg.msg[0] == launch::OP_LAUNCHER_OF {
                    let i = (msg.msg[1] as usize).wrapping_sub(1);
                    match (0..MAX_COMPONENTS).find(|&k| m.launcher(k) == Some(i)) {
                        Some(k) => [Reply::Ok as u64, k as u64, 0, 0],
                        None => [Reply::NotFound as u64, 0, 0, 0],
                    }
                } else if msg.msg[0] == launch::OP_ICON_PIXELS {
                    m.icon_pixels(msg.msg[1] as usize, msg.msg[2] as usize)
                } else if msg.msg[0] != launch::OP_LAUNCH {
                    match m.launcher(msg.msg[1] as usize) {
                        Some(t) => {
                            let c = m.component(t);
                            let what = if msg.msg[0] == launch::OP_ICON { c.icon } else { c.name };
                            let w = launch::words(what.as_bytes());
                            [Reply::Ok as u64, w[0], w[1], w[2]]
                        }
                        None => [Reply::NotFound as u64, 0, 0, 0],
                    }
                } else {
                    [m.launch([msg.msg[1], msg.msg[2], msg.msg[3]]) as u64, 0, 0, 0]
                })
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
