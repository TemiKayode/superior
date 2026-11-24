//! Threads, their capability spaces, and system call handling.
//!
//! System call arguments are named by their x86-64 registers below (`rdi`
//! names the capability, `rsi`, `rdx`, `r8`, `r9` the message words, `r10`
//! the transfer word, `rax` the number and result). On AArch64 they are
//! `x0`, `x1`-`x4`, `x5` and `x8`; see `arch::Args`.
//!
//! Each thread has a saved [`UserFrame`], an address space, and a capability
//! space (CSpace) of [`CSPACE_SLOTS`] slots. A system call names a
//! capability by slot; this module resolves it, checks rights, and passes
//! the object index to the IPC engine in `superior_objects::ipc`, which
//! decides who runs next.
//!
//! A thread's CSpace starts as its own window of [`CSPACE_SLOTS`] slots; a
//! CNode made by retype can replace it (`ThreadSetSpace`). Either way it is
//! a range of one capability table, so a capability
//! granted through IPC is derived from the sender's across CSpaces, and
//! revoking the sender's copy reaches every copy it handed out.
//!
//! Kernel objects: user space makes endpoints, notifications and smaller
//! untyped blocks with `Retype`, which consumes memory from an untyped
//! capability, threads that run in the creator's address space, and 4 KiB
//! frames they can map into their own address space
//! (`FrameMap`). A frame capability records where it is mapped; deleting or
//! revoking it unmaps it first, so memory is never reused while still
//! mapped. The endpoint and notification state itself lives in the IPC
//! engine's fixed tables; retype claims a free entry, and the entry is
//! freed (waking anyone blocked on it with an error) once the last
//! capability to the object is gone. The memory consumed is real
//! accounting: an untyped block can only make as many objects as fit, and
//! gets its memory back only when revoked.
//!
//! The kernel is entered two ways, a system call or a timer interrupt, and
//! both end in [`resume`]. A thread that entered by system call gets its
//! results in registers and leaves by `sysret`; a thread that was
//! preempted gets its exact registers back by `iretq`.
//!
//! When no thread can run, [`resume`] idles: it halts the CPU with
//! interrupts enabled, the one place the kernel ever enables them, until
//! an interrupt makes a thread runnable. The timer signals notification
//! [`TIMER_NTFN`] on every tick, so a thread can sleep by waiting on it.
//!
//! Several CPUs share the kernel under one lock ([`lock_kernel`]); the IPC
//! engine keeps each CPU's current thread. A CPU entering the kernel saves
//! the registers of the thread it ran ([`save_running`]); if another CPU
//! stopped that thread meanwhile, the engine lets it go then, and a system
//! call it was making is made again when it next runs. After its work a
//! CPU kicks any other that now has something better to run (see
//! `crate::smp`).

use crate::arch::vm::{self, AddressSpace};
use crate::arch::{self, Args, Exit, UserFrame, iommu};
use crate::iommu::IoFault;
use crate::memory::{MapError, TablePool};
use crate::smp::{self, MAX_CPUS};
use crate::{kprint, kprintln};
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};
use superior_objects::abi::{
    CNODE_SLOT_BITS, CapTransfer, DEVICE_FRAME_MAX_BITS, Error, FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType,
    Syscall,
};
use superior_objects::cap::{CapError, Capability, Object, Rights, Slot, Table};
use superior_objects::ipc::{Ipc, Tid};

/// Table sizes. Self-test builds keep them small: the self-test fills
/// each table to prove that freeing objects frees their entries.
#[cfg(not(feature = "selftest"))]
pub const MAX_THREADS: usize = 32;
#[cfg(feature = "selftest")]
pub const MAX_THREADS: usize = 9;
const _: () = assert!(arch::TICK_HZ as u64 == superior_objects::abi::TICK_HZ);
pub const CSPACE_SLOTS: usize = 16;
/// Layout of the one capability table: each thread's own window, then one
/// hidden slot per thread holding its CNode CSpace's capability (which keeps
/// the CNode alive), then one hidden slot per thread holding its address
/// space's capability (likewise), then the slots CNode objects are carved
/// from. That pool is sized at boot to the machine's RAM ([`init_tables`]):
/// a slot for every page, so the Memory Server can hold a capability to
/// each, plus [`BASE_CHUNKS`] chunks for everything else.
const WINDOW_SLOTS: usize = MAX_THREADS * CSPACE_SLOTS;
const ROOT_SLOTS: usize = WINDOW_SLOTS;
const VSPACE_SLOTS: usize = ROOT_SLOTS + MAX_THREADS;
const CNODE_POOL: usize = VSPACE_SLOTS + MAX_THREADS;
/// CNodes are made of 16-slot chunks, aligned to their own size.
const CNODE_CHUNK: usize = 16;
#[cfg(not(feature = "selftest"))]
const BASE_CHUNKS: usize = 512;
/// Self-test builds keep the pool this small, so the self-test can fill it.
#[cfg(feature = "selftest")]
const BASE_CHUNKS: usize = 16;
#[cfg(not(feature = "selftest"))]
const MAX_ENDPOINTS: usize = 32;
#[cfg(feature = "selftest")]
const MAX_ENDPOINTS: usize = 8;
#[cfg(not(feature = "selftest"))]
const MAX_NOTIFICATIONS: usize = 64;
#[cfg(feature = "selftest")]
const MAX_NOTIFICATIONS: usize = 8;
/// Address spaces: one per boot process, plus address-space objects.
const MAX_SPACES: usize = 32;
/// I/O address spaces (IOMMU domains): one per device a driver holds.
const MAX_IO_SPACES: usize = 8;
const DEBUG_STR_MAX: usize = 256;
/// Interrupt lines a notification can be bound to.
const MAX_IRQS: usize = 256;
/// The notification the timer signals (bit 0) on every tick.
pub const TIMER_NTFN: u16 = 0;
/// Pending `TimerSignal`s at once, across the system (one per
/// notification).
const MAX_TIMERS: usize = 64;
/// Self-test builds give up after this many seconds, so a deadlock fails
/// the test instead of idling forever.
#[cfg(feature = "selftest")]
const SELFTEST_TIMEOUT_SECS: u64 = 60;
/// The root task's thread (the Component Manager).
pub const ROOT_TID: Tid = 0;
/// More fast reboots than this within [`REBOOT_WINDOW`] ticks and the
/// kernel gives up: the root task is failing at once, every time.
const MAX_REBOOTS: usize = 5;
const REBOOT_WINDOW: u64 = 60 * superior_objects::abi::TICK_HZ;

#[derive(Clone, Copy, Default)]
struct Stats {
    ticks: u64,
    /// Timer ticks that took the CPU from one thread and gave it to another.
    preemptions: u64,
    /// Times the CPU halted because no thread could run.
    idle_halts: u64,
    /// User faults sent to a handler, and faults that stopped a thread.
    faults_handled: u64,
    faults_unhandled: u64,
    /// DMA requests the IOMMU blocked, and those from functions bound to
    /// no I/O address space (or lost to a full fault log).
    io_faults: u64,
    io_faults_unowned: u64,
    /// IOMMU fault interrupts taken.
    io_fault_irqs: u64,
    /// Returns to user mode, by CPU.
    resumes: [u64; MAX_CPUS],
}

/// An address space and where its page tables come from.
#[derive(Clone, Copy)]
struct VSpace {
    root: AddressSpace,
    pool: TablePool,
    /// Made by retype (so destroyed with its last capability), not by the
    /// kernel at boot.
    object: bool,
}

/// An I/O address space: its memory (header page, top-level table, then
/// the pool its other tables come from) and the PCI function bound to it.
#[derive(Clone, Copy)]
struct IoDomain {
    base: u64,
    pool: TablePool,
    sid: Option<u16>,
    /// DMA requests the IOMMU blocked since the holder last asked
    /// (`IoFaults`), and the first of them: page address and whether it
    /// was a write; and interrupt messages it blocked.
    faults: u64,
    first_fault: (u64, bool),
    irq_faults: u64,
    /// Signalled (notification id, badge) when the IOMMU blocks one of
    /// its device's requests (`IoFaultNotify`).
    notify: Option<(u16, u64)>,
}

impl IoDomain {
    fn root(&self) -> u64 {
        self.base + 4096
    }
}

struct Kernel {
    /// Notifications: the ones objects name (`MAX_NOTIFICATIONS`), then
    /// one per thread for [`sleep`], which only the kernel signals.
    ipc: Ipc<MAX_THREADS, MAX_ENDPOINTS, { MAX_NOTIFICATIONS + MAX_THREADS }>,
    frames: [UserFrame; MAX_THREADS],
    /// Address spaces by id.
    vspaces: [Option<VSpace>; MAX_SPACES],
    /// The address space each thread runs in.
    spaces: [Option<u16>; MAX_THREADS],
    /// Every capability: thread windows, CSpace roots and CNode objects.
    caps: BootTable<Table>,
    /// Each thread's CSpace as (first table index, slot count). Empty if
    /// its CNode was destroyed under it.
    cspace: [(u32, u32); MAX_THREADS],
    /// Live CNode objects, by first pool chunk: their slot-count bits.
    cnodes: BootTable<[Option<u8>]>,
    /// Pool chunks some CNode covers.
    chunk_used: BootTable<[bool]>,
    /// Scratch for [`reap`]: pool chunks a capability names as a CNode.
    cnode_live: BootTable<[bool]>,
    /// Notification (and badge) each interrupt line signals.
    irq_ntfn: [Option<(u16, u64)>; MAX_IRQS],
    /// The capability this thread last called through had Grant or
    /// GrantReply, so its server's reply may carry a capability.
    reply_grant: [bool; MAX_THREADS],
    /// Endpoint and notification table entries in use by some object.
    ep_used: [bool; MAX_ENDPOINTS],
    ntfn_used: [bool; MAX_NOTIFICATIONS],
    /// Pending `TimerSignal`s: (deadline in ticks, notification, bits).
    timers: [Option<(u64, u16, u64)>; MAX_TIMERS],
    /// When each sleeping thread wakes (`Sleep`).
    sleep_until: [Option<u64>; MAX_THREADS],
    /// While the machine is suspended (`Suspend`): who asked, and the ticks
    /// still to wait beyond the alarm now set.
    suspend: Option<Suspended>,
    /// Which CPUs have stopped their tick and halted for the suspend.
    parked: [bool; MAX_CPUS],
    /// Where the frame capability in each capability-table slot is mapped:
    /// (address space, user address).
    mapped: BootTable<[Mapping]>,
    /// I/O address spaces by id.
    io_spaces: [Option<IoDomain>; MAX_IO_SPACES],
    /// Where the frame capability in each capability-table slot is mapped
    /// for DMA: (I/O address space, I/O address).
    io_mapped: BootTable<[Mapping]>,
    /// Each thread's fault handler: endpoint and badge.
    fault_ep: [Option<(u16, u64)>; MAX_THREADS],
    /// Blocked in a fault call: the reply says how to resume.
    in_fault: [bool; MAX_THREADS],
    /// That fault call is a foreign system call: its pc is past the
    /// instruction that made it.
    syscall_fault: [bool; MAX_THREADS],
    /// Runs a foreign ABI: its system calls are faults (`REGS_FOREIGN`).
    foreign: [bool; MAX_THREADS],
    /// Its thread pointer (`REGS_SET_TLS`; on AArch64 also whatever it
    /// put in `TPIDR_EL0` itself).
    tls: [u64; MAX_THREADS],
    /// A foreign thread's FPU and SIMD registers while it is not running.
    fp: [arch::FpState; MAX_THREADS],
    /// The thread whose FPU registers each CPU holds, if any.
    fp_owner: [Option<Tid>; MAX_CPUS],
    /// Thread table entries in use, by a boot thread or a Thread object.
    thread_used: [bool; MAX_THREADS],
    /// Made by retype (so destroyed with its last capability).
    thread_object: [bool; MAX_THREADS],
    /// Scheduling-context table entries in use: by a boot thread (entry
    /// `t` for boot thread `t`, kept for good) or a SchedContext object.
    sc_used: [bool; MAX_THREADS],
    /// Made by retype (so destroyed with its last capability).
    sc_object: [bool; MAX_THREADS],
    /// Configured with ThreadConfigure, and at what priority.
    configured: [Option<u8>; MAX_THREADS],
    /// Not yet run: its frame holds start registers (entry, stack, argument),
    /// not the results of a system call, and must be resumed untouched.
    fresh: [bool; MAX_THREADS],
    /// Last left user mode by interrupt: its frame is complete and must be
    /// resumed untouched, including `rcx` and `r11`.
    preempted: [bool; MAX_THREADS],
    /// The thread whose registers each CPU holds (it last resumed it), if
    /// they are still wanted: saved into `frames` when that CPU next
    /// enters the kernel.
    running: [Option<Tid>; MAX_CPUS],
    /// When each of the last [`MAX_REBOOTS`] fast reboots happened, as a
    /// ring indexed by the reboot count.
    reboot_ticks: [u64; MAX_REBOOTS],
    stats: Stats,
}

/// Where a frame capability is mapped: (space id, page-aligned address),
/// packed in one word (the id, plus one, in the address's low 12 bits;
/// 0 for nowhere), so a table of them takes 8 bytes a slot.
#[derive(Clone, Copy)]
struct Mapping(u64);

impl Mapping {
    const NONE: Mapping = Mapping(0);

    fn new(id: u16, addr: u64) -> Mapping {
        debug_assert!(addr & 0xfff == 0 && (id as u64) < 0xfff);
        Mapping(addr | (id as u64 + 1))
    }

    fn is_some(self) -> bool {
        self.0 != 0
    }

    fn is_none(self) -> bool {
        self.0 == 0
    }

    /// The space it is mapped in, if any.
    fn space(self) -> Option<u16> {
        (self.0 != 0).then(|| ((self.0 & 0xfff) - 1) as u16)
    }

    /// The mapping, leaving none.
    fn take(&mut self) -> Option<(u16, u64)> {
        let m = core::mem::replace(self, Mapping::NONE).0;
        (m != 0).then(|| (((m & 0xfff) - 1) as u16, m & !0xfff))
    }
}

/// A table the kernel sets aside at boot, sized to the machine's RAM
/// ([`init_tables`]). A pointer, so the kernel's statics hold none of it
/// and need no memory before boot; empty until then.
struct BootTable<T: ?Sized>(*mut T);

// SAFETY: a boot table is reached only through the kernel, under its lock.
unsafe impl<T: ?Sized> Send for BootTable<T> {}

impl<T: ?Sized> Deref for BootTable<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: an empty slice, or memory `init_tables` set aside and
        // initialised for this table alone.
        unsafe { &*self.0 }
    }
}

impl<T: ?Sized> DerefMut for BootTable<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above; `&mut self` makes this the only reference.
        unsafe { &mut *self.0 }
    }
}

const fn no_slice<T>() -> BootTable<[T]> {
    BootTable(core::ptr::slice_from_raw_parts_mut(
        core::ptr::NonNull::dangling().as_ptr(),
        0,
    ))
}

/// Sets aside the capability table and the tables that go with it, sized
/// to the machine's RAM, from the kernel's own untyped memory. Called once,
/// at boot, before any capability is placed. Returns the table's slots and
/// the bytes it all took.
pub fn init_tables(ram_bytes: u64) -> Result<(usize, u64), &'static str> {
    let pages = (ram_bytes / 4096) as usize;
    let chunks = if cfg!(feature = "selftest") {
        BASE_CHUNKS
    } else {
        BASE_CHUNKS + pages.next_power_of_two() / CNODE_CHUNK
    };
    let slots = CNODE_POOL + chunks * CNODE_CHUNK;
    let align8 = |n: usize| (n + 7) & !7;
    let caps_at = 0;
    let mapped_at = align8(caps_at + slots * Table::SLOT_BYTES);
    let io_at = align8(mapped_at + slots * size_of::<Mapping>());
    let cnodes_at = align8(io_at + slots * size_of::<Mapping>());
    let used_at = align8(cnodes_at + chunks * size_of::<Option<u8>>());
    let live_at = used_at + chunks;
    let bytes = (live_at + chunks) as u64;
    let bits = bytes.next_power_of_two().trailing_zeros().max(12) as u8;
    let pa = crate::memory::carve(bits).ok_or("no memory for the capability table")?;
    let p = vm::phys_ptr(pa);
    fn fill<T: Copy>(at: *mut u8, len: usize, v: T) -> BootTable<[T]> {
        let t = at as *mut T;
        for i in 0..len {
            // SAFETY: inside the block carved for these tables.
            unsafe { t.add(i).write(v) };
        }
        BootTable(core::ptr::slice_from_raw_parts_mut(t, len))
    }
    let mut k = KERNEL.lock();
    // SAFETY: the block was just carved for these tables alone, and is
    // RAM the kernel maps; every offset is 8-aligned and inside it.
    unsafe {
        k.caps = BootTable(Table::init(p.add(caps_at), slots) as *mut Table);
        k.mapped = fill(p.add(mapped_at), slots, Mapping::NONE);
        k.io_mapped = fill(p.add(io_at), slots, Mapping::NONE);
        k.cnodes = fill(p.add(cnodes_at), chunks, None);
        k.chunk_used = fill(p.add(used_at), chunks, false);
        k.cnode_live = fill(p.add(live_at), chunks, false);
    }
    Ok((slots, 1 << bits))
}

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel {
    ipc: Ipc::new(),
    frames: [UserFrame::ZERO; MAX_THREADS],
    vspaces: [None; MAX_SPACES],
    spaces: [None; MAX_THREADS],
    caps: BootTable(no_slice::<Slot>().0 as *mut Table),
    cspace: {
        let mut c = [(0, 0); MAX_THREADS];
        let mut t = 0;
        while t < MAX_THREADS {
            c[t] = window(t);
            t += 1;
        }
        c
    },
    cnodes: no_slice(),
    chunk_used: no_slice(),
    cnode_live: no_slice(),
    irq_ntfn: [None; MAX_IRQS],
    timers: [None; MAX_TIMERS],
    sleep_until: [None; MAX_THREADS],
    suspend: None,
    parked: [false; MAX_CPUS],
    reply_grant: [false; MAX_THREADS],
    ep_used: [false; MAX_ENDPOINTS],
    mapped: no_slice(),
    io_spaces: [None; MAX_IO_SPACES],
    io_mapped: no_slice(),
    fault_ep: [None; MAX_THREADS],
    in_fault: [false; MAX_THREADS],
    syscall_fault: [false; MAX_THREADS],
    foreign: [false; MAX_THREADS],
    tls: [0; MAX_THREADS],
    fp: [arch::FpState::INITIAL; MAX_THREADS],
    fp_owner: [None; MAX_CPUS],
    thread_used: [false; MAX_THREADS],
    thread_object: [false; MAX_THREADS],
    sc_used: [false; MAX_THREADS],
    sc_object: [false; MAX_THREADS],
    configured: [None; MAX_THREADS],
    // The timer's notification belongs to the kernel and is never freed.
    ntfn_used: {
        let mut u = [false; MAX_NOTIFICATIONS];
        u[TIMER_NTFN as usize] = true;
        u
    },
    fresh: [false; MAX_THREADS],
    preempted: [false; MAX_THREADS],
    running: [None; MAX_CPUS],
    reboot_ticks: [0; MAX_REBOOTS],
    stats: Stats {
        ticks: 0,
        preemptions: 0,
        idle_halts: 0,
        faults_handled: 0,
        faults_unhandled: 0,
        io_faults: 0,
        io_faults_unowned: 0,
        io_fault_irqs: 0,
        resumes: [0; MAX_CPUS],
    },
});

/// Creates a thread in a new address space running `image`, with `arg` in
/// `rdi` and the given capabilities installed in its CSpace.
pub fn spawn_process(
    tid: Tid,
    image: &[u8],
    prio: u8,
    arg: u64,
    caps: &[(usize, Capability)],
) -> Result<(), &'static str> {
    spawn_process_with(tid, image, prio, arg, caps, &[])
}

/// [`spawn_process`], also mapping each `(address, bytes)` of `extra`
/// read-only into the new address space.
pub fn spawn_process_with(
    tid: Tid,
    image: &[u8],
    prio: u8,
    arg: u64,
    caps: &[(usize, Capability)],
    extra: &[(u64, &[u8])],
) -> Result<(), &'static str> {
    let space = AddressSpace::new()?;
    let entry = space.load_elf(image)?;
    let stack_top = space.map_stack()?;
    for &(va, data) in extra {
        space.map_data(va, data)?;
    }

    let mut k = KERNEL.lock();
    let t = tid as usize;
    if t >= MAX_THREADS {
        return Err("thread id out of range");
    }
    for &(slot, cap) in caps {
        let slot = cap_slot(&k, tid, slot).ok_or("cspace slot out of range")?;
        k.caps
            .insert_root(slot, cap)
            .map_err(|_| "cspace slot unavailable")?;
        match cap.object {
            Object::Endpoint { id } => k.ep_used[id as usize] = true,
            Object::Notification { id } => k.ntfn_used[id as usize] = true,
            _ => {}
        }
    }
    let id = k
        .vspaces
        .iter()
        .position(Option::is_none)
        .ok_or("address-space table full")?;
    // The root task's address space grows (page tables for what it maps)
    // from its arena, which a fast reboot hands out again.
    let pool = if crate::memory::arena_active() {
        TablePool::Arena
    } else {
        TablePool::Kernel
    };
    k.vspaces[id] = Some(VSpace {
        root: space,
        pool,
        object: false,
    });
    k.frames[t] = UserFrame::new_thread(entry, stack_top, arg);
    k.spaces[t] = Some(id as u16);
    k.thread_used[t] = true;
    k.fresh[t] = true;
    k.sc_used[t] = true;
    k.ipc
        .bind_sc(tid, Some(tid))
        .map_err(|_| "could not bind the thread's scheduling context")?;
    k.ipc
        .spawn(tid, prio)
        .map_err(|_| "could not make thread runnable")?;
    Ok(())
}

/// Derives a capability from one thread's CSpace into another's, as a
/// child of the source (so revoking the source removes it).
pub fn derive_cap(
    from: Tid,
    src: usize,
    to: Tid,
    dst: usize,
    mask: Rights,
    badge: Option<u64>,
) -> Result<(), &'static str> {
    let mut k = KERNEL.lock();
    let (Some(src), Some(dst)) = (cap_slot(&k, from, src), cap_slot(&k, to, dst)) else {
        return Err("cspace slot out of range");
    };
    k.caps
        .derive(src, dst, mask, badge)
        .map_err(|_| "derive failed")
}

/// Limits thread `t` to `budget` timer ticks in every `period` ticks.
pub fn configure_sched(t: Tid, budget: u32, period: u32) -> Result<(), &'static str> {
    KERNEL
        .lock()
        .ipc
        .configure_sc(t, budget, period)
        .map_err(|_| "bad scheduling parameters")
}

/// Makes endpoint `ep` (with `badge`) thread `t`'s timeout handler at boot.
pub fn set_timeout_handler(t: Tid, ep: u16, badge: u64) -> Result<(), &'static str> {
    KERNEL
        .lock()
        .ipc
        .set_timeout_handler(t, Some((ep, badge)))
        .map_err(|_| "bad timeout handler")
}

/// Places an original capability in thread `t`'s slot `slot` at boot.
pub fn grant_root(t: Tid, slot: usize, cap: Capability) -> Result<(), &'static str> {
    let mut k = KERNEL.lock();
    let s = cap_slot(&k, t, slot).ok_or("cspace slot out of range")?;
    k.caps
        .insert_root(s, cap)
        .map_err(|_| "cspace slot unavailable")
}

/// Gives boot thread `t` a CSpace of `1 << bits` slots (a CNode from the
/// pool) in place of its window, before any capability is placed in it.
/// Its own slot `self_slot` gets a capability to that CNode.
pub fn give_cnode(t: Tid, bits: u8, self_slot: usize) -> Result<(), &'static str> {
    let mut k = KERNEL.lock();
    let k = &mut *k;
    let c = alloc_cnode(k, bits).ok_or("CNode pool full")?;
    claim_cnode(k, c, bits);
    let base = CNODE_POOL + c * CNODE_CHUNK;
    let cap = Capability::new(
        Object::CNode {
            base: base as u32,
            size_bits: bits,
        },
        Rights::READ | Rights::WRITE | Rights::GRANT,
    );
    let root = ROOT_SLOTS + t as usize;
    k.caps
        .insert_root(root, cap)
        .map_err(|_| "CSpace root slot in use")?;
    k.cspace[t as usize] = (base as u32, 1 << bits);
    k.caps
        .derive(root, base + self_slot, Rights::ALL, None)
        .map_err(|_| "CNode self slot")?;
    Ok(())
}

/// Index in the capability table of thread `t`'s slot `slot`.
fn cap_slot(k: &Kernel, t: Tid, slot: usize) -> Option<usize> {
    let (base, size) = *k.cspace.get(t as usize)?;
    (slot < size as usize).then(|| base as usize + slot)
}

/// Thread `t`'s own window of the capability table.
const fn window(t: usize) -> (u32, u32) {
    ((t * CSPACE_SLOTS) as u32, CSPACE_SLOTS as u32)
}

/// Runs the highest-priority thread this CPU can, idling until there is
/// one. Every CPU ends its boot here. Never returns: from here on the
/// kernel is entered only through system calls and traps.
pub fn start() -> ! {
    let mut frame = UserFrame::ZERO;
    let guard = lock_kernel();
    resume(guard, &mut frame);
    arch::enter_user(frame)
}

/// The kernel lock is fair: CPUs get it in the order they asked for it
/// (a ticket each), so none can be kept waiting behind the others for
/// ever, which strict priorities across CPUs would otherwise allow.
static TICKET_NEXT: AtomicU32 = AtomicU32::new(0);
static TICKET_SERVING: AtomicU32 = AtomicU32::new(0);

/// The kernel, locked by one CPU; dropping it passes the lock on to the
/// next ticket.
struct KernelGuard(ManuallyDrop<MutexGuard<'static, Kernel>>);

impl Deref for KernelGuard {
    type Target = Kernel;
    fn deref(&self) -> &Kernel {
        &self.0
    }
}

impl DerefMut for KernelGuard {
    fn deref_mut(&mut self) -> &mut Kernel {
        &mut self.0
    }
}

impl Drop for KernelGuard {
    fn drop(&mut self) {
        // SAFETY: dropped once, here; the next ticket finds it unlocked.
        unsafe { ManuallyDrop::drop(&mut self.0) };
        TICKET_SERVING.fetch_add(1, Ordering::Release);
    }
}

/// Takes the kernel lock for this CPU, in turn, carrying out shootdown
/// requests while it waits (the CPU holding the lock may be waiting for
/// them).
fn lock_kernel() -> KernelGuard {
    let ticket = TICKET_NEXT.fetch_add(1, Ordering::Relaxed);
    while TICKET_SERVING.load(Ordering::Acquire) != ticket {
        smp::service();
        core::hint::spin_loop();
    }
    // This CPU's turn: the lock is free, or about to be (its holder has
    // passed the turn on and is releasing it).
    loop {
        if let Some(mut k) = KERNEL.try_lock() {
            k.ipc.set_cpu(arch::cpu_id());
            smp::kicked();
            return KernelGuard(ManuallyDrop::new(k));
        }
        smp::service();
        core::hint::spin_loop();
    }
}

/// Saves the registers of the thread this CPU ran, which entered the
/// kernel with `frame` (by system call if `syscall`). Returns it if it is
/// still this CPU's to run; `None` if another CPU stopped it meanwhile
/// (then a system call it made is made again when it next runs).
fn save_running(k: &mut Kernel, frame: &UserFrame, syscall: bool) -> Option<Tid> {
    let me = arch::cpu_id();
    let t = k.running[me].take();
    if let Some(t) = t {
        k.frames[t as usize] = *frame;
        k.preempted[t as usize] = !syscall;
        if let Some(tls) = arch::user_tls() {
            k.tls[t as usize] = tls;
        }
        if k.fp_owner[me] == Some(t) {
            arch::fp_save(&mut k.fp[t as usize]);
        }
    }
    if let Some(gone) = k.ipc.settle() {
        if Some(gone) == t && syscall {
            k.frames[gone as usize].rewind_syscall();
            k.preempted[gone as usize] = true;
        }
        return None;
    }
    t
}

/// The registers in `frames[t]` are being replaced: whatever CPU still
/// holds `t`'s old ones must not save them over the new.
fn disown(k: &mut Kernel, t: Tid) {
    for r in k.running.iter_mut() {
        if *r == Some(t) {
            *r = None;
        }
    }
}

pub fn handle_syscall(frame: &mut UserFrame) -> Exit {
    let mut guard = lock_kernel();
    let k = &mut *guard;
    let Some(cur) = save_running(k, frame, true) else {
        return resume(guard, frame);
    };

    if k.foreign[cur as usize] {
        // Not a Superior system call: its handler (a personality server)
        // answers it, and every register comes back as it was but for the
        // result.
        k.preempted[cur as usize] = true;
        let nr = frame.foreign_syscall()[0];
        raise_fault(k, cur, FaultKind::ForeignSyscall, nr, frame.pc(), 0);
        return resume(guard, frame);
    }
    let a = frame.args();
    let msg = [a.a1, a.a2, a.a3, a.a4];
    let mut reboot = false;
    let result = match Syscall::from_u64(a.nr) {
        None => Err(Error::IllegalOperation.code()),
        Some(Syscall::Reboot) => {
            let r = reboot_allowed(k, cur, a.a0);
            reboot = r.is_ok();
            r
        }
        Some(Syscall::CapRevoke) => cap_revoke(k, cur, a.a0),
        Some(Syscall::CapDelete) => cap_delete(k, cur, a.a0),
        Some(Syscall::FrameMap) => frame_map(k, cur, &a),
        Some(Syscall::FrameUnmap) => frame_unmap(k, cur, a.a0),
        Some(Syscall::FrameMapInto) => frame_map_into(k, cur, &a),
        Some(Syscall::Ticks) => {
            let ticks = k.stats.ticks;
            k.ipc.set_msg_of(cur, [ticks, smp::online() as u64, 0, 0]);
            Ok(())
        }
        Some(Syscall::Random) => {
            let r = crate::entropy::draw();
            let w = |i: usize| u64::from_le_bytes(r[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
            k.ipc.set_msg_of(cur, [w(0), w(1), w(2), w(3)]);
            Ok(())
        }
        Some(Syscall::Time) => match crate::rtc::now() {
            Some(t) => {
                k.ipc.set_msg_of(cur, [t, 0, 0, 0]);
                Ok(())
            }
            None => Err(Error::IllegalOperation.code()),
        },
        Some(Syscall::IntxLine) => intx_line(k, cur, &a),
        Some(Syscall::ThreadRegisters) => thread_registers(k, cur, &a),
        Some(Syscall::ThreadSetTimeoutHandler) => thread_set_timeout_handler(k, cur, &a),
        Some(Syscall::SchedContextBind) => sched_context_bind(k, cur, &a),
        Some(Syscall::SchedControlConfigure) => sched_control_configure(k, cur, &a),
        Some(Syscall::ThreadSetAffinity) => thread_set_affinity(k, cur, &a),
        Some(Syscall::IrqMsiMessage) => irq_msi_message(k, cur, &a),
        Some(Syscall::FrameDmaAddress) => frame_dma_address(k, cur, a.a0),
        Some(Syscall::DeviceFrame) => device_frame(k, cur, &a),
        Some(Syscall::IoSpaceBind) => io_space_bind(k, cur, &a),
        Some(Syscall::IoMap) => io_map(k, cur, &a),
        Some(Syscall::IoUnmap) => io_unmap(k, cur, a.a0),
        Some(Syscall::NotificationBind) => notification_bind(k, cur, a.a0),
        Some(Syscall::TimerSignal) => timer_signal(k, cur, a.a0, a.a1),
        Some(Syscall::Sleep) => sleep(k, cur, a.a0),
        Some(Syscall::Suspend) => suspend(k, cur, a.a0, a.a1),
        Some(Syscall::IoFaults) => io_faults(k, cur, a.a0),
        Some(Syscall::UntypedInfo) => untyped_info(k, cur, a.a0),
        Some(Syscall::IoFaultNotify) => io_fault_notify(k, cur, a.a0, a.a1),
        Some(Syscall::ThreadSetVSpace) => thread_set_vspace(k, cur, &a),
        Some(Syscall::ThreadSetFaultHandler) => thread_set_fault_handler(k, cur, &a),
        Some(Syscall::SetFaultHandler) => set_fault_handler(k, cur, a.a0),
        Some(Syscall::ThreadConfigure) => thread_configure(k, cur, &a),
        Some(Syscall::ThreadResume) => thread_resume(k, cur, a.a0),
        Some(Syscall::ThreadSuspend) => thread_suspend(k, cur, a.a0),
        Some(Syscall::ThreadCopyCap) => thread_copy_cap(k, cur, &a),
        Some(Syscall::ThreadSetSpace) => thread_set_space(k, cur, &a),
        Some(Syscall::CNodeCopy) => cnode_copy(k, cur, &a),
        Some(Syscall::IrqSetNotification) => irq_set_notification(k, cur, &a),
        Some(Syscall::IrqAck) => irq_cap(k, cur, a.a0).map(arch::irq_unmask),
        Some(Syscall::IoPortIn) => io_port_in(k, cur, &a),
        Some(Syscall::IoPortOut) => io_port_out(k, cur, &a),
        Some(Syscall::CNodeDelete) => cnode_index(k, cur, &a).and_then(|s| delete_index(k, s)),
        Some(Syscall::CNodeRevoke) => cnode_index(k, cur, &a).and_then(|s| revoke_index(k, s)),
        Some(Syscall::CapMint) => cap_mint(k, cur, &a),
        Some(Syscall::Retype) => retype(k, cur, &a),
        Some(Syscall::DebugPutStr) => debug_put_str(k, cur, a.a0, a.a1),
        Some(Syscall::DebugSelftestDone) => {
            let stats = k.stats;
            let sched = k.ipc.stats;
            drop(guard);
            report_sched(sched);
            selftest_done(cur, a.a0, stats)
        }
        Some(op) => match CapTransfer::decode(a.a5) {
            Some(xfer) => ipc_op(k, cur, op, a.a0 as usize, msg, xfer),
            None => Err(Error::InvalidArgument.code()),
        },
    };
    // The result belongs to the caller, even if the operation woke a
    // thread that has since taken the CPU.
    k.ipc.set_status_of(cur, result.err().unwrap_or(0));
    complete_transfers(k);
    if reboot {
        guard = fast_reboot(guard, "the Component Manager asked for a restart");
    }
    resume(guard, frame)
}

/// The timer fired, either in user mode or while the kernel idled.
/// Every CPU has its own timer; CPU 0's keeps the system's time (ticks,
/// budget refills, the timer notification and `TimerSignal`s), the others'
/// only charge and slice their own threads.
pub fn handle_timer(frame: &mut UserFrame) -> Exit {
    crate::entropy::interrupt(0xff);
    let mut guard = lock_kernel();
    let k = &mut *guard;
    let global = arch::cpu_id() == 0;
    if k.suspend.is_some() {
        // Time stands still: this is the alarm, or a tick from before
        // this CPU parked.
        suspended_timer(k);
        if !frame.is_user_mode() {
            return Exit::Iret;
        }
        save_running(k, frame, false);
        return resume(guard, frame);
    }
    if global {
        k.stats.ticks += 1;
        collect_io_faults(k);
    }
    #[cfg(feature = "selftest")]
    if global && k.stats.ticks > SELFTEST_TIMEOUT_SECS * arch::TICK_HZ as u64 {
        // Say where every thread is stuck before giving up.
        for t in 0..MAX_THREADS as Tid {
            let tcb = k.ipc.thread(t);
            if tcb.state != superior_objects::ipc::State::Inactive || k.thread_used[t as usize] {
                kprintln!(
                    "[state] thread {t}: {:?} prio {} passive {} sc {:?} pc {:#x}",
                    tcb.state,
                    tcb.prio,
                    tcb.passive,
                    k.ipc.sched_context(t),
                    k.frames[t as usize].pc()
                );
            }
        }
        kprintln!(
            "[state] current {:?}, user mode {}",
            core::array::from_fn::<Option<Tid>, MAX_CPUS, _>(|c| k.ipc.current_on(c)),
            frame.is_user_mode()
        );
        drop(guard);
        kprintln!("[fail] self-test timed out after {SELFTEST_TIMEOUT_SECS} s");
        arch::qemu_exit(false);
    }
    if !frame.is_user_mode() {
        // The only kernel code that runs with interrupts enabled is the
        // idle halt in `resume`. Advance time (refilling budgets), wake any
        // sleeper, and return to it; the idle loop decides who runs.
        k.ipc.tick_cpu(global);
        note_timeout(k);
        if global {
            let _ = k.ipc.signal_irq(TIMER_NTFN, 1);
            fire_timers(k);
        }
        return Exit::Iret;
    }
    save_running(k, frame, false);
    if k.ipc.tick_cpu(global) {
        k.stats.preemptions += 1;
    }
    note_timeout(k);
    if global {
        let _ = k.ipc.signal_irq(TIMER_NTFN, 1);
        fire_timers(k);
    }
    resume(guard, frame)
}

/// Another CPU kicked this one: reschedule. While idle, the idle loop does.
pub fn handle_kick(frame: &mut UserFrame) -> Exit {
    if !frame.is_user_mode() {
        return Exit::Iret;
    }
    let mut guard = lock_kernel();
    save_running(&mut guard, frame, false);
    resume(guard, frame)
}

/// A CPU exception. From user mode it becomes a `Call` from the faulting
/// thread to its fault handler, or stops the thread if it has none; in
/// kernel mode it is a kernel bug.
pub fn handle_fault(frame: &mut UserFrame, kind: FaultKind, code: u64, addr: u64) -> Exit {
    if !frame.is_user_mode() {
        panic!(
            "kernel {kind:?} at pc {:#x}, address {addr:#x}, code {code:#x}",
            frame.pc()
        );
    }
    let mut guard = lock_kernel();
    let k = &mut *guard;
    // Resume (if ever) with every register exactly as it was: if another
    // CPU stopped the thread meanwhile, it faults again when it next runs.
    let Some(cur) = save_running(k, frame, false) else {
        return resume(guard, frame);
    };
    match k.fault_ep[cur as usize] {
        None if cur == ROOT_TID && rebootable() => {
            kprintln!(
                "[fault] the Component Manager: {kind:?} at pc {:#x}, address {addr:#x}",
                frame.pc()
            );
            k.stats.faults_unhandled += 1;
            guard = fast_reboot(guard, "the Component Manager failed");
        }
        _ => raise_fault(k, cur, kind, addr, frame.pc(), code),
    }
    resume(guard, frame)
}

/// A tick that emptied a budget lent to a thread with a timeout handler
/// made it call that handler: from here on it is a fault like any other,
/// resumed or stopped by the handler's reply. Its registers were saved
/// before the tick, so `Retry` resumes it exactly.
fn note_timeout(k: &mut Kernel) {
    if let Some(t) = k.ipc.take_timeout() {
        k.stats.faults_handled += 1;
        k.in_fault[t as usize] = true;
        k.syscall_fault[t as usize] = false;
    }
}

/// Whether a fault handler's reply `msg` stops the thread rather than
/// resuming it (see [`apply_fault_reply`]).
fn fault_reply_stops(msg: &[u64; 4]) -> bool {
    !(msg[0] == FaultReply::Retry as u64 || (msg[0] == FaultReply::ResumeAt as u64 && vm::is_user(msg[1])))
}

/// After a reply to `to`: if `to` waits in a fault and the reply says
/// stop, it stops now rather than when it next runs. A thread whose
/// timeout fault is answered `Stop` may be throttled on its caller's empty
/// budget, and that caller learns it has to retry only once it stops.
fn stop_if_told(k: &mut Kernel, to: Option<Tid>, msg: &[u64; 4]) {
    let Some(t) = to else { return };
    if !k.in_fault[t as usize] || k.ipc.thread(t).status != 0 || !fault_reply_stops(msg) {
        return;
    }
    // Woken by this reply, it is not running anywhere yet.
    if matches!(
        k.ipc.thread(t).state,
        superior_objects::ipc::State::Ready | superior_objects::ipc::State::Throttled { .. }
    ) {
        k.in_fault[t as usize] = false;
        kprintln!("[fault] thread {t}: handler said stop; stopped");
        k.stats.faults_unhandled += 1;
        let _ = k.ipc.destroy(t);
    }
}

/// Makes thread `cur`'s fault a `Call` to its fault handler, or stops it
/// if it has none (or the call fails).
fn raise_fault(k: &mut Kernel, cur: Tid, kind: FaultKind, addr: u64, pc: u64, code: u64) {
    let Some((ep, badge)) = k.fault_ep[cur as usize] else {
        return stop_thread(k, cur, kind, addr, pc);
    };
    k.stats.faults_handled += 1;
    k.in_fault[cur as usize] = true;
    k.syscall_fault[cur as usize] = matches!(kind, FaultKind::ForeignSyscall);
    k.ipc.set_transfer(CapTransfer::NONE);
    if k.ipc.call(ep, badge, [kind as u64, addr, pc, code]).is_err() {
        k.in_fault[cur as usize] = false;
        stop_thread(k, cur, kind, addr, pc);
    }
}

/// `ThreadRegisters`: rdi = thread (Write right), rsi = operation, rdx =
/// its value. See the `REGS_*` constants.
fn thread_registers(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    use superior_objects::abi::{
        REGS_BARRIER, REGS_FOREIGN, REGS_FORK_FROM, REGS_FP_GET, REGS_FP_SET, REGS_GET, REGS_SET, REGS_SET_TLS,
        REGS_SYSCALL, REGS_SYSCALL_MORE, REGS_TLS,
    };
    let t = thread_cap(k, cur, f.a0)? as usize;
    let r = k.frames[t].foreign_syscall();
    let msg = match f.a1 {
        REGS_SYSCALL => [r[0], r[1], r[2], r[3]],
        REGS_SYSCALL_MORE => [r[4], r[5], r[6], r[7]],
        REGS_SET_TLS => {
            // A non-canonical FS base would fault in the kernel.
            if f.a2 != 0 && !vm::is_user(f.a2) {
                return Err(Error::InvalidArgument.code());
            }
            k.tls[t] = f.a2;
            [0; 4]
        }
        REGS_TLS => [k.tls[t], 0, 0, 0],
        REGS_GET => {
            let fr = &k.frames[t];
            let at = |n: u64| f.a2.checked_add(n).and_then(|i| fr.linux_reg(i)).unwrap_or(0);
            [at(0), at(1), at(2), at(3)]
        }
        REGS_SET => {
            // Only a thread that is not running: its frame is what it
            // resumes with.
            if !k.in_fault[t] && !thread_inactive(k, t as Tid) {
                return Err(Error::IllegalOperation.code());
            }
            let mut frame = k.frames[t];
            for (n, v) in [(0, f.a3), (1, f.a4)] {
                if let Some(i) = f.a2.checked_add(n) {
                    if !frame.set_linux_reg(i, v, vm::is_user) {
                        return Err(Error::InvalidArgument.code());
                    }
                }
            }
            k.frames[t] = frame;
            k.preempted[t] = true;
            [0; 4]
        }
        // Its state as saved when it entered the kernel, which is what it
        // resumes with.
        REGS_FP_GET => {
            let fp = &k.fp[t];
            let at = |n: u64| f.a2.checked_add(n).and_then(|i| fp.word(i)).unwrap_or(0);
            [at(0), at(1), at(2), at(3)]
        }
        REGS_FP_SET => {
            if !k.in_fault[t] && !thread_inactive(k, t as Tid) {
                return Err(Error::IllegalOperation.code());
            }
            for (n, v) in [(0, f.a3), (1, f.a4)] {
                if let Some(i) = f.a2.checked_add(n) {
                    k.fp[t].set_word(i, v);
                }
            }
            [0; 4]
        }
        // Every other CPU with the address space loaded answers a
        // shootdown (from an interrupt, after the user code it ran: a
        // barrier), and this one is in the kernel.
        REGS_BARRIER => {
            if let Some(space) = space_of(k, t as Tid) {
                smp::shootdown(space.root_pa(), false);
            }
            [0; 4]
        }
        REGS_FORK_FROM => {
            let from = thread_cap(k, cur, f.a2)? as usize;
            if !thread_inactive(k, t as Tid) || k.configured[t].is_none() || from == t {
                return Err(Error::IllegalOperation.code());
            }
            disown(k, t as Tid);
            let mut frame = k.frames[from];
            frame.resume_at(frame.pc(), 0);
            k.frames[t] = frame;
            k.tls[t] = k.tls[from];
            k.fp[t] = k.fp[from];
            // Every register exactly as given, not a fresh thread's.
            k.fresh[t] = false;
            k.preempted[t] = true;
            [0; 4]
        }
        REGS_FOREIGN if f.a2 <= 1 => {
            k.foreign[t] = f.a2 == 1;
            k.fp[t] = arch::FpState::INITIAL;
            [0; 4]
        }
        _ => return Err(Error::InvalidArgument.code()),
    };
    k.ipc.set_msg_of(cur, msg);
    Ok(())
}

/// Rebuilds the root task for a fast reboot (set by `main` once it has
/// started the Component Manager): a `fn() -> Result<(), &'static str>`.
static ROOT_BUILDER: AtomicUsize = AtomicUsize::new(0);
static REBOOTS: AtomicU64 = AtomicU64::new(0);

/// Makes fast reboots possible: `build` starts the root task again.
pub fn set_root_builder(build: fn() -> Result<(), &'static str>) {
    ROOT_BUILDER.store(build as usize, Ordering::SeqCst);
}

/// How many fast reboots there have been.
pub fn reboots() -> u64 {
    REBOOTS.load(Ordering::SeqCst)
}

fn rebootable() -> bool {
    ROOT_BUILDER.load(Ordering::SeqCst) != 0
}

/// The fast reboot (spec section 4): the Component Manager or the Memory
/// Server failed, and neither can be restarted in place. Everything made
/// from the root task's memory is destroyed (every component, endpoint,
/// address space and I/O domain), then the root task itself, and it is
/// started again from the boot bundle. Hardware state the drivers left
/// is theirs to reset when they start again, as after any restart; the
/// IOMMU blocks a device still aiming at memory it no longer has. The state
/// store keeps its contents.
fn fast_reboot(mut guard: KernelGuard, why: &str) -> KernelGuard {
    let k = &mut *guard;
    let now = k.stats.ticks;
    let n = REBOOTS.load(Ordering::SeqCst);
    let oldest = k.reboot_ticks[n as usize % MAX_REBOOTS];
    if n >= MAX_REBOOTS as u64 && now.saturating_sub(oldest) < REBOOT_WINDOW {
        panic!("{why}: more than {MAX_REBOOTS} fast reboots within 60 s; giving up");
    }
    k.reboot_ticks[n as usize % MAX_REBOOTS] = now;
    kprintln!("[reboot] {why}: fast reboot {}", n + 1);
    tear_down_root(k);
    REBOOTS.store(n + 1, Ordering::SeqCst);
    drop(guard);
    let addr = ROOT_BUILDER.load(Ordering::SeqCst);
    // SAFETY: only `set_root_builder` stores here, a function of this type.
    let build: fn() -> Result<(), &'static str> = unsafe { core::mem::transmute(addr) };
    if let Err(e) = build() {
        panic!("fast reboot: {e}");
    }
    let guard = lock_kernel();
    kprintln!(
        "[reboot] Component Manager started again, {} ms after the failure",
        (guard.stats.ticks - now) * 1000 / superior_objects::abi::TICK_HZ
    );
    guard
}

/// Destroys the root task and everything made from its memory.
fn tear_down_root(k: &mut Kernel) {
    use superior_objects::abi::root;
    let t = ROOT_TID;
    let memory = [root::UNTYPED].into_iter().chain(root::SPARE..root::SPARE + root::SPARE_COUNT);
    for slot in memory {
        if let Some(s) = cap_slot(k, t, slot as usize) {
            if k.caps.get(s).is_some() {
                let _ = revoke_index(k, s);
            }
        }
    }
    let space = k.spaces[t as usize];
    let (base, size) = k.cspace[t as usize];
    destroy_thread(k, t);
    // Its CSpace holds a capability to itself, so nothing else frees it.
    if size > 0 {
        if let Some(c) = (base as usize).checked_sub(CNODE_POOL) {
            destroy_cnode(k, c / CNODE_CHUNK);
        }
    }
    if let Some(id) = space {
        destroy_vspace(k, id);
    }
    reap(k);
}

/// `Reboot`: rdi = the root task's untyped capability.
fn reboot_allowed(k: &Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let root = cap_slot(k, ROOT_TID, superior_objects::abi::root::UNTYPED as usize);
    let own = own_slot(k, cur, slot);
    let untyped = own.and_then(|s| k.caps.get(s)).is_some_and(|c| c.object.untyped().is_some());
    if cur != ROOT_TID || !rebootable() || own.is_none() || own != root || !untyped {
        return Err(Error::InvalidCapability.code());
    }
    Ok(())
}

/// A device interrupt (already masked and acknowledged at the PIC): signal
/// the notification bound to its line. Like the timer, it can arrive in
/// user mode or while the kernel idles.
pub fn handle_irq(frame: &mut UserFrame, line: u8) -> Exit {
    crate::entropy::interrupt(line);
    let mut guard = lock_kernel();
    let k = &mut *guard;
    let bound = k.irq_ntfn.get(line as usize).copied().flatten();
    if !frame.is_user_mode() {
        if let Some((ntfn, badge)) = bound {
            let _ = k.ipc.signal_irq(ntfn, badge);
        }
        return Exit::Iret;
    }
    save_running(k, frame, false);
    if let Some((ntfn, badge)) = bound {
        let _ = k.ipc.signal_irq(ntfn, badge);
    }
    resume(guard, frame)
}

/// The interrupt line an IRQ capability in the caller's slot names.
fn irq_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<u8, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    match k.caps.get(s).map(|c| c.object) {
        Some(Object::Irq { line }) => Ok(line),
        _ => Err(Error::InvalidCapability.code()),
    }
}

/// `IrqMsiMessage`: rdi = IRQ capability for an MSI vector, rsi = the I/O
/// address space (Write) of the function that may raise it, or
/// `u64::MAX` for none.
fn irq_msi_message(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let line = irq_cap(k, cur, f.a0)?;
    let source = if f.a1 == u64::MAX {
        None
    } else {
        let id = io_space_cap(k, cur, f.a1)?;
        let d = k.io_spaces[id].ok_or(Error::InvalidCapability.code())?;
        Some(d.sid.ok_or(Error::InvalidArgument.code())?)
    };
    let (address, data) =
        arch::msi_message(line, source).ok_or(Error::InvalidArgument.code())?;
    k.ipc.set_msg_of(cur, [address, data, 0, 0]);
    Ok(())
}

/// `FrameDmaAddress`: rdi = frame capability (Map right). With no IOMMU
/// yet, a device reaches a frame at its physical address.
fn frame_dma_address(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Frame { paddr, .. } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::MAP) {
        return Err(Error::InsufficientRights.code());
    }
    k.ipc.set_msg_of(cur, [paddr, 0, 0, 0]);
    Ok(())
}

/// `DeviceFrame`: rdi = device memory, rsi = page offset, rdx = empty
/// slot, r8 = the frame's size in bits (0 for a page).
fn device_frame(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let src = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(src).ok_or(Error::InvalidCapability.code())?;
    let Object::DeviceUntyped { base, size_bits } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    let offset = f.a1;
    let bits = if f.a3 == 0 { 12 } else { f.a3 };
    if !(12..=DEVICE_FRAME_MAX_BITS).contains(&bits)
        || !offset.is_multiple_of(4096)
        || offset.checked_add(1 << bits).is_none_or(|end| end > 1 << size_bits)
    {
        return Err(Error::InvalidArgument.code());
    }
    let dst = own_slot(k, cur, f.a2).ok_or(Error::InvalidArgument.code())?;
    if k.caps.get(dst).is_some() {
        return Err(Error::SlotOccupied.code());
    }
    let frame = Capability::new(
        Object::Frame {
            paddr: base + offset,
            size_bits: bits as u8,
        },
        Rights::READ | Rights::WRITE | Rights::GRANT | Rights::MAP,
    );
    k.caps.insert_child(src, dst, frame).map_err(cap_error)
}

/// `IrqSetNotification`: rdi = IRQ capability, rsi = notification (Write).
fn irq_set_notification(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let line = irq_cap(k, cur, f.a0)?;
    if !arch::irq_routable(line) || line as usize >= MAX_IRQS {
        return Err(Error::InvalidArgument.code());
    }
    let s = own_slot(k, cur, f.a1).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Notification { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    // An unbadged signal would OR in nothing: use bit 0.
    let badge = if cap.badge == 0 { 1 } else { cap.badge };
    k.irq_ntfn[line as usize] = Some((id as u16, badge));
    arch::irq_unmask(line);
    Ok(())
}

/// `TimerSignal`: rdi = notification (Write), rsi = ticks from now (0
/// cancels).
fn timer_signal(k: &mut Kernel, cur: Tid, slot: u64, ticks: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Notification { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    let id = id as u16;
    // One deadline per notification: a new one replaces the old.
    for t in k.timers.iter_mut() {
        if matches!(t, Some((_, n, _)) if *n == id) {
            *t = None;
        }
    }
    if ticks == 0 {
        return Ok(());
    }
    let free = k
        .timers
        .iter()
        .position(Option::is_none)
        .ok_or(Error::ObjectTableFull.code())?;
    let bits = if cap.badge == 0 { 1 } else { cap.badge };
    k.timers[free] = Some((k.stats.ticks.saturating_add(ticks), id, bits));
    Ok(())
}

/// Signals every notification whose `TimerSignal` deadline has come.
/// Thread `t`'s own notification, on which it sleeps.
fn sleep_ntfn(t: Tid) -> u16 {
    (MAX_NOTIFICATIONS + t as usize) as u16
}

/// `Sleep`: rdi = ticks. Waits on the caller's own notification until the
/// kernel signals it then. Bits left from an earlier sleep cut short are
/// forgotten first, so they cannot end this one early.
fn sleep(k: &mut Kernel, cur: Tid, ticks: u64) -> Result<(), u64> {
    if ticks == 0 {
        return Ok(());
    }
    let n = sleep_ntfn(cur);
    let _ = k.ipc.clear_notification(n);
    k.sleep_until[cur as usize] = Some(k.stats.ticks.saturating_add(ticks));
    k.ipc.wait(n).map_err(|e| e.status())
}

/// A suspend under way: the thread that asked, ticks left to wait, and
/// whether to RAM (ACPI S3) rather than to idle.
#[derive(Clone, Copy)]
struct Suspended {
    caller: Tid,
    left: u64,
    ram: bool,
}

/// `Suspend`: rdi = the root task's untyped capability, rsi = ticks.
/// The caller waits on its own notification, as in `Sleep`, and every CPU
/// parks the next time it would pick a thread ([`park`]); the CPUs in user
/// mode are kicked into the kernel to do so. Where the machine can, it
/// then suspends to RAM ([`sleep_to_ram`]); else it stays suspended to
/// idle, every CPU halted, until an alarm.
fn suspend(k: &mut Kernel, cur: Tid, slot: u64, ticks: u64) -> Result<(), u64> {
    let root = cap_slot(k, ROOT_TID, superior_objects::abi::root::UNTYPED as usize);
    let own = own_slot(k, cur, slot);
    let untyped = own.and_then(|s| k.caps.get(s)).is_some_and(|c| c.object.untyped().is_some());
    if cur != ROOT_TID || own.is_none() || own != root || !untyped {
        return Err(Error::InvalidCapability.code());
    }
    if ticks == 0 || k.suspend.is_some() {
        return Err(Error::InvalidArgument.code());
    }
    let n = sleep_ntfn(cur);
    let _ = k.ipc.clear_notification(n);
    k.ipc.wait(n).map_err(|e| e.status())?;
    let ram = arch::ram_sleep_available();
    k.suspend = Some(Suspended { caller: cur, left: ticks, ram });
    let to = if ram { "RAM (ACPI S3)" } else { "idle" };
    kprintln!("[power] suspending to {to} for {ticks} ticks at tick {}", k.stats.ticks);
    let me = arch::cpu_id();
    for x in 0..smp::online() {
        if x != me {
            smp::kick(x);
        }
    }
    Ok(())
}

/// This CPU stops its tick and halts until the suspend ends; CPU 0 sets
/// the alarm that ends it.
fn park(k: &mut Kernel) {
    let me = arch::cpu_id();
    if core::mem::replace(&mut k.parked[me], true) {
        return;
    }
    arch::tick_stop();
    if me == 0 {
        if let Some(s) = k.suspend.as_mut() {
            // To RAM: look each tick for the other CPUs to have parked.
            let wait = if s.ram { 1 } else { s.left };
            let waited = arch::alarm(wait);
            if !s.ram {
                s.left -= waited;
            }
        }
    }
}

/// Whether CPU 0 may suspend to RAM now: every other CPU parked, and none
/// waiting for the kernel lock (a CPU started again after S3 would never
/// take the turn it is waiting for).
fn ram_ready(k: &Kernel) -> bool {
    let others_parked = (1..smp::online()).all(|x| k.parked[x]);
    let waiting = TICKET_NEXT.load(Ordering::Acquire).wrapping_sub(TICKET_SERVING.load(Ordering::Acquire));
    arch::cpu_id() == 0 && k.suspend.is_some_and(|s| s.ram) && others_parked && waiting == 1
}

/// CPU 0, with every other CPU parked: suspends the machine to RAM for
/// the suspend's ticks (in whole seconds, the RTC alarm's), restarts the
/// other CPUs, and ends the suspend. If the machine does not sleep, the
/// suspend carries on to idle.
fn sleep_to_ram(k: &mut Kernel) {
    let Some(s) = k.suspend else { return };
    let hz = arch::TICK_HZ as u64;
    let seconds = s.left.div_ceil(hz).max(2);
    let before = smp::online();
    match arch::ram_sleep(seconds) {
        Ok(wake) => {
            for x in 1..before {
                k.parked[x] = false;
            }
            let n = arch::ram_sleep_restart_cpus(before);
            kprintln!("[power] woke from S3: {wake}; {n} CPUs running again");
            end_suspend(k);
        }
        Err(e) => {
            kprintln!("[power] S3 failed ({e}): suspending to idle instead");
            if let Some(s) = k.suspend.as_mut() {
                s.ram = false;
                s.left -= arch::alarm(s.left);
            }
        }
    }
}

/// The suspend is over: this CPU starts its tick again.
fn unpark(k: &mut Kernel) {
    let me = arch::cpu_id();
    if core::mem::take(&mut k.parked[me]) {
        arch::tick_start();
    }
}

/// The timer interrupted while suspended. On parked CPU 0 the alarm may
/// have come: set the next, or end the suspend (waking the caller and
/// every CPU). A tick from before a CPU parked changes nothing, but on
/// some machines its handler started the tick again; stop it.
fn suspended_timer(k: &mut Kernel) {
    let me = arch::cpu_id();
    if !k.parked[me] {
        return;
    }
    if me != 0 {
        arch::tick_stop();
        return;
    }
    if !arch::alarm_fired() {
        arch::alarm_keep();
        return;
    }
    let Some(s) = k.suspend.as_mut() else { return };
    if s.ram {
        // Still waiting for the other CPUs to park ([`resume`] sleeps).
        arch::alarm(1);
        return;
    }
    if s.left > 0 {
        s.left -= arch::alarm(s.left);
        return;
    }
    end_suspend(k);
}

/// The suspend is over: wakes the caller and every CPU.
fn end_suspend(k: &mut Kernel) {
    let Some(s) = k.suspend else { return };
    let caller = s.caller;
    k.suspend = None;
    unpark(k);
    kprintln!("[power] resumed at tick {}", k.stats.ticks);
    let _ = k.ipc.signal_irq(sleep_ntfn(caller), 1);
    for x in 1..smp::online() {
        smp::kick(x);
    }
}

fn fire_timers(k: &mut Kernel) {
    let now = k.stats.ticks;
    for t in 0..MAX_THREADS {
        if k.sleep_until[t].is_some_and(|w| w <= now) {
            k.sleep_until[t] = None;
            let _ = k.ipc.signal_irq(sleep_ntfn(t as Tid), 1);
        }
    }
    for i in 0..MAX_TIMERS {
        if let Some((deadline, n, bits)) = k.timers[i] {
            if deadline <= now {
                k.timers[i] = None;
                let _ = k.ipc.signal_irq(n, bits);
            }
        }
    }
}

/// Credits each DMA request the IOMMU blocked to the I/O address space of
/// the function that made it, and signals the notification each space
/// that got one has bound (`IoFaultNotify`).
fn collect_io_faults(k: &mut Kernel) {
    let (spaces, stats) = (&mut k.io_spaces, &mut k.stats);
    let mut hit = [false; MAX_IO_SPACES];
    let lost = iommu::take_faults(|sid, fault| {
        stats.io_faults += 1;
        let Some(i) = spaces.iter().position(|d| d.is_some_and(|d| d.sid == Some(sid))) else {
            stats.io_faults_unowned += 1;
            return;
        };
        hit[i] = true;
        let Some(d) = spaces[i].as_mut() else {
            return;
        };
        let (page, write) = match fault {
            IoFault::Interrupt => {
                d.irq_faults += 1;
                return;
            }
            IoFault::Read(page) => (page, false),
            IoFault::Write(page) => (page, true),
        };
        if d.faults == 0 {
            d.first_fault = (page, write);
        }
        d.faults += 1;
    });
    if lost {
        stats.io_faults_unowned += 1;
    }
    for (i, d) in k.io_spaces.iter().enumerate() {
        if let (true, Some((n, badge))) = (hit[i], d.as_ref().and_then(|d| d.notify)) {
            let _ = k.ipc.signal_irq(n, badge);
        }
    }
}

/// The IOMMU's fault interrupt: its faults are collected (and their
/// spaces' holders signalled) now rather than at the next tick.
pub fn handle_io_fault_irq(frame: &mut UserFrame) -> Exit {
    let mut guard = lock_kernel();
    let k = &mut *guard;
    k.stats.io_fault_irqs += 1;
    if k.stats.io_fault_irqs <= 3 {
        kprintln!("[iommu] fault interrupt {}", k.stats.io_fault_irqs);
    }
    collect_io_faults(k);
    if !frame.is_user_mode() {
        return Exit::Iret;
    }
    save_running(k, frame, false);
    resume(guard, frame)
}

/// `IoFaultNotify`: rdi = I/O address space (Read), rsi = notification
/// (Write), or `u64::MAX` to unbind.
fn io_fault_notify(k: &mut Kernel, cur: Tid, space: u64, ntfn: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, space).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::IoSpace { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::READ) {
        return Err(Error::InsufficientRights.code());
    }
    let notify = if ntfn == u64::MAX {
        None
    } else {
        let n = own_slot(k, cur, ntfn).ok_or(Error::InvalidCapability.code())?;
        let ncap = *k.caps.get(n).ok_or(Error::InvalidCapability.code())?;
        let Object::Notification { id } = ncap.object else {
            return Err(Error::InvalidCapability.code());
        };
        if !ncap.rights.contains(Rights::WRITE) {
            return Err(Error::InsufficientRights.code());
        }
        Some((id as u16, if ncap.badge == 0 { 1 } else { ncap.badge }))
    };
    let d = k.io_spaces[id as usize]
        .as_mut()
        .ok_or(Error::InvalidCapability.code())?;
    d.notify = notify;
    Ok(())
}

/// `IoFaults`: rdi = I/O address space (Read). Returns the requests the
/// IOMMU blocked since the last call, and the first one's page and kind.
/// `UntypedInfo`: rdi = an untyped capability. Returns its size in bits and
/// how much is uncarved; for the boot framebuffer's device memory, also
/// its geometry (`abi::framebuffer::Geometry::pack`), else zeros.
fn untyped_info(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let screen = match cap.object {
        Object::DeviceUntyped { base, .. } => arch::framebuffer_geometry(base),
        _ => None,
    }
    .unwrap_or([0, 0]);
    let (_, bits) = cap.object.untyped().ok_or(Error::InvalidCapability.code())?;
    // What carving would find free: all of it once nothing made from it
    // is left, as `carve` resets.
    let free = match k.caps.has_children(s) {
        false => 1u64 << bits,
        true => k.caps.untyped_free(s).unwrap_or(0),
    };
    k.ipc.set_msg_of(cur, [bits as u64, free, screen[0], screen[1]]);
    Ok(())
}

fn io_faults(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::IoSpace { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::READ) {
        return Err(Error::InsufficientRights.code());
    }
    collect_io_faults(k);
    let d = k.io_spaces[id as usize]
        .as_mut()
        .ok_or(Error::InvalidCapability.code())?;
    let reply = [
        d.faults,
        d.first_fault.0,
        d.first_fault.1 as u64,
        d.irq_faults,
    ];
    d.faults = 0;
    d.first_fault = (0, false);
    d.irq_faults = 0;
    k.ipc.set_msg_of(cur, reply);
    Ok(())
}

/// `NotificationBind`: rdi = notification (Read), bound to the caller.
fn notification_bind(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Notification { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::READ) {
        return Err(Error::InsufficientRights.code());
    }
    k.ipc
        .bind_notification(cur, id as u16)
        .map_err(|e| e.status())
}

/// The port `rsi`, `rdx` bytes wide, checked against the I/O-port
/// capability in `rdi` and the right `need`.
fn io_port(k: &Kernel, cur: Tid, f: &Args, need: Rights) -> Result<(u16, u64), u64> {
    let s = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::IoPort { base, count } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(need) {
        return Err(Error::InsufficientRights.code());
    }
    let width = f.a2;
    if !matches!(width, 1 | 2 | 4) {
        return Err(Error::InvalidArgument.code());
    }
    let (lo, hi) = (base as u64, base as u64 + count as u64);
    if f.a1 < lo || f.a1 + width > hi {
        return Err(Error::InvalidArgument.code());
    }
    Ok((f.a1 as u16, width))
}

/// `IoPortIn`: rdi = I/O-port capability, rsi = port, rdx = width.
fn io_port_in(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let (port, width) = io_port(k, cur, f, Rights::READ)?;
    let v = arch::io_in(port, width);
    k.ipc.set_msg_of(cur, [v, 0, 0, 0]);
    Ok(())
}

/// `IoPortOut`: rdi = I/O-port capability, rsi = port, rdx = width, r8 =
/// value.
fn io_port_out(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let (port, width) = io_port(k, cur, f, Rights::WRITE)?;
    arch::io_out(port, width, f.a3);
    Ok(())
}

fn stop_thread(k: &mut Kernel, t: Tid, kind: FaultKind, addr: u64, pc: u64) {
    kprintln!("[fault] thread {t}: unhandled {kind:?} at pc {pc:#x}, address {addr:#x}; stopped");
    k.stats.faults_unhandled += 1;
    k.ipc.crash_current();
}

/// Applies a fault handler's reply to thread `t`. Returns false if the
/// thread must stop instead of resuming.
fn apply_fault_reply(k: &mut Kernel, t: Tid) -> bool {
    let tcb = k.ipc.thread(t);
    if tcb.status != 0 {
        return false; // the handler went away without replying
    }
    let msg = tcb.msg;
    match msg[0] {
        x if x == FaultReply::Retry as u64 => true,
        x if x == FaultReply::ResumeAt as u64 => {
            // Returning to an address outside the user window could fault
            // in the kernel (a non-canonical rip on x86-64).
            if !vm::is_user(msg[1]) {
                return false;
            }
            k.frames[t as usize].resume_at(msg[1], msg[2]);
            true
        }
        _ => false,
    }
}

/// `SetFaultHandler`: rdi = slot of an endpoint capability with Write.
fn set_fault_handler(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    k.fault_ep[cur as usize] = Some(fault_endpoint(k, cur, slot)?);
    Ok(())
}

/// `ThreadSetFaultHandler`: rdi = thread, rsi = endpoint with Write.
fn thread_set_fault_handler(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    k.fault_ep[t as usize] = Some(fault_endpoint(k, cur, f.a1)?);
    Ok(())
}

/// The scheduling context in the caller's slot `slot`, which must hold a
/// SchedContext capability with Write.
fn sched_context_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<Tid, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::SchedContext { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok(id as Tid)
}

/// `SchedContextBind`: rdi = thread, rsi = scheduling context, or
/// `u64::MAX` for none.
fn sched_context_bind(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    let sc = if f.a1 == u64::MAX {
        None
    } else {
        Some(sched_context_cap(k, cur, f.a1)?)
    };
    k.ipc.bind_sc(t, sc).map_err(|e| e.status())
}

/// `ThreadSetAffinity`: rdi = thread, rsi = CPU, or `u64::MAX` for any.
fn thread_set_affinity(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    let cpu = match f.a1 {
        u64::MAX => None,
        c if c < crate::smp::online() as u64 => Some(c as usize),
        _ => return Err(Error::InvalidArgument.code()),
    };
    k.ipc.set_affinity(t, cpu).map_err(|e| e.status())
}

/// `SchedControlConfigure`: rdi = sched control, rsi = scheduling context,
/// rdx = budget, r8 = period (0: unlimited); a budget of 0 empties it.
fn sched_control_configure(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let s = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    if !matches!(k.caps.get(s).map(|c| c.object), Some(Object::SchedControl)) {
        return Err(Error::InvalidCapability.code());
    }
    let sc = sched_context_cap(k, cur, f.a1)?;
    let r = match (f.a2, f.a3) {
        (_, 0) => k.ipc.unlimit_sc(sc),
        (0, _) => k.ipc.empty_sc(sc),
        (b, p) => {
            let (Ok(b), Ok(p)) = (u32::try_from(b), u32::try_from(p)) else {
                return Err(Error::InvalidArgument.code());
            };
            k.ipc.configure_sc(sc, b, p)
        }
    };
    r.map_err(|_| Error::InvalidArgument.code())
}

/// `ThreadSetTimeoutHandler`: rdi = thread, rsi = endpoint with Write, or
/// `u64::MAX` for none.
fn thread_set_timeout_handler(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    let handler = if f.a1 == u64::MAX {
        None
    } else {
        Some(fault_endpoint(k, cur, f.a1)?)
    };
    k.ipc
        .set_timeout_handler(t, handler)
        .map_err(|e| e.status())
}

/// The endpoint and badge of the caller's slot `slot`, which must hold an
/// endpoint capability with Write.
fn fault_endpoint(k: &Kernel, cur: Tid, slot: u64) -> Result<(u16, u64), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Endpoint { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok((id as u16, cap.badge))
}

/// The address space thread `t` runs in.
fn space_of(k: &Kernel, t: Tid) -> Option<AddressSpace> {
    let id = k.spaces[t as usize]?;
    k.vspaces[id as usize].map(|v| v.root)
}

/// Kicks every other CPU that now has something better to run.
fn kick_others(k: &Kernel) {
    let me = arch::cpu_id();
    for x in 0..smp::online() {
        if x != me && k.ipc.needs_kick(x) {
            smp::kick(x);
        }
    }
}

/// Loads the registers of the thread the IPC engine chose into `frame`,
/// switches address space if needed, and says how to return to it. If no
/// thread can run, halts until an interrupt makes one runnable.
fn resume(mut guard: KernelGuard, frame: &mut UserFrame) -> Exit {
    let next = loop {
        if guard.suspend.is_some() {
            // No thread runs until the alarm ends the suspend.
            park(&mut guard);
            if ram_ready(&guard) {
                sleep_to_ram(&mut guard);
                continue;
            }
            drop(guard);
            arch::idle_wait();
            guard = lock_kernel();
            continue;
        }
        unpark(&mut guard);
        guard.ipc.reschedule();
        kick_others(&guard);
        if let Some(next) = guard.ipc.current() {
            let k = &mut *guard;
            if core::mem::take(&mut k.in_fault[next as usize]) && !apply_fault_reply(k, next) {
                kprintln!("[fault] thread {next}: handler said stop (or failed); stopped");
                k.stats.faults_unhandled += 1;
                k.ipc.crash_current();
                continue;
            }
            break next;
        }
        guard.stats.idle_halts += 1;
        drop(guard);
        // Waits for an interrupt with no window in which one could slip
        // past and leave the CPU halted with work to do. The interrupt
        // handler runs on this stack and returns here.
        arch::idle_wait();
        guard = lock_kernel();
    };
    let k = &mut *guard;
    let n = next as usize;
    let mut out = k.frames[n];
    let exit = if core::mem::take(&mut k.fresh[n]) {
        // First run: start registers, no results to deliver.
        Exit::Sysret
    } else if k.preempted[n] {
        Exit::Iret
    } else {
        let t = k.ipc.thread(next);
        out.set_results(
            t.status,
            t.badge,
            t.msg,
            t.cap_received.map_or(0, |s| s as u64 + 1),
        );
        Exit::Sysret
    };
    let Some(space) = space_of(k, next) else {
        panic!(
            "thread {next} (on CPU {}) has no address space: {:?} prio {} used {} configured {:?} sc {:?} pc {:#x}, running {:?}, current {:?}",
            arch::cpu_id(),
            k.ipc.thread(next).state,
            k.ipc.thread(next).prio,
            k.thread_used[next as usize],
            k.configured[next as usize],
            k.ipc.sched_context(next),
            k.frames[next as usize].pc(),
            k.running,
            core::array::from_fn::<Option<Tid>, MAX_CPUS, _>(|c| k.ipc.current_on(c)),
        )
    };
    space.activate();
    smp::note_loaded(space.root_pa());
    k.running[arch::cpu_id()] = Some(next);
    k.stats.resumes[arch::cpu_id()] += 1;
    arch::set_user_tls(k.tls[n]);
    let cpu = arch::cpu_id();
    if k.foreign[n] {
        arch::fp_enable(true);
        arch::fp_restore(&k.fp[n]);
        k.fp_owner[cpu] = Some(next);
    } else {
        arch::fp_enable(false);
        k.fp_owner[cpu] = None;
    }
    *frame = out;
    exit
}

/// Copies each capability the last IPC operation transferred. A transfer
/// that cannot be made (the granted slot was emptied, or the accept slot
/// filled, while the message waited) is dropped; the message still arrives.
fn complete_transfers(k: &mut Kernel) {
    for t in k.ipc.take_transfers().into_iter().flatten() {
        let src = cap_slot(k, t.from, t.grant as usize);
        let dst = cap_slot(k, t.to, t.accept as usize);
        let landed = match (src, dst) {
            (Some(src), Some(dst)) => k.caps.derive(src, dst, Rights::ALL, None).is_ok(),
            _ => false,
        };
        k.ipc.set_cap_received(t.to, landed.then_some(t.accept));
    }
}

/// `CapRevoke`: removes everything derived from the caller's slot,
/// unmapping any frames among them first.
fn cap_revoke(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    revoke_index(k, s)
}

/// Revokes table slot `s`: see [`cap_revoke`].
fn revoke_index(k: &mut Kernel, s: usize) -> Result<(), u64> {
    let mut objects = false;
    let Kernel {
        caps,
        mapped,
        io_mapped,
        vspaces,
        io_spaces,
        ..
    } = k;
    caps.revoke_each(s, |i, c| {
        objects |= reapable(&c.object);
        unmap_parts(mapped, io_mapped, vspaces, io_spaces, i, frame_pages(&c.object));
    })
    .map_err(cap_error)?;
    // Revoking only frames and memory (the Memory Server's pages) leaves
    // no object behind to free: no pass over the table.
    if objects {
        reap(k);
    }
    Ok(())
}

/// Whether the object a capability names is freed with its last
/// capability (by [`reap`]).
fn reapable(o: &Object) -> bool {
    matches!(
        o,
        Object::Thread { .. }
            | Object::CNode { .. }
            | Object::AddressSpace { .. }
            | Object::IoSpace { .. }
            | Object::Endpoint { .. }
            | Object::Notification { .. }
            | Object::SchedContext { .. }
    )
}

/// `CapDelete`: empties the caller's slot, unmapping a frame first.
fn cap_delete(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    delete_index(k, s)
}

/// Deletes table slot `s`: see [`cap_delete`].
fn delete_index(k: &mut Kernel, s: usize) -> Result<(), u64> {
    let c = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    unmap_slot(k, s);
    k.caps.delete(s).map_err(cap_error)?;
    if reapable(&c.object) {
        reap(k);
    }
    Ok(())
}

/// Unmaps the frame whose capability is in table slot `s`, if mapped,
/// from its address space and from its I/O address space.
fn unmap_slot(k: &mut Kernel, s: usize) {
    let pages = k.caps.get(s).map_or(1, |c| frame_pages(&c.object));
    unmap_parts(&mut k.mapped, &mut k.io_mapped, &k.vspaces, &k.io_spaces, s, pages);
}

/// The pages a mapping of the object covers: a frame's, or one.
fn frame_pages(o: &Object) -> u64 {
    match o {
        Object::Frame { size_bits, .. } => 1 << (size_bits.max(&12) - 12),
        _ => 1,
    }
}

/// [`unmap_slot`], on the parts of the kernel it needs (so it can run
/// while the capability table is borrowed).
fn unmap_parts(
    mapped: &mut [Mapping],
    io_mapped: &mut [Mapping],
    vspaces: &[Option<VSpace>],
    io_spaces: &[Option<IoDomain>],
    s: usize,
    pages: u64,
) {
    if let Some((id, va)) = mapped[s].take() {
        if let Some(v) = vspaces[id as usize] {
            for p in 0..pages {
                v.root.unmap(va + p * 4096);
            }
            smp::shootdown(v.root.root_pa(), false);
        }
    }
    if let Some((id, iova)) = io_mapped[s].take() {
        if let Some(d) = io_spaces[id as usize] {
            crate::iommu::unmap(d.root(), iova);
            iommu::flush();
        }
    }
}

/// `IntxLine`: rdi = root-bus device, rsi = pin (1 to 4).
fn intx_line(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let (Ok(device), Ok(pin)) = (u8::try_from(f.a0), u8::try_from(f.a1)) else {
        return Err(Error::InvalidArgument.code());
    };
    if device >= 32 || !(1..=4).contains(&pin) {
        return Err(Error::InvalidArgument.code());
    }
    let w = arch::intx_line(device, pin)
        .filter(|&w| w < arch::intx_lines().len())
        .ok_or(Error::IllegalOperation.code())?;
    k.ipc.set_msg_of(cur, [w as u64, 0, 0, 0]);
    Ok(())
}

/// The I/O address space a capability in the caller's slot names, with
/// Write.
fn io_space_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<usize, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::IoSpace { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok(id as usize)
}

/// `IoSpaceBind`: rdi = I/O address space, rsi = IOMMU control, rdx =
/// PCI requester ID.
fn io_space_bind(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let id = io_space_cap(k, cur, f.a0)?;
    let ctl = own_slot(k, cur, f.a1).ok_or(Error::InvalidCapability.code())?;
    if !matches!(
        k.caps.get(ctl).map(|c| c.object),
        Some(Object::IommuControl)
    ) {
        return Err(Error::InvalidCapability.code());
    }
    let sid = u16::try_from(f.a2)
        .ok()
        .filter(|&s| iommu::valid_sid(s))
        .ok_or(Error::InvalidArgument.code())?;
    let mut d = k.io_spaces[id].ok_or(Error::InvalidCapability.code())?;
    // One function per space, one space per function.
    if d.sid.is_some() || k.io_spaces.iter().flatten().any(|o| o.sid == Some(sid)) {
        return Err(Error::IllegalOperation.code());
    }
    // Memory the firmware says the function keeps using whatever it is
    // told (a USB controller's legacy keyboard emulation, a GPU's stolen
    // memory): mapped where it is before its DMA is translated, or it
    // would fault from the start. It is not RAM, so no frame the driver
    // maps can land on it.
    let (root, mut pages) = (d.root(), 0u64);
    for pa in iommu::reserved_pages(sid) {
        match crate::iommu::map(root, pa, pa, true, &mut d.pool) {
            Ok(()) => pages += 1,
            // Two regions overlap.
            Err(crate::iommu::IoMapError::InUse) => {}
            Err(e) => {
                for pa in iommu::reserved_pages(sid) {
                    crate::iommu::unmap(root, pa);
                }
                // The tables made so far stay in the space's tree, so its
                // pool must not hand them out again.
                k.io_spaces[id] = Some(d);
                return Err(match e {
                    crate::iommu::IoMapError::OutOfMemory => Error::NotEnoughMemory,
                    _ => Error::InvalidArgument,
                }
                .code());
            }
        }
    }
    if pages > 0 {
        kprintln!(
            "[ok] IOMMU: {:02x}:{:02x}.{} bound, with its {pages} page{} of reserved memory mapped where they are",
            sid >> 8,
            sid >> 3 & 31,
            sid & 7,
            if pages == 1 { "" } else { "s" }
        );
    }
    iommu::attach(sid, id as u16 + 1, d.base, d.root());
    k.io_spaces[id] = Some(IoDomain {
        sid: Some(sid),
        ..d
    });
    Ok(())
}

/// `IoMap`: rdi = frame (Map right), rsi = I/O address space, rdx = 1 if
/// the device may write it. The I/O address is the frame's physical
/// address.
fn io_map(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    if f.a2 > 1 {
        return Err(Error::InvalidArgument.code());
    }
    let s = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Frame { paddr, size_bits } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    let write = f.a2 == 1;
    let needed = if write {
        Rights::MAP | Rights::WRITE
    } else {
        Rights::MAP | Rights::READ
    };
    if !cap.rights.contains(needed) {
        return Err(Error::InsufficientRights.code());
    }
    // Only a page of RAM: a device must not reach another's registers.
    if size_bits != 12 || !crate::memory::is_ram(paddr) {
        return Err(Error::InvalidArgument.code());
    }
    let id = io_space_cap(k, cur, f.a1)?;
    if k.io_mapped[s].is_some() {
        return Err(Error::AlreadyMapped.code());
    }
    let d = k.io_spaces[id]
        .as_mut()
        .ok_or(Error::InvalidCapability.code())?;
    let root = d.root();
    crate::iommu::map(root, paddr, paddr, write, &mut d.pool).map_err(|e| match e {
        crate::iommu::IoMapError::InUse => Error::AlreadyMapped.code(),
        crate::iommu::IoMapError::OutOfMemory => Error::NotEnoughMemory.code(),
        crate::iommu::IoMapError::TooHigh => Error::InvalidArgument.code(),
    })?;
    iommu::flush();
    k.io_mapped[s] = Mapping::new(id as u16, paddr);
    k.ipc.set_msg_of(cur, [paddr, 0, 0, 0]);
    Ok(())
}

/// `IoUnmap`: rdi = frame slot.
fn io_unmap(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let (id, iova) = k.io_mapped[s].take().ok_or(Error::InvalidArgument.code())?;
    if let Some(d) = k.io_spaces[id as usize] {
        crate::iommu::unmap(d.root(), iova);
        iommu::flush();
    }
    Ok(())
}

/// Destroys I/O address space `id`: its function's DMA is blocked first,
/// then every frame mapped in it is forgotten (its tables are about to go
/// back to untyped memory with it).
fn destroy_io_space(k: &mut Kernel, id: usize) {
    if let Some(sid) = k.io_spaces[id].and_then(|d| d.sid) {
        iommu::detach(sid);
    }
    for m in k.io_mapped.iter_mut() {
        if m.space() == Some(id as u16) {
            *m = Mapping::NONE;
        }
    }
    k.io_spaces[id] = None;
}

/// `FrameMap`: rdi = frame slot, rsi = user address, rdx = 1 for writable.
fn frame_map(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    if f.a2 > 1 {
        return Err(Error::InvalidArgument.code());
    }
    let id = k.spaces[cur as usize].ok_or(Error::IllegalOperation.code())?;
    map_into(k, cur, f.a0, f.a1, f.a2, id)
}

/// `FrameMapInto`: rdi = frame slot, rsi = user address, rdx = flags, r8
/// = address-space slot (Write right).
fn frame_map_into(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let id = vspace_cap(k, cur, f.a3)?;
    map_into(k, cur, f.a0, f.a1, f.a2, id)
}

/// Maps the frame in the caller's slot `slot` at `va` in address space
/// `id`, with [`MAP_WRITE`] / [`MAP_EXEC`] `flags`.
fn map_into(k: &mut Kernel, cur: Tid, slot: u64, va: u64, flags: u64, id: u16) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Frame { paddr, .. } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    let pages = frame_pages(&cap.object);
    let (writable, executable) = (flags & MAP_WRITE != 0, flags & MAP_EXEC != 0);
    // Writable or executable, never both.
    if flags & !(MAP_WRITE | MAP_EXEC) != 0 || (writable && executable) {
        return Err(Error::InvalidArgument.code());
    }
    let needed = if writable {
        Rights::MAP | Rights::WRITE
    } else {
        Rights::MAP | Rights::READ
    };
    if !cap.rights.contains(needed) {
        return Err(Error::InsufficientRights.code());
    }
    // A large (device) frame is mapped as a run of pages from `va`.
    let end = va.checked_add(pages * 4096);
    if !va.is_multiple_of(4096) || !vm::is_user(va) || end.is_none_or(|e| !vm::is_user_range(va, e)) {
        return Err(Error::InvalidArgument.code());
    }
    if executable && pages > 1 {
        return Err(Error::InvalidArgument.code());
    }
    if k.mapped[s].is_some() {
        return Err(Error::AlreadyMapped.code());
    }
    let v = k.vspaces[id as usize]
        .as_mut()
        .ok_or(Error::IllegalOperation.code())?;
    for p in 0..pages {
        let at = va + p * 4096;
        if let Err(e) = v.root.map_frame(at, paddr + p * 4096, writable, executable, &mut v.pool) {
            // Undo the pages mapped so far.
            for q in 0..p {
                v.root.unmap(va + q * 4096);
            }
            if p > 0 {
                smp::shootdown(v.root.root_pa(), false);
            }
            return Err(match e {
                MapError::InUse => Error::AlreadyMapped.code(),
                MapError::OutOfMemory => Error::NotEnoughMemory.code(),
            });
        }
    }
    k.mapped[s] = Mapping::new(id, va);
    Ok(())
}

/// The address space a capability in the caller's slot names, with Write.
fn vspace_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<u16, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::AddressSpace { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok(id as u16)
}

/// `ThreadSetVSpace`: rdi = thread, rsi = address space. The thread's
/// hidden slot gets a copy of the capability, keeping the space alive.
fn thread_set_vspace(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    let id = vspace_cap(k, cur, f.a1)?;
    let src = own_slot(k, cur, f.a1).ok_or(Error::InvalidCapability.code())?;
    let hidden = VSPACE_SLOTS + t as usize;
    if k.caps.get(hidden).is_some() {
        let _ = k.caps.delete(hidden);
    }
    k.caps
        .derive(src, hidden, Rights::ALL, None)
        .map_err(cap_error)?;
    k.spaces[t as usize] = Some(id);
    reap(k);
    Ok(())
}

/// Destroys address space `id`: forgets every frame mapped in it (its page
/// tables are about to go back to untyped memory with it) and stops every
/// thread still running in it.
fn destroy_vspace(k: &mut Kernel, id: u16) {
    for m in k.mapped.iter_mut() {
        if m.space() == Some(id) {
            *m = Mapping::NONE;
        }
    }
    for t in 0..MAX_THREADS {
        if k.spaces[t] == Some(id) {
            let _ = k.ipc.suspend(t as Tid);
            k.spaces[t] = None;
        }
    }
    // No CPU may keep its tables loaded once their memory can be reused.
    if let Some(v) = k.vspaces[id as usize].take() {
        smp::shootdown(v.root.root_pa(), true);
    }
}

/// `FrameUnmap`: rdi = frame slot.
fn frame_unmap(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    if !matches!(cap.object, Object::Frame { .. }) {
        return Err(Error::InvalidCapability.code());
    }
    if k.mapped[s].is_none() {
        return Err(Error::InvalidArgument.code());
    }
    unmap_slot(k, s);
    Ok(())
}

fn cap_error(e: CapError) -> u64 {
    match e {
        CapError::SlotEmpty | CapError::SlotOutOfRange => Error::InvalidCapability.code(),
        CapError::SlotOccupied => Error::SlotOccupied.code(),
        CapError::OutOfMemory => Error::NotEnoughMemory.code(),
        CapError::BadgeAlreadySet | CapError::NotBadgeable => Error::InvalidArgument.code(),
        CapError::WrongObjectType => Error::InvalidCapability.code(),
        CapError::HasChildren => Error::IllegalOperation.code(),
    }
}

/// Frees every endpoint and notification no capability refers to any
/// more, waking threads blocked on them with `ObjectDestroyed`.
fn reap(k: &mut Kernel) {
    // Destroying a thread empties its CSpace, which can orphan more
    // objects (or threads): repeat until nothing changes. Destroying a
    // CNode empties it, with the same effect. Each round is one pass over
    // the capability table marking what is still referred to.
    loop {
        let live = Live::of(k);
        let chunks = k.cnodes.len();
        if let Some(t) = (0..MAX_THREADS).find(|&t| k.thread_object[t] && !live.threads[t]) {
            destroy_thread(k, t as Tid);
            continue;
        }
        if let Some(c) = (0..chunks).find(|&c| k.cnodes[c].is_some() && !k.cnode_live[c]) {
            destroy_cnode(k, c);
            continue;
        }
        let dead = (0..MAX_SPACES)
            .find(|&id| matches!(k.vspaces[id], Some(v) if v.object) && !live.spaces[id]);
        if let Some(id) = dead {
            destroy_vspace(k, id as u16);
            continue;
        }
        if let Some(id) =
            (0..MAX_IO_SPACES).find(|&id| k.io_spaces[id].is_some() && !live.io_spaces[id])
        {
            destroy_io_space(k, id);
            continue;
        }
        // A scheduling context goes with its last capability, taking the
        // CPU time of every thread on it until they are bound again.
        for id in 0..MAX_THREADS {
            if k.sc_object[id] && !live.scs[id] {
                k.sc_object[id] = false;
                k.sc_used[id] = false;
                let _ = k.ipc.destroy_sc(id as Tid);
            }
        }
        for id in 0..MAX_ENDPOINTS {
            if k.ep_used[id] && !live.endpoints[id] {
                k.ep_used[id] = false;
                // A fault handler naming this endpoint must not follow its
                // id to whatever object reuses the table entry.
                for h in k.fault_ep.iter_mut() {
                    if matches!(h, Some((e, _)) if *e as usize == id) {
                        *h = None;
                    }
                }
                let _ = k.ipc.destroy_endpoint(id as u16);
            }
        }
        for id in 0..MAX_NOTIFICATIONS {
            if id != TIMER_NTFN as usize && k.ntfn_used[id] && !live.ntfns[id] {
                k.ntfn_used[id] = false;
                // An interrupt line bound to it must not follow its id to
                // whatever notification reuses the entry. Unbound, the line
                // masks itself at its next interrupt and stays masked
                // until a driver binds it again.
                for line in 0..MAX_IRQS {
                    if matches!(k.irq_ntfn[line], Some((n, _)) if n as usize == id) {
                        k.irq_ntfn[line] = None;
                    }
                }
                // Nor an I/O space's fault notification.
                for d in k.io_spaces.iter_mut().flatten() {
                    if matches!(d.notify, Some((n, _)) if n as usize == id) {
                        d.notify = None;
                    }
                }
                // Nor may a pending timer.
                for t in k.timers.iter_mut() {
                    if matches!(t, Some((_, n, _)) if *n as usize == id) {
                        *t = None;
                    }
                }
                let _ = k.ipc.destroy_notification(id as u16);
            }
        }
        break;
    }
}

/// Which table entries some capability still refers to.
/// (Which CNodes, it leaves in `Kernel::cnode_live`.)
struct Live {
    threads: [bool; MAX_THREADS],
    spaces: [bool; MAX_SPACES],
    io_spaces: [bool; MAX_IO_SPACES],
    endpoints: [bool; MAX_ENDPOINTS],
    ntfns: [bool; MAX_NOTIFICATIONS],
    scs: [bool; MAX_THREADS],
}

impl Live {
    fn of(k: &mut Kernel) -> Live {
        let cnodes = &mut *k.cnode_live;
        cnodes.iter_mut().for_each(|c| *c = false);
        let mut l = Live {
            threads: [false; MAX_THREADS],
            spaces: [false; MAX_SPACES],
            io_spaces: [false; MAX_IO_SPACES],
            endpoints: [false; MAX_ENDPOINTS],
            ntfns: [false; MAX_NOTIFICATIONS],
            scs: [false; MAX_THREADS],
        };
        for c in k.caps.iter() {
            let i = match c.object {
                Object::Thread { id } => l.threads.get_mut(id as usize),
                Object::CNode { base, .. } => (base as usize)
                    .checked_sub(CNODE_POOL)
                    .and_then(|o| cnodes.get_mut(o / CNODE_CHUNK)),
                Object::AddressSpace { id } => l.spaces.get_mut(id as usize),
                Object::IoSpace { id } => l.io_spaces.get_mut(id as usize),
                Object::Endpoint { id } => l.endpoints.get_mut(id as usize),
                Object::Notification { id } => l.ntfns.get_mut(id as usize),
                Object::SchedContext { id } => l.scs.get_mut(id as usize),
                _ => None,
            };
            if let Some(i) = i {
                *i = true;
            }
        }
        l
    }
}

/// Stops thread `t`, empties its CSpace and frees its table entry. Its
/// address space belongs to its creator and stays.
fn destroy_thread(k: &mut Kernel, t: Tid) {
    // A caller it owed a reply learns the server is gone (PeerRestarted).
    let _ = k.ipc.destroy(t);
    let (base, size) = window(t as usize);
    let own = base as usize..(base + size) as usize;
    for s in own.chain([ROOT_SLOTS + t as usize, VSPACE_SLOTS + t as usize]) {
        if k.caps.get(s).is_some() {
            unmap_slot(k, s);
            let _ = k.caps.delete(s);
        }
    }
    let i = t as usize;
    k.cspace[i] = window(i);
    k.thread_object[i] = false;
    k.thread_used[i] = false;
    k.configured[i] = None;
    k.spaces[i] = None;
    k.fault_ep[i] = None;
    k.in_fault[i] = false;
    k.foreign[i] = false;
    k.tls[i] = 0;
    k.sleep_until[i] = None;
    let _ = k.ipc.clear_notification(sleep_ntfn(t));
    let _ = k.ipc.reset_thread(t);
}

/// The thread a capability in the caller's slot names, with Write right.
fn thread_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<Tid, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Thread { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok(id as Tid)
}

fn thread_inactive(k: &Kernel, t: Tid) -> bool {
    k.ipc.thread(t).state == superior_objects::ipc::State::Inactive
}

/// `ThreadConfigure`: rdi = thread, rsi = entry, rdx = stack top, r8 =
/// argument, r9 = priority.
fn thread_configure(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    let (entry, stack_top, prio) = (f.a1, f.a2, f.a4);
    // Returning to a non-canonical address faults in the kernel: keep both
    // addresses inside a user window.
    if !vm::is_user(entry)
        || stack_top.checked_sub(16).is_none_or(|s| !vm::is_user_range(s, stack_top))
        || !stack_top.is_multiple_of(16)
    {
        return Err(Error::InvalidArgument.code());
    }
    // A thread cannot create one that outranks it.
    if prio > k.ipc.thread(cur).prio as u64 {
        return Err(Error::InsufficientRights.code());
    }
    let i = t as usize;
    // Its own address space if it was given one, else its creator's.
    if k.caps.get(VSPACE_SLOTS + i).is_none() {
        k.spaces[i] = k.spaces[cur as usize];
    }
    disown(k, t);
    k.frames[i] = UserFrame::new_thread(entry, stack_top, f.a3);
    k.fresh[i] = true;
    k.preempted[i] = false;
    k.fault_ep[i] = k.fault_ep[cur as usize];
    let _ = k.ipc.set_timeout_handler(t, k.ipc.timeout_handler(cur));
    k.foreign[i] = false;
    k.tls[i] = 0;
    // Nor escape its budget: the new thread shares its creator's context,
    // so a component's threads draw on one budget however many it makes.
    let _ = k.ipc.bind_sc(t, k.ipc.bound_sc(cur));
    k.configured[i] = Some(prio as u8);
    Ok(())
}

/// `ThreadResume`: starts a configured thread, or restarts a suspended one.
fn thread_resume(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let t = thread_cap(k, cur, slot)?;
    let prio = k.configured[t as usize].ok_or(Error::IllegalOperation.code())?;
    if k.spaces[t as usize].is_none() {
        return Err(Error::IllegalOperation.code());
    }
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    k.ipc.spawn(t, prio).map_err(|e| e.status())
}

/// `ThreadSuspend`: stops a thread wherever it is.
fn thread_suspend(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let t = thread_cap(k, cur, slot)?;
    // A cancelled fault call is simply retried on resume: the faulting
    // instruction runs again and faults again. A foreign system call's
    // pc is past its instruction, so it is pointed back at it.
    k.ipc.suspend(t).map_err(|e| e.status())?;
    if core::mem::take(&mut k.in_fault[t as usize]) && k.syscall_fault[t as usize] {
        k.frames[t as usize].rewind_syscall();
    }
    Ok(())
}

/// `ThreadCopyCap`: rdi = thread, rsi = caller's slot, rdx = the thread's
/// slot, r8 = rights mask.
fn thread_copy_cap(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    let src = own_slot(k, cur, f.a1).ok_or(Error::InvalidCapability.code())?;
    let dst = own_slot(k, t, f.a2).ok_or(Error::InvalidArgument.code())?;
    let mask = u8::try_from(f.a3)
        .map(Rights::from_bits_truncate)
        .map_err(|_| Error::InvalidArgument.code())?;
    k.caps.derive(src, dst, mask, None).map_err(cap_error)
}

/// The caller's slot `slot` as a capability-table index.
fn own_slot(k: &Kernel, cur: Tid, slot: u64) -> Option<usize> {
    usize::try_from(slot).ok().and_then(|s| cap_slot(k, cur, s))
}

/// The CNode a capability in the caller's slot names, with Write right:
/// its first table index and slot count.
fn cnode_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<(usize, usize), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::CNode { base, size_bits } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    Ok((base as usize, 1 << size_bits))
}

/// Table index of index `rsi` of the CNode in the caller's slot `rdi`.
fn cnode_index(k: &Kernel, cur: Tid, f: &Args) -> Result<usize, u64> {
    let (base, size) = cnode_cap(k, cur, f.a0)?;
    let i = usize::try_from(f.a1)
        .ok()
        .filter(|&i| i < size)
        .ok_or(Error::InvalidArgument.code())?;
    Ok(base + i)
}

/// `CNodeCopy`: rdi = CNode, rsi = index, rdx = caller's slot, r8 = rights
/// mask, r9 = badge (0 = keep).
fn cnode_copy(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let dst = cnode_index(k, cur, f)?;
    let src = own_slot(k, cur, f.a2).ok_or(Error::InvalidCapability.code())?;
    let mask = u8::try_from(f.a3)
        .map(Rights::from_bits_truncate)
        .map_err(|_| Error::InvalidArgument.code())?;
    let badge = (f.a4 != 0).then_some(f.a4);
    k.caps.derive(src, dst, mask, badge).map_err(cap_error)
}

/// `ThreadSetSpace`: rdi = thread, rsi = CNode. The thread's hidden root
/// slot gets a copy of the CNode capability, keeping the CNode alive.
fn thread_set_space(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.a0)?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    let (base, size) = cnode_cap(k, cur, f.a1)?;
    let src = own_slot(k, cur, f.a1).ok_or(Error::InvalidCapability.code())?;
    let root = ROOT_SLOTS + t as usize;
    if k.caps.get(root).is_some() {
        let _ = k.caps.delete(root);
    }
    k.caps
        .derive(src, root, Rights::ALL, None)
        .map_err(cap_error)?;
    k.cspace[t as usize] = (base as u32, size as u32);
    reap(k);
    Ok(())
}

/// A pool chunk starting `1 << bits` free slots, aligned to their size.
/// Taken from the top of the pool down, so the bottom stays free for a
/// CNode as large as the pool's RAM-sized part (the Memory Server's).
fn alloc_cnode(k: &Kernel, bits: u8) -> Option<usize> {
    let n = ((1usize << bits) / CNODE_CHUNK).max(1);
    let used = &*k.chunk_used;
    (0..used.len() / n)
        .rev()
        .map(|i| i * n)
        .find(|&c| used[c..c + n].iter().all(|u| !u))
}

/// Records a CNode of `1 << bits` slots at pool chunk `c`.
fn claim_cnode(k: &mut Kernel, c: usize, bits: u8) {
    k.cnodes[c] = Some(bits);
    let n = ((1usize << bits) / CNODE_CHUNK).max(1);
    k.chunk_used[c..c + n].iter_mut().for_each(|u| *u = true);
}

/// Destroys the CNode starting at pool chunk `c`: empties its slots and
/// leaves any thread using it as its CSpace with none.
fn destroy_cnode(k: &mut Kernel, c: usize) {
    let Some(bits) = k.cnodes[c].take() else {
        return;
    };
    let n = ((1usize << bits) / CNODE_CHUNK).max(1);
    k.chunk_used[c..c + n].iter_mut().for_each(|u| *u = false);
    let base = CNODE_POOL + c * CNODE_CHUNK;
    for s in base..base + (1 << bits) {
        if k.caps.get(s).is_some() {
            unmap_slot(k, s);
            let _ = k.caps.delete(s);
        }
    }
    for cs in k.cspace.iter_mut() {
        if cs.0 as usize == base && cs.1 > 0 {
            *cs = (0, 0);
        }
    }
}

/// `CapMint`: rdi = source slot, rsi = empty destination slot, rdx =
/// rights mask, r8 = badge (0 = none).
fn cap_mint(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let src = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let dst = own_slot(k, cur, f.a1).ok_or(Error::InvalidArgument.code())?;
    let mask = u8::try_from(f.a2)
        .map(Rights::from_bits_truncate)
        .map_err(|_| Error::InvalidArgument.code())?;
    let badge = (f.a3 != 0).then_some(f.a3);
    k.caps.derive(src, dst, mask, badge).map_err(cap_error)
}

/// `Retype`: rdi = untyped slot, rsi = object type, rdx = size in bits,
/// r8 = empty destination slot, r9 = 0 for the caller's CSpace or a CNode
/// slot + 1.
fn retype(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let src = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let ut = *k.caps.get(src).ok_or(Error::InvalidCapability.code())?;
    if ut.object.untyped().is_none() {
        return Err(Error::InvalidCapability.code());
    }
    // Device memory is registers, not RAM: it makes only frames over
    // them, and smaller device-memory blocks.
    let device = matches!(ut.object, Object::DeviceUntyped { .. });
    // The new capability goes in the caller's own CSpace, or (r9 = a CNode
    // slot + 1) at index r8 of that CNode.
    let dst = if f.a4 == 0 {
        own_slot(k, cur, f.a3).ok_or(Error::InvalidArgument.code())?
    } else {
        let (base, size) = cnode_cap(k, cur, f.a4 - 1)?;
        usize::try_from(f.a3)
            .ok()
            .filter(|&i| i < size)
            .map(|i| base + i)
            .ok_or(Error::InvalidArgument.code())?
    };
    if k.caps.get(dst).is_some() {
        return Err(Error::SlotOccupied.code());
    }
    let ty = ObjectType::from_u64(f.a1).ok_or(Error::InvalidArgument.code())?;
    let bits = ty.size_bits(f.a2).ok_or(Error::InvalidArgument.code())?;
    if device && !matches!(ty, ObjectType::Untyped | ObjectType::Frame) {
        return Err(Error::InvalidArgument.code());
    }
    // Claim a table entry only once everything else is known to succeed.
    let free = |used: &[bool]| used.iter().position(|u| !u);
    let entry = match ty {
        ObjectType::Untyped => None,
        ObjectType::Endpoint => Some(free(&k.ep_used).ok_or(Error::ObjectTableFull.code())?),
        ObjectType::Notification => Some(free(&k.ntfn_used).ok_or(Error::ObjectTableFull.code())?),
        ObjectType::Frame => None,
        ObjectType::Thread => Some(free(&k.thread_used).ok_or(Error::ObjectTableFull.code())?),
        ObjectType::CNode => {
            Some(alloc_cnode(k, bits - CNODE_SLOT_BITS).ok_or(Error::ObjectTableFull.code())?)
        }
        ObjectType::AddressSpace => Some(
            k.vspaces
                .iter()
                .position(Option::is_none)
                .ok_or(Error::ObjectTableFull.code())?,
        ),
        // Only with an IOMMU the kernel drives.
        ObjectType::IoSpace if !iommu::present() => return Err(Error::IllegalOperation.code()),
        ObjectType::IoSpace => Some(
            k.io_spaces
                .iter()
                .position(Option::is_none)
                .ok_or(Error::ObjectTableFull.code())?,
        ),
        ObjectType::SchedContext => Some(free(&k.sc_used).ok_or(Error::ObjectTableFull.code())?),
    };
    let base = k.caps.carve(src, bits).map_err(cap_error)?;
    let ipc_rights = Rights::READ | Rights::WRITE | Rights::GRANT | Rights::GRANT_REPLY;
    let cap = match (ty, entry) {
        (ObjectType::Endpoint, Some(id)) => {
            k.ep_used[id] = true;
            Capability::new(Object::Endpoint { id: id as u32 }, ipc_rights)
        }
        (ObjectType::Notification, Some(id)) => {
            k.ntfn_used[id] = true;
            Capability::new(Object::Notification { id: id as u32 }, ipc_rights)
        }
        (ObjectType::Thread, Some(t)) => {
            // Its previous thread was destroyed (so is inactive).
            let reset = k.ipc.reset_thread(t as Tid);
            debug_assert!(reset.is_ok(), "retyping active thread {t}");
            // Entry t's context is not its own: it runs on none until
            // ThreadConfigure binds it to its creator's.
            let _ = k.ipc.bind_sc(t as Tid, None);
            k.thread_used[t] = true;
            k.thread_object[t] = true;
            k.cspace[t] = window(t);
            k.configured[t] = None;
            k.reply_grant[t] = false;
            Capability::new(
                Object::Thread { id: t as u32 },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::CNode, Some(c)) => {
            let slot_bits = bits - CNODE_SLOT_BITS;
            claim_cnode(k, c, slot_bits);
            Capability::new(
                Object::CNode {
                    base: (CNODE_POOL + c * CNODE_CHUNK) as u32,
                    size_bits: slot_bits,
                },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::AddressSpace, Some(id)) => {
            let root = AddressSpace::new_in(base).map_err(|_| Error::IllegalOperation.code())?;
            k.vspaces[id] = Some(VSpace {
                root,
                pool: TablePool::Own {
                    next: base + 4096,
                    end: base + (1 << bits),
                },
                object: true,
            });
            Capability::new(
                Object::AddressSpace { id: id as u32 },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::IoSpace, Some(id)) => {
            vm::zero_frame(base);
            vm::zero_frame(base + 4096);
            let mut d = IoDomain {
                base,
                pool: TablePool::Own {
                    next: base + 2 * 4096,
                    end: base + (1 << bits),
                },
                sid: None,
                faults: 0,
                first_fault: (0, false),
                irq_faults: 0,
                notify: None,
            };
            iommu::init_space(base, d.root(), id as u16 + 1);
            for &pa in iommu::fixed_pages() {
                crate::iommu::map(d.root(), pa, pa, true, &mut d.pool)
                    .expect("a new I/O space has room for its fixed pages");
            }
            k.io_spaces[id] = Some(d);
            Capability::new(
                Object::IoSpace { id: id as u32 },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::SchedContext, Some(id)) => {
            k.sc_used[id] = true;
            k.sc_object[id] = true;
            let _ = k.ipc.empty_sc(id as Tid);
            Capability::new(
                Object::SchedContext { id: id as u32 },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::Frame, _) => {
            if !device {
                vm::zero_frame(base);
            }
            Capability::new(
                Object::Frame {
                    paddr: base,
                    size_bits: bits,
                },
                Rights::READ | Rights::WRITE | Rights::GRANT | Rights::MAP,
            )
        }
        _ if device => Capability::new(
            Object::DeviceUntyped {
                base,
                size_bits: bits,
            },
            Rights::ALL,
        ),
        _ => Capability::new(
            Object::Untyped {
                base,
                size_bits: bits,
            },
            Rights::ALL,
        ),
    };
    k.caps
        .insert_child(src, dst, cap)
        .expect("destination slot checked empty");
    Ok(())
}

fn ipc_op(
    k: &mut Kernel,
    cur: Tid,
    op: Syscall,
    slot: usize,
    msg: [u64; 4],
    xfer: CapTransfer,
) -> Result<(), u64> {
    // Both named slots must lie in the caller's CSpace, and a granted slot
    // must hold a capability now. (It is copied at delivery, which for a
    // blocked sender comes later; see `complete_transfers`.)
    let in_cspace = |s: Option<u16>| s.is_none_or(|s| cap_slot(k, cur, s as usize).is_some());
    if !in_cspace(xfer.grant) || !in_cspace(xfer.accept) {
        return Err(Error::InvalidArgument.code());
    }
    let granted_slot_empty = xfer
        .grant
        .is_some_and(|g| cap_slot(k, cur, g as usize).is_none_or(|s| k.caps.get(s).is_none()));
    if granted_slot_empty {
        return Err(Error::InvalidCapability.code());
    }
    k.ipc.set_transfer(xfer);

    if op == Syscall::Yield {
        return k.ipc.yield_now().map_err(|e| e.status());
    }
    if op == Syscall::SchedPassive {
        return k.ipc.make_passive().map_err(|e| e.status());
    }
    let replying = matches!(op, Syscall::Reply | Syscall::ReplyRecv);
    if replying && xfer.grant.is_some() {
        let may = k
            .ipc
            .caller_of(cur)
            .is_some_and(|c| k.reply_grant[c as usize]);
        if !may {
            return Err(Error::InsufficientRights.code());
        }
    }
    if op == Syscall::Reply {
        let to = k.ipc.caller_of(cur);
        k.ipc.reply(msg).map_err(|e| e.status())?;
        stop_if_told(k, to, &msg);
        return Ok(());
    }
    if op == Syscall::ReplySave {
        let i = k.ipc.save_caller().map_err(|e| e.status())?;
        k.ipc.set_msg_of(cur, [i as u64, 0, 0, 0]);
        return Ok(());
    }
    if op == Syscall::ReplyTo {
        if xfer.grant.is_some() {
            return Err(Error::InvalidArgument.code());
        }
        let to = k.ipc.saved_caller(cur, slot);
        k.ipc.reply_saved(slot, msg).map_err(|e| e.status())?;
        stop_if_told(k, to, &msg);
        return Ok(());
    }
    let cap = *cap_slot(k, cur, slot)
        .and_then(|s| k.caps.get(s))
        .ok_or(Error::InvalidCapability.code())?;
    let need = |r: Rights| {
        if cap.rights.contains(r) {
            Ok(())
        } else {
            Err(Error::InsufficientRights.code())
        }
    };
    let replied_to = if op == Syscall::ReplyRecv {
        k.ipc.caller_of(cur)
    } else {
        None
    };
    let ipc = &mut k.ipc;
    let r = match (op, cap.object) {
        (Syscall::Send | Syscall::NBSend, Object::Endpoint { id }) => {
            need(Rights::WRITE)?;
            if xfer.grant.is_some() {
                need(Rights::GRANT)?;
            }
            ipc.send(id as u16, cap.badge, msg, op == Syscall::Send)
        }
        (Syscall::Call, Object::Endpoint { id }) => {
            need(Rights::WRITE)?;
            if xfer.grant.is_some() {
                need(Rights::GRANT)?;
            }
            k.reply_grant[cur as usize] =
                cap.rights.contains(Rights::GRANT) || cap.rights.contains(Rights::GRANT_REPLY);
            ipc.call(id as u16, cap.badge, msg)
        }
        (Syscall::Recv | Syscall::NBRecv, Object::Endpoint { id }) => {
            need(Rights::READ)?;
            ipc.recv(id as u16, op == Syscall::Recv)
        }
        (Syscall::ReplyRecv, Object::Endpoint { id }) => {
            need(Rights::READ)?;
            ipc.reply_recv(id as u16, msg)
        }
        (Syscall::Signal, Object::Notification { id }) => {
            need(Rights::WRITE)?;
            // An unbadged capability still has to leave a mark: OR-ing in
            // no bits would lose a signal sent before anyone waits.
            let bits = if cap.badge == 0 { 1 } else { cap.badge };
            ipc.signal(id as u16, bits)
        }
        (Syscall::Wait, Object::Notification { id }) => {
            need(Rights::READ)?;
            ipc.wait(id as u16)
        }
        _ => return Err(Error::InvalidCapability.code()),
    };
    r.map_err(|e| e.status())?;
    stop_if_told(k, replied_to, &msg);
    Ok(())
}

fn debug_put_str(k: &Kernel, cur: Tid, ptr: u64, len: u64) -> Result<(), u64> {
    let mut buf = [0u8; DEBUG_STR_MAX];
    let len = (len as usize).min(DEBUG_STR_MAX);
    let space = space_of(k, cur).ok_or(Error::IllegalOperation.code())?;
    space
        .copy_from_user(ptr, &mut buf[..len])
        .map_err(|_| Error::InvalidArgument.code())?;
    let s = core::str::from_utf8(&buf[..len]).unwrap_or("<invalid utf-8>");
    kprint!("[t{cur}] {s}");
    Ok(())
}

/// Checks the boot self-test's scheduling-context scenario: a budgeted
/// high-priority hog must have been throttled, the passive server must
/// have run on its callers' contexts, and the slow server must have had a
/// timeout fault when its caller's budget ran out.
fn report_sched(s: superior_objects::ipc::SchedStats) {
    if s.throttles == 0 {
        kprintln!("[fail] no thread was ever throttled by its budget");
    } else {
        kprintln!("[pass] budgets: {} throttles", s.throttles);
    }
    if s.donated_ticks == 0 {
        kprintln!("[fail] the passive server never ran on a lent scheduling context");
    } else {
        kprintln!(
            "[pass] passive server: {} ticks charged to callers' contexts",
            s.donated_ticks
        );
    }
    if s.timeouts == 0 {
        kprintln!("[fail] no lent budget ran dry under a timeout handler");
    } else {
        kprintln!("[pass] timeout faults: {}", s.timeouts);
    }
    SCHED_OK.store(
        s.throttles > 0 && s.donated_ticks > 0 && s.timeouts > 0,
        core::sync::atomic::Ordering::Relaxed,
    );
}

static SCHED_OK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn selftest_done(cur: Tid, code: u64, stats: Stats) -> ! {
    let Stats {
        ticks,
        preemptions,
        idle_halts,
        ..
    } = stats;
    if code == 0 {
        kprintln!("[pass] user self-test reported success (thread {cur})");
    } else {
        kprintln!("[fail] user self-test reported failure {code} (thread {cur})");
    }
    // The spinner never yields, so the client finishing at all means the
    // timer preempted it; check the kernel's own count agrees.
    let code = if preemptions == 0 {
        kprintln!("[fail] no thread was ever preempted ({ticks} timer ticks)");
        code.max(1)
    } else {
        kprintln!("[pass] timer preemption: {ticks} ticks, {preemptions} preemptive switches");
        code
    };
    let code = if SCHED_OK.load(core::sync::atomic::Ordering::Relaxed) {
        code
    } else {
        code.max(1)
    };
    // The client's faults all went to its handler; the spinner's one
    // fault had no handler and stopped it, and the slow server's timeout
    // handler stopped it.
    let code = if stats.faults_handled > 0 && stats.faults_unhandled == 2 {
        kprintln!(
            "[pass] faults: {} handled by IPC, 2 stopped their threads",
            stats.faults_handled
        );
        code
    } else {
        kprintln!(
            "[fail] faults: {} handled, {} unhandled (want >0 and 2)",
            stats.faults_handled,
            stats.faults_unhandled
        );
        code.max(1)
    };
    // The client sleeps on the timer notification after every other
    // thread has blocked, so the CPU must have idled.
    let code = if idle_halts == 0 {
        kprintln!("[fail] the CPU never idled");
        code.max(1)
    } else {
        kprintln!("[pass] idle: halted {idle_halts} times with every thread blocked");
        code
    };
    // Every CPU online ran user threads.
    let cpus = smp::online();
    let r = &stats.resumes[..cpus];
    let code = if r.iter().all(|&n| n > 0) {
        kprintln!("[pass] SMP: {cpus} CPUs ran user threads, resuming them {r:?} times");
        code
    } else {
        kprintln!("[fail] SMP: of {cpus} CPUs, some never ran a user thread: {r:?}");
        code.max(1)
    };
    #[cfg(not(feature = "selftest"))]
    let _ = code;
    #[cfg(feature = "selftest")]
    {
        if code == 0 {
            kprintln!("[pass] all self-tests passed");
        }
        arch::qemu_exit(code == 0);
    }
    #[allow(unreachable_code)]
    arch::halt_forever()
}
