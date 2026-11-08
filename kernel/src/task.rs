//! Threads, their capability spaces, and system call handling.
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

use crate::syscall::{self, Exit, UserFrame};
use crate::vm::{self, AddressSpace, MapError, USER_BASE, USER_END};
use crate::{kprint, kprintln};
use spin::{Mutex, MutexGuard};
use superior_objects::abi::{
    CapTransfer, Error, FaultKind, FaultReply, ObjectType, Syscall, CNODE_SLOT_BITS,
};
use superior_objects::cap::{CNode, CapError, Capability, Object, Rights};
use superior_objects::ipc::{Ipc, Tid};
use x86_64::instructions::interrupts;

pub const MAX_THREADS: usize = 8;
pub const CSPACE_SLOTS: usize = 16;
/// Layout of the one capability table: each thread's own window, then one
/// hidden slot per thread holding its CNode CSpace's capability (which keeps
/// the CNode alive), then the slots CNode objects are carved from.
const WINDOW_SLOTS: usize = MAX_THREADS * CSPACE_SLOTS;
const ROOT_SLOTS: usize = WINDOW_SLOTS;
const CNODE_POOL: usize = ROOT_SLOTS + MAX_THREADS;
/// CNodes are made of 16-slot chunks, aligned to their own size.
const CNODE_CHUNK: usize = 16;
const CNODE_CHUNKS: usize = 16;
const CAP_TABLE_SLOTS: usize = CNODE_POOL + CNODE_CHUNK * CNODE_CHUNKS;
const MAX_ENDPOINTS: usize = 8;
const MAX_NOTIFICATIONS: usize = 8;
const DEBUG_STR_MAX: usize = 256;
/// The notification the timer signals (bit 0) on every tick.
pub const TIMER_NTFN: u16 = 0;
/// Self-test builds give up after this many seconds, so a deadlock fails
/// the test instead of idling forever.
#[cfg(feature = "selftest")]
const SELFTEST_TIMEOUT_SECS: u64 = 60;

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
}

struct Kernel {
    ipc: Ipc<MAX_THREADS, MAX_ENDPOINTS, MAX_NOTIFICATIONS>,
    frames: [UserFrame; MAX_THREADS],
    spaces: [Option<AddressSpace>; MAX_THREADS],
    /// Every capability: thread windows, CSpace roots and CNode objects.
    caps: CNode<CAP_TABLE_SLOTS>,
    /// Each thread's CSpace as (first table index, slot count). Empty if
    /// its CNode was destroyed under it.
    cspace: [(u16, u16); MAX_THREADS],
    /// Live CNode objects, by first pool chunk: their slot-count bits.
    cnodes: [Option<u8>; CNODE_CHUNKS],
    /// The capability this thread last called through had Grant or
    /// GrantReply, so its server's reply may carry a capability.
    reply_grant: [bool; MAX_THREADS],
    /// Endpoint and notification table entries in use by some object.
    ep_used: [bool; MAX_ENDPOINTS],
    ntfn_used: [bool; MAX_NOTIFICATIONS],
    /// Where the frame capability in each capability-table slot is mapped:
    /// (thread whose address space, user address).
    mapped: [Option<(Tid, u64)>; CAP_TABLE_SLOTS],
    /// Each thread's fault handler: endpoint and badge.
    fault_ep: [Option<(u16, u64)>; MAX_THREADS],
    /// Blocked in a fault call: the reply says how to resume.
    in_fault: [bool; MAX_THREADS],
    /// Thread table entries in use, by a boot thread or a Thread object.
    thread_used: [bool; MAX_THREADS],
    /// Made by retype (so destroyed with its last capability).
    thread_object: [bool; MAX_THREADS],
    /// Configured with ThreadConfigure, and at what priority.
    configured: [Option<u8>; MAX_THREADS],
    /// Not yet run: its frame holds start registers (entry, stack, argument),
    /// not the results of a system call, and must be resumed untouched.
    fresh: [bool; MAX_THREADS],
    /// Last left user mode by interrupt: its frame is complete and must be
    /// resumed untouched, including `rcx` and `r11`.
    preempted: [bool; MAX_THREADS],
    stats: Stats,
}

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel {
    ipc: Ipc::new(),
    frames: [UserFrame::ZERO; MAX_THREADS],
    spaces: [None; MAX_THREADS],
    caps: CNode::new(),
    cspace: {
        let mut c = [(0, 0); MAX_THREADS];
        let mut t = 0;
        while t < MAX_THREADS {
            c[t] = window(t);
            t += 1;
        }
        c
    },
    cnodes: [None; CNODE_CHUNKS],
    reply_grant: [false; MAX_THREADS],
    ep_used: [false; MAX_ENDPOINTS],
    mapped: [None; CAP_TABLE_SLOTS],
    fault_ep: [None; MAX_THREADS],
    in_fault: [false; MAX_THREADS],
    thread_used: [false; MAX_THREADS],
    thread_object: [false; MAX_THREADS],
    configured: [None; MAX_THREADS],
    // The timer's notification belongs to the kernel and is never freed.
    ntfn_used: {
        let mut u = [false; MAX_NOTIFICATIONS];
        u[TIMER_NTFN as usize] = true;
        u
    },
    fresh: [false; MAX_THREADS],
    preempted: [false; MAX_THREADS],
    stats: Stats {
        ticks: 0,
        preemptions: 0,
        idle_halts: 0,
        faults_handled: 0,
        faults_unhandled: 0,
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
    let space = AddressSpace::new()?;
    let entry = space.load_elf(image)?;
    let stack_top = space.map_stack()?;

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
    k.frames[t] = UserFrame::new_thread(entry, stack_top, arg);
    k.spaces[t] = Some(space);
    k.thread_used[t] = true;
    k.fresh[t] = true;
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

/// Places an original capability in thread `t`'s slot `slot` at boot.
pub fn grant_root(t: Tid, slot: usize, cap: Capability) -> Result<(), &'static str> {
    let mut k = KERNEL.lock();
    let s = cap_slot(&k, t, slot).ok_or("cspace slot out of range")?;
    k.caps
        .insert_root(s, cap)
        .map_err(|_| "cspace slot unavailable")
}

/// Index in the capability table of thread `t`'s slot `slot`.
fn cap_slot(k: &Kernel, t: Tid, slot: usize) -> Option<usize> {
    let (base, size) = *k.cspace.get(t as usize)?;
    (slot < size as usize).then(|| base as usize + slot)
}

/// Thread `t`'s own window of the capability table.
const fn window(t: usize) -> (u16, u16) {
    ((t * CSPACE_SLOTS) as u16, CSPACE_SLOTS as u16)
}

/// Runs the highest-priority thread. Never returns: from here on the
/// kernel is entered only through system calls and traps.
pub fn start() -> ! {
    let frame = {
        let mut k = KERNEL.lock();
        k.ipc.schedule();
        let t = k.ipc.current().expect("no runnable thread at start") as usize;
        k.fresh[t] = false;
        k.spaces[t].unwrap().activate();
        k.frames[t]
    };
    syscall::enter_user(frame)
}

pub fn handle_syscall(frame: &mut UserFrame) -> Exit {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    let cur = k.ipc.current().expect("system call with no current thread");
    k.frames[cur as usize] = *frame;
    k.preempted[cur as usize] = false;

    let msg = [frame.rsi, frame.rdx, frame.r8, frame.r9];
    let result = match Syscall::from_u64(frame.rax) {
        None => Err(Error::IllegalOperation.code()),
        Some(Syscall::CapRevoke) => cap_revoke(k, cur, frame.rdi),
        Some(Syscall::CapDelete) => cap_delete(k, cur, frame.rdi),
        Some(Syscall::FrameMap) => frame_map(k, cur, frame),
        Some(Syscall::FrameUnmap) => frame_unmap(k, cur, frame.rdi),
        Some(Syscall::SetFaultHandler) => set_fault_handler(k, cur, frame.rdi),
        Some(Syscall::ThreadConfigure) => thread_configure(k, cur, frame),
        Some(Syscall::ThreadResume) => thread_resume(k, cur, frame.rdi),
        Some(Syscall::ThreadSuspend) => thread_suspend(k, cur, frame.rdi),
        Some(Syscall::ThreadCopyCap) => thread_copy_cap(k, cur, frame),
        Some(Syscall::ThreadSetSpace) => thread_set_space(k, cur, frame),
        Some(Syscall::CNodeCopy) => cnode_copy(k, cur, frame),
        Some(Syscall::CNodeDelete) => cnode_index(k, cur, frame).and_then(|s| delete_index(k, s)),
        Some(Syscall::CNodeRevoke) => cnode_index(k, cur, frame).and_then(|s| revoke_index(k, s)),
        Some(Syscall::CapMint) => cap_mint(k, cur, frame),
        Some(Syscall::Retype) => retype(k, cur, frame),
        Some(Syscall::DebugPutStr) => debug_put_str(k, cur, frame.rdi, frame.rsi),
        Some(Syscall::DebugSelftestDone) => {
            let stats = k.stats;
            let sched = k.ipc.stats;
            drop(guard);
            report_sched(sched);
            selftest_done(cur, frame.rdi, stats)
        }
        Some(op) => match CapTransfer::decode(frame.r10) {
            Some(xfer) => ipc_op(k, cur, op, frame.rdi as usize, msg, xfer),
            None => Err(Error::InvalidArgument.code()),
        },
    };
    // The result belongs to the caller, even if the operation woke a
    // thread that has since taken the CPU.
    k.ipc.set_status_of(cur, result.err().unwrap_or(0));
    complete_transfers(k);
    resume(guard, cur, frame)
}

/// The timer fired, either in user mode or while the kernel idled.
pub fn handle_timer(frame: &mut UserFrame) -> Exit {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    k.stats.ticks += 1;
    #[cfg(feature = "selftest")]
    if k.stats.ticks > SELFTEST_TIMEOUT_SECS * crate::apic::TICK_HZ as u64 {
        drop(guard);
        kprintln!("[fail] self-test timed out after {SELFTEST_TIMEOUT_SECS} s");
        crate::qemu::exit(crate::qemu::ExitCode::Failure);
    }
    if !frame.is_user_mode() {
        // The only kernel code that runs with interrupts enabled is the
        // idle halt in `resume`. Advance time (refilling budgets), wake any
        // sleeper, and return to it; the idle loop decides who runs.
        k.ipc.tick();
        let _ = k.ipc.signal_irq(TIMER_NTFN, 1);
        return Exit::Iret;
    }
    let cur = k
        .ipc
        .current()
        .expect("timer interrupt with no current thread");
    k.frames[cur as usize] = *frame;
    k.preempted[cur as usize] = true;
    if k.ipc.tick() {
        k.stats.preemptions += 1;
    }
    let _ = k.ipc.signal_irq(TIMER_NTFN, 1);
    resume(guard, cur, frame)
}

/// A CPU exception. From user mode it becomes a `Call` from the faulting
/// thread to its fault handler, or stops the thread if it has none; in
/// kernel mode it is a kernel bug.
pub fn handle_fault(frame: &mut UserFrame, kind: FaultKind, code: u64) -> Exit {
    let addr = match kind {
        FaultKind::PageFault => x86_64::registers::control::Cr2::read_raw(),
        _ => 0,
    };
    if !frame.is_user_mode() {
        panic!(
            "kernel {kind:?} at rip {:#x}, address {addr:#x}, code {code:#x}",
            frame.rip
        );
    }
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    let cur = k.ipc.current().expect("user fault with no current thread");
    k.frames[cur as usize] = *frame;
    // Resume (if ever) with every register exactly as it was.
    k.preempted[cur as usize] = true;
    match k.fault_ep[cur as usize] {
        Some((ep, badge)) => {
            k.stats.faults_handled += 1;
            k.in_fault[cur as usize] = true;
            k.ipc.set_transfer(CapTransfer::NONE);
            let msg = [kind as u64, addr, frame.rip, code];
            if k.ipc.call(ep, badge, msg).is_err() {
                k.in_fault[cur as usize] = false;
                stop_thread(k, cur, kind, addr, frame.rip);
            }
        }
        None => stop_thread(k, cur, kind, addr, frame.rip),
    }
    resume(guard, cur, frame)
}

fn stop_thread(k: &mut Kernel, t: Tid, kind: FaultKind, addr: u64, rip: u64) {
    kprintln!("[fault] thread {t}: unhandled {kind:?} at rip {rip:#x}, address {addr:#x}; stopped");
    k.stats.faults_unhandled += 1;
    k.ipc.suspend_current();
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
            // iretq to a non-canonical rip would fault in the kernel.
            if !(USER_BASE..USER_END).contains(&msg[1]) {
                return false;
            }
            let f = &mut k.frames[t as usize];
            f.rip = msg[1];
            f.rax = msg[2];
            true
        }
        _ => false,
    }
}

/// `SetFaultHandler`: rdi = slot of an endpoint capability with Write.
fn set_fault_handler(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Endpoint { id } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Error::InsufficientRights.code());
    }
    k.fault_ep[cur as usize] = Some((id as u16, cap.badge));
    Ok(())
}

/// Loads the registers of the thread the IPC engine chose into `frame`,
/// switches address space if needed, and says how to return to it. If no
/// thread can run, halts until an interrupt makes one runnable.
fn resume(mut guard: MutexGuard<'_, Kernel>, cur: Tid, frame: &mut UserFrame) -> Exit {
    let next = loop {
        guard.ipc.schedule();
        if let Some(next) = guard.ipc.current() {
            let k = &mut *guard;
            if core::mem::take(&mut k.in_fault[next as usize]) && !apply_fault_reply(k, next) {
                kprintln!("[fault] thread {next}: handler said stop (or failed); stopped");
                k.stats.faults_unhandled += 1;
                k.ipc.suspend_current();
                continue;
            }
            break next;
        }
        guard.stats.idle_halts += 1;
        drop(guard);
        // `sti; hlt` is atomic: an interrupt cannot slip in between and
        // leave the CPU halted with work to do. The interrupt handler runs
        // on this stack and returns here.
        interrupts::enable_and_hlt();
        interrupts::disable();
        guard = KERNEL.lock();
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
        out.rax = t.status;
        out.rdi = t.badge;
        [out.rsi, out.rdx, out.r8, out.r9] = t.msg;
        out.r10 = t.cap_received.map_or(0, |s| s as u64 + 1);
        Exit::Sysret
    };
    if next != cur {
        k.spaces[n].unwrap().activate();
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
    let mut gone = [false; CAP_TABLE_SLOTS];
    k.caps
        .revoke_each(s, |i, _| gone[i] = true)
        .map_err(cap_error)?;
    for (i, _) in gone.iter().enumerate().filter(|(_, g)| **g) {
        unmap_slot(k, i);
    }
    reap(k);
    Ok(())
}

/// `CapDelete`: empties the caller's slot, unmapping a frame first.
fn cap_delete(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    delete_index(k, s)
}

/// Deletes table slot `s`: see [`cap_delete`].
fn delete_index(k: &mut Kernel, s: usize) -> Result<(), u64> {
    k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    unmap_slot(k, s);
    k.caps.delete(s).map_err(cap_error)?;
    reap(k);
    Ok(())
}

/// Unmaps the frame whose capability is in table slot `s`, if mapped.
fn unmap_slot(k: &mut Kernel, s: usize) {
    if let Some((t, va)) = k.mapped[s].take() {
        if let Some(space) = k.spaces[t as usize] {
            space.unmap(va);
        }
    }
}

/// `FrameMap`: rdi = frame slot, rsi = user address, rdx = 1 for writable.
fn frame_map(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let s = own_slot(k, cur, f.rdi).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(s).ok_or(Error::InvalidCapability.code())?;
    let Object::Frame { paddr, .. } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    let writable = match f.rdx {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidArgument.code()),
    };
    let needed = if writable {
        Rights::MAP | Rights::WRITE
    } else {
        Rights::MAP | Rights::READ
    };
    if !cap.rights.contains(needed) {
        return Err(Error::InsufficientRights.code());
    }
    let va = f.rsi;
    if !va.is_multiple_of(4096) || !(USER_BASE..USER_END).contains(&va) {
        return Err(Error::InvalidArgument.code());
    }
    if k.mapped[s].is_some() {
        return Err(Error::AlreadyMapped.code());
    }
    let space = k.spaces[cur as usize].ok_or(Error::IllegalOperation.code())?;
    space.map_frame(va, paddr, writable).map_err(|e| match e {
        MapError::InUse => Error::AlreadyMapped.code(),
        MapError::OutOfMemory => Error::NotEnoughMemory.code(),
    })?;
    k.mapped[s] = Some((cur, va));
    Ok(())
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
    // objects (or threads): repeat until nothing changes.
    // Destroying a CNode empties it, with the same effect.
    loop {
        let dead = (0..MAX_THREADS).find(|&t| {
            k.thread_object[t]
                && !k
                    .caps
                    .iter()
                    .any(|c| c.object == Object::Thread { id: t as u32 })
        });
        if let Some(t) = dead {
            destroy_thread(k, t as Tid);
            continue;
        }
        let dead = (0..CNODE_CHUNKS).find(|&c| {
            let base = (CNODE_POOL + c * CNODE_CHUNK) as u32;
            k.cnodes[c].is_some()
                && !k
                    .caps
                    .iter()
                    .any(|cap| matches!(cap.object, Object::CNode { base: b, .. } if b == base))
        });
        match dead {
            Some(c) => destroy_cnode(k, c),
            None => break,
        }
    }
    for id in 0..MAX_ENDPOINTS {
        let live = k
            .caps
            .iter()
            .any(|c| c.object == Object::Endpoint { id: id as u32 });
        if k.ep_used[id] && !live {
            k.ep_used[id] = false;
            // A fault handler naming this endpoint must not follow its id
            // to whatever object reuses the table entry.
            for h in k.fault_ep.iter_mut() {
                if matches!(h, Some((e, _)) if *e as usize == id) {
                    *h = None;
                }
            }
            let _ = k.ipc.destroy_endpoint(id as u16);
        }
    }
    for id in 0..MAX_NOTIFICATIONS {
        if id == TIMER_NTFN as usize {
            continue;
        }
        let live = k
            .caps
            .iter()
            .any(|c| c.object == Object::Notification { id: id as u32 });
        if k.ntfn_used[id] && !live {
            k.ntfn_used[id] = false;
            let _ = k.ipc.destroy_notification(id as u16);
        }
    }
}

/// Stops thread `t`, empties its CSpace and frees its table entry. Its
/// address space belongs to its creator and stays.
fn destroy_thread(k: &mut Kernel, t: Tid) {
    let _ = k.ipc.suspend(t);
    let (base, size) = window(t as usize);
    let own = base as usize..(base + size) as usize;
    for s in own.chain([ROOT_SLOTS + t as usize]) {
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
fn thread_configure(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.rdi)?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    let (entry, stack_top, prio) = (f.rsi, f.rdx, f.r9);
    // sysret to a non-canonical rip faults in the kernel: keep both
    // addresses inside the user window.
    if !(USER_BASE..USER_END).contains(&entry)
        || !(USER_BASE + 16..=USER_END).contains(&stack_top)
        || !stack_top.is_multiple_of(16)
    {
        return Err(Error::InvalidArgument.code());
    }
    // A thread cannot create one that outranks it.
    if prio > k.ipc.thread(cur).prio as u64 {
        return Err(Error::InsufficientRights.code());
    }
    let i = t as usize;
    k.spaces[i] = k.spaces[cur as usize];
    k.frames[i] = UserFrame::new_thread(entry, stack_top, f.r8);
    k.fresh[i] = true;
    k.preempted[i] = false;
    k.fault_ep[i] = k.fault_ep[cur as usize];
    // Nor escape its budget: the new thread gets the same parameters.
    let sc = *k.ipc.sched_context(cur);
    if let Some(budget) = sc.budget {
        let _ = k.ipc.configure_sc(t, budget, sc.period);
    }
    k.configured[i] = Some(prio as u8);
    Ok(())
}

/// `ThreadResume`: starts a configured thread, or restarts a suspended one.
fn thread_resume(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let t = thread_cap(k, cur, slot)?;
    let prio = k.configured[t as usize].ok_or(Error::IllegalOperation.code())?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    k.ipc.spawn(t, prio).map_err(|e| e.status())
}

/// `ThreadSuspend`: stops a thread wherever it is.
fn thread_suspend(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let t = thread_cap(k, cur, slot)?;
    // A cancelled fault call is simply retried on resume: the faulting
    // instruction runs again and faults again.
    k.in_fault[t as usize] = false;
    k.ipc.suspend(t).map_err(|e| e.status())
}

/// `ThreadCopyCap`: rdi = thread, rsi = caller's slot, rdx = the thread's
/// slot, r8 = rights mask.
fn thread_copy_cap(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.rdi)?;
    let src = own_slot(k, cur, f.rsi).ok_or(Error::InvalidCapability.code())?;
    let dst = own_slot(k, t, f.rdx).ok_or(Error::InvalidArgument.code())?;
    let mask = u8::try_from(f.r8)
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
fn cnode_index(k: &Kernel, cur: Tid, f: &UserFrame) -> Result<usize, u64> {
    let (base, size) = cnode_cap(k, cur, f.rdi)?;
    let i = usize::try_from(f.rsi)
        .ok()
        .filter(|&i| i < size)
        .ok_or(Error::InvalidArgument.code())?;
    Ok(base + i)
}

/// `CNodeCopy`: rdi = CNode, rsi = index, rdx = caller's slot, r8 = rights
/// mask, r9 = badge (0 = keep).
fn cnode_copy(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let dst = cnode_index(k, cur, f)?;
    let src = own_slot(k, cur, f.rdx).ok_or(Error::InvalidCapability.code())?;
    let mask = u8::try_from(f.r8)
        .map(Rights::from_bits_truncate)
        .map_err(|_| Error::InvalidArgument.code())?;
    let badge = (f.r9 != 0).then_some(f.r9);
    k.caps.derive(src, dst, mask, badge).map_err(cap_error)
}

/// `ThreadSetSpace`: rdi = thread, rsi = CNode. The thread's hidden root
/// slot gets a copy of the CNode capability, keeping the CNode alive.
fn thread_set_space(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let t = thread_cap(k, cur, f.rdi)?;
    if !thread_inactive(k, t) {
        return Err(Error::IllegalOperation.code());
    }
    let (base, size) = cnode_cap(k, cur, f.rsi)?;
    let src = own_slot(k, cur, f.rsi).ok_or(Error::InvalidCapability.code())?;
    let root = ROOT_SLOTS + t as usize;
    if k.caps.get(root).is_some() {
        let _ = k.caps.delete(root);
    }
    k.caps
        .derive(src, root, Rights::ALL, None)
        .map_err(cap_error)?;
    k.cspace[t as usize] = (base as u16, size as u16);
    reap(k);
    Ok(())
}

/// First pool chunk of `1 << bits` free slots, aligned to their size.
fn alloc_cnode(k: &Kernel, bits: u8) -> Option<usize> {
    let n = (1usize << bits) / CNODE_CHUNK;
    let mut used = [false; CNODE_CHUNKS];
    for (c, b) in k.cnodes.iter().enumerate() {
        if let Some(b) = b {
            let len = (1usize << b) / CNODE_CHUNK;
            used[c..c + len].iter_mut().for_each(|u| *u = true);
        }
    }
    (0..CNODE_CHUNKS)
        .step_by(n)
        .find(|&c| used[c..c + n].iter().all(|u| !u))
}

/// Destroys the CNode starting at pool chunk `c`: empties its slots and
/// leaves any thread using it as its CSpace with none.
fn destroy_cnode(k: &mut Kernel, c: usize) {
    let Some(bits) = k.cnodes[c].take() else {
        return;
    };
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
fn cap_mint(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let src = own_slot(k, cur, f.rdi).ok_or(Error::InvalidCapability.code())?;
    let dst = own_slot(k, cur, f.rsi).ok_or(Error::InvalidArgument.code())?;
    let mask = u8::try_from(f.rdx)
        .map(Rights::from_bits_truncate)
        .map_err(|_| Error::InvalidArgument.code())?;
    let badge = (f.r8 != 0).then_some(f.r8);
    k.caps.derive(src, dst, mask, badge).map_err(cap_error)
}

/// `Retype`: rdi = untyped slot, rsi = object type, rdx = size in bits
/// (untyped only), r8 = empty destination slot.
fn retype(k: &mut Kernel, cur: Tid, f: &UserFrame) -> Result<(), u64> {
    let src = own_slot(k, cur, f.rdi).ok_or(Error::InvalidCapability.code())?;
    let ut = *k.caps.get(src).ok_or(Error::InvalidCapability.code())?;
    if !matches!(ut.object, Object::Untyped { .. }) {
        return Err(Error::InvalidCapability.code());
    }
    let dst = own_slot(k, cur, f.r8).ok_or(Error::InvalidArgument.code())?;
    if k.caps.get(dst).is_some() {
        return Err(Error::SlotOccupied.code());
    }
    let ty = ObjectType::from_u64(f.rsi).ok_or(Error::InvalidArgument.code())?;
    let bits = ty.size_bits(f.rdx).ok_or(Error::InvalidArgument.code())?;
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
            let _ = k.ipc.reset_thread(t as Tid);
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
            k.cnodes[c] = Some(slot_bits);
            Capability::new(
                Object::CNode {
                    base: (CNODE_POOL + c * CNODE_CHUNK) as u32,
                    size_bits: slot_bits,
                },
                Rights::READ | Rights::WRITE | Rights::GRANT,
            )
        }
        (ObjectType::Frame, _) => {
            vm::zero_frame(base);
            Capability::new(
                Object::Frame {
                    paddr: base,
                    size_bits: bits,
                },
                Rights::READ | Rights::WRITE | Rights::GRANT | Rights::MAP,
            )
        }
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
        return k.ipc.reply(msg).map_err(|e| e.status());
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
            ipc.signal(id as u16, cap.badge)
        }
        (Syscall::Wait, Object::Notification { id }) => {
            need(Rights::READ)?;
            ipc.wait(id as u16)
        }
        _ => return Err(Error::InvalidCapability.code()),
    };
    r.map_err(|e| e.status())
}

fn debug_put_str(k: &Kernel, cur: Tid, ptr: u64, len: u64) -> Result<(), u64> {
    let mut buf = [0u8; DEBUG_STR_MAX];
    let len = (len as usize).min(DEBUG_STR_MAX);
    let space = k.spaces[cur as usize].ok_or(Error::IllegalOperation.code())?;
    space
        .copy_from_user(ptr, &mut buf[..len])
        .map_err(|_| Error::InvalidArgument.code())?;
    let s = core::str::from_utf8(&buf[..len]).unwrap_or("<invalid utf-8>");
    kprint!("[t{cur}] {s}");
    Ok(())
}

/// Checks the boot self-test's scheduling-context scenario: a budgeted
/// high-priority hog must have been throttled, and the passive server must
/// have run on its callers' contexts.
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
    SCHED_OK.store(
        s.throttles > 0 && s.donated_ticks > 0,
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
    // fault had no handler and stopped it.
    let code = if stats.faults_handled > 0 && stats.faults_unhandled == 1 {
        kprintln!(
            "[pass] faults: {} handled by IPC, 1 unhandled stopped its thread",
            stats.faults_handled
        );
        code
    } else {
        kprintln!(
            "[fail] faults: {} handled, {} unhandled (want >0 and 1)",
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
    #[cfg(not(feature = "selftest"))]
    let _ = code;
    #[cfg(feature = "selftest")]
    {
        if code == 0 {
            kprintln!("[pass] all self-tests passed");
            crate::qemu::exit(crate::qemu::ExitCode::Success);
        }
        crate::qemu::exit(crate::qemu::ExitCode::Failure);
    }
    #[allow(unreachable_code)]
    crate::halt_forever()
}
