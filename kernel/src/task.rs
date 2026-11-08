//! Threads, their capability spaces, and system call handling.
//!
//! Each thread has a saved [`UserFrame`], an address space, and a capability
//! space (CSpace) of [`CSPACE_SLOTS`] slots. A system call names a
//! capability by slot; this module resolves it, checks rights, and passes
//! the object index to the IPC engine in `superior_objects::ipc`, which
//! decides who runs next.
//!
//! All CSpaces are windows onto one capability table, so a capability
//! granted through IPC is derived from the sender's across CSpaces, and
//! revoking the sender's copy reaches every copy it handed out.
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
use crate::vm::AddressSpace;
use crate::{kprint, kprintln};
use spin::{Mutex, MutexGuard};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::cap::{CNode, CapError, Capability, Object, Rights};
use superior_objects::ipc::{Ipc, Tid};
use x86_64::instructions::interrupts;

pub const MAX_THREADS: usize = 8;
pub const CSPACE_SLOTS: usize = 16;
const CAP_TABLE_SLOTS: usize = MAX_THREADS * CSPACE_SLOTS;
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
}

struct Kernel {
    ipc: Ipc<MAX_THREADS, MAX_ENDPOINTS, MAX_NOTIFICATIONS>,
    frames: [UserFrame; MAX_THREADS],
    spaces: [Option<AddressSpace>; MAX_THREADS],
    /// Every thread's CSpace: thread `t` owns slots
    /// `t * CSPACE_SLOTS .. (t + 1) * CSPACE_SLOTS`.
    caps: CNode<CAP_TABLE_SLOTS>,
    /// The capability this thread last called through had Grant or
    /// GrantReply, so its server's reply may carry a capability.
    reply_grant: [bool; MAX_THREADS],
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
    reply_grant: [false; MAX_THREADS],
    fresh: [false; MAX_THREADS],
    preempted: [false; MAX_THREADS],
    stats: Stats {
        ticks: 0,
        preemptions: 0,
        idle_halts: 0,
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
        let slot = cap_slot(tid, slot).ok_or("cspace slot out of range")?;
        k.caps
            .insert_root(slot, cap)
            .map_err(|_| "cspace slot unavailable")?;
    }
    k.frames[t] = UserFrame::new_thread(entry, stack_top, arg);
    k.spaces[t] = Some(space);
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
    let (Some(src), Some(dst)) = (cap_slot(from, src), cap_slot(to, dst)) else {
        return Err("cspace slot out of range");
    };
    KERNEL
        .lock()
        .caps
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

/// Index in the capability table of thread `t`'s slot `slot`.
fn cap_slot(t: Tid, slot: usize) -> Option<usize> {
    ((t as usize) < MAX_THREADS && slot < CSPACE_SLOTS).then(|| t as usize * CSPACE_SLOTS + slot)
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
        Some(Syscall::CapRevoke) => cap_op(k, cur, frame.rdi, |c, s| c.revoke(s).map(|_| ())),
        Some(Syscall::CapDelete) => cap_op(k, cur, frame.rdi, |c, s| c.delete(s)),
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
    k.ipc.set_status(result.err().unwrap_or(0));
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

/// Loads the registers of the thread the IPC engine chose into `frame`,
/// switches address space if needed, and says how to return to it. If no
/// thread can run, halts until an interrupt makes one runnable.
fn resume(mut guard: MutexGuard<'_, Kernel>, cur: Tid, frame: &mut UserFrame) -> Exit {
    let next = loop {
        guard.ipc.schedule();
        if let Some(next) = guard.ipc.current() {
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
        let src = cap_slot(t.from, t.grant as usize);
        let dst = cap_slot(t.to, t.accept as usize);
        let landed = match (src, dst) {
            (Some(src), Some(dst)) => k.caps.derive(src, dst, Rights::ALL, None).is_ok(),
            _ => false,
        };
        k.ipc.set_cap_received(t.to, landed.then_some(t.accept));
    }
}

/// Runs a CNode operation on the caller's slot `slot`.
fn cap_op(
    k: &mut Kernel,
    cur: Tid,
    slot: u64,
    op: impl FnOnce(&mut CNode<CAP_TABLE_SLOTS>, usize) -> Result<(), CapError>,
) -> Result<(), u64> {
    let s = usize::try_from(slot)
        .ok()
        .and_then(|s| cap_slot(cur, s))
        .ok_or(Error::InvalidCapability.code())?;
    op(&mut k.caps, s).map_err(|e| match e {
        CapError::SlotEmpty | CapError::SlotOutOfRange => Error::InvalidCapability.code(),
        _ => Error::IllegalOperation.code(),
    })
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
    let in_cspace = |s: Option<u16>| s.is_none_or(|s| (s as usize) < CSPACE_SLOTS);
    if !in_cspace(xfer.grant) || !in_cspace(xfer.accept) {
        return Err(Error::InvalidArgument.code());
    }
    let granted_slot_empty = xfer.grant.is_some_and(|g| {
        k.caps
            .get(cur as usize * CSPACE_SLOTS + g as usize)
            .is_none()
    });
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
    let cap = *cap_slot(cur, slot)
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
