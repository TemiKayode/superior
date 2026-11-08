//! Threads, their capability spaces, and system call handling.
//!
//! Each thread has a saved [`UserFrame`], an address space, and a small
//! CNode as its capability space. A system call names a capability by slot;
//! this module resolves it, checks rights, and passes the object index to
//! the IPC engine in `superior_objects::ipc`, which decides who runs next.
//!
//! The kernel is entered two ways, a system call or a timer interrupt, and
//! both end in [`resume`]. A thread that entered by system call gets its
//! results in registers and leaves by `sysret`; a thread that was
//! preempted gets its exact registers back by `iretq`.

use crate::syscall::{self, Exit, UserFrame};
use crate::vm::AddressSpace;
use crate::{kprint, kprintln, qemu};
use spin::Mutex;
use superior_objects::abi::{Error, Syscall};
use superior_objects::cap::{CNode, Capability, Object, Rights};
use superior_objects::ipc::{Ipc, Tid};

pub const MAX_THREADS: usize = 8;
pub const CSPACE_SLOTS: usize = 16;
const MAX_ENDPOINTS: usize = 8;
const MAX_NOTIFICATIONS: usize = 8;
const DEBUG_STR_MAX: usize = 256;

struct Kernel {
    ipc: Ipc<MAX_THREADS, MAX_ENDPOINTS, MAX_NOTIFICATIONS>,
    frames: [UserFrame; MAX_THREADS],
    spaces: [Option<AddressSpace>; MAX_THREADS],
    cspaces: [CNode<CSPACE_SLOTS>; MAX_THREADS],
    /// Not yet run: its frame holds start registers (entry, stack, argument),
    /// not the results of a system call, and must be resumed untouched.
    fresh: [bool; MAX_THREADS],
    /// Last left user mode by interrupt: its frame is complete and must be
    /// resumed untouched, including `rcx` and `r11`.
    preempted: [bool; MAX_THREADS],
    ticks: u64,
    /// Timer ticks that took the CPU from one thread and gave it to another.
    preemptions: u64,
}

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel {
    ipc: Ipc::new(),
    frames: [UserFrame::ZERO; MAX_THREADS],
    spaces: [None; MAX_THREADS],
    cspaces: [const { CNode::new() }; MAX_THREADS],
    fresh: [false; MAX_THREADS],
    preempted: [false; MAX_THREADS],
    ticks: 0,
    preemptions: 0,
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
        k.cspaces[t]
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
        Some(Syscall::DebugPutStr) => debug_put_str(k, cur, frame.rdi, frame.rsi),
        Some(Syscall::DebugSelftestDone) => {
            let (ticks, preemptions) = (k.ticks, k.preemptions);
            drop(guard);
            selftest_done(cur, frame.rdi, ticks, preemptions)
        }
        Some(op) => ipc_op(k, cur, op, frame.rdi as usize, msg),
    };
    k.ipc.set_status(result.err().unwrap_or(0));
    resume(guard, cur, frame)
}

/// The timer fired while `frame`'s thread ran in user mode.
pub fn handle_timer(frame: &mut UserFrame) -> Exit {
    assert!(frame.is_user_mode(), "timer interrupt in kernel mode");
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    let cur = k
        .ipc
        .current()
        .expect("timer interrupt with no current thread");
    k.frames[cur as usize] = *frame;
    k.preempted[cur as usize] = true;
    k.ticks += 1;
    if k.ipc.tick() {
        k.preemptions += 1;
    }
    resume(guard, cur, frame)
}

/// Loads the registers of the thread the IPC engine chose into `frame`,
/// switches address space if needed, and says how to return to it.
fn resume(mut guard: spin::MutexGuard<'_, Kernel>, cur: Tid, frame: &mut UserFrame) -> Exit {
    let k = &mut *guard;
    let Some(next) = k.ipc.current() else {
        drop(guard);
        no_runnable_threads();
    };
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
        Exit::Sysret
    };
    if next != cur {
        k.spaces[n].unwrap().activate();
    }
    *frame = out;
    exit
}

fn ipc_op(k: &mut Kernel, cur: Tid, op: Syscall, slot: usize, msg: [u64; 4]) -> Result<(), u64> {
    if op == Syscall::Yield {
        return k.ipc.yield_now().map_err(|e| e.status());
    }
    if op == Syscall::Reply {
        return k.ipc.reply(msg).map_err(|e| e.status());
    }
    let cap = *k.cspaces[cur as usize]
        .get(slot)
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
            ipc.send(id as u16, cap.badge, msg, op == Syscall::Send)
        }
        (Syscall::Call, Object::Endpoint { id }) => {
            need(Rights::WRITE)?;
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

fn selftest_done(cur: Tid, code: u64, ticks: u64, preemptions: u64) -> ! {
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
    #[cfg(feature = "selftest")]
    {
        if code == 0 {
            kprintln!("[pass] all self-tests passed");
            qemu::exit(qemu::ExitCode::Success);
        }
        qemu::exit(qemu::ExitCode::Failure);
    }
    #[allow(unreachable_code)]
    crate::halt_forever()
}

fn no_runnable_threads() -> ! {
    kprintln!("[fail] every thread is blocked: no runnable thread");
    #[cfg(feature = "selftest")]
    qemu::exit(qemu::ExitCode::Failure);
    #[allow(unreachable_code)]
    crate::halt_forever()
}
