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

use crate::arch::vm::{self, AddressSpace, USER_BASE, USER_END};
use crate::arch::{self, iommu, Args, Exit, UserFrame};
use crate::memory::{MapError, TablePool};
use crate::{kprint, kprintln};
use spin::{Mutex, MutexGuard};
use superior_objects::abi::{
    CapTransfer, Error, FaultKind, FaultReply, ObjectType, Syscall, CNODE_SLOT_BITS, MAP_EXEC,
    MAP_WRITE,
};
use superior_objects::cap::{CNode, CapError, Capability, Object, Rights};
use superior_objects::ipc::{Ipc, Tid};

/// Table sizes. Self-test builds keep them small: the self-test fills
/// each table to prove that freeing objects frees their entries.
#[cfg(not(feature = "selftest"))]
pub const MAX_THREADS: usize = 32;
#[cfg(feature = "selftest")]
pub const MAX_THREADS: usize = 8;
const _: () = assert!(arch::TICK_HZ as u64 == superior_objects::abi::TICK_HZ);
pub const CSPACE_SLOTS: usize = 16;
/// Layout of the one capability table: each thread's own window, then one
/// hidden slot per thread holding its CNode CSpace's capability (which keeps
/// the CNode alive), then one hidden slot per thread holding its address
/// space's capability (likewise), then the slots CNode objects are carved
/// from.
const WINDOW_SLOTS: usize = MAX_THREADS * CSPACE_SLOTS;
const ROOT_SLOTS: usize = WINDOW_SLOTS;
const VSPACE_SLOTS: usize = ROOT_SLOTS + MAX_THREADS;
const CNODE_POOL: usize = VSPACE_SLOTS + MAX_THREADS;
/// CNodes are made of 16-slot chunks, aligned to their own size.
const CNODE_CHUNK: usize = 16;
#[cfg(not(feature = "selftest"))]
const CNODE_CHUNKS: usize = 256;
#[cfg(feature = "selftest")]
const CNODE_CHUNKS: usize = 16;
const CAP_TABLE_SLOTS: usize = CNODE_POOL + CNODE_CHUNK * CNODE_CHUNKS;
#[cfg(not(feature = "selftest"))]
const MAX_ENDPOINTS: usize = 32;
#[cfg(feature = "selftest")]
const MAX_ENDPOINTS: usize = 8;
#[cfg(not(feature = "selftest"))]
const MAX_NOTIFICATIONS: usize = 32;
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
}

impl IoDomain {
    fn root(&self) -> u64 {
        self.base + 4096
    }
}

struct Kernel {
    ipc: Ipc<MAX_THREADS, MAX_ENDPOINTS, MAX_NOTIFICATIONS>,
    frames: [UserFrame; MAX_THREADS],
    /// Address spaces by id.
    vspaces: [Option<VSpace>; MAX_SPACES],
    /// The address space each thread runs in.
    spaces: [Option<u16>; MAX_THREADS],
    /// Every capability: thread windows, CSpace roots and CNode objects.
    caps: CNode<CAP_TABLE_SLOTS>,
    /// Each thread's CSpace as (first table index, slot count). Empty if
    /// its CNode was destroyed under it.
    cspace: [(u16, u16); MAX_THREADS],
    /// Live CNode objects, by first pool chunk: their slot-count bits.
    cnodes: [Option<u8>; CNODE_CHUNKS],
    /// Notification (and badge) each interrupt line signals.
    irq_ntfn: [Option<(u16, u64)>; MAX_IRQS],
    /// The capability this thread last called through had Grant or
    /// GrantReply, so its server's reply may carry a capability.
    reply_grant: [bool; MAX_THREADS],
    /// Endpoint and notification table entries in use by some object.
    ep_used: [bool; MAX_ENDPOINTS],
    ntfn_used: [bool; MAX_NOTIFICATIONS],
    /// Where the frame capability in each capability-table slot is mapped:
    /// (address space, user address).
    mapped: [Option<(u16, u64)>; CAP_TABLE_SLOTS],
    /// I/O address spaces by id.
    io_spaces: [Option<IoDomain>; MAX_IO_SPACES],
    /// Where the frame capability in each capability-table slot is mapped
    /// for DMA: (I/O address space, I/O address).
    io_mapped: [Option<(u8, u64)>; CAP_TABLE_SLOTS],
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
    vspaces: [None; MAX_SPACES],
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
    irq_ntfn: [None; MAX_IRQS],
    reply_grant: [false; MAX_THREADS],
    ep_used: [false; MAX_ENDPOINTS],
    mapped: [None; CAP_TABLE_SLOTS],
    io_spaces: [None; MAX_IO_SPACES],
    io_mapped: [None; CAP_TABLE_SLOTS],
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
    k.vspaces[id] = Some(VSpace {
        root: space,
        pool: TablePool::Kernel,
        object: false,
    });
    k.frames[t] = UserFrame::new_thread(entry, stack_top, arg);
    k.spaces[t] = Some(id as u16);
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

/// Gives boot thread `t` a CSpace of `1 << bits` slots (a CNode from the
/// pool) in place of its window, before any capability is placed in it.
/// Its own slot `self_slot` gets a capability to that CNode.
pub fn give_cnode(t: Tid, bits: u8, self_slot: usize) -> Result<(), &'static str> {
    let mut k = KERNEL.lock();
    let k = &mut *k;
    let c = alloc_cnode(k, bits).ok_or("CNode pool full")?;
    k.cnodes[c] = Some(bits);
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
    k.cspace[t as usize] = (base as u16, 1 << bits);
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
        space_of(&k, t as Tid).unwrap().activate();
        k.frames[t]
    };
    arch::enter_user(frame)
}

pub fn handle_syscall(frame: &mut UserFrame) -> Exit {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    let cur = k.ipc.current().expect("system call with no current thread");
    k.frames[cur as usize] = *frame;
    k.preempted[cur as usize] = false;

    let a = frame.args();
    let msg = [a.a1, a.a2, a.a3, a.a4];
    let result = match Syscall::from_u64(a.nr) {
        None => Err(Error::IllegalOperation.code()),
        Some(Syscall::CapRevoke) => cap_revoke(k, cur, a.a0),
        Some(Syscall::CapDelete) => cap_delete(k, cur, a.a0),
        Some(Syscall::FrameMap) => frame_map(k, cur, &a),
        Some(Syscall::FrameUnmap) => frame_unmap(k, cur, a.a0),
        Some(Syscall::FrameMapInto) => frame_map_into(k, cur, &a),
        Some(Syscall::Ticks) => {
            let ticks = k.stats.ticks;
            k.ipc.set_msg_of(cur, [ticks, 0, 0, 0]);
            Ok(())
        }
        Some(Syscall::IrqMsiMessage) => irq_msi_message(k, cur, a.a0),
        Some(Syscall::FrameDmaAddress) => frame_dma_address(k, cur, a.a0),
        Some(Syscall::DeviceFrame) => device_frame(k, cur, &a),
        Some(Syscall::IoSpaceBind) => io_space_bind(k, cur, &a),
        Some(Syscall::IoMap) => io_map(k, cur, &a),
        Some(Syscall::IoUnmap) => io_unmap(k, cur, a.a0),
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
    resume(guard, cur, frame)
}

/// The timer fired, either in user mode or while the kernel idled.
pub fn handle_timer(frame: &mut UserFrame) -> Exit {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    k.stats.ticks += 1;
    #[cfg(feature = "selftest")]
    if k.stats.ticks > SELFTEST_TIMEOUT_SECS * arch::TICK_HZ as u64 {
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
            k.ipc.current(),
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
pub fn handle_fault(frame: &mut UserFrame, kind: FaultKind, code: u64, addr: u64) -> Exit {
    if !frame.is_user_mode() {
        panic!(
            "kernel {kind:?} at pc {:#x}, address {addr:#x}, code {code:#x}",
            frame.pc()
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
            let msg = [kind as u64, addr, frame.pc(), code];
            if k.ipc.call(ep, badge, msg).is_err() {
                k.in_fault[cur as usize] = false;
                stop_thread(k, cur, kind, addr, frame.pc());
            }
        }
        None => stop_thread(k, cur, kind, addr, frame.pc()),
    }
    resume(guard, cur, frame)
}

/// A device interrupt (already masked and acknowledged at the PIC): signal
/// the notification bound to its line. Like the timer, it can arrive in
/// user mode or while the kernel idles.
pub fn handle_irq(frame: &mut UserFrame, line: u8) -> Exit {
    let mut guard = KERNEL.lock();
    let k = &mut *guard;
    let bound = k.irq_ntfn.get(line as usize).copied().flatten();
    if !frame.is_user_mode() {
        if let Some((ntfn, badge)) = bound {
            let _ = k.ipc.signal_irq(ntfn, badge);
        }
        return Exit::Iret;
    }
    let cur = k.ipc.current().expect("interrupt with no current thread");
    k.frames[cur as usize] = *frame;
    k.preempted[cur as usize] = true;
    if let Some((ntfn, badge)) = bound {
        let _ = k.ipc.signal_irq(ntfn, badge);
    }
    resume(guard, cur, frame)
}

/// The interrupt line an IRQ capability in the caller's slot names.
fn irq_cap(k: &Kernel, cur: Tid, slot: u64) -> Result<u8, u64> {
    let s = own_slot(k, cur, slot).ok_or(Error::InvalidCapability.code())?;
    match k.caps.get(s).map(|c| c.object) {
        Some(Object::Irq { line }) => Ok(line),
        _ => Err(Error::InvalidCapability.code()),
    }
}

/// `IrqMsiMessage`: rdi = IRQ capability for an MSI vector.
fn irq_msi_message(k: &mut Kernel, cur: Tid, slot: u64) -> Result<(), u64> {
    let line = irq_cap(k, cur, slot)?;
    let (address, data) = arch::msi_message(line).ok_or(Error::InvalidArgument.code())?;
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
/// slot.
fn device_frame(k: &mut Kernel, cur: Tid, f: &Args) -> Result<(), u64> {
    let src = own_slot(k, cur, f.a0).ok_or(Error::InvalidCapability.code())?;
    let cap = *k.caps.get(src).ok_or(Error::InvalidCapability.code())?;
    let Object::DeviceUntyped { base, size_bits } = cap.object else {
        return Err(Error::InvalidCapability.code());
    };
    let offset = f.a1;
    if !offset.is_multiple_of(4096) || offset >= 1 << size_bits {
        return Err(Error::InvalidArgument.code());
    }
    let dst = own_slot(k, cur, f.a2).ok_or(Error::InvalidArgument.code())?;
    if k.caps.get(dst).is_some() {
        return Err(Error::SlotOccupied.code());
    }
    let frame = Capability::new(
        Object::Frame {
            paddr: base + offset,
            size_bits: 12,
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
            // Returning to an address outside the user window could fault
            // in the kernel (a non-canonical rip on x86-64).
            if !(USER_BASE..USER_END).contains(&msg[1]) {
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
        // Waits for an interrupt with no window in which one could slip
        // past and leave the CPU halted with work to do. The interrupt
        // handler runs on this stack and returns here.
        arch::idle_wait();
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
        out.set_results(
            t.status,
            t.badge,
            t.msg,
            t.cap_received.map_or(0, |s| s as u64 + 1),
        );
        Exit::Sysret
    };
    if next != cur {
        space_of(k, next)
            .expect("running thread has no address space")
            .activate();
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

/// Unmaps the frame whose capability is in table slot `s`, if mapped,
/// from its address space and from its I/O address space.
fn unmap_slot(k: &mut Kernel, s: usize) {
    if let Some((id, va)) = k.mapped[s].take() {
        if let Some(v) = k.vspaces[id as usize] {
            v.root.unmap(va);
        }
    }
    if let Some((id, iova)) = k.io_mapped[s].take() {
        if let Some(d) = k.io_spaces[id as usize] {
            crate::iommu::unmap(d.root(), iova);
            iommu::flush();
        }
    }
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
    let d = k.io_spaces[id].ok_or(Error::InvalidCapability.code())?;
    // One function per space, one space per function.
    if d.sid.is_some() || k.io_spaces.iter().flatten().any(|o| o.sid == Some(sid)) {
        return Err(Error::IllegalOperation.code());
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
    k.io_mapped[s] = Some((id as u8, paddr));
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
        if matches!(m, Some((s, _)) if *s as usize == id) {
            *m = None;
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
    if !va.is_multiple_of(4096) || !(USER_BASE..USER_END).contains(&va) {
        return Err(Error::InvalidArgument.code());
    }
    if k.mapped[s].is_some() {
        return Err(Error::AlreadyMapped.code());
    }
    let v = k.vspaces[id as usize]
        .as_mut()
        .ok_or(Error::IllegalOperation.code())?;
    v.root
        .map_frame(va, paddr, writable, executable, &mut v.pool)
        .map_err(|e| match e {
            MapError::InUse => Error::AlreadyMapped.code(),
            MapError::OutOfMemory => Error::NotEnoughMemory.code(),
        })?;
    k.mapped[s] = Some((id, va));
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
        if matches!(m, Some((s, _)) if *s == id) {
            *m = None;
        }
    }
    for t in 0..MAX_THREADS {
        if k.spaces[t] == Some(id) {
            let _ = k.ipc.suspend(t as Tid);
            k.spaces[t] = None;
        }
    }
    k.vspaces[id as usize] = None;
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
        if let Some(t) = (0..MAX_THREADS).find(|&t| k.thread_object[t] && !live.threads[t]) {
            destroy_thread(k, t as Tid);
            continue;
        }
        if let Some(c) = (0..CNODE_CHUNKS).find(|&c| k.cnodes[c].is_some() && !live.cnodes[c]) {
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
                let _ = k.ipc.destroy_notification(id as u16);
            }
        }
        break;
    }
}

/// Which table entries some capability still refers to.
struct Live {
    threads: [bool; MAX_THREADS],
    cnodes: [bool; CNODE_CHUNKS],
    spaces: [bool; MAX_SPACES],
    io_spaces: [bool; MAX_IO_SPACES],
    endpoints: [bool; MAX_ENDPOINTS],
    ntfns: [bool; MAX_NOTIFICATIONS],
}

impl Live {
    fn of(k: &Kernel) -> Live {
        let mut l = Live {
            threads: [false; MAX_THREADS],
            cnodes: [false; CNODE_CHUNKS],
            spaces: [false; MAX_SPACES],
            io_spaces: [false; MAX_IO_SPACES],
            endpoints: [false; MAX_ENDPOINTS],
            ntfns: [false; MAX_NOTIFICATIONS],
        };
        for c in k.caps.iter() {
            let i = match c.object {
                Object::Thread { id } => l.threads.get_mut(id as usize),
                Object::CNode { base, .. } => (base as usize)
                    .checked_sub(CNODE_POOL)
                    .and_then(|o| l.cnodes.get_mut(o / CNODE_CHUNK)),
                Object::AddressSpace { id } => l.spaces.get_mut(id as usize),
                Object::IoSpace { id } => l.io_spaces.get_mut(id as usize),
                Object::Endpoint { id } => l.endpoints.get_mut(id as usize),
                Object::Notification { id } => l.ntfns.get_mut(id as usize),
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
    // Its own address space if it was given one, else its creator's.
    if k.caps.get(VSPACE_SLOTS + i).is_none() {
        k.spaces[i] = k.spaces[cur as usize];
    }
    k.frames[i] = UserFrame::new_thread(entry, stack_top, f.a3);
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
    // instruction runs again and faults again.
    k.in_fault[t as usize] = false;
    k.ipc.suspend(t).map_err(|e| e.status())
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
    r.map_err(|e| e.status())
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
        }
        arch::qemu_exit(code == 0);
    }
    #[allow(unreachable_code)]
    arch::halt_forever()
}
