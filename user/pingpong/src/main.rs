//! Boot self-test program. The kernel loads this image twice, each copy in
//! its own address space:
//!
//! - role 0, the **server**: holds an endpoint with Read+Write and answers
//!   every call with `msg[0] + 1` and the caller's badge. On request
//!   (`msg[1]`) it instead replies granting its notification capability,
//!   or revokes every copy of that capability it has handed out.
//! - role 1, the **client**: holds a badged copy with Write only. It
//!   checks that the kernel enforces rights, receives a capability in a
//!   reply, uses it, watches the server revoke it, makes its own kernel
//!   objects from untyped memory and reclaims it, maps frames of memory
//!   into its address space, then times call/reply round trips and reports
//!   the result.
//! - role 2, the **spinner**: spins without a system call. It shares the
//!   client's priority, so the client only runs if the kernel preempts it.
//!   Then it tells the client it is done and touches unmapped memory with
//!   no fault handler, which stops it.
//!
//! The server is also the client's fault handler: faults arrive as calls
//! with the fault badge, and it emulates or skips the faulting instruction.
//!
//! - role 3, the **hog**: spins forever above every other thread. Only its
//!   scheduling context's budget (2 ticks in 10) lets anything else run.
//!
//! Finally the client sleeps on the timer notification. With every other
//! thread blocked, that only returns if the kernel idles and the timer
//! wakes it.
//!
//! The same program runs on x86-64 and AArch64; only the instructions the
//! fault tests use differ.
//!
//! Timings under QEMU's software emulation say nothing about real
//! hardware; they are printed so the same binary can be measured on metal.

#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use superior_objects::abi::{CapTransfer, Error, FaultKind, FaultReply, ObjectType, Syscall};
use superior_sys::{Ret, syscall, syscall_x};

const EP: u64 = 0;
const EMPTY_SLOT: u64 = 5;
/// Client: the timer notification and the spinner's done signal.
const TIMER: u64 = 1;
const SPINNER_DONE: u64 = 2;
/// Spinner: its done signal.
const DONE_OUT: u64 = 0;
/// Client: a badged endpoint capability that makes the server its fault
/// handler, and an address nothing is mapped at.
const FAULT_EP: u64 = 11;
const FAULT_BADGE: u64 = 0xFA;
const UNMAPPED: u64 = 0x7000_6000_0000;
/// Client: a worker thread it creates, with its stack and signals.
const TCB: u64 = 12;
const STACK_FRAME: u64 = 6;
const DONE_NTFN: u64 = 7;
const PARK_EP: u64 = 8;
const DONE_BADGED: u64 = 9;
const VA_STACK: u64 = USER_BASE + 0x5000_0000;
const WORKER_ARG: u64 = 14;
/// Worker CSpace slots.
const W_DONE: u64 = 0;
const W_PARK: u64 = 1;
/// Shared with the worker thread, which runs in this address space.
static WORKER_RESULT: AtomicU64 = AtomicU64::new(0);
static WORKER_FAULT: AtomicU64 = AtomicU64::new(0);
static WORKER_STATUS: AtomicU64 = AtomicU64::new(u64::MAX);
const SPIN_ITERATIONS: u64 = 100_000_000;
const SLEEP_TICKS: u64 = 5;
/// Server: the notification it hands out.
const GIFT: u16 = 1;
/// Client: where a received capability goes.
const RECEIVED: u16 = 3;
/// The gift's badge: signalling through any copy ORs it into the word.
const GIFT_BADGE: u64 = 0x5;
/// Client: its 64 KiB untyped block, and slots for objects made from it.
const UNTYPED: u64 = 4;
const UNTYPED_BITS: u64 = 16;
const NEW_NTFN: u64 = 6;
const NEW_EP: u64 = 7;
const SUB_UNTYPED: u64 = 8;
const MINTED: u64 = 9;
const SUB_NTFN: u64 = 10;
/// Rights bits (see `superior_objects::cap::Rights`).
const RIGHT_READ: u64 = 1 << 0;
const RIGHT_WRITE: u64 = 1 << 1;
const RIGHT_MAP: u64 = 1 << 4;
/// Frame slots and where to map them: well clear of this program's image
/// (at the window base) and its stack (just below base + 2 GiB).
const FRAME_A: u64 = 6;
const FRAME_RO: u64 = 7;
const FRAME_B: u64 = 8;
const USER_BASE: u64 = 0x7000_0000_0000;
const VA_A: u64 = USER_BASE + 0x4000_0000;
const VA_RO: u64 = VA_A + 0x1000;
const WORDS: usize = 512;
const RIGHTS_ALL: u64 = 0b1_1111;
/// Requests in `msg[1]`.
const OP_ECHO: u64 = 0;
const OP_GIVE: u64 = 1;
const OP_REVOKE: u64 = 2;
const CLIENT_BADGE: u64 = 0xC1;
const WARMUP: u64 = 1_000;
const ROUNDS: u64 = 20_000;

fn put_str(s: &str) {
    syscall(
        Syscall::DebugPutStr,
        s.as_ptr() as u64,
        [s.len() as u64, 0, 0, 0],
    );
}

fn finish(pass: bool) -> ! {
    syscall(Syscall::DebugSelftestDone, if pass { 0 } else { 1 }, [0; 4]);
    loop {
        core::hint::spin_loop();
    }
}

/// A fixed buffer for formatting without an allocator.
struct Line {
    buf: [u8; 160],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Line {
            buf: [0; 160],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?")
    }
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

macro_rules! say {
    ($($arg:tt)*) => {{
        let mut line = Line::new();
        let _ = writeln!(line, $($arg)*);
        put_str(line.as_str());
    }};
}

fn rdtsc() -> u64 {
    superior_sys::cycles()
}

/// Lengths of the instructions the fault tests use, which the handler
/// skips: a load, a store, a privileged instruction, an invalid opcode.
#[cfg(target_arch = "x86_64")]
const FAULTING_LEN: (u64, u64, u64, u64) = (3, 3, 1, 2);
#[cfg(target_arch = "aarch64")]
const FAULTING_LEN: (u64, u64, u64, u64) = (4, 4, 4, 4);

/// Loads from `addr`, which faults; the handler skips the load and supplies
/// the loaded register. A callee-saved register must come back intact.
fn faulting_load(addr: u64) -> (u64, u64) {
    let (value, kept): (u64, u64);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the load faults; the handler skips it and supplies rax.
    // `mov rax, [rdi]` is exactly 3 bytes (48 8b 07).
    unsafe {
        asm!(
            "mov rax, qword ptr [rdi]",
            in("rdi") addr,
            out("rax") value,
            inout("r12") 0x1234_5678u64 => kept,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the load faults; the handler skips it and supplies x0.
    unsafe {
        asm!(
            "ldr x0, [x1]",
            in("x1") addr,
            out("x0") value,
            inout("x20") 0x1234_5678u64 => kept,
            options(nostack),
        );
    }
    (value, kept)
}

/// Stores to `addr`, which faults; returns what the handler put in the
/// first result register.
fn faulting_store(addr: u64) -> u64 {
    let code: u64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the store faults; the handler skips it.
    // `mov [rdi], rax` is exactly 3 bytes (48 89 07).
    unsafe {
        asm!(
            "mov qword ptr [rdi], rax",
            in("rdi") addr,
            inout("rax") 0u64 => code,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the store faults; the handler skips it.
    unsafe {
        asm!(
            "str x0, [x1]",
            in("x1") addr,
            inout("x0") 0u64 => code,
            options(nostack),
        );
    }
    code
}

/// A privileged instruction (`hlt`; on AArch64 `wfi`, which the kernel
/// traps from user mode) and an invalid opcode (`ud2`; `udf #0`). Returns
/// what the handler reported for each.
fn privileged_and_invalid() -> (u64, u64) {
    let (gp, ud): (u64, u64);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: both instructions fault in user mode; the handler skips them.
    unsafe {
        asm!("hlt", inout("rax") 0u64 => gp, options(nostack, nomem));
        asm!("ud2", inout("rax") 0u64 => ud, options(nostack, nomem));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: both instructions fault in user mode; the handler skips them.
    unsafe {
        asm!("wfi", inout("x0") 0u64 => gp, options(nostack, nomem));
        asm!("udf #0", inout("x0") 0u64 => ud, options(nostack, nomem));
    }
    (gp, ud)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(role: u64) -> ! {
    match role {
        0 => server(),
        1 => client(),
        2 => spinner(),
        _ => hog(),
    }
}

fn server() -> ! {
    // From the first receive on, run only on callers' scheduling contexts.
    syscall(Syscall::SchedPassive, 0, [0; 4]);
    let mut r = syscall(Syscall::Recv, EP, [0; 4]);
    loop {
        if r.badge == FAULT_BADGE {
            r = syscall(Syscall::ReplyRecv, EP, fault_reply(r.msg));
            continue;
        }
        let (reply, xfer) = match r.msg[1] {
            OP_GIVE => (
                [0; 4],
                CapTransfer {
                    grant: Some(GIFT),
                    accept: None,
                },
            ),
            OP_REVOKE => {
                let s = syscall(Syscall::CapRevoke, GIFT as u64, [0; 4]).status;
                ([s, 0, 0, 0], CapTransfer::NONE)
            }
            _ => ([r.msg[0].wrapping_add(1), r.badge, 0, 0], CapTransfer::NONE),
        };
        r = syscall_x(Syscall::ReplyRecv, EP, reply, xfer);
        if r.status != 0 {
            // The kernel refused the reply (e.g. a grant it did not
            // allow): report that to the caller and go back to receiving.
            syscall(Syscall::Reply, 0, [r.status, u64::MAX, 0, 0]);
            r = syscall(Syscall::Recv, EP, [0; 4]);
        }
    }
}

fn retype(untyped: u64, ty: ObjectType, bits: u64, dst: u64) -> u64 {
    syscall(Syscall::Retype, untyped, [ty as u64, bits, dst, 0]).status
}

fn mint(src: u64, dst: u64, rights: u64, badge: u64) -> u64 {
    syscall(Syscall::CapMint, src, [dst, rights, badge, 0]).status
}

fn ok(cond: bool) -> u64 {
    cond as u64
}

/// Making kernel objects from untyped memory, and getting it back.
fn retype_tests() -> bool {
    use ObjectType::{Endpoint, Notification, Untyped};
    let mut pass = true;
    let inval = Error::InvalidCapability.code();

    let made = retype(UNTYPED, Notification, 0, NEW_NTFN);
    let minted = mint(NEW_NTFN, MINTED, RIGHT_WRITE, 0x7);
    let sig = syscall(Syscall::Signal, MINTED, [0; 4]).status;
    let w = syscall(Syscall::Wait, NEW_NTFN, [0; 4]);
    pass &= expect(
        "a retyped notification works through a minted, badged copy",
        ok(made == 0 && minted == 0 && sig == 0 && w.status == 0 && w.badge == 0x7),
        1,
    );
    let r = syscall(Syscall::Wait, MINTED, [0; 4]);
    pass &= expect(
        "the minted copy has only the rights asked for",
        r.status,
        Error::InsufficientRights.code(),
    );
    pass &= expect(
        "a badge cannot be minted over a badge",
        mint(MINTED, SUB_NTFN, RIGHTS_ALL, 0x3),
        Error::InvalidArgument.code(),
    );

    let made = retype(UNTYPED, Endpoint, 0, NEW_EP);
    let r = syscall(Syscall::NBRecv, NEW_EP, [0; 4]);
    pass &= expect(
        "a retyped endpoint works",
        ok(made == 0 && r.status == Error::WouldBlock.code()),
        1,
    );

    pass &= expect(
        "retype from a capability that is not untyped is refused",
        retype(NEW_NTFN, Notification, 0, SUB_NTFN),
        inval,
    );
    pass &= expect(
        "retype into an occupied slot is refused",
        retype(UNTYPED, Notification, 0, NEW_NTFN),
        Error::SlotOccupied.code(),
    );
    pass &= expect(
        "retype larger than the untyped block is refused",
        retype(UNTYPED, Untyped, UNTYPED_BITS + 1, SUB_UNTYPED),
        Error::NotEnoughMemory.code(),
    );

    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    let s1 = syscall(Syscall::Signal, MINTED, [0; 4]).status;
    let s2 = syscall(Syscall::NBRecv, NEW_EP, [0; 4]).status;
    pass &= expect(
        "revoking the untyped destroys every object made from it",
        ok(rv == 0 && s1 == inval && s2 == inval),
        1,
    );

    // The whole block is free again: carve it into one sub-block.
    let whole = retype(UNTYPED, Untyped, UNTYPED_BITS, SUB_UNTYPED);
    let full = retype(UNTYPED, Notification, 0, SUB_NTFN);
    pass &= expect(
        "revoked memory is reusable, all of it, and then the block is full",
        ok(whole == 0 && full == Error::NotEnoughMemory.code()),
        1,
    );
    let nested = retype(SUB_UNTYPED, Notification, 0, SUB_NTFN);
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    let gone = syscall(Syscall::Signal, SUB_NTFN, [0; 4]).status;
    pass &= expect(
        "objects from a sub-block die when the parent block is revoked",
        ok(nested == 0 && rv == 0 && gone == inval),
        1,
    );

    // The kernel's notification table is finite; revoking frees entries.
    let mut made = 0;
    let mut last = 0;
    // Enough empty slots to outnumber the free table entries (slot 11
    // holds the fault endpoint).
    for slot in [6, 7, 8, 9, 10, 12, 13, 14, 15] {
        last = retype(UNTYPED, Notification, 0, slot);
        if last != 0 {
            break;
        }
        made += 1;
    }
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    let again = retype(UNTYPED, Notification, 0, NEW_NTFN);
    let rv2 = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    say!("     made {made} notifications before the table filled");
    pass &= expect(
        "the notification table fills, and revoke frees its entries",
        ok(made > 0 && last == Error::ObjectTableFull.code() && rv == 0 && again == 0 && rv2 == 0),
        1,
    );
    pass
}

fn map(frame: u64, va: u64, writable: bool) -> u64 {
    syscall(Syscall::FrameMap, frame, [va, writable as u64, 0, 0]).status
}

fn page(va: u64) -> *mut u64 {
    va as *mut u64
}

/// Reads every word of the page at `va`; true if all equal `f(i)`.
fn page_is(va: u64, f: impl Fn(usize) -> u64) -> bool {
    // SAFETY: the caller has just mapped a readable frame at `va`.
    (0..WORDS).all(|i| unsafe { page(va).add(i).read_volatile() } == f(i))
}

fn pattern(i: usize) -> u64 {
    0x5eed_0000_0000 ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Frames: memory a thread maps into its own address space.
fn frame_tests() -> bool {
    use ObjectType::Frame;
    let mut pass = true;
    let in_use = Error::AlreadyMapped.code();

    let made = retype(UNTYPED, Frame, 0, FRAME_A);
    let mapped = map(FRAME_A, VA_A, true);
    let zeroed = mapped == 0 && page_is(VA_A, |_| 0);
    pass &= expect(
        "a retyped frame maps writable and starts zeroed",
        ok(made == 0 && zeroed),
        1,
    );
    for i in 0..WORDS {
        // SAFETY: FRAME_A is mapped writable at VA_A.
        unsafe { page(VA_A).add(i).write_volatile(pattern(i)) };
    }
    pass &= expect("the mapped frame holds data", ok(page_is(VA_A, pattern)), 1);

    let minted = mint(FRAME_A, FRAME_RO, RIGHT_READ | RIGHT_MAP, 0);
    let rw = map(FRAME_RO, VA_RO, true);
    let ro = map(FRAME_RO, VA_RO, false);
    pass &= expect(
        "a read-only copy cannot map writable, but maps read-only",
        ok(minted == 0 && rw == Error::InsufficientRights.code() && ro == 0),
        1,
    );
    pass &= expect(
        "both mappings see the same memory",
        ok(page_is(VA_RO, pattern)),
        1,
    );

    pass &= expect(
        "a frame capability maps only once",
        map(FRAME_A, VA_A + 0x2000, true),
        in_use,
    );
    let made = retype(UNTYPED, Frame, 0, FRAME_B);
    let over = map(FRAME_B, VA_A, true);
    let code = map(FRAME_B, USER_BASE, true);
    pass &= expect(
        "mapping over a used address (data or program code) is refused",
        ok(made == 0 && over == in_use && code == in_use),
        1,
    );
    let unaligned = map(FRAME_B, VA_A + 0x2008, true);
    let kernel = map(FRAME_B, 0xffff_8000_0000_0000, true);
    pass &= expect(
        "unaligned and kernel addresses are refused",
        ok(unaligned == Error::InvalidArgument.code() && kernel == Error::InvalidArgument.code()),
        1,
    );

    let un = syscall(Syscall::FrameUnmap, FRAME_RO, [0; 4]).status;
    let again = map(FRAME_RO, VA_RO, false);
    pass &= expect(
        "unmap frees the address for another mapping",
        ok(un == 0 && again == 0 && page_is(VA_RO, pattern)),
        1,
    );

    // Revoking the untyped block destroys the frames, which must unmap
    // them; the same memory then comes back zeroed in a new frame.
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    let made = retype(UNTYPED, Frame, 0, FRAME_A);
    let remap = map(FRAME_A, VA_A, true);
    let made_b = retype(UNTYPED, Frame, 0, FRAME_B);
    let freed = map(FRAME_B, VA_RO, false);
    pass &= expect(
        "revoke unmaps every copy's mapping, and reused memory comes back zeroed",
        ok(rv == 0 && made == 0 && remap == 0 && page_is(VA_A, |_| 0) && made_b == 0 && freed == 0),
        1,
    );
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    pass &= expect("cleanup revoke", rv, 0);
    pass
}

/// The server as fault handler. It knows the client's test instructions
/// (a load or store, a privileged instruction, an invalid opcode) and skips
/// them, handing back in the first result register (`rax`, `x0`) what the
/// kernel reported so the client can check it.
fn fault_reply([kind, addr, pc, code]: [u64; 4]) -> [u64; 4] {
    let resume = |len: u64, value: u64| [FaultReply::ResumeAt as u64, pc + len, value, 0];
    let (load, store, privileged, invalid) = FAULTING_LEN;
    match FaultKind::from_u64(kind) {
        Some(FaultKind::PageFault) if code & 2 != 0 => resume(store, code),
        Some(FaultKind::PageFault) => resume(load, addr),
        Some(FaultKind::GeneralProtection) => resume(privileged, kind),
        Some(FaultKind::InvalidOpcode) => resume(invalid, kind),
        _ => [FaultReply::Stop as u64, 0, 0, 0],
    }
}

/// A thread the client creates in its own address space.
extern "C" fn worker(arg: u64) -> ! {
    // Faults; the inherited handler (the server) skips the load and hands
    // back the faulting address.
    let (seen, _) = faulting_load(UNMAPPED);
    WORKER_FAULT.store(seen, Ordering::SeqCst);
    WORKER_RESULT.store(arg * 3, Ordering::SeqCst);
    syscall(Syscall::Signal, W_DONE, [0; 4]);
    loop {
        // Nobody sends here: this blocks until the client suspends it.
        let r = syscall(Syscall::Recv, W_PARK, [0; 4]);
        WORKER_STATUS.store(r.status, Ordering::SeqCst);
        syscall(Syscall::Signal, W_DONE, [0; 4]);
    }
}

fn thread_op(op: Syscall, args: [u64; 4]) -> u64 {
    syscall(op, TCB, args).status
}

/// Threads as objects: make one, give it capabilities, run it, stop it,
/// restart it and destroy it.
fn thread_tests() -> bool {
    use ObjectType::{Endpoint, Frame, Notification, Thread};
    let mut pass = true;
    let setup = [
        retype(UNTYPED, Thread, 0, TCB),
        retype(UNTYPED, Frame, 0, STACK_FRAME),
        map(STACK_FRAME, VA_STACK, true),
        retype(UNTYPED, Notification, 0, DONE_NTFN),
        mint(DONE_NTFN, DONE_BADGED, RIGHT_WRITE, 0x1),
        retype(UNTYPED, Endpoint, 0, PARK_EP),
        thread_op(
            Syscall::ThreadCopyCap,
            [DONE_BADGED, W_DONE, RIGHT_WRITE, 0],
        ),
        thread_op(Syscall::ThreadCopyCap, [PARK_EP, W_PARK, RIGHT_READ, 0]),
    ];
    pass &= expect(
        "make a thread object, its stack and its capabilities",
        ok(setup.iter().all(|&s| s == 0)),
        1,
    );

    let entry = worker as *const () as u64;
    let top = VA_STACK + 0x1000;
    let too_high = thread_op(Syscall::ThreadConfigure, [entry, top, WORKER_ARG, 6]);
    let kernel_entry = thread_op(Syscall::ThreadConfigure, [0xffff_8000_0000_0000, top, 0, 5]);
    pass &= expect(
        "a thread may not outrank its creator or start outside user memory",
        ok(too_high == Error::InsufficientRights.code()
            && kernel_entry == Error::InvalidArgument.code()),
        1,
    );

    let conf = thread_op(Syscall::ThreadConfigure, [entry, top, WORKER_ARG, 5]);
    let run = thread_op(Syscall::ThreadResume, [0; 4]);
    let w = syscall(Syscall::Wait, DONE_NTFN, [0; 4]);
    pass &= expect(
        "the new thread runs here, with copied capabilities and the inherited fault handler",
        ok(conf == 0
            && run == 0
            && w.status == 0
            && w.badge == 0x1
            && WORKER_RESULT.load(Ordering::SeqCst) == WORKER_ARG * 3
            && WORKER_FAULT.load(Ordering::SeqCst) == UNMAPPED),
        1,
    );

    // The worker now waits in Recv. Stop it, then start it again.
    let stop = thread_op(Syscall::ThreadSuspend, [0; 4]);
    let again = thread_op(Syscall::ThreadResume, [0; 4]);
    let w = syscall(Syscall::Wait, DONE_NTFN, [0; 4]);
    pass &= expect(
        "suspending a blocked thread cancels its call, and it resumes after",
        ok(stop == 0
            && again == 0
            && w.status == 0
            && WORKER_STATUS.load(Ordering::SeqCst) == Error::Interrupted.code()),
        1,
    );

    // Deleting the only capability destroys the thread and frees its table
    // entry: every free entry can be retyped again.
    let del = syscall(Syscall::CapDelete, TCB, [0; 4]).status;
    let mut made = 0;
    let mut last = 0;
    for slot in [TCB, 13, 14, 15, 10] {
        last = retype(UNTYPED, Thread, 0, slot);
        if last != 0 {
            break;
        }
        made += 1;
    }
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    say!("     made {made} threads before the table filled");
    pass &= expect(
        "deleting the capability destroys the thread and frees its entry",
        ok(del == 0 && made == 4 && last == Error::ObjectTableFull.code() && rv == 0),
        1,
    );
    pass
}

/// Faults: delivered to the handler as IPC, resumed by its reply.
fn fault_tests() -> bool {
    let mut pass = true;
    pass &= expect(
        "the server becomes this thread's fault handler",
        syscall(Syscall::SetFaultHandler, FAULT_EP, [0; 4]).status,
        0,
    );

    let (value, kept) = faulting_load(UNMAPPED);
    pass &= expect(
        "a page fault reaches the handler with its address, and the thread resumes",
        ok(value == UNMAPPED && kept == 0x1234_5678),
        1,
    );

    // A store to a read-only mapping: error code present|write|user = 7.
    use ObjectType::Frame;
    let made = retype(UNTYPED, Frame, 0, FRAME_A);
    let ro = mint(FRAME_A, FRAME_RO, RIGHT_READ | RIGHT_MAP, 0);
    let mapped = map(FRAME_RO, VA_RO, false);
    let code = faulting_store(VA_RO);
    let untouched = page_is(VA_RO, |_| 0);
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    pass &= expect(
        "a store to a read-only page faults as a write, and memory is untouched",
        ok(made == 0 && ro == 0 && mapped == 0 && code == 7 && untouched && rv == 0),
        1,
    );

    let (gp, ud) = privileged_and_invalid();
    pass &= expect(
        "a privileged instruction and an invalid opcode reach the handler",
        ok(gp == FaultKind::GeneralProtection as u64 && ud == FaultKind::InvalidOpcode as u64),
        1,
    );
    pass
}

/// Calls the server with request `op`, offering `accept` for a capability.
fn request(op: u64, accept: Option<u16>) -> Ret {
    syscall_x(
        Syscall::Call,
        EP,
        [0, op, 0, 0],
        CapTransfer {
            grant: None,
            accept,
        },
    )
}

/// Capability transfer through IPC, granted and revoked by the server.
fn transfer_tests() -> bool {
    let mut pass = true;
    let into = |accept| CapTransfer {
        grant: None,
        accept: Some(accept),
    };

    let r = syscall_x(
        Syscall::Call,
        EP,
        [0, OP_ECHO, 0, 0],
        CapTransfer {
            grant: Some(TIMER as u16),
            accept: None,
        },
    );
    pass &= expect(
        "granting over an endpoint without the Grant right is refused",
        r.status,
        Error::InsufficientRights.code(),
    );
    let r = syscall_x(Syscall::Call, EP, [0, OP_ECHO, 0, 0], into(200));
    pass &= expect(
        "accept slot outside the CSpace is refused",
        r.status,
        Error::InvalidArgument.code(),
    );

    let r = request(OP_GIVE, None);
    let dropped = r.status == 0 && r.cap.is_none();
    let r = syscall(Syscall::Signal, RECEIVED as u64, [0; 4]);
    pass &= expect(
        "a capability offered to a caller that accepts none is dropped",
        (dropped && r.status == Error::InvalidCapability.code()) as u64,
        1,
    );

    let r = request(OP_GIVE, Some(RECEIVED));
    pass &= expect(
        "a reply grants a capability into the accept slot",
        (r.status == 0 && r.cap == Some(RECEIVED)) as u64,
        1,
    );
    let s = syscall(Syscall::Signal, RECEIVED as u64, [0; 4]).status;
    let w = syscall_x(Syscall::Wait, RECEIVED as u64, [0; 4], CapTransfer::NONE);
    pass &= expect(
        "the received capability works (signal, then wait sees the bits)",
        (s == 0 && w.status == 0 && w.badge == GIFT_BADGE) as u64,
        1,
    );

    let r = request(OP_REVOKE, None);
    pass &= expect("the server revokes what it granted", r.msg[0], 0);
    let r = syscall(Syscall::Signal, RECEIVED as u64, [0; 4]);
    pass &= expect(
        "the revoked copy is gone from this CSpace",
        r.status,
        Error::InvalidCapability.code(),
    );

    let r = request(OP_GIVE, Some(RECEIVED));
    let d = syscall(Syscall::CapDelete, RECEIVED as u64, [0; 4]).status;
    let after = syscall(Syscall::Signal, RECEIVED as u64, [0; 4]).status;
    pass &= expect(
        "a received capability can be deleted by its holder",
        (r.cap == Some(RECEIVED) && d == 0 && after == Error::InvalidCapability.code()) as u64,
        1,
    );
    pass
}

/// Spins forever at the highest priority; its budget keeps it in check.
fn hog() -> ! {
    let mut n = 0u64;
    loop {
        n = core::hint::black_box(n.wrapping_add(1));
    }
}

fn spinner() -> ! {
    let mut n = 0u64;
    while n < SPIN_ITERATIONS {
        n = core::hint::black_box(n + 1);
    }
    syscall(Syscall::Signal, DONE_OUT, [0; 4]);
    // No fault handler: the kernel stops this thread here.
    // SAFETY: deliberately faults; nothing is mapped at UNMAPPED.
    unsafe { core::ptr::read_volatile(UNMAPPED as *const u64) };
    put_str("FAIL spinner survived an unhandled fault\n");
    finish(false)
}

/// CNode test slots (all free again after the thread tests revoke).
const CN: u64 = 12;
const TCB2: u64 = 10;
const CN_BIG: u64 = 13;
/// The worker's signal through its CNode carries this badge.
const CN_BADGE: u64 = 0x2;

fn cnode_op(op: Syscall, cnode: u64, args: [u64; 4]) -> u64 {
    syscall(op, cnode, args).status
}

fn tcb2(op: Syscall, args: [u64; 4]) -> u64 {
    syscall(op, TCB2, args).status
}

/// CNodes as objects: make one, fill it, make it a new thread's CSpace,
/// and check it lives exactly as long as some capability (or thread)
/// refers to it.
fn cnode_tests() -> bool {
    use ObjectType::{CNode, Endpoint, Frame, Notification, Thread};
    let mut pass = true;
    let made = retype(UNTYPED, CNode, 4, CN);
    let too_big = retype(
        UNTYPED,
        CNode,
        superior_objects::abi::CNODE_MAX_BITS + 1,
        CN_BIG,
    );
    let no_room = retype(UNTYPED, CNode, 8, CN_BIG);
    pass &= expect(
        "a 16-slot CNode is made; oversized or unplaceable ones are refused",
        ok(made == 0
            && too_big == Error::InvalidArgument.code()
            && no_room == Error::ObjectTableFull.code()),
        1,
    );

    let setup = [
        retype(UNTYPED, Thread, 0, TCB2),
        retype(UNTYPED, Frame, 0, STACK_FRAME),
        map(STACK_FRAME, VA_STACK, true),
        retype(UNTYPED, Notification, 0, DONE_NTFN),
        retype(UNTYPED, Endpoint, 0, PARK_EP),
        cnode_op(
            Syscall::CNodeCopy,
            CN,
            [W_DONE, DONE_NTFN, RIGHT_WRITE, CN_BADGE],
        ),
        cnode_op(Syscall::CNodeCopy, CN, [W_PARK, PARK_EP, RIGHT_READ, 0]),
    ];
    pass &= expect(
        "capabilities are copied (and badged) into the CNode",
        ok(setup.iter().all(|&s| s == 0)),
        1,
    );
    let out = cnode_op(Syscall::CNodeCopy, CN, [16, PARK_EP, RIGHT_READ, 0]);
    let full = cnode_op(Syscall::CNodeCopy, CN, [W_DONE, PARK_EP, RIGHT_READ, 0]);
    let del = cnode_op(Syscall::CNodeDelete, CN, [W_PARK, 0, 0, 0]);
    let again = cnode_op(Syscall::CNodeCopy, CN, [W_PARK, PARK_EP, RIGHT_READ, 0]);
    let rv = cnode_op(Syscall::CNodeRevoke, CN, [W_PARK, 0, 0, 0]);
    pass &= expect(
        "indexes past the end and full slots are refused; delete frees a slot",
        ok(out == Error::InvalidArgument.code()
            && full == Error::SlotOccupied.code()
            && del == 0
            && again == 0
            && rv == 0),
        1,
    );

    let entry = worker as *const () as u64;
    let top = VA_STACK + 0x1000;
    let space = tcb2(Syscall::ThreadSetSpace, [CN, 0, 0, 0]);
    let conf = tcb2(Syscall::ThreadConfigure, [entry, top, WORKER_ARG, 5]);
    let run = tcb2(Syscall::ThreadResume, [0; 4]);
    let w = syscall(Syscall::Wait, DONE_NTFN, [0; 4]);
    pass &= expect(
        "a thread runs with the CNode as its CSpace (its signal bears the CNode's badge)",
        ok(space == 0 && conf == 0 && run == 0 && w.status == 0 && w.badge == CN_BADGE),
        1,
    );

    // The thread holds the CNode: deleting this capability leaves it alive.
    let gone = syscall(Syscall::CapDelete, CN, [0; 4]).status;
    let stop = tcb2(Syscall::ThreadSuspend, [0; 4]);
    let go = tcb2(Syscall::ThreadResume, [0; 4]);
    let w = syscall(Syscall::Wait, DONE_NTFN, [0; 4]);
    pass &= expect(
        "the CNode outlives its creator's capability while a thread uses it",
        ok(gone == 0 && stop == 0 && go == 0 && w.status == 0 && w.badge == CN_BADGE),
        1,
    );

    // Destroying the thread drops the last reference: the whole pool is
    // free again, so a CNode of every chunk fits.
    let del = syscall(Syscall::CapDelete, TCB2, [0; 4]).status;
    let whole = retype(UNTYPED, CNode, 8, CN_BIG);
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    let whole_again = retype(UNTYPED, CNode, 8, CN_BIG);
    let rv2 = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    pass &= expect(
        "destroying its last user frees the CNode, and revoke frees CNodes too",
        ok(del == 0 && whole == 0 && rv == 0 && whole_again == 0 && rv2 == 0),
        1,
    );
    pass
}

/// Address-space objects: made from untyped memory, paying for their own
/// page tables, mapped into by a capability holder (writable or
/// executable, never both), and destroyed with the memory they came from.
fn vspace_tests() -> bool {
    use ObjectType::{AddressSpace, Frame, Thread, Untyped};
    use superior_objects::abi::{MAP_EXEC, MAP_WRITE};
    const SUB: u64 = 13;
    const AS: u64 = 6;
    const F: u64 = 7;
    const RO: u64 = 8;
    const F2: u64 = 9;
    const T: u64 = 10;
    const VA1: u64 = USER_BASE + 0x1000_0000;
    let map_into = |frame: u64, va: u64, flags: u64, space: u64| {
        syscall(Syscall::FrameMapInto, frame, [va, flags, space, 0]).status
    };
    let mut pass = true;
    let sub = retype(UNTYPED, Untyped, 15, SUB);
    let small = retype(SUB, AddressSpace, 13, AS);
    let big = retype(SUB, AddressSpace, 21, AS);
    let made = retype(SUB, AddressSpace, 14, AS);
    pass &= expect(
        "an address space of 16 KiB is made; below 16 KiB or above 1 MiB is refused",
        ok(sub == 0
            && small == Error::InvalidArgument.code()
            && big == Error::InvalidArgument.code()
            && made == 0),
        1,
    );

    let f = retype(SUB, Frame, 0, F);
    let ro = mint(F, RO, RIGHT_READ | RIGHT_MAP, 0);
    let wx = map_into(F, VA1, MAP_WRITE | MAP_EXEC, AS);
    let junk = map_into(F, VA1, 4, AS);
    let not_space = map_into(F, VA1, 0, F);
    let ro_write = map_into(RO, VA1, MAP_WRITE, AS);
    let ro_exec = map_into(RO, VA1, MAP_EXEC, AS);
    pass &= expect(
        "map into a space: W+X, bad flags, a non-space, read-only as writable refused; exec needs Read",
        ok(f == 0
            && ro == 0
            && wx == Error::InvalidArgument.code()
            && junk == Error::InvalidArgument.code()
            && not_space == Error::InvalidCapability.code()
            && ro_write == Error::InsufficientRights.code()
            && ro_exec == 0),
        1,
    );

    // 16 KiB is the top-level table and three more. The first mapping
    // took all three (one per level below the top); a page in another
    // GiB needs two more and must fail, while one beside the first
    // needs none.
    let f2 = retype(SUB, Frame, 0, F2);
    let far = map_into(F2, VA1 + 0x4000_0000, MAP_WRITE, AS);
    let near = map_into(F2, VA1 + 0x1000, MAP_WRITE, AS);
    let twice = syscall(Syscall::FrameMap, F2, [VA_A, 1, 0, 0]).status;
    pass &= expect(
        "an address space's page tables come from its own memory: when they run out, mapping fails",
        ok(f2 == 0
            && far == Error::NotEnoughMemory.code()
            && near == 0
            && twice == Error::AlreadyMapped.code()),
        1,
    );

    // A thread put in the space holds it; revoking the memory the space
    // came from destroys it anyway, and the thread cannot run.
    let entry = VA1;
    let t = retype(UNTYPED, Thread, 0, T);
    let set = syscall(Syscall::ThreadSetVSpace, T, [AS, 0, 0, 0]).status;
    let conf = syscall(Syscall::ThreadConfigure, T, [entry, VA1 + 0x2000, 0, 1]).status;
    let rv = syscall(Syscall::CapRevoke, SUB, [0; 4]).status;
    let run = syscall(Syscall::ThreadResume, T, [0; 4]).status;
    let gone = map_into(F2, VA1, 0, AS);
    let cleanup = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    pass &= expect(
        "revoking its memory destroys an address space a thread is using, and the thread cannot run",
        ok(t == 0
            && set == 0
            && conf == 0
            && rv == 0
            && run == Error::IllegalOperation.code()
            && gone == Error::InvalidCapability.code()
            && cleanup == 0),
        1,
    );
    pass
}

fn expect(what: &str, got: u64, want: u64) -> bool {
    if got == want {
        say!("ok   {what}");
        true
    } else {
        say!("FAIL {what}: status {got}, expected {want}");
        false
    }
}

fn client() -> ! {
    say!("client: up in its own address space (the spinner was preempted)");
    let mut pass = true;

    // The kernel must refuse what this capability space does not allow.
    let r = syscall(Syscall::Call, EMPTY_SLOT, [0; 4]);
    pass &= expect(
        "call on an empty slot is refused",
        r.status,
        Error::InvalidCapability.code(),
    );
    let r = syscall(Syscall::NBRecv, EP, [0; 4]);
    pass &= expect(
        "receive on a write-only endpoint is refused",
        r.status,
        Error::InsufficientRights.code(),
    );
    let r = syscall(Syscall::DebugPutStr, 0x10, [8, 0, 0, 0]);
    pass &= expect(
        "kernel pointer in debug print is refused",
        r.status,
        Error::InvalidArgument.code(),
    );
    let r = syscall(Syscall::Wait, EP, [0; 4]);
    pass &= expect(
        "wait on an endpoint (wrong type) is refused",
        r.status,
        Error::InvalidCapability.code(),
    );
    pass &= transfer_tests();
    pass &= retype_tests();
    pass &= frame_tests();
    pass &= fault_tests();
    pass &= thread_tests();
    pass &= cnode_tests();
    pass &= vspace_tests();

    // Round trips through the server.
    let (mut min, mut total) = (u64::MAX, 0u64);
    for i in 0..WARMUP + ROUNDS {
        let t0 = rdtsc();
        let r = syscall(Syscall::Call, EP, [i, 0, 0, 0]);
        let dt = rdtsc().wrapping_sub(t0);
        if r.status != 0 || r.msg[0] != i + 1 || r.msg[1] != CLIENT_BADGE {
            say!(
                "FAIL round {i}: status {} reply {} badge seen by server {:#x}",
                r.status,
                r.msg[0],
                r.msg[1]
            );
            finish(false);
        }
        if i >= WARMUP {
            min = min.min(dt);
            total += dt;
        }
    }
    say!(
        "ok   {ROUNDS} call/reply round trips across address spaces, server saw badge {CLIENT_BADGE:#x}"
    );
    say!(
        "     cycles per round trip (QEMU, not representative): min {min}, mean {}",
        total / ROUNDS
    );

    // Wait for the spinner to finish, then sleep with nothing else runnable.
    let r = syscall(Syscall::Wait, SPINNER_DONE, [0; 4]);
    pass &= expect("spinner finished and signalled", r.status, 0);
    let mut woke = 0;
    for _ in 0..SLEEP_TICKS {
        let r = syscall(Syscall::Wait, TIMER, [0; 4]);
        if r.status == 0 && r.badge & 1 == 1 {
            woke += 1;
        }
    }
    pass &= expect(
        "woken by the timer notification every time while idle",
        woke,
        SLEEP_TICKS,
    );
    finish(pass)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    put_str("user panic\n");
    finish(false)
}
