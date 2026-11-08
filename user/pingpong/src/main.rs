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
//! Timings under QEMU's software emulation say nothing about real
//! hardware; they are printed so the same binary can be measured on metal.

#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::{self, Write};
use superior_objects::abi::{
    CapTransfer, Error, FaultKind, FaultReply, MSG_WORDS, ObjectType, Syscall,
};

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

struct Ret {
    status: u64,
    badge: u64,
    msg: [u64; MSG_WORDS],
    /// Slot a capability arrived in, if any.
    cap: Option<u16>,
}

#[inline(always)]
fn syscall(nr: Syscall, a0: u64, m: [u64; MSG_WORDS]) -> Ret {
    syscall_x(nr, a0, m, CapTransfer::NONE)
}

#[inline(always)]
fn syscall_x(nr: Syscall, a0: u64, m: [u64; MSG_WORDS], x: CapTransfer) -> Ret {
    let (status, badge, m0, m1, m2, m3, cap): (u64, u64, u64, u64, u64, u64, u64);
    // SAFETY: the kernel preserves every register except rax, rdi, rsi,
    // rdx, r8, r9, r10 (outputs) and rcx, r11 (clobbered by `syscall`).
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as u64 => status,
            inlateout("rdi") a0 => badge,
            inlateout("rsi") m[0] => m0,
            inlateout("rdx") m[1] => m1,
            inlateout("r8") m[2] => m2,
            inlateout("r9") m[3] => m3,
            inlateout("r10") x.encode() => cap,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Ret {
        status,
        badge,
        msg: [m0, m1, m2, m3],
        cap: if cap == 0 { None } else { Some(cap as u16 - 1) },
    }
}

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
    // SAFETY: rdtsc has no preconditions.
    unsafe { core::arch::x86_64::_rdtsc() }
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
/// (a 3-byte load or store, `hlt`, `ud2`) and skips them, handing back in
/// `rax` what the kernel reported so the client can check it.
fn fault_reply([kind, addr, rip, code]: [u64; 4]) -> [u64; 4] {
    let resume = |len: u64, rax: u64| [FaultReply::ResumeAt as u64, rip + len, rax, 0];
    match FaultKind::from_u64(kind) {
        Some(FaultKind::PageFault) if code & 2 != 0 => resume(3, code),
        Some(FaultKind::PageFault) => resume(3, addr),
        Some(FaultKind::GeneralProtection) => resume(1, kind),
        Some(FaultKind::InvalidOpcode) => resume(2, kind),
        _ => [FaultReply::Stop as u64, 0, 0, 0],
    }
}

/// Faults: delivered to the handler as IPC, resumed by its reply.
fn fault_tests() -> bool {
    let mut pass = true;
    pass &= expect(
        "the server becomes this thread's fault handler",
        syscall(Syscall::SetFaultHandler, FAULT_EP, [0; 4]).status,
        0,
    );

    let (value, kept): (u64, u64);
    // SAFETY: the load faults; the handler skips it and supplies rax.
    // `mov rax, [rdi]` is exactly 3 bytes (48 8b 07).
    unsafe {
        asm!(
            "mov rax, qword ptr [rdi]",
            in("rdi") UNMAPPED,
            out("rax") value,
            inout("r12") 0x1234_5678u64 => kept,
            options(nostack),
        );
    }
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
    let code: u64;
    // SAFETY: the store faults (read-only page); the handler skips it.
    // `mov [rdi], rax` is exactly 3 bytes (48 89 07).
    unsafe {
        asm!(
            "mov qword ptr [rdi], rax",
            in("rdi") VA_RO,
            inout("rax") 0u64 => code,
            options(nostack),
        );
    }
    let untouched = page_is(VA_RO, |_| 0);
    let rv = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]).status;
    pass &= expect(
        "a store to a read-only page faults as a write, and memory is untouched",
        ok(made == 0 && ro == 0 && mapped == 0 && code == 7 && untouched && rv == 0),
        1,
    );

    let (gp, ud): (u64, u64);
    // SAFETY: both instructions fault in user mode; the handler skips them.
    unsafe {
        asm!("hlt", inout("rax") 0u64 => gp, options(nostack, nomem));
        asm!("ud2", inout("rax") 0u64 => ud, options(nostack, nomem));
    }
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
