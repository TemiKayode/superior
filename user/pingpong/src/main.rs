//! Boot self-test program. The kernel loads this image twice, each copy in
//! its own address space:
//!
//! - role 0, the **server**: holds an endpoint with Read+Write and answers
//!   every call with `msg[0] + 1` and the caller's badge.
//! - role 1, the **client**: holds a badged copy with Write only. It
//!   checks that the kernel enforces rights, then times call/reply round
//!   trips and reports the result.
//! - role 2, the **spinner**: spins without a system call. It shares the
//!   client's priority, so the client only runs if the kernel preempts it.
//!   Then it tells the client it is done and blocks for good.
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
use superior_objects::abi::{Error, MSG_WORDS, Syscall};

const EP: u64 = 0;
const EMPTY_SLOT: u64 = 5;
/// Client: the timer notification and the spinner's done signal.
const TIMER: u64 = 1;
const SPINNER_DONE: u64 = 2;
/// Spinner: its done signal and a notification nobody signals.
const DONE_OUT: u64 = 0;
const PARK: u64 = 1;
const SPIN_ITERATIONS: u64 = 100_000_000;
const SLEEP_TICKS: u64 = 5;
const CLIENT_BADGE: u64 = 0xC1;
const WARMUP: u64 = 1_000;
const ROUNDS: u64 = 20_000;

struct Ret {
    status: u64,
    badge: u64,
    msg: [u64; MSG_WORDS],
}

#[inline(always)]
fn syscall(nr: Syscall, a0: u64, m: [u64; MSG_WORDS]) -> Ret {
    let (status, badge, m0, m1, m2, m3);
    // SAFETY: the kernel preserves every register except rax, rdi, rsi,
    // rdx, r8, r9 (outputs) and rcx, r11 (clobbered by `syscall`).
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as u64 => status,
            inlateout("rdi") a0 => badge,
            inlateout("rsi") m[0] => m0,
            inlateout("rdx") m[1] => m1,
            inlateout("r8") m[2] => m2,
            inlateout("r9") m[3] => m3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Ret {
        status,
        badge,
        msg: [m0, m1, m2, m3],
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
        _ => spinner(),
    }
}

fn server() -> ! {
    let mut r = syscall(Syscall::Recv, EP, [0; 4]);
    loop {
        let reply = [r.msg[0].wrapping_add(1), r.badge, 0, 0];
        r = syscall(Syscall::ReplyRecv, EP, reply);
    }
}

fn spinner() -> ! {
    let mut n = 0u64;
    while n < SPIN_ITERATIONS {
        n = core::hint::black_box(n + 1);
    }
    syscall(Syscall::Signal, DONE_OUT, [0; 4]);
    loop {
        syscall(Syscall::Wait, PARK, [0; 4]);
    }
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
