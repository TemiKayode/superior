//! Test components for the Component Manager, chosen by argument.
//!
//! - `arg 0`, the client: calls the `echo` service (slot 0) three times
//!   and checks every answer, then asks the manager (control, slot 1) to
//!   shut down with pass or fail. The service is started lazily, so the
//!   first call is the one that starts it.
//! - `arg 1`, the probe: reads the address where the manager has the boot
//!   bundle mapped. Components have address spaces of their own, so that
//!   must fault (and the manager, its fault handler, reports it).
//! - `arg 2`, the supervision client (`boot/supervise.manifest`): drives
//!   the `counter` service (slot 0) through crashes and checks its state
//!   and journal survive, calls the `crashy` service (slot 1) of a
//!   component that never stays up and expects the manager to give up on
//!   it, and crashes `base` (slot 2) to check that the rest-for-one
//!   component after it, `after` (slot 3, an echo), is restarted too.
//!   Control is slot 4.
//! - `arg 3`, the crasher: faults as soon as it starts.

#![no_std]
#![no_main]

use superior_objects::abi::{Error, Syscall, root};
use superior_sys::{Called, USER_BASE, call_retry, print_line, syscall};

const ECHO: u64 = 0;
const CONTROL: u64 = 1;
const OP_SHUTDOWN: u64 = 2;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

fn client() -> ! {
    let mut failures = 0;
    for k in 1..=3u64 {
        let sent = 100 * k;
        let r = syscall(Syscall::Call, ECHO, [sent, 0, 0, 0]);
        // The badge is the client's number (index + 1): never 0. The
        // count is per instance, so it shows one instance served all.
        let ok = r.status == 0 && r.msg[0] == sent + 1 && r.msg[1] != 0 && r.msg[2] == k;
        say!(
            "[{}] client: call {k}: sent {sent}, got {} (badge {}, call {} of this instance, status {})",
            if ok { "pass" } else { "fail" },
            r.msg[0],
            r.msg[1],
            r.msg[2],
            r.status
        );
        failures += !ok as u64;
    }
    syscall(Syscall::Call, CONTROL, [OP_SHUTDOWN, failures, 0, 0]);
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

fn probe() -> ! {
    let va = USER_BASE + root::BUNDLE_OFFSET;
    say!("probe: reading {va:#x}, where the manager has the boot bundle");
    // SAFETY: deliberately not: this must fault.
    let v = unsafe { core::ptr::read_volatile(va as *const u64) };
    say!("[fail] probe: read {v:#x} from the manager's memory");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

// The supervision client's slots, and the counter's operations.
const COUNTER: u64 = 0;
const CRASHY: u64 = 1;
const BASE: u64 = 2;
const AFTER: u64 = 3;
const SUPERVISE_CONTROL: u64 = 4;
const GET: u64 = 1;
const ADD: u64 = 2;
const CRASH: u64 = 3;
const ADD_CRASH: u64 = 4;
const TRIES: u32 = 4;

struct Checks(u64);

impl Checks {
    fn check(&mut self, ok: bool, what: core::fmt::Arguments) {
        say!("[{}] supervise: {what}", if ok { "pass" } else { "fail" });
        self.0 += !ok as u64;
    }
}

/// The answer to a call that may be retried, or all-ones words.
fn answered(c: Called) -> [u64; 4] {
    match c {
        Called::Answered(r) if r.status == 0 => r.msg,
        _ => [u64::MAX; 4],
    }
}

fn supervise() -> ! {
    let mut t = Checks(0);
    let peer_restarted = Error::PeerRestarted.code();

    // State and journal survive restarts.
    let r = answered(call_retry(COUNTER, [GET, 0, 0, 0], TRIES));
    t.check(
        r[0] == 0 && r[1] == 1,
        format_args!("counter starts at {} (instance {})", r[0], r[1]),
    );
    let r = answered(call_retry(COUNTER, [ADD, 1, 5, 0], TRIES));
    t.check(
        r[0] == 5 && r[1] == 0,
        format_args!("add 5 (request 1): {}", r[0]),
    );
    let r = syscall(Syscall::Call, COUNTER, [CRASH, 0, 0, 0]);
    t.check(
        r.status == peer_restarted,
        format_args!(
            "the counter crashed under a call: status {} (PeerRestarted)",
            r.status
        ),
    );
    let r = answered(call_retry(COUNTER, [GET, 0, 0, 0], TRIES));
    t.check(
        r[0] == 5 && r[1] == 2,
        format_args!("after the restart: value {} (instance {})", r[0], r[1]),
    );
    // Applied, journaled, then crashed before replying: the retry (same
    // request id) must be answered from the journal, not applied again.
    let r = answered(call_retry(COUNTER, [ADD_CRASH, 2, 10, 0], TRIES));
    t.check(
        r[0] == 15 && r[1] == 1,
        format_args!(
            "add 10 (request 2), crashed before replying, retried: {} (from the journal: {})",
            r[0], r[1]
        ),
    );
    let r = answered(call_retry(COUNTER, [GET, 0, 0, 0], TRIES));
    t.check(
        r[0] == 15 && r[1] == 3,
        format_args!("applied once: value {} (instance {})", r[0], r[1]),
    );

    // Restart intensity: the crasher never stays up; the manager gives
    // up on it and its service fails fast.
    let c = call_retry(CRASHY, [0; 4], TRIES);
    t.check(
        matches!(c, Called::Unavailable),
        format_args!("a service given up on answers unavailable"),
    );

    // Rest-for-one: crashing base restarts after too.
    let r = answered(call_retry(AFTER, [7, 0, 0, 0], TRIES));
    t.check(
        r[0] == 8 && r[2] == 1,
        format_args!("after: call {} of its instance", r[2]),
    );
    let r = syscall(Syscall::Call, BASE, [CRASH, 0, 0, 0]);
    t.check(
        r.status == peer_restarted,
        format_args!("base crashed under a call"),
    );
    let r = answered(call_retry(AFTER, [7, 0, 0, 0], TRIES));
    t.check(
        r[0] == 8 && r[2] == 1,
        format_args!(
            "after was restarted with base: call {} of a new instance",
            r[2]
        ),
    );

    syscall(Syscall::Call, SUPERVISE_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

fn crasher() -> ! {
    say!("crasher: starting");
    // SAFETY: deliberately not: this must fault.
    let v = unsafe { core::ptr::read_volatile((USER_BASE + root::BUNDLE_OFFSET) as *const u64) };
    say!("[fail] crasher: read {v:#x}");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(role: u64) -> ! {
    match role {
        0 => client(),
        2 => supervise(),
        3 => crasher(),
        _ => probe(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
