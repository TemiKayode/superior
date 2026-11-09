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
//! - `arg 4`, the block client (`boot/drivers.manifest`): reads the test
//!   disk through the `block` service (slot 0) into a frame of its own,
//!   checks every word against the pattern `cargo xtask` wrote, checks the
//!   PCI bus server (slot 1) will not give it the driver's device, crashes
//!   the driver and reads again once it is back. Memory in slot 2, control
//!   in slot 3.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall, root};
use superior_objects::interfaces::{Status, block, pci};
use superior_sys::{Called, USER_BASE, call_retry, print_line, syscall, syscall_x};

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

/// Failures so far, and the name checks are logged under.
struct Checks(u64, &'static str);

impl Checks {
    fn check(&mut self, ok: bool, what: core::fmt::Arguments) {
        say!("[{}] {}: {what}", if ok { "pass" } else { "fail" }, self.1);
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
    let mut t = Checks(0, "supervise");
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

// The block client's slots.
const BLOCK: u64 = 0;
const BLOCK_PCI: u64 = 1;
const BLOCK_MEMORY: u64 = 2;
const BLOCK_CONTROL: u64 = 3;
const BUFFER: u64 = 4;
const BUFFER_VA: u64 = USER_BASE + 0x4000_0000;

/// Word `k` of sector `s` of the test disk (see `xtask`).
fn disk_word(s: u64, k: u64) -> u64 {
    0x5355_0000_0000_0000 | s << 16 | k
}

/// Reads `count` sectors from `sector` into the buffer (lent with the
/// call; retried if the driver restarts under it) and checks them.
fn read_and_check(sector: u64, count: u64) -> Result<(), &'static str> {
    let words = (count * block::SECTOR / 8) as usize;
    // SAFETY: the buffer frame is mapped at BUFFER_VA.
    let buf = unsafe { core::slice::from_raw_parts_mut(BUFFER_VA as *mut u64, 512) };
    buf.fill(0);
    let lend = CapTransfer {
        grant: Some(BUFFER as u16),
        accept: None,
    };
    let peer_restarted = Error::PeerRestarted.code();
    let mut r = syscall_x(Syscall::Call, BLOCK, [block::READ, sector, count, 0], lend);
    for _ in 0..3 {
        if r.status != peer_restarted {
            break;
        }
        r = syscall_x(Syscall::Call, BLOCK, [block::READ, sector, count, 0], lend);
    }
    if r.status != 0 || r.msg[0] != Status::Ok as u64 {
        return Err("the read failed");
    }
    for (k, w) in buf[..words].iter().enumerate() {
        let k = k as u64;
        if *w != disk_word(sector + k / 64, k % 64) {
            return Err("wrong data");
        }
    }
    Ok(())
}

fn block_client() -> ! {
    let mut t = Checks(0, "block");
    let r = syscall(Syscall::Call, BLOCK, [block::INFO, block::VERSION, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == 0 && r.msg[1] == 128 && r.msg[2] == 512,
        format_args!("{} sectors of {} bytes", r.msg[1], r.msg[2]),
    );
    let made = syscall(
        Syscall::Retype,
        BLOCK_MEMORY,
        [ObjectType::Frame as u64, 0, BUFFER, 0],
    );
    let mapped = syscall(Syscall::FrameMap, BUFFER, [BUFFER_VA, 1, 0, 0]);
    t.check(
        made.status == 0 && mapped.status == 0,
        format_args!("a buffer page of its own"),
    );
    for (sector, count) in [(0, 8), (100, 8), (127, 1)] {
        let r = read_and_check(sector, count);
        t.check(
            r.is_ok(),
            format_args!(
                "read {count} sectors from {sector} by DMA into its page: {}",
                r.err().unwrap_or("every word right")
            ),
        );
    }
    // Exactly one driver per device.
    let ids = 0x1af4u64 << 16 | 0x1042;
    let r = syscall(Syscall::Call, BLOCK_PCI, [pci::OPEN, pci::VERSION, ids, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::InUse as u64,
        format_args!("the bus server will not give it the driver's device"),
    );
    let r = syscall(Syscall::Call, BLOCK_PCI, [pci::BAR_PAGE, 4, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Denied as u64,
        format_args!("nor any BAR page"),
    );
    // The device can reach only what its driver maps into its IOMMU
    // domain: aimed at another page of the driver's, the DMA must not land.
    let r = syscall(Syscall::Call, BLOCK, [0x57a7, 0, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Ok as u64 && r.msg[1] == 1,
        format_args!(
            "DMA aimed outside the device's IOMMU domain did not land (request {})",
            match (r.msg[2], r.msg[3]) {
                (0, _) => "never completed",
                (_, 0) => "completed but wrote nothing there",
                _ => "failed",
            }
        ),
    );
    let r = read_and_check(32, 8);
    t.check(
        r.is_ok(),
        format_args!(
            "read 8 sectors from 32 after the driver restarted on a fresh domain: {}",
            r.err().unwrap_or("every word right")
        ),
    );
    // Crash the driver; reads work again once it is restarted.
    let r = syscall(Syscall::Call, BLOCK, [0xdead, 0, 0, 0]);
    t.check(
        r.status == Error::PeerRestarted.code(),
        format_args!("the driver crashed under a call (PeerRestarted)"),
    );
    let r = read_and_check(64, 8);
    t.check(
        r.is_ok(),
        format_args!(
            "read 8 sectors from 64 after the restart: {}",
            r.err().unwrap_or("every word right")
        ),
    );
    syscall(Syscall::Call, BLOCK_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
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
        4 => block_client(),
        _ => probe(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
