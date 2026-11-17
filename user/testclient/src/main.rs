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
//! - `arg 5`, the memory client (`boot/memory.manifest`): pages its heap in
//!   by touching it, takes frames from the Memory Server (slot 0) up to
//!   its quota and one more (refused), gives one back, then checks the
//!   hog's pages came back to the pool. Control in slot 1.
//! - `arg 6`, the hog: touches more heap than its quota allows, so the
//!   manager restarts it; the next instance (it counts instances in its
//!   state page, slot 1) checks it holds nothing and that every page it
//!   is given now is zeroed, though the pool has reused the last
//!   instance's pages. It then blocks on the notification in slot 2.
//! - `arg 7`, the file client under load (`boot/fs.manifest`): appends
//!   records to a file through the filesystem server (slot 0) while the
//!   injector kills the server and the disk driver, retrying calls cut
//!   off by a restart; checks every acknowledged record reads back; then
//!   a large file, truncation, unlinking, the directory tree and renames;
//!   then appends one more record and renames a file, and shuts the
//!   machine down at once (a power cut).
//!   Control in slot 1, memory in slot 2.
//! - `arg 8`, the file client after the power cut (`boot/fs-verify.manifest`):
//!   checks every acknowledged record is on the disk. Same slots.
//! - `arg 9`, a second file client: its container must not hold the
//!   first client's file. Memory in slot 1, a notification to block on in
//!   slot 2.
//! - `arg 22`, the hot-plug client (`boot/hotplug.manifest`): opens a
//!   card the host plugs in while the machine runs, sees what it held
//!   revoked when the card is taken out, and opens the next one.
//! - `arg 24`, the display client (`boot/display.manifest`): draws test
//!   pictures in a surface of its own pages, lends it to the display
//!   driver (slot 0) and has them shown, kills the driver (control, slot
//!   1) and has the next shown by its restarted instance; `cargo xtask
//!   display-test` checks every pixel of the screen each time. Memory in
//!   slot 2.
//! - `arg 25` and `arg 26`, the desktop clients (`boot/desktop.manifest`):
//!   each draws a window in pages of its own and has the compositor (slot
//!   0) show it; the second moves its window and kills the compositor, the
//!   first client and the display driver in turn (control, slot 1). `cargo
//!   xtask desktop-test` checks every pixel of the screen after each step.
//!   Memory in slot 2.
//! - `arg 10`, the fault injector: asks the manager (control, slot 0) to
//!   kill the filesystem server and the disk driver at pseudo-random
//!   moments, then blocks on the notification in slot 1.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering, fence};
use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall, root};
use superior_objects::idl::{display, window};
use superior_objects::interfaces::fs::ring;
use superior_objects::interfaces::{Status, block, dns, fs, input, install, mem, net, nic, pci, power, update};
use superior_sys::{Called, USER_BASE, call_retry, print_line, syscall, syscall_x};

const ECHO: u64 = 0;
const CONTROL: u64 = 1;
const OP_SHUTDOWN: u64 = 2;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

fn client() -> ! {
    let mut failures = 0;
    #[cfg(target_arch = "x86_64")]
    {
        let (ok, ticks, rounds) = direction_flag_survives();
        say!(
            "[{}] client: direction flag set across {ticks} timer ticks ({rounds} rounds): kernel unharmed, flag and registers intact",
            if ok { "pass" } else { "fail" }
        );
        failures += !ok as u64;
    }
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
    // Sleep: blocks for the ticks asked (the timer may land up to one
    // tick late), on a notification of the thread's own.
    let before = superior_sys::ticks();
    let r = syscall(Syscall::Sleep, 20, [0; 4]);
    let slept = superior_sys::ticks() - before;
    let zero = syscall(Syscall::Sleep, 0, [0; 4]).status;
    let ok = r.status == 0 && (20..=22).contains(&slept) && zero == 0;
    say!(
        "[{}] client: slept 20 ticks: woke after {slept} (status {}; 0 ticks: status {zero})",
        if ok { "pass" } else { "fail" },
        r.status
    );
    failures += !ok as u64;
    syscall(Syscall::Call, CONTROL, [OP_SHUTDOWN, failures, 0, 0]);
    superior_sys::park()
}

/// Spins with the direction flag set (as user code does mid-way through a
/// backward copy) until the timer has interrupted it for 20 ticks. The
/// kernel's own code needs the flag clear: an interrupt entry that kept it
/// set made every kernel `memcpy` run backwards and wrecked the saved
/// registers. Each round also checks the flag and callee-saved registers
/// come back as they were. Returns (ok, ticks spanned, rounds).
#[cfg(target_arch = "x86_64")]
fn direction_flag_survives() -> (bool, u64, u64) {
    const PATTERN: u64 = 0x5eed_df00_d1f0_0d00;
    const SPIN: u64 = 2_000_000;
    let start = ticks();
    let mut rounds = 0;
    let mut ok = true;
    while ticks() < start + 20 && rounds < 10_000 {
        let flags: u64;
        let (b, c): (u64, u64);
        // SAFETY: the flag is set and cleared within the block, and no
        // string instruction or call runs while it is set.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov rbx, {p}",
                "std",
                "2:",
                "dec {n}",
                "jnz 2b",
                "pushfq",
                "pop {f}",
                "cld",
                "mov {b}, rbx",
                "pop rbx",
                p = in(reg) PATTERN,
                n = inout(reg) SPIN => _,
                f = out(reg) flags,
                b = out(reg) b,
                inout("r12") PATTERN => c,
            );
        }
        ok &= flags & 1 << 10 != 0 && b == PATTERN && c == PATTERN;
        rounds += 1;
    }
    (ok && ticks() >= start + 20, ticks() - start, rounds)
}

/// Competes with the client for the CPU, both with the direction flag
/// set, so every timer tick switches between them and each resumes from
/// the registers the kernel saved for it.
fn df_spinner() -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        let (ok, ticks, rounds) = direction_flag_survives();
        say!(
            "[{}] spinner: direction flag set across {ticks} timer ticks ({rounds} rounds): flag and registers intact",
            if ok { "pass" } else { "fail" }
        );
    }
    superior_sys::park()
}

fn probe() -> ! {
    let va = USER_BASE + root::BUNDLE_OFFSET;
    say!("probe: reading {va:#x}, where the manager has the boot bundle");
    // SAFETY: deliberately not: this must fault.
    let v = unsafe { core::ptr::read_volatile(va as *const u64) };
    say!("[fail] probe: read {v:#x} from the manager's memory");
    superior_sys::park()
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
    // The kernel fails the call at the fault, before the manager has
    // handled it, and until then the old `after` may still answer. The
    // manager stops the whole group before starting any of it, so once
    // base's new instance answers, `after`'s old one is gone (calls to it
    // wait for the new one).
    answered(call_retry(BASE, [GET, 0, 0, 0], TRIES));
    let r = answered(call_retry(AFTER, [7, 0, 0, 0], TRIES));
    t.check(
        r[0] == 8 && r[2] == 1,
        format_args!(
            "after was restarted with base: call {} of a new instance",
            r[2]
        ),
    );

    syscall(Syscall::Call, SUPERVISE_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

// The block client's slots.
const BLOCK: u64 = 0;
const BLOCK_PCI: u64 = 1;
const BLOCK_MEMORY: u64 = 2;
const BLOCK_CONTROL: u64 = 3;
const BUFFER: u64 = 4;
const BUFFER_VA: u64 = USER_BASE + 0x4000_0000;
/// A second thread that reads at the same time as the first: its thread,
/// stack pages, buffer and the notification it signals when done. In its
/// own CSpace: the block endpoint in 0, the notification in 2 and its
/// buffer in `BUFFER`, so it reads like the main thread.
const HELPER: u64 = 5;
const HELPER_STACK: u64 = 6;
const HELPER_BUFFER: u64 = 8;
const HELPER_DONE: u64 = 9;
const H_DONE: u64 = 2;
const HELPER_STACK_VA: u64 = USER_BASE + 0x4800_0000;
const HELPER_BUFFER_VA: u64 = BUFFER_VA + 0x1000;
/// Reads each thread makes at the same time.
const ROUNDS: u64 = 40;
/// Reads the helper got wrong (or `u64::MAX` until it is done).
static HELPER_FAILED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// The NVMe driver's test operation: its I/O queues and how busy they got.
const OP_QUEUES: u64 = 0x9e5e;

/// Word `k` of sector `s` of the test disk (see `xtask`), and of the
/// second namespace's disk (NVMe).
fn disk_word(s: u64, k: u64) -> u64 {
    0x5355_0000_0000_0000 | s << 16 | k
}

fn disk2_word(s: u64, k: u64) -> u64 {
    0x4e32_0000_0000_0000 | s << 16 | k
}

/// Reads `count` sectors from `sector` into the buffer (lent with the
/// call; retried if the driver restarts under it) and checks them.
fn read_and_check(sector: u64, count: u64) -> Result<(), &'static str> {
    read_unit(0, sector, count, BUFFER_VA, disk_word)
}

/// Reads `count` sectors from `sector` of `unit` into the buffer in slot
/// `BUFFER`, mapped at `va`, and checks each word against `word`.
fn read_unit(
    unit: u64,
    sector: u64,
    count: u64,
    va: u64,
    word: fn(u64, u64) -> u64,
) -> Result<(), &'static str> {
    let words = (count * block::SECTOR / 8) as usize;
    // SAFETY: the buffer frame is mapped at `va`.
    let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u64, 512) };
    buf.fill(0);
    let lend = CapTransfer {
        grant: Some(BUFFER as u16),
        accept: None,
    };
    let peer_restarted = Error::PeerRestarted.code();
    let msg = [block::READ, sector, count, unit];
    let mut r = syscall_x(Syscall::Call, BLOCK, msg, lend);
    for _ in 0..3 {
        if r.status != peer_restarted {
            break;
        }
        r = syscall_x(Syscall::Call, BLOCK, msg, lend);
    }
    if r.status != 0 || r.msg[0] != Status::Ok as u64 {
        return Err("the read failed");
    }
    for (k, w) in buf[..words].iter().enumerate() {
        let k = k as u64;
        if *w != word(sector + k / 64, k % 64) {
            return Err("wrong data");
        }
    }
    Ok(())
}

/// The helper thread: `ROUNDS` reads of the test disk, then it says how
/// many went wrong.
extern "C" fn block_helper(_: u64) -> ! {
    let failed = (0..ROUNDS)
        .filter(|&i| read_unit(0, (i * 8) % 128, 8, HELPER_BUFFER_VA, disk_word).is_err())
        .count() as u64;
    HELPER_FAILED.store(failed, Ordering::SeqCst);
    syscall(Syscall::Signal, H_DONE, [0; 4]);
    // Not waiting on H_DONE: that could take the signal back before the
    // main thread sees it. The main thread suspends this one.
    superior_sys::park()
}

/// Starts the helper thread: Ok, or what failed.
fn start_helper() -> Result<(), &'static str> {
    let made = |ty: ObjectType, slot: u64| {
        syscall(Syscall::Retype, BLOCK_MEMORY, [ty as u64, 0, slot, 0]).status == 0
    };
    let map = |slot: u64, va: u64| syscall(Syscall::FrameMap, slot, [va, 1, 0, 0]).status == 0;
    if !(made(ObjectType::Thread, HELPER)
        && made(ObjectType::Frame, HELPER_STACK)
        && made(ObjectType::Frame, HELPER_STACK + 1)
        && map(HELPER_STACK, HELPER_STACK_VA)
        && map(HELPER_STACK + 1, HELPER_STACK_VA + 0x1000)
        && made(ObjectType::Frame, HELPER_BUFFER)
        && map(HELPER_BUFFER, HELPER_BUFFER_VA)
        && made(ObjectType::Notification, HELPER_DONE))
    {
        return Err("out of memory");
    }
    for (from, to) in [(BLOCK, BLOCK), (HELPER_DONE, H_DONE), (HELPER_BUFFER, BUFFER)] {
        if syscall(Syscall::ThreadCopyCap, HELPER, [from, to, 0xff, 0]).status != 0 {
            return Err("could not give it its capabilities");
        }
    }
    let entry = block_helper as *const () as u64;
    let top = HELPER_STACK_VA + 0x2000;
    let configured = (0..=255u64).rev().any(|prio| {
        syscall(Syscall::ThreadConfigure, HELPER, [entry, top, 0, prio]).status == 0
    });
    if !configured || syscall(Syscall::ThreadResume, HELPER, [0; 4]).status != 0 {
        return Err("could not start it");
    }
    Ok(())
}

// ---- the hot-plug client (`arg 22`, boot/hotplug.manifest) ----

const HOT_PCI: u64 = 0;
const HOT_CONTROL: u64 = 1;
/// The card's IOMMU domain and a page of its registers arrive here.
const HOT_DOMAIN: u64 = 2;
const HOT_BAR: u64 = 3;
const HOT_BAR_VA: u64 = USER_BASE + 0x4000_0000;
/// Ticks to wait for the host to plug the card in, or take it out.
const HOT_WAIT: u64 = 6000;

/// Opens the virtio entropy card (1af4:1044), asking every 50 ms until
/// it is there: the `OPEN` reply and whether a domain came with it.
fn hot_open() -> Option<([u64; 4], bool)> {
    let deadline = ticks() + HOT_WAIT;
    while ticks() < deadline {
        syscall(Syscall::CapDelete, HOT_DOMAIN, [0; 4]);
        let x = CapTransfer {
            grant: None,
            accept: Some(HOT_DOMAIN as u16),
        };
        let r = syscall_x(Syscall::Call, HOT_PCI, [pci::OPEN, pci::VERSION, 0x1af4 << 16 | 0x1044, 0], x);
        if r.status == 0 && r.msg[0] == Status::Ok as u64 {
            return Some((r.msg, r.cap == Some(HOT_DOMAIN as u16)));
        }
        superior_sys::sleep(5);
    }
    None
}

/// Whether the card's registers answer: page 0 of its BAR 4 (virtio's
/// common configuration), whose second feature word has VERSION_1.
fn hot_answers() -> bool {
    syscall(Syscall::CapDelete, HOT_BAR, [0; 4]);
    let x = CapTransfer {
        grant: None,
        accept: Some(HOT_BAR as u16),
    };
    let p = syscall_x(Syscall::Call, HOT_PCI, [pci::BAR_PAGE, 4, 0, 0], x);
    p.status == 0
        && p.msg[0] == Status::Ok as u64
        && p.cap == Some(HOT_BAR as u16)
        && syscall(Syscall::FrameMap, HOT_BAR, [HOT_BAR_VA, 1, 0, 0]).status == 0
        // SAFETY: the page is mapped; these are two of its registers.
        && unsafe {
            (HOT_BAR_VA as *mut u32).write_volatile(1);
            ((HOT_BAR_VA + 4) as *const u32).read_volatile() & 1 == 1
        }
}

fn hotplug_client() -> ! {
    let mut t = Checks(0, "hotplug");
    let place = |m: [u64; 4]| (m[1] >> 8, m[1] >> 3 & 0x1f, m[1] & 7);
    let first = hot_open();
    let (m, domain) = first.unwrap_or(([0; 4], false));
    let (bus, dev, func) = place(m);
    t.check(
        first.is_some() && bus != 0 && domain && hot_answers(),
        format_args!(
            "a card plugged in while running ({bus:02x}:{dev:02x}.{func}) opens with an IOMMU domain of its own, and its registers answer"
        ),
    );
    // Taken out: the bus server no longer knows this client as an owner.
    // (The registers are not touched again: their page is being revoked.)
    let deadline = ticks() + HOT_WAIT;
    let mut gone = false;
    while !gone && ticks() < deadline {
        let r = syscall(Syscall::Call, HOT_PCI, [pci::CONFIG_READ, 0, 0, 0]);
        gone = r.status == 0 && r.msg[0] == Status::Denied as u64;
        if !gone {
            superior_sys::sleep(5);
        }
    }
    // What it held is gone with the card: the page cannot be mapped
    // again, the domain answers nothing, and there is no card to open.
    let page_gone = syscall(Syscall::FrameMap, HOT_BAR, [HOT_BAR_VA + 0x1000, 1, 0, 0]).status != 0;
    let domain_gone = syscall(Syscall::IoFaults, HOT_DOMAIN, [0; 4]).status != 0;
    let r = syscall(Syscall::Call, HOT_PCI, [pci::OPEN, pci::VERSION, 0x1af4 << 16 | 0x1044, 0]);
    t.check(
        gone && page_gone && domain_gone && r.status == 0 && r.msg[0] == Status::NotFound as u64,
        format_args!(
            "taken out: the page of its registers and its domain are revoked, and there is no card to open"
        ),
    );
    let second = hot_open();
    let (m, domain) = second.unwrap_or(([0; 4], false));
    let (bus, dev, func) = place(m);
    t.check(
        second.is_some() && domain && hot_answers(),
        format_args!("a card plugged in again ({bus:02x}:{dev:02x}.{func}) opens and answers like the first"),
    );
    syscall(Syscall::Call, HOT_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// The block client, for the disk driver whose device is opened by `open`
/// (the bus server's `OPEN` or `OPEN_CLASS` call).
/// Where an IOMMU domain would arrive with the bridged device's `OPEN`.
const BRIDGED_DOMAIN: u64 = 40;
/// A BAR page of a device behind a bridge, and where it is mapped.
const BRIDGED_BAR: u64 = 41;
const BRIDGED_BAR_VA: u64 = USER_BASE + 0x4a00_0000;

/// Takes page 0 of memory BAR `bar` of the device this client has open
/// and maps it at `BRIDGED_BAR_VA`.
fn bridged_bar(bar: u64) -> bool {
    syscall(Syscall::CapDelete, BRIDGED_BAR, [0; 4]);
    let x = CapTransfer {
        grant: None,
        accept: Some(BRIDGED_BAR as u16),
    };
    let p = syscall_x(Syscall::Call, BLOCK_PCI, [pci::BAR_PAGE, bar, 0, 0], x);
    p.status == 0
        && p.msg[0] == Status::Ok as u64
        && p.cap == Some(BRIDGED_BAR as u16)
        && syscall(Syscall::FrameMap, BRIDGED_BAR, [BRIDGED_BAR_VA, 1, 0, 0]).status == 0
}

fn block_client(open: [u64; 4]) -> ! {
    let mut t = Checks(0, "block");
    let r = syscall(Syscall::Call, BLOCK, [block::INFO, block::VERSION, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == 0 && r.msg[1] == 128 && r.msg[2] == 512,
        format_args!("{} sectors of {} bytes", r.msg[1], r.msg[2]),
    );
    let units = r.msg[3];
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
    // A second unit (NVMe's second namespace, AHCI's second port) is a disk of its own: its
    // own size, its own data, its own bounds.
    if units > 1 {
        let r = syscall(Syscall::Call, BLOCK, [block::INFO, block::VERSION, 1, 0]);
        t.check(
            r.status == 0 && r.msg[0] == 0 && r.msg[1] == 64 && r.msg[3] == units,
            format_args!("unit 1 of {units}: {} sectors of {} bytes", r.msg[1], r.msg[2]),
        );
        for (sector, count) in [(0, 8), (60, 4)] {
            let r = read_unit(1, sector, count, BUFFER_VA, disk2_word);
            t.check(
                r.is_ok(),
                format_args!(
                    "read {count} sectors from {sector} of unit 1: {}",
                    r.err().unwrap_or("its own data, every word right")
                ),
            );
        }
        let lend = CapTransfer {
            grant: Some(BUFFER as u16),
            accept: None,
        };
        let past = syscall_x(Syscall::Call, BLOCK, [block::READ, 64, 1, 1], lend);
        let none = syscall(Syscall::Call, BLOCK, [block::INFO, block::VERSION, units, 0]);
        t.check(
            past.msg[0] == Status::Invalid as u64 && none.msg[0] == Status::NotFound as u64,
            format_args!("unit 1 ends at its own size, and there is no unit {units}"),
        );
    }
    // Two threads reading at once; the NVMe driver serves them on two
    // queues, each with its own thread and vector, the AHCI driver on two
    // command slots (NCQ tags), each with its own thread.
    let helper = start_helper();
    let mut failed = 0;
    if helper.is_ok() {
        failed = (0..ROUNDS)
            .filter(|&i| read_and_check((i * 8 + 64) % 128, 8).is_err())
            .count() as u64;
        syscall(Syscall::Wait, HELPER_DONE, [0; 4]);
        syscall(Syscall::ThreadSuspend, HELPER, [0; 4]);
    }
    let helper_failed = HELPER_FAILED.load(Ordering::SeqCst);
    t.check(
        helper.is_ok() && failed == 0 && helper_failed == 0,
        format_args!(
            "two threads read {ROUNDS} times each at once: {}",
            match helper {
                Err(e) => e,
                Ok(()) if failed + helper_failed == 0 => "every word right",
                Ok(()) => "some reads went WRONG",
            }
        ),
    );
    let r = syscall(Syscall::Call, BLOCK, [OP_QUEUES, 0, 0, 0]);
    if r.status == 0 && r.msg[0] == Status::Ok as u64 {
        let (queues, peak, used) = (r.msg[1], r.msg[2], r.msg[3]);
        t.check(
            queues >= 2 && used == (1 << queues) - 1 && peak >= 2,
            format_args!(
                "the driver used all {queues} of its queues, with up to {peak} commands in flight at once"
            ),
        );
    }
    // Exactly one driver per device: the bus server refuses the client the
    // driver's, asked for the way the driver asked (a virtio disk by its
    // IDs, an NVMe or AHCI controller by its class).
    let r = syscall(Syscall::Call, BLOCK_PCI, open);
    t.check(
        r.status == 0 && r.msg[0] == Status::InUse as u64,
        format_args!("the bus server will not give it the driver's device"),
    );
    let r = syscall(Syscall::Call, BLOCK_PCI, [pci::BAR_PAGE, 4, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Denied as u64,
        format_args!("nor any BAR page"),
    );
    // The NVMe test's machine has a device behind a conventional bridge
    // (a virtio entropy source at 0b:01.0: nine empty root ports come
    // before the NVMe controller's, so the buses are numbered past the
    // eight the kernel's tables once reached). Its DMA would carry the
    // bridge's requester ID, so no IOMMU domain could hold it alone: the
    // bus server opens it without one and refuses it bus mastering.
    if open[0] == pci::OPEN_CLASS && open[2] == 0x01_08_02 {
        let x = CapTransfer {
            grant: None,
            accept: Some(BRIDGED_DOMAIN as u16),
        };
        let r = syscall_x(
            Syscall::Call,
            BLOCK_PCI,
            [pci::OPEN, pci::VERSION, 0x1af4 << 16 | 0x1044, 0],
            x,
        );
        let master = syscall(Syscall::Call, BLOCK_PCI, [pci::BUS_MASTER, 1, 0, 0]);
        t.check(
            r.status == 0
                && r.msg[0] == Status::Ok as u64
                && r.msg[1] == 0xb << 8 | 1 << 3
                && r.cap.is_none()
                && master.status == 0
                && master.msg[0] == Status::Denied as u64,
            format_args!(
                "the device behind the conventional bridge ({:02x}:{:02x}.{}) opens with no IOMMU domain, and may not master the bus",
                r.msg[1] >> 8,
                r.msg[1] >> 3 & 0x1f,
                r.msg[1] & 7
            ),
        );
        let ok = Status::Ok as u64;
        // Its BAR 4 is prefetchable memory, which the bridge passes
        // through its prefetchable window: virtio's common configuration
        // is there, and its second feature word has VERSION_1 (bit 0).
        let version_1 = bridged_bar(4) && {
            // SAFETY: the BAR's first page is mapped; these are two of
            // its registers.
            unsafe {
                (BRIDGED_BAR_VA as *mut u32).write_volatile(1);
                ((BRIDGED_BAR_VA + 4) as *const u32).read_volatile() & 1 == 1
            }
        };
        syscall(Syscall::CapDelete, BRIDGED_BAR, [0; 4]);
        let closed = syscall(Syscall::Call, BLOCK_PCI, [pci::CLOSE, 0, 0, 0]);
        t.check(
            version_1 && closed.status == 0 && closed.msg[0] == ok,
            format_args!(
                "its prefetchable BAR answers through the bridge's prefetchable window; then it is given back"
            ),
        );
        // An RTL-8139 behind another root port has its registers twice:
        // in an I/O BAR (0), reached through the port's I/O window and
        // only by way of the bus server, and in a memory BAR (1).
        syscall(Syscall::CapDelete, BRIDGED_DOMAIN, [0; 4]);
        let r = syscall_x(
            Syscall::Call,
            BLOCK_PCI,
            [pci::OPEN, pci::VERSION, 0x10ec << 16 | 0x8139, 0],
            x,
        );
        let opened = r.status == 0 && r.msg[0] == ok && r.msg[3] & 1 == 1 && r.msg[2] & 2 == 2;
        let io = |m: [u64; 4]| {
            let r = syscall(Syscall::Call, BLOCK_PCI, m);
            (r.status == 0 && r.msg[0] == ok).then_some(r.msg[1])
        };
        let mapped = opened && bridged_bar(1);
        // SAFETY: the BAR's page is mapped while `mapped`; offsets are
        // inside its 256 bytes of registers.
        let mmio = |off: u64| unsafe { ((BRIDGED_BAR_VA + off) as *const u8).read_volatile() };
        let mut mac = [0u8; 6];
        let mut same = mapped;
        for (i, b) in mac.iter_mut().enumerate() {
            *b = io([pci::IO_READ, 0, i as u64, 1]).unwrap_or(0xee) as u8;
            same &= mapped && *b == mmio(i as u64);
        }
        // The multicast filter's bytes hold what is written: one written
        // through each BAR, read through the other.
        let crossed = mapped
            && io([pci::IO_WRITE, 1 << 8, 8, 0xa5]).is_some()
            && mmio(8) == 0xa5
            && {
                // SAFETY: as above.
                unsafe { ((BRIDGED_BAR_VA + 9) as *mut u8).write_volatile(0x5a) };
                io([pci::IO_READ, 0, 9, 1]) == Some(0x5a)
            };
        // Nothing past the BAR's 256 ports, and no ports for a memory BAR.
        let past = syscall(Syscall::Call, BLOCK_PCI, [pci::IO_READ, 0, 256, 1]);
        let memory = syscall(Syscall::Call, BLOCK_PCI, [pci::IO_READ, 1, 0, 1]);
        let kept_in = past.status == 0
            && past.msg[0] == Status::Invalid as u64
            && memory.status == 0
            && memory.msg[0] == Status::NotFound as u64;
        syscall(Syscall::CapDelete, BRIDGED_BAR, [0; 4]);
        syscall(Syscall::Call, BLOCK_PCI, [pci::CLOSE, 0, 0, 0]);
        t.check(
            // QEMU's MAC addresses: 52:54:00:12:34 and the card's number.
            same && mac[..5] == [0x52, 0x54, 0x00, 0x12, 0x34] && crossed && kept_in,
            format_args!(
                "the RTL-8139 behind a root port ({:02x}:{:02x}.{}): MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} by its I/O BAR and its memory BAR alike; writes cross over; no port past the BAR",
                r.msg[1] >> 8,
                r.msg[1] >> 3 & 0x1f,
                r.msg[1] & 7,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            ),
        );
    }
    // The x86-64 virtio-blk test's DMAR puts a virtio entropy source
    // (00:11.0) under a second VT-d unit that is not there, as a laptop's
    // graphics are under a unit of their own: the kernel cannot drive that
    // unit, so it will not bind the function, and the bus server opens it
    // with no IOMMU domain and refuses it bus mastering, as for a device
    // behind a conventional bridge. Its registers still answer.
    if cfg!(target_arch = "x86_64") && open[0] == pci::OPEN && open[2] == 0x1af4 << 16 | 0x1042 {
        let x = CapTransfer {
            grant: None,
            accept: Some(BRIDGED_DOMAIN as u16),
        };
        let r = syscall_x(Syscall::Call, BLOCK_PCI, [pci::OPEN, pci::VERSION, 0x1af4 << 16 | 0x1044, 0], x);
        let master = syscall(Syscall::Call, BLOCK_PCI, [pci::BUS_MASTER, 1, 0, 0]);
        let answers = r.status == 0 && r.msg[0] == Status::Ok as u64 && bridged_bar(4) && {
            // SAFETY: the BAR's first page is mapped; virtio's common
            // configuration is there, and its second feature word has
            // VERSION_1 (bit 0).
            unsafe {
                (BRIDGED_BAR_VA as *mut u32).write_volatile(1);
                ((BRIDGED_BAR_VA + 4) as *const u32).read_volatile() & 1 == 1
            }
        };
        syscall(Syscall::CapDelete, BRIDGED_BAR, [0; 4]);
        syscall(Syscall::Call, BLOCK_PCI, [pci::CLOSE, 0, 0, 0]);
        t.check(
            r.status == 0
                && r.msg[0] == Status::Ok as u64
                && r.msg[1] == 0x11 << 3
                && r.cap.is_none()
                && master.status == 0
                && master.msg[0] == Status::Denied as u64
                && answers,
            format_args!(
                "the device under a VT-d unit the kernel cannot drive ({:02x}:{:02x}.{}) opens with no IOMMU domain and may not master the bus; its registers answer",
                r.msg[1] >> 8,
                r.msg[1] >> 3 & 0x1f,
                r.msg[1] & 7
            ),
        );
    }
    // The device can reach only what its driver maps into its IOMMU
    // domain: aimed at another page of the driver's, the DMA must not land,
    // and the IOMMU must report the blocked write to the driver.
    let r = syscall(Syscall::Call, BLOCK, [0x57a7, 0, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Ok as u64 && r.msg[1] == 1,
        format_args!(
            "DMA aimed outside the device's IOMMU domain did not land and was reported (request {})",
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
        format_args!("the driver crashed under a call (PeerRestarted; status {})", r.status),
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
    superior_sys::park()
}

// The memory tests' slots and layout.
const MEM: u64 = 0;
const MEM_CONTROL: u64 = 1;
const MEM_STATE: u64 = 1;
const FRAMES: u64 = 2;
const HEAP: u64 = USER_BASE + mem::HEAP_OFFSET;
const FRAME_VA: u64 = USER_BASE + 0x4000_0000;
const STATE_VA: u64 = USER_BASE + 0x5000_0000;
/// The memory client's heap and quota (`boot/memory.manifest`).
const CLIENT_HEAP: u64 = 32;
const CLIENT_QUOTA: u64 = 40;
/// The big client's heap (and quota): far more than the Memory Server's
/// own block of 512 pages, so it comes out of the spare RAM it was given.
const BIG_HEAP: u64 = 4096;
/// The big client's service, which the memory client calls last
/// (`boot/memory.manifest`): in the client, and in the big client.
const BIG_CLIENT: u64 = 12;
const BIG_SERVICE: u64 = 2;
/// The hog's quota, and how many heap pages it touches the first time.
const HOG_QUOTA: u64 = 8;
const HOG_TOUCH: u64 = 12;
/// A notification nobody signals, for the hog to block on.
const HOG_IDLE: u64 = 2;

fn info() -> [u64; 4] {
    let r = syscall(Syscall::Call, MEM, [mem::INFO, mem::VERSION, 0, 0]);
    if r.status == 0 { r.msg } else { [u64::MAX; 4] }
}

/// Word `k` of heap page `p`, as written by the tests.
fn heap_word(p: u64, k: u64) -> u64 {
    0x4845_4150_0000_0000 | p << 16 | k
}

/// Touches heap page `p` (it pages in on the first access): checks it
/// arrived zeroed, then fills it. Returns whether it was zero.
fn touch(p: u64) -> bool {
    // SAFETY: the heap is ours; a page appears on first touch.
    let page = unsafe { core::slice::from_raw_parts_mut((HEAP + p * 4096) as *mut u64, 512) };
    let zero = page.iter().all(|&w| w == 0);
    for (k, w) in page.iter_mut().enumerate() {
        *w = heap_word(p, k as u64);
    }
    zero
}

fn memory_client() -> ! {
    let mut t = Checks(0, "memory");
    // Let the hog (higher priority) run its course first.
    superior_sys::sleep(50);
    let r = info();
    t.check(
        r[0] == 0 && r[1] == CLIENT_QUOTA && r[2] == 0,
        format_args!("quota {} pages, {} in use", r[1], r[2]),
    );
    let free_before = r[3];
    let zeroed = (0..CLIENT_HEAP).all(touch);
    t.check(
        zeroed,
        format_args!("{CLIENT_HEAP} heap pages appeared on first touch, each zeroed"),
    );
    let intact = (0..CLIENT_HEAP).all(|p| {
        // SAFETY: as in `touch`; every page is mapped now.
        let page = unsafe { core::slice::from_raw_parts((HEAP + p * 4096) as *const u64, 512) };
        page.iter()
            .enumerate()
            .all(|(k, &w)| w == heap_word(p, k as u64))
    });
    t.check(intact, format_args!("and kept what was written"));
    let r = info();
    t.check(
        r[2] == CLIENT_HEAP && r[3] == free_before - CLIENT_HEAP,
        format_args!(
            "{} pages charged to it; the pool has {} fewer",
            r[2],
            free_before - r[3]
        ),
    );
    // Frames up to the quota, then one more.
    let mut handles = [0u64; 8];
    let room = CLIENT_QUOTA - CLIENT_HEAP;
    let mut got = 0;
    for n in 0..room {
        let x = CapTransfer {
            grant: None,
            accept: Some((FRAMES + n) as u16),
        };
        let r = syscall_x(Syscall::Call, MEM, [mem::FRAME, 0, 0, 0], x);
        if r.status == 0 && r.msg[0] == Status::Ok as u64 && r.cap == Some((FRAMES + n) as u16) {
            handles[n as usize] = r.msg[1];
            got += 1;
        }
    }
    t.check(
        got == room,
        format_args!("{got} frames granted, filling the quota"),
    );
    let r = syscall(Syscall::Call, MEM, [mem::FRAME, 0, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Denied as u64,
        format_args!("one more is refused: the quota is spent"),
    );
    // A granted frame is a page like any other; giving it back takes the
    // capability (and the mapping) away.
    let mapped = syscall(Syscall::FrameMap, FRAMES, [FRAME_VA, 1, 0, 0]).status == 0;
    // SAFETY: just mapped, writable.
    let zero = mapped && unsafe { (FRAME_VA as *const u64).read_volatile() } == 0;
    let r = syscall(Syscall::Call, MEM, [mem::FREE, handles[0], 0, 0]);
    let gone = syscall(Syscall::FrameMap, FRAMES, [FRAME_VA + 4096, 1, 0, 0]).status != 0;
    t.check(
        zero && r.msg[0] == Status::Ok as u64 && gone,
        format_args!("a granted frame arrives zeroed; freed, its capability is gone"),
    );
    let r = info();
    t.check(
        r[2] == CLIENT_QUOTA - 1,
        format_args!("{} pages in use after freeing one", r[2]),
    );
    let x = CapTransfer {
        grant: None,
        accept: Some(FRAMES as u16),
    };
    let r = syscall_x(Syscall::Call, MEM, [mem::FRAME, 0, 0, 0], x);
    t.check(
        r.msg[0] == Status::Ok as u64,
        format_args!("so another frame is granted"),
    );
    // Only the manager may page in or release.
    let r = syscall(Syscall::Call, MEM, [mem::RELEASE, 3, 0, 0]);
    t.check(
        r.msg[0] == Status::Denied as u64,
        format_args!("a component may not release another's pages"),
    );
    clone_parent(&mut t);
    // Last, the big client: started by this call, it answers once it has
    // paged in its whole heap.
    let r = syscall(Syscall::Call, BIG_CLIENT, [0; 4]);
    t.check(
        r.status == 0 && r.msg[0] == 0 && r.msg[1] == BIG_HEAP,
        format_args!("the big client paged in {} heap pages, all from spare RAM", r.msg[1]),
    );
    syscall(Syscall::Call, MEM_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// Started (lazily) by the memory client's call: pages in a heap of
/// [`BIG_HEAP`] pages, more than the Memory Server's own block and more
/// than its CSpace once had slots for, so it must come from the spare
/// RAM the kernel handed over. Answers with its failures and its heap,
/// then exits (its pages go back).
fn big() -> ! {
    let call = syscall(Syscall::Recv, BIG_SERVICE, [0; 4]);
    let mut t = Checks(0, "big");
    let r = info();
    t.check(
        r[0] == 0 && r[1] == BIG_HEAP && r[3] >= 4 * BIG_HEAP,
        format_args!(
            "the pool holds {} pages ({} MiB), far more than the server's own 512",
            r[3],
            r[3] * 4096 >> 20
        ),
    );
    let free_before = r[3];
    let zeroed = (0..BIG_HEAP).all(touch);
    t.check(
        zeroed,
        format_args!("{BIG_HEAP} heap pages ({} MiB) appeared on first touch, each zeroed", BIG_HEAP * 4096 >> 20),
    );
    let intact = (0..BIG_HEAP).all(|p| {
        // SAFETY: as in `touch`; every page is mapped now.
        let page = unsafe { core::slice::from_raw_parts((HEAP + p * 4096) as *const u64, 512) };
        page.iter()
            .enumerate()
            .all(|(k, &w)| w == heap_word(p, k as u64))
    });
    t.check(intact, format_args!("and kept what was written"));
    let r = info();
    t.check(
        r[2] == BIG_HEAP && r[3] == free_before - BIG_HEAP,
        format_args!("{} pages charged to it; the pool has {} fewer", r[2], free_before - r[3]),
    );
    let pages = if call.status == 0 { BIG_HEAP } else { 0 };
    syscall(Syscall::Reply, 0, [t.0, pages, 0, 0]);
    syscall(Syscall::Call, MEM_CONTROL, [OP_EXIT, t.0, 0, 0]);
    superior_sys::park()
}

/// `[OP_CLONE, component]`: start that component with a copy-on-write
/// copy of this one's heap. `[OP_EXIT]`: stop this component for good.
const OP_CLONE: u64 = 4;
const OP_EXIT: u64 = 5;
/// The `clone` component's index in `boot/memory.manifest`.
const CLONE_INDEX: u64 = 3;
/// What the client writes to heap page 0 after cloning, and the clone to
/// page 1.
const PARENT_MARK: u64 = 0x5041_5245_4e54_0000;
const CLONE_MARK: u64 = 0x434c_4f4e_4500_0000;

fn heap_page(p: u64) -> &'static mut [u64] {
    // SAFETY: the heap is this component's; every page is mapped (or
    // faults in) on touch.
    unsafe { core::slice::from_raw_parts_mut((HEAP + p * 4096) as *mut u64, 512) }
}

/// Every heap page from `from` holds what [`touch`] wrote.
fn heap_intact(from: u64) -> bool {
    (from..CLIENT_HEAP).all(|p| {
        heap_page(p)
            .iter()
            .enumerate()
            .all(|(k, &w)| w == heap_word(p, k as u64))
    })
}

/// The memory client clones itself into `clone`, then writes to its own
/// heap: neither sees the other's writes, and once the clone is gone the
/// pool is back where it was.
fn clone_parent(t: &mut Checks) {
    let before = info();
    let r = syscall(Syscall::Call, MEM_CONTROL, [OP_CLONE, CLONE_INDEX, 0, 0]);
    let after = info();
    // (The pool may already be a page down: the clone can run, and
    // write, on another CPU before this.)
    t.check(
        r.status == 0 && r.msg[0] == Status::Ok as u64 && after[2] == before[2],
        format_args!("cloned into clone, still {} pages charged to it", after[2]),
    );
    let mark = heap_page(0);
    mark.iter_mut().for_each(|w| *w = PARENT_MARK);
    t.check(
        mark.iter().all(|&w| w == PARENT_MARK) && info()[2] == before[2],
        format_args!("its write to shared page 0 is its own, at no extra charge"),
    );
    // Breaking the sharing took a page until the clone lets go of its
    // copies: then the pool is exactly as before.
    let start = superior_sys::ticks();
    while info()[3] != before[3] && superior_sys::ticks() - start < 500 {
        superior_sys::sleep(1);
    }
    let end = info();
    t.check(
        end[3] == before[3] && end[2] == before[2],
        format_args!("the clone exited and the pool is back to {} free", end[3]),
    );
    t.check(
        heap_page(0).iter().all(|&w| w == PARENT_MARK) && heap_intact(1),
        format_args!("the clone's write to page 1 never reached the client"),
    );
}

/// The reboot client (`boot/reboot.manifest`): memory in slot 0, control
/// in slot 1, its state page in slot 2. Its state page records which boot
/// it is on and a pattern, and the failures so far.
const REBOOT_STATE: u64 = 2;
const OP_CRASH_MANAGER: u64 = 6;
const MEMSERVER_INDEX: u64 = 0;
const REBOOT_HEAP: u64 = 4;

fn reboot_word(k: u64) -> u64 {
    0x5245_424f_4f54_0000 | k
}

/// Boot 0 writes its state and has the Memory Server killed; boot 1 (after
/// that fast reboot) checks the state and crashes the Component Manager;
/// boot 2 (after the second) checks it again and shuts down.
fn reboot_client() -> ! {
    let mut t = Checks(0, "reboot");
    let mapped = syscall(Syscall::FrameMap, REBOOT_STATE, [STATE_VA, 1, 0, 0]).status == 0;
    // SAFETY: the state page is mapped at STATE_VA (checked below).
    let state = unsafe { core::slice::from_raw_parts_mut(STATE_VA as *mut u64, 512) };
    if !mapped {
        t.check(false, format_args!("its state page is mapped"));
        syscall(Syscall::Call, MEM_CONTROL, [OP_SHUTDOWN, 1, 0, 0]);
        superior_sys::park()
    }
    let boot = state[0];
    t.0 = state[511];
    // The Memory Server serves this boot: heap pages arrive, zeroed.
    let zeroed = (0..REBOOT_HEAP).all(|p| {
        let page = heap_page(p);
        let z = page.iter().all(|&w| w == 0);
        page[0] = boot + 1;
        z && page[0] == boot + 1
    });
    t.check(
        zeroed,
        format_args!("boot {boot}: {REBOOT_HEAP} heap pages from the Memory Server, zeroed"),
    );
    let kept = state[1..64].iter().enumerate().all(|(k, &w)| w == reboot_word(k as u64));
    match boot {
        0 => {
            state[1..64]
                .iter_mut()
                .enumerate()
                .for_each(|(k, w)| *w = reboot_word(k as u64));
            state[0] = 1;
            state[511] = t.0;
            say!("reboot: state written; killing the Memory Server");
            syscall(Syscall::Call, MEM_CONTROL, [OP_KILL, MEMSERVER_INDEX, 0, 0]);
        }
        1 => {
            t.check(
                kept,
                format_args!("after the Memory Server failed, the state store kept what was written"),
            );
            state[0] = 2;
            state[511] = t.0;
            say!("reboot: crashing the Component Manager");
            syscall(Syscall::Call, MEM_CONTROL, [OP_CRASH_MANAGER, 0, 0, 0]);
        }
        _ => {
            t.check(
                boot == 2 && kept,
                format_args!("after the Component Manager failed, the state store kept it too"),
            );
            syscall(Syscall::Call, MEM_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
        }
    }
    superior_sys::park()
}

/// The clone of the memory client: it starts with the client's heap.
fn clone_child() -> ! {
    let mut t = Checks(0, "clone");
    let r = info();
    t.check(
        r[0] == 0 && r[1] == CLIENT_QUOTA && r[2] == CLIENT_HEAP,
        format_args!("{} heap pages charged to it, quota {}", r[2], r[1]),
    );
    // Page 0 too, whether or not the client has written to it yet.
    t.check(
        heap_intact(0),
        format_args!("every page reads as the client wrote it before the clone"),
    );
    let page = heap_page(1);
    page.iter_mut().for_each(|w| *w = CLONE_MARK);
    t.check(
        page.iter().all(|&w| w == CLONE_MARK) && heap_intact(2) && info()[2] == CLIENT_HEAP,
        format_args!("its write to page 1 stays its own, at no extra charge"),
    );
    say!("clone: done ({} failed)", t.0);
    syscall(Syscall::Call, MEM_CONTROL, [OP_EXIT, t.0, 0, 0]);
    superior_sys::park()
}

fn hog() -> ! {
    let mapped = syscall(Syscall::FrameMap, MEM_STATE, [STATE_VA, 1, 0, 0]).status == 0;
    // SAFETY: the state page is mapped at STATE_VA.
    let instance = if mapped {
        let count = STATE_VA as *mut u64;
        unsafe {
            let n = count.read_volatile() + 1;
            count.write_volatile(n);
            n
        }
    } else {
        0
    };
    if instance == 1 {
        say!("hog: touching {HOG_TOUCH} heap pages with a quota of {HOG_QUOTA}");
        for p in 0..HOG_TOUCH {
            touch(p);
        }
        say!("[fail] hog: touched more heap than its quota");
    } else {
        let mut t = Checks(0, "hog");
        let r = info();
        t.check(
            r[0] == 0 && r[2] == 0,
            format_args!(
                "restarted (instance {instance}) holding {} pages: all came back",
                r[2]
            ),
        );
        let zeroed = (0..HOG_QUOTA).all(touch);
        t.check(
            zeroed,
            format_args!("{HOG_QUOTA} heap pages again, every one zeroed though reused"),
        );
        say!("hog: done ({} failed)", t.0);
    }
    // Out of the way of the (lower-priority) client: block for good.
    loop {
        syscall(Syscall::Wait, HOG_IDLE, [0; 4]);
    }
}

// The file tests' slots and layout.
const FS: u64 = 0;
const FS_CONTROL: u64 = 1;
const FS_MEMORY: u64 = 2;
const FS_BUFFER: u64 = 4;
const FS_BUFFER_VA: u64 = USER_BASE + 0x4000_0000;
/// Records appended under load; one more goes in just before the power
/// cut.
const RECORDS: u64 = 400;
const RECORD: u64 = 64;
/// Component numbers in `boot/fs.manifest` (manifest order).
const DRIVER_INDEX: u64 = 1;
const FS_INDEX: u64 = 2;
const OP_KILL: u64 = 3;

/// Word `j` of record `k`.
fn record_word(k: u64, j: u64) -> u64 {
    0x5245_434f_0000_0000 | k << 8 | j
}

/// A call to the filesystem server lending the buffer, retried while the
/// server (or the driver under it) is restarted. Returns the reply and
/// how many times it was retried.
fn fs_call(m: [u64; 4], lend: bool) -> ([u64; 4], u64) {
    let x = CapTransfer {
        grant: lend.then_some(FS_BUFFER as u16),
        accept: None,
    };
    for tries in 0..50 {
        let r = syscall_x(Syscall::Call, FS, m, x);
        if r.status == 0 {
            return (r.msg, tries);
        }
        if r.status != Error::PeerRestarted.code() {
            break;
        }
        // A tick for the server to come back (and mount) before the
        // next try, so the tries outlast a slow restart.
        superior_sys::sleep(1);
    }
    ([u64::MAX; 4], 50)
}

fn fs_buffer() -> &'static mut [u64] {
    // SAFETY: the buffer frame is mapped at FS_BUFFER_VA.
    unsafe { core::slice::from_raw_parts_mut(FS_BUFFER_VA as *mut u64, 512) }
}

fn fs_setup(memory: u64) -> bool {
    syscall(
        Syscall::Retype,
        memory,
        [ObjectType::Frame as u64, 0, FS_BUFFER, 0],
    )
    .status
        == 0
        && syscall(Syscall::FrameMap, FS_BUFFER, [FS_BUFFER_VA, 1, 0, 0]).status == 0
}

fn fs_bytes() -> &'static mut [u8] {
    // SAFETY: the buffer frame is mapped at FS_BUFFER_VA.
    unsafe { core::slice::from_raw_parts_mut(FS_BUFFER_VA as *mut u8, 4096) }
}

const OK: u64 = Status::Ok as u64;

/// A call naming `path` (in the buffer): `[op, path length, extra]`.
fn fs_path(op: u64, path: &str, extra: u64) -> ([u64; 4], u64) {
    let len = fs::put_path(fs_bytes(), path).unwrap();
    fs_call([op, len, extra, 0], true)
}

/// `[status, handle, size, kind]`.
fn fs_open(path: &str, flags: u64) -> [u64; 4] {
    fs_path(fs::OPEN, path, flags).0
}

/// A status, where a retried `UNLINK` or `RENAME` answering `NotFound`
/// had already happened before the restart cut it off.
fn done(r: ([u64; 4], u64)) -> u64 {
    match r {
        (m, tries) if tries > 0 && m[0] == Status::NotFound as u64 => OK,
        (m, _) => m[0],
    }
}

fn fs_rename(from: &str, to: &str) -> u64 {
    let b = fs_bytes();
    let l1 = fs::put_path(b, from).unwrap();
    let l2 = fs::put_path(&mut b[l1 as usize..], to).unwrap();
    done(fs_call([fs::RENAME, l1, l2, 0], true))
}

/// Makes a symbolic link at `path` to `target`.
fn fs_symlink(path: &str, target: &str) -> u64 {
    let b = fs_bytes();
    let l1 = fs::put_path(b, path).unwrap();
    let l2 = fs::put_path(&mut b[l1 as usize..], target).unwrap();
    fs_call([fs::SYMLINK, l1, l2, 0], true).0[0]
}

/// Whether the link at `path` holds `target`; or the status.
fn fs_readlink(path: &str, target: &str) -> Result<bool, u64> {
    let (r, _) = fs_path(fs::READLINK, path, 0);
    match r[0] {
        OK => Ok(&fs_bytes()[..r[1] as usize] == target.as_bytes()),
        s => Err(s),
    }
}

fn fs_unlink(path: &str) -> u64 {
    done(fs_path(fs::UNLINK, path, 0))
}

fn fs_statfs() -> [u64; 4] {
    fs_call([fs::STATFS, 0, 0, 0], false).0
}

/// Appends record `k`. Returns whether it was acknowledged, and retries.
fn append(h: u64, k: u64) -> (bool, u64) {
    let b = fs_buffer();
    for j in 0..RECORD / 8 {
        b[j as usize] = record_word(k, j);
    }
    let (r, tries) = fs_call([fs::WRITE, h, k * RECORD, RECORD], true);
    (r[0] == OK, tries)
}

/// The first record that did not read back right, and how.
enum Wrong {
    /// The read failed with this status (`u64::MAX`: retries ran out).
    Read(u64, u64),
    /// Record, word, what was there.
    Word(u64, u64, u64),
}

impl core::fmt::Display for Wrong {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Wrong::Read(k, s) => write!(f, "{k}: the read failed, status {s:#x}"),
            Wrong::Word(k, j, w) => write!(
                f,
                "{k}: word {j} is {w:#x}, not {:#x}",
                record_word(k, j)
            ),
        }
    }
}

/// Checks records `0..n` of the file read back right. Returns the first
/// wrong one.
fn check_records(h: u64, n: u64) -> Result<(), Wrong> {
    let per_block = fs::BLOCK / RECORD;
    let mut k = 0;
    while k < n {
        let (r, _) = fs_call([fs::READ, h, k * RECORD, fs::BLOCK], true);
        if r[0] != OK {
            return Err(Wrong::Read(k, r[0]));
        }
        let b = fs_buffer();
        for i in 0..per_block.min(n - k) {
            let rec = k + i;
            for j in 0..RECORD / 8 {
                let w = b[(i * RECORD / 8 + j) as usize];
                if w != record_word(rec, j) {
                    return Err(Wrong::Word(rec, j, w));
                }
            }
        }
        k += per_block;
    }
    Ok(())
}

/// The big file's byte at `p`.
fn big_byte(p: u64) -> u8 {
    ((p % 251) ^ (p / 4096 * 17)) as u8
}

/// Bytes of the big file; written in unaligned 4000-byte pieces, so most
/// writes span two blocks, and through the indirect block.
const BIG: u64 = 70 * 4000;
const PIECE: u64 = 4000;

fn write_big(h: u64) -> bool {
    let mut off = 0;
    while off < BIG {
        let b = fs_bytes();
        for i in 0..PIECE {
            b[i as usize] = big_byte(off + i);
        }
        if fs_call([fs::WRITE, h, off, PIECE], true).0[0] != OK {
            return false;
        }
        off += PIECE;
    }
    true
}

/// Checks bytes `[from, to)` of the big file, read in unaligned pieces:
/// `big_byte`, except zero in `[zero_from, zero_to)`.
fn check_big(h: u64, from: u64, to: u64, zero_from: u64, zero_to: u64) -> Result<(), u64> {
    let mut off = from;
    while off < to {
        let want = (to - off).min(3001);
        let (r, _) = fs_call([fs::READ, h, off, want], true);
        if r[0] != OK || r[1] != want {
            return Err(off);
        }
        let b = fs_bytes();
        for i in 0..want {
            let p = off + i;
            let expect = if (zero_from..zero_to).contains(&p) {
                0
            } else {
                big_byte(p)
            };
            if b[i as usize] != expect {
                return Err(p);
            }
        }
        off += want;
    }
    Ok(())
}

/// Writes bytes `off..off + len` of the big file's pattern (`len` at
/// most a block) at `off` of `h`; whether it was acknowledged.
fn put_big(h: u64, off: u64, len: u64) -> bool {
    let b = fs_bytes();
    for i in 0..len {
        b[i as usize] = big_byte(off + i);
    }
    fs_call([fs::WRITE, h, off, len], true).0[0] == OK
}

/// A sparse file past 4 MiB, through the double indirect block: pieces
/// written across the step from the indirect block to the double one, in
/// its first indirect block and in a later one, the holes between read as
/// zeros; cut back, written again, and its blocks all come back when it
/// goes.
fn huge_file(t: &mut Checks) {
    // Block 1033 is the double indirect block's first.
    const STEP: u64 = (9 + 1024) * 4096;
    let pieces = [(STEP - 2000, 4096), (4_300_000, 4096), (9_000_000, 4096)];
    let before = fs_statfs();
    let h = fs_open("huge", fs::CREATE | fs::TRUNC)[1];
    let wrote = pieces.iter().all(|&(off, len)| put_big(h, off, len));
    let size = fs_call([fs::STAT, h, 0, 0], false).0[1];
    let during = fs_statfs();
    let read = pieces.iter().all(|&(off, len)| check_big(h, off, off + len, 0, 0).is_ok());
    // Holes: before the first piece, between pieces, in a missing
    // indirect block.
    let holes = [(STEP - 6000, STEP - 2000), (STEP + 2096, STEP + 9000), (6_000_000, 6_004_000)];
    let zeros = holes.iter().all(|&(a, b)| check_big(h, a, b, a, b).is_ok());
    // Six data blocks, the indirect block, the double one and two of its
    // indirect blocks.
    t.check(
        wrote && size == 9_004_096 && read && zeros && before[1] - during[1] == 10,
        format_args!(
            "a sparse {size}-byte file through the double indirect block: every piece reads back, the holes read as zeros, {} blocks used",
            before[1] - during[1]
        ),
    );
    // Cut into the double indirect range, then write past the end again.
    let cut = fs_call([fs::TRUNCATE, h, 4_300_100, 0], false).0[0];
    let again = put_big(h, 9_000_000, 4096);
    let read = check_big(h, 4_300_000, 4_300_100, 0, 0).is_ok()
        && check_big(h, 4_300_100, 4_304_096, 4_300_100, 4_304_096).is_ok()
        && check_big(h, 9_000_000, 9_004_096, 0, 0).is_ok();
    let gone = fs_unlink("huge");
    let after = fs_statfs();
    t.check(
        cut == OK && again && read && gone == OK && after[1] == before[1] && after[2] == before[2],
        format_args!("cut to 4300100 bytes and written past the end again; unlinked, every block came back"),
    );
}

/// Files made in one directory: past the 511 inodes there once were.
const MANY_FILES: usize = 600;

/// Lists directory `h`: how many entries, and whether each of `names`
/// is among them.
fn list(h: u64, names: &[&str]) -> (u64, bool) {
    let (mut total, mut found) = (0, 0u64);
    let mut cookie = 0;
    loop {
        let (r, _) = fs_call([fs::READDIR, h, cookie, 0], true);
        if r[0] != OK || r[1] == 0 {
            break;
        }
        let b = fs_bytes();
        for i in 0..r[1] as usize {
            let e = fs::Entry(&b[i * fs::ENTRY..(i + 1) * fs::ENTRY]);
            for (k, n) in names.iter().enumerate() {
                if e.name() == n.as_bytes() {
                    found |= 1 << k;
                }
            }
        }
        total += r[1];
        cookie = r[2];
    }
    (total, found == (1u64 << names.len()) - 1)
}

/// Symbolic links, under fault injection; `links/` stays for the second
/// boot (`fs_verify`).
fn symlink_checks(t: &mut Checks) {
    fs_path(fs::MKDIR, "links", 0);
    fs_path(fs::MKDIR, "links/dir", 0);
    let target = fs_open("links/dir/target", fs::CREATE)[1];
    let b = fs_bytes();
    b[..10].copy_from_slice(b"link data!");
    fs_call([fs::WRITE, target, 0, 10], true);
    let made = [
        ("links/to-file", "dir/target"),
        ("links/to-dir", "dir"),
        ("links/abs", "/links/dir/target"),
        ("links/up", "../links/./dir/target"),
        ("links/escape", "../../../../../links/dir/target"),
        ("links/chain", "to-dir/../to-file"),
        ("links/loop1", "loop2"),
        ("links/loop2", "loop1"),
        ("links/dangling", "dir/made-through-a-link"),
    ]
    .iter()
    .all(|(p, to)| fs_symlink(p, to) == OK);
    // Each leads to the same file.
    let opened = ["links/to-file", "links/to-dir/target", "links/abs", "links/up", "links/chain"]
        .iter()
        .all(|p| {
            let r = fs_open(p, 0);
            r[0] == OK && r[1] == target && r[2] == 10
        });
    t.check(
        made && opened,
        format_args!("9 symbolic links made; relative, absolute, through a directory, with .. and chained, each opens links/dir/target"),
    );
    // `..` in a target stops at the container's root: no way out.
    let escape = fs_open("links/escape", 0);
    t.check(
        escape[0] == OK && escape[1] == target,
        format_args!("a target climbing past the root stays in the container"),
    );
    let looped = fs_open("links/loop1", 0)[0];
    let nofollow = fs_open("links/to-file", fs::NOFOLLOW)[0];
    let excl = fs_open("links/to-file", fs::CREATE | fs::EXCL)[0];
    t.check(
        looped == Status::TooManyLinks as u64
            && nofollow == Status::TooManyLinks as u64
            && excl == Status::Exists as u64,
        format_args!("a loop of links and NOFOLLOW answer TooManyLinks; an exclusive create finds the name taken"),
    );
    let read = fs_readlink("links/to-file", "dir/target");
    let not_link = fs_readlink("links/dir/target", "");
    let again = fs_symlink("links/to-file", "dir/target");
    let taken = fs_symlink("links/to-file", "elsewhere");
    let over_file = fs_symlink("links/dir/target", "x");
    let mkdir_on = fs_path(fs::MKDIR, "links/to-dir", 0).0[0];
    t.check(
        read == Ok(true)
            && not_link == Err(Status::Invalid as u64)
            && again == OK
            && taken == Status::Exists as u64
            && over_file == Status::Exists as u64
            && mkdir_on == Status::Exists as u64,
        format_args!("READLINK gives the target (and refuses a file); a name taken is refused, the same link again is not"),
    );
    // Creating through a dangling link makes its target.
    let created = fs_open("links/dangling", fs::CREATE);
    let there = fs_open("links/dir/made-through-a-link", 0);
    t.check(
        created[0] == OK && there[0] == OK && there[1] == created[1],
        format_args!("creating through a dangling link makes links/dir/made-through-a-link"),
    );
    // Unlink and rename act on the link, not what it names.
    let gone = fs_unlink("links/to-dir");
    let still = fs_open("links/dir/target", 0)[1];
    let link_gone = fs_open("links/to-dir/target", 0)[0];
    let moved = fs_rename("links/abs", "links/abs2");
    let renamed = fs_readlink("links/abs2", "/links/dir/target");
    let links = fs_open("links", fs::DIRECTORY)[1];
    let mut kinds_right = false;
    let (r, _) = fs_call([fs::READDIR, links, 0, 0], true);
    if r[0] == OK {
        let b = fs_bytes();
        kinds_right = (0..r[1] as usize).all(|i| {
            let e = fs::Entry(&b[i * fs::ENTRY..(i + 1) * fs::ENTRY]);
            let want = if e.name() == b"dir" { fs::KIND_DIR } else { fs::KIND_LINK };
            e.kind() == want
        }) && r[1] == 9;
    }
    t.check(
        gone == OK
            && still == target
            && link_gone == Status::NotFound as u64
            && moved == OK
            && renamed == Ok(true)
            && kinds_right,
        format_args!("unlinking a link leaves its target; a renamed link keeps its target; links list as links"),
    );
    // The loops and the dangling one go; the rest stay for the next boot.
    for p in ["links/loop1", "links/loop2", "links/dangling", "links/escape"] {
        fs_unlink(p);
    }
}

/// The file client under fault injection (`arg 7`).
fn fs_client() -> ! {
    let mut t = Checks(0, "fs");
    t.check(
        fs_setup(FS_MEMORY),
        format_args!("a buffer page of its own"),
    );
    let made = fs_path(fs::MKDIR, "logs", 0).0[0];
    let r = fs_open("/logs/app.log", fs::CREATE | fs::TRUNC);
    t.check(
        made == OK && r[0] == OK && r[2] == 0 && r[3] == fs::KIND_FILE,
        format_args!("created an empty logs/app.log"),
    );
    let h = r[1];
    let (mut acked, mut retried) = (0, 0);
    for k in 0..RECORDS {
        let (ok, tries) = append(h, k);
        retried += tries;
        if !ok {
            break;
        }
        acked += 1;
    }
    t.check(
        acked == RECORDS,
        format_args!(
            "{acked} records written under fault injection ({retried} calls cut off by a restart and retried)"
        ),
    );
    match check_records(h, acked) {
        Ok(()) => t.check(true, format_args!("every acknowledged record reads back")),
        Err(w) => t.check(false, format_args!("every acknowledged record reads back (first wrong: {w})")),
    }
    let (r, _) = fs_call([fs::STAT, h, 0, 0], false);
    t.check(
        r[1] == acked * RECORD,
        format_args!("the file is {} bytes", r[1]),
    );

    // A file past the direct blocks, written in pieces spanning blocks.
    fs_path(fs::MKDIR, "data", 0);
    let big = fs_open("data/big", fs::CREATE | fs::TRUNC)[1];
    let wrote = write_big(big);
    let c = check_big(big, 0, BIG, BIG, BIG);
    t.check(
        wrote && c.is_ok(),
        format_args!(
            "a {BIG}-byte file (through its indirect block) reads back (first wrong byte: {})",
            c.err().map_or(-1, |k| k as i64)
        ),
    );
    // Truncate, then write past the end: the gap reads as zero.
    let cut = fs_call([fs::TRUNCATE, big, 10_000, 0], false).0[0];
    let b = fs_bytes();
    for i in 0..4u64 {
        b[i as usize] = big_byte(20_000 + i);
    }
    let w = fs_call([fs::WRITE, big, 20_000, 4], true).0[0];
    let size = fs_call([fs::STAT, big, 0, 0], false).0[1];
    let c = check_big(big, 0, 20_004, 10_000, 20_000);
    t.check(
        cut == OK && w == OK && size == 20_004 && c.is_ok(),
        format_args!("truncated to 10000 and written at 20000: {size} bytes, zeros between"),
    );

    // Blocks come back when a file goes, and its handle stays dead.
    let before = fs_statfs();
    let tmp = fs_open("tmp", fs::CREATE)[1];
    let mut off = 0;
    while off < 50_000 {
        fs_call([fs::WRITE, tmp, off, 4096], true);
        off += 4096;
    }
    let during = fs_statfs();
    let gone = fs_unlink("tmp");
    let after = fs_statfs();
    fs_open("tmp2", fs::CREATE);
    let stale = fs_call([fs::STAT, tmp, 0, 0], false).0[0];
    t.check(
        gone == OK
            && during[1] + 14 == before[1]
            && after[1] == before[1]
            && after[2] == before[2]
            && stale == Status::NotFound as u64,
        format_args!(
            "unlinking a 53248-byte file returned its {} blocks; its handle is dead",
            before[1] - during[1]
        ),
    );
    fs_unlink("tmp2");
    huge_file(&mut t);

    // The tree.
    for d in ["a", "a/b", "a/b/c"] {
        fs_path(fs::MKDIR, d, 0);
    }
    let f = fs_open("a/b/c/f", fs::CREATE)[1];
    fs_call([fs::WRITE, f, 0, 100], true);
    let excl = fs_open("a/b/c/f", fs::CREATE | fs::EXCL)[0];
    let through = fs_open("a/b/c/f/x", 0)[0];
    let missing = fs_open("a/nope/f", fs::CREATE)[0];
    let dotdot = fs_open("a/../a", 0)[0];
    t.check(
        excl == Status::Exists as u64
            && through == Status::NotDir as u64
            && missing == Status::NotFound as u64
            && dotdot == Status::Invalid as u64,
        format_args!(
            "a/b/c/f: exclusive create refused, no path through a file, no missing parent, no .."
        ),
    );
    let mv = fs_rename("a/b/c/f", "a/g");
    let old = fs_open("a/b/c/f", 0)[0];
    let new = fs_open("a/g", 0);
    let into = fs_rename("a", "a/b/a2");
    t.check(
        mv == OK
            && old == Status::NotFound as u64
            && new[0] == OK
            && new[1] == f
            && new[2] == 100
            && into == Status::Invalid as u64,
        format_args!("renamed a/b/c/f to a/g (the same file); a cannot move into itself"),
    );
    let full = fs_unlink("a/b");
    let a = fs_open("a", fs::DIRECTORY)[1];
    let (n1, both) = list(a, &["b", "g"]);
    let rm = (fs_unlink("a/b/c"), fs_unlink("a/b"));
    let (n2, only_g) = list(a, &["g"]);
    t.check(
        full == Status::NotEmpty as u64 && n1 == 2 && both && rm == (OK, OK) && n2 == 1 && only_g,
        format_args!("a non-empty directory stays; a lists b and g, then g alone"),
    );
    // A directory past its direct blocks of entries, with more files
    // than the 511 inodes there once were.
    fs_path(fs::MKDIR, "many", 0);
    let free = fs_statfs()[2];
    let mut names = [[0u8; 9]; MANY_FILES];
    let mut made = 0;
    for (i, n) in names.iter_mut().enumerate() {
        *n = *b"many/f000";
        n[6] = b'0' + (i / 100) as u8;
        n[7] = b'0' + (i / 10 % 10) as u8;
        n[8] = b'0' + (i % 10) as u8;
        let p = core::str::from_utf8(n).unwrap_or("");
        made += (fs_open(p, fs::CREATE)[0] == OK) as u64;
    }
    let used = free - fs_statfs()[2];
    let many = fs_open("many", fs::DIRECTORY)[1];
    let (listed, ends) = list(many, &["f000", "f599"]);
    let mut removed = 0;
    for n in &names {
        removed += (fs_unlink(core::str::from_utf8(n).unwrap_or("")) == OK) as u64;
    }
    let (n0, _) = list(many, &[]);
    let n = MANY_FILES as u64;
    t.check(
        made == n && used == n && listed == n && ends && removed == n && n0 == 0 && fs_statfs()[2] == free,
        format_args!("{n} files in one directory (ten blocks of entries, through its indirect block) listed, then removed, every inode back"),
    );
    symlink_checks(&mut t);

    // The same kind of work through a ring, still under fault injection.
    ring_phase(&mut t);

    // One more record, then a rename, both acknowledged; then the machine
    // stops at once: the rename never goes home before the power cut.
    let (ok, _) = append(h, RECORDS);
    let mv = fs_rename("a/g", "g2");
    t.check(
        ok && mv == OK,
        format_args!("record {RECORDS} and a rename of a/g to g2 acknowledged; cutting the power"),
    );
    syscall(Syscall::Call, FS_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

// ---- the ring client (`fs::ring`) ----

/// The ring's pages (`shared 16 16` in the manifest), mapped at RING_VA.
const RING_SHARED: u64 = 16;
/// Where the completion notification and the doorbell arrive.
const RING_COMPL: u64 = 40;
const RING_BELL: u64 = 41;
const RING_VA: u64 = USER_BASE + 0x6000_0000;
/// Requests in flight, each with a 4 KiB buffer of the data pages.
const DEPTH: usize = ring::DATA_PAGES as usize;

fn rhdr(off: usize) -> &'static AtomicU32 {
    // SAFETY: the ring page is mapped at RING_VA for good.
    unsafe { &*((RING_VA + off as u64) as *const AtomicU32) }
}

/// Data buffer `t` (4 KiB) of the ring.
fn rbuf(t: usize) -> &'static mut [u8] {
    // SAFETY: the data pages follow the ring page, mapped for good.
    unsafe { core::slice::from_raw_parts_mut((RING_VA + 4096 + 4096 * t as u64) as *mut u8, 4096) }
}

struct Ring {
    /// The server's endpoint, and its attach, start and doorbell
    /// operations (the filesystem's or the network server's).
    server: u64,
    ops: [u64; 3],
    sq_tail: u32,
    cq_head: u32,
    /// Each tag's request, while in flight: `[op, a, b, c]`.
    inflight: [Option<[u64; 4]>; DEPTH],
    /// System calls the ring itself cost: doorbells and sleeps.
    doorbells: u64,
    waits: u64,
    /// Times the server was restarted under it and it set up again.
    reconnects: u64,
}

impl Ring {
    /// Maps the shared pages and sets the ring up with the server.
    fn new() -> Option<Ring> {
        Ring::with(FS, [fs::RING_ATTACH, fs::RING_START, fs::RING_DOORBELL])
    }

    fn with(server: u64, ops: [u64; 3]) -> Option<Ring> {
        for p in 0..ring::PAGES {
            let va = RING_VA + 4096 * p;
            if syscall(Syscall::FrameMap, RING_SHARED + p, [va, 1, 0, 0]).status != 0 {
                return None;
            }
        }
        let mut r = Ring {
            server,
            ops,
            sq_tail: 0,
            cq_head: 0,
            inflight: [None; DEPTH],
            doorbells: 0,
            waits: 0,
            reconnects: 0,
        };
        r.register().then_some(r)
    }

    /// Attaches the pages, starts the ring and takes the doorbell; tried
    /// again from the start if the server is restarted meanwhile.
    fn register(&mut self) -> bool {
        'again: for _ in 0..50 {
            for s in [RING_COMPL, RING_BELL] {
                syscall(Syscall::CapDelete, s, [0; 4]);
            }
            for p in 0..ring::PAGES {
                let x = CapTransfer {
                    grant: Some((RING_SHARED + p) as u16),
                    accept: None,
                };
                let r = syscall_x(Syscall::Call, self.server, [self.ops[0], p, 0, 0], x);
                if r.status != 0 || r.msg[0] != OK {
                    continue 'again;
                }
            }
            for (op, slot) in [(self.ops[1], RING_COMPL), (self.ops[2], RING_BELL)] {
                let x = CapTransfer {
                    grant: None,
                    accept: Some(slot as u16),
                };
                let r = syscall_x(Syscall::Call, self.server, [op, 0, 0, 0], x);
                if r.status != 0 || r.msg[0] != OK || r.cap != Some(slot as u16) {
                    superior_sys::sleep(1);
                    continue 'again;
                }
            }
            // The server cleared the header.
            self.sq_tail = 0;
            self.cq_head = 0;
            return true;
        }
        false
    }

    fn free_tag(&self) -> Option<usize> {
        self.inflight.iter().position(|x| x.is_none())
    }

    /// Puts request `m` (data in buffer `tag`) in the submission queue.
    fn push(&mut self, tag: usize, m: [u64; 4]) {
        let sqe = RING_VA as usize + ring::SQ + (self.sq_tail % ring::ENTRIES) as usize * ring::SQE;
        let words = [m[0], tag as u64, m[1], m[2], m[3], tag as u64 * 4096];
        for (i, w) in words.iter().enumerate() {
            // SAFETY: inside the ring page.
            unsafe { ((sqe + 8 * i) as *mut u64).write_volatile(*w) };
        }
        self.sq_tail = self.sq_tail.wrapping_add(1);
        rhdr(ring::SQ_TAIL).store(self.sq_tail, Ordering::Release);
    }

    fn submit(&mut self, tag: usize, m: [u64; 4]) {
        self.inflight[tag] = Some(m);
        self.push(tag, m);
    }

    /// Rings the doorbell if the server said it sleeps. False if the
    /// server is gone (restarted).
    fn kick(&mut self) -> bool {
        fence(Ordering::SeqCst);
        if rhdr(ring::FLAGS).load(Ordering::Relaxed) & ring::NEED_WAKEUP == 0 {
            return true;
        }
        self.doorbells += 1;
        syscall(Syscall::Signal, RING_BELL, [0; 4]).status == 0
    }

    /// The next completion: `(tag, [status, r1, r2, r3])`.
    fn reap(&mut self) -> Option<(usize, [u64; 4])> {
        if rhdr(ring::CQ_TAIL).load(Ordering::Acquire) == self.cq_head {
            return None;
        }
        let cqe = RING_VA as usize + ring::CQ + (self.cq_head % ring::ENTRIES) as usize * ring::CQE;
        // SAFETY: inside the ring page.
        let w = |i: usize| unsafe { ((cqe + 8 * i) as *const u64).read_volatile() };
        let (tag, r) = (w(0) as usize, [w(1), w(2), w(3), w(4)]);
        self.cq_head = self.cq_head.wrapping_add(1);
        rhdr(ring::CQ_HEAD).store(self.cq_head, Ordering::Release);
        if tag >= DEPTH || self.inflight[tag].take().is_none() {
            return self.reap(); // a duplicate after a resubmission
        }
        Some((tag, r))
    }

    /// Sleeps until a completion is posted. False if the server is gone.
    fn wait(&mut self) -> bool {
        // Wake when half of what is in flight is done: the queue refills
        // while the server still has work, so it need not sleep.
        let inflight = self.inflight.iter().filter(|x| x.is_some()).count() as u32;
        let want = (inflight / 2).max(1);
        rhdr(ring::CLIENT_WAITING).store(want, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        let pending = rhdr(ring::CQ_TAIL)
            .load(Ordering::Acquire)
            .wrapping_sub(self.cq_head);
        if pending >= want {
            rhdr(ring::CLIENT_WAITING).store(0, Ordering::Relaxed);
            return true;
        }
        self.waits += 1;
        let ok = syscall(Syscall::Wait, RING_COMPL, [0; 4]).status == 0;
        rhdr(ring::CLIENT_WAITING).store(0, Ordering::Relaxed);
        ok
    }

    /// The server was restarted: set up again and submit what had no
    /// completion (every operation is idempotent).
    fn reconnect(&mut self) -> bool {
        self.reconnects += 1;
        if !self.register() {
            return false;
        }
        for t in 0..DEPTH {
            if let Some(m) = self.inflight[t] {
                self.push(t, m);
            }
        }
        true
    }

    /// Has everything in flight answered: `done(tag, reply, buffer)` for
    /// each. False if the server is gone (restarted).
    fn settle(&mut self, mut done: impl FnMut(usize, [u64; 4], &[u8])) -> bool {
        loop {
            if !self.kick() {
                return false;
            }
            while let Some((t, r)) = self.reap() {
                done(t, r, rbuf(t));
            }
            if self.inflight.iter().all(|x| x.is_none()) {
                return true;
            }
            if !self.wait() {
                return false;
            }
        }
    }

    /// Runs requests `0..n`, `DEPTH` in flight: `make(i, buffer)` fills
    /// the buffer and gives the request, `done(i, reply, buffer)` checks
    /// the reply. Returns how many replies were right.
    fn run(
        &mut self,
        n: u64,
        mut make: impl FnMut(u64, &mut [u8]) -> [u64; 4],
        mut done: impl FnMut(u64, [u64; 4], &[u8]) -> bool,
    ) -> u64 {
        let mut which = [0u64; DEPTH];
        let (mut next, mut finished, mut right) = (0, 0, 0);
        while finished < n {
            while next < n {
                let Some(t) = self.free_tag() else { break };
                which[t] = next;
                let m = make(next, rbuf(t));
                self.submit(t, m);
                next += 1;
            }
            let mut alive = self.kick();
            let mut got = false;
            while let Some((t, r)) = self.reap() {
                right += done(which[t], r, rbuf(t)) as u64;
                finished += 1;
                got = true;
            }
            if alive && !got {
                alive = self.wait();
            }
            if !alive && !self.reconnect() {
                return right;
            }
        }
        right
    }
}

/// Byte `j` of the ring log's record `k` (1 KiB records).
fn ring_byte(k: u64, j: u64) -> u8 {
    (k.wrapping_mul(131) ^ j.wrapping_mul(7) ^ (j >> 8)) as u8
}

const RING_RECORDS: u64 = 300;
const RING_RECORD: u64 = 1024;

/// The ring phase of the file test: opens a file, writes records and
/// reads them back, all through the ring, under fault injection.
fn ring_phase(t: &mut Checks) {
    let Some(mut r) = Ring::new() else {
        t.check(false, format_args!("ring: set up"));
        return;
    };
    let mut handle = 0;
    let opened = r.run(
        1,
        |_, b| {
            let len = fs::put_path(b, "ring.log").unwrap();
            [fs::OPEN, len, fs::CREATE | fs::TRUNC, 0]
        },
        |_, rep, _| {
            handle = rep[1];
            rep[0] == OK
        },
    );
    let h = handle;
    let wrote = r.run(
        RING_RECORDS,
        |k, b| {
            for j in 0..RING_RECORD {
                b[j as usize] = ring_byte(k, j);
            }
            [fs::WRITE, h, k * RING_RECORD, RING_RECORD]
        },
        |_, rep, _| rep[0] == OK,
    );
    let blocks = RING_RECORDS * RING_RECORD / fs::BLOCK;
    let per = fs::BLOCK / RING_RECORD;
    let read = r.run(
        blocks,
        |i, _| [fs::READ, h, i * fs::BLOCK, fs::BLOCK],
        |i, rep, b| {
            rep[0] == OK
                && rep[1] == fs::BLOCK
                && (0..fs::BLOCK).all(|p| {
                    let (k, j) = (i * per + p / RING_RECORD, p % RING_RECORD);
                    b[p as usize] == ring_byte(k, j)
                })
        },
    );
    let ios = 1 + RING_RECORDS + blocks;
    let calls = r.doorbells + r.waits;
    t.check(
        opened == 1 && wrote == RING_RECORDS && read == blocks,
        format_args!(
            "ring: {ios} requests, {DEPTH} in flight, every write acknowledged and read back"
        ),
    );
    say!(
        "fs: ring: {calls} system calls for {ios} requests under fault injection ({} doorbells, {} sleeps; set up again {} times after a restart)",
        r.doorbells,
        r.waits,
        r.reconnects
    );
}

/// Reads the ring log back through a ring, with no faults injected: what
/// the ring costs in system calls in the steady state.
fn ring_steady(t: &mut Checks, h: u64) {
    let Some(mut r) = Ring::new() else {
        t.check(false, format_args!("ring: set up"));
        return;
    };
    let per = fs::BLOCK / RING_RECORD;
    let blocks = RING_RECORDS * RING_RECORD / fs::BLOCK;
    let n = 4 * blocks;
    let right = r.run(
        n,
        |i, _| [fs::READ, h, i % blocks * fs::BLOCK, fs::BLOCK],
        |i, rep, b| {
            let i = i % blocks;
            rep[0] == OK
                && (0..fs::BLOCK)
                    .all(|p| b[p as usize] == ring_byte(i * per + p / RING_RECORD, p % RING_RECORD))
        },
    );
    let calls = r.doorbells + r.waits;
    // Each sleep asks to be woken with half of the queue done, so on one
    // CPU a quarter as many calls as reads. On several the server runs
    // beside the client and, out of work, wakes it early to refill: a few
    // more. Calls one by one would be one per read.
    t.check(
        right == n && calls * 3 <= n,
        format_args!(
            "ring, no faults: {n} reads with {calls} system calls ({} doorbells, {} sleeps)",
            r.doorbells, r.waits
        ),
    );
}

/// The file client after the power cut (`arg 8`).
fn fs_verify() -> ! {
    let mut t = Checks(0, "fs");
    t.check(
        fs_setup(FS_MEMORY),
        format_args!("a buffer page of its own"),
    );
    let r = fs_open("logs/app.log", 0);
    let n = RECORDS + 1;
    t.check(
        r[0] == OK && r[2] == n * RECORD,
        format_args!("after the power cut logs/app.log is {} bytes", r[2]),
    );
    match check_records(r[1], n) {
        Ok(()) => t.check(true, format_args!("all {n} acknowledged records survived")),
        Err(w) => t.check(false, format_args!("all {n} acknowledged records survived (first wrong: {w})")),
    }
    let g2 = fs_open("g2", 0);
    let ag = fs_open("a/g", 0)[0];
    let root = fs_open("/", fs::DIRECTORY);
    let (count, all) = list(root[1], &["logs", "data", "a", "many", "g2", "ring.log", "links"]);
    t.check(
        g2[0] == OK && g2[2] == 100 && ag == Status::NotFound as u64 && count == 7 && all,
        format_args!(
            "the last rename survived: g2 is there, a/g is not; the root lists {count} entries"
        ),
    );
    let to_file = fs_open("links/to-file", 0);
    let target = fs_open("links/dir/target", 0)[1];
    let up = fs_open("links/up", 0)[1] == target;
    // chain went through to-dir, which the first boot unlinked.
    let dangling = fs_open("links/chain", 0)[0] == Status::NotFound as u64;
    let abs2 = fs_readlink("links/abs2", "/links/dir/target");
    let gone = fs_open("links/loop1", fs::NOFOLLOW)[0];
    t.check(
        to_file[0] == OK
            && to_file[1] == target
            && to_file[2] == 10
            && up
            && dangling
            && abs2 == Ok(true)
            && gone == Status::NotFound as u64,
        format_args!("symbolic links survived the power cut: links/to-file and up open links/dir/target, chain dangles (to-dir is gone), abs2 reads back, the removed loop is gone"),
    );
    let log = fs_open("ring.log", 0);
    let per = fs::BLOCK / RING_RECORD;
    let mut right = 0;
    for i in 0..RING_RECORDS / per {
        let (r, _) = fs_call([fs::READ, log[1], i * fs::BLOCK, fs::BLOCK], true);
        let b = fs_bytes();
        right += (r[0] == OK
            && (0..fs::BLOCK)
                .all(|p| b[p as usize] == ring_byte(i * per + p / RING_RECORD, p % RING_RECORD)))
            as u64;
    }
    t.check(
        log[0] == OK && log[2] == RING_RECORDS * RING_RECORD && right == RING_RECORDS / per,
        format_args!("ring.log survived: {} bytes", log[2]),
    );
    ring_steady(&mut t, log[1]);
    let big = fs_open("data/big", 0);
    let c = check_big(big[1], 0, 20_004, 10_000, 20_000);
    t.check(
        big[0] == OK && big[2] == 20_004 && c.is_ok(),
        format_args!("data/big survived: {} bytes", big[2]),
    );
    syscall(Syscall::Call, FS_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// Records each load client writes.
const LOAD_RECORDS: u64 = 120;

/// A load client (`arg 21`, boot/fs.manifest): appends records to a file
/// in its own container while the others (and the main client) do the
/// same, so the server has calls from several clients waiting at once
/// to answer with one commit; then reads every one back.
fn fs_load() -> ! {
    let mut t = Checks(0, "fs load");
    let ready = fs_setup(1);
    let r = fs_open("load.log", fs::CREATE | fs::TRUNC);
    let (mut acked, mut retried) = (0, 0);
    if ready && r[0] == OK {
        while acked < LOAD_RECORDS {
            let (ok, tries) = append(r[1], acked);
            retried += tries;
            if !ok {
                break;
            }
            acked += 1;
        }
    }
    let back = acked > 0 && check_records(r[1], acked).is_ok();
    t.check(
        acked == LOAD_RECORDS && back,
        format_args!(
            "{acked} records written alongside the other clients, every one read back ({retried} calls cut off by a restart and retried)"
        ),
    );
    superior_sys::park()
}

/// Another component (`arg 9`): its own container.
fn fs_other() -> ! {
    let mut t = Checks(0, "fs other");
    t.check(fs_setup(1), format_args!("a buffer page of its own"));
    let theirs = fs_open("logs/app.log", 0)[0];
    let root = fs_open("", 0)[0];
    t.check(
        theirs == Status::NotFound as u64 && root == Status::NotFound as u64,
        format_args!("another component's logs/app.log is not in its container, which is empty"),
    );
    fs_path(fs::MKDIR, "logs", 0);
    let r = fs_open("logs/app.log", fs::CREATE);
    let (ok, _) = append(r[1], 7);
    let (st, _) = fs_call([fs::STAT, r[1], 0, 0], false);
    let root = fs_open("", fs::DIRECTORY)[1];
    let (count, logs) = list(root, &["logs"]);
    t.check(
        r[0] == OK && ok && st[1] == 8 * RECORD && count == 1 && logs,
        format_args!("its own logs/app.log is a separate file, alone in its tree"),
    );
    loop {
        syscall(Syscall::Wait, 2, [0; 4]);
    }
}

/// Kills `targets` (component numbers) in turn, at pseudo-random moments
/// 30 to 150 ms apart; with `pauses`, every eighth gap is 0.5 s longer.
fn injector(targets: &[u64], pauses: bool) -> ! {
    // A fixed seed: the moments vary with timing, not between runs.
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    // Let the client get going first.
    superior_sys::sleep(10);
    // Until the client cuts the power: through every phase of its test.
    for n in 0.. {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let wait = 3 + seed % 12 + if pauses && n % 8 == 7 { 50 } else { 0 };
        superior_sys::sleep(wait);
        let target = targets[n % targets.len()];
        syscall(Syscall::Call, 0, [OP_KILL, target, 0, 0]);
    }
    unreachable!()
}

// ---- the network client (`arg 13`, boot/net.manifest and
// boot/lde.manifest) ----

const NET: u64 = 0;
const NET_CONTROL: u64 = 1;
const NET_MEMORY: u64 = 2;
/// The socket's notification arrives here.
const NET_NTFN: u64 = 3;
const NET_PAGE: u64 = 4;
const NET_PAGE_VA: u64 = USER_BASE + 0x4000_0000;
/// QEMU's user-mode network: the gateway (from DHCP) is the host, and UDP
/// to it reaches the host's loopback, where `cargo xtask net-test` echoes
/// on this port.
const ECHO_PORT: u16 = 47001;
/// Ticks to wait for the server's first DHCP lease.
const LEASE_TICKS: u64 = 1000;
/// At least this many pings and echoes, and for at least this many ticks
/// each, so the injector's kills land throughout.
const PINGS: u64 = 20;
const ECHOES: u64 = 200;
const PING_TICKS: u64 = 200;
const ECHO_TICKS: u64 = 500;
/// Ticks to wait for an answer before sending again.
const NET_TIMEOUT: u64 = 30;
const NET_TRIES: u32 = 50;

/// An address word (as in `net::addr`), printed as its dotted IPv4 address.
struct Dotted(u64);

impl core::fmt::Display for Dotted {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let b = ((self.0 >> 16) as u32).to_be_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

/// Datagrams past a page and up to the largest (`net::MAX_DATAGRAM`),
/// echoed by the host in turn: at least `BIG_ECHOES`, for at least
/// `BIG_TICKS`.
const BIG_SIZES: [u64; 6] = [4097, 9000, 16_384, 33_333, 50_000, net::MAX_DATAGRAM];
const BIG_ECHOES: u64 = 12;
const BIG_TICKS: u64 = 200;

/// The IPv4 address in an address word (`net::addr`), mapped into IPv6.
fn mapped4(word: u64) -> u128 {
    0xffff_0000_0000 | (word >> 16) as u32 as u128
}

/// Datagrams past a page: echoed by the host under fault injection, sent
/// to the socket itself (round the server's loopback, in fragments), and
/// a ping of the largest size to this host, which answers it.
fn big_checks(t: &mut Checks, gw: u64, me: u64) {
    let (mut ok, mut n, mut stats) = (0, 0, (0, 0));
    if let Some(mut s) = Sock::new(true) {
        let start = ticks();
        while n < BIG_ECHOES || ticks() < start + BIG_TICKS {
            let k = n;
            n += 1;
            let len = BIG_SIZES[k as usize % BIG_SIZES.len()];
            ok += s.big_exchange(mapped4(gw), ECHO_PORT, false, len, |j| echo_at(k, j)) as u64;
        }
        stats = (s.resent, s.rebinds);
    }
    t.check(
        ok == n && n >= BIG_ECHOES,
        format_args!(
            "{ok} of {n} UDP datagrams of 4097 to 65507 bytes echoed by the host, every byte right ({} sent again, {} sockets bound again)",
            stats.0, stats.1
        ),
    );
    let mut ok = 0;
    if let Some(mut s) = Sock::new(true) {
        for (k, len) in [(100, 5000), (101, 40_000), (102, net::MAX_DATAGRAM)] {
            ok += s.big_exchange(mapped4(me), 0, true, len, |j| echo_at(k, j)) as u64;
        }
    }
    let mut pinged = false;
    if let Some(mut s) = Sock::new(false) {
        pinged = s.big_exchange(mapped4(me), 7, false, net::MAX_DATAGRAM, |j| echo_at(103, j));
    }
    t.check(
        ok == 3 && pinged,
        format_args!(
            "datagrams of 5000, 40000 and 65507 bytes sent to itself in fragments, and a 65507-byte ping of this host answered, every byte right"
        ),
    );
}

fn net_page() -> &'static mut [u8] {
    // SAFETY: the page is mapped at NET_PAGE_VA for good.
    unsafe { core::slice::from_raw_parts_mut(NET_PAGE_VA as *mut u8, 4096) }
}

/// A call lending the page; `None` if the server was restarted under it.
fn net_call(m: [u64; 4]) -> Option<[u64; 4]> {
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, NET, m, x);
    (r.status == 0).then_some(r.msg)
}

struct Sock {
    udp: bool,
    handle: u64,
    /// Its port (UDP) or echo identifier.
    port: u16,
    /// Bound again after the server lost the socket (it was restarted).
    rebinds: u64,
    /// Requests sent again after no answer came in time.
    resent: u64,
}

impl Sock {
    fn new(udp: bool) -> Option<Sock> {
        let mut s = Sock {
            udp,
            handle: 0,
            port: 0,
            rebinds: 0,
            resent: 0,
        };
        s.bind().then_some(s)
    }

    fn bind(&mut self) -> bool {
        for _ in 0..200 {
            syscall(Syscall::CapDelete, NET_NTFN, [0; 4]);
            let op = if self.udp {
                net::UDP_BIND
            } else {
                net::ICMP_BIND
            };
            let x = CapTransfer {
                grant: None,
                accept: Some(NET_NTFN as u16),
            };
            let r = syscall_x(Syscall::Call, NET, [op, 0, 0, 0], x);
            if r.status == 0 && r.msg[0] == OK && r.cap == Some(NET_NTFN as u16) {
                self.handle = r.msg[1];
                self.port = r.msg[2] as u16;
                return true;
            }
            superior_sys::sleep(1);
        }
        false
    }

    /// Sends `len` bytes of what `fill` writes to `to` and waits for an
    /// answer `matches` accepts, sending again on a timeout and binding
    /// again if the server restarted. False if none came at all.
    fn exchange(
        &mut self,
        to: u64,
        len: u64,
        fill: impl Fn(&mut [u8]),
        matches: impl Fn(u64, &[u8], u64) -> bool,
    ) -> bool {
        let mut tries = 0;
        'send: while tries < NET_TRIES {
            tries += 1;
            if tries > 1 {
                self.resent += 1;
            }
            fill(net_page());
            match net_call([net::SEND, self.handle, to, len]) {
                Some(r) if r[0] == OK => {}
                Some(r) if r[0] == Status::NotFound as u64 => {
                    self.rebind();
                    continue;
                }
                // Restarted under the call, or the driver was.
                _ => {
                    self.rebind_if_lost();
                    continue;
                }
            }
            let deadline = ticks() + NET_TIMEOUT;
            loop {
                // Everything that has arrived.
                loop {
                    match net_call([net::RECV, self.handle, 0, 0]) {
                        Some(r) if r[0] == OK => {
                            if matches(r[1], &net_page()[..r[1] as usize], r[2]) {
                                return true;
                            }
                        }
                        Some(r) if r[0] == Status::Empty as u64 => break,
                        _ => {
                            self.rebind_if_lost();
                            continue 'send;
                        }
                    }
                }
                let now = ticks();
                if now >= deadline {
                    continue 'send;
                }
                syscall(Syscall::TimerSignal, NET_NTFN, [deadline - now, 0, 0, 0]);
                let w = syscall(Syscall::Wait, NET_NTFN, [0; 4]);
                if w.status != 0 {
                    // Its notification is gone: the server restarted.
                    self.rebind();
                    continue 'send;
                }
            }
        }
        false
    }

    /// As `exchange`, over IPv6 (`SEND6` and `RECV6`): to `to`:`port`
    /// (for ICMP echo, `port` is the sequence number; with `to_self`, the
    /// socket's own port, whatever it is after a rebind). `fill` writes
    /// the payload, and `matches` gets an answer's length, payload,
    /// sender and port.
    fn exchange6(
        &mut self,
        to: u128,
        port: u16,
        to_self: bool,
        len: u64,
        fill: impl Fn(&mut [u8]),
        matches: impl Fn(u64, &[u8], u128, u16) -> bool,
    ) -> bool {
        let mut tries = 0;
        'send: while tries < NET_TRIES {
            tries += 1;
            if tries > 1 {
                self.resent += 1;
            }
            let port = if to_self { self.port } else { port };
            net_page()[..16].copy_from_slice(&to.to_be_bytes());
            fill(&mut net_page()[16..]);
            match net_call([net::SEND6, self.handle, port as u64, len]) {
                Some(r) if r[0] == OK => {}
                Some(r) if r[0] == Status::NotFound as u64 => {
                    self.rebind();
                    continue;
                }
                _ => {
                    self.rebind_if_lost();
                    continue;
                }
            }
            let deadline = ticks() + NET_TIMEOUT;
            loop {
                loop {
                    match net_call([net::RECV6, self.handle, 0, 0]) {
                        Some(r) if r[0] == OK => {
                            let p = net_page();
                            if matches(r[1], &p[16..16 + r[1] as usize], page_addr(0), r[2] as u16) {
                                return true;
                            }
                        }
                        Some(r) if r[0] == Status::Empty as u64 => break,
                        _ => {
                            self.rebind_if_lost();
                            continue 'send;
                        }
                    }
                }
                let now = ticks();
                if now >= deadline {
                    continue 'send;
                }
                syscall(Syscall::TimerSignal, NET_NTFN, [deadline - now, 0, 0, 0]);
                if syscall(Syscall::Wait, NET_NTFN, [0; 4]).status != 0 {
                    self.rebind();
                    continue 'send;
                }
            }
        }
        false
    }

    /// Sends a `len`-byte datagram whose byte `j` is `byte(j)` to `to`
    /// (an IPv4 address mapped, or IPv6) port `port` (with `to_self`, the
    /// socket's own; for ICMP echo, the sequence number), and waits for
    /// an answer from `to` with the same bytes. Past what follows the
    /// address on the page, the payload is staged first (`SEND_PART`) and
    /// an answer's rest fetched (`RECV_PART`). Sends again on a timeout,
    /// binds again after a restart; false if no answer came at all.
    fn big_exchange(&mut self, to: u128, port: u16, to_self: bool, len: u64, byte: impl Fn(u64) -> u8) -> bool {
        const ROOM: u64 = 4096 - 16;
        let mut tries = 0;
        'send: while tries < NET_TRIES {
            tries += 1;
            if tries > 1 {
                self.resent += 1;
            }
            let port = if to_self { self.port } else { port };
            if len > ROOM {
                let mut at = 0;
                while at < len {
                    let n = (len - at).min(4096);
                    for j in 0..n {
                        net_page()[j as usize] = byte(at + j);
                    }
                    match net_call([net::SEND_PART, self.handle, at, n]) {
                        Some(r) if r[0] == OK => at += n,
                        Some(r) if r[0] == Status::NotFound as u64 => {
                            self.rebind();
                            continue 'send;
                        }
                        Some(r) if r[0] == Status::NoSpace as u64 => {
                            superior_sys::sleep(1);
                            continue 'send;
                        }
                        _ => {
                            self.rebind_if_lost();
                            continue 'send;
                        }
                    }
                }
            } else {
                for j in 0..len {
                    net_page()[16 + j as usize] = byte(j);
                }
            }
            net_page()[..16].copy_from_slice(&to.to_be_bytes());
            match net_call([net::SEND6, self.handle, port as u64, len]) {
                Some(r) if r[0] == OK => {}
                Some(r) if r[0] == Status::NotFound as u64 => {
                    self.rebind();
                    continue;
                }
                _ => {
                    self.rebind_if_lost();
                    continue;
                }
            }
            let deadline = ticks() + NET_TIMEOUT;
            loop {
                loop {
                    let r = match net_call([net::RECV6, self.handle, 0, 0]) {
                        Some(r) if r[0] == OK => r,
                        Some(r) if r[0] == Status::Empty as u64 => break,
                        _ => {
                            self.rebind_if_lost();
                            continue 'send;
                        }
                    };
                    let n = r[1];
                    let first = n.min(ROOM);
                    let mut right = page_addr(0) == to
                        && n == len
                        && (0..first).all(|j| net_page()[16 + j as usize] == byte(j));
                    // The rest, a page at a time.
                    let mut at = first;
                    while right && at < n {
                        match net_call([net::RECV_PART, self.handle, at, 0]) {
                            Some(p) if p[0] == OK && p[1] > 0 => {
                                right = (0..p[1]).all(|j| net_page()[j as usize] == byte(at + j));
                                at += p[1];
                            }
                            _ => {
                                self.rebind_if_lost();
                                continue 'send;
                            }
                        }
                    }
                    if right {
                        return true;
                    }
                }
                let now = ticks();
                if now >= deadline {
                    continue 'send;
                }
                syscall(Syscall::TimerSignal, NET_NTFN, [deadline - now, 0, 0, 0]);
                if syscall(Syscall::Wait, NET_NTFN, [0; 4]).status != 0 {
                    self.rebind();
                    continue 'send;
                }
            }
        }
        false
    }

    fn rebind(&mut self) {
        self.rebinds += 1;
        self.bind();
    }

    /// Binds again if the server no longer knows the socket.
    fn rebind_if_lost(&mut self) {
        match net_call([net::RECV, self.handle, 0, 0]) {
            Some(r) if r[0] != Status::NotFound as u64 => {}
            _ => self.rebind(),
        }
    }
}

/// Rounds of datagrams through the client's ring, and for at least this
/// many ticks, so the injector's kills land among them.
const RING_ROUNDS: u64 = 100;
const RING_TICKS: u64 = 300;
const RING_BURST: usize = 4;

/// UDP echoes through the client's ring with the network server
/// (`net::ring`): each round submits a burst of datagrams, then asks for
/// what has arrived a burst at a time, sleeping on the socket's
/// notification when there is nothing. No request takes a call. Under
/// fault injection: a restarted server has lost the ring and the socket,
/// and both are set up again.
fn net_ring_checks(t: &mut Checks, gw: u64) {
    let ops = [net::RING_ATTACH, net::RING_START, net::RING_DOORBELL];
    let (Some(mut r), Some(mut s)) = (Ring::with(NET, ops), Sock::new(true)) else {
        t.check(false, format_args!("the client's ring with the network server: set up"));
        return;
    };
    let to = gw | ECHO_PORT as u64;
    let (mut echoed, mut requests, mut resent, mut round) = (0u64, 0u64, 0u64, 0u64);
    let start = ticks();
    // The ring, and the socket if the server lost it, set up again.
    let recover = |r: &mut Ring, s: &mut Sock| {
        r.inflight = [None; DEPTH];
        r.reconnects += 1;
        r.register();
        s.rebind_if_lost();
    };
    while round < RING_ROUNDS || ticks() < start + RING_TICKS {
        let number = |b: usize| 5_000_000 + round * RING_BURST as u64 + b as u64;
        let length = |k: u64| 64 + k * 37 % 1200;
        let mut seen = [false; RING_BURST];
        let mut tries = 0;
        'round: while tries < NET_TRIES {
            tries += 1;
            resent += (tries > 1) as u64;
            for b in (0..RING_BURST).filter(|&b| !seen[b]) {
                let (k, buf) = (number(b), rbuf(b));
                for j in 0..length(k) {
                    buf[j as usize] = echo_at(k, j);
                }
                r.submit(b, [net::SEND, s.handle, to, length(k)]);
                requests += 1;
            }
            let mut sent = true;
            if !r.settle(|_, reply, _| sent &= reply[0] == OK) || !sent {
                recover(&mut r, &mut s);
                continue 'round;
            }
            let deadline = ticks() + NET_TIMEOUT;
            loop {
                for b in 0..RING_BURST {
                    r.submit(RING_BURST + b, [net::RECV, s.handle, 0, 0]);
                    requests += 1;
                }
                let (mut empty, mut lost) = (0, false);
                let alive = r.settle(|_, reply, buf| {
                    if reply[0] == Status::Empty as u64 {
                        empty += 1;
                    } else if reply[0] != OK {
                        lost = true;
                    } else if let Some(b) = (0..RING_BURST).find(|&b| {
                        let k = number(b);
                        reply[1] == length(k)
                            && reply[2] == to
                            && buf[..reply[1] as usize]
                                .iter()
                                .enumerate()
                                .all(|(j, &x)| x == echo_at(k, j as u64))
                    }) {
                        seen[b] = true;
                    }
                });
                if !alive || lost {
                    recover(&mut r, &mut s);
                    continue 'round;
                }
                if seen.iter().all(|&x| x) {
                    break 'round;
                }
                if empty == RING_BURST {
                    // Nothing waiting: sleep on the socket's notification.
                    let now = ticks();
                    if now >= deadline {
                        continue 'round;
                    }
                    syscall(Syscall::TimerSignal, NET_NTFN, [deadline - now, 0, 0, 0]);
                    if syscall(Syscall::Wait, NET_NTFN, [0; 4]).status != 0 {
                        recover(&mut r, &mut s);
                        continue 'round;
                    }
                }
            }
        }
        echoed += seen.iter().filter(|&&x| x).count() as u64;
        round += 1;
    }
    let total = round * RING_BURST as u64;
    t.check(
        echoed == total && requests >= 2 * r.doorbells,
        format_args!(
            "{echoed} of {total} UDP datagrams echoed through the client's ring, every byte right: {requests} requests, {} doorbells, {} sleeps ({resent} rounds again, ring set up {} more times)",
            r.doorbells, r.waits, r.reconnects
        ),
    );
    // The server counts since it started: if the injector has just killed
    // it, one more request through the ring first.
    let mut st = [0; 4];
    for _ in 0..8 {
        st = syscall(Syscall::Call, NET, [net::RING_STATS, net::VERSION, 0, 0]).msg;
        if st[0] == OK && st[1] > 0 {
            break;
        }
        r.submit(0, [net::RECV, s.handle, 0, 0]);
        if !r.settle(|_, _, _| {}) {
            recover(&mut r, &mut s);
        }
    }
    t.check(
        st[0] == OK && st[1] > 0,
        format_args!(
            "the server took {} requests from clients' rings since it last started, woken by {} doorbells",
            st[1], st[2]
        ),
    );
}

// ---- TCP: in the network test, and the TCP test (`arg 18`,
// boot/tcp.manifest) ----

/// The host's TCP echo (`cargo xtask net-test` and `tcp-test`): what a
/// connection sends comes back, and once the client shuts down, the echo
/// closes too.
const TCP_ECHO_PORT: u16 = 47002;
/// A port nothing listens on.
const TCP_CLOSED_PORT: u16 = 47003;
/// The TCP test listens here; the host connects through QEMU's
/// forwarding.
const TCP_LISTEN_PORT: u16 = 8080;
/// Notifications for the TCP test's listening socket and the connections
/// it accepts.
const LISTEN_NTFN: u64 = 6;
const ACCEPTED_NTFN: u64 = 7;
/// TCP echoes under fault injection: at least this many, for at least
/// this long, and no longer than the limit.
const TCP_ECHOES: u64 = 30;
const TCP_TICKS: u64 = 500;
const TCP_LIMIT: u64 = 4000;
/// Ticks an echo may go without progress before it is given up as stuck.
const TCP_STUCK: u64 = 3000;

/// Where a connection goes: an address word (IPv4), or an IPv6 address
/// and port.
#[derive(Clone, Copy)]
enum Dest {
    V4(u64),
    V6(u128, u16),
}

impl Dest {
    fn port(self, port: u16) -> Dest {
        match self {
            Dest::V4(w) => Dest::V4(w & !0xffff | port as u64),
            Dest::V6(a, _) => Dest::V6(a, port),
        }
    }
}

/// The 16-byte address at `at` in the page.
fn page_addr(at: usize) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&net_page()[at..at + 16]);
    u128::from_be_bytes(b)
}

/// QEMU's IPv6 network (xtask's `ipv6-net=fd00:3::/64`): the host is ::2
/// on it and the DNS server ::3; this host makes its address from the
/// prefix and its MAC (52:54:00:12:34:56) as a modified EUI-64.
const GW6: u128 = 0xfd00_0003_0000_0000_0000_0000_0000_0002;
const DNS6: u128 = 0xfd00_0003_0000_0000_0000_0000_0000_0003;
const HOST6: u128 = 0xfd00_0003_0000_0000_5054_00ff_fe12_3456;
const LINK_LOCAL6: u128 = 0xfe80_0000_0000_0000_5054_00ff_fe12_3456;

/// An IPv6 address, in RFC 5952's short form.
struct Six(u128);

impl core::fmt::Display for Six {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let g: [u16; 8] = core::array::from_fn(|i| (self.0 >> (112 - 16 * i)) as u16);
        let (mut best, mut len) = (8, 1);
        let mut i = 0;
        while i < 8 {
            let n = g[i..].iter().take_while(|&&x| x == 0).count();
            if n > len {
                (best, len) = (i, n);
            }
            i += n.max(1);
        }
        let mut i = 0;
        while i < 8 {
            if i == best {
                f.write_str("::")?;
                i += len;
                continue;
            }
            if i > 0 && i != best + len {
                f.write_str(":")?;
            }
            write!(f, "{:x}", g[i])?;
            i += 1;
        }
        Ok(())
    }
}

/// `INFO6`, asked until the server has a global address and a DNS
/// server, or `wait` ticks
/// pass: [link-local, global, router, DNS] and the reply.
fn info6(wait: u64) -> Option<([u128; 4], [u64; 4])> {
    let start = ticks();
    loop {
        if let Some(r) = net_call([net::INFO6, net::VERSION, 0, 0]) {
            // With the DNS server too (it may come later, by DHCPv6).
            if r[0] == OK && page_addr(48) != 0 {
                return Some((core::array::from_fn(|k| page_addr(16 * k)), r));
            }
        }
        if ticks() > start + wait {
            return None;
        }
        pause(2);
    }
}

/// Why a connection ended early.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// The server restarted: a call failed, the handle is unknown, or the
    /// notification is gone.
    Lost,
    /// A status: the connection was reset, refused or timed out.
    Status(u64),
}

/// A TCP connection, and the slot its notification is in.
struct Stream {
    h: u64,
    ntfn: u64,
}

fn tcp_reply(r: Option<[u64; 4]>) -> Result<[u64; 4], Cut> {
    match r {
        None => Err(Cut::Lost),
        Some(r) if r[0] == Status::NotFound as u64 => Err(Cut::Lost),
        Some(r) => Ok(r),
    }
}

/// Byte `j` of TCP stream `k`.
fn tcp_byte(k: u64, j: u64) -> u8 {
    (k.wrapping_mul(0x9e37) ^ j.wrapping_mul(13) ^ j >> 9) as u8
}

impl Stream {
    /// A call that grants a notification into `ntfn`.
    fn granting(op: u64, arg: u64, ntfn: u64) -> Result<[u64; 4], Cut> {
        syscall(Syscall::CapDelete, ntfn, [0; 4]);
        let x = CapTransfer {
            grant: None,
            accept: Some(ntfn as u16),
        };
        let r = syscall_x(Syscall::Call, NET, [op, arg, 0, 0], x);
        if r.status != 0 {
            return Err(Cut::Lost);
        }
        if r.msg[0] != OK {
            return Err(Cut::Status(r.msg[0]));
        }
        Ok(r.msg)
    }

    fn connect(to: u64, ntfn: u64) -> Result<Stream, Cut> {
        let r = Stream::granting(net::TCP_CONNECT, to, ntfn)?;
        Ok(Stream { h: r[1], ntfn })
    }

    /// A connection to `d`, over either family.
    fn connect_to(d: Dest, ntfn: u64) -> Result<Stream, Cut> {
        let (a, port) = match d {
            Dest::V4(w) => return Stream::connect(w, ntfn),
            Dest::V6(a, port) => (a, port),
        };
        syscall(Syscall::CapDelete, ntfn, [0; 4]);
        net_page()[..16].copy_from_slice(&a.to_be_bytes());
        let x = CapTransfer {
            grant: Some(NET_PAGE as u16),
            accept: Some(ntfn as u16),
        };
        let r = syscall_x(Syscall::Call, NET, [net::TCP_CONNECT6, port as u64, 0, 0], x);
        if r.status != 0 {
            return Err(Cut::Lost);
        }
        if r.msg[0] != OK {
            return Err(Cut::Status(r.msg[0]));
        }
        Ok(Stream { h: r.msg[1], ntfn })
    }

    /// The peer's address and family (`TCP_PEER`).
    fn peer(&self) -> Option<(u128, u64)> {
        let r = net_call([net::TCP_PEER, self.h, 0, 0])?;
        (r[0] == OK).then(|| (page_addr(0), r[2]))
    }

    /// Waits for the notification, `ticks` at most.
    fn wait(&self, ticks: u64) -> Result<(), Cut> {
        syscall(Syscall::TimerSignal, self.ntfn, [ticks, 0, 0, 0]);
        if syscall(Syscall::Wait, self.ntfn, [0; 4]).status != 0 {
            return Err(Cut::Lost);
        }
        Ok(())
    }

    fn state(&self) -> Result<[u64; 4], Cut> {
        tcp_reply(net_call([net::TCP_STATE, self.h, 0, 0]))
    }

    /// Queues the first `n` bytes of the page; how many were taken.
    fn send(&self, n: u64) -> Result<u64, Cut> {
        let r = tcp_reply(net_call([net::SEND, self.h, 0, n]))?;
        match r[0] {
            OK => Ok(r[1]),
            s if s == Status::Empty as u64 => Ok(0),
            s => Err(Cut::Status(s)),
        }
    }

    /// What has arrived, into the page: `Some(0)` at the end, `None` if
    /// nothing yet.
    fn recv(&self) -> Result<Option<u64>, Cut> {
        let r = tcp_reply(net_call([net::RECV, self.h, 0, 0]))?;
        match r[0] {
            OK => Ok(Some(r[1])),
            s if s == Status::Empty as u64 => Ok(None),
            s => Err(Cut::Status(s)),
        }
    }

    fn shutdown(&self) -> Result<(), Cut> {
        match tcp_reply(net_call([net::TCP_SHUTDOWN, self.h, 0, 0]))?[0] {
            OK => Ok(()),
            s => Err(Cut::Status(s)),
        }
    }

    fn close(self) {
        net_call([net::CLOSE, self.h, 0, 0]);
        syscall(Syscall::CapDelete, self.ntfn, [0; 4]);
    }

    /// Echoes with a peer that sends back what it gets: sends `len` bytes
    /// of stream `k`, checking each that comes back, then shuts down and
    /// reads to the end. Whether every byte came back right.
    fn echo(&self, k: u64, len: u64) -> Result<bool, Cut> {
        let (mut sent, mut got, mut right, mut shut) = (0, 0, true, false);
        let mut last = ticks();
        loop {
            let mut moved = false;
            if sent < len {
                let n = (len - sent).min(4096);
                for (j, b) in net_page()[..n as usize].iter_mut().enumerate() {
                    *b = tcp_byte(k, sent + j as u64);
                }
                let took = self.send(n)?;
                sent += took;
                moved |= took > 0;
            } else if !shut {
                self.shutdown()?;
                shut = true;
            }
            while let Some(n) = self.recv()? {
                if n == 0 {
                    return Ok(right && got == len);
                }
                right &= net_page()[..n as usize]
                    .iter()
                    .enumerate()
                    .all(|(j, &b)| b == tcp_byte(k, got + j as u64));
                got += n;
                moved = true;
            }
            if moved {
                last = ticks();
            } else {
                if ticks() > last + TCP_STUCK {
                    return Err(Cut::Status(Status::TimedOut as u64));
                }
                self.wait(20)?;
            }
        }
    }
}

/// IPv6 in the network test, under fault injection: the addresses from
/// the router's advertisement, pings to the host, UDP echoes (up to what
/// one frame holds: QEMU does not reassemble IPv6), datagrams of up to
/// 4,000 bytes to the socket itself (in fragments, round the loopback),
/// and TCP echoes.
fn ipv6_checks(t: &mut Checks) {
    let (a, r) = info6(3000).unwrap_or(([0; 4], [0; 4]));
    t.check(
        a[0] == LINK_LOCAL6 && a[1] == HOST6 && a[2] >> 112 == 0xfe80 && a[3] == DNS6 && r[1] == 64,
        format_args!(
            "IPv6: this host is {}/{}, the router {}, DNS {}, link-local {}",
            Six(a[1]),
            r[1],
            Six(a[2]),
            Six(a[3]),
            Six(a[0])
        ),
    );
    let (mut answered, mut pings, mut stats) = (0, 0, (0, 0));
    if let Some(mut s) = Sock::new(false) {
        let start = ticks();
        while pings < PINGS || ticks() < start + PING_TICKS {
            let seq = pings;
            pings += 1;
            let ok = s.exchange6(
                GW6,
                seq as u16,
                false,
                56,
                |b| {
                    for (j, x) in b[..56].iter_mut().enumerate() {
                        *x = echo_byte(seq, j as u64);
                    }
                },
                |len, b, from, port| {
                    from == GW6
                        && port == seq as u16
                        && len == 56
                        && b.iter().enumerate().all(|(j, &x)| x == echo_byte(seq, j as u64))
                },
            );
            answered += ok as u64;
        }
        stats = (s.resent, s.rebinds);
    }
    t.check(
        answered == pings && pings >= PINGS,
        format_args!(
            "{answered} of {pings} pings to {} over IPv6 answered, every byte right ({} sent again, {} sockets bound again)",
            Six(GW6),
            stats.0,
            stats.1
        ),
    );
    // UDP to the host's echo, and to the socket itself in fragments.
    for (to_self, label) in [(false, 0), (true, 1)] {
        let (mut ok, mut n, mut stats) = (0, 0, (0, 0));
        let (want, lasting) = if to_self { (20, 0) } else { (ECHOES / 2, ECHO_TICKS / 2) };
        if let Some(mut s) = Sock::new(true) {
            let start = ticks();
            while n < want || ticks() < start + lasting {
                let k = n;
                n += 1;
                let len = if to_self { 1453 + k * 641 % 2548 } else { 1 + k * 97 % 1452 };
                let to = if to_self { HOST6 } else { GW6 };
                let got = s.exchange6(
                    to,
                    ECHO_PORT,
                    to_self,
                    len,
                    |b| {
                        for j in 0..len {
                            b[j as usize] = echo_at(k, j);
                        }
                    },
                    |m, b, from, _| {
                        from == to && m == len && b.iter().enumerate().all(|(j, &x)| x == echo_at(k, j as u64))
                    },
                );
                ok += got as u64;
            }
            stats = (s.resent, s.rebinds);
        }
        if label == 0 {
            t.check(
                ok == n && n >= want,
                format_args!(
                    "{ok} of {n} UDP datagrams of 1 to 1452 bytes over IPv6 echoed by the host, every byte right ({} sent again, {} sockets bound again)",
                    stats.0, stats.1
                ),
            );
        } else {
            t.check(
                ok == n && n >= want,
                format_args!(
                    "{ok} of {n} UDP datagrams of 1453 to 4000 bytes sent to itself over IPv6, in fragments, every byte right ({} sent again)",
                    stats.0
                ),
            );
        }
    }
    // Past a page, to itself over IPv6 (QEMU does not fragment IPv6), in
    // 1448-byte fragments round the loopback.
    let mut ok = 0;
    if let Some(mut s) = Sock::new(true) {
        for (k, len) in [(200, 4097), (201, 30_000), (202, net::MAX_DATAGRAM)] {
            ok += s.big_exchange(HOST6, 0, true, len, |j| echo_at(k, j)) as u64;
        }
    }
    let mut pinged = false;
    if let Some(mut s) = Sock::new(false) {
        pinged = s.big_exchange(HOST6, 9, false, 20_000, |j| echo_at(203, j));
    }
    t.check(
        ok == 3 && pinged,
        format_args!(
            "datagrams of 4097, 30000 and 65507 bytes sent to itself over IPv6, and a 20000-byte IPv6 ping of this host answered, every byte right"
        ),
    );
    tcp_under_faults(t, Dest::V6(GW6, TCP_ECHO_PORT));
}

/// TCP connections to the host's echo while the injector kills the
/// server and the driver: each sends up to 8,000 bytes and reads them
/// back. A connection a restart cuts is made again; no byte may come back
/// wrong.
fn tcp_under_faults(t: &mut Checks, to: Dest) {
    let six = matches!(to, Dest::V6(..));
    let (mut done, mut cut, mut wrong, mut k) = (0u64, 0u64, 0u64, 0u64);
    let mut bytes = 0;
    let start = ticks();
    while (done < TCP_ECHOES || ticks() < start + TCP_TICKS) && ticks() < start + TCP_LIMIT {
        k += 1;
        let len = 1 + k * 1777 % 8000;
        match Stream::connect_to(to, NET_NTFN) {
            Ok(s) => {
                let r = s.echo(k, len);
                s.close();
                match r {
                    Ok(true) => {
                        done += 1;
                        bytes += len;
                    }
                    Ok(false) => wrong += 1,
                    Err(_) => cut += 1,
                }
            }
            Err(_) => {
                cut += 1;
                pause(5);
            }
        }
    }
    t.check(
        done >= TCP_ECHOES && wrong == 0,
        format_args!(
            "{done} TCP connections{} echoed {bytes} bytes through the host under fault injection, every byte right ({cut} cut by a restart and made again, {wrong} wrong)",
            if six { " over IPv6" } else { "" }
        ),
    );
}

/// The TCP test (`arg 18`, boot/tcp.manifest): the network server drops
/// one TCP segment in 20 each way, so retransmission, fast retransmit
/// and out-of-order arrival all happen.
const TCP_BULK: u64 = 100_000;
const TCP_BULK6: u64 = 50_000;
/// Connections echoed at once (the server holds 16), each this many bytes,
/// and the first of the slots their notifications arrive in.
const TCP_MANY: u64 = 14;
const TCP_MANY_BYTES: u64 = 20_000;
const MANY_NTFN: u64 = 48;

/// `TCP_MANY` connections to the host's echo port at once, each sending
/// its own stream a piece at a time in turn and checking what comes
/// back. Whether all of them came back right.
fn many_at_once(gw: u64) -> bool {
    let mut streams: [Option<Stream>; TCP_MANY as usize] = [const { None }; TCP_MANY as usize];
    for (i, s) in streams.iter_mut().enumerate() {
        match Stream::connect(gw | TCP_ECHO_PORT as u64, MANY_NTFN + i as u64) {
            Ok(c) => *s = Some(c),
            Err(_) => return false,
        }
    }
    // Per stream: bytes sent, bytes back, whether shut down, finished.
    let mut sent = [0u64; TCP_MANY as usize];
    let mut got = [0u64; TCP_MANY as usize];
    let mut shut = [false; TCP_MANY as usize];
    let mut done = [false; TCP_MANY as usize];
    let mut right = true;
    let mut last = ticks();
    while done.iter().any(|d| !d) {
        let mut moved = false;
        for (i, s) in streams.iter().enumerate() {
            let Some(s) = s else { continue };
            if done[i] {
                continue;
            }
            let k = 2000 + i as u64;
            if sent[i] < TCP_MANY_BYTES {
                let n = (TCP_MANY_BYTES - sent[i]).min(1500);
                for (j, b) in net_page()[..n as usize].iter_mut().enumerate() {
                    *b = tcp_byte(k, sent[i] + j as u64);
                }
                match s.send(n) {
                    Ok(took) => {
                        sent[i] += took;
                        moved |= took > 0;
                    }
                    Err(_) => return false,
                }
            } else if !shut[i] {
                if s.shutdown().is_err() {
                    return false;
                }
                shut[i] = true;
            }
            loop {
                match s.recv() {
                    Ok(Some(0)) => {
                        done[i] = true;
                        right &= got[i] == TCP_MANY_BYTES;
                        break;
                    }
                    Ok(Some(n)) => {
                        right &= net_page()[..n as usize]
                            .iter()
                            .enumerate()
                            .all(|(j, &b)| b == tcp_byte(k, got[i] + j as u64));
                        got[i] += n;
                        moved = true;
                    }
                    Ok(None) => break,
                    Err(_) => return false,
                }
            }
        }
        if moved {
            last = ticks();
        } else if ticks() > last + TCP_STUCK {
            return false;
        } else {
            superior_sys::sleep(1);
        }
    }
    for s in streams.into_iter().flatten() {
        s.close();
    }
    right
}
/// Connections the host makes to the listening port, and the bytes each
/// sends (more than the server's 8 KiB window, so it shuts).
const TCP_INBOUND: u64 = 3;

/// Bytes each way between two of this host's sockets.
const LOCAL_BYTES: u64 = 20_000;

/// Both ends of a connection here, through the loopback: a listener on
/// `TCP_LISTEN_PORT + 1`, a connection to it, and the accepted end; each
/// sends `LOCAL_BYTES` (streams 7 and 8) and reads the other's.
fn local_pair(me: Dest) -> bool {
    let port = TCP_LISTEN_PORT + 1;
    let Ok(lr) = Stream::granting(net::TCP_LISTEN, port as u64, LISTEN_NTFN) else {
        return false;
    };
    let l = Stream { h: lr[1], ntfn: LISTEN_NTFN };
    let Ok(a) = Stream::connect_to(me.port(port), NET_NTFN) else {
        l.close();
        return false;
    };
    let mut b = None;
    for _ in 0..100 {
        if let Ok(r) = Stream::granting(net::TCP_ACCEPT, l.h, ACCEPTED_NTFN) {
            b = Some(Stream { h: r[1], ntfn: ACCEPTED_NTFN });
            break;
        }
        let _ = l.wait(5);
    }
    l.close();
    let Some(b) = b else {
        a.close();
        return false;
    };
    // The accepted end knows its peer, in the right family.
    let peer = b.peer();
    let mut right = match me {
        Dest::V4(_) => peer.is_some_and(|p| p.1 == 4),
        Dest::V6(addr, _) => peer == Some((addr, 6)),
    };
    // [sent, received, ended] for each end.
    let mut st = [[0u64; 3]; 2];
    let start = ticks();
    while ticks() < start + 2000 && !(st[0][2] == 1 && st[1][2] == 1) {
        let mut moved = false;
        for (i, s) in [&a, &b].into_iter().enumerate() {
            let (mine, theirs) = (7 + i as u64, 8 - i as u64);
            let sent = st[i][0];
            if sent < LOCAL_BYTES {
                let n = (LOCAL_BYTES - sent).min(4096);
                for (j, x) in net_page()[..n as usize].iter_mut().enumerate() {
                    *x = tcp_byte(mine, sent + j as u64);
                }
                let took = s.send(n).unwrap_or(0);
                st[i][0] += took;
                moved |= took > 0;
                if st[i][0] == LOCAL_BYTES {
                    let _ = s.shutdown();
                }
            }
            while let Ok(Some(n)) = s.recv() {
                if n == 0 {
                    st[i][2] = 1;
                    break;
                }
                let got = st[i][1];
                right &= net_page()[..n as usize]
                    .iter()
                    .enumerate()
                    .all(|(j, &x)| x == tcp_byte(theirs, got + j as u64));
                st[i][1] += n;
                moved = true;
            }
        }
        if !moved {
            let _ = a.wait(2);
        }
    }
    a.close();
    b.close();
    right && st.iter().all(|e| e[1] == LOCAL_BYTES && e[2] == 1)
}

fn tcp_client() -> ! {
    let mut t = Checks(0, "tcp");
    let made = syscall(
        Syscall::Retype,
        NET_MEMORY,
        [ObjectType::Frame as u64, 0, NET_PAGE, 0],
    );
    let mapped = syscall(Syscall::FrameMap, NET_PAGE, [NET_PAGE_VA, 1, 0, 0]);
    let start = ticks();
    let info = loop {
        let r = syscall(Syscall::Call, NET, [net::INFO, net::VERSION, 0, 0]);
        if (r.status == 0 && r.msg[0] == OK) || ticks() > start + LEASE_TICKS {
            break r.msg;
        }
        superior_sys::sleep(1);
    };
    t.check(
        made.status == 0 && mapped.status == 0 && info[0] == OK,
        format_args!("this host is {}", Dotted(info[1])),
    );
    let gw = info[3];

    // Nothing listens on this host's own closed port: the server's reset
    // comes back round the loopback. (QEMU's user network does not answer
    // a refused connection on every host.)
    let refused = match Stream::connect(info[1] | TCP_CLOSED_PORT as u64, NET_NTFN) {
        Ok(s) => {
            let mut r = Ok(None);
            for _ in 0..50 {
                r = s.recv();
                if r != Ok(None) {
                    break;
                }
                let _ = s.wait(20);
            }
            s.close();
            r
        }
        Err(e) => Err(e),
    };
    t.check(
        refused == Err(Cut::Status(Status::Refused as u64)),
        format_args!("a connection to a closed port of this host's is refused, through the loopback"),
    );

    // A bulk echo through the lossy server.
    let began = ticks();
    let (bulk, state) = match Stream::connect(gw | TCP_ECHO_PORT as u64, NET_NTFN) {
        Ok(s) => {
            let mut state = 0;
            for _ in 0..100 {
                state = s.state().map_or(0, |r| r[1]);
                if state == net::TCP_ESTABLISHED {
                    break;
                }
                let _ = s.wait(10);
            }
            let r = s.echo(1, TCP_BULK);
            s.close();
            (r, state)
        }
        Err(e) => (Err(e), 0),
    };
    let took = ticks() - began;
    t.check(
        bulk == Ok(true) && state == net::TCP_ESTABLISHED,
        format_args!(
            "{TCP_BULK} bytes echoed by the host with one segment in 20 dropped each way, every byte right, in {}.{:02} s",
            took / 100,
            took % 100
        ),
    );

    let began = ticks();
    let many = many_at_once(gw);
    let took = ticks() - began;
    t.check(
        many,
        format_args!(
            "{TCP_MANY} connections at once echoed by the host, {TCP_MANY_BYTES} bytes each, every byte right, in {}.{:02} s",
            took / 100,
            took % 100
        ),
    );

    // The host connects in: each connection's bytes are checked and sent
    // back, until it shuts down; then this side does.
    let listener = Stream::granting(net::TCP_LISTEN, TCP_LISTEN_PORT as u64, LISTEN_NTFN);
    let taken = Stream::granting(net::TCP_LISTEN, TCP_LISTEN_PORT as u64, NET_NTFN);
    t.check(
        listener.is_ok() && taken == Err(Cut::Status(Status::InUse as u64)),
        format_args!("listening on port {TCP_LISTEN_PORT}, which a second listener cannot take"),
    );
    let l = Stream {
        h: listener.map_or(0, |r| r[1]),
        ntfn: LISTEN_NTFN,
    };
    let (mut served, mut right, mut total) = (0, true, 0);
    let mut first = true;
    let start = ticks();
    while served < TCP_INBOUND && ticks() < start + 6000 {
        let r = Stream::granting(net::TCP_ACCEPT, l.h, ACCEPTED_NTFN);
        let s = match r {
            Ok(r) => Stream {
                h: r[1],
                ntfn: ACCEPTED_NTFN,
            },
            Err(_) => {
                let _ = l.wait(10);
                continue;
            }
        };
        if first {
            // Let the host fill the window before reading anything.
            first = false;
            pause(100);
        }
        // Echo until the host's end, checking its bytes (stream 1000 +
        // its number, as the host makes them).
        let k = 1000 + served;
        let (mut got, mut back, mut ended) = (0u64, 0u64, false);
        let mut ok = true;
        let mut pending = [0u8; 4096];
        let mut have = 0usize;
        let began = ticks();
        while ticks() < began + 3000 {
            let mut moved = false;
            if have == 0 && !ended {
                match s.recv() {
                    Ok(Some(0)) => ended = true,
                    Ok(Some(n)) => {
                        let p = &net_page()[..n as usize];
                        ok &= p.iter().enumerate().all(|(j, &b)| b == tcp_byte(k, got + j as u64));
                        pending[..n as usize].copy_from_slice(p);
                        have = n as usize;
                        got += n;
                        moved = true;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            if have > 0 {
                net_page()[..have].copy_from_slice(&pending[..have]);
                match s.send(have as u64) {
                    Ok(0) => {}
                    Ok(n) => {
                        pending.copy_within(n as usize..have, 0);
                        have -= n as usize;
                        back += n;
                        moved = true;
                    }
                    Err(_) => break,
                }
            }
            if ended && have == 0 {
                let _ = s.shutdown();
                // Wait for our FIN to be acknowledged.
                for _ in 0..100 {
                    match s.state() {
                        Ok(r) if r[2] > 0 => {
                            let _ = s.wait(5);
                        }
                        _ => break,
                    }
                }
                break;
            }
            if !moved {
                let _ = s.wait(5);
            }
        }
        s.close();
        if ended && back == got {
            served += 1;
            total += got;
            right &= ok;
        }
    }
    l.close();
    t.check(
        served == TCP_INBOUND && right,
        format_args!(
            "{served} connections from the host accepted, {total} bytes checked and echoed back, every byte right"
        ),
    );
    t.check(local_pair(Dest::V4(info[1])), format_args!("a connection between two sockets of this host's carried {LOCAL_BYTES} bytes each way, every byte right"));
    // IPv6: a closed port, a bulk echo through the lossy server, a local
    // pair.
    let have6 = info6(1000).is_some();
    let refused6 = Stream::connect_to(Dest::V6(HOST6, TCP_CLOSED_PORT), NET_NTFN).and_then(|s| {
        let mut r = Ok(None);
        for _ in 0..50 {
            r = s.recv();
            if r != Ok(None) {
                break;
            }
            let _ = s.wait(20);
        }
        s.close();
        r
    });
    t.check(
        have6 && refused6 == Err(Cut::Status(Status::Refused as u64)),
        format_args!("over IPv6, a connection to a closed port of this host's is refused"),
    );
    let bulk6 = Stream::connect_to(Dest::V6(GW6, TCP_ECHO_PORT), NET_NTFN).and_then(|s| {
        let r = s.echo(2, TCP_BULK6);
        s.close();
        r
    });
    t.check(
        bulk6 == Ok(true),
        format_args!("over IPv6, {TCP_BULK6} bytes echoed by the host with one segment in 20 dropped each way, every byte right"),
    );
    t.check(
        local_pair(Dest::V6(HOST6, 0)),
        format_args!("over IPv6, a connection between two sockets of this host's carried {LOCAL_BYTES} bytes each way, every byte right, the accepted end's peer {} over IPv6", Six(HOST6)),
    );
    let s = syscall(Syscall::Call, NET, [net::TCP_STATS, net::VERSION, 0, 0]).msg;
    t.check(
        s[0] == OK && s[1] > 0 && s[2] > 0 && s[3] > 0,
        format_args!(
            "{} segments sent again, {} dropped on purpose, {} kept out of order",
            s[1], s[2], s[3]
        ),
    );
    syscall(Syscall::Call, NET_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// The resolver (`boot/net.manifest`), whose host-side server
/// (`cargo xtask net-test`) knows the names below.
const DNS: u64 = 5;
/// Names resolved under fault injection, at least, and for how long.
const NAMES: u64 = 100;
const NAME_TICKS: u64 = 300;
/// Times a call is made again (the resolver or the network server
/// restarted, or nothing answered in time) before giving up.
const DNS_TRIES: u32 = 60;

/// Writes formatted text into the start of the page; returns its length.
fn put_text(args: core::fmt::Arguments) -> u64 {
    struct Page(usize);
    impl core::fmt::Write for Page {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let p = net_page();
            p.get_mut(self.0..self.0 + s.len())
                .ok_or(core::fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.0 += s.len();
            Ok(())
        }
    }
    let mut p = Page(0);
    let _ = core::fmt::Write::write_fmt(&mut p, args);
    p.0 as u64
}

/// Resolves the name `args` gives, asking again while the resolver or
/// the network is restarting: the reply, and how many calls were made
/// again.
fn resolve(args: core::fmt::Arguments) -> ([u64; 4], u32) {
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    let mut again = 0;
    for _ in 0..DNS_TRIES {
        let len = put_text(args);
        let r = syscall_x(Syscall::Call, DNS, [dns::RESOLVE, dns::VERSION, len, 0], x);
        if r.status == 0 && r.msg[0] != Status::Unreachable as u64 {
            return (r.msg, again);
        }
        again += 1;
        superior_sys::sleep(1);
    }
    ([Status::Unreachable as u64, 0, 0, 0], again)
}

/// The records of DNS type `kind` of the name `args` gives, asking again
/// while the resolver or the network is restarting: the status, how many,
/// and the records joined with `|` (in `text`; its length).
fn dns_records(args: core::fmt::Arguments, kind: u64, text: &mut [u8; 256]) -> (u64, u64, usize) {
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    for _ in 0..DNS_TRIES {
        let len = put_text(args);
        let r = syscall_x(Syscall::Call, DNS, [dns::RECORDS, dns::VERSION, len | kind << 16, 0], x);
        if r.status == 0 && r.msg[0] != Status::Unreachable as u64 {
            let (mut at, mut n) = (0, 0);
            if r.msg[0] == OK {
                let p = net_page();
                for i in 0..r.msg[1] {
                    let len = u16::from_le_bytes([p[at], p[at + 1]]) as usize;
                    if i > 0 && n < text.len() {
                        text[n] = b'|';
                        n += 1;
                    }
                    let take = len.min(text.len() - n);
                    text[n..n + take].copy_from_slice(&p[at + 2..at + 2 + take]);
                    n += take;
                    at += 2 + len;
                }
            }
            return (r.msg[0], r.msg[1], n);
        }
        superior_sys::sleep(1);
    }
    (Status::Unreachable as u64, 0, 0)
}

/// Records other than addresses: text, mail exchangers, services,
/// reverse names and name servers, each as the resolver's text for it.
fn dns_record_checks(t: &mut Checks) {
    let mut all = true;
    let mut want = |name: &str, kind: u64, records: u64, expect: &str| {
        let mut text = [0u8; 256];
        let (s, n, len) = dns_records(format_args!("{name}"), kind, &mut text);
        let ok = s == OK && n == records && &text[..len] == expect.as_bytes();
        if !ok {
            say!(
                "{name} type {kind}: status {s}, {n} records: {}",
                core::str::from_utf8(&text[..len]).unwrap_or("(not text)")
            );
        }
        all &= ok;
    };
    want("txt.superior.test", dns::TXT, 2, "v=spf1 -all|hello world");
    // Through a CNAME, like an address.
    want("alias-txt.superior.test", dns::TXT, 2, "v=spf1 -all|hello world");
    want("superior.test", dns::MX, 2, "10 mx1.superior.test|20 mx2.superior.test");
    want("superior.test", dns::NS, 1, "ns1.superior.test");
    want("_sip._tcp.superior.test", dns::SRV, 1, "0 5 5060 sip.superior.test");
    want("10.2.0.192.in-addr.arpa", dns::PTR, 1, "www.superior.test");
    // An answer too big for a datagram: the resolver fetches it over TCP.
    // Six TXT records of 200 bytes each.
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    let mut big = false;
    for _ in 0..DNS_TRIES {
        let len = put_text(format_args!("big.superior.test"));
        let r = syscall_x(Syscall::Call, DNS, [dns::RECORDS, dns::VERSION, len | dns::TXT << 16, 0], x);
        if r.status == 0 && r.msg[0] != Status::Unreachable as u64 {
            let p = net_page();
            big = r.msg[0] == OK
                && r.msg[1] == 6
                && (0..6usize).all(|i| {
                    let at = i * 202;
                    u16::from_le_bytes([p[at], p[at + 1]]) == 200
                        && (0..200usize).all(|j| p[at + 2 + j] == b'a' + ((i * 7 + j) % 26) as u8)
                });
            break;
        }
        superior_sys::sleep(1);
    }
    // Asked again, short answers come from the resolver's cache (unless
    // the injector killed it in between: then once more).
    let mut cached = false;
    for _ in 0..8 {
        let len = put_text(format_args!("superior.test"));
        let r = syscall_x(Syscall::Call, DNS, [dns::RECORDS, dns::VERSION, len | dns::MX << 16, 0], x);
        if r.status == 0 && r.msg[0] == OK && r.msg[1] == 2 && r.msg[3] == 1 {
            cached = true;
            break;
        }
        superior_sys::sleep(1);
    }
    t.check(
        big && cached,
        format_args!(
            "big.superior.test's six 200-byte TXT records, too long for UDP, came over TCP, every byte right; superior.test's MX answered from the cache"
        ),
    );
    let mut text = [0u8; 256];
    let (none, _, _) = dns_records(format_args!("www.superior.test"), dns::TXT, &mut text);
    let (nowhere, _, _) = dns_records(format_args!("nowhere.superior.test"), dns::MX, &mut text);
    t.check(
        all && none == Status::NotFound as u64 && nowhere == Status::NotFound as u64,
        format_args!(
            "DNS records: superior.test's MX are mx1 (10) and mx2 (20), its NS ns1, its SIP SRV sip:5060; txt and its alias have two TXT; 192.0.2.10's PTR is www"
        ),
    );
}

/// Resolves the name `args` gives to an IPv6 address, asking again while
/// the resolver or the network is restarting: the status, the address,
/// and whether it came from the cache.
fn resolve6(args: core::fmt::Arguments) -> (u64, [u8; 16], bool) {
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    for _ in 0..DNS_TRIES {
        let len = put_text(args);
        let r = syscall_x(Syscall::Call, DNS, [dns::RESOLVE6, dns::VERSION, len, 0], x);
        if r.status == 0 && r.msg[0] != Status::Unreachable as u64 {
            let mut a = [0; 16];
            if r.msg[0] == OK {
                a.copy_from_slice(&net_page()[..16]);
            }
            return (r.msg[0], a, r.msg[2] == 1);
        }
        superior_sys::sleep(1);
    }
    (Status::Unreachable as u64, [0; 16], false)
}

/// An IPv6 address in the 2001:db8:: form the DNS test's names use: its
/// groups, with the zeros between the first two and the last left out.
struct Colons([u8; 16]);

impl core::fmt::Display for Colons {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let g = |i: usize| u16::from_be_bytes([self.0[2 * i], self.0[2 * i + 1]]);
        let first = (0..8).find(|&i| g(i) == 0).unwrap_or(8);
        let last = (first..8).find(|&i| g(i) != 0).unwrap_or(8);
        for i in 0..first {
            write!(f, "{}{:x}", if i > 0 { ":" } else { "" }, g(i))?;
        }
        if first < 8 {
            write!(f, "::")?;
            for i in last..8 {
                write!(f, "{}{:x}", if i > last { ":" } else { "" }, g(i))?;
            }
        }
        Ok(())
    }
}

fn pause(t: u64) {
    superior_sys::sleep(t);
}

fn dns_checks(t: &mut Checks) {
    let a = |ip: [u8; 4]| net::addr(ip, 0);
    let (r, _) = resolve(format_args!("www.superior.test"));
    t.check(
        r[0] == OK && r[1] == a([192, 0, 2, 10]),
        format_args!("www.superior.test is {}", Dotted(r[1])),
    );
    let (r, _) = resolve(format_args!("Alias.Superior.Test."));
    t.check(
        r[0] == OK && r[1] == a([192, 0, 2, 10]),
        format_args!("alias.superior.test, a CNAME for www, is {}", Dotted(r[1])),
    );
    // IPv6 addresses (AAAA records), through a CNAME too; a name with only
    // an IPv4 address has none, and one with only IPv6 none of IPv4.
    let v6 = |last: u8| {
        let mut a = [0; 16];
        a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        a[15] = last;
        a
    };
    let (s, www6, _) = resolve6(format_args!("www.superior.test"));
    let (s2, alias6, _) = resolve6(format_args!("alias.superior.test"));
    // The injector may kill the resolver between two questions, and its
    // cache goes with it: ask again until an answer comes from the cache.
    let (mut again6, mut from_cache) = ([0; 16], false);
    for _ in 0..8 {
        (_, again6, from_cache) = resolve6(format_args!("www.superior.test"));
        if from_cache {
            break;
        }
    }
    t.check(
        s == OK && www6 == v6(0x10) && s2 == OK && alias6 == v6(0x10) && again6 == www6 && from_cache,
        format_args!(
            "www.superior.test's IPv6 address is {}, alias's too, and the second answer was cached",
            Colons(www6)
        ),
    );
    let (none6, _, _) = resolve6(format_args!("cached.superior.test"));
    let (only6, addr6, _) = resolve6(format_args!("v6only.superior.test"));
    let (none4, _) = resolve(format_args!("v6only.superior.test"));
    t.check(
        none6 == Status::NotFound as u64
            && only6 == OK
            && addr6 == v6(0x66)
            && none4[0] == Status::NotFound as u64,
        format_args!(
            "cached.superior.test has no IPv6 address; v6only.superior.test has {} and no IPv4 one",
            Colons(addr6)
        ),
    );
    dns_record_checks(t);
    let (r, _) = resolve(format_args!("nowhere.superior.test"));
    let (bad, _) = resolve(format_args!("no..dots"));
    t.check(
        r[0] == Status::NotFound as u64 && bad[0] == Status::Invalid as u64,
        format_args!("nowhere.superior.test does not exist, and no..dots is no name"),
    );
    // Cached for its TTL (300 s): asked of the server once, unless the
    // resolver was killed in between.
    let mut cached = 0;
    let mut right = 0;
    for _ in 0..20 {
        let (r, _) = resolve(format_args!("cached.superior.test"));
        right += (r[0] == OK && r[1] == a([192, 0, 2, 20])) as u32;
        cached += r[3];
    }
    t.check(
        right == 20 && cached >= 15,
        format_args!("cached.superior.test resolved 20 times, {cached} from the cache"),
    );
    // A TTL of 1 s: after 1.5 s the answer is not in the cache.
    let (first, _) = resolve(format_args!("short.superior.test"));
    pause(150);
    let (second, _) = resolve(format_args!("short.superior.test"));
    t.check(
        first[0] == OK
            && second[0] == OK
            && second[1] == a([192, 0, 2, 30])
            && first[2] <= 1
            && second[3] == 0,
        format_args!("short.superior.test (TTL 1 s) asked of the server again after 1.5 s"),
    );
    // Many names, each new to the resolver, while the injector kills it,
    // the network server and the driver.
    let (mut names, mut ok, mut again) = (0u64, 0u64, 0u32);
    let start = ticks();
    while names < NAMES || ticks() < start + NAME_TICKS {
        let k = names;
        names += 1;
        let (r, n) = resolve(format_args!("n{k}.superior.test"));
        again += n;
        ok += (r[0] == OK && r[1] == a([198, 51, (k >> 8) as u8, k as u8])) as u64;
    }
    t.check(
        ok == names,
        format_args!(
            "{ok} of {names} names resolved under fault injection, every address right ({again} calls made again)"
        ),
    );
}

/// Echo `k`'s length and byte `j`.
fn echo_len(k: u64) -> u64 {
    1 + k * 97 % 4000
}

fn echo_byte(k: u64, j: u64) -> u8 {
    (k.wrapping_mul(31) ^ j.wrapping_mul(7) ^ j >> 8) as u8
}

/// Byte `j` of UDP echo `k`: its number first (so a late echo of an
/// earlier one is told apart), then the pattern.
fn echo_at(k: u64, j: u64) -> u8 {
    match k.to_le_bytes().get(j as usize) {
        Some(&b) => b,
        None => echo_byte(k, j),
    }
}

fn net_client() -> ! {
    let mut t = Checks(0, "net");
    let made = syscall(
        Syscall::Retype,
        NET_MEMORY,
        [ObjectType::Frame as u64, 0, NET_PAGE, 0],
    );
    let mapped = syscall(Syscall::FrameMap, NET_PAGE, [NET_PAGE_VA, 1, 0, 0]);
    t.check(
        made.status == 0 && mapped.status == 0,
        format_args!("a page of its own"),
    );
    // The server has no address until DHCP answers: ask until it has.
    let ask = |op: u64| {
        let start = ticks();
        loop {
            let r = syscall(Syscall::Call, NET, [op, net::VERSION, 0, 0]);
            if r.status == 0 && r.msg[0] == OK {
                return Some(r.msg);
            }
            if ticks() > start + LEASE_TICKS {
                return None;
            }
            superior_sys::sleep(1);
        }
    };
    let info = ask(net::INFO).unwrap_or([0; 4]);
    let lease = ask(net::LEASE).unwrap_or([0; 4]);
    let (host, gateway) = (Dotted(info[1]), Dotted(info[3]));
    let same_net = |a: u64| (a >> 16) as u32 & lease[1] as u32;
    t.check(
        info[1] != 0 && info[3] != 0 && lease[1] != 0 && same_net(info[1]) == same_net(info[3]),
        format_args!("this host is {host}, the gateway {gateway}"),
    );
    t.check(
        lease[2] != 0 && lease[3] > 0,
        format_args!(
            "netmask /{}, DNS server {}, {} s left on the lease",
            (lease[1] as u32).count_ones(),
            Dotted(lease[2]),
            lease[3]
        ),
    );
    let gw = info[3];

    // Pings to the gateway, under fault injection.
    let (mut answered, mut pings) = (0, 0);
    let mut stats = (0, 0);
    if let Some(mut s) = Sock::new(false) {
        let start = ticks();
        while pings < PINGS || ticks() < start + PING_TICKS {
            let seq = pings;
            pings += 1;
            let to = gw | seq as u64;
            let ok = s.exchange(
                to,
                56,
                |b| {
                    for (j, x) in b[..56].iter_mut().enumerate() {
                        *x = echo_byte(seq, j as u64);
                    }
                },
                |len, b, from| {
                    from == to
                        && len == 56
                        && b.iter()
                            .enumerate()
                            .all(|(j, &x)| x == echo_byte(seq, j as u64))
                },
            );
            answered += ok as u64;
        }
        stats = (s.resent, s.rebinds);
    }
    t.check(
        answered == pings && pings >= PINGS,
        format_args!(
            "{answered} of {pings} pings to {gateway} answered, every byte right ({} sent again, {} sockets bound again after a restart)",
            stats.0, stats.1
        ),
    );

    // UDP datagrams of 1 to 4000 bytes, echoed by the host: those over
    // 1472 bytes go out in fragments, and come back in them.
    let (mut echoed, mut echoes) = (0, 0);
    let mut stats = (0, 0);
    if let Some(mut s) = Sock::new(true) {
        let to = gw | ECHO_PORT as u64;
        let start = ticks();
        while echoes < ECHOES || ticks() < start + ECHO_TICKS {
            let k = echoes;
            echoes += 1;
            let len = echo_len(k);
            let ok = s.exchange(
                to,
                len,
                |b| {
                    for j in 0..len {
                        b[j as usize] = echo_at(k, j);
                    }
                },
                |n, b, from| {
                    from == to
                        && n == len
                        && b.iter()
                            .enumerate()
                            .all(|(j, &x)| x == echo_at(k, j as u64))
                },
            );
            echoed += ok as u64;
        }
        stats = (s.resent, s.rebinds);
    }
    t.check(
        echoed == echoes && echoes >= ECHOES,
        format_args!(
            "{echoed} of {echoes} UDP datagrams of 1 to 4000 bytes echoed by the host, every byte right ({} sent again, {} sockets bound again after a restart)",
            stats.0, stats.1
        ),
    );
    big_checks(&mut t, gw, info[1]);
    let s = syscall(Syscall::Call, NET, [net::STATS, net::VERSION, 0, 0]).msg;
    t.check(
        s[0] == OK && s[1] > 0 && s[2] > 0,
        format_args!(
            "{} datagrams reassembled from fragments, {} sent in fragments, {} dropped half reassembled",
            s[1], s[2], s[3]
        ),
    );
    dns_checks(&mut t);
    tcp_under_faults(&mut t, Dest::V4(gw | TCP_ECHO_PORT as u64));
    ipv6_checks(&mut t);
    net_ring_checks(&mut t, gw);
    // Frames go between the server and the driver through their rings;
    // only around a restart of either does one take a call.
    let s = syscall(Syscall::Call, NET, [net::LINK_STATS, net::VERSION, 0, 0]).msg;
    t.check(
        s[0] == OK && s[3] > 0 && s[1] > 20 * s[2],
        format_args!(
            "{} frames through the rings with the driver, {} by a call each; rings set up {} times",
            s[1], s[2], s[3]
        ),
    );
    syscall(Syscall::Call, NET_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

const INPUT: u64 = 0;
const INPUT_CONTROL: u64 = 1;
/// The subscription's notification arrives here.
const INPUT_NTFN: u64 = 3;
/// The word the host types, again and again, with a space after each.
const WORD: &[u8] = b"superior";
/// Whole words that must come through, and for at least how long.
const WORDS: u64 = 10;
const TYPING_TICKS: u64 = 1500;
const TYPING_LIMIT: u64 = 9000;

// ---- the Wi-Fi client (`arg 41`, boot/wifi.manifest) ----

/// The radio's `nic` endpoint, to tell it which network to join.
const RADIO: u64 = 5;
/// The network the test harness's access point runs.
const WIFI_SSID: &[u8] = b"superior-test";
const WIFI_PASSPHRASE: &[u8] = b"correct horse battery staple";
/// Ticks to wait for the link to come up.
const LINK_TICKS: u64 = 3000;
const WIFI_PINGS: u64 = 10;
const WIFI_ECHOES: u64 = 40;

/// Asks the radio to join `ssid` with `pass`: the reply's status.
fn wifi_join(ssid: &[u8], pass: &[u8]) -> u64 {
    let page = net_page();
    page[..ssid.len()].copy_from_slice(ssid);
    page[ssid.len()..ssid.len() + pass.len()].copy_from_slice(pass);
    let x = CapTransfer {
        grant: Some(NET_PAGE as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, RADIO, [nic::JOIN, ssid.len() as u64, pass.len() as u64, 0], x);
    if r.status == 0 { r.msg[0] } else { u64::MAX }
}

/// The networks a survey found: each one's entry as `NETWORKS` wrote it.
type Networks = ([[u8; nic::network::SIZE]; nic::network::MAX], usize);

/// Has the radio survey the networks in range (`SCAN`), then asks for them
/// (`NETWORKS`) until the survey is done. Also returns whether a second
/// `SCAN` during the survey was refused with `InUse`.
fn wifi_survey() -> Option<(Networks, bool)> {
    let r = syscall(Syscall::Call, RADIO, [nic::SCAN, 0, 0, 0]);
    if r.status != 0 || r.msg[0] != OK {
        return None;
    }
    let again = syscall(Syscall::Call, RADIO, [nic::SCAN, 0, 0, 0]).msg[0] == Status::InUse as u64;
    let start = ticks();
    while ticks() < start + LINK_TICKS {
        superior_sys::sleep(5);
        let x = CapTransfer {
            grant: Some(NET_PAGE as u16),
            accept: None,
        };
        let r = syscall_x(Syscall::Call, RADIO, [nic::NETWORKS, 0, 0, 0], x);
        if r.status == 0 && r.msg[0] == OK {
            let page = net_page();
            let n = (r.msg[1] as usize).min(nic::network::MAX);
            let mut out = [[0u8; nic::network::SIZE]; nic::network::MAX];
            for (i, e) in out.iter_mut().enumerate().take(n) {
                e.copy_from_slice(&page[i * nic::network::SIZE..(i + 1) * nic::network::SIZE]);
            }
            return Some(((out, n), again));
        }
    }
    None
}

/// The networks the Wi-Fi test's harness puts in range, strongest first:
/// SSID, security, channel, signal (dBm).
const WIFI_IN_RANGE: [(&[u8], u8, u8, i8); 3] = [
    (b"superior-test", nic::security::WPA2_PSK, 6, -45),
    (b"superior-wpa3", nic::security::WPA3_SAE, 6, -60),
    (b"superior-guest", nic::security::OPEN, 11, -71),
];

/// Whether a survey found just the networks the harness puts in range, in
/// order of signal.
fn wifi_found_all(found: &Networks) -> bool {
    use nic::network as at;
    let (list, n) = found;
    *n == WIFI_IN_RANGE.len()
        && list.iter().zip(WIFI_IN_RANGE).all(|(e, (ssid, security, channel, signal))| {
            let len = e[at::SSID_LEN] as usize;
            &e[at::SSID..at::SSID + len] == ssid && e[at::SECURITY] == security && e[at::CHANNEL] == channel && e[at::SIGNAL] as i8 == signal
        })
}

fn wifi_client() -> ! {
    let mut t = Checks(0, "wifi");
    let made = syscall(Syscall::Retype, NET_MEMORY, [ObjectType::Frame as u64, 0, NET_PAGE, 0]);
    let mapped = syscall(Syscall::FrameMap, NET_PAGE, [NET_PAGE_VA, 1, 0, 0]);
    t.check(made.status == 0 && mapped.status == 0, format_args!("a page of its own"));
    // The nonces come from the kernel's entropy pool.
    let (r1, r2) = (superior_sys::random(), superior_sys::random());
    t.check(
        matches!((r1, r2), (Some(a), Some(b)) if a != b && a != [0; 32] && b != [0; 32]),
        format_args!("the kernel gives random bytes, a fresh 32 at every draw"),
    );
    let link = || syscall(Syscall::Call, RADIO, [nic::LINK, 0, 0, 0]).msg;
    let before = link();
    t.check(
        before[0] == OK && before[1] == nic::link::IDLE,
        format_args!("the radio starts with no network (link {})", before[1]),
    );
    let survey = wifi_survey();
    let (found, refused_again) = survey.unwrap_or((([[0; nic::network::SIZE]; nic::network::MAX], 0), false));
    t.check(
        survey.is_some() && wifi_found_all(&found),
        format_args!(
            "a survey finds the {} networks in range, strongest first: superior-test (WPA2-PSK, ch 6, -45 dBm), superior-wpa3 (WPA3-SAE, ch 6, -60), superior-guest (open, ch 11, -71)",
            found.1
        ),
    );
    t.check(refused_again, format_args!("a second scan during a survey is refused (in use)"));
    t.check(
        link()[1] == nic::link::IDLE,
        format_args!("surveying joined nothing"),
    );
    t.check(
        wifi_join(WIFI_SSID, b"short") == Status::Invalid as u64,
        format_args!("a passphrase under 8 characters is refused"),
    );
    t.check(
        wifi_join(WIFI_SSID, WIFI_PASSPHRASE) == OK,
        format_args!("the radio is told to join \"superior-test\""),
    );
    let start = ticks();
    let mut l = link();
    while l[1] != nic::link::UP && ticks() < start + LINK_TICKS {
        superior_sys::sleep(5);
        l = link();
    }
    let b = l[2].to_be_bytes();
    t.check(
        l[0] == OK && l[1] == nic::link::UP,
        format_args!(
            "joined and keyed in {} ms: BSSID {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            (ticks() - start) * 10,
            b[2], b[3], b[4], b[5], b[6], b[7]
        ),
    );
    // The network server sees an ordinary card: DHCP over the link.
    let ask = |op: u64| {
        let start = ticks();
        loop {
            let r = syscall(Syscall::Call, NET, [op, net::VERSION, 0, 0]);
            if r.status == 0 && r.msg[0] == OK {
                return Some(r.msg);
            }
            if ticks() > start + LEASE_TICKS {
                return None;
            }
            superior_sys::sleep(1);
        }
    };
    let info = ask(net::INFO).unwrap_or([0; 4]);
    let lease = ask(net::LEASE).unwrap_or([0; 4]);
    t.check(
        info[1] != 0 && info[3] != 0 && lease[1] != 0,
        format_args!(
            "leased {} (netmask /{}) over Wi-Fi, the gateway {}",
            Dotted(info[1]),
            (lease[1] as u32).count_ones(),
            Dotted(info[3])
        ),
    );
    let gw = info[3];
    let mut answered = 0;
    if let Some(mut s) = Sock::new(false) {
        for seq in 0..WIFI_PINGS {
            let to = gw | seq;
            answered += s.exchange(
                to,
                56,
                |b| {
                    for (j, x) in b[..56].iter_mut().enumerate() {
                        *x = echo_byte(seq, j as u64);
                    }
                },
                |len, b, from| from == to && len == 56 && b.iter().enumerate().all(|(j, &x)| x == echo_byte(seq, j as u64)),
            ) as u64;
        }
    }
    t.check(
        answered == WIFI_PINGS,
        format_args!("{answered} of {WIFI_PINGS} pings to the gateway answered, every byte right"),
    );
    let (mut echoed, mut fragmented) = (0, 0);
    if let Some(mut s) = Sock::new(true) {
        let to = gw | ECHO_PORT as u64;
        for k in 0..WIFI_ECHOES {
            let len = echo_len(k);
            let ok = s.exchange(
                to,
                len,
                |b| {
                    for j in 0..len {
                        b[j as usize] = echo_at(k, j);
                    }
                },
                |n, b, from| from == to && n == len && b.iter().enumerate().all(|(j, &x)| x == echo_at(k, j as u64)),
            );
            echoed += ok as u64;
            fragmented += (ok && len > 1472) as u64;
        }
    }
    t.check(
        echoed == WIFI_ECHOES && fragmented > 0,
        format_args!("{echoed} of {WIFI_ECHOES} UDP datagrams echoed by the gateway, every byte right ({fragmented} of them in fragments)"),
    );
    // The access point renewed the keys while those went to and fro (it
    // does after so many frames), and none was lost to it.
    let l = link();
    let (pairwise, group) = (l[3] >> 32, l[3] & 0xffff_ffff);
    t.check(
        l[1] == nic::link::UP && pairwise >= 1 && group >= 1,
        format_args!("the keys were renewed under way, {pairwise} times pairwise and {group} the group key, the link still up"),
    );
    // A survey while linked: the link stays up.
    let again = wifi_survey();
    t.check(
        again.is_some_and(|(f, _)| wifi_found_all(&f)) && link()[1] == nic::link::UP,
        format_args!("a survey while linked finds the same networks, and the link stays up"),
    );
    // WPA3: the same network through the SAE-only access point.
    t.check(
        wifi_join(b"superior-wpa3", WIFI_PASSPHRASE) == OK,
        format_args!("the radio is told to join \"superior-wpa3\""),
    );
    let start = ticks();
    let mut l = link();
    while l[1] != nic::link::UP && ticks() < start + LINK_TICKS {
        superior_sys::sleep(5);
        l = link();
    }
    let b = l[2].to_be_bytes();
    t.check(
        l[0] == OK && l[1] == nic::link::UP && l[2] >> 48 == nic::suite::WPA3_SAE,
        format_args!(
            "joined by SAE and keyed in {} ms: BSSID {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, WPA3-SAE",
            (ticks() - start) * 10,
            b[2], b[3], b[4], b[5], b[6], b[7]
        ),
    );
    // The harness forges a deauthentication now; it must change nothing.
    superior_sys::sleep(30);
    let mut answered = 0;
    if let Some(mut s) = Sock::new(false) {
        for seq in 0..WIFI_PINGS {
            let to = gw | seq;
            answered += s.exchange(
                to,
                56,
                |b| {
                    for (j, x) in b[..56].iter_mut().enumerate() {
                        *x = echo_byte(seq, j as u64);
                    }
                },
                |len, b, from| from == to && len == 56 && b.iter().enumerate().all(|(j, &x)| x == echo_byte(seq, j as u64)),
            ) as u64;
        }
    }
    t.check(
        answered == WIFI_PINGS && link()[1] == nic::link::UP,
        format_args!("{answered} of {WIFI_PINGS} pings answered over WPA3, the link up through a forged deauthentication"),
    );
    syscall(Syscall::Call, NET_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

fn subscribe() -> bool {
    for _ in 0..2000 {
        syscall(Syscall::CapDelete, INPUT_NTFN, [0; 4]);
        let x = CapTransfer {
            grant: None,
            accept: Some(INPUT_NTFN as u16),
        };
        let r = syscall_x(Syscall::Call, INPUT, [input::SUBSCRIBE, input::VERSION, 0, 0], x);
        if r.status == 0 && r.msg[0] == OK && r.cap == Some(INPUT_NTFN as u16) {
            return true;
        }
        superior_sys::sleep(1);
    }
    false
}

/// The host types "superior " over and over on a USB keyboard while the
/// injector kills the HID driver and the xHCI driver. Every word typed
/// between restarts must come through whole, and nothing but the keys
/// typed may ever arrive.
fn keyboard_client() -> ! {
    let mut t = Checks(0, "keyboard");
    t.check(subscribe(), format_args!("subscribed to the keyboard"));
    let (mut whole, mut broken, mut strays, mut resubscribed) = (0u64, 0u64, 0u64, 0u64);
    let mut word = [0u8; 16];
    let mut len = 0;
    let start = ticks();
    let mut first = None;
    'typing: while (whole < WORDS || ticks() < start + TYPING_TICKS) && ticks() < start + TYPING_LIMIT {
        loop {
            let r = syscall(Syscall::Call, INPUT, [input::READ, 0, 0, 0]);
            if r.status != 0 || (r.msg[0] != OK && r.msg[0] != Status::Empty as u64) {
                // Restarted: subscribe again.
                resubscribed += 1;
                subscribe();
                continue 'typing;
            }
            if r.msg[0] == Status::Empty as u64 {
                break;
            }
            let (key, pressed) = (r.msg[2], r.msg[3] & 1 == 1);
            if r.msg[1] != input::KEY {
                strays += 1;
                continue;
            }
            if !pressed {
                continue;
            }
            match key {
                0x2c => {
                    if &word[..len] == WORD {
                        whole += 1;
                        if first.is_none() {
                            first = Some(ticks());
                            say!("keyboard: the first whole word came through");
                        }
                    } else if len > 0 {
                        broken += 1;
                    }
                    len = 0;
                }
                4..=29 => {
                    let c = b'a' + (key - 4) as u8;
                    if !WORD.contains(&c) {
                        strays += 1;
                    }
                    if len < word.len() {
                        word[len] = c;
                        len += 1;
                    }
                }
                _ => strays += 1,
            }
        }
        syscall(Syscall::TimerSignal, INPUT_NTFN, [20, 0, 0, 0]);
        if syscall(Syscall::Wait, INPUT_NTFN, [0; 4]).status != 0 {
            // The notification is gone: the driver restarted.
            resubscribed += 1;
            subscribe();
        }
    }
    t.check(
        whole >= WORDS && strays == 0,
        format_args!(
            "{whole} words typed on the USB keyboard came through whole, no key that was not typed ({broken} broken by restarts, {strays} stray keys, {resubscribed} subscriptions again)"
        ),
    );
    syscall(Syscall::Call, INPUT_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

// ---- the display client (`arg 24`, boot/display.manifest) ----

const DISPLAY: u64 = 0;
const DISPLAY_CONTROL: u64 = 1;
const DISPLAY_MEMORY: u64 = 2;
/// The surface's pages, mapped in a row.
const SURFACE: u64 = 8;
const SURFACE_VA: u64 = USER_BASE + 0x4000_0000;
/// The driver's component, which this client kills halfway.
const DISPLAY_DRIVER_INDEX: u64 = 1;
/// The size `cargo xtask display-test` gives QEMU's display, which its
/// EDID must report as preferred.
const SCREEN: (u64, u64) = (800, 600);
/// The rectangle the second flush of the first picture redraws.
const PATCH: (u64, u64, u64, u64) = (100, 150, 320, 200);
/// Ticks the host gets to take a screenshot of each picture.
const SCREENSHOT_TICKS: u64 = 300;

/// The test picture's pixel at (x, y) in phase `phase` (XRGB8888). `cargo
/// xtask display-test` computes the same to check the screenshots.
fn test_pixel(x: u64, y: u64, phase: u64) -> u32 {
    let r = (x + 64 * phase) & 0xff;
    let g = (y + 32 * phase) & 0xff;
    let b = (((x >> 3) ^ (y >> 3)) * 8 + 16 * phase) & 0xff;
    (r << 16 | g << 8 | b) as u32
}

fn draw(x0: u64, y0: u64, w: u64, h: u64, phase: u64) {
    let pitch = SCREEN.0;
    for y in y0..y0 + h {
        for x in x0..x0 + w {
            // SAFETY: the surface's pages are mapped, writable, and hold
            // the whole screen.
            unsafe { ((SURFACE_VA as *mut u32).add((y * pitch + x) as usize)).write(test_pixel(x, y, phase)) };
        }
    }
}

fn rect(x: u64, y: u64, w: u64, h: u64) -> u64 {
    x | y << 16 | w << 32 | h << 48
}

/// A display call; after a restart, retried until the new instance
/// answers.
fn display_call(m: [u64; 4], page: Option<u64>) -> [u64; 4] {
    let x = CapTransfer {
        grant: page.map(|p| (SURFACE + p) as u16),
        accept: None,
    };
    for _ in 0..100 {
        let r = syscall_x(Syscall::Call, DISPLAY, m, x);
        if r.status == 0 {
            return r.msg;
        }
        superior_sys::sleep(5);
    }
    [u64::MAX; 4]
}

/// Lends the surface and shows the preferred mode: the mode's index.
fn display_set_up(t: &mut Checks, pages: u64, first: bool) -> Option<u64> {
    let info = display_call(display::info(), None);
    let (modes, preferred, edid) = (info[1], info[2], info[3]);
    let m = display_call(display::mode(preferred), None);
    if first {
        t.check(
            info[0] == 0 && edid == 1 && modes > 1 && m[0] == 0 && (m[1], m[2]) == SCREEN,
            format_args!(
                "the display's EDID gives {modes} modes, {}x{} at {} Hz preferred",
                m[1], m[2], m[3]
            ),
        );
    }
    let lent = (0..pages).all(|p| display_call(display::attach(p), Some(p))[0] == 0);
    let r = display_call(display::set_mode(preferred), None);
    t.check(
        lent && r[0] == 0 && r[1] == SCREEN.0 * 4 && r[2] != r[3],
        format_args!(
            "{pages} surface pages lent; {}x{} shown, pitch {}, framebuffers at {:#x} and {:#x}",
            SCREEN.0, SCREEN.1, r[1], r[2], r[3]
        ),
    );
    (r[0] == 0).then_some(preferred)
}

// ---- the desktop clients (`arg 25` and `arg 26`, boot/desktop.manifest) ----

const WINDOWS: u64 = 0;
const DESKTOP_CONTROL: u64 = 1;
const WINDOW_MEMORY: u64 = 2;
/// The window's pages, mapped in a row.
const WINDOW_PAGE_SLOTS: u64 = 8;
const WINDOW_VA: u64 = USER_BASE + 0x4000_0000;
/// Components the second client kills: the display driver, the
/// compositor and the first client.
const DESKTOP_DRIVER_INDEX: u64 = 1;
const COMPOSITOR_INDEX: u64 = 2;
const FIRST_CLIENT_INDEX: u64 = 3;
/// The screen `cargo xtask desktop-test` gives QEMU's display.
const DESKTOP_SCREEN: (u64, u64) = (800, 600);

/// A window of the test: its number in the picture, size, position and
/// phase, and the compositor's number for it while it has one.
struct TestWindow {
    id: u64,
    size: (u64, u64),
    at: (u64, u64),
    phase: u64,
    window: Option<u64>,
}

impl TestWindow {
    fn pages(&self) -> u64 {
        (self.size.0 * self.size.1 * 4).div_ceil(4096)
    }
}

/// Window `id`'s pixel at (x, y) of it in phase `phase` (XRGB8888). `cargo
/// xtask desktop-test` computes the same to check the screenshots.
fn window_pixel(x: u64, y: u64, id: u64, phase: u64) -> u32 {
    let r = (2 * x + 80 * id + 40 * phase) & 0xff;
    let g = (2 * y + 50 * id) & 0xff;
    let b = ((x ^ y) + 30 * phase) & 0xff;
    (r << 16 | g << 8 | b) as u32
}

fn draw_window(w: &TestWindow) {
    for y in 0..w.size.1 {
        for x in 0..w.size.0 {
            // SAFETY: the window's pages are mapped, writable, and hold it.
            unsafe {
                ((WINDOW_VA as *mut u32).add((y * w.size.0 + x) as usize)).write(window_pixel(x, y, w.id, w.phase))
            };
        }
    }
}

/// A call to the compositor: `Err` if it failed (the compositor
/// restarted), else the reply.
fn window_call(m: [u64; 4], page: Option<u64>) -> Result<[u64; 4], ()> {
    let x = CapTransfer {
        grant: page.map(|p| (WINDOW_PAGE_SLOTS + p) as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, WINDOWS, m, x);
    if r.status == 0 { Ok(r.msg) } else { Err(()) }
}

/// The compositor's `INFO`, tried again while it restarts.
fn window_info() -> [u64; 4] {
    for _ in 0..200 {
        if let Ok(m) = window_call(window::info(), None) {
            return m;
        }
        superior_sys::sleep(5);
    }
    [u64::MAX; 4]
}

/// Waits until `shown` windows are on the screen; whether they came.
fn wait_shown(shown: u64) -> bool {
    for _ in 0..500 {
        if window_info()[3] == shown {
            return true;
        }
        superior_sys::sleep(2);
    }
    false
}

/// Makes the window, lends its pages and shows all of it; again from the
/// start if the compositor restarts on the way. The reply to the commit.
fn open_window(w: &mut TestWindow) -> [u64; 4] {
    open_styled(w, 0)
}

/// As [`open_window`], the window given `style` before it is shown.
fn open_styled(w: &mut TestWindow, style: u64) -> [u64; 4] {
    for _ in 0..50 {
        w.window = None;
        let size = w.size.0 | w.size.1 << 16;
        let Ok(r) = window_call(window::create(size, w.at.0 | w.at.1 << 16), None) else {
            superior_sys::sleep(5);
            continue;
        };
        if r[0] != 0 {
            return r;
        }
        let n = r[1];
        let lent = (0..w.pages()).try_for_each(|p| match window_call(window::attach(n, p), Some(p)) {
            Ok(m) if m[0] == 0 => Ok(()),
            _ => Err(()),
        });
        if lent.is_err() {
            continue;
        }
        if style != 0 {
            match window_call(window::style(n, style), None) {
                Ok(m) if m[0] == 0 => {}
                Ok(m) => return m,
                Err(()) => continue,
            }
        }
        let full = w.size.0 << 32 | w.size.1 << 48;
        if let Ok(m) = window_call(window::commit(n, full), None) {
            if m[0] == 0 {
                w.window = Some(n);
            }
            return m;
        }
    }
    [u64::MAX; 4]
}

fn make_window_pages(t: &mut Checks, w: &TestWindow) {
    let mut made = true;
    for p in 0..w.pages() {
        made &= syscall(Syscall::Retype, WINDOW_MEMORY, [ObjectType::Frame as u64, 0, WINDOW_PAGE_SLOTS + p, 0]).status
            == 0
            && syscall(Syscall::FrameMap, WINDOW_PAGE_SLOTS + p, [WINDOW_VA + p * 4096, 1, 0, 0]).status == 0;
    }
    t.check(made, format_args!("{} pages for a {}x{} window", w.pages(), w.size.0, w.size.1));
    draw_window(w);
}

/// The first client: shows window A and keeps it shown, making it again
/// whenever the compositor restarts, until the second client kills it.
fn desktop_first() -> ! {
    let mut t = Checks(0, "desktop");
    let mut w = TestWindow { id: 0, size: (300, 200), at: (100, 100), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    let r = open_window(&mut w);
    t.check(
        r[0] == 0 && w.window.is_some(),
        format_args!("window A shown (window {})", w.window.unwrap_or(u64::MAX)),
    );
    loop {
        superior_sys::sleep(5);
        // Moving it where it is changes nothing, but a compositor that
        // restarted (whether or not this call saw it) knows no such window.
        let here = w.window.map(|n| window_call(window::move_to(n, w.at.0 | w.at.1 << 16), None));
        if here != Some(Ok([0; 4])) {
            say!("desktop: window A: the compositor restarted; making the window again");
            let r = open_window(&mut w);
            t.check(r[0] == 0, format_args!("window A made again after the compositor's restart"));
        }
    }
}

/// The second client: shows window B over A, moves it, and has the
/// compositor, the first client and the display driver killed in turn;
/// the host checks a screenshot of each picture.
fn desktop_second() -> ! {
    let mut t = Checks(0, "desktop");
    let mut w = TestWindow { id: 1, size: (320, 240), at: (250, 180), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    let info = window_info();
    t.check(
        info[0] == 0 && (info[1], info[2]) == DESKTOP_SCREEN,
        format_args!("the screen is {}x{}", info[1], info[2]),
    );
    t.check(wait_shown(1), format_args!("window A is on the screen"));
    // No window but its own is the client's, whichever number it tries.
    let mut refused = 0;
    for n in 0..window::MAX_WINDOWS {
        for m in [window::move_to(n, 0), window::raise(n), window::destroy(n), window::commit(n, 1 << 32 | 1 << 48)] {
            refused += (window_call(m, None) == Ok([Status::NotFound as u64, 0, 0, 0])) as u64;
        }
    }
    t.check(
        refused == 4 * window::MAX_WINDOWS,
        format_args!("another client's window cannot be moved, raised, destroyed or drawn ({refused} calls refused)"),
    );
    let r = open_window(&mut w);
    t.check(
        r[0] == 0 && window_info()[3] == 2,
        format_args!("picture 1 on the screen: window B over window A (frame {})", r[1]),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    w.at = (420, 300);
    let moved = w.window.map(|n| window_call(window::move_to(n, w.at.0 | w.at.1 << 16), None));
    t.check(
        moved == Some(Ok([0; 4])),
        format_args!("picture 2 on the screen: window B moved, and what it covered painted again"),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    say!("desktop: killing the compositor");
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_KILL, COMPOSITOR_INDEX, 0, 0]);
    // Window A first, so it is behind again.
    let back = wait_shown(1);
    let r = open_window(&mut w);
    t.check(
        back && r[0] == 0 && window_info()[3] == 2,
        format_args!("picture 3 on the screen after the compositor's restart: both windows made again"),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    say!("desktop: killing window A's client");
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_KILL, FIRST_CLIENT_INDEX, 0, 0]);
    t.check(wait_shown(1), format_args!("picture 4 on the screen: window A gone with its client"));
    superior_sys::sleep(SCREENSHOT_TICKS);
    say!("desktop: killing the display driver");
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_KILL, DESKTOP_DRIVER_INDEX, 0, 0]);
    w.phase = 1;
    draw_window(&w);
    let full = w.size.0 << 32 | w.size.1 << 48;
    let r = w.window.map(|n| window_call(window::commit(n, full), None));
    t.check(
        matches!(r, Some(Ok(m)) if m[0] == 0),
        format_args!("picture 5 on the screen after the display driver's restart: window B drawn anew"),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    say!("desktop: done ({} failed)", t.0);
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

// ---- the input clients (`arg 27` and `arg 28`, boot/input.manifest) ----

/// The notification the compositor signals when a window has events.
const WINDOW_NTFN: u64 = 5;
/// Components the second input client kills: the input driver and the
/// compositor.
const INPUT_DRIVER_INDEX: u64 = 2;
const INPUT_COMPOSITOR_INDEX: u64 = 4;

/// An event the compositor gave a window.
enum WindowEvent {
    /// A key's usage, and whether it went down.
    Key(u64, bool),
    /// Where the pointer is in the window, and the buttons held.
    Pointer(i64, i64, u64),
    Focus(bool),
    Leave,
    /// Where the pointer is in the window, and the steps up and right.
    Wheel(i64, i64, i64, i64),
    /// Its close box was pressed.
    Close,
    /// It was dragged by its title bar to here.
    Moved(u64, u64),
}

/// Makes the notification the compositor is to signal.
fn make_window_ntfn() {
    syscall(Syscall::Retype, WINDOW_MEMORY, [ObjectType::Notification as u64, 0, WINDOW_NTFN, 0]);
}

/// Lends the compositor the notification to signal when window `w` has
/// events; whether it took it.
fn listen(w: &TestWindow) -> bool {
    let Some(n) = w.window else { return false };
    let x = CapTransfer {
        grant: Some(WINDOW_NTFN as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, WINDOWS, window::listen(n), x);
    r.status == 0 && r.msg[0] == OK
}

/// Window `w`'s next event, if it has one.
fn next_event(w: &TestWindow) -> Option<WindowEvent> {
    let n = w.window?;
    let m = window_call(window::next(n), None).ok().filter(|m| m[0] == OK)?;
    Some(match m[1] {
        window::KEY => WindowEvent::Key(m[2], m[3] & 1 == 1),
        window::POINTER => WindowEvent::Pointer(m[2] as u16 as i16 as i64, (m[2] >> 16) as u16 as i16 as i64, m[3]),
        window::FOCUS => WindowEvent::Focus(m[2] == 1),
        window::CLOSE => WindowEvent::Close,
        window::MOVED => WindowEvent::Moved(m[2] & 0xffff, (m[2] >> 16) & 0xffff),
        window::WHEEL => WindowEvent::Wheel(
            m[2] as u16 as i16 as i64,
            (m[2] >> 16) as u16 as i16 as i64,
            m[3] as u32 as i32 as i64,
            (m[3] >> 32) as u32 as i32 as i64,
        ),
        _ => WindowEvent::Leave,
    })
}

/// Sleeps until the compositor signals or `ticks` pass.
fn wait_events(ticks: u64) {
    syscall(Syscall::TimerSignal, WINDOW_NTFN, [ticks, 0, 0, 0]);
    syscall(Syscall::Wait, WINDOW_NTFN, [0; 4]);
}

/// The letter a key's usage stands for (`?` for any other key).
fn letter(usage: u64) -> u8 {
    if (4..=29).contains(&usage) { b'a' + (usage - 4) as u8 } else { b'?' }
}

/// Draws the window in its next phase and shows all of it.
fn draw_next(w: &mut TestWindow) {
    w.phase += 1;
    draw_window(w);
    let full = w.size.0 << 32 | w.size.1 << 48;
    if let Some(n) = w.window {
        let _ = window_call(window::commit(n, full), None);
    }
}

/// Waits until the compositor has done everything it was doing (it does
/// one thing at a time): what the client says next is on the screen.
fn settled() {
    window_info();
}

/// The first input client: shows window A, draws it anew at each key it
/// gets, and says where the pointer came and when it was clicked; makes
/// its window again whenever the compositor restarts.
fn input_first() -> ! {
    let mut t = Checks(0, "input");
    let mut w = TestWindow { id: 0, size: (300, 200), at: (100, 100), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    make_window_ntfn();
    let r = open_window(&mut w);
    t.check(r[0] == 0 && listen(&w), format_args!("window A shown"));
    let mut typed = [0u8; 8];
    let mut keys = 0;
    let (mut arrivals, mut clicks, mut held, mut focused) = (0, 0, 0, false);
    loop {
        wait_events(5);
        while let Some(e) = next_event(&w) {
            match e {
                WindowEvent::Key(k, true) => {
                    if keys < typed.len() {
                        typed[keys] = letter(k);
                    }
                    keys += 1;
                    draw_next(&mut w);
                    if keys == 3 && &typed[..3] == b"abc" {
                        settled();
                        t.check(true, format_args!("window A: typed \"abc\", drawn anew at each key"));
                    } else if keys > 3 || typed[keys - 1] != b"abc"[keys - 1] {
                        t.check(false, format_args!("window A got key '{}', not typed to it", letter(k) as char));
                    }
                }
                WindowEvent::Pointer(x, y, b) => {
                    if (x, y) == (50, 30) && b == 0 && held == 0 {
                        arrivals += 1;
                        settled();
                        say!("input: window A: the pointer came to (50, 30) (time {arrivals})");
                    }
                    if (x, y) == (50, 30) && b == 0 && held & 1 != 0 {
                        clicks += 1;
                        settled();
                        t.check(
                            focused,
                            format_args!(
                                "window A: clicked at (50, 30), so it has the focus and is in front (time {clicks})"
                            ),
                        );
                    }
                    held = b;
                }
                WindowEvent::Focus(f) => focused = f,
                _ => {}
            }
        }
        // Moving it where it is changes nothing, but a compositor that
        // restarted knows no such window.
        let here = w.window.map(|n| window_call(window::move_to(n, w.at.0 | w.at.1 << 16), None));
        if here != Some(Ok([0; 4])) {
            say!("input: window A: the compositor restarted; making the window again");
            let r = open_window(&mut w);
            t.check(
                r[0] == 0 && listen(&w),
                format_args!("window A made again after the compositor's restart"),
            );
            (held, focused) = (0, false);
        }
    }
}

/// Where the tablet puts the pointer in window B, at the end of the input
/// test: (460, 300) on the screen, over B alone.
const TABLET_AT: (i64, i64) = (160, 100);

/// The second input client: shows window B over A and checks the pointer
/// and keys it gets as the host moves the mouse, clicks and types; has
/// the compositor and the input driver killed in turn; then checks where
/// the tablet puts the pointer and the steps the wheel turns.
fn input_second() -> ! {
    let mut t = Checks(0, "input");
    let mut w = TestWindow { id: 1, size: (320, 240), at: (300, 200), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    make_window_ntfn();
    t.check(wait_shown(1), format_args!("window A is on the screen"));
    let r = open_window(&mut w);
    t.check(r[0] == 0 && listen(&w), format_args!("window B shown"));
    let mut typed = [0u8; 8];
    let mut keys = 0;
    let (mut held, mut focused, mut leaves) = (0, false, 0);
    let (mut came, mut press_at, mut announced, mut made_again) = (false, None, false, None);
    // The tablet and the wheel, last: whether they are next, whether the
    // tablet put the pointer on B, and the steps up and down.
    let (mut tablet, mut tablet_came, mut ups, mut downs, mut wheel_here) = (false, false, 0, 0, true);
    loop {
        wait_events(5);
        while let Some(e) = next_event(&w) {
            match e {
                WindowEvent::Focus(f) => {
                    focused = f;
                    if f && !announced {
                        announced = true;
                        settled();
                        t.check(true, format_args!("window B shown over window A, with the focus"));
                    }
                    if f && made_again.take().is_some() {
                        settled();
                        t.check(true, format_args!("window B made again after the compositor's restart, with the focus"));
                    }
                    if !f && keys == 3 {
                        settled();
                        t.check(true, format_args!("window B lost the focus to window A: picture 6 on the screen"));
                        superior_sys::sleep(SCREENSHOT_TICKS);
                        t.check(
                            &typed[..3] == b"def" && leaves > 0,
                            format_args!(
                                "window B got only the keys typed to it (\"{}\") and was told the pointer left it {leaves} time{}",
                                core::str::from_utf8(&typed[..3]).unwrap_or("?"),
                                if leaves == 1 { "" } else { "s" }
                            ),
                        );
                        tablet = true;
                    }
                }
                WindowEvent::Pointer(x, y, b) if tablet => {
                    if (x, y) == TABLET_AT && b == 0 && !tablet_came {
                        tablet_came = true;
                        settled();
                        say!("input: window B: the tablet put the pointer at ({x}, {y})");
                    }
                }
                WindowEvent::Wheel(x, y, up, right) if tablet_came => {
                    if up > 0 {
                        ups += up;
                    } else {
                        downs -= up;
                    }
                    wheel_here &= (x, y) == TABLET_AT;
                    if right != 0 {
                        t.check(false, format_args!("window B: the wheel turned {right} steps right"));
                    }
                    if ups == 2 && downs == 0 {
                        say!("input: window B: the wheel turned 2 steps up");
                    }
                    if ups == 2 && downs == 1 {
                        settled();
                        t.check(
                            wheel_here,
                            format_args!(
                                "window B: the wheel turned 2 steps up and 1 down, the pointer at ({x}, {y}): picture 7 on the screen"
                            ),
                        );
                        superior_sys::sleep(SCREENSHOT_TICKS);
                        say!("input: done ({} failed)", t.0);
                        syscall(Syscall::Call, DESKTOP_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
                        superior_sys::park()
                    }
                }
                WindowEvent::Pointer(x, y, b) => {
                    if (x, y) == (200, 150) && b == 0 && held == 0 && !came {
                        came = true;
                        say!("input: window B: the pointer came to (200, 150)");
                    }
                    if b & 1 != 0 && held == 0 {
                        press_at = Some((x, y));
                    }
                    if b == 0 && held & 1 != 0 {
                        let outside = !(0..320).contains(&x) || !(0..240).contains(&y);
                        let from = press_at.take().unwrap_or((-1, -1));
                        t.check(
                            from == (200, 150) && (x, y) == (400, 250) && outside && focused,
                            format_args!(
                                "window B: held the pointer from ({}, {}) to ({x}, {y}), outside it, and let it go",
                                from.0, from.1
                            ),
                        );
                    }
                    held = b;
                }
                WindowEvent::Leave => leaves += 1,
                WindowEvent::Key(k, true) => {
                    if keys < typed.len() {
                        typed[keys] = letter(k);
                    }
                    keys += 1;
                    draw_next(&mut w);
                    settled();
                    match keys {
                        1 => {
                            t.check(
                                typed[0] == b'd',
                                format_args!("window B: typed \"d\", the first key it got: picture 4 on the screen"),
                            );
                            superior_sys::sleep(SCREENSHOT_TICKS);
                            say!("input: killing the compositor");
                            syscall(Syscall::Call, DESKTOP_CONTROL, [OP_KILL, INPUT_COMPOSITOR_INDEX, 0, 0]);
                            // Window A first, so it is behind again.
                            let back = wait_shown(1);
                            let r = open_window(&mut w);
                            t.check(back && r[0] == 0 && listen(&w), format_args!("window B made again"));
                            (held, focused, made_again) = (0, false, Some(()));
                        }
                        2 => {
                            t.check(&typed[..2] == b"de", format_args!("window B: typed \"de\""));
                            superior_sys::sleep(SCREENSHOT_TICKS);
                            say!("input: killing the input driver");
                            syscall(Syscall::Call, DESKTOP_CONTROL, [OP_KILL, INPUT_DRIVER_INDEX, 0, 0]);
                        }
                        3 => t.check(
                            &typed[..3] == b"def",
                            format_args!("window B: typed \"def\" after the input driver's restart"),
                        ),
                        _ => t.check(false, format_args!("window B got key '{}', not typed to it", letter(k) as char)),
                    }
                }
                _ => {}
            }
        }
    }
}

// ---- the window style clients (`arg 37` and `arg 38`, boot/windows.manifest) ----

/// How opaque window B's pixel at (x, y) of it is. `cargo xtask
/// windows-test` computes the same to check the screenshots.
fn translucence(x: u64, y: u64) -> u64 {
    (x * 3 + y) & 0xff
}

/// Window A of the window style test: decorated, opaque; the host drags
/// it by its title bar.
fn styled_first() -> ! {
    let mut t = Checks(0, "windows");
    let mut w = TestWindow { id: 0, size: (300, 200), at: (100, 120), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    make_window_ntfn();
    let r = open_styled(&mut w, window::DECORATED);
    t.check(r[0] == 0 && listen(&w), format_args!("window A shown, decorated"));
    let mut pointed = 0;
    loop {
        wait_events(5);
        while let Some(e) = next_event(&w) {
            match e {
                // The pointer may cross it on its way to the title bar; from
                // the press there (which gives it the focus) it gets none.
                WindowEvent::Focus(true) => pointed = 0,
                WindowEvent::Pointer(..) => pointed += 1,
                WindowEvent::Moved(x, y) => {
                    settled();
                    t.check(
                        (x, y) == (300, 270) && pointed == 0,
                        format_args!(
                            "window A dragged by its title bar to ({x}, {y}), in front, with the focus, \
                             and no pointer events of its own ({pointed}): picture 2 on the screen"
                        ),
                    );
                }
                _ => {}
            }
        }
    }
}

/// Window B of the window style test: translucent and decorated, over
/// window A; the host presses its close box, and it closes.
fn styled_second() -> ! {
    let mut t = Checks(0, "windows");
    let mut w = TestWindow { id: 1, size: (320, 240), at: (300, 220), phase: 0, window: None };
    make_window_pages(&mut t, &w);
    for y in 0..w.size.1 {
        for x in 0..w.size.0 {
            let p = window_pixel(x, y, w.id, w.phase) | (translucence(x, y) << 24) as u32;
            // SAFETY: the window's pages are mapped, writable, and hold it.
            unsafe { ((WINDOW_VA as *mut u32).add((y * w.size.0 + x) as usize)).write(p) };
        }
    }
    make_window_ntfn();
    t.check(wait_shown(1), format_args!("window A is on the screen"));
    // A window whose frame would reach off the screen is refused its
    // decorations, and a decorated one may not be moved there.
    let corner = window_call(window::create(10 | 10 << 16, 0), None).map(|m| m[1]).unwrap_or(u64::MAX);
    let off = window_call(window::style(corner, window::DECORATED), None).map(|m| m[0]);
    let odd = window_call(window::style(corner, 8), None).map(|m| m[0]);
    let placed = window_call(window::move_to(corner, 2 | 20 << 16), None).map(|m| m[0]);
    let styled = window_call(window::style(corner, window::DECORATED), None).map(|m| m[0]);
    let back = window_call(window::move_to(corner, 1 | 20 << 16), None).map(|m| m[0]);
    let gone = window_call(window::destroy(corner), None).map(|m| m[0]);
    let invalid = Ok(Status::Invalid as u64);
    t.check(
        off == invalid && odd == invalid && placed == Ok(OK) && styled == Ok(OK) && back == invalid && gone == Ok(OK),
        format_args!("decorations that would reach off the screen, and unknown styles, are refused"),
    );
    let r = open_styled(&mut w, window::ALPHA | window::DECORATED);
    t.check(
        r[0] == 0 && listen(&w) && window_info()[3] == 2,
        format_args!("picture 1 on the screen: window B shown over window A, translucent and decorated"),
    );
    loop {
        wait_events(5);
        while let Some(e) = next_event(&w) {
            if let WindowEvent::Close = e {
                let n = w.window.take().unwrap_or(u64::MAX);
                let r = window_call(window::destroy(n), None);
                settled();
                t.check(
                    r == Ok([0; 4]) && window_info()[3] == 1,
                    format_args!("window B closed from its close box: picture 3 on the screen"),
                );
                superior_sys::sleep(SCREENSHOT_TICKS);
                say!("windows: done ({} failed)", t.0);
                syscall(Syscall::Call, DESKTOP_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
                superior_sys::park()
            }
        }
    }
}

/// The toolkit and widgets tests' watcher (`arg 39`, boot/toolkit.manifest,
/// and `arg 42`, boot/widgets.manifest): once the app's window (`what`)
/// has been shown and is gone again, shuts the system down (after the
/// host's last screenshot).
fn window_watcher(test: &str, what: &str) -> ! {
    let mut seen = false;
    loop {
        let shown = window_info()[3];
        if shown == 1 && !seen {
            seen = true;
            say!("{test}: {what} is on the screen");
        }
        if shown == 0 && seen {
            break;
        }
        superior_sys::sleep(5);
    }
    say!("{test}: {what} is gone");
    superior_sys::sleep(SCREENSHOT_TICKS);
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_SHUTDOWN, 0, 0, 0]);
    superior_sys::park()
}

/// The desktop shell test's watcher (`arg 40`, boot/panel.manifest), a
/// window manager too, to see what the panel does: both apps minimised,
/// then the greeter closed (Hello still minimised), then the greeter
/// launched again with the focus; then it shuts the system down (after
/// the host's last screenshot).
fn panel_watcher() -> ! {
    // The greeter's and Hello's windows: whether each is shown, minimised
    // and has the focus, as the compositor lists them to a manager.
    let apps = || {
        let mut s = [(false, false, false); 2];
        let Ok(l) = window_call(window::list(), None) else { return s };
        for w in (0..window::MAX_WINDOWS).filter(|&w| l[0] == 0 && l[1] & 1 << w != 0) {
            let Ok(d) = window_call(window::describe(w), None) else { continue };
            let title = d[1].to_le_bytes();
            let k = if title.starts_with(b"Greeter") {
                0
            } else if title.starts_with(b"Hello") {
                1
            } else {
                continue;
            };
            if d[0] == 0 && d[3] & 1 == 0 {
                s[k] = (true, l[3] & 1 << w != 0, l[2] == w);
            }
        }
        s
    };
    let minimised = (true, true, false);
    let steps = [
        ("both apps minimised", [minimised, minimised]),
        ("the greeter gone, Hello minimised", [(false, false, false), minimised]),
        ("the greeter back with the focus, Hello minimised", [(true, false, true), minimised]),
        // Then text copied in Hello and pasted in the greeter.
        ("Hello back with the focus", [(true, false, false), (true, false, true)]),
        ("the greeter with the focus again", [(true, false, true), (true, false, false)]),
    ];
    let mut at = 0;
    while at < steps.len() {
        if apps() == steps[at].1 {
            say!("panel test: {} (step {})", steps[at].0, at + 1);
            at += 1;
            if at == 3 {
                // Keys type as on a Dvorak keyboard from now on (a
                // manager's call).
                let r = window_call(window::set_layout(window::LAYOUT_DVORAK), None).map_or(u64::MAX, |m| m[0]);
                let l = window_call(window::layout(), None).map_or(u64::MAX, |m| m[1]);
                say!("panel test: keyboard layout {l} (status {r})");
            }
        }
        superior_sys::sleep(5);
    }
    superior_sys::sleep(SCREENSHOT_TICKS);
    syscall(Syscall::Call, DESKTOP_CONTROL, [OP_SHUTDOWN, 0, 0, 0]);
    superior_sys::park()
}

fn display_client() -> ! {
    let mut t = Checks(0, "display");
    let pages = (SCREEN.0 * SCREEN.1 * 4).div_ceil(4096);
    let mut made = true;
    for p in 0..pages {
        made &= syscall(Syscall::Retype, DISPLAY_MEMORY, [ObjectType::Frame as u64, 0, SURFACE + p, 0]).status == 0
            && syscall(Syscall::FrameMap, SURFACE + p, [SURFACE_VA + p * 4096, 1, 0, 0]).status == 0;
    }
    t.check(made, format_args!("a surface of {pages} pages for {}x{}", SCREEN.0, SCREEN.1));
    display_set_up(&mut t, pages, true);
    // The first picture: all of it, then a patch of it in another phase.
    // The second flush shows the other framebuffer, which must have the
    // first picture as well as the patch.
    draw(0, 0, SCREEN.0, SCREEN.1, 1);
    let a = display_call(display::flush(rect(0, 0, SCREEN.0, SCREEN.1)), None);
    let (px, py, pw, ph) = PATCH;
    draw(px, py, pw, ph, 2);
    let b = display_call(display::flush(rect(px, py, pw, ph)), None);
    t.check(
        a[0] == 0 && b[0] == 0 && (a[1], b[1]) == (1, 0) && (a[2], b[2]) == (1, 2),
        format_args!("picture 1 on the screen: flipped to framebuffer {} and back to {}", a[1], b[1]),
    );
    let past = display_call(display::flush(rect(SCREEN.0 - 10, 0, 20, 10)), None);
    t.check(
        past[0] == Status::Invalid as u64,
        format_args!("a rectangle past the screen's edge is refused"),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    // The driver dies; its restarted instance knows nothing of the
    // surface or the mode, and gets both again.
    say!("display: killing the driver");
    syscall(Syscall::Call, DISPLAY_CONTROL, [OP_KILL, DISPLAY_DRIVER_INDEX, 0, 0]);
    display_set_up(&mut t, pages, false);
    draw(0, 0, SCREEN.0, SCREEN.1, 3);
    let c = display_call(display::flush(rect(0, 0, SCREEN.0, SCREEN.1)), None);
    t.check(
        c[0] == 0 && c[2] == 1,
        format_args!("picture 2 on the screen after the driver's restart (flip {})", c[2]),
    );
    superior_sys::sleep(SCREENSHOT_TICKS);
    say!("display: done ({} failed)", t.0);
    syscall(Syscall::Call, DISPLAY_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

// ---- the audio clients (`arg 29` and `arg 30`, boot/audio.manifest) ----

const AUDIO: u64 = 0;
const AUDIO_CONTROL: u64 = 1;
const AUDIO_MEMORY: u64 = 2;
/// The notification the mixer signals as frames play (and the timer).
const AUDIO_NTFN: u64 = 3;
/// The ring's pages, mapped in a row.
const AUDIO_RING: u64 = 8;
const AUDIO_RING_VA: u64 = USER_BASE + 0x4000_0000;
/// Components the second audio client kills: the sound driver and the
/// mixer.
const SOUND_DRIVER_INDEX: u64 = 1;
const MIXER_INDEX: u64 = 2;
/// The rate `cargo xtask audio-test` records at.
const AUDIO_RATE: u64 = 22050;
/// Ticks a sound gets to play, a driver's restart included.
const PLAY_TICKS: u64 = 3000;

/// A test sound: its length in frames, amplitude, and the left and right
/// channels' periods. `cargo xtask audio-test` has the same table.
#[derive(Clone, Copy)]
struct Sound {
    name: &'static str,
    frames: u64,
    amp: i64,
    periods: (u64, u64),
}

const A1: Sound = Sound { name: "a1", frames: 6615, amp: 6000, periods: (100, 150) };
const A2: Sound = Sound { name: "a2", frames: 44100, amp: 7000, periods: (60, 90) };
const B2: Sound = Sound { name: "b2", frames: 11025, amp: 9000, periods: (44, 70) };
const B3: Sound = Sound { name: "b3", frames: 6615, amp: 8000, periods: (80, 120) };
const B4: Sound = Sound { name: "b4", frames: 6615, amp: 5000, periods: (50, 200) };
/// Played last: QEMU writes the recording through a buffer, which its
/// exit on AArch64 does not flush, so the end of b4 gets pushed out
/// with silence after it.
const SILENCE: Sound = Sound { name: "silence", frames: 4410, amp: 0, periods: (2, 2) };

/// A triangle wave: `-amp` at 0, up to `amp` over half the period and down
/// again over the rest. `cargo xtask audio-test` computes the same.
fn triangle(i: u64, period: u64, amp: i64) -> i16 {
    let p = (i % period) as i64;
    let half = period as i64 / 2;
    let v = if p < half { -amp + 2 * amp * p / half } else { amp - 2 * amp * (p - half) / (period as i64 - half) };
    v as i16
}

impl Sound {
    /// Frame `i` (S16LE stereo).
    fn frame(&self, i: u64) -> u32 {
        let l = triangle(i, self.periods.0, self.amp) as u16 as u32;
        let r = triangle(i, self.periods.1, self.amp) as u16 as u32;
        l | r << 16
    }
}

/// A call to the mixer: `Err` if it failed (the mixer restarted), else
/// the reply.
fn audio_call(m: [u64; 4], grant: Option<u64>) -> Result<[u64; 4], ()> {
    let x = CapTransfer {
        grant: grant.map(|s| s as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, AUDIO, m, x);
    if r.status == 0 { Ok(r.msg) } else { Err(()) }
}

/// The mixer's `INFO` (rate, streams started, streams playing), tried
/// again while it restarts.
fn audio_info() -> [u64; 4] {
    for _ in 0..400 {
        if let Ok(m) = audio_call(superior_objects::idl::audio::info(), None) {
            if m[0] == 0 {
                return m;
            }
        }
        superior_sys::sleep(5);
    }
    [u64::MAX; 4]
}

/// Waits until `f` holds of the mixer's `INFO`; whether it came to.
fn audio_until(mut f: impl FnMut([u64; 4]) -> bool) -> bool {
    let end = ticks() + PLAY_TICKS;
    while ticks() < end {
        if f(audio_info()) {
            return true;
        }
        superior_sys::sleep(2);
    }
    false
}

fn audio_wait(ticks: u64) {
    syscall(Syscall::TimerSignal, AUDIO_NTFN, [ticks, 0, 0, 0]);
    syscall(Syscall::Wait, AUDIO_NTFN, [0; 4]);
}

fn make_audio_ring(t: &mut Checks) {
    use superior_objects::idl::audio;
    let mut made = syscall(Syscall::Retype, AUDIO_MEMORY, [ObjectType::Notification as u64, 0, AUDIO_NTFN, 0]).status == 0;
    for p in 0..audio::RING_PAGES {
        made &= syscall(Syscall::Retype, AUDIO_MEMORY, [ObjectType::Frame as u64, 0, AUDIO_RING + p, 0]).status == 0
            && syscall(Syscall::FrameMap, AUDIO_RING + p, [AUDIO_RING_VA + p * 4096, 1, 0, 0]).status == 0;
    }
    t.check(made, format_args!("a ring of {} pages for {} frames", audio::RING_PAGES, audio::RING_FRAMES));
}

/// A client's stream: frames written, and what the mixer last said had
/// played and could be written.
struct Player {
    written: u64,
    played: u64,
    limit: u64,
}

/// Lends the ring and the notification and starts the stream; tried again
/// while the mixer restarts. Whether it started.
fn audio_set_up(p: &mut Player) -> bool {
    use superior_objects::idl::audio;
    for _ in 0..100 {
        let ok = (0..audio::RING_PAGES).all(|i| audio_call(audio::attach(i), Some(AUDIO_RING + i)) == Ok([0; 4]))
            && audio_call(audio::listen(), Some(AUDIO_NTFN)) == Ok([0; 4])
            && audio_call(audio::start(), None).is_ok_and(|m| m[0] == 0);
        if ok {
            *p = Player { written: 0, played: 0, limit: audio::RING_FRAMES };
            return true;
        }
        superior_sys::sleep(5);
    }
    false
}

/// Commits what is written; whether the mixer took it.
fn audio_commit(p: &mut Player) -> bool {
    match audio_call(superior_objects::idl::audio::commit(p.written), None) {
        Ok(m) if m[0] == 0 => {
            (p.played, p.limit) = (m[1], m[2]);
            true
        }
        _ => false,
    }
}

/// Plays `s` to the end, writing as much at a time as the ring takes;
/// whether all of it played.
fn play(p: &mut Player, s: &Sound) -> bool {
    let ring = superior_objects::idl::audio::RING_FRAMES;
    let first = p.written;
    let end = ticks() + PLAY_TICKS;
    let mut commits = 0;
    while ticks() < end {
        while p.written - first < s.frames && p.written < p.limit {
            let at = AUDIO_RING_VA + p.written % ring * 4;
            // SAFETY: inside the ring, mapped and writable.
            unsafe { (at as *mut u32).write_volatile(s.frame(p.written - first)) };
            p.written += 1;
        }
        if !audio_commit(p) {
            say!("[fail] audio: {}: the mixer refused a commit", s.name);
            return false;
        }
        commits += 1;
        if p.written - first == s.frames && p.played >= p.written {
            say!("audio: {}: {} frames played, {commits} commits", s.name, s.frames);
            return true;
        }
        audio_wait(5);
    }
    false
}

/// The first audio client: plays a1, then a2 once the second client's
/// stream is started, then keeps its stream, setting it up again whenever
/// the mixer restarts.
fn audio_first() -> ! {
    let mut t = Checks(0, "audio");
    make_audio_ring(&mut t);
    let info = audio_info();
    t.check(info[0] == 0 && info[1] == AUDIO_RATE, format_args!("the mixer plays at {} Hz", info[1]));
    let mut p = Player { written: 0, played: 0, limit: 0 };
    t.check(audio_set_up(&mut p), format_args!("stream A set up"));
    t.check(play(&mut p, &A1), format_args!("stream A: a1 played to the end"));
    t.check(audio_until(|m| m[2] == 2), format_args!("stream A: the second stream is started"));
    t.check(play(&mut p, &A2), format_args!("stream A: a2 played to the end, in pieces of a ring"));
    loop {
        audio_wait(5);
        if !audio_commit(&mut p) {
            say!("audio: stream A: the mixer restarted; setting the stream up again");
            t.check(audio_set_up(&mut p), format_args!("stream A set up again after the mixer's restart"));
        }
    }
}

/// The second audio client: plays b2 over a2, then b3 after having the
/// mixer killed and b4 after having the sound driver killed; the host
/// checks the sound QEMU recorded.
fn audio_second() -> ! {
    let mut t = Checks(0, "audio");
    make_audio_ring(&mut t);
    let mut seen = false;
    t.check(
        audio_until(|m| {
            seen |= m[3] >= 1;
            seen && m[3] == 0
        }),
        format_args!("a1 played and done"),
    );
    let mut p = Player { written: 0, played: 0, limit: 0 };
    t.check(audio_set_up(&mut p), format_args!("stream B set up"));
    t.check(audio_until(|m| m[3] >= 1), format_args!("a2 playing"));
    superior_sys::sleep(20);
    let b2 = play(&mut p, &B2);
    t.check(b2 && audio_until(|m| m[3] == 0), format_args!("b2 played over a2, and both done"));
    say!("audio: killing the mixer");
    syscall(Syscall::Call, AUDIO_CONTROL, [OP_KILL, MIXER_INDEX, 0, 0]);
    let again = audio_set_up(&mut p) && audio_until(|m| m[2] == 2);
    t.check(again, format_args!("both streams set up again after the mixer's restart"));
    t.check(
        play(&mut p, &B3) && audio_until(|m| m[3] == 0),
        format_args!("b3 played after the mixer's restart"),
    );
    say!("audio: killing the sound driver");
    syscall(Syscall::Call, AUDIO_CONTROL, [OP_KILL, SOUND_DRIVER_INDEX, 0, 0]);
    t.check(
        play(&mut p, &B4) && audio_until(|m| m[3] == 0),
        format_args!("b4 played after the sound driver's restart"),
    );
    t.check(play(&mut p, &SILENCE), format_args!("silence played, for the recording's sake"));
    say!("audio: done ({} failed)", t.0);
    syscall(Syscall::Call, AUDIO_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

fn crasher() -> ! {
    say!("crasher: starting");
    // SAFETY: deliberately not: this must fault.
    let v = unsafe { core::ptr::read_volatile((USER_BASE + root::BUNDLE_OFFSET) as *const u64) };
    say!("[fail] crasher: read {v:#x}");
    superior_sys::park()
}

/// Ticks each of the suspend test's suspends asks for: the first ends by
/// its alarm; on x86-64, where the machine suspends to RAM, the second is
/// long, and the test ends it early with a key press.
#[cfg(target_arch = "x86_64")]
const SUSPEND_TICKS: [u64; 2] = [200, 6000];
#[cfg(not(target_arch = "x86_64"))]
const SUSPEND_TICKS: [u64; 2] = [200, 200];

/// The suspend test (`boot/suspend.manifest`): reads the disk, has the
/// manager suspend the machine (the driver resets its device first, and
/// brings it up again after), then reads it again. Time stands still while
/// suspended: hardly a tick may pass across the whole round trip.
fn suspend_client() -> ! {
    let mut t = Checks(0, "suspend");
    let made = syscall(Syscall::Retype, BLOCK_MEMORY, [ObjectType::Frame as u64, 0, BUFFER, 0]);
    let mapped = syscall(Syscall::FrameMap, BUFFER, [BUFFER_VA, 1, 0, 0]);
    let r = read_and_check(0, 8);
    t.check(
        made.status == 0 && mapped.status == 0 && r.is_ok(),
        format_args!("read 8 sectors before suspending: {}", r.err().unwrap_or("every word right")),
    );
    // Only the manager's badge may suspend the driver.
    let r = syscall(Syscall::Call, BLOCK, [power::SUSPEND, 0, 0, 0]);
    t.check(
        r.status == 0 && r.msg[0] == Status::Invalid as u64,
        format_args!("the driver refuses SUSPEND from a client"),
    );
    for (round, asked) in (1..=2).zip(SUSPEND_TICKS) {
        let before = ticks();
        let r = syscall(Syscall::Call, BLOCK_CONTROL, [power::OP_SUSPEND, asked, 0, 0]);
        let passed = ticks() - before;
        t.check(
            r.status == 0 && r.msg[0] == Status::Ok as u64 && passed < 50,
            format_args!(
                "suspend {round}: suspended for up to {asked} ticks and resumed, {passed} ticks passed meanwhile (status {})",
                r.msg[0]
            ),
        );
        let mut bad = None;
        for (sector, count) in [(0, 8), (100, 8), (127, 1)] {
            if let Err(e) = read_and_check(sector, count) {
                bad = Some(e);
            }
        }
        t.check(
            bad.is_none(),
            format_args!(
                "suspend {round}: the disk reads after the resume: {}",
                bad.unwrap_or("every word right")
            ),
        );
        // The ticks run again: a sleep ends.
        let before = ticks();
        superior_sys::sleep(10);
        let slept = ticks() - before;
        t.check(slept >= 10, format_args!("suspend {round}: the ticks run again: a 10-tick sleep took {slept}"));
    }
    syscall(Syscall::Call, BLOCK_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// The A/B test's downloads (`boot/ab-system.manifest`): updates the
/// host left on the system disk after the slots, each laid out as a slot
/// (a header sector, then the signed bundle): 0 a version 3 changed after
/// signing, 1 version 3, 2 version 4.
const DOWNLOAD_FIRST: u64 = superior_objects::ab::SLOT_FIRST[1] + superior_objects::ab::SLOT_SECTORS;

/// A call to the manager through the control capability.
fn manager(m: [u64; 4]) -> [u64; 4] {
    let r = syscall(Syscall::Call, BLOCK_CONTROL, m);
    if r.status != 0 { [u64::MAX, 0, 0, 0] } else { r.msg }
}

/// Moves `count` sectors (up to a page) between the disk and the buffer.
fn disk(op: u64, sector: u64, count: u64) -> bool {
    let lend = CapTransfer { grant: Some(BUFFER as u16), accept: None };
    let r = syscall_x(Syscall::Call, BLOCK, [op, sector, count, 0], lend);
    r.status == 0 && r.msg[0] == Status::Ok as u64
}

/// Copies download `k` into the slot the manager says is free, header and
/// all, as an updater would once it had downloaded it; then tells the
/// manager it is ready. The manager's answer.
fn stage(k: u64) -> u64 {
    let r = manager([update::OP_UPDATE_SLOT, 0, 0, 0]);
    if r[0] != Status::Ok as u64 {
        return r[0];
    }
    let (from, to) = (DOWNLOAD_FIRST + k * superior_objects::ab::SLOT_SECTORS, r[2]);
    if !disk(block::READ, from, 1) {
        return Status::DeviceError as u64;
    }
    // SAFETY: the buffer is mapped; its first sector is the header.
    let header: [u8; 512] = unsafe { *(BUFFER_VA as *const [u8; 512]) };
    let Some(len) = superior_objects::ab::slot_length(&header) else {
        return Status::NotFound as u64;
    };
    let sectors = 1 + len.div_ceil(512) as u64;
    let mut done = 0;
    while done < sectors {
        let n = (sectors - done).min(8);
        if !disk(block::READ, from + done, n) || !disk(block::WRITE, to + done, n) {
            return Status::DeviceError as u64;
        }
        done += n;
    }
    if syscall(Syscall::Call, BLOCK, [block::FLUSH, 0, 0, 0]).msg[0] != Status::Ok as u64 {
        return Status::DeviceError as u64;
    }
    manager([update::OP_UPDATE_READY, 0, 0, 0])[0]
}

/// The A/B test's client, in each system the slots hold: role 32 in
/// version 2, 33 in version 3 (which never confirms it came up, as a
/// broken update would not), 34 in version 4.
fn ab_client(role: u64) -> ! {
    let mut t = Checks(0, "ab");
    let made = syscall(Syscall::Retype, BLOCK_MEMORY, [ObjectType::Frame as u64, 0, BUFFER, 0]);
    let mapped = syscall(Syscall::FrameMap, BUFFER, [BUFFER_VA, 1, 0, 0]);
    let info = manager([update::OP_BOOT_INFO, 0, 0, 0]);
    let (slot, fell_back, version, floor) = (info[1] & 0xff, info[1] & update::FELL_BACK != 0, info[2], info[3]);
    let name = if slot == 0 { 'A' } else { 'B' };
    t.check(
        made.status == 0 && mapped.status == 0 && info[0] == Status::Ok as u64,
        format_args!(
            "running version {version} from slot {name}{}, rollback floor {floor}",
            if fell_back { " (fell back)" } else { "" }
        ),
    );
    let ok = Status::Ok as u64;
    match role {
        32 if !fell_back => {
            t.check(slot == 0 && version == 2, format_args!("a fresh disk boots slot A"));
            t.check(manager([update::OP_BOOT_OK, 0, 0, 0])[0] == ok, format_args!("confirmed it came up"));
            let r = stage(0);
            t.check(
                r == Status::Denied as u64,
                format_args!("an update changed after signing is refused (status {r})"),
            );
            let r = stage(1);
            t.check(r == ok, format_args!("version 3 written to slot B and staged (status {r})"));
        }
        32 => {
            t.check(
                slot == 0 && version == 2 && floor == 2,
                format_args!("version 3 never confirmed, so slot A again"),
            );
            t.check(manager([update::OP_BOOT_OK, 0, 0, 0])[0] == ok, format_args!("confirmed it came up"));
            let r = stage(2);
            t.check(r == ok, format_args!("version 4 written to slot B and staged (status {r})"));
        }
        33 => {
            t.check(slot == 1 && version == 3, format_args!("the staged update boots, and does not confirm"));
        }
        _ => {
            t.check(slot == 1 && version == 4, format_args!("the staged version 4 boots"));
            let r = manager([update::OP_BOOT_OK, 0, 0, 0])[0];
            let info = manager([update::OP_BOOT_INFO, 0, 0, 0]);
            t.check(
                r == ok && info[3] == 4,
                format_args!("confirmed it came up: slot B active, rollback floor {}", info[3]),
            );
            // Slot A still holds version 2: below the floor now.
            let r = manager([update::OP_UPDATE_READY, 0, 0, 0])[0];
            t.check(
                r == Status::Invalid as u64,
                format_args!("version 2, still in slot A, may not be staged again: a rollback (status {r})"),
            );
        }
    }
    syscall(Syscall::Call, BLOCK_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// The package test's downloads (`boot/packages.manifest`), after the
/// package store, each laid out as a store slot: 0 the app signed by
/// another key, 1 the app changed after signing, 2 an app that uses the
/// disk, 3 one that asks for a device, 4 one that asks to install
/// packages itself, 5 the app.
const PACKAGE_DOWNLOADS: u64 =
    superior_objects::package::FIRST + superior_objects::package::COUNT as u64 * superior_objects::package::SECTORS;
/// The installer's `report` service, which the app calls.
const REPORT: u64 = 5;
/// What the app says when it calls.
const APP_HELLO: u64 = 0xa99;

/// Copies download `k` into a free store slot, as an installer would once
/// it had downloaded it, and asks the manager to install it: the
/// manager's answer.
fn install_download(k: u64) -> u64 {
    use superior_objects::package;
    let r = manager([install::OP_PACKAGE_SLOT, 0, 0, 0]);
    if r[0] != Status::Ok as u64 {
        return r[0];
    }
    let (from, to) = (PACKAGE_DOWNLOADS + k * package::SECTORS, r[2]);
    if !disk(block::READ, from, 1) {
        return Status::DeviceError as u64;
    }
    // SAFETY: the buffer is mapped; its first sector is the header.
    let header: [u8; 512] = unsafe { *(BUFFER_VA as *const [u8; 512]) };
    let Some(len) = package::length(&header) else {
        return Status::NotFound as u64;
    };
    let sectors = 1 + len.div_ceil(512) as u64;
    let mut done = 0;
    while done < sectors {
        let n = (sectors - done).min(8);
        if !disk(block::READ, from + done, n) || !disk(block::WRITE, to + done, n) {
            return Status::DeviceError as u64;
        }
        done += n;
    }
    if syscall(Syscall::Call, BLOCK, [block::FLUSH, 0, 0, 0]).msg[0] != Status::Ok as u64 {
        return Status::DeviceError as u64;
    }
    manager([install::OP_INSTALL, r[1], 0, 0])[0]
}

/// Waits for the app to call `report`, and answers it: whether it said
/// hello.
fn app_calls() -> bool {
    let call = syscall(Syscall::Recv, REPORT, [0; 4]);
    syscall(Syscall::Reply, 0, [0; 4]);
    call.status == 0 && call.msg[0] == APP_HELLO
}

/// The package test's installer (role 35): it counts its boots in sector
/// 1 of the disk. Boot 1 has five bad packages refused and installs the
/// app; boot 2 finds it installed from the store, and uninstalls it; boot
/// 3 finds nothing installed.
fn install_client() -> ! {
    let mut t = Checks(0, "packages");
    let ok = Status::Ok as u64;
    let made = syscall(Syscall::Retype, BLOCK_MEMORY, [ObjectType::Frame as u64, 0, BUFFER, 0]);
    let mapped = syscall(Syscall::FrameMap, BUFFER, [BUFFER_VA, 1, 0, 0]);
    let read = disk(block::READ, 1, 1);
    // SAFETY: the buffer is mapped; its first word is the boot count.
    let boots = unsafe { core::ptr::read_volatile(BUFFER_VA as *const u64) };
    unsafe { core::ptr::write_volatile(BUFFER_VA as *mut u64, boots + 1) };
    let counted = disk(block::WRITE, 1, 1) && syscall(Syscall::Call, BLOCK, [block::FLUSH, 0, 0, 0]).msg[0] == ok;
    let installed = manager([install::OP_PACKAGES, 0, 0, 0]);
    t.check(
        made.status == 0 && mapped.status == 0 && read && counted && installed[0] == ok,
        format_args!("boot {}: store slots in use {:#x}", boots + 1, installed[1]),
    );
    match boots {
        0 => {
            t.check(installed[1] == 0, format_args!("a fresh store holds no packages"));
            let bad: [(u64, &str, Status); 5] = [
                (0, "the app signed by another key", Status::Denied),
                (1, "the app changed after signing", Status::Denied),
                (2, "an app that uses the disk", Status::Invalid),
                (3, "an app that asks for a device", Status::Invalid),
                (4, "an app that asks to install packages", Status::Invalid),
            ];
            for (k, what, want) in bad {
                let r = install_download(k);
                t.check(r == want as u64, format_args!("{what} is refused (status {r})"));
            }
            let empty = manager([install::OP_PACKAGES, 0, 0, 0])[1];
            t.check(empty == 0, format_args!("refused packages are cleared from the store"));
            let r = install_download(5);
            t.check(r == ok, format_args!("the app is installed (status {r})"));
            t.check(app_calls(), format_args!("the installed app runs, and calls the installer"));
            let r = install_download(5);
            t.check(r == Status::InUse as u64, format_args!("installing it twice is refused (status {r})"));
            let now = manager([install::OP_PACKAGES, 0, 0, 0])[1];
            t.check(now == 1, format_args!("the store holds the app alone"));
        }
        1 => {
            t.check(installed[1] == 1, format_args!("the app was installed at boot from the store"));
            t.check(app_calls(), format_args!("it runs, and calls the installer"));
            let r = manager([install::OP_UNINSTALL, 0, 0, 0])[0];
            let now = manager([install::OP_PACKAGES, 0, 0, 0])[1];
            t.check(r == ok && now == 0, format_args!("the app is uninstalled (status {r})"));
        }
        _ => {
            t.check(installed[1] == 0, format_args!("once uninstalled, nothing is installed at boot"));
        }
    }
    syscall(Syscall::Call, BLOCK_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    superior_sys::park()
}

/// The package test's app (role 36), installed from a package: it calls
/// the installer's `report` service (slot 0), then waits to be
/// uninstalled.
fn app_client() -> ! {
    syscall(Syscall::Call, 0, [APP_HELLO, 0, 0, 0]);
    superior_sys::park()
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(role: u64) -> ! {
    match role {
        0 => client(),
        2 => supervise(),
        3 => crasher(),
        4 => block_client([pci::OPEN, pci::VERSION, 0x1af4 << 16 | 0x1042, 0]),
        11 => block_client([pci::OPEN_CLASS, pci::VERSION, 0x01_08_02, 0]),
        12 => block_client([pci::OPEN_CLASS, pci::VERSION, 0x01_06_01, 0]),
        13 => net_client(),
        14 => keyboard_client(),
        15 => df_spinner(),
        5 => memory_client(),
        6 => hog(),
        19 => clone_child(),
        23 => big(),
        20 => reboot_client(),
        22 => hotplug_client(),
        7 => fs_client(),
        8 => fs_verify(),
        9 => fs_other(),
        21 => fs_load(),
        10 => injector(&[FS_INDEX, DRIVER_INDEX], false),
        // The keyboard test: a word takes some 0.2 s to type, longer than
        // most gaps between kills, so it gets pauses to come through in.
        17 => injector(&[DRIVER_INDEX, FS_INDEX], true),
        // The network test: the driver, the network server, the resolver.
        16 => injector(&[1, 2, 3], false),
        18 => tcp_client(),
        24 => display_client(),
        25 => desktop_first(),
        26 => desktop_second(),
        27 => input_first(),
        28 => input_second(),
        29 => audio_first(),
        30 => audio_second(),
        31 => suspend_client(),
        32..=34 => ab_client(role),
        35 => install_client(),
        36 => app_client(),
        37 => styled_first(),
        38 => styled_second(),
        39 => window_watcher("toolkit", "the greeter's window"),
        40 => panel_watcher(),
        41 => wifi_client(),
        42 => window_watcher("widgets", "the List window"),
        43 => window_watcher("notes", "the Notes window"),
        _ => probe(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
