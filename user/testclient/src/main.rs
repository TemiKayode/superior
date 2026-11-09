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
//! - `arg 10`, the fault injector: asks the manager (control, slot 0) to
//!   kill the filesystem server and the disk driver at pseudo-random
//!   moments, then blocks on the notification in slot 1.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall, root};
use superior_objects::interfaces::{Status, block, fs, mem, pci};
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
    let start = ticks();
    while ticks() < start + 50 {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
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
    syscall(Syscall::Call, MEM_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
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

/// Checks records `0..n` of the file read back right. Returns the first
/// wrong one.
fn check_records(h: u64, n: u64) -> Result<(), u64> {
    let per_block = fs::BLOCK / RECORD;
    let mut k = 0;
    while k < n {
        let (r, _) = fs_call([fs::READ, h, k * RECORD, fs::BLOCK], true);
        if r[0] != OK {
            return Err(k);
        }
        let b = fs_buffer();
        for i in 0..per_block.min(n - k) {
            let rec = k + i;
            for j in 0..RECORD / 8 {
                if b[(i * RECORD / 8 + j) as usize] != record_word(rec, j) {
                    return Err(rec);
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
    let c = check_records(h, acked);
    t.check(
        c.is_ok(),
        format_args!(
            "every acknowledged record reads back (first wrong: {})",
            c.err().map_or(-1, |k| k as i64)
        ),
    );
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
    // A directory past one block of entries.
    fs_path(fs::MKDIR, "many", 0);
    let mut names = [[0u8; 8]; 70];
    let mut made = 0;
    for (i, n) in names.iter_mut().enumerate() {
        *n = *b"many/f00";
        n[6] = b'0' + (i / 10) as u8;
        n[7] = b'0' + (i % 10) as u8;
        let p = core::str::from_utf8(n).unwrap_or("");
        made += (fs_open(p, fs::CREATE)[0] == OK) as u64;
    }
    let many = fs_open("many", fs::DIRECTORY)[1];
    let (n70, ends) = list(many, &["f00", "f69"]);
    let mut removed = 0;
    for n in &names {
        removed += (fs_unlink(core::str::from_utf8(n).unwrap_or("")) == OK) as u64;
    }
    let (n0, _) = list(many, &[]);
    t.check(
        made == 70 && n70 == 70 && ends && removed == 70 && n0 == 0,
        format_args!("70 files in one directory (two blocks of entries) listed, then removed"),
    );

    // One more record, then a rename, both acknowledged; then the machine
    // stops at once: the rename never goes home before the power cut.
    let (ok, _) = append(h, RECORDS);
    let mv = fs_rename("a/g", "g2");
    t.check(
        ok && mv == OK,
        format_args!("record {RECORDS} and a rename of a/g to g2 acknowledged; cutting the power"),
    );
    syscall(Syscall::Call, FS_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
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
    let c = check_records(r[1], n);
    t.check(
        c.is_ok(),
        format_args!(
            "all {n} acknowledged records survived (first wrong: {})",
            c.err().map_or(-1, |k| k as i64)
        ),
    );
    let g2 = fs_open("g2", 0);
    let ag = fs_open("a/g", 0)[0];
    let root = fs_open("/", fs::DIRECTORY);
    let (count, all) = list(root[1], &["logs", "data", "a", "many", "g2"]);
    t.check(
        g2[0] == OK && g2[2] == 100 && ag == Status::NotFound as u64 && count == 5 && all,
        format_args!(
            "the last rename survived: g2 is there, a/g is not; the root lists {count} entries"
        ),
    );
    let big = fs_open("data/big", 0);
    let c = check_big(big[1], 0, 20_004, 10_000, 20_000);
    t.check(
        big[0] == OK && big[2] == 20_004 && c.is_ok(),
        format_args!("data/big survived: {} bytes", big[2]),
    );
    syscall(Syscall::Call, FS_CONTROL, [OP_SHUTDOWN, t.0, 0, 0]);
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
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

fn injector() -> ! {
    // A fixed seed: the moments vary with timing, not between runs.
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    // Let the client get going first.
    let start = ticks();
    while ticks() < start + 10 {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
    // Until the client cuts the power: through every phase of its test.
    for n in 0.. {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let wait = 3 + seed % 12;
        let start = ticks();
        while ticks() < start + wait {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        let target = if n % 2 == 0 { FS_INDEX } else { DRIVER_INDEX };
        syscall(Syscall::Call, 0, [OP_KILL, target, 0, 0]);
    }
    unreachable!()
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
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
        5 => memory_client(),
        6 => hog(),
        7 => fs_client(),
        8 => fs_verify(),
        9 => fs_other(),
        10 => injector(),
        _ => probe(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
