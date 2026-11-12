//! The mixer: the sound server. It is the sound driver's one client and
//! serves `audio` to every component that plays sound, as the driver does
//! to it: each client lends a ring of its own pages and commits frames to
//! it; the mixer adds the streams together, sample by sample (saturating),
//! into a ring of its own that it lends to the driver, and keeps that
//! [`LEAD`] frames ahead of what the device has played.
//!
//! A stream is mixed as its frames arrive. One that runs dry is silent
//! until its client writes more, which then plays on from there: its
//! frames are never skipped. When every stream has played all it was
//! given the mixer stops the driver's stream, and starts it again with
//! the next frames.
//!
//! Crash-only. A restarted mixer knows no streams; the clients' next calls
//! are refused and they set theirs up again. A restarted driver has lost
//! the ring: a call it refuses has the mixer lend it the ring again and
//! start over (the frames it had are dropped). A client that goes takes
//! its ring with it (the manager revokes its memory, and with it the
//! copies kept here): the mixer checks each stream's first page before it
//! reads the ring, and drops the stream whose page is gone.
//!
//! Slots: 0 the sound driver (`audio`), 1 the receive side of `audio`, 2 a
//! notification (its timer, and the driver's signal), 3 memory for the
//! mixer's ring.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::idl::audio;
use superior_objects::interfaces::Status;
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const DRIVER: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const MEMORY: u64 = 3;
/// Where a lent page or notification arrives.
const LENT: u64 = 4;
/// Where a stream's first page is copied to see if it is still there.
const PROBE: u64 = 5;
/// A copy of the notification badged `DRIVER_BADGE`, lent to the driver.
const DRIVER_NTFN: u64 = 6;
const DRIVER_BADGE: u64 = 1;
/// The mixer's ring, lent to the driver.
const OUT: u64 = 16;
/// The notification each stream's client lent (`LISTEN`).
const LISTENERS: u64 = OUT + audio::RING_PAGES;
/// Each stream's ring: stream `i`'s pages from `RINGS + i * RING_PAGES`.
const RINGS: u64 = 64;
const MAX_STREAMS: usize = 4;
const _: () = assert!(LISTENERS + MAX_STREAMS as u64 <= RINGS);
const _: () = assert!(RINGS + MAX_STREAMS as u64 * audio::RING_PAGES <= 1 << 8);
const OUT_VA: u64 = USER_BASE + 0x4000_0000;
/// Stream `i`'s ring, from `RING_VA + i * RING_SPAN`.
const RING_VA: u64 = USER_BASE + 0x4100_0000;
const RING_SPAN: u64 = 0x10_0000;
const RING: u64 = audio::RING_FRAMES;
const FRAME: u64 = 4;
/// How far ahead of the device the mix is kept: three of the driver's
/// periods (a quarter of the ring each), about half a second at 22 kHz.
const LEAD: u64 = 3 * RING / 4;
/// Rights for a copy of a lent capability.
const ALL: u64 = 0x1f;
/// Ticks between looks while the driver plays, signalled or not, and
/// between checks that every stream's client is still there.
const LOOK_TICKS: u64 = 5;
const CHECK_TICKS: u64 = 20;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("mixer: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy)]
struct Stream {
    /// The client's badge.
    owner: u64,
    /// Ring pages attached.
    pages: u64,
    listening: bool,
    started: bool,
    /// Frames the client has written, and the mixer has taken into the mix.
    written: u64,
    taken: u64,
    /// Where in the mix the stream's last frame taken went (one past it).
    mixed_to: u64,
    /// What the client last heard had played, to signal it on a change.
    told: u64,
}

impl Stream {
    fn pending(&self) -> bool {
        self.started && self.written > self.taken
    }
}

/// The driver's side: the mixer's ring and its stream there.
struct Output {
    /// The driver has the ring and the notification.
    lent: bool,
    /// Its stream is started.
    running: bool,
    /// Frames mixed and committed, played, and how far the driver lets
    /// the mix be written.
    written: u64,
    played: u64,
    limit: u64,
    /// Times the ring was lent, and the driver's streams started.
    lends: u64,
    starts: u64,
}

struct Mixer {
    rate: u64,
    streams: [Option<Stream>; MAX_STREAMS],
    out: Output,
    reaped: u64,
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// A call to the driver: its reply, or `None` if the call failed (the
/// driver died in it) or was refused.
fn driver(m: [u64; 4], grant: Option<u64>) -> Option<[u64; 4]> {
    let x = CapTransfer { grant: grant.map(|s| s as u16), accept: None };
    let r = syscall_x(Syscall::Call, DRIVER, m, x);
    (r.status == 0 && r.msg[0] == Status::Ok as u64).then_some(r.msg)
}

fn ring_va(i: usize) -> u64 {
    RING_VA + i as u64 * RING_SPAN
}

impl Mixer {
    /// Makes the mixer's ring.
    fn make_ring(&mut self) -> bool {
        (0..audio::RING_PAGES).all(|p| {
            syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, OUT + p, 0]).status == 0
                && syscall(Syscall::FrameMap, OUT + p, [OUT_VA + p * 4096, 1, 0, 0]).status == 0
        })
    }

    /// Lends the driver the ring and the notification.
    fn lend(&mut self) -> bool {
        self.out.lent = false;
        self.out.running = false;
        for p in 0..audio::RING_PAGES {
            if driver(audio::attach(p), Some(OUT + p)).is_none() {
                return false;
            }
        }
        if driver(audio::listen(), Some(DRIVER_NTFN)).is_none() {
            return false;
        }
        self.out.lent = true;
        self.out.lends += 1;
        if self.out.lends == 1 {
            say!("ring lent to the sound driver");
        } else {
            say!("the sound driver restarted; ring lent again");
        }
        true
    }

    /// Everything the mix held is played or dropped: no stream waits on
    /// the driver's stream any longer.
    fn forget_output(&mut self) {
        self.out.running = false;
        for s in self.streams.iter_mut().flatten() {
            s.mixed_to = 0;
        }
    }

    /// Starts the driver's stream: lends the ring first if the driver does
    /// not have it (or has lost it, restarted). Whether it started.
    fn start_output(&mut self) -> bool {
        for _ in 0..2 {
            if !self.out.lent && !self.lend() {
                // Calls block until the driver is back; one that failed
                // was cut off by its death.
                continue;
            }
            if driver(audio::start(), None).is_some() {
                self.out.running = true;
                self.out.written = 0;
                self.out.played = 0;
                self.out.limit = RING;
                self.out.starts += 1;
                if self.out.starts <= 4 || self.out.starts.is_power_of_two() {
                    say!("the sound driver's stream started (time {})", self.out.starts);
                }
                return true;
            }
            self.out.lent = false;
        }
        false
    }

    fn stop_output(&mut self) {
        if driver(audio::stop(), None).is_none() {
            self.out.lent = false;
        }
        self.forget_output();
    }

    /// Commits the mix as far as it is written, learning what has played.
    fn commit(&mut self) {
        match driver(audio::commit(self.out.written), None) {
            Some(m) => {
                self.out.played = m[1];
                self.out.limit = m[2];
            }
            None => {
                // Restarted: the ring and what was mixed are gone.
                self.out.lent = false;
                self.forget_output();
            }
        }
    }

    /// Whether stream `i`'s client still has its ring (it goes with the
    /// client); drops the stream if not.
    fn alive(&mut self, i: usize) -> bool {
        let Some(s) = self.streams[i] else { return false };
        if s.pages == 0 {
            return true;
        }
        let slot = RINGS + i as u64 * audio::RING_PAGES;
        if syscall(Syscall::CapMint, slot, [PROBE, ALL, 0, 0]).status == 0 {
            syscall(Syscall::CapDelete, PROBE, [0; 4]);
            return true;
        }
        say!("stream {i} is gone with its client");
        self.reaped += 1;
        self.drop_stream(i);
        false
    }

    fn drop_stream(&mut self, i: usize) {
        if let Some(s) = self.streams[i].take() {
            for p in 0..s.pages {
                syscall(Syscall::CapDelete, RINGS + i as u64 * audio::RING_PAGES + p, [0; 4]);
            }
            syscall(Syscall::CapDelete, LISTENERS + i as u64, [0; 4]);
        }
    }

    /// Frames of stream `i` that have played: those taken, less those
    /// still ahead of the device in the mix.
    fn played(&self, i: usize) -> u64 {
        let Some(s) = self.streams[i] else { return 0 };
        let ahead = if self.out.running { s.mixed_to.saturating_sub(self.out.played) } else { 0 };
        s.taken.saturating_sub(ahead)
    }

    /// Adds `n` frames from each stream that has them into the mix, from
    /// where it is written to.
    fn mix(&mut self, n: u64) {
        let from = self.out.written;
        for f in from..from + n {
            let at = (f % RING * FRAME) as usize;
            // SAFETY: inside the mixer's ring, mapped and its own.
            unsafe { ((OUT_VA as usize + at) as *mut u32).write_volatile(0) };
        }
        for i in 0..MAX_STREAMS {
            let Some(s) = self.streams[i] else { continue };
            if !s.pending() || !self.alive(i) {
                continue;
            }
            let k = (s.written - s.taken).min(n);
            for j in 0..k {
                let src = ((s.taken + j) % RING * FRAME) as usize;
                let dst = ((from + j) % RING * FRAME) as usize;
                // SAFETY: inside the stream's ring (mapped, its client's
                // pages checked just now) and the mixer's.
                unsafe {
                    let a = ((ring_va(i) as usize + src) as *const u32).read_volatile();
                    let out = (OUT_VA as usize + dst) as *mut u32;
                    let b = out.read_volatile();
                    out.write_volatile(add(a, b));
                }
            }
            let s = self.streams[i].as_mut().unwrap();
            s.taken += k;
            s.mixed_to = from + k;
        }
        self.out.written = from + n;
    }

    /// Does what is due: mixes what the streams have as far ahead as the
    /// driver lets it, starts and stops the driver's stream, and signals
    /// the clients whose frames have played.
    fn pump(&mut self) {
        let pending = self.streams.iter().flatten().any(Stream::pending);
        if self.out.running {
            self.commit();
        }
        if pending && !self.out.running {
            self.start_output();
        }
        if self.out.running {
            let room = (self.out.played + LEAD).min(self.out.limit).saturating_sub(self.out.written);
            let most = self.streams.iter().flatten().filter(|s| s.pending()).map(|s| s.written - s.taken).max();
            let n = room.min(most.unwrap_or(0));
            if n > 0 {
                self.mix(n);
                self.commit();
            }
            let still = self.streams.iter().flatten().any(Stream::pending);
            if self.out.running && !still && self.out.played >= self.out.written {
                self.stop_output();
            }
        }
        for i in 0..MAX_STREAMS {
            let played = self.played(i);
            let Some(s) = self.streams[i].as_mut() else { continue };
            if s.listening && played != s.told {
                syscall(Syscall::Signal, LISTENERS + i as u64, [0; 4]);
            }
            s.told = played;
        }
    }

    /// The caller's stream, made if it has none (and there is room).
    fn stream(&mut self, badge: u64, make: bool) -> Option<usize> {
        if let Some(i) = self.streams.iter().position(|s| s.is_some_and(|s| s.owner == badge)) {
            return self.alive(i).then_some(i).or_else(|| self.stream(badge, make));
        }
        if !make {
            return None;
        }
        let i = self.streams.iter().position(Option::is_none)?;
        self.streams[i] = Some(Stream {
            owner: badge,
            pages: 0,
            listening: false,
            started: false,
            written: 0,
            taken: 0,
            mixed_to: 0,
            told: 0,
        });
        Some(i)
    }

    fn attach(&mut self, i: usize, page: u64, lent: bool) -> Status {
        if !lent || page >= audio::RING_PAGES {
            return Status::Invalid;
        }
        if page == 0 {
            // A new ring: the old one's pages go, and the stream stops.
            let s = self.streams[i].unwrap();
            for p in 0..s.pages {
                syscall(Syscall::CapDelete, RINGS + i as u64 * audio::RING_PAGES + p, [0; 4]);
            }
            let s = self.streams[i].as_mut().unwrap();
            s.pages = 0;
            s.started = false;
        }
        if page != self.streams[i].unwrap().pages {
            return Status::Invalid;
        }
        let slot = RINGS + i as u64 * audio::RING_PAGES + page;
        if syscall(Syscall::CapMint, LENT, [slot, ALL, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        if syscall(Syscall::FrameMap, slot, [ring_va(i) + page * 4096, 0, 0, 0]).status != 0 {
            syscall(Syscall::CapDelete, slot, [0; 4]);
            return Status::Invalid;
        }
        self.streams[i].as_mut().unwrap().pages += 1;
        Status::Ok
    }

    fn listen(&mut self, i: usize, lent: bool) -> Status {
        let slot = LISTENERS + i as u64;
        syscall(Syscall::CapDelete, slot, [0; 4]);
        let kept = lent && syscall(Syscall::CapMint, LENT, [slot, ALL, 0, 0]).status == 0;
        self.streams[i].as_mut().unwrap().listening = kept;
        if kept { Status::Ok } else { Status::Invalid }
    }

    fn start(&mut self, i: usize) -> [u64; 4] {
        let s = self.streams[i].as_mut().unwrap();
        if s.pages != audio::RING_PAGES {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        *s = Stream { started: true, written: 0, taken: 0, mixed_to: 0, told: 0, ..*s };
        let started = self.streams.iter().flatten().filter(|s| s.started).count();
        say!("stream {i} started ({started} started)");
        [Status::Ok as u64, RING / 4, 0, 0]
    }

    fn commit_stream(&mut self, i: usize, written: u64) -> [u64; 4] {
        let s = self.streams[i].unwrap();
        if !s.started || written < s.written || written > s.taken + RING {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        self.streams[i].as_mut().unwrap().written = written;
        self.pump();
        let Some(s) = self.streams[i] else {
            return [Status::Invalid as u64, 0, 0, 0];
        };
        [Status::Ok as u64, self.played(i), s.taken + RING, 0]
    }

    fn serve(&mut self, m: [u64; 4], badge: u64, cap: Option<u16>) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        if m[0] == audio::INFO {
            if m[1] != audio::VERSION {
                return status(Status::Invalid);
            }
            self.pump();
            let started = self.streams.iter().flatten().filter(|s| s.started).count() as u64;
            let playing = (0..MAX_STREAMS)
                .filter(|&i| self.streams[i].is_some_and(|s| s.started && self.played(i) < s.written))
                .count() as u64;
            return [Status::Ok as u64, self.rate, started, playing];
        }
        // A ring's first page makes the caller a stream; anything else
        // needs one.
        let make = m[0] == audio::ATTACH && m[1] == 0;
        let Some(i) = self.stream(badge, make) else {
            return status(if make { Status::NoSpace } else { Status::Invalid });
        };
        let lent = cap == Some(LENT as u16);
        match m[0] {
            audio::ATTACH => status(self.attach(i, m[1], lent)),
            audio::LISTEN => status(self.listen(i, lent)),
            audio::START => self.start(i),
            audio::COMMIT => self.commit_stream(i, m[1]),
            audio::STOP => {
                self.streams[i].as_mut().unwrap().started = false;
                self.pump();
                status(Status::Ok)
            }
            _ => status(Status::Invalid),
        }
    }

    /// Drops the streams whose clients have gone.
    fn check(&mut self) {
        for i in 0..MAX_STREAMS {
            self.alive(i);
        }
    }
}

/// Two frames added, each channel saturating.
fn add(a: u32, b: u32) -> u32 {
    let ch = |v: u32, shift: u32| (v >> shift) as u16 as i16;
    let l = ch(a, 0).saturating_add(ch(b, 0)) as u16 as u32;
    let r = ch(a, 16).saturating_add(ch(b, 16)) as u16 as u32;
    l | r << 16
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut x = Mixer {
        rate: 0,
        streams: [None; MAX_STREAMS],
        out: Output { lent: false, running: false, written: 0, played: 0, limit: 0, lends: 0, starts: 0 },
        reaped: 0,
    };
    if !x.make_ring() {
        say!("[fail] no memory for the ring");
        superior_sys::park()
    }
    if syscall(Syscall::CapMint, NOTIFY, [DRIVER_NTFN, ALL, DRIVER_BADGE, 0]).status != 0 {
        say!("[fail] minting the driver's copy of the notification");
    }
    // The driver's rate is the mix's; its INFO waits until it is up.
    loop {
        if let Some(m) = driver(audio::info(), None) {
            x.rate = m[1];
            break;
        }
        superior_sys::sleep(5);
    }
    if !x.lend() {
        say!("[fail] the sound driver took no ring");
    }
    say!("ready: up to {MAX_STREAMS} streams mixed at {} Hz, {LEAD} frames ahead of the device", x.rate);
    // The timer and the driver wake the same `Recv` that waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the notification");
    }
    let accept = CapTransfer { grant: None, accept: Some(LENT as u16) };
    let mut reply: Option<[u64; 4]> = None;
    let mut next_check = ticks() + CHECK_TICKS;
    loop {
        if ticks() >= next_check {
            x.check();
            next_check = ticks() + CHECK_TICKS;
        }
        let wake = if x.out.running { LOOK_TICKS } else { next_check.saturating_sub(ticks()).max(1) };
        syscall(Syscall::TimerSignal, NOTIFY, [wake, 0, 0, 0]);
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            // The driver's signal or the timer: either way, what is due.
            x.pump();
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let mut cap = r.cap;
        let m = x.serve(r.msg, r.badge, cap.take());
        if r.cap == Some(LENT as u16) {
            // The caller's capability goes back before the reply (a copy
            // is kept).
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
