//! A sound driver's host: serves the `audio` interface over the card the
//! driver registers (`lde-snd.c`), playing one caller's stream through the
//! card's first PCM device.
//!
//! After the probe the mixer's master and PCM outputs are switched on at
//! full volume, as ALSA's userspace leaves a card (Linux's drivers start
//! muted). The caller lends a ring of `audio::RING_PAGES` pages, kept and
//! mapped read-only; `START` opens and prepares the PCM device for signed
//! 16-bit stereo at [`RATE`] Hz with a buffer the size of the ring (in
//! memory the device reaches) in periods of a quarter of it. The device
//! starts with the first frames committed: each `COMMIT` copies what the
//! caller wrote into the same place in the buffer. The hardware's position
//! (the driver's pointer, with the periods its interrupt reports for the
//! laps) says how far it has played; what it has played is cleared at
//! once, so a caller that falls behind is heard as silence, never as old
//! frames again. In a CSpace of 2^11 slots.

use crate::{ALL, CLASS_SLOTS, CLASS_VA, LENT, LISTENER, NOTIFY, PAGE, SERVICE, lde_interrupt, lde_next_timer, lde_run_timers, say, start};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use superior_driver::{Failure, dma_barrier, irq_ack};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::idl::audio;
use superior_objects::interfaces::Status;
use superior_sys::{syscall, syscall_x};

/// The rate streams are played at.
pub const RATE: u32 = 22050;
const CHANNELS: u32 = 2;
const FRAME: u64 = 4;
const RING: u64 = audio::RING_FRAMES;
/// Four periods to the buffer: the device interrupts at each.
const PERIOD: u64 = RING / 4;
const _: () = assert!(RING * FRAME == audio::RING_PAGES * PAGE as u64);
/// The caller's ring pages, mapped in a row.
const RING_SLOTS: u64 = CLASS_SLOTS;
const RING_VA: u64 = CLASS_VA;
const _: () = assert!(RING_SLOTS + audio::RING_PAGES <= 2048);
/// While a stream is open the loop looks at the hardware this often
/// (ticks), interrupts or not.
const LOOK: u64 = 5;
/// The mixer controls set to their largest at the start, those the card
/// has: a switch on, a volume full.
const UNMUTE: [&str; 6] = [
    "Master Playback Switch",
    "Master Playback Volume",
    "PCM Switch",
    "PCM Volume",
    "PCM Playback Switch",
    "PCM Playback Volume",
];

unsafe extern "C" {
    fn lde_snd_card(pcms: *mut c_uint, midis: *mut c_uint, controls: *mut c_uint) -> *const c_char;
    fn lde_snd_pcm(i: c_uint, device: *mut c_int, playback: *mut c_uint) -> *const c_char;
    fn lde_snd_control_max(name: *const c_char) -> c_int;
    fn lde_snd_open(device: c_int, rate: c_uint, channels: c_uint, buffer: c_uint, period: c_uint, area: *mut *mut c_void, dma: *mut u64) -> c_int;
    fn lde_snd_trigger(start: c_int) -> c_int;
    fn lde_snd_pointer() -> c_ulong;
    fn lde_snd_periods() -> c_ulong;
    fn lde_snd_close();
}

/// The stream, from `START` to `STOP`.
struct Stream {
    /// The device's buffer.
    area: *mut u8,
    /// The device has been started (by the first frames committed).
    running: bool,
    /// Frames the caller has written, copied into the buffer, and played;
    /// and how far the buffer is cleared behind what was played.
    written: u64,
    copied: u64,
    played: u64,
    cleared: u64,
    /// The hardware's last position in the buffer, in frames.
    position: u64,
    /// Times the device ran past what was written.
    underruns: u64,
    behind: bool,
}

struct Sound {
    /// The PCM device played through, and its name.
    device: c_int,
    /// Ring pages attached.
    pages: u64,
    listening: bool,
    stream: Option<Stream>,
    /// Streams started, for the log.
    streams: u64,
}

struct Cell(UnsafeCell<Sound>);
// SAFETY: the component has one thread.
unsafe impl Sync for Cell {}
static SOUND: Cell = Cell(UnsafeCell::new(Sound {
    device: 0,
    pages: 0,
    listening: false,
    stream: None,
    streams: 0,
}));

/// The sound host's state, taken afresh at each use (see [`crate::host`]).
fn state() -> &'static mut Sound {
    // SAFETY: one thread, and no caller keeps the reference across a call
    // that could take it again.
    unsafe { &mut *SOUND.0.get() }
}

/// A C string of lde-snd.c's, as text.
fn text(p: *const c_char) -> &'static str {
    if p.is_null() {
        return "";
    }
    // SAFETY: lde-snd.c's strings end with a zero byte and live as long
    // as the card.
    let bytes = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
    core::str::from_utf8(bytes).unwrap_or("?")
}

fn bring_up(name: &'static str) -> Result<(), Failure> {
    start(name)?;
    let (mut pcms, mut midis, mut controls) = (0, 0, 0);
    // SAFETY: lde-snd.c's, after the probe; the pointers are to locals.
    let card = unsafe { lde_snd_card(&mut pcms, &mut midis, &mut controls) };
    if card.is_null() {
        return Err(("the driver registered no sound card", 0));
    }
    say!(
        "card: {}; {pcms} PCM device{}, {midis} MIDI port{}, {controls} mixer controls",
        text(card),
        if pcms == 1 { "" } else { "s" },
        if midis == 1 { "" } else { "s" }
    );
    let mut chosen = None;
    for i in 0..pcms {
        let (mut device, mut playback) = (0, 0);
        // SAFETY: as above.
        let pcm = text(unsafe { lde_snd_pcm(i, &mut device, &mut playback) });
        say!("PCM device {device}: \"{pcm}\", {playback} playback stream{}", if playback == 1 { "" } else { "s" });
        if playback > 0 && chosen.is_none() {
            chosen = Some(device);
        }
    }
    state().device = chosen.ok_or(("the card has no PCM device that plays", 0))?;
    let mut set = 0;
    for control in UNMUTE {
        let mut name = [0u8; 48];
        name[..control.len()].copy_from_slice(control.as_bytes());
        // SAFETY: lde-snd.c's; `name` ends with a zero byte.
        if unsafe { lde_snd_control_max(name.as_ptr() as *const c_char) } >= 0 {
            set += 1;
        }
    }
    say!("mixer: {set} controls set so the master and PCM outputs play at full volume");
    Ok(())
}

/// Lets go of the ring: deleting each page's capability unmaps it.
fn drop_ring() {
    let s = state();
    for p in 0..s.pages {
        syscall(Syscall::CapDelete, RING_SLOTS + p, [0; 4]);
    }
    s.pages = 0;
}

/// Stops and closes the stream, if one is open.
fn stop() {
    let Some(st) = state().stream.take() else { return };
    // SAFETY: lde-snd.c's, from the one thread.
    unsafe { lde_snd_close() };
    say!(
        "stream {} stopped: {} frames played ({} late, {} underrun{})",
        state().streams,
        st.played,
        st.written.saturating_sub(st.copied),
        st.underruns,
        if st.underruns == 1 { "" } else { "s" }
    );
}

/// `ATTACH`: keeps and maps page `page` of the caller's ring.
fn attach(page: u64, lent: bool) -> Status {
    if !lent || page >= audio::RING_PAGES {
        return Status::Invalid;
    }
    if page == 0 {
        stop();
        drop_ring();
    }
    if page != state().pages {
        return Status::Invalid;
    }
    // A copy of what was lent (the lent capability goes after the call),
    // mapped read-only: the host only ever reads the ring.
    if syscall(Syscall::CapMint, LENT, [RING_SLOTS + page, ALL, 0, 0]).status != 0 {
        return Status::Invalid;
    }
    let va = RING_VA + page * PAGE as u64;
    if syscall(Syscall::FrameMap, RING_SLOTS + page, [va, 0, 0, 0]).status != 0 {
        syscall(Syscall::CapDelete, RING_SLOTS + page, [0; 4]);
        return Status::Invalid;
    }
    state().pages += 1;
    Status::Ok
}

/// `START`: opens and prepares the PCM device; it starts with the first
/// frames committed.
fn start_stream() -> [u64; 4] {
    let fail = |s: Status| [s as u64, 0, 0, 0];
    if state().pages != audio::RING_PAGES {
        return fail(Status::Invalid);
    }
    stop();
    let (mut area, mut dma) = (core::ptr::null_mut(), 0u64);
    let bytes = (RING * FRAME) as c_uint;
    // SAFETY: lde-snd.c's, from the one thread; the pointers are to locals.
    let rc = unsafe { lde_snd_open(state().device, RATE, CHANNELS, bytes, (PERIOD * FRAME) as c_uint, &mut area, &mut dma) };
    if rc != 0 {
        say!("[fail] the driver could not open its PCM device (errno {})", -rc);
        return fail(Status::DeviceError);
    }
    let area = area as *mut u8;
    // SAFETY: the buffer is `bytes` long and the stream's alone.
    unsafe { core::ptr::write_bytes(area, 0, bytes as usize) };
    let s = state();
    s.streams += 1;
    s.stream = Some(Stream {
        area,
        running: false,
        written: 0,
        copied: 0,
        played: 0,
        cleared: 0,
        position: 0,
        underruns: 0,
        behind: false,
    });
    if s.streams <= 4 || s.streams.is_power_of_two() {
        say!(
            "stream {}: {RATE} Hz, 16-bit stereo, a {RING}-frame buffer at {dma:#x} in {PERIOD}-frame periods",
            s.streams
        );
    }
    [Status::Ok as u64, PERIOD, 0, 0]
}

/// Frame `f`'s place in the buffer and the ring.
fn place(f: u64) -> usize {
    ((f % RING) * FRAME) as usize
}

/// Learns how far the device has played and clears what it has. Whether
/// it played more.
fn update() -> bool {
    let Some(st) = state().stream.as_mut() else { return false };
    if !st.running {
        return false;
    }
    // SAFETY: lde-snd.c's, from the one thread.
    let (position, periods) = unsafe { (lde_snd_pointer() as u64 % RING, lde_snd_periods() as u64) };
    let mut played = st.played + (position + RING - st.position) % RING;
    // A whole lap between two looks shows only in the periods counted.
    while played + RING <= periods * PERIOD {
        played += RING;
    }
    st.position = position;
    if played == st.played {
        return false;
    }
    st.played = played;
    // What was played is cleared: frames written next lap land after.
    for f in st.cleared..played {
        let at = place(f);
        // SAFETY: inside the buffer, a frame at a time.
        unsafe { (st.area.add(at) as *mut u32).write_volatile(0) };
    }
    st.cleared = played;
    let behind = played > st.written;
    if behind && !st.behind {
        st.underruns += 1;
    }
    st.behind = behind;
    true
}

/// `COMMIT`: copies frames the caller wrote into the buffer.
fn commit(written: u64) -> [u64; 4] {
    let fail = |s: Status| [s as u64, 0, 0, 0];
    update();
    let Some(st) = state().stream.as_mut() else {
        return fail(Status::Invalid);
    };
    if written < st.written || written > st.played + RING {
        return fail(Status::Invalid);
    }
    // Frames the device has passed are never played.
    for f in st.copied.max(st.played)..written {
        let at = place(f);
        // SAFETY: inside the ring (mapped) and the buffer, a frame at a time.
        unsafe {
            let v = ((RING_VA as usize + at) as *const u32).read_volatile();
            (st.area.add(at) as *mut u32).write_volatile(v);
        }
    }
    dma_barrier();
    st.copied = st.copied.max(written);
    st.written = written;
    if !st.running && written > 0 {
        // SAFETY: lde-snd.c's, from the one thread.
        let rc = unsafe { lde_snd_trigger(1) };
        if rc != 0 {
            say!("[fail] the driver could not start its PCM device (errno {})", -rc);
            return fail(Status::DeviceError);
        }
        st.running = true;
    }
    [Status::Ok as u64, st.played, st.played + RING, 0]
}

fn serve(m: [u64; 4], cap: Option<u16>) -> [u64; 4] {
    let status = |s: Status| [s as u64, 0, 0, 0];
    match m[0] {
        audio::INFO if m[1] == audio::VERSION => {
            update();
            let (streams, playing) = match &state().stream {
                Some(st) => (1, (st.written > st.played) as u64),
                None => (0, 0),
            };
            [Status::Ok as u64, RATE as u64, streams, playing]
        }
        audio::ATTACH => status(attach(m[1], cap == Some(LENT as u16))),
        audio::LISTEN => {
            state().listening = cap == Some(LISTENER as u16);
            status(if state().listening { Status::Ok } else { Status::Invalid })
        }
        audio::START => start_stream(),
        audio::COMMIT => commit(m[1]),
        audio::STOP => {
            if state().stream.is_none() {
                return status(Status::Invalid);
            }
            stop();
            status(Status::Ok)
        }
        _ => status(Status::Invalid),
    }
}

/// Runs the Linux sound driver linked into this component, serving
/// `audio`. `name` is the driver's, for the log.
pub fn run(name: &'static str) -> ! {
    if let Err((what, code)) = bring_up(name) {
        say!("[fail] {what} ({code:#x})");
        superior_sys::park()
    }
    say!("Linux's {name} driver runs the sound card");
    // The interrupt and the driver's timers wake the same `Recv` that
    // waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the notification");
    }
    // A call may lend a ring page (ATTACH) or a notification (LISTEN):
    // either arrives in LENT.
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut reply: Option<[u64; 4]> = None;
    loop {
        // SAFETY: lde.c's, from the one thread.
        let timer = unsafe {
            lde_run_timers();
            lde_next_timer()
        } as u64;
        let wake = match (timer, state().stream.is_some()) {
            (0, true) => LOOK,
            (t, true) => t.min(LOOK),
            (t, false) => t,
        };
        syscall(Syscall::TimerSignal, NOTIFY, [wake, 0, 0, 0]);
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            // The interrupt or a timer: the driver's handler quiets the
            // device, so the line can be unmasked after.
            // SAFETY: the driver's, from the one thread.
            unsafe { lde_interrupt() };
            irq_ack(crate::IRQ);
            if update() && state().listening {
                syscall(Syscall::Signal, LISTENER, [0; 4]);
            }
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let mut cap = r.cap;
        if r.msg[0] == audio::LISTEN && cap == Some(LENT as u16) {
            // Keep the notification (replacing an earlier one).
            syscall(Syscall::CapDelete, LISTENER, [0; 4]);
            let kept = syscall(Syscall::CapMint, LENT, [LISTENER, ALL, 0, 0]).status == 0;
            syscall(Syscall::CapDelete, LENT, [0; 4]);
            cap = kept.then_some(LISTENER as u16);
        }
        let m = serve(r.msg, cap);
        if cap == Some(LENT as u16) {
            // The caller's page goes back before the reply (a copy is kept).
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}
