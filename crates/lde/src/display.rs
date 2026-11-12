//! A display driver's host: serves the `display` interface over the DRM
//! device the driver registers (`lde-drm.c`).
//!
//! The connector's modes are what the driver's get_modes reports (from
//! the display's EDID, if it read one) and its mode_valid accepts. The
//! caller lends its surface a page at a time; they are kept, mapped
//! read-only. `SET_MODE` has the driver make two framebuffers in video
//! memory (its fb_create) and commit the mode; each `FLUSH` copies a
//! rectangle of the surface into the framebuffer not shown and commits
//! that one (the driver's update: a page flip), then copies it into the
//! other too, so both always hold the whole picture. In a CSpace of 2^11
//! slots.

use crate::{ALL, CLASS_SLOTS, CLASS_VA, LENT, NOTIFY, PAGE, SERVICE, lde_next_timer, lde_run_timers, say, start};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use superior_driver::Failure;
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::idl::display;
use superior_objects::interfaces::Status;
use superior_sys::{syscall, syscall_x};

/// The caller's surface pages, mapped in a row.
const SURFACE: u64 = CLASS_SLOTS;
const SURFACE_VA: u64 = CLASS_VA;
const _: () = assert!(SURFACE + display::SURFACE_PAGES <= 2048);

unsafe extern "C" {
    fn lde_drm_probe() -> c_int;
    fn lde_drm_edid() -> c_int;
    fn lde_drm_mode(i: c_uint, width: *mut u32, height: *mut u32, refresh: *mut u32, preferred: *mut u32) -> c_int;
    fn lde_drm_start(i: c_uint, pitch: *mut u32) -> c_int;
    fn lde_drm_buffer(b: c_int) -> *mut c_void;
    fn lde_drm_buffer_offset(b: c_int) -> u64;
    fn lde_drm_flip(b: c_int) -> c_int;
}

struct Display {
    modes: u64,
    /// Surface pages attached.
    pages: u64,
    /// The mode shown, if one is: its size and pitch.
    shown: Option<(u32, u32, u32)>,
    /// The framebuffer shown, and flips so far.
    front: c_int,
    flips: u64,
}

struct Cell(UnsafeCell<Display>);
// SAFETY: the component has one thread.
unsafe impl Sync for Cell {}
static DISPLAY: Cell = Cell(UnsafeCell::new(Display {
    modes: 0,
    pages: 0,
    shown: None,
    front: 0,
    flips: 0,
}));

/// The display host's state, taken afresh at each use (see [`crate::host`]).
fn state() -> &'static mut Display {
    // SAFETY: one thread, and no caller keeps the reference across a call
    // that could take it again.
    unsafe { &mut *DISPLAY.0.get() }
}

/// Mode `i`: width, height, refresh rate, and whether it is preferred.
fn mode(i: u64) -> Option<(u32, u32, u32, bool)> {
    let (mut w, mut h, mut hz, mut preferred) = (0, 0, 0, 0);
    let i = c_uint::try_from(i).ok()?;
    // SAFETY: the pointers are to locals; lde-drm.c's, from the one thread.
    let there = unsafe { lde_drm_mode(i, &mut w, &mut h, &mut hz, &mut preferred) } != 0;
    there.then_some((w, h, hz, preferred != 0))
}

fn bring_up(name: &'static str) -> Result<(), Failure> {
    start(name)?;
    // SAFETY: lde-drm.c's, after the probe.
    let n = unsafe { lde_drm_probe() };
    if n <= 0 {
        return Err(("the connector reports no mode, errno", n.unsigned_abs() as u64));
    }
    state().modes = n as u64;
    let (w, h, hz, preferred) = mode(0).unwrap_or_default();
    say!(
        "{n} modes from the {}; {w}x{h} at {hz} Hz first{}",
        // SAFETY: lde-drm.c's.
        if unsafe { lde_drm_edid() } != 0 { "display's EDID" } else { "standard list" },
        if preferred { " (preferred)" } else { "" }
    );
    Ok(())
}

/// Lets go of the surface: deleting each page's capability unmaps it.
fn drop_surface() {
    let d = state();
    for p in 0..d.pages {
        syscall(Syscall::CapDelete, SURFACE + p, [0; 4]);
    }
    d.pages = 0;
}

/// `ATTACH`: keeps and maps page `page` of the caller's surface.
fn attach(page: u64, lent: bool) -> Status {
    if !lent || page >= display::SURFACE_PAGES {
        return Status::Invalid;
    }
    if page == 0 {
        drop_surface();
    }
    if page != state().pages {
        return Status::Invalid;
    }
    // A copy of what was lent (the lent capability goes after the call),
    // mapped read-only: the host only ever reads the surface.
    if syscall(Syscall::CapMint, LENT, [SURFACE + page, ALL, 0, 0]).status != 0 {
        return Status::Invalid;
    }
    let va = SURFACE_VA + page * PAGE as u64;
    if syscall(Syscall::FrameMap, SURFACE + page, [va, 0, 0, 0]).status != 0 {
        syscall(Syscall::CapDelete, SURFACE + page, [0; 4]);
        return Status::Invalid;
    }
    state().pages += 1;
    Status::Ok
}

/// `SET_MODE`: the driver makes the framebuffers and shows the mode.
fn set_mode(i: u64) -> [u64; 4] {
    let fail = |s: Status| [s as u64, 0, 0, 0];
    let Some((w, h, hz, _)) = mode(i) else {
        return fail(Status::Invalid);
    };
    if (w as u64 * 4 * h as u64).div_ceil(PAGE as u64) > state().pages {
        return fail(Status::Invalid);
    }
    let mut pitch = 0;
    // SAFETY: lde-drm.c's, from the one thread; `pitch` is a local.
    let rc = unsafe { lde_drm_start(i as c_uint, &mut pitch) };
    if rc != 0 {
        say!("[fail] the driver could not show {w}x{h} (errno {})", -rc);
        state().shown = None;
        return fail(Status::DeviceError);
    }
    let d = state();
    d.shown = Some((w, h, pitch));
    d.front = 0;
    // SAFETY: lde-drm.c's.
    let (front, back) = unsafe { (lde_drm_buffer_offset(0), lde_drm_buffer_offset(1)) };
    say!("{w}x{h} at {hz} Hz shown; framebuffers at {front:#x} and {back:#x} in video memory, pitch {pitch}");
    [Status::Ok as u64, pitch as u64, front, back]
}

/// Copies the rectangle from the surface into framebuffer `b`, a pixel at
/// a time: video memory is device memory, where wider or unaligned
/// accesses may fault.
fn copy(b: c_int, x: u32, y: u32, w: u32, h: u32, pitch: u32) {
    // SAFETY: lde-drm.c's: the framebuffer's mapping.
    let to = unsafe { lde_drm_buffer(b) } as *mut u32;
    if to.is_null() {
        return;
    }
    for row in y..y + h {
        let at = (row * pitch + x * 4) as usize / 4;
        let from = (SURFACE_VA as *const u32).wrapping_add(at);
        for k in 0..w as usize {
            // SAFETY: the rectangle lies in the mode, whose rows the
            // surface's attached pages and the framebuffer both hold.
            unsafe { to.add(at + k).write_volatile(from.add(k).read()) };
        }
    }
}

/// `FLUSH`: shows the surface's rectangle.
fn flush(rect: u64) -> [u64; 4] {
    let fail = |s: Status| [s as u64, 0, 0, 0];
    let Some((mw, mh, pitch)) = state().shown else {
        return fail(Status::Invalid);
    };
    let (x, y) = (rect as u32 & 0xffff, (rect >> 16) as u32 & 0xffff);
    let (w, h) = ((rect >> 32) as u32 & 0xffff, (rect >> 48) as u32 & 0xffff);
    if w == 0 || h == 0 || x + w > mw || y + h > mh {
        return fail(Status::Invalid);
    }
    let back = 1 - state().front;
    copy(back, x, y, w, h, pitch);
    // SAFETY: lde-drm.c's, from the one thread.
    let rc = unsafe { lde_drm_flip(back) };
    if rc != 0 {
        say!("[fail] the driver could not flip (errno {})", -rc);
        return fail(Status::DeviceError);
    }
    let d = state();
    d.front = back;
    d.flips += 1;
    let flips = d.flips;
    // The framebuffer now hidden catches up.
    copy(1 - back, x, y, w, h, pitch);
    if flips <= 4 || flips.is_power_of_two() {
        say!("flip {flips}: framebuffer {back} shown, {w}x{h} at ({x}, {y}) copied in");
    }
    [Status::Ok as u64, back as u64, flips, 0]
}

fn serve(m: [u64; 4], lent: bool) -> [u64; 4] {
    let status = |s: Status| [s as u64, 0, 0, 0];
    match m[0] {
        display::INFO if m[1] == display::VERSION => {
            let modes = state().modes;
            let preferred = (0..modes).find(|&i| mode(i).is_some_and(|m| m.3)).unwrap_or(0);
            // SAFETY: lde-drm.c's.
            let edid = unsafe { lde_drm_edid() } as u64;
            [Status::Ok as u64, modes, preferred, edid]
        }
        display::MODE => match mode(m[1]) {
            Some((w, h, hz, _)) => [Status::Ok as u64, w as u64, h as u64, hz as u64],
            None => status(Status::NotFound),
        },
        display::ATTACH => status(attach(m[1], lent)),
        display::SET_MODE => set_mode(m[1]),
        display::FLUSH => flush(m[1]),
        _ => status(Status::Invalid),
    }
}

/// Runs the Linux display driver linked into this component, serving
/// `display`. `name` is the driver's, for the log.
pub fn run(name: &'static str) -> ! {
    if let Err((what, code)) = bring_up(name) {
        say!("[fail] {what} ({code:#x})");
        superior_sys::park()
    }
    say!("Linux's {name} driver runs the display");
    // The driver's timers wake the same `Recv` that waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the notification");
    }
    // A call may lend a surface page (ATTACH): it arrives in LENT.
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut reply: Option<[u64; 4]> = None;
    loop {
        // SAFETY: lde.c's, from the one thread.
        let wake = unsafe {
            lde_run_timers();
            lde_next_timer()
        } as u64;
        syscall(Syscall::TimerSignal, NOTIFY, [wake, 0, 0, 0]);
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() || r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let m = serve(r.msg, lent);
        if lent {
            // The caller's page goes back before the reply (a copy is kept).
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}
