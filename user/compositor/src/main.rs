//! The compositor: the display server. It is the display driver's one
//! client and serves `window` to every other component that draws.
//!
//! Its screen is a surface of its own pages, lent to the display driver.
//! A client draws a window into pages of its own and lends them here, a
//! page at a time; they are kept, mapped read-only. When a client commits
//! a rectangle of a window, the compositor repaints that part of the
//! screen, the desktop first and then every window over it from back to
//! front, and has the driver show it (the driver copies it into the
//! framebuffer not shown and flips, so the screen changes whole).
//!
//! Crash-only. A restarted compositor knows no windows; the clients' next
//! calls fail once and they make theirs again. A restarted display driver
//! has lost the screen: a flush it refuses has the compositor lend it the
//! screen again and repaint all of it (and it checks every half second
//! while nothing is drawn). A client that is restarted or stopped takes
//! its pages with it (the manager revokes its memory, and with it the
//! copies kept here): the compositor checks each window's first page
//! before it reads the window and every fifth of a second, and takes away
//! the window whose page is gone.
//!
//! Input comes from an input driver (`input`), which signals a badged
//! copy of the compositor's notification when events arrive. The pointer
//! is drawn over everything once it first moves. The window under it gets
//! pointer events; a button pressed over a window gives it the keyboard
//! focus, puts it in front and holds the pointer to it until every button
//! is let go. A tablet's absolute position spans the whole screen; the
//! wheel turns for the window the pointer events go to. Keys go to the
//! window with the focus. Each window keeps its
//! events until its client reads them and signals the notification the
//! client lent. A restarted input driver has forgotten the subscription:
//! a read it refuses has the compositor subscribe again (and it reads
//! every fifth of a second as well as when signalled).
//!
//! Slots: 0 the display, 1 the receive side of `window`, 2 a notification
//! (its timer and input), 3 memory for the screen, 6 the input driver (if
//! any).

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::idl::{display, window};
use superior_objects::interfaces::{Status, input};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const DISPLAY: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const MEMORY: u64 = 3;
/// Where a lent page or notification arrives.
const LENT: u64 = 4;
/// Where a window's first page is copied to see if it is still there.
const PROBE: u64 = 5;
const INPUT: u64 = 6;
/// A copy of the notification badged `INPUT_BADGE`, lent to the input
/// driver.
const INPUT_CAP: u64 = 7;
const INPUT_BADGE: u64 = 1;
/// The screen's pages.
const SCREEN: u64 = 16;
/// The notification each window's client lent (`LISTEN`).
const LISTENERS: u64 = SCREEN + SCREEN_PAGES;
const _: () = assert!(LISTENERS + window::MAX_WINDOWS <= WINDOW_SLOTS);
/// Each window's pages: window `i` from `WINDOW_SLOTS + i *
/// window::WINDOW_PAGES`.
const WINDOW_SLOTS: u64 = 1056;
const _: () = assert!(WINDOW_SLOTS + window::MAX_WINDOWS * window::WINDOW_PAGES <= 1 << 13);
const SCREEN_VA: u64 = USER_BASE + 0x4000_0000;
/// Window `i`'s pages, in a row from `WINDOW_VA + i * WINDOW_SPAN`.
const WINDOW_VA: u64 = USER_BASE + 0x5000_0000;
const WINDOW_SPAN: u64 = 0x20_0000;
const _: () = assert!(window::WINDOW_PAGES * 4096 <= WINDOW_SPAN);
/// The most screen pages (1024x768).
const SCREEN_PAGES: u64 = display::SURFACE_PAGES;
const _: () = assert!(SCREEN + SCREEN_PAGES <= WINDOW_SLOTS);
/// Rights for a copy of a lent page.
const ALL: u64 = 0x1f;
/// Ticks between checks that every window's client is still there.
const CHECK_TICKS: u64 = 20;
/// Ticks without a flush after which the driver is asked whether it still
/// shows the screen.
const KEEPALIVE_TICKS: u64 = 50;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("compositor: {}", format_args!($($t)*))) };
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// The desktop behind the windows: squares of 16 pixels in two shades.
/// `cargo xtask desktop-test` computes the same to check screenshots.
fn desktop(x: u32, y: u32) -> u32 {
    if ((x >> 4) + (y >> 4)) & 1 == 0 { 0x0028_3040 } else { 0x0030_3848 }
}

/// The pointer, its tip at the top left: `#` black, `o` white, a space
/// what is under it. `cargo xtask input-test` draws the same to check
/// screenshots.
const CURSOR: [&[u8; 12]; 17] = [
    b"#           ",
    b"##          ",
    b"#o#         ",
    b"#oo#        ",
    b"#ooo#       ",
    b"#oooo#      ",
    b"#ooooo#     ",
    b"#oooooo#    ",
    b"#ooooooo#   ",
    b"#oooooooo#  ",
    b"#ooooo##### ",
    b"#oo#oo#     ",
    b"#o# #oo#    ",
    b"##  #oo#    ",
    b"#    #oo#   ",
    b"     #oo#   ",
    b"      ##    ",
];
const CURSOR_W: u32 = 12;
const CURSOR_H: u32 = 17;

/// A window's events not yet read.
#[derive(Clone, Copy)]
struct Queue {
    events: [(u64, u64, u64); window::EVENTS as usize],
    head: usize,
    len: usize,
    /// Whether its client lent a notification.
    listening: bool,
}

const EMPTY_QUEUE: Queue = Queue {
    events: [(0, 0, 0); window::EVENTS as usize],
    head: 0,
    len: 0,
    listening: false,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Rect {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

impl Rect {
    fn from_word(r: u64) -> Rect {
        Rect {
            x: r as u32 & 0xffff,
            y: (r >> 16) as u32 & 0xffff,
            w: (r >> 32) as u32 & 0xffff,
            h: (r >> 48) as u32 & 0xffff,
        }
    }

    fn word(self) -> u64 {
        self.x as u64 | (self.y as u64) << 16 | (self.w as u64) << 32 | (self.h as u64) << 48
    }

    fn empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    fn intersect(self, o: Rect) -> Rect {
        let (x0, y0) = (self.x.max(o.x), self.y.max(o.y));
        let (x1, y1) = ((self.x + self.w).min(o.x + o.w), (self.y + self.h).min(o.y + o.h));
        if x1 <= x0 || y1 <= y0 {
            NONE
        } else {
            Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
        }
    }

    /// The smallest rectangle holding both.
    fn union(self, o: Rect) -> Rect {
        if self.empty() {
            return o;
        }
        if o.empty() {
            return self;
        }
        let (x0, y0) = (self.x.min(o.x), self.y.min(o.y));
        let (x1, y1) = ((self.x + self.w).max(o.x + o.w), (self.y + self.h).max(o.y + o.h));
        Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
    }
}

const NONE: Rect = Rect { x: 0, y: 0, w: 0, h: 0 };

#[derive(Clone, Copy)]
struct Window {
    /// The badge of the client that made it.
    owner: u64,
    /// Where it is on the screen, and its size.
    at: Rect,
    /// Pages attached so far.
    pages: u64,
    shown: bool,
}

impl Window {
    fn needed(&self) -> u64 {
        (self.at.w as u64 * self.at.h as u64 * 4).div_ceil(4096)
    }
}

struct Compositor {
    width: u32,
    height: u32,
    /// The screen's pages attached to the driver, and whether it shows
    /// them.
    screen_pages: u64,
    showing: bool,
    windows: [Option<Window>; window::MAX_WINDOWS as usize],
    /// Shown windows, back to front.
    order: [usize; window::MAX_WINDOWS as usize],
    shown: usize,
    /// Times the screen changed, and when it last did.
    frames: u64,
    last_flush: u64,
    /// Windows taken away because their client went, and the part of the
    /// screen they leave to repaint.
    reaped: u64,
    pending: Rect,
    queues: [Queue; window::MAX_WINDOWS as usize],
    /// Where the pointer is, and whether it is drawn (once it has moved).
    pointer: (u32, u32),
    cursor: bool,
    /// The buttons held.
    buttons: u64,
    /// The window under the pointer (or holding it), the one holding it
    /// while buttons are held, and the one with the keyboard focus.
    hover: Option<usize>,
    grab: Option<usize>,
    focus: Option<usize>,
    /// Whether the input driver has this compositor as a subscriber, and
    /// how many times it subscribed.
    subscribed: bool,
    subscriptions: u64,
}

/// A call to the display driver; while it restarts, tried again until the
/// new instance answers. `None` if it never does.
fn display_call(m: [u64; 4], page: Option<u64>) -> Option<[u64; 4]> {
    let x = CapTransfer {
        grant: page.map(|p| (SCREEN + p) as u16),
        accept: None,
    };
    for _ in 0..200 {
        let r = syscall_x(Syscall::Call, DISPLAY, m, x);
        if r.status == 0 {
            return Some(r.msg);
        }
        superior_sys::sleep(5);
    }
    None
}

fn screen_ptr() -> *mut u32 {
    SCREEN_VA as *mut u32
}

fn window_ptr(i: usize) -> *const u32 {
    (WINDOW_VA + i as u64 * WINDOW_SPAN) as *const u32
}

impl Compositor {
    /// Lends the screen to the driver and shows its preferred mode; the
    /// first time, makes the screen's pages.
    fn set_up_display(&mut self) -> bool {
        self.showing = false;
        let Some(info) = display_call(display::info(), None) else {
            return false;
        };
        let preferred = info[2];
        let Some(m) = display_call(display::mode(preferred), None) else {
            return false;
        };
        let (w, h) = (m[1] as u32, m[2] as u32);
        let pages = (w as u64 * h as u64 * 4).div_ceil(4096);
        if info[0] != 0 || m[0] != 0 || pages > SCREEN_PAGES {
            say!("[fail] the display offers no mode to show");
            return false;
        }
        if self.screen_pages == 0 {
            for p in 0..pages {
                let made = syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, SCREEN + p, 0]).status == 0
                    && syscall(Syscall::FrameMap, SCREEN + p, [SCREEN_VA + p * 4096, 1, 0, 0]).status == 0;
                if !made {
                    say!("[fail] no memory for the screen ({p} of {pages} pages)");
                    return false;
                }
            }
            self.screen_pages = pages;
        }
        let lent = (0..pages).all(|p| display_call(display::attach(p), Some(p)).is_some_and(|r| r[0] == 0));
        let r = display_call(display::set_mode(preferred), None);
        if !lent || r.is_none_or(|r| r[0] != 0 || r[1] != w as u64 * 4) {
            say!("[fail] the display would not show the screen");
            return false;
        }
        (self.width, self.height) = (w, h);
        self.showing = true;
        true
    }

    fn whole(&self) -> Rect {
        Rect { x: 0, y: 0, w: self.width, h: self.height }
    }

    /// Whether window `i`'s client still has it: its first page is still
    /// here. One whose page is gone is taken away.
    fn alive(&mut self, i: usize) -> bool {
        let Some(w) = self.windows[i] else {
            return false;
        };
        if w.pages == 0 {
            return true;
        }
        let slot = WINDOW_SLOTS + i as u64 * window::WINDOW_PAGES;
        if syscall(Syscall::CapMint, slot, [PROBE, ALL, 0, 0]).status == 0 {
            syscall(Syscall::CapDelete, PROBE, [0; 4]);
            return true;
        }
        say!("window {i} is gone with its client; taken off the screen");
        self.reaped += 1;
        if w.shown {
            self.pending = self.pending.union(w.at);
        }
        self.remove(i);
        false
    }

    /// Takes away every window whose client has gone; true if one was
    /// shown (its part of the screen is then pending).
    fn reap(&mut self) -> bool {
        for i in 0..self.windows.len() {
            let _ = self.alive(i);
        }
        !self.pending.empty()
    }

    /// Repaints `r` of the screen: the desktop, then each shown window.
    fn paint(&mut self, r: Rect) {
        let screen = screen_ptr();
        let pitch = self.width as usize;
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                // SAFETY: the screen's pages are mapped, writable, and hold
                // `width` times `height` pixels; `r` lies on the screen.
                unsafe { screen.add(y as usize * pitch + x as usize).write(desktop(x, y)) };
            }
        }
        for k in 0..self.shown {
            let i = self.order[k];
            let Some(w) = self.windows[i] else { continue };
            let part = w.at.intersect(r);
            if part.empty() {
                continue;
            }
            let from = window_ptr(i);
            for y in part.y..part.y + part.h {
                let row = (y - w.at.y) as usize * w.at.w as usize;
                for x in part.x..part.x + part.w {
                    // SAFETY: all the window's pages are mapped (it is shown
                    // only once they are), in a row from its address.
                    let p = unsafe { from.add(row + (x - w.at.x) as usize).read() };
                    // SAFETY: as above, for the screen.
                    unsafe { screen.add(y as usize * pitch + x as usize).write(p) };
                }
            }
        }
        let c = self.cursor_rect();
        let part = c.intersect(r);
        for y in part.y..part.y + part.h {
            for x in part.x..part.x + part.w {
                let p = match CURSOR[(y - c.y) as usize][(x - c.x) as usize] {
                    b'#' => 0,
                    b'o' => 0x00ff_ffff,
                    _ => continue,
                };
                // SAFETY: as above.
                unsafe { screen.add(y as usize * pitch + x as usize).write(p) };
            }
        }
    }

    /// Where the pointer is drawn (nothing before it first moves).
    fn cursor_rect(&self) -> Rect {
        if !self.cursor {
            return NONE;
        }
        let (x, y) = self.pointer;
        Rect { x, y, w: CURSOR_W, h: CURSOR_H }.intersect(self.whole())
    }

    /// Repaints `r` and has the driver show it. A driver that refuses (it
    /// was restarted and has lost the screen) gets the screen again, and
    /// all of it is shown.
    fn show(&mut self, r: Rect) {
        // Every window drawn must still be there; the parts of those gone
        // are repainted too.
        self.reap();
        let r = r.union(core::mem::replace(&mut self.pending, NONE)).intersect(self.whole());
        if r.empty() {
            return;
        }
        self.paint(r);
        self.flush(r);
    }

    fn flush(&mut self, r: Rect) {
        self.last_flush = ticks();
        if self.showing && display_call(display::flush(r.word()), None).is_some_and(|m| m[0] == 0) {
            self.frames += 1;
            return;
        }
        say!("the display lost the screen; lending it again");
        if self.set_up_display() {
            let all = self.whole();
            self.paint(all);
            if display_call(display::flush(all.word()), None).is_some_and(|m| m[0] == 0) {
                self.frames += 1;
                say!(
                    "the whole screen shown again ({} window{})",
                    self.shown,
                    if self.shown == 1 { "" } else { "s" }
                );
            }
        }
    }

    fn remove(&mut self, i: usize) {
        let Some(w) = self.windows[i].take() else { return };
        for p in 0..w.pages {
            syscall(Syscall::CapDelete, WINDOW_SLOTS + i as u64 * window::WINDOW_PAGES + p, [0; 4]);
        }
        syscall(Syscall::CapDelete, LISTENERS + i as u64, [0; 4]);
        self.queues[i] = EMPTY_QUEUE;
        self.unstack(i);
        if self.grab == Some(i) {
            self.grab = None;
        }
        if self.hover == Some(i) {
            self.hover = None;
        }
        if self.focus == Some(i) {
            // The front window takes the focus.
            self.focus = None;
            self.set_focus(self.front());
        }
    }

    fn front(&self) -> Option<usize> {
        self.shown.checked_sub(1).map(|k| self.order[k])
    }

    /// Gives window `i` an event, and signals its client.
    fn post(&mut self, i: usize, kind: u64, a: u64, b: u64) {
        let q = &mut self.queues[i];
        let n = q.events.len();
        if q.len == n {
            // The oldest goes.
            q.head = (q.head + 1) % n;
            q.len -= 1;
        }
        q.events[(q.head + q.len) % n] = (kind, a, b);
        q.len += 1;
        if q.listening {
            syscall(Syscall::Signal, LISTENERS + i as u64, [0; 4]);
        }
    }

    fn set_focus(&mut self, to: Option<usize>) {
        if to == self.focus {
            return;
        }
        if let Some(o) = self.focus {
            self.post(o, window::FOCUS, 0, 0);
        }
        self.focus = to;
        if let Some(n) = to {
            say!("window {n} has the focus");
            self.post(n, window::FOCUS, 1, 0);
        }
    }

    /// The front window under the pointer.
    fn window_at(&self) -> Option<usize> {
        let (x, y) = self.pointer;
        self.order[..self.shown].iter().rev().copied().find(|&i| {
            self.windows[i].is_some_and(|w| x >= w.at.x && x < w.at.x + w.at.w && y >= w.at.y && y < w.at.y + w.at.h)
        })
    }

    /// The pointer in window `i`'s pixels (x | y << 16, each a signed
    /// 16-bit number).
    fn local(&self, i: usize) -> u64 {
        let Some(w) = self.windows[i] else { return 0 };
        let x = (self.pointer.0 as i32 - w.at.x as i32) as i16 as u16 as u64;
        let y = (self.pointer.1 as i32 - w.at.y as i32) as i16 as u16 as u64;
        x | y << 16
    }

    /// Tells window `i` (if any) where the pointer is.
    fn post_pointer(&mut self, i: Option<usize>) {
        if let Some(i) = i {
            self.post(i, window::POINTER, self.local(i), self.buttons);
        }
    }

    /// The window under the pointer changed to `to`: the one it left is
    /// told so.
    fn hover_to(&mut self, to: Option<usize>) {
        if self.hover != to {
            if let Some(h) = self.hover {
                self.post(h, window::LEAVE, 0, 0);
            }
            self.hover = to;
        }
    }

    /// One event from the input driver: the part of the screen it changes.
    fn input_event(&mut self, kind: u64, a: u64, b: u64) -> Rect {
        match kind {
            input::KEY => {
                if let Some(f) = self.focus {
                    self.post(f, window::KEY, a, b);
                }
                NONE
            }
            input::MOTION => {
                let to = |at: u32, d: u64, size: u32| (at as i64 + d as i64).clamp(0, size as i64 - 1) as u32;
                self.move_pointer((to(self.pointer.0, a, self.width), to(self.pointer.1, b, self.height)))
            }
            input::POSITION => {
                // From 0..=POSITION_MAX over the device to the screen's pixels.
                let to = |v: u64, size: u32| ((v.min(input::POSITION_MAX) * size as u64) >> 16) as u32;
                self.move_pointer((to(a, self.width), to(b, self.height)))
            }
            input::WHEEL => {
                if let Some(i) = self.grab.or_else(|| self.window_at()) {
                    let steps = (a as i32 as u32 as u64) | (b as i32 as u32 as u64) << 32;
                    self.post(i, window::WHEEL, self.local(i), steps);
                }
                NONE
            }
            input::BUTTON if a < 8 => {
                let held = self.buttons;
                if b == 1 {
                    self.buttons |= 1 << a;
                } else {
                    self.buttons &= !(1 << a);
                }
                let mut damage = NONE;
                if held == 0 && self.buttons != 0 {
                    let under = self.window_at();
                    self.grab = under;
                    self.hover_to(under);
                    if let Some(i) = under {
                        self.set_focus(Some(i));
                        if self.front() != Some(i) {
                            self.to_front(i);
                            damage = self.windows[i].map_or(NONE, |w| w.at);
                        }
                    }
                }
                self.post_pointer(self.grab.or(self.hover));
                if self.buttons == 0 && held != 0 {
                    self.let_go();
                }
                damage
            }
            _ => NONE,
        }
    }

    /// The pointer moved to `to`: the window under it (or holding it) is
    /// told. The part of the screen it changes.
    fn move_pointer(&mut self, to: (u32, u32)) -> Rect {
        let before = self.cursor_rect();
        self.pointer = to;
        self.cursor = true;
        let target = self.grab.or_else(|| self.window_at());
        self.hover_to(target);
        self.post_pointer(target);
        before.union(self.cursor_rect())
    }

    /// Every button is up: the window that held the pointer lets it go,
    /// and the one under it gets it.
    fn let_go(&mut self) {
        self.grab = None;
        let under = self.window_at();
        if under != self.hover {
            self.hover_to(under);
            self.post_pointer(under);
        }
    }

    /// Subscribes to the input driver, lending it the badged notification.
    fn subscribe(&mut self) {
        let x = CapTransfer { grant: Some(INPUT_CAP as u16), accept: None };
        let r = syscall_x(Syscall::Call, INPUT, [input::SUBSCRIBE, input::VERSION, 0, 0], x);
        if r.status != 0 || r.msg[0] != Status::Ok as u64 {
            return;
        }
        self.subscribed = true;
        self.subscriptions += 1;
        if self.subscriptions == 1 {
            say!("input subscribed: keys and the pointer");
        } else {
            say!("the input driver restarted; input subscribed again");
        }
        // Buttons held then are up now.
        if self.buttons != 0 {
            self.buttons = 0;
            self.post_pointer(self.grab.or(self.hover));
            self.let_go();
        }
    }

    /// Reads every event the input driver has.
    fn read_input(&mut self) {
        if !self.subscribed {
            self.subscribe();
            if !self.subscribed {
                return;
            }
        }
        let mut damage = NONE;
        for _ in 0..256 {
            let r = syscall(Syscall::Call, INPUT, [input::READ, 0, 0, 0]);
            if r.status != 0 || (r.msg[0] != Status::Ok as u64 && r.msg[0] != Status::Empty as u64) {
                // Restarted: it no longer knows this subscriber.
                self.subscribed = false;
                break;
            }
            if r.msg[0] == Status::Empty as u64 {
                break;
            }
            damage = damage.union(self.input_event(r.msg[1], r.msg[2], r.msg[3]));
        }
        if !damage.empty() {
            self.show(damage);
        }
    }

    fn listen(&mut self, i: usize, lent: bool) -> Status {
        if !lent {
            return Status::Invalid;
        }
        let slot = LISTENERS + i as u64;
        syscall(Syscall::CapDelete, slot, [0; 4]);
        if syscall(Syscall::CapMint, LENT, [slot, ALL, 0, 0]).status != 0 {
            self.queues[i].listening = false;
            return Status::Invalid;
        }
        self.queues[i].listening = true;
        if self.queues[i].len > 0 {
            syscall(Syscall::Signal, slot, [0; 4]);
        }
        Status::Ok
    }

    fn next(&mut self, i: usize) -> [u64; 4] {
        let q = &mut self.queues[i];
        if q.len == 0 {
            return [Status::Empty as u64, 0, 0, 0];
        }
        let (kind, a, b) = q.events[q.head];
        q.head = (q.head + 1) % q.events.len();
        q.len -= 1;
        [Status::Ok as u64, kind, a, b]
    }

    fn unstack(&mut self, i: usize) {
        if let Some(k) = self.order[..self.shown].iter().position(|&o| o == i) {
            self.order.copy_within(k + 1..self.shown, k);
            self.shown -= 1;
        }
    }

    fn to_front(&mut self, i: usize) {
        self.unstack(i);
        self.order[self.shown] = i;
        self.shown += 1;
    }

    /// The caller's window `n`, if it has one by that number.
    fn own(&mut self, n: u64, badge: u64) -> Option<usize> {
        let i = usize::try_from(n).ok().filter(|&i| i < self.windows.len())?;
        if self.windows[i].is_some_and(|w| w.owner == badge) && self.alive(i) {
            Some(i)
        } else {
            None
        }
    }

    fn fits(&self, at: Rect) -> bool {
        !at.empty() && at.x + at.w <= self.width && at.y + at.h <= self.height
    }

    fn create(&mut self, size: u64, position: u64, badge: u64) -> [u64; 4] {
        let at = Rect::from_word(position & 0xffff_ffff | size << 32);
        if size >> 32 != 0 || position >> 32 != 0 || !self.fits(at) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let w = Window { owner: badge, at, pages: 0, shown: false };
        if w.needed() > window::WINDOW_PAGES {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        // Windows whose clients have gone make room.
        if self.reap() {
            self.show(NONE);
        }
        let Some(i) = self.windows.iter().position(Option::is_none) else {
            return [Status::InUse as u64, 0, 0, 0];
        };
        self.windows[i] = Some(w);
        self.queues[i] = EMPTY_QUEUE;
        [Status::Ok as u64, i as u64, 0, 0]
    }

    fn attach(&mut self, i: usize, page: u64, lent: bool) -> Status {
        let Some(w) = self.windows[i] else { return Status::NotFound };
        if !lent || page != w.pages || page >= w.needed() {
            return Status::Invalid;
        }
        let slot = WINDOW_SLOTS + i as u64 * window::WINDOW_PAGES + page;
        // A copy of what was lent (the lent capability goes after the
        // call), mapped read-only: windows are only ever read here.
        if syscall(Syscall::CapMint, LENT, [slot, ALL, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        let va = WINDOW_VA + i as u64 * WINDOW_SPAN + page * 4096;
        if syscall(Syscall::FrameMap, slot, [va, 0, 0, 0]).status != 0 {
            syscall(Syscall::CapDelete, slot, [0; 4]);
            return Status::Invalid;
        }
        if let Some(w) = self.windows[i].as_mut() {
            w.pages += 1;
        }
        Status::Ok
    }

    fn commit(&mut self, i: usize, rect: u64) -> [u64; 4] {
        let Some(mut w) = self.windows[i] else { return [Status::NotFound as u64, 0, 0, 0] };
        let r = Rect::from_word(rect);
        if w.pages < w.needed() || r.empty() || r.x + r.w > w.at.w || r.y + r.h > w.at.h {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let damage = if w.shown {
            Rect { x: w.at.x + r.x, y: w.at.y + r.y, w: r.w, h: r.h }
        } else {
            w.shown = true;
            self.windows[i] = Some(w);
            self.to_front(i);
            self.set_focus(Some(i));
            w.at
        };
        self.show(damage);
        [Status::Ok as u64, self.frames, 0, 0]
    }

    fn move_to(&mut self, i: usize, position: u64) -> Status {
        let Some(mut w) = self.windows[i] else { return Status::NotFound };
        let to = Rect { x: position as u32 & 0xffff, y: (position >> 16) as u32 & 0xffff, w: w.at.w, h: w.at.h };
        if position >> 32 != 0 || !self.fits(to) {
            return Status::Invalid;
        }
        let from = w.at;
        if from == to {
            return Status::Ok;
        }
        w.at = to;
        self.windows[i] = Some(w);
        if w.shown {
            self.show(from.union(to));
        }
        Status::Ok
    }

    fn serve(&mut self, m: [u64; 4], badge: u64, lent: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            window::INFO if m[1] == window::VERSION => {
                if self.reap() {
                    self.show(NONE);
                }
                [Status::Ok as u64, self.width as u64, self.height as u64, self.shown as u64]
            }
            window::CREATE => self.create(m[1], m[2], badge),
            op @ (window::ATTACH
            | window::COMMIT
            | window::MOVE_TO
            | window::RAISE
            | window::DESTROY
            | window::LISTEN
            | window::NEXT) => {
                let Some(i) = self.own(m[1], badge) else {
                    return status(Status::NotFound);
                };
                match op {
                    window::ATTACH => status(self.attach(i, m[2], lent)),
                    window::COMMIT => self.commit(i, m[2]),
                    window::MOVE_TO => status(self.move_to(i, m[2])),
                    window::LISTEN => status(self.listen(i, lent)),
                    window::NEXT => self.next(i),
                    window::RAISE => {
                        if let Some(w) = self.windows[i].filter(|w| w.shown) {
                            self.to_front(i);
                            self.show(w.at);
                        }
                        status(Status::Ok)
                    }
                    _ => {
                        let w = self.windows[i];
                        self.remove(i);
                        if let Some(w) = w.filter(|w| w.shown) {
                            self.show(w.at);
                        }
                        status(Status::Ok)
                    }
                }
            }
            _ => status(Status::Invalid),
        }
    }

    /// The timer: windows whose clients went, and a driver that may have
    /// lost the screen while nothing was drawn.
    fn tick(&mut self) {
        if self.reap() {
            self.show(NONE);
        }
        // An input driver that restarted refuses the read (or there is
        // none yet to subscribe to).
        self.read_input();
        if ticks() >= self.last_flush + KEEPALIVE_TICKS {
            // One pixel, repainted as it is: shows nothing new, but a
            // driver that lost the screen refuses it.
            let r = Rect { x: 0, y: 0, w: 1, h: 1 };
            self.paint(r);
            self.flush(r);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut c = Compositor {
        width: 0,
        height: 0,
        screen_pages: 0,
        showing: false,
        windows: [None; window::MAX_WINDOWS as usize],
        order: [0; window::MAX_WINDOWS as usize],
        shown: 0,
        frames: 0,
        last_flush: 0,
        reaped: 0,
        pending: NONE,
        queues: [EMPTY_QUEUE; window::MAX_WINDOWS as usize],
        pointer: (0, 0),
        cursor: false,
        buttons: 0,
        hover: None,
        grab: None,
        focus: None,
        subscribed: false,
        subscriptions: 0,
    };
    if !c.set_up_display() {
        superior_sys::park()
    }
    // The pointer starts in the middle of the screen.
    c.pointer = (c.width / 2, c.height / 2);
    let all = c.whole();
    c.paint(all);
    c.flush(all);
    say!("ready: the desktop on a {}x{} screen", c.width, c.height);
    // The timer wakes the same `Recv` that waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the notification");
    }
    if syscall(Syscall::CapMint, NOTIFY, [INPUT_CAP, ALL, INPUT_BADGE, 0]).status != 0 {
        say!("[fail] minting the input driver's copy of the notification");
    }
    c.read_input();
    let accept = CapTransfer { grant: None, accept: Some(LENT as u16) };
    let mut reply: Option<[u64; 4]> = None;
    let mut next_check = ticks() + CHECK_TICKS;
    loop {
        let now = ticks();
        if now >= next_check {
            c.tick();
            next_check = ticks() + CHECK_TICKS;
        }
        syscall(Syscall::TimerSignal, NOTIFY, [next_check.saturating_sub(ticks()).max(1), 0, 0, 0]);
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            if r.badge & INPUT_BADGE != 0 {
                c.read_input();
            }
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let m = c.serve(r.msg, r.badge, lent);
        if lent {
            // The caller's page goes back before the reply (a copy is kept).
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
