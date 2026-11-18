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
//! Style: a translucent window's pixels are blended over what is behind
//! them by their top byte; a decorated one gets a border and a title bar
//! with a close box, drawn here around its pixels (focused windows' title
//! bars in another colour), its title written in its title bar in the
//! toolkit's font. A button pressed on a title bar drags the
//! window until let go; one pressed on a close box tells its client. A
//! resizable window's right and bottom borders drag an outline of the
//! size asked for, drawn over every window; let go, its client is told
//! and sets the size it accepts.
//!
//! The desktop shell: a client whose badge is a manager's
//! (`MANAGER_BADGE`, from `manages window` in its manifest) may list,
//! describe and activate every window; its own windows are told when the
//! windows change, stay in front of every other client's and never take
//! the keyboard focus.
//!
//! Slots: 0 the display, 1 the receive side of `window`, 2 a notification
//! (its timer and input), 3 memory for the screen, 6 the input driver (if
//! any).

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall, TICK_HZ};
use superior_objects::idl::{display, window};
use superior_objects::interfaces::{Status, input};
use superior_objects::manifest::MANAGER_BADGE;
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
// The toolkit's keymap numbers its layouts as `window` does.
const _: () = {
    use superior_toolkit::keymap;
    assert!(keymap::US == window::LAYOUT_US && keymap::UK == window::LAYOUT_UK);
    assert!(keymap::DVORAK == window::LAYOUT_DVORAK && keymap::FRENCH == window::LAYOUT_FRENCH);
    assert!(keymap::LAYOUTS == window::LAYOUTS);
};

/// Key repeat's delay and interval in ticks.
const REPEAT_DELAY_TICKS: u64 = window::REPEAT_DELAY * TICK_HZ / 1000;
const REPEAT_TICKS: u64 = window::REPEAT_INTERVAL * TICK_HZ / 1000;

/// A key held for the window with the focus: its usage, the `KEY` event's
/// `b` (the modifier byte as it last was), when it next repeats and how
/// many times it has.
#[derive(Clone, Copy)]
struct Repeat {
    window: usize,
    usage: u64,
    b: u64,
    next: u64,
    count: u64,
}

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

/// Decorations' colours. `cargo xtask windows-test` has the same to check
/// screenshots.
const BORDER_COLOUR: u32 = 0x0018_1c22;
const TITLE_FOCUSED: u32 = 0x0035_6a9e;
const TITLE_UNFOCUSED: u32 = 0x0050_565e;
const CLOSE_COLOUR: u32 = 0x00c0_4038;
const CLOSE_CROSS: u32 = 0x00f0_f0f0;
const TITLE_TEXT: u32 = 0x00f0_f0f0;
/// Where a title starts in its title bar, from its left and top, at what
/// scale of the font, and the space it leaves before the close box.
const TITLE_LEFT: u32 = 4;
const TITLE_TOP: u32 = 2;
const TITLE_SCALE: u32 = 2;
const TITLE_GAP: u32 = 4;
/// The outline a resize drags: its colour and thickness.
const OUTLINE_COLOUR: u32 = 0x00f0_c040;
const OUTLINE: u32 = 2;

/// `src` (its top byte how opaque it is) over `dst`.
fn blend(src: u32, dst: u32) -> u32 {
    let a = src >> 24;
    let channel = |shift: u32| {
        let (s, d) = ((src >> shift) & 0xff, (dst >> shift) & 0xff);
        ((s * a + d * (255 - a) + 127) / 255) << shift
    };
    channel(16) | channel(8) | channel(0)
}

/// Where on a window (or its frame) a point is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Its own pixels.
    Inside,
    Title,
    Close,
    Minimise,
    /// A resizable window's maximise box.
    Maximise,
    Border,
    /// A border (or a corner between two), which resizes a resizable
    /// window: which of its sides move.
    Edge(Sides),
}

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

/// The sides of a window a drag of its frame moves.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Sides {
    left: bool,
    top: bool,
    right: bool,
    bottom: bool,
}

#[derive(Clone, Copy)]
struct Resize {
    window: usize,
    sides: Sides,
    from: (u32, u32),
    size: (u32, u32),
}

#[derive(Clone, Copy)]
struct Window {
    /// The badge of the client that made it.
    owner: u64,
    /// Where it is on the screen, and its size.
    at: Rect,
    /// Pages attached so far.
    pages: u64,
    shown: bool,
    /// `window::ALPHA` and `window::DECORATED`.
    style: u64,
    /// Its title, and how long it is.
    title: [u8; window::TITLE_BYTES as usize],
    title_len: usize,
    /// After a drag of its left or top border, until its client sets the
    /// size it takes: that its right (and bottom) edge stays where it is.
    anchored: Sides,
    /// Minimised: shown, but drawn nowhere, until activated.
    minimised: bool,
    /// Where its client's next `SET_SIZE` puts it (once maximised, or
    /// put back from that).
    place: Option<(u32, u32)>,
    /// Maximised: where it was, and its size.
    unmaximised: Option<Rect>,
    /// What its client says it is (`SET_ICON`), for the desktop shell.
    icon: u64,
}

/// A window at `at` resized to `size`: its left (or top) edge moved if
/// that side is in `sides`, so its right (or bottom) edge stays, else its
/// top left staying.
fn anchored(at: Rect, size: (u32, u32), sides: Sides) -> Rect {
    let x = if sides.left { (at.x + at.w).saturating_sub(size.0) } else { at.x };
    let y = if sides.top { (at.y + at.h).saturating_sub(size.1) } else { at.y };
    Rect { x, y, w: size.0, h: size.1 }
}

/// The frame of a window at `at` with `style`: itself, or with its
/// decorations around it; `None` if they would reach past the screen's
/// top or left.
fn frame_of(at: Rect, style: u64) -> Option<Rect> {
    if style & window::DECORATED == 0 {
        return Some(at);
    }
    let (b, t) = (window::BORDER as u32, window::TITLE as u32);
    Some(Rect { x: at.x.checked_sub(b)?, y: at.y.checked_sub(t + b)?, w: at.w + 2 * b, h: at.h + t + 2 * b })
}

impl Window {
    fn needed(&self) -> u64 {
        (self.at.w as u64 * self.at.h as u64 * 4).div_ceil(4096)
    }

    fn decorated(&self) -> bool {
        self.style & window::DECORATED != 0
    }

    /// The part of the screen it covers, decorations and all.
    fn frame(&self) -> Rect {
        frame_of(self.at, self.style).unwrap_or(self.at)
    }

    /// Which part of it (x, y) on the screen is, if any.
    fn part(&self, x: u32, y: u32) -> Option<Part> {
        let f = self.frame();
        let within = |r: Rect| x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
        if !within(f) {
            return None;
        }
        if within(self.at) {
            return Some(Part::Inside);
        }
        let (t, m, c) = (window::TITLE as u32, window::CLOSE_MARGIN as u32, window::CLOSE_BOX as u32);
        let top = self.at.y - t;
        if !within(Rect { x: self.at.x, y: top, w: self.at.w, h: t }) {
            // The top border is the strip above the title bar.
            let sides = Sides {
                left: x < self.at.x,
                top: y < top,
                right: x >= self.at.x + self.at.w,
                bottom: y >= self.at.y + self.at.h,
            };
            if sides != Sides::default() && self.style & window::RESIZABLE != 0 {
                return Some(Part::Edge(sides));
            }
            return Some(Part::Border);
        }
        let right = self.at.x + self.at.w;
        if y < top + m || y >= top + m + c {
            return Some(Part::Title);
        }
        // Box k from the right spans [right - (k + 1)(m + c), that + c).
        let k = (0..self.boxes()).find(|&k| x + (k + 1) * (m + c) >= right && x + k * (m + c) + m < right);
        Some(match (k, self.boxes()) {
            (Some(0), _) => Part::Close,
            (Some(1), 3) => Part::Maximise,
            (Some(_), _) => Part::Minimise,
            (None, _) => Part::Title,
        })
    }

    /// How many boxes its title bar has at its right end: close, then
    /// maximise (if resizable), then minimise.
    fn boxes(&self) -> u32 {
        if self.style & window::RESIZABLE != 0 { 3 } else { 2 }
    }

    /// (x, y) on the screen in box `k` (from the right) of its title bar.
    fn in_box(&self, k: u32, x: u32, y: u32) -> (u32, u32) {
        let (m, c) = (window::CLOSE_MARGIN as u32, window::CLOSE_BOX as u32);
        (x + (k + 1) * (m + c) - (self.at.x + self.at.w), y - (self.at.y - window::TITLE as u32 + m))
    }

    /// As much of its title as fits before its boxes.
    fn shown_title(&self) -> &[u8] {
        let (m, c) = (window::CLOSE_MARGIN as u32, window::CLOSE_BOX as u32);
        let room = self.at.w.saturating_sub(TITLE_LEFT + TITLE_GAP + self.boxes() * (m + c));
        let fits = (room / TITLE_SCALE + 1) / superior_toolkit::font::ADVANCE;
        let title = &self.title[..self.title_len];
        &title[..superior_toolkit::font::ahead(title, 0, fits as usize)]
    }

    /// Its decoration's pixel at (x, y) on the screen, a part of its frame
    /// outside it.
    fn decoration(&self, x: u32, y: u32, focused: bool) -> u32 {
        match self.part(x, y) {
            Some(Part::Title) => {
                let (tx, ty) = (self.at.x + TITLE_LEFT, self.at.y - window::TITLE as u32 + TITLE_TOP);
                if x >= tx
                    && y >= ty
                    && superior_toolkit::font::text_lit(self.shown_title(), TITLE_SCALE, x - tx, y - ty)
                {
                    TITLE_TEXT
                } else if focused {
                    TITLE_FOCUSED
                } else {
                    TITLE_UNFOCUSED
                }
            }
            Some(Part::Close) => {
                let c = window::CLOSE_BOX as u32;
                let (cx, cy) = self.in_box(0, x, y);
                if (3..c - 3).contains(&cx) && (cx == cy || cx + cy == c - 1) { CLOSE_CROSS } else { CLOSE_COLOUR }
            }
            Some(Part::Maximise) => {
                // A square outline, its top thicker.
                let c = window::CLOSE_BOX as u32;
                let (cx, cy) = self.in_box(1, x, y);
                let inside = (3..c - 3).contains(&cx) && (3..c - 3).contains(&cy);
                if inside && (cx == 3 || cx == c - 4 || cy <= 4 || cy == c - 4) { CLOSE_CROSS } else { CLOSE_COLOUR }
            }
            Some(Part::Minimise) => {
                // A bar along its bottom.
                let c = window::CLOSE_BOX as u32;
                let (cx, cy) = self.in_box(self.boxes() - 1, x, y);
                if (3..c - 3).contains(&cx) && (c - 5..c - 3).contains(&cy) { CLOSE_CROSS } else { CLOSE_COLOUR }
            }
            _ => BORDER_COLOUR,
        }
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
    /// A resize's new size to say, once its outline is shown.
    asking: Option<(usize, (u32, u32))>,
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
    /// The last pointer event posted: to which window, and where in it.
    posted: Option<(usize, u64)>,
    grab: Option<usize>,
    focus: Option<usize>,
    /// The key held, repeating.
    repeat: Option<Repeat>,
    /// The keyboard layout (`window::LAYOUT_*`).
    layout: u64,
    /// The clipboard's text, a zero byte ending it early.
    clipboard: [u8; window::CLIPBOARD_BYTES as usize],
    /// The window dragged by its title bar, and where the pointer is on it
    /// (from its top left); whether it has moved.
    drag: Option<(usize, (i32, i32))>,
    dragged: bool,
    /// The window being resized by its frame: which edges move, where the
    /// pointer was pressed, and the size asked for so far.
    resize: Option<Resize>,
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
            self.pending = self.pending.union(w.frame());
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
            let part = w.frame().intersect(r);
            if part.empty() {
                continue;
            }
            let (alpha, focused) = (w.style & window::ALPHA != 0, self.focus == Some(i));
            let from = window_ptr(i);
            for y in part.y..part.y + part.h {
                for x in part.x..part.x + part.w {
                    // SAFETY: as above, for the screen.
                    let to = unsafe { screen.add(y as usize * pitch + x as usize) };
                    let inside = x >= w.at.x && x < w.at.x + w.at.w && y >= w.at.y && y < w.at.y + w.at.h;
                    let p = if inside {
                        let at = (y - w.at.y) as usize * w.at.w as usize + (x - w.at.x) as usize;
                        // SAFETY: all the window's pages are mapped (it is
                        // shown only once they are), in a row from its
                        // address.
                        let p = unsafe { from.add(at).read() };
                        // SAFETY: as above, for the screen.
                        if alpha { blend(p, unsafe { to.read() }) } else { p }
                    } else {
                        w.decoration(x, y, focused)
                    };
                    // SAFETY: as above.
                    unsafe { to.write(p) };
                }
            }
        }
        let o = self.outline();
        if !o.empty() {
            for y in r.y..r.y + r.h {
                for x in r.x..r.x + r.w {
                    let inside = x >= o.x + OUTLINE && x + OUTLINE < o.x + o.w && y >= o.y + OUTLINE && y + OUTLINE < o.y + o.h;
                    if x >= o.x && x < o.x + o.w && y >= o.y && y < o.y + o.h && !inside {
                        // SAFETY: as above.
                        unsafe { screen.add(y as usize * pitch + x as usize).write(OUTLINE_COLOUR) };
                    }
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

    /// The outline of the frame a resize asks for, if one is dragged.
    fn outline(&self) -> Rect {
        let Some(z) = self.resize else { return NONE };
        let Some(w) = self.windows[z.window] else { return NONE };
        let at = anchored(w.at, z.size, z.sides);
        frame_of(at, w.style).unwrap_or(at).intersect(self.whole())
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
        self.pointer_still();
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
        if self.drag.is_some_and(|(d, _)| d == i) {
            (self.drag, self.dragged) = (None, false);
        }
        if self.resize.is_some_and(|z| z.window == i) {
            self.pending = self.pending.union(self.outline());
            self.resize = None;
        }
        if self.focus == Some(i) {
            // The front window takes the focus.
            self.focus = None;
            self.set_focus(self.front());
        }
        self.changed();
    }

    /// The front window that may have the focus: not a manager's.
    fn front(&self) -> Option<usize> {
        self.order[..self.shown].iter().rev().copied().find(|&i| !self.manager(i))
    }

    /// Whether window `i` is a manager's (the desktop shell's).
    fn manager(&self, i: usize) -> bool {
        self.windows[i].is_some_and(|w| w.owner & MANAGER_BADGE != 0)
    }

    /// The windows, their titles or the focus changed: every manager's
    /// window is told (once, until it reads it).
    fn changed(&mut self) {
        for i in 0..self.windows.len() {
            if !self.manager(i) {
                continue;
            }
            let q = &self.queues[i];
            let n = q.events.len();
            if q.len > 0 && q.events[(q.head + q.len - 1) % n].0 == window::WINDOWS {
                continue;
            }
            self.post(i, window::WINDOWS, 0, 0);
        }
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

    /// Gives window `to` the focus (none for `None`); a manager's window
    /// (the panel's menu newly shown) never takes it, and the focus stays.
    fn set_focus(&mut self, to: Option<usize>) {
        if to.is_some_and(|i| self.manager(i)) || to == self.focus {
            return;
        }
        self.stop_repeat();
        if let Some(o) = self.focus {
            self.post(o, window::FOCUS, 0, 0);
            self.repaint_title(o);
        }
        self.focus = to;
        if let Some(n) = to {
            say!("window {n} has the focus");
            self.post(n, window::FOCUS, 1, 0);
            self.repaint_title(n);
        }
        self.changed();
    }

    /// Window `i`'s title bar shows whether it has the focus: if it is a
    /// shown decorated window, its frame is to be repainted.
    fn repaint_title(&mut self, i: usize) {
        if let Some(w) = self.windows[i].filter(|w| w.shown && w.decorated()) {
            self.pending = self.pending.union(w.frame());
        }
    }

    /// The front window whose frame the pointer is on, and where on it.
    fn hit(&self) -> Option<(usize, Part)> {
        let (x, y) = self.pointer;
        self.order[..self.shown]
            .iter()
            .rev()
            .find_map(|&i| self.windows[i].and_then(|w| w.part(x, y)).map(|p| (i, p)))
    }

    /// The front window under the pointer, if the pointer is on its own
    /// pixels (not its decorations).
    fn window_at(&self) -> Option<usize> {
        self.hit().filter(|&(_, p)| p == Part::Inside).map(|(i, _)| i)
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
            let at = self.local(i);
            self.posted = Some((i, at));
            self.post(i, window::POINTER, at, self.buttons);
        }
    }

    /// The windows changed under a pointer that did not move (one moved,
    /// appeared, went, was raised, minimised or resized): the window now
    /// under it is told where it is, and one it left that it left, as if
    /// the pointer had moved. Not while a button holds the pointer to a
    /// window or a frame is dragged.
    fn pointer_still(&mut self) {
        if !self.cursor || self.grab.is_some() || self.drag.is_some() || self.resize.is_some() || self.buttons != 0 {
            return;
        }
        let target = self.window_at();
        if target == self.hover && target.is_none_or(|i| self.posted == Some((i, self.local(i)))) {
            return;
        }
        self.hover_to(target);
        self.post_pointer(target);
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
                    self.post(f, window::KEY, a, self.typed(a, b));
                }
                let modifier = (0xe0..=0xe7).contains(&a);
                if b & 1 == 1 && !modifier {
                    self.stop_repeat();
                    self.repeat = self.focus.map(|f| Repeat { window: f, usage: a, b, next: ticks() + REPEAT_DELAY_TICKS, count: 0 });
                } else if b & 1 == 0 && self.repeat.is_some_and(|r| r.usage == a) {
                    self.stop_repeat();
                } else if let Some(r) = self.repeat.as_mut() {
                    // Shift or Control pressed or let go meanwhile.
                    r.b = r.b & !0xff00 | b & 0xff00;
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
                    let hit = self.hit();
                    let under = hit.filter(|&(_, p)| p == Part::Inside).map(|(i, _)| i);
                    self.grab = under;
                    self.hover_to(under);
                    if let Some((i, part)) = hit.filter(|&(i, _)| !self.manager(i)) {
                        self.set_focus(Some(i));
                        if self.front() != Some(i) {
                            self.to_front(i);
                            damage = self.windows[i].map_or(NONE, |w| w.frame());
                        }
                        match (part, self.windows[i]) {
                            (Part::Title, Some(w)) => {
                                let (x, y) = self.pointer;
                                self.drag = Some((i, (x as i32 - w.at.x as i32, y as i32 - w.at.y as i32)));
                                self.dragged = false;
                            }
                            (Part::Close, _) => {
                                say!("window {i}: its close box was pressed");
                                self.post(i, window::CLOSE, 0, 0);
                            }
                            (Part::Minimise, _) => {
                                say!("window {i}: its minimise box was pressed");
                                damage = damage.union(self.minimise(i));
                            }
                            (Part::Maximise, _) => {
                                say!("window {i}: its maximise box was pressed");
                                self.maximise(i);
                            }
                            (Part::Edge(sides), Some(w)) => {
                                self.resize = Some(Resize { window: i, sides, from: self.pointer, size: (w.at.w, w.at.h) });
                            }
                            _ => {}
                        }
                    }
                }
                self.post_pointer(self.grab.or(self.hover));
                if self.buttons == 0 && held != 0 {
                    self.end_drag();
                    damage = damage.union(self.end_resize());
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
        if let Some((i, (ox, oy))) = self.drag {
            return before.union(self.cursor_rect()).union(self.drag_to(i, ox, oy));
        }
        if self.resize.is_some() {
            return before.union(self.cursor_rect()).union(self.resize_to());
        }
        let target = self.grab.or_else(|| self.window_at());
        self.hover_to(target);
        self.post_pointer(target);
        before.union(self.cursor_rect())
    }

    /// Moves window `i`, dragged by its title bar, to keep the pointer
    /// where it was on it (`ox`, `oy` from its top left), its frame on the
    /// screen. The part of the screen it changes.
    fn drag_to(&mut self, i: usize, ox: i32, oy: i32) -> Rect {
        let Some(mut w) = self.windows[i] else { return NONE };
        let (b, t) = (window::BORDER as u32, window::TITLE as u32);
        let (min_x, min_y) = (b, t + b);
        let max_x = self.width.saturating_sub(w.at.w + b).max(min_x);
        let max_y = self.height.saturating_sub(w.at.h + b).max(min_y);
        let x = (self.pointer.0 as i32 - ox).clamp(min_x as i32, max_x as i32) as u32;
        let y = (self.pointer.1 as i32 - oy).clamp(min_y as i32, max_y as i32) as u32;
        if (x, y) == (w.at.x, w.at.y) {
            return NONE;
        }
        let from = w.frame();
        (w.at.x, w.at.y) = (x, y);
        self.windows[i] = Some(w);
        self.dragged = true;
        from.union(w.frame())
    }

    /// The pointer moved while a window's frame is dragged: the size it
    /// asks for, at least `MIN_WIDTH` by `MIN_HEIGHT`, its frame on the
    /// screen and its pixels within the pages attached. The part of the
    /// screen it changes.
    fn resize_to(&mut self) -> Rect {
        let Some(mut z) = self.resize else { return NONE };
        let Some(w) = self.windows[z.window] else { return NONE };
        let grow = |from: u32, to: u32, size: u32| (size as i64 + to as i64 - from as i64).max(0) as u32;
        let (b, t) = if w.decorated() { (window::BORDER as u32, window::TITLE as u32) } else { (0, 0) };
        let s = z.sides;
        let mut size = (
            if s.right {
                grow(z.from.0, self.pointer.0, w.at.w)
            } else if s.left {
                grow(self.pointer.0, z.from.0, w.at.w)
            } else {
                w.at.w
            },
            if s.bottom {
                grow(z.from.1, self.pointer.1, w.at.h)
            } else if s.top {
                grow(self.pointer.1, z.from.1, w.at.h)
            } else {
                w.at.h
            },
        );
        // Its frame on the screen: a side dragged left or up stops at the
        // screen's edge, the opposite side staying where it is.
        let room = (
            if s.left { (w.at.x + w.at.w).saturating_sub(b) } else { self.width.saturating_sub(w.at.x + b) },
            if s.top { (w.at.y + w.at.h).saturating_sub(t + b) } else { self.height.saturating_sub(w.at.y + b) },
        );
        size.0 = size.0.clamp(window::MIN_WIDTH as u32, room.0.max(window::MIN_WIDTH as u32));
        size.1 = size.1.clamp(window::MIN_HEIGHT as u32, room.1.max(window::MIN_HEIGHT as u32));
        // As many rows as the pages attached hold at that width.
        let rows = (w.pages * 1024 / size.0 as u64) as u32;
        size.1 = size.1.min(rows.max(1));
        if size == z.size {
            return NONE;
        }
        let before = self.outline();
        z.size = size;
        self.resize = Some(z);
        // Said once the outline is on the screen.
        self.asking = Some((z.window, size));
        before.union(self.outline())
    }

    /// The buttons are up: a window whose frame was dragged is told the
    /// size asked for (if not its own). The part of the screen to repaint.
    fn end_resize(&mut self) -> Rect {
        let Some(z) = self.resize else { return NONE };
        let gone = self.outline();
        self.resize = None;
        if let Some(mut w) = self.windows[z.window].filter(|w| (w.at.w, w.at.h) != z.size) {
            // The size it sets is taken from its right (or bottom) edge if
            // its left (or top) border was dragged.
            w.anchored = Sides { left: z.sides.left, top: z.sides.top, ..Sides::default() };
            self.windows[z.window] = Some(w);
            self.post(z.window, window::RESIZE, z.size.0 as u64 | (z.size.1 as u64) << 16, 0);
        }
        gone
    }

    /// The buttons are up: a window dragged by its title bar is told where
    /// it ended.
    fn end_drag(&mut self) {
        if let Some((i, _)) = self.drag.take() {
            if core::mem::replace(&mut self.dragged, false) {
                if let Some(w) = self.windows[i] {
                    say!("window {i} dragged to ({}, {})", w.at.x, w.at.y);
                    self.post(i, window::MOVED, w.at.x as u64 | (w.at.y as u64) << 16, 0);
                }
            }
        }
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
            self.end_drag();
            let gone = self.end_resize();
            self.pending = self.pending.union(gone);
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
        // A title bar repainted for the focus is pending.
        if !damage.empty() || !self.pending.empty() {
            self.show(damage);
        }
        if let Some((i, size)) = self.asking.take() {
            say!("window {i}: asking for {}x{}", size.0, size.1);
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

    /// Puts window `i` in front; managers' windows stay in front of every
    /// other.
    fn to_front(&mut self, i: usize) {
        self.unstack(i);
        self.order[self.shown] = i;
        self.shown += 1;
        let mut stack = [0; window::MAX_WINDOWS as usize];
        let mut n = 0;
        for managers in [false, true] {
            for k in 0..self.shown {
                let j = self.order[k];
                if self.manager(j) == managers {
                    stack[n] = j;
                    n += 1;
                }
            }
        }
        self.order[..n].copy_from_slice(&stack[..n]);
    }

    /// Minimises window `i`: drawn nowhere, and the front window takes the
    /// focus if it had it, until it is activated. The part of the screen
    /// to repaint.
    fn minimise(&mut self, i: usize) -> Rect {
        let Some(mut w) = self.windows[i].filter(|w| w.shown && !w.minimised) else { return NONE };
        w.minimised = true;
        self.windows[i] = Some(w);
        self.unstack(i);
        if self.hover == Some(i) {
            self.hover = None;
            self.post(i, window::LEAVE, 0, 0);
        }
        say!("window {i} minimised");
        if self.focus == Some(i) {
            self.set_focus(self.front());
        }
        self.changed();
        w.frame()
    }

    /// Maximises window `i`, or puts it back where it was and as big if it
    /// is maximised: its client is asked for the size (`RESIZE`), and the
    /// size it sets is taken at the place (it told, `MOVED`). Maximised,
    /// it fills the screen above any manager's windows along its bottom
    /// (the panel), its frame within that.
    fn maximise(&mut self, i: usize) {
        let Some(mut w) = self.windows[i] else { return };
        let (b, t) = (window::BORDER as u32, window::TITLE as u32);
        let (to, size) = if let Some(r) = w.unmaximised.take() {
            say!("window {i} asked back to {}x{} at ({}, {})", r.w, r.h, r.x, r.y);
            ((r.x, r.y), (r.w, r.h))
        } else {
            let bottom = (0..self.windows.len())
                .filter(|&k| self.manager(k))
                .filter_map(|k| self.windows[k].filter(|m| m.shown && m.frame().y + m.frame().h == self.height))
                .map(|m| m.frame().y)
                .min()
                .unwrap_or(self.height);
            let size = (self.width - 2 * b, bottom.saturating_sub(t + 2 * b));
            w.unmaximised = Some(w.at);
            say!("window {i} maximised: asked to be {}x{}", size.0, size.1);
            ((b, t + b), size)
        };
        w.place = Some(to);
        self.windows[i] = Some(w);
        self.changed();
        self.post(i, window::RESIZE, size.0 as u64 | (size.1 as u64) << 16, 0);
    }

    /// Window `i` is no longer minimised (it goes in front).
    fn restore(&mut self, i: usize) {
        if let Some(mut w) = self.windows[i].filter(|w| w.minimised) {
            w.minimised = false;
            self.windows[i] = Some(w);
            say!("window {i} restored");
        }
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

    /// Whether a window at `at` with `style` would lie wholly on the
    /// screen, decorations and all.
    fn fits_styled(&self, at: Rect, style: u64) -> bool {
        frame_of(at, style).is_some_and(|f| self.fits(f))
    }

    fn create(&mut self, size: u64, position: u64, badge: u64) -> [u64; 4] {
        let at = Rect::from_word(position & 0xffff_ffff | size << 32);
        if size >> 32 != 0 || position >> 32 != 0 || !self.fits(at) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let w = Window {
            owner: badge,
            at,
            pages: 0,
            shown: false,
            style: 0,
            title: [0; window::TITLE_BYTES as usize],
            title_len: 0,
            anchored: Sides::default(),
            minimised: false,
            place: None,
            unmaximised: None,
            icon: 0,
        };
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
        // More pages than it needs now leave room to grow.
        if !lent || page != w.pages || page >= window::WINDOW_PAGES {
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
            self.changed();
            w.frame()
        };
        self.show(damage);
        [Status::Ok as u64, self.frames, 0, 0]
    }

    fn move_to(&mut self, i: usize, position: u64) -> Status {
        let Some(mut w) = self.windows[i] else { return Status::NotFound };
        let to = Rect { x: position as u32 & 0xffff, y: (position >> 16) as u32 & 0xffff, w: w.at.w, h: w.at.h };
        if position >> 32 != 0 || !self.fits_styled(to, w.style) {
            return Status::Invalid;
        }
        if w.at == to {
            return Status::Ok;
        }
        let from = w.frame();
        w.at = to;
        self.windows[i] = Some(w);
        if w.shown {
            self.show(from.union(w.frame()));
        }
        Status::Ok
    }

    fn set_title(&mut self, i: usize, a: u64, b: u64) -> Status {
        let Some(mut w) = self.windows[i] else { return Status::NotFound };
        let mut bytes = [0u8; window::TITLE_BYTES as usize];
        bytes[..8].copy_from_slice(&a.to_le_bytes());
        bytes[8..].copy_from_slice(&b.to_le_bytes());
        let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
        if !bytes[..len].iter().all(|c| (32..=126).contains(c)) {
            return Status::Invalid;
        }
        (w.title, w.title_len) = (bytes, len);
        self.windows[i] = Some(w);
        self.changed();
        if w.shown && w.decorated() {
            self.show(w.frame());
        }
        Status::Ok
    }

    fn set_size(&mut self, i: usize, size: u64) -> Status {
        let Some(mut w) = self.windows[i] else { return Status::NotFound };
        let (tw, th) = (size as u32 & 0xffff, (size >> 16) as u32 & 0xffff);
        // After a drag of its left or top border, its right or bottom edge
        // stays (if the window can grow that way).
        // Maximised (or put back), at its place.
        let placed = w.place.take().map(|(x, y)| Rect { x, y, w: tw, h: th }).filter(|&a| self.fits_styled(a, w.style));
        let kept = Some(anchored(w.at, (tw, th), w.anchored))
            .filter(|&a| w.anchored != Sides::default() && self.fits_styled(a, w.style));
        let to = placed.or(kept).unwrap_or(Rect { w: tw, h: th, ..w.at });
        let needed = (to.w as u64 * to.h as u64 * 4).div_ceil(4096);
        if size >> 32 != 0 || to.empty() || needed > w.pages || !self.fits_styled(to, w.style) {
            return Status::Invalid;
        }
        w.anchored = Sides::default();
        if to == w.at {
            self.windows[i] = Some(w);
            return Status::Ok;
        }
        let from = w.frame();
        let moved = (to.x, to.y) != (w.at.x, w.at.y);
        w.at = to;
        self.windows[i] = Some(w);
        say!("window {i} resized to {}x{}", to.w, to.h);
        if moved && placed.is_some() {
            say!("window {i} moved to ({}, {})", to.x, to.y);
            self.post(i, window::MOVED, to.x as u64 | (to.y as u64) << 16, 0);
        } else if moved {
            say!("window {i} moved to ({}, {}) to keep its right and bottom edges", to.x, to.y);
            self.post(i, window::MOVED, to.x as u64 | (to.y as u64) << 16, 0);
        }
        if w.shown {
            self.show(from.union(w.frame()));
        }
        Status::Ok
    }

    fn set_style(&mut self, i: usize, style: u64) -> Status {
        let Some(mut w) = self.windows[i] else { return Status::NotFound };
        if style & !(window::ALPHA | window::DECORATED | window::RESIZABLE) != 0 || !self.fits_styled(w.at, style) {
            return Status::Invalid;
        }
        let from = w.frame();
        w.style = style;
        self.windows[i] = Some(w);
        if w.shown {
            self.show(from.union(w.frame()));
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
            window::LIST | window::DESCRIBE | window::ACTIVATE | window::ICON | window::SET_LAYOUT
                if badge & MANAGER_BADGE == 0 =>
            {
                status(Status::Denied)
            }
            window::SET_LAYOUT => {
                if m[1] >= window::LAYOUTS {
                    return status(Status::Invalid);
                }
                self.layout = m[1];
                say!("keyboard layout {}", superior_toolkit::keymap::NAMES[m[1] as usize]);
                status(Status::Ok)
            }
            window::LAYOUT => [Status::Ok as u64, self.layout, 0, 0],
            window::MINIMISE => {
                // A manager's (any other client's window), or the window's
                // own client's.
                let i = usize::try_from(m[1]).ok().filter(|&i| i < self.windows.len());
                let Some(i) = i.filter(|&i| self.windows[i].is_some_and(|w| w.shown) && self.alive(i)) else {
                    return status(Status::NotFound);
                };
                let mine = self.windows[i].is_some_and(|w| w.owner == badge);
                if self.manager(i) || (badge & MANAGER_BADGE == 0 && !mine) {
                    return status(if mine { Status::Invalid } else { Status::Denied });
                }
                let r = self.minimise(i);
                self.show(r);
                status(Status::Ok)
            }
            window::LIST => {
                if self.reap() {
                    self.show(NONE);
                }
                let bits = |f: fn(&Window) -> bool| {
                    (0..self.windows.len()).filter(|&i| self.windows[i].as_ref().is_some_and(f)).fold(0, |m, i| m | 1 << i)
                };
                let (shown, minimised) = (bits(|w| w.shown), bits(|w| w.shown && w.minimised));
                [Status::Ok as u64, shown, self.focus.map_or(window::MAX_WINDOWS, |f| f as u64), minimised]
            }
            window::DESCRIBE | window::ACTIVATE | window::ICON => {
                let i = usize::try_from(m[1]).ok().filter(|&i| i < self.windows.len());
                let Some(i) = i.filter(|&i| self.windows[i].is_some_and(|w| w.shown) && self.alive(i)) else {
                    return status(Status::NotFound);
                };
                let Some(w) = self.windows[i] else { return status(Status::NotFound) };
                if m[0] == window::DESCRIBE {
                    let word = |k: usize| u64::from_le_bytes(w.title[k * 8..k * 8 + 8].try_into().unwrap());
                    let flags = self.manager(i) as u64 | (w.minimised as u64) << 1 | (w.unmaximised.is_some() as u64) << 2;
                    return [Status::Ok as u64, word(0), word(1), flags];
                }
                if m[0] == window::ICON {
                    return [Status::Ok as u64, w.icon, w.owner & !MANAGER_BADGE, 0];
                }
                if self.manager(i) {
                    return status(Status::Invalid);
                }
                self.restore(i);
                say!("window {i} activated by the desktop shell");
                self.to_front(i);
                self.set_focus(Some(i));
                self.show(w.frame());
                status(Status::Ok)
            }
            op @ (window::ATTACH
            | window::COMMIT
            | window::MOVE_TO
            | window::RAISE
            | window::DESTROY
            | window::LISTEN
            | window::NEXT
            | window::STYLE
            | window::SET_TITLE
            | window::SET_SIZE
            | window::SET_ICON
            | window::CLIP_PUT
            | window::CLIP_GET) => {
                let Some(i) = self.own(m[1], badge) else {
                    return status(Status::NotFound);
                };
                match op {
                    window::ATTACH => status(self.attach(i, m[2], lent)),
                    window::COMMIT => self.commit(i, m[2]),
                    window::MOVE_TO => status(self.move_to(i, m[2])),
                    window::LISTEN => status(self.listen(i, lent)),
                    window::NEXT => self.next(i),
                    window::STYLE => status(self.set_style(i, m[2])),
                    window::SET_TITLE => status(self.set_title(i, m[2], m[3])),
                    window::SET_SIZE => status(self.set_size(i, m[2])),
                    window::CLIP_PUT | window::CLIP_GET => self.clip(op, i, m[2], m[3]),
                    window::SET_ICON => {
                        if let Some(w) = self.windows[i].as_mut() {
                            w.icon = m[2];
                        }
                        self.changed();
                        status(Status::Ok)
                    }
                    window::RAISE => {
                        self.restore(i);
                        if let Some(w) = self.windows[i].filter(|w| w.shown) {
                            self.to_front(i);
                            self.show(w.frame());
                        }
                        status(Status::Ok)
                    }
                    _ => {
                        let w = self.windows[i];
                        self.remove(i);
                        if let Some(w) = w.filter(|w| w.shown) {
                            self.show(w.frame());
                        }
                        status(Status::Ok)
                    }
                }
            }
            _ => status(Status::Invalid),
        }
    }

    /// A `KEY` event's `b` for key `usage`, pressed or let go (`b`), with
    /// the character it types under the layout in bits 16 to 23.
    fn typed(&self, usage: u64, b: u64) -> u64 {
        let ch = superior_toolkit::keymap::character(self.layout, usage, (b >> 8) as u8).unwrap_or(0);
        b & 0xffff | (ch as u64) << 16
    }

    /// The held key stops repeating.
    fn stop_repeat(&mut self) {
        if let Some(r) = self.repeat.take().filter(|r| r.count > 0) {
            say!("window {}: key {} held, repeated {} times", r.window, r.usage, r.count);
        }
    }

    /// The held key pressed again, if it is time: when next to look.
    fn repeat_key(&mut self, now: u64) -> Option<u64> {
        let mut r = self.repeat?;
        if self.focus != Some(r.window) {
            self.stop_repeat();
            return None;
        }
        if now >= r.next {
            self.post(r.window, window::KEY, r.usage, self.typed(r.usage, r.b | 2));
            // One at a time: a late wakeup does not flood the window.
            (r.next, r.count) = (now + REPEAT_TICKS, r.count + 1);
            self.repeat = Some(r);
        }
        Some(r.next)
    }

    /// `CLIP_PUT` or `CLIP_GET` for window `i`: only while it has the
    /// keyboard focus.
    fn clip(&mut self, op: u64, i: usize, part: u64, bytes: u64) -> [u64; 4] {
        if self.focus != Some(i) {
            say!("window {i}: the clipboard refused, it has not the focus");
            return [Status::Denied as u64, 0, 0, 0];
        }
        let Some(at) = usize::try_from(part).ok().filter(|&p| p < self.clipboard.len() / 8).map(|p| p * 8) else {
            return [Status::Invalid as u64, 0, 0, 0];
        };
        let len = |c: &[u8]| c.iter().position(|&b| b == 0).unwrap_or(c.len());
        if op == window::CLIP_PUT {
            if at == 0 {
                self.clipboard = [0; window::CLIPBOARD_BYTES as usize];
            }
            self.clipboard[at..at + 8].copy_from_slice(&bytes.to_le_bytes());
            // The part that ends the text (with a zero byte, or the last).
            if bytes.to_le_bytes().contains(&0) || at + 8 == self.clipboard.len() {
                let n = len(&self.clipboard);
                say!("window {i} copied {n} bytes to the clipboard");
            }
            return [Status::Ok as u64, 0, 0, 0];
        }
        let word = u64::from_le_bytes(self.clipboard[at..at + 8].try_into().unwrap());
        [Status::Ok as u64, word, len(&self.clipboard) as u64, 0]
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
        asking: None,
        reaped: 0,
        pending: NONE,
        queues: [EMPTY_QUEUE; window::MAX_WINDOWS as usize],
        pointer: (0, 0),
        cursor: false,
        buttons: 0,
        hover: None,
        posted: None,
        grab: None,
        focus: None,
        clipboard: [0; window::CLIPBOARD_BYTES as usize],
        repeat: None,
        layout: window::LAYOUT_US,
        drag: None,
        dragged: false,
        resize: None,
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
        let wake = c.repeat_key(now).map_or(next_check, |r| r.min(next_check));
        syscall(Syscall::TimerSignal, NOTIFY, [wake.saturating_sub(ticks()).max(1), 0, 0, 0]);
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
