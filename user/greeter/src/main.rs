//! The greeter: the first app on the toolkit. A decorated window titled
//! "Greeter" asks for a name in a text field; its button (or Enter in the
//! field) greets it below. The close box closes it, and the greeter
//! exits (so a launcher may start it again). Its frame resizes it, from
//! `MIN` to `MAX`: its widgets follow the width. Started with `arg 1` it is
//! "Hello" instead, elsewhere on the screen: a second app for the desktop
//! shell's test.
//!
//! Crash-only like every window client: when the compositor restarts, the
//! next call fails and the greeter makes its window again, its state kept.
//!
//! Slots: 0 the compositor's `window`, 1 memory, 2 the notification the
//! compositor signals (made here), 3 the Component Manager (if given, to
//! exit), 8 on the window's pages.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::idl::window;
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};
use superior_toolkit::{Event, Id, Rect, Surface, Ui};

const WINDOWS: u64 = 0;
const MEMORY: u64 = 1;
const NTFN: u64 = 2;
const MANAGER: u64 = 3;
/// `[OP_EXIT, failures]` to the Component Manager: stop for good.
const OP_EXIT: u64 = 5;
const PAGE_SLOTS: u64 = 8;
const VA: u64 = USER_BASE + 0x4000_0000;
/// The window's size at first, the least it takes and the most (its pages
/// hold that much).
pub const SIZE: (u32, u32) = (280, 124);
const MIN: (u32, u32) = (200, 124);
const MAX: (u32, u32) = (600, 400);

/// What it is called (in its log and its title) and where its window
/// first goes, by its `arg`.
struct Variant {
    name: &'static str,
    title: &'static [u8],
    at: (u64, u64),
    /// Its window's icon (the toolkit's name).
    icon: &'static [u8],
}

const VARIANTS: [Variant; 2] = [
    Variant { name: "greeter", title: b"Greeter", at: (260, 180), icon: b"person" },
    Variant { name: "hello", title: b"Hello", at: (330, 250), icon: b"wave" },
];

static VARIANT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn variant() -> &'static Variant {
    &VARIANTS[VARIANT.load(core::sync::atomic::Ordering::Relaxed)]
}

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("{}: {}", variant().name, format_args!($($t)*))) };
}

/// Pages for the largest window.
fn pages() -> u64 {
    (MAX.0 as u64 * MAX.1 as u64 * 4).div_ceil(4096)
}

/// A call to the compositor, lending window page `page` or the
/// notification: `None` if it failed (the compositor restarted).
fn call(m: [u64; 4], grant: Option<u64>) -> Option<[u64; 4]> {
    let x = CapTransfer { grant: grant.map(|s| s as u16), accept: None };
    let r = syscall_x(Syscall::Call, WINDOWS, m, x);
    (r.status == 0).then_some(r.msg)
}

fn ok(m: Option<[u64; 4]>) -> bool {
    m.is_some_and(|m| m[0] == 0)
}

fn rect_word(r: Rect) -> u64 {
    r.x as u64 | (r.y as u64) << 16 | (r.w as u64) << 32 | (r.h as u64) << 48
}

/// The title as `SET_TITLE` takes it.
fn title_words() -> (u64, u64) {
    let mut b = [0u8; 16];
    let title = variant().title;
    b[..title.len()].copy_from_slice(title);
    (u64::from_le_bytes(b[..8].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap()))
}

struct App {
    ui: Ui,
    field: Id,
    button: Id,
    out: Id,
    window: Option<u64>,
    at: (u64, u64),
}

impl App {
    fn surface(&self) -> Surface<'static> {
        let (w, h) = (self.ui.w, self.ui.h);
        // SAFETY: the window's pages are mapped, writable, in a row from
        // `VA`, and hold `MAX` pixels, more than `w` by `h`; only one
        // surface is used at a time.
        let px = unsafe { core::slice::from_raw_parts_mut(VA as *mut u32, (w * h) as usize) };
        Surface { px, w, h }
    }

    fn size_word(&self) -> u64 {
        self.ui.w as u64 | (self.ui.h as u64) << 16
    }

    /// The user asked for `w` by `h`: it takes the nearest it can, draws
    /// itself at that size and sets it.
    fn resize(&mut self, w: u32, h: u32) {
        let (w, h) = (w.clamp(MIN.0, MAX.0), h.clamp(MIN.1, MAX.1));
        let Some(n) = self.window else { return };
        let was = (self.ui.w, self.ui.h);
        self.ui.resize(w, h);
        self.ui.draw(&mut self.surface());
        let r = call(window::set_size(n, self.size_word()), None).map_or(u64::MAX, |m| m[0]);
        if r != 0 {
            // Refused (it would not fit where it is): as it was.
            self.ui.resize(was.0, was.1);
            self.show(Rect { x: 0, y: 0, w: was.0, h: was.1 });
        }
        say!("resized to {w}x{h} (status {r})");
    }

    /// Makes the window, decorated and titled, lends its pages and the
    /// notification, and shows it; again while the compositor restarts.
    fn open(&mut self) -> bool {
        self.ui.draw(&mut self.surface());
        for _ in 0..50 {
            self.window = None;
            let size = self.size_word();
            let Some(r) = call(window::create(size, self.at.0 | self.at.1 << 16), None) else {
                superior_sys::sleep(5);
                continue;
            };
            if r[0] != 0 {
                return false;
            }
            let n = r[1];
            let (a, b) = title_words();
            let made = (0..pages()).all(|p| ok(call(window::attach(n, p), Some(PAGE_SLOTS + p))))
                && ok(call(window::style(n, window::DECORATED | window::RESIZABLE), None))
                && ok(call(window::set_title(n, a, b), None))
                && ok(call(window::set_icon(n, superior_toolkit::icon_by_name(variant().icon) as u64), None))
                && ok(call(window::listen(n), Some(NTFN)));
            let all = Rect { x: 0, y: 0, w: self.ui.w, h: self.ui.h };
            if made && ok(call(window::commit(n, rect_word(all)), None)) {
                self.window = Some(n);
                return true;
            }
        }
        false
    }

    /// Draws part `r` of the window and shows it.
    fn show(&mut self, r: Rect) {
        if r.empty() {
            return;
        }
        let drawn = self.ui.draw_part(&mut self.surface(), r);
        if let Some(n) = self.window {
            let _ = call(window::commit(n, rect_word(drawn)), None);
        }
    }

    fn greet(&mut self) {
        let mut line = [0u8; 48];
        let mut len = 0;
        let name = self.ui.text(self.field);
        let name = if name.is_empty() { "stranger" } else { name };
        for part in ["Hello, ", name, "!"] {
            for &c in part.as_bytes() {
                if len < line.len() {
                    line[len] = c;
                    len += 1;
                }
            }
        }
        let text = core::str::from_utf8(&line[..len]).unwrap_or("?");
        let damage = self.ui.set_text(self.out, text);
        self.show(damage);
        say!("said \"{}\"", self.ui.text(self.out));
    }

    /// One event from the compositor; false once the window is closed.
    fn event(&mut self, kind: u64, a: u64, b: u64) -> bool {
        let e = match kind {
            window::POINTER => Event::Pointer { x: a as u16 as i16 as i32, y: (a >> 16) as u16 as i16 as i32, buttons: b },
            window::KEY => Event::Key { usage: a, down: b & 1 == 1, modifiers: (b >> 8) as u8 },
            window::FOCUS => Event::Focus(a == 1),
            window::LEAVE => Event::Leave,
            window::MOVED => {
                self.at = (a & 0xffff, (a >> 16) & 0xffff);
                return true;
            }
            window::RESIZE => {
                self.resize(a as u32 & 0xffff, (a >> 16) as u32 & 0xffff);
                return true;
            }
            window::CLOSE => {
                if let Some(n) = self.window.take() {
                    let _ = call(window::destroy(n), None);
                }
                say!("closed");
                syscall(Syscall::Call, MANAGER, [OP_EXIT, 0, 0, 0]);
                return false;
            }
            _ => return true,
        };
        let before = (self.ui.widget(self.field).text, self.ui.cursor(self.field));
        let r = self.ui.event(e);
        self.show(r.damage);
        if (self.ui.widget(self.field).text, self.ui.cursor(self.field)) != before {
            say!("the field holds \"{}\", the cursor at {}", self.ui.text(self.field), self.ui.cursor(self.field));
        }
        if r.clicked == Some(self.button) || r.entered == Some(self.field) {
            self.greet();
        }
        true
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    VARIANT.store((arg as usize).min(VARIANTS.len() - 1), core::sync::atomic::Ordering::Relaxed);
    let mut made = syscall(Syscall::Retype, MEMORY, [ObjectType::Notification as u64, 0, NTFN, 0]).status == 0;
    for p in 0..pages() {
        made &= syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, PAGE_SLOTS + p, 0]).status == 0
            && syscall(Syscall::FrameMap, PAGE_SLOTS + p, [VA + p * 4096, 1, 0, 0]).status == 0;
    }
    if !made {
        say!("[fail] no memory for the window");
        superior_sys::park()
    }
    let mut ui = Ui::new(SIZE.0, SIZE.1);
    ui.label("Your name:");
    let field = ui.field();
    let button = ui.button("Greet");
    let out = ui.label("");
    let mut app = App { ui, field, button, out, window: None, at: variant().at };
    if !app.open() {
        say!("[fail] the compositor would not show the window");
        superior_sys::park()
    }
    let title = core::str::from_utf8(variant().title).unwrap_or("?");
    say!("ready: window {}, decorated, titled \"{title}\"", app.window.unwrap_or(u64::MAX));
    loop {
        syscall(Syscall::TimerSignal, NTFN, [5, 0, 0, 0]);
        syscall(Syscall::Wait, NTFN, [0; 4]);
        let Some(n) = app.window else { superior_sys::park() };
        loop {
            match call(window::next(n), None) {
                Some(m) if m[0] == 0 => {
                    if !app.event(m[1], m[2], m[3]) {
                        superior_sys::park()
                    }
                }
                Some(_) => break,
                None => {
                    app.window = None;
                    break;
                }
            }
        }
        // Moving it where it is changes nothing, but a compositor that
        // restarted knows no such window.
        let here = app.window.and_then(|n| call(window::move_to(n, app.at.0 | app.at.1 << 16), None));
        if here != Some([0; 4]) {
            say!("the compositor restarted; making the window again");
            app.open();
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
