//! Notes: a toolkit app for lines of text, to show the toolkit's text
//! area. A decorated window titled "Notes": a text area of six lines, and
//! a label saying where the cursor is. The close box closes it, and it
//! exits.
//!
//! Crash-only like every window client: when the compositor restarts, the
//! next call fails and it makes its window again, its text kept.
//!
//! `cargo xtask notes-test` lays out the same window (`layout`) to check
//! screenshots.
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
/// The window's size and where it goes; how many lines the area shows.
const SIZE: (u32, u32) = (320, 200);
const AT: (u64, u64) = (240, 150);
const ROWS: u32 = 6;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("notes: {}", format_args!($($t)*))) };
}

/// Pages for the window.
fn pages() -> u64 {
    (SIZE.0 as u64 * SIZE.1 as u64 * 4).div_ceil(4096)
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

/// Lays the window out: the text area, then the label under it. The area
/// and the label.
pub fn layout(ui: &mut Ui) -> (Id, Id) {
    let area = ui.area(ROWS);
    let status = ui.label("");
    status_text(ui, status);
    (area, status)
}

/// The label's text: "Line 2, column 5" (from 1).
fn status_text(ui: &mut Ui, status: Id) -> Rect {
    let (l, c) = ui.area_cursor();
    let mut line = [0u8; 32];
    let mut len = 0;
    let mut put = |s: &[u8]| {
        for &b in s {
            if len < line.len() {
                line[len] = b;
                len += 1;
            }
        }
    };
    let number = |n: usize, d: &mut [u8; 4]| -> usize {
        let mut k = d.len();
        let mut n = n;
        loop {
            k -= 1;
            d[k] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 || k == 0 {
                return k;
            }
        }
    };
    let mut d = [0u8; 4];
    put(b"Line ");
    let k = number(l + 1, &mut d);
    put(&d[k..]);
    put(b", column ");
    let k = number(c + 1, &mut d);
    put(&d[k..]);
    let text = core::str::from_utf8(&line[..len]).unwrap_or("?");
    ui.set_text(status, text)
}

struct App {
    ui: Ui,
    area: Id,
    status: Id,
    window: Option<u64>,
}

impl App {
    fn surface(&self) -> Surface<'static> {
        let (w, h) = (self.ui.w, self.ui.h);
        // SAFETY: the window's pages are mapped, writable, in a row from
        // `VA`, and hold `w` by `h` pixels; only one surface is used at a
        // time.
        let px = unsafe { core::slice::from_raw_parts_mut(VA as *mut u32, (w * h) as usize) };
        Surface { px, w, h }
    }

    /// Makes the window, decorated and titled, lends its pages and the
    /// notification, and shows it; again while the compositor restarts.
    fn open(&mut self) -> bool {
        self.ui.draw(&mut self.surface());
        for _ in 0..50 {
            self.window = None;
            let size = self.ui.w as u64 | (self.ui.h as u64) << 16;
            let Some(r) = call(window::create(size, AT.0 | AT.1 << 16), None) else {
                superior_sys::sleep(5);
                continue;
            };
            if r[0] != 0 {
                return false;
            }
            let n = r[1];
            let made = (0..pages()).all(|p| ok(call(window::attach(n, p), Some(PAGE_SLOTS + p))))
                && ok(call(window::style(n, window::DECORATED), None))
                && ok(call(window::set_title(n, u64::from_le_bytes(*b"Notes\0\0\0"), 0), None))
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

    /// What the log tells of the text: its lines, the cursor and the first
    /// line shown.
    fn state(&self) -> (usize, (usize, usize), usize) {
        (self.ui.area_lines(), self.ui.area_cursor(), self.ui.widget(self.area).scroll)
    }

    fn say_state(&self) {
        let (lines, (l, c), top) = self.state();
        // The text quoted, its newlines as `\n` (core's `{:?}` for `str`
        // drags in tables that do not link position-independent here).
        let mut quoted = [0u8; 2 * superior_toolkit::AREA_TEXT];
        let mut n = 0;
        for &b in self.ui.area_text().as_bytes() {
            let esc: &[u8] = match b {
                b'\n' => b"\\n",
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                _ => core::slice::from_ref(&b),
            };
            quoted[n..n + esc.len()].copy_from_slice(esc);
            n += esc.len();
        }
        let text = core::str::from_utf8(&quoted[..n]).unwrap_or("?");
        say!("{lines} lines, the cursor at line {l}, column {c}, line {top} at the top: \"{text}\"");
    }

    /// One event from the compositor; false once the window is closed.
    fn event(&mut self, kind: u64, a: u64, b: u64) -> bool {
        let (x, y) = (a as u16 as i16 as i32, (a >> 16) as u16 as i16 as i32);
        let e = match kind {
            window::POINTER => Event::Pointer { x, y, buttons: b },
            window::WHEEL => Event::Wheel { x, y, up: b as u32 as i32 },
            window::KEY => Event::from_key(a, b),
            window::FOCUS => Event::Focus(a == 1),
            window::LEAVE => Event::Leave,
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
        let before = (self.state(), self.ui.area_text().len());
        let r = self.ui.event(e);
        let mut damage = r.damage;
        if (self.state(), self.ui.area_text().len()) != before {
            damage = damage.union(status_text(&mut self.ui, self.status));
            self.say_state();
        }
        self.show(damage);
        true
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
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
    let (area, status) = layout(&mut ui);
    let mut app = App { ui, area, status, window: None };
    if !app.open() {
        say!("[fail] the compositor would not show the window");
        superior_sys::park()
    }
    say!("ready: window {}, decorated, titled \"Notes\"", app.window.unwrap_or(u64::MAX));
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
        let here = app.window.and_then(|n| call(window::move_to(n, AT.0 | AT.1 << 16), None));
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
