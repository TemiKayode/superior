//! List: a toolkit app that keeps a list of things, to show the toolkit's
//! lines, lists and text selection. A decorated, resizable window titled
//! "List": a line with a label, a text field and an "Add" button; a list
//! of items, ten fruits at first; and a line with a "Remove" button and a
//! status label (the item chosen, or how many there are). "Add" (or Enter
//! in the field) adds the field's text to the end of the list and chooses
//! it; "Remove" takes the chosen item out. The close box closes it, and it
//! exits.
//!
//! Crash-only like every window client: when the compositor restarts, the
//! next call fails and it makes its window again, its state kept.
//!
//! `cargo xtask widgets-test` lays out the same window (`layout`) to check
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
/// The window's size at first, the least it takes and the most (its pages
/// hold that much), and where it goes.
const SIZE: (u32, u32) = (320, 206);
const MIN: (u32, u32) = (280, 206);
const MAX: (u32, u32) = (560, 400);
const AT: (u64, u64) = (240, 140);
/// The list's items at first, and how many rows it shows.
const FRUIT: [&str; 10] = ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "kiwi", "lemon", "mango"];
const ROWS: u32 = 6;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("list: {}", format_args!($($t)*))) };
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

/// The window's widgets.
struct Widgets {
    field: Id,
    add: Id,
    list: Id,
    remove: Id,
    status: Id,
}

/// Lays the window out: the label, field and "Add" on a line, the list,
/// then "Remove" and the status (taking the rest of its line), the fruit
/// in the list.
fn layout(ui: &mut Ui) -> Widgets {
    ui.begin_row();
    ui.label("Item:");
    let field = ui.field();
    let add = ui.button("Add");
    ui.end_row();
    let list = ui.list(ROWS);
    for f in FRUIT {
        ui.push_item(list, f);
    }
    ui.begin_row();
    let remove = ui.button("Remove");
    let status = ui.label("");
    ui.stretch(status);
    ui.end_row();
    let w = Widgets { field, add, list, remove, status };
    status_text(ui, &w);
    w
}

/// The status label's text: the item chosen, or how many there are.
fn status_text(ui: &mut Ui, w: &Widgets) -> Rect {
    let mut line = [0u8; 40];
    let mut len = 0;
    let mut put = |s: &str| {
        for &c in s.as_bytes() {
            if len < line.len() {
                line[len] = c;
                len += 1;
            }
        }
    };
    match ui.chosen(w.list) {
        Some(k) => {
            put("Chosen: ");
            put(ui.item(w.list, k));
        }
        None => {
            let n = ui.items(w.list);
            let mut d = [0u8; 2];
            d[0] = b'0' + (n / 10 % 10) as u8;
            d[1] = b'0' + (n % 10) as u8;
            put(core::str::from_utf8(if n >= 10 { &d } else { &d[1..] }).unwrap_or("?"));
            put(" items");
        }
    }
    let text = core::str::from_utf8(&line[..len]).unwrap_or("?");
    ui.set_text(w.status, text)
}

struct App {
    ui: Ui,
    w: Widgets,
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
            let made = (0..pages()).all(|p| ok(call(window::attach(n, p), Some(PAGE_SLOTS + p))))
                && ok(call(window::style(n, window::DECORATED | window::RESIZABLE), None))
                && ok(call(window::set_title(n, u64::from_le_bytes(*b"List\0\0\0\0"), 0), None))
                && ok(call(window::set_icon(n, superior_toolkit::icon_by_name(b"list") as u64), None))
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

    /// The list's state, as its log line tells it.
    fn list_state(&self) -> (Option<usize>, usize, usize) {
        let l = self.w.list;
        (self.ui.chosen(l), self.ui.widget(l).scroll, self.ui.items(l))
    }

    fn say_list(&self) {
        let (chosen, scroll, n) = self.list_state();
        let last = (scroll + ROWS as usize).min(n).saturating_sub(1);
        match chosen {
            Some(k) => say!("{n} items, \"{}\" chosen (item {k}), items {scroll} to {last} shown", self.ui.item(self.w.list, k)),
            None => say!("{n} items, none chosen, items {scroll} to {last} shown"),
        }
    }

    fn say_field(&self) {
        let f = self.w.field;
        let text = self.ui.text(f);
        match self.ui.selection(f) {
            Some((a, b)) => say!(
                "the field holds \"{text}\", the cursor at {}, \"{}\" selected",
                self.ui.cursor(f),
                core::str::from_utf8(&text.as_bytes()[a..b]).unwrap_or("?")
            ),
            None => say!("the field holds \"{text}\", the cursor at {}", self.ui.cursor(f)),
        }
    }

    /// The field's text added to the end of the list, and chosen.
    fn add(&mut self) {
        let mut item = [0u8; superior_toolkit::MAX_TEXT];
        let text = self.ui.text(self.w.field);
        if text.is_empty() {
            return;
        }
        let n = text.len();
        item[..n].copy_from_slice(text.as_bytes());
        let item = core::str::from_utf8(&item[..n]).unwrap_or("?");
        let mut damage = self.ui.push_item(self.w.list, item);
        let last = self.ui.items(self.w.list) - 1;
        damage = damage.union(self.ui.choose(self.w.list, Some(last)));
        damage = damage.union(self.ui.set_text(self.w.field, ""));
        damage = damage.union(status_text(&mut self.ui, &self.w));
        self.show(damage);
        say!("added \"{item}\"");
    }

    /// The chosen item taken out.
    fn remove(&mut self) {
        let Some(k) = self.ui.chosen(self.w.list) else { return };
        let mut item = [0u8; superior_toolkit::MAX_TEXT];
        let text = self.ui.item(self.w.list, k);
        let n = text.len();
        item[..n].copy_from_slice(text.as_bytes());
        let mut damage = self.ui.remove_item(self.w.list, k);
        damage = damage.union(status_text(&mut self.ui, &self.w));
        self.show(damage);
        say!("removed \"{}\"", core::str::from_utf8(&item[..n]).unwrap_or("?"));
    }

    /// One event from the compositor; false once the window is closed.
    fn event(&mut self, kind: u64, a: u64, b: u64) -> bool {
        let (x, y) = (a as u16 as i16 as i32, (a >> 16) as u16 as i16 as i32);
        let e = match kind {
            window::POINTER => Event::Pointer { x, y, buttons: b },
            window::WHEEL => Event::Wheel { x, y, up: b as u32 as i32 },
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
        let f = self.w.field;
        let field = |ui: &Ui| (ui.widget(f).text, ui.cursor(f), ui.selection(f));
        let (field_before, list_before) = (field(&self.ui), self.list_state());
        let r = self.ui.event(e);
        let mut damage = r.damage;
        if r.picked.is_some() {
            damage = damage.union(status_text(&mut self.ui, &self.w));
        }
        self.show(damage);
        if field(&self.ui) != field_before {
            self.say_field();
        }
        if r.clicked == Some(self.w.add) || r.entered == Some(f) {
            self.add();
        }
        if r.clicked == Some(self.w.remove) {
            self.remove();
        }
        if self.list_state() != list_before {
            self.say_list();
        }
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
    let w = layout(&mut ui);
    let mut app = App { ui, w, window: None, at: AT };
    if !app.open() {
        say!("[fail] the compositor would not show the window");
        superior_sys::park()
    }
    say!("ready: window {}, decorated, titled \"List\"", app.window.unwrap_or(u64::MAX));
    app.say_list();
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
