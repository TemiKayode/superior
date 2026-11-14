//! The desktop shell's panel: a strip along the bottom of the screen,
//! drawn with the toolkit. At its left an "Apps" button opens the launcher
//! menu, a window above it with a button for each `start launch`
//! component in the manifest: pressing one asks the Component Manager to
//! start it and closes the menu (as does "Apps" again). Then a button for
//! each other client's window (its title), the one with the keyboard focus
//! selected: pressing one puts that window in front with the focus
//! (drawing it again if it was minimised), or minimises it if it already
//! had the focus. At its right a clock: the time of day (UTC, hours and
//! minutes) from the kernel's real-time clock (`Time`).
//!
//! It manages the compositor (`manages window`): it may list, describe,
//! activate and minimise every window, the compositor tells its window
//! when they change (`WINDOWS`), and its windows stay in front without
//! taking the focus. Crash-only like every window client: a restarted
//! compositor knows no panel, and it makes its window again.
//!
//! `cargo xtask panel-test` lays out the same panel and menu (`layout`,
//! `menu_layout`) to check screenshots.
//!
//! Slots: 0 the compositor's `window` (a manager's), 1 the Component
//! Manager (`launch-control`), 2 memory, 3 the notification the compositor
//! signals (made here), 8 on the panel's pages, then the menu's.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::idl::window;
use superior_objects::interfaces::launch;
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};
use superior_toolkit::{BOX_H, Event, Id, PAD, Rect, Surface, Ui};

const WINDOWS: u64 = 0;
const MANAGER: u64 = 1;
const MEMORY: u64 = 2;
const NTFN: u64 = 3;
const PAGE_SLOTS: u64 = 8;
const VA: u64 = USER_BASE + 0x4000_0000;
/// The panel's height; it is the screen's width.
const HEIGHT: u32 = 32;
/// The widest screen it lays out for (1024 pixels).
const MAX_PAGES: u64 = (1024 * HEIGHT as u64 * 4).div_ceil(4096);
const MAX_LAUNCHERS: usize = 6;
const MAX_TASKS: usize = window::MAX_WINDOWS as usize;
/// The launcher menu: its width, the most pages it takes (a button for
/// every launcher), and where they go.
const MENU_W: u32 = 160;
const MENU_PAGES: u64 = (MENU_W as u64 * menu_height(MAX_LAUNCHERS) as u64 * 4).div_ceil(4096);
const MENU_SLOTS: u64 = PAGE_SLOTS + MAX_PAGES;
const MENU_VA: u64 = VA + 0x10_0000;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("panel: {}", format_args!($($t)*))) };
}

/// The menu's height for `n` launchers: a button each, in a column.
const fn menu_height(n: usize) -> u32 {
    PAD + n as u32 * (BOX_H + PAD)
}

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

/// The clock's text for `seconds` since 1970 (UTC): hours and minutes.
fn clock_text(seconds: Option<u64>) -> [u8; 5] {
    let Some(s) = seconds else { return *b"--:--" };
    let (h, m) = (s / 3600 % 24, s / 60 % 60);
    [b'0' + (h / 10) as u8, b'0' + (h % 10) as u8, b':', b'0' + (m / 10) as u8, b'0' + (m % 10) as u8]
}

/// A short name or title, held inline.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    bytes: [u8; launch::NAME_BYTES],
    len: usize,
}

impl Name {
    const EMPTY: Name = Name { bytes: [0; launch::NAME_BYTES], len: 0 };

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("?")
    }
}

/// A window on the panel: its number, title, and whether it has the focus
/// or is minimised.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Task {
    window: u64,
    title: Name,
    focused: bool,
    minimised: bool,
}

const NO_TASK: Task = Task { window: 0, title: Name::EMPTY, focused: false, minimised: false };

/// Lays the panel out: "Apps" (selected while the menu is open), a button
/// for each of `tasks` (the focused one selected), then the clock at the
/// right end. "Apps" is button 0, the tasks' buttons follow in order, and
/// the clock is last.
fn layout(ui: &mut Ui, tasks: &[Task], menu_open: bool, clock: &[u8; 5]) {
    ui.clear();
    let apps = ui.button("Apps");
    ui.select(apps, menu_open);
    for t in tasks {
        let id = ui.button(if t.title.len == 0 { "untitled" } else { t.title.as_str() });
        ui.select(id, t.focused);
    }
    let c = ui.label(core::str::from_utf8(clock).unwrap_or("--:--"));
    ui.push_right(c);
}

/// Lays the launcher menu out: a button for each of `launchers`, in a
/// column.
fn menu_layout(ui: &mut Ui, launchers: &[Name]) {
    ui.clear();
    for l in launchers {
        ui.button(l.as_str());
    }
}

/// A window of the panel's own: its toolkit state, the compositor's
/// number for it, and where its pixels are.
struct Own {
    ui: Ui,
    window: Option<u64>,
    va: u64,
}

impl Own {
    fn surface(&self) -> Surface<'static> {
        let (w, h) = (self.ui.w, self.ui.h);
        // SAFETY: the window's pages are mapped, writable, in a row from
        // `va`, and hold `w` by `h` pixels; only one surface is used at a
        // time.
        let px = unsafe { core::slice::from_raw_parts_mut(self.va as *mut u32, (w * h) as usize) };
        Surface { px, w, h }
    }

    /// Draws part `r` and shows it.
    fn show(&mut self, r: Rect) {
        if r.empty() {
            return;
        }
        let drawn = self.ui.draw_part(&mut self.surface(), r);
        if let Some(n) = self.window {
            let _ = call(window::commit(n, rect_word(drawn)), None);
        }
    }

    /// Draws all of it and shows it.
    fn show_all(&mut self) {
        self.ui.draw(&mut self.surface());
        if let Some(n) = self.window {
            let whole = Rect { x: 0, y: 0, w: self.ui.w, h: self.ui.h };
            let _ = call(window::commit(n, rect_word(whole)), None);
        }
    }

    /// Makes its window at `at` from `pages` pages in slots from `slot`,
    /// lent the notification: false if the compositor would not.
    fn create(&mut self, at: (u64, u64), slot: u64) -> bool {
        self.window = None;
        let size = self.ui.w as u64 | (self.ui.h as u64) << 16;
        let pages = (self.ui.w as u64 * self.ui.h as u64 * 4).div_ceil(4096);
        let Some(r) = call(window::create(size, at.0 | at.1 << 16), None).filter(|r| r[0] == 0) else { return false };
        let n = r[1];
        if (0..pages).all(|p| ok(call(window::attach(n, p), Some(slot + p)))) && ok(call(window::listen(n), Some(NTFN))) {
            self.window = Some(n);
            return true;
        }
        let _ = call(window::destroy(n), None);
        false
    }

    /// Takes a pointer event (`a`, `b` as `POINTER` has them, or `None`
    /// for `LEAVE`): the button clicked, if any.
    fn pointer(&mut self, e: Option<(u64, u64)>) -> Option<Id> {
        let e = match e {
            Some((a, b)) => Event::Pointer { x: a as u16 as i16 as i32, y: (a >> 16) as u16 as i16 as i32, buttons: b },
            None => Event::Leave,
        };
        let r = self.ui.event(e);
        self.show(r.damage);
        r.clicked
    }
}

struct Panel {
    bar: Own,
    menu: Own,
    launchers: [Name; MAX_LAUNCHERS],
    nlaunchers: usize,
    tasks: [Task; MAX_TASKS],
    ntasks: usize,
    at: (u64, u64),
    clock: [u8; 5],
    /// Where the pointer last was on the panel (it is laid out anew under
    /// it), none once it left.
    pointer: Option<(i32, i32)>,
}

impl Panel {
    fn open(&mut self) -> bool {
        for _ in 0..50 {
            if self.bar.create(self.at, PAGE_SLOTS) {
                self.refresh(true);
                return true;
            }
            superior_sys::sleep(5);
        }
        false
    }

    fn menu_open(&self) -> bool {
        self.menu.window.is_some()
    }

    /// Opens the launcher menu above "Apps", or closes it if it is open.
    fn toggle_menu(&mut self) {
        if self.menu_open() {
            self.close_menu();
            return;
        }
        let h = self.menu.ui.h;
        if self.menu.create((0, self.at.1.saturating_sub(h as u64)), MENU_SLOTS) {
            self.menu.show_all();
            let d = self.bar.ui.select(0, true);
            self.bar.show(d);
            struct Launchers<'a>(&'a [Name]);
            impl core::fmt::Display for Launchers<'_> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    for (k, l) in self.0.iter().enumerate() {
                        write!(f, "{}{}", if k > 0 { ", " } else { "" }, l.as_str())?;
                    }
                    Ok(())
                }
            }
            say!("menu open: {}", Launchers(&self.launchers[..self.nlaunchers]));
        }
    }

    fn close_menu(&mut self) {
        let Some(n) = self.menu.window.take() else { return };
        let _ = call(window::destroy(n), None);
        // Its buttons' state goes with it.
        menu_layout(&mut self.menu.ui, &self.launchers[..self.nlaunchers]);
        let d = self.bar.ui.select(0, false);
        self.bar.show(d);
        say!("menu closed");
    }

    /// Asks the compositor which windows there are; if they changed (or
    /// `all`), lays the panel out anew and shows it.
    fn refresh(&mut self, all: bool) {
        let Some(list) = call(window::list(), None).filter(|m| m[0] == 0) else { return };
        let mut tasks = [NO_TASK; MAX_TASKS];
        let mut n = 0;
        for w in 0..window::MAX_WINDOWS {
            if list[1] & 1 << w == 0 {
                continue;
            }
            let Some(d) = call(window::describe(w), None).filter(|m| m[0] == 0) else { continue };
            if d[3] & 1 != 0 {
                continue;
            }
            let (bytes, len) = launch::name([d[1], d[2], 0]);
            let mut title = Name::EMPTY;
            title.bytes = bytes;
            title.len = len.min(window::TITLE_BYTES as usize);
            let minimised = list[3] & 1 << w != 0;
            tasks[n] = Task { window: w, title, focused: list[2] == w, minimised };
            n += 1;
        }
        if !all && tasks[..n] == self.tasks[..self.ntasks] {
            return;
        }
        (self.tasks, self.ntasks) = (tasks, n);
        self.lay_out();
        // Said once it is on the screen.
        self.say_tasks();
    }

    /// Lays the panel out anew (under the pointer) and shows all of it.
    fn lay_out(&mut self) {
        let open = self.menu_open();
        layout(&mut self.bar.ui, &self.tasks[..self.ntasks], open, &self.clock);
        if let Some((x, y)) = self.pointer {
            self.bar.ui.event(Event::Pointer { x, y, buttons: 0 });
        }
        self.bar.show_all();
    }

    /// The clock shows the time now, if the minute changed.
    fn tick(&mut self) {
        let now = clock_text(superior_sys::time());
        if now == self.clock {
            return;
        }
        self.clock = now;
        let id = self.bar.ui.len() - 1;
        let d = self.bar.ui.set_text(id, core::str::from_utf8(&now).unwrap_or("--:--"));
        self.bar.show(d);
        say!("the clock shows {}", core::str::from_utf8(&now).unwrap_or("?"));
    }

    fn say_tasks(&self) {
        struct Tasks<'a>(&'a [Task]);
        impl core::fmt::Display for Tasks<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                if self.0.is_empty() {
                    return f.write_str("none");
                }
                for (k, t) in self.0.iter().enumerate() {
                    let sep = if k > 0 { ", " } else { "" };
                    let state = if t.minimised {
                        " (minimised)"
                    } else if t.focused {
                        " (focused)"
                    } else {
                        ""
                    };
                    write!(f, "{sep}\"{}\"{state}", t.title.as_str())?;
                }
                Ok(())
            }
        }
        say!("windows: {}", Tasks(&self.tasks[..self.ntasks]));
    }

    /// Button `id` of the panel was clicked: "Apps" opens or closes the
    /// menu; a task button puts its window in front, or minimises it if it
    /// has the focus.
    fn clicked(&mut self, id: Id) {
        if id == 0 {
            self.toggle_menu();
            return;
        }
        let Some(&t) = self.tasks[..self.ntasks].get(id - 1) else { return };
        self.close_menu();
        if t.focused && !t.minimised {
            let r = call(window::minimise(t.window), None);
            say!("minimised \"{}\" (status {})", t.title.as_str(), r.map_or(u64::MAX, |m| m[0]));
        } else {
            let r = call(window::activate(t.window), None);
            say!("activated \"{}\" (status {})", t.title.as_str(), r.map_or(u64::MAX, |m| m[0]));
        }
    }

    /// Launcher `k` in the menu was clicked: the menu closes and its app
    /// starts.
    fn launch(&mut self, k: usize) {
        let Some(l) = self.launchers[..self.nlaunchers].get(k).copied() else { return };
        self.close_menu();
        let w = launch::words(&l.bytes[..l.len]);
        let r = syscall(Syscall::Call, MANAGER, [launch::OP_LAUNCH, w[0], w[1], w[2]]);
        say!("launched {} (status {})", l.as_str(), if r.status == 0 { r.msg[0] } else { u64::MAX });
    }

    fn event(&mut self, kind: u64, a: u64, b: u64) {
        let clicked = match kind {
            window::POINTER => {
                self.pointer = Some((a as u16 as i16 as i32, (a >> 16) as u16 as i16 as i32));
                self.bar.pointer(Some((a, b)))
            }
            window::LEAVE => {
                self.pointer = None;
                self.bar.pointer(None)
            }
            window::WINDOWS => {
                self.refresh(false);
                None
            }
            _ => None,
        };
        if let Some(id) = clicked {
            self.clicked(id);
        }
    }

    fn menu_event(&mut self, kind: u64, a: u64, b: u64) {
        let clicked = match kind {
            window::POINTER => self.menu.pointer(Some((a, b))),
            window::LEAVE => self.menu.pointer(None),
            _ => None,
        };
        if let Some(k) = clicked {
            self.launch(k);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut made = syscall(Syscall::Retype, MEMORY, [ObjectType::Notification as u64, 0, NTFN, 0]).status == 0;
    for (slot, va, pages) in [(PAGE_SLOTS, VA, MAX_PAGES), (MENU_SLOTS, MENU_VA, MENU_PAGES)] {
        for p in 0..pages {
            made &= syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, slot + p, 0]).status == 0
                && syscall(Syscall::FrameMap, slot + p, [va + p * 4096, 1, 0, 0]).status == 0;
        }
    }
    if !made {
        say!("[fail] no memory for the panel");
        superior_sys::park()
    }
    // The screen's size, once the compositor answers.
    let mut info = [u64::MAX; 4];
    for _ in 0..200 {
        if let Some(m) = call(window::info(), None).filter(|m| m[0] == 0) {
            info = m;
            break;
        }
        superior_sys::sleep(5);
    }
    let (width, height) = (info[1].min(1024) as u32, info[2] as u32);
    if info[0] != 0 || height < HEIGHT {
        say!("[fail] no screen to put the panel on");
        superior_sys::park()
    }
    let mut launchers = [Name::EMPTY; MAX_LAUNCHERS];
    let mut nlaunchers = 0;
    while nlaunchers < MAX_LAUNCHERS {
        let r = syscall(Syscall::Call, MANAGER, [launch::OP_LAUNCHERS, nlaunchers as u64, 0, 0]);
        if r.status != 0 || r.msg[0] != 0 {
            break;
        }
        let (bytes, len) = launch::name([r.msg[1], r.msg[2], r.msg[3]]);
        launchers[nlaunchers] = Name { bytes, len };
        nlaunchers += 1;
    }
    let mut menu = Ui::new(MENU_W, menu_height(nlaunchers.max(1)));
    menu_layout(&mut menu, &launchers[..nlaunchers]);
    let mut p = Panel {
        bar: Own { ui: Ui::row(width, HEIGHT), window: None, va: VA },
        menu: Own { ui: menu, window: None, va: MENU_VA },
        launchers,
        nlaunchers,
        tasks: [NO_TASK; MAX_TASKS],
        ntasks: 0,
        at: (0, (height - HEIGHT) as u64),
        clock: clock_text(superior_sys::time()),
        pointer: None,
    };
    if !p.open() {
        say!("[fail] the compositor would not show the panel");
        superior_sys::park()
    }
    say!("ready: {}x{} at the bottom, {} launchers in its menu", width, HEIGHT, p.nlaunchers);
    say!("the clock shows {}", core::str::from_utf8(&p.clock).unwrap_or("?"));
    loop {
        syscall(Syscall::TimerSignal, NTFN, [20, 0, 0, 0]);
        syscall(Syscall::Wait, NTFN, [0; 4]);
        let Some(n) = p.bar.window else { superior_sys::park() };
        let mut restarted = false;
        loop {
            match call(window::next(n), None) {
                Some(m) if m[0] == 0 => p.event(m[1], m[2], m[3]),
                Some(m) if m[0] == superior_objects::interfaces::Status::Empty as u64 => break,
                _ => {
                    restarted = true;
                    break;
                }
            }
        }
        while let Some(n) = p.menu.window {
            match call(window::next(n), None) {
                Some(m) if m[0] == 0 => p.menu_event(m[1], m[2], m[3]),
                _ => break,
            }
        }
        if restarted {
            say!("the compositor restarted; making the panel again");
            p.menu.window = None;
            p.open();
        }
        p.tick();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
