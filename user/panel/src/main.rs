//! The desktop shell's panel: a strip along the bottom of the screen,
//! drawn with the toolkit. At its left an "Apps" button opens the launcher
//! menu, a window above it with a button for each `start launch`
//! component in the manifest (with the icon its manifest names): pressing
//! one asks the Component Manager to start it and closes the menu (as does
//! "Apps" again). Then a button for each other client's window (its icon
//! and title), the one with the keyboard focus selected: pressing one puts
//! that window in front with the focus (drawing it again if it was
//! minimised), or minimises it if it already had the focus. At its right
//! a clock: the date and time of day ("Sat 14 Nov 09:41") in a time zone,
//! from the kernel's real-time clock (`Time`). Pressing it opens a menu of
//! time zones above it (UTC at first); pressing one shows the clock in
//! that zone, its daylight saving and all. Left of the clock a keyboard
//! button names the keyboard layout keys type under; pressing it opens a
//! menu of the layouts, and pressing one has the compositor use it (the
//! panel sets it again when the compositor restarts).
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
use superior_objects::time::{self, ZONES};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};
use superior_toolkit::{BOX_H, Event, Id, PAD, Rect, Surface, Ui, icon_by_name, keymap};

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
/// The menu (the launchers, the time zones or the keyboard layouts): its
/// width, the most pages it takes (a button for every launcher, zone or
/// layout), and where they go.
const MENU_W: u32 = 160;
const MENU_ROWS: usize = max(max(MAX_LAUNCHERS, ZONES.len()), keymap::NAMES.len());
const MENU_PAGES: u64 = (MENU_W as u64 * menu_height(MENU_ROWS) as u64 * 4).div_ceil(4096);
const MENU_SLOTS: u64 = PAGE_SLOTS + MAX_PAGES;
const MENU_VA: u64 = VA + 0x10_0000;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("panel: {}", format_args!($($t)*))) };
}

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
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

/// The clock's text for `seconds` since 1970 (UTC) in time zone `zone`
/// (of `ZONES`): the date and the time of day.
fn clock_text(seconds: Option<u64>, zone: usize) -> [u8; 16] {
    let Some(s) = seconds else { return *b"--- -- --- --:--" };
    time::clock(&ZONES[zone], s as i64)
}

fn text(t: &[u8]) -> &str {
    core::str::from_utf8(t).unwrap_or("?")
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
    icon: u8,
}

const NO_TASK: Task = Task { window: 0, title: Name::EMPTY, focused: false, minimised: false, icon: 0 };

/// Which menu is open.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Menu {
    Launchers,
    Zones,
    Layouts,
}

impl Menu {
    /// What the log calls it.
    fn name(self) -> &'static str {
        match self {
            Menu::Launchers => "menu",
            Menu::Zones => "time zones",
            Menu::Layouts => "keyboard layouts",
        }
    }
}

/// Lays the panel out: "Apps" (selected while the launcher menu is open),
/// a button for each of `tasks` (the focused one selected), then at the
/// right end the keyboard button naming layout `kb` (selected while the
/// layouts' menu is open) and the clock (selected while the time zones'
/// menu is open). "Apps" is button 0, the tasks' buttons follow in order,
/// then the keyboard button, and the clock is last.
fn layout(ui: &mut Ui, tasks: &[Task], menu: Option<Menu>, clock: &[u8; 16], kb: usize) {
    ui.clear();
    let apps = ui.button("Apps");
    ui.select(apps, menu == Some(Menu::Launchers));
    for t in tasks {
        let id = ui.icon_button(t.icon, if t.title.len == 0 { "untitled" } else { t.title.as_str() });
        ui.select(id, t.focused);
    }
    let k = ui.icon_button(icon_by_name(b"keyboard"), keymap::NAMES[kb]);
    ui.select(k, menu == Some(Menu::Layouts));
    let c = ui.icon_button(icon_by_name(b"clock"), text(clock));
    ui.select(c, menu == Some(Menu::Zones));
    ui.push_right(c);
    ui.push_left_of(k, c);
}

/// Lays the launcher menu out: a button for each of `launchers` (with its
/// icon of `icons`), in a column.
fn menu_layout(ui: &mut Ui, launchers: &[Name], icons: &[u8]) {
    ui.clear();
    for (l, &icon) in launchers.iter().zip(icons) {
        ui.icon_button(icon, l.as_str());
    }
}

/// Lays the time zones' menu out: a button for each of `ZONES`, in a
/// column, `zone`'s selected.
fn zone_layout(ui: &mut Ui, zone: usize) {
    ui.clear();
    for (k, z) in ZONES.iter().enumerate() {
        let id = ui.button(z.name);
        ui.select(id, k == zone);
    }
}

/// Lays the keyboard layouts' menu out: a button for each layout, in a
/// column, `kb`'s selected.
fn keyboard_layout(ui: &mut Ui, kb: usize) {
    ui.clear();
    for (k, name) in keymap::NAMES.iter().enumerate() {
        let id = ui.button(name);
        ui.select(id, k == kb);
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
    /// Which menu is open, if one is.
    open: Option<Menu>,
    launchers: [Name; MAX_LAUNCHERS],
    icons: [u8; MAX_LAUNCHERS],
    nlaunchers: usize,
    tasks: [Task; MAX_TASKS],
    ntasks: usize,
    at: (u64, u64),
    width: u32,
    clock: [u8; 16],
    /// The clock's time zone, of `ZONES`.
    zone: usize,
    /// The keyboard layout, of `keymap::NAMES`.
    kb: usize,
    /// Where the pointer last was on the panel (it is laid out anew under
    /// it), none once it left.
    pointer: Option<(i32, i32)>,
}

impl Panel {
    fn open(&mut self) -> bool {
        for _ in 0..50 {
            if self.bar.create(self.at, PAGE_SLOTS) {
                // A restarted compositor starts on the US layout.
                if self.kb != keymap::US as usize {
                    let _ = call(window::set_layout(self.kb as u64), None);
                }
                self.refresh(true);
                return true;
            }
            superior_sys::sleep(5);
        }
        false
    }

    /// The panel's button that opens `menu`.
    fn opener(&self, menu: Menu) -> Id {
        match menu {
            Menu::Launchers => 0,
            Menu::Layouts => self.bar.ui.len() - 2,
            Menu::Zones => self.bar.ui.len() - 1,
        }
    }

    /// Opens `menu` (the launchers above "Apps", the time zones above the
    /// clock, the keyboard layouts above the keyboard button), or closes it if it is open; another menu open closes.
    fn toggle_menu(&mut self, menu: Menu) {
        let was = self.open;
        self.close_menu();
        if was == Some(menu) {
            return;
        }
        let rows = match menu {
            Menu::Launchers => self.nlaunchers.max(1),
            Menu::Zones => ZONES.len(),
            Menu::Layouts => keymap::NAMES.len(),
        };
        self.menu.ui = Ui::new(MENU_W, menu_height(rows));
        let x = match menu {
            Menu::Launchers => {
                menu_layout(&mut self.menu.ui, &self.launchers[..self.nlaunchers], &self.icons);
                0
            }
            Menu::Zones => {
                zone_layout(&mut self.menu.ui, self.zone);
                self.width.saturating_sub(MENU_W) as u64
            }
            Menu::Layouts => {
                keyboard_layout(&mut self.menu.ui, self.kb);
                let x = self.bar.ui.widget(self.opener(menu)).rect.x;
                x.min(self.width.saturating_sub(MENU_W)) as u64
            }
        };
        let h = self.menu.ui.h;
        if self.menu.create((x, self.at.1.saturating_sub(h as u64)), MENU_SLOTS) {
            self.open = Some(menu);
            self.menu.show_all();
            let d = self.bar.ui.select(self.opener(menu), true);
            self.bar.show(d);
            struct Names<'a>(&'a [Name]);
            impl core::fmt::Display for Names<'_> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    for (k, l) in self.0.iter().enumerate() {
                        write!(f, "{}{}", if k > 0 { ", " } else { "" }, l.as_str())?;
                    }
                    Ok(())
                }
            }
            match menu {
                Menu::Launchers => say!("menu open: {}", Names(&self.launchers[..self.nlaunchers])),
                Menu::Zones => say!("time zones open: {} chosen", ZONES[self.zone].name),
                Menu::Layouts => say!("keyboard layouts open: {} chosen", keymap::NAMES[self.kb]),
            }
        }
    }

    fn close_menu(&mut self) {
        let Some(menu) = self.open.take() else { return };
        if let Some(n) = self.menu.window.take() {
            let _ = call(window::destroy(n), None);
        }
        let d = self.bar.ui.select(self.opener(menu), false);
        self.bar.show(d);
        say!("{} closed", menu.name());
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
            let icon = call(window::icon(w), None).filter(|m| m[0] == 0).map_or(0, |m| m[1] as u8);
            tasks[n] = Task { window: w, title, focused: list[2] == w, minimised, icon };
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
        layout(&mut self.bar.ui, &self.tasks[..self.ntasks], self.open, &self.clock, self.kb);
        if let Some((x, y)) = self.pointer {
            self.bar.ui.event(Event::Pointer { x, y, buttons: 0 });
        }
        self.bar.show_all();
    }

    /// The clock shows the time now, if the minute (or the zone) changed.
    fn tick(&mut self) {
        let now = clock_text(superior_sys::time(), self.zone);
        if now == self.clock {
            return;
        }
        self.clock = now;
        let id = self.bar.ui.len() - 1;
        let d = self.bar.ui.set_text(id, text(&now));
        self.bar.show(d);
        say!("the clock shows {} ({})", text(&now), ZONES[self.zone].name);
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

    /// Button `id` of the panel was clicked: "Apps", the keyboard button
    /// and the clock open or close their menus; a task button puts its window in front, or minimises it if it
    /// has the focus.
    fn clicked(&mut self, id: Id) {
        if id == 0 {
            self.toggle_menu(Menu::Launchers);
            return;
        }
        if id == self.bar.ui.len() - 1 {
            self.toggle_menu(Menu::Zones);
            return;
        }
        if id == self.bar.ui.len() - 2 {
            self.toggle_menu(Menu::Layouts);
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

    /// Zone `k` in the time zones' menu was clicked: the menu closes and
    /// the clock shows that zone's time.
    fn choose_zone(&mut self, k: usize) {
        if k >= ZONES.len() {
            return;
        }
        self.close_menu();
        self.zone = k;
        say!("time zone {}", ZONES[k].name);
        self.tick();
    }

    /// Layout `k` in the keyboard layouts' menu was clicked: the menu
    /// closes, the compositor has keys type under it, and the keyboard
    /// button names it.
    fn choose_layout(&mut self, k: usize) {
        if k >= keymap::NAMES.len() {
            return;
        }
        self.close_menu();
        let r = call(window::set_layout(k as u64), None).map_or(u64::MAX, |m| m[0]);
        if r == 0 {
            self.kb = k;
            self.lay_out();
        }
        say!("keyboard layout {} (status {r})", keymap::NAMES[k]);
    }

    fn menu_event(&mut self, kind: u64, a: u64, b: u64) {
        let clicked = match kind {
            window::POINTER => self.menu.pointer(Some((a, b))),
            window::LEAVE => self.menu.pointer(None),
            _ => None,
        };
        match (clicked, self.open) {
            (Some(k), Some(Menu::Launchers)) => self.launch(k),
            (Some(k), Some(Menu::Zones)) => self.choose_zone(k),
            (Some(k), Some(Menu::Layouts)) => self.choose_layout(k),
            _ => {}
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
    let mut icons = [0; MAX_LAUNCHERS];
    let mut nlaunchers = 0;
    while nlaunchers < MAX_LAUNCHERS {
        let r = syscall(Syscall::Call, MANAGER, [launch::OP_LAUNCHERS, nlaunchers as u64, 0, 0]);
        if r.status != 0 || r.msg[0] != 0 {
            break;
        }
        let (bytes, len) = launch::name([r.msg[1], r.msg[2], r.msg[3]]);
        launchers[nlaunchers] = Name { bytes, len };
        let r = syscall(Syscall::Call, MANAGER, [launch::OP_ICON, nlaunchers as u64, 0, 0]);
        if r.status == 0 && r.msg[0] == 0 {
            let (bytes, len) = launch::name([r.msg[1], r.msg[2], r.msg[3]]);
            icons[nlaunchers] = icon_by_name(&bytes[..len]);
        }
        nlaunchers += 1;
    }
    let mut p = Panel {
        bar: Own { ui: Ui::row(width, HEIGHT), window: None, va: VA },
        menu: Own { ui: Ui::new(MENU_W, menu_height(1)), window: None, va: MENU_VA },
        open: None,
        launchers,
        icons,
        nlaunchers,
        tasks: [NO_TASK; MAX_TASKS],
        ntasks: 0,
        at: (0, (height - HEIGHT) as u64),
        width,
        clock: clock_text(superior_sys::time(), 0),
        zone: 0,
        kb: call(window::layout(), None).filter(|m| m[0] == 0).map_or(0, |m| m[1] as usize).min(keymap::NAMES.len() - 1),
        pointer: None,
    };
    if !p.open() {
        say!("[fail] the compositor would not show the panel");
        superior_sys::park()
    }
    say!("ready: {}x{} at the bottom, {} launchers in its menu", width, HEIGHT, p.nlaunchers);
    say!("the clock shows {} ({})", text(&p.clock), ZONES[p.zone].name);
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
            p.open = None;
            p.open();
        }
        p.tick();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
