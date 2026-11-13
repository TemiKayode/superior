//! The desktop shell's panel: a strip along the bottom of the screen,
//! drawn with the toolkit. It starts with a launcher button for each
//! `start launch` component in the manifest (`+ name`), which asks the
//! Component Manager to start it, then a button for each other client's
//! window (its title), the one with the keyboard focus selected; pressing
//! one puts that window in front with the focus.
//!
//! It manages the compositor (`manages window`): it may list, describe and
//! activate every window, the compositor tells its window when they change
//! (`WINDOWS`), and its window stays in front without taking the focus.
//! Crash-only like every window client: a restarted compositor knows no
//! panel, and it makes its window again.
//!
//! `cargo xtask panel-test` lays out the same panel (`layout`) to check
//! screenshots.
//!
//! Slots: 0 the compositor's `window` (a manager's), 1 the Component
//! Manager (`launch-control`), 2 memory, 3 the notification the compositor
//! signals (made here), 8 on the window's pages.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::idl::window;
use superior_objects::interfaces::launch;
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};
use superior_toolkit::{Event, Id, Rect, Surface, Ui};

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

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("panel: {}", format_args!($($t)*))) };
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

/// A window on the panel: its number, title, and whether it has the focus.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Task {
    window: u64,
    title: Name,
    focused: bool,
}

/// Lays the panel out: a launcher for each of `launchers` (`+ name`),
/// then a button for each of `tasks`, the focused one selected. The
/// buttons' ids are the launchers' and then the tasks' indices.
fn layout(ui: &mut Ui, launchers: &[Name], tasks: &[Task]) {
    ui.clear();
    for l in launchers {
        let mut text = [0u8; launch::NAME_BYTES + 2];
        text[..2].copy_from_slice(b"+ ");
        text[2..2 + l.len].copy_from_slice(&l.bytes[..l.len]);
        ui.button(core::str::from_utf8(&text[..2 + l.len]).unwrap_or("?"));
    }
    for t in tasks {
        let id = ui.button(if t.title.len == 0 { "untitled" } else { t.title.as_str() });
        ui.select(id, t.focused);
    }
}

struct Panel {
    ui: Ui,
    launchers: [Name; MAX_LAUNCHERS],
    nlaunchers: usize,
    tasks: [Task; MAX_TASKS],
    ntasks: usize,
    window: Option<u64>,
    at: (u64, u64),
    /// Where the pointer last was on the panel (it is laid out anew under
    /// it), none once it left.
    pointer: Option<(i32, i32)>,
}

impl Panel {
    fn surface(&self) -> Surface<'static> {
        let (w, h) = (self.ui.w, self.ui.h);
        // SAFETY: the window's pages are mapped, writable, in a row from
        // `VA`, and hold `w` by `h` pixels; only one surface is used at a
        // time.
        let px = unsafe { core::slice::from_raw_parts_mut(VA as *mut u32, (w * h) as usize) };
        Surface { px, w, h }
    }

    fn pages(&self) -> u64 {
        (self.ui.w as u64 * self.ui.h as u64 * 4).div_ceil(4096)
    }

    fn open(&mut self) -> bool {
        for _ in 0..50 {
            self.window = None;
            let size = self.ui.w as u64 | (self.ui.h as u64) << 16;
            let Some(r) = call(window::create(size, self.at.0 | self.at.1 << 16), None) else {
                superior_sys::sleep(5);
                continue;
            };
            if r[0] != 0 {
                return false;
            }
            let n = r[1];
            if (0..self.pages()).all(|p| ok(call(window::attach(n, p), Some(PAGE_SLOTS + p))))
                && ok(call(window::listen(n), Some(NTFN)))
            {
                self.window = Some(n);
                self.refresh(true);
                return true;
            }
        }
        false
    }

    /// Asks the compositor which windows there are; if they changed (or
    /// `all`), lays the panel out anew and shows it.
    fn refresh(&mut self, all: bool) {
        let Some(list) = call(window::list(), None).filter(|m| m[0] == 0) else { return };
        let mut tasks = [Task { window: 0, title: Name::EMPTY, focused: false }; MAX_TASKS];
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
            tasks[n] = Task { window: w, title, focused: list[2] == w };
            n += 1;
        }
        if !all && tasks[..n] == self.tasks[..self.ntasks] {
            return;
        }
        (self.tasks, self.ntasks) = (tasks, n);
        layout(&mut self.ui, &self.launchers[..self.nlaunchers], &self.tasks[..self.ntasks]);
        if let Some((x, y)) = self.pointer {
            self.ui.event(Event::Pointer { x, y, buttons: 0 });
        }
        self.ui.draw(&mut self.surface());
        let whole = Rect { x: 0, y: 0, w: self.ui.w, h: self.ui.h };
        if let Some(n) = self.window {
            let _ = call(window::commit(n, rect_word(whole)), None);
        }
        // Said once it is on the screen.
        self.say_tasks();
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
                    write!(f, "{sep}\"{}\"{}", t.title.as_str(), if t.focused { " (focused)" } else { "" })?;
                }
                Ok(())
            }
        }
        say!("windows: {}", Tasks(&self.tasks[..self.ntasks]));
    }

    /// Button `id` was clicked: a launcher starts its app, a task button
    /// puts its window in front.
    fn clicked(&mut self, id: Id) {
        if id < self.nlaunchers {
            let l = self.launchers[id];
            let w = launch::words(&l.bytes[..l.len]);
            let r = syscall(Syscall::Call, MANAGER, [launch::OP_LAUNCH, w[0], w[1], w[2]]);
            say!("launched {} (status {})", l.as_str(), if r.status == 0 { r.msg[0] } else { u64::MAX });
        } else if let Some(t) = self.tasks.get(id - self.nlaunchers).filter(|_| id - self.nlaunchers < self.ntasks) {
            let t = *t;
            let r = call(window::activate(t.window), None);
            say!("activated \"{}\" (status {})", t.title.as_str(), r.map_or(u64::MAX, |m| m[0]));
        }
    }

    fn event(&mut self, kind: u64, a: u64, b: u64) {
        let e = match kind {
            window::POINTER => {
                let (x, y) = (a as u16 as i16 as i32, (a >> 16) as u16 as i16 as i32);
                self.pointer = Some((x, y));
                Event::Pointer { x, y, buttons: b }
            }
            window::LEAVE => {
                self.pointer = None;
                Event::Leave
            }
            window::WINDOWS => {
                self.refresh(false);
                return;
            }
            _ => return,
        };
        let r = self.ui.event(e);
        if !r.damage.empty() {
            let drawn = self.ui.draw_part(&mut self.surface(), r.damage);
            if let Some(n) = self.window {
                let _ = call(window::commit(n, rect_word(drawn)), None);
            }
        }
        if let Some(id) = r.clicked {
            self.clicked(id);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut made = syscall(Syscall::Retype, MEMORY, [ObjectType::Notification as u64, 0, NTFN, 0]).status == 0;
    for p in 0..MAX_PAGES {
        made &= syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, PAGE_SLOTS + p, 0]).status == 0
            && syscall(Syscall::FrameMap, PAGE_SLOTS + p, [VA + p * 4096, 1, 0, 0]).status == 0;
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
    let mut p = Panel {
        ui: Ui::row(width, HEIGHT),
        launchers: [Name::EMPTY; MAX_LAUNCHERS],
        nlaunchers: 0,
        tasks: [Task { window: 0, title: Name::EMPTY, focused: false }; MAX_TASKS],
        ntasks: 0,
        window: None,
        at: (0, (height - HEIGHT) as u64),
        pointer: None,
    };
    while p.nlaunchers < MAX_LAUNCHERS {
        let r = syscall(Syscall::Call, MANAGER, [launch::OP_LAUNCHERS, p.nlaunchers as u64, 0, 0]);
        if r.status != 0 || r.msg[0] != 0 {
            break;
        }
        let (bytes, len) = launch::name([r.msg[1], r.msg[2], r.msg[3]]);
        p.launchers[p.nlaunchers] = Name { bytes, len };
        p.nlaunchers += 1;
    }
    if !p.open() {
        say!("[fail] the compositor would not show the panel");
        superior_sys::park()
    }
    struct Launchers<'a>(&'a [Name]);
    impl core::fmt::Display for Launchers<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            for (k, l) in self.0.iter().enumerate() {
                write!(f, "{}{}", if k > 0 { ", " } else { "" }, l.as_str())?;
            }
            Ok(())
        }
    }
    say!(
        "ready: {}x{} at the bottom, {} launchers ({})",
        width,
        HEIGHT,
        p.nlaunchers,
        Launchers(&p.launchers[..p.nlaunchers])
    );
    loop {
        syscall(Syscall::TimerSignal, NTFN, [20, 0, 0, 0]);
        syscall(Syscall::Wait, NTFN, [0; 4]);
        let Some(n) = p.window else { superior_sys::park() };
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
        if restarted {
            say!("the compositor restarted; making the panel again");
            p.open();
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
