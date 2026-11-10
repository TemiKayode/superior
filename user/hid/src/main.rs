//! A USB HID keyboard driver: uses the `usb` interface of a host controller
//! driver and serves `input` (`superior_objects::interfaces::input`).
//!
//! It finds the first device with a boot-protocol keyboard interface
//! (class 3, subclass 1, protocol 1), claims it, has its interrupt-IN
//! endpoint polled, selects the configuration and the boot protocol, and
//! turns each 8-byte boot report into key presses and releases by comparing
//! it with the one before. Events go into a ring every subscriber reads
//! from at its own pace.
//!
//! One `Recv` waits for calls, the host controller driver's signal that
//! reports have arrived, and a timer (`TimerSignal`), on which the driver
//! reads anything waiting and, if the host controller driver was restarted
//! and has forgotten the endpoint, sets the keyboard up again.
//!
//! Slots: 0 the `usb` endpoint, 1 the `input` endpoint (receive), 2
//! untyped memory.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::interfaces::{Status, input, usb};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const USB: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 2;
/// This thread's notification, bound to it.
const SELF: u64 = 3;
/// Copies of it badged TIMER (for `TimerSignal`) and REPORT (for the host
/// controller driver).
const TIMER_CAP: u64 = 4;
const REPORT_CAP: u64 = 5;
/// The page lent with control transfers and reads.
const PAGE: u64 = 6;
/// A capability being granted.
const MINT: u64 = 7;
/// Where a caller's capability arrives (none are expected).
const LENT: u64 = 8;
/// Subscriber `i`'s notification.
const SUB_NTFN: u64 = 9;

const PAGE_VA: u64 = USER_BASE + 0x4000_0000;

const REPORT: u64 = 1;
const TIMER: u64 = 2;
/// Ticks between timer rounds.
const PERIOD: u64 = 10;
const READ: u64 = 1;
const WRITE: u64 = 2;

const SUBSCRIBERS: usize = 4;
const EVENTS: usize = 64;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("hid: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy)]
struct Keyboard {
    device: u64,
    endpoint: u8,
}

#[derive(Clone, Copy, Default)]
struct KeyEvent {
    key: u8,
    pressed: bool,
    modifiers: u8,
}

struct Subscriber {
    owner: u64,
    /// The number of the next event it reads.
    cursor: u64,
}

struct Hid {
    keyboard: Option<Keyboard>,
    /// The last boot report: modifiers, then up to six keys.
    last: [u8; 8],
    events: [KeyEvent; EVENTS],
    /// Events ever added; event `n` is at `n % EVENTS`.
    added: u64,
    subscribers: [Option<Subscriber>; SUBSCRIBERS],
    setups: u64,
}

static mut HID: Hid = Hid {
    keyboard: None,
    last: [0; 8],
    events: [KeyEvent {
        key: 0,
        pressed: false,
        modifiers: 0,
    }; EVENTS],
    added: 0,
    subscribers: [const { None }; SUBSCRIBERS],
    setups: 0,
};

fn page() -> &'static mut [u8] {
    // SAFETY: the page is mapped at PAGE_VA for good.
    unsafe { core::slice::from_raw_parts_mut(PAGE_VA as *mut u8, 4096) }
}

/// Calls the host controller driver; `grant` lends or grants a capability.
fn usb_call(m: [u64; 4], grant: Option<u64>) -> Result<[u64; 4], Status> {
    let x = CapTransfer {
        grant: grant.map(|s| s as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, USB, m, x);
    if r.status != 0 {
        return Err(Status::DeviceError);
    }
    match Status::from_u64(r.msg[0]) {
        Status::Ok => Ok(r.msg),
        s => Err(s),
    }
}

/// A control transfer with the page as its data stage.
fn control(device: u64, request_type: u8, request: u8, value: u16, index: u16, len: u16) -> Result<u64, Status> {
    let setup = request_type as u64
        | (request as u64) << 8
        | (value as u64) << 16
        | (index as u64) << 32
        | (len as u64) << 48;
    usb_call([usb::CONTROL, device, setup, 0], Some(PAGE)).map(|r| r[1])
}

/// Finds a boot keyboard's interface in device `device`'s configuration:
/// (configuration value, interface number, endpoint descriptor).
fn find_keyboard(device: u64) -> Result<Option<(u8, u8, u64)>, Status> {
    // The configuration descriptor's header, for its length, then all of it.
    let n = control(device, 0x80, 6, 2 << 8, 0, 9)?;
    if n < 9 {
        return Ok(None);
    }
    let total = u16::from_le_bytes([page()[2], page()[3]]).min(1024);
    let n = control(device, 0x80, 6, 2 << 8, 0, total)? as usize;
    let d = &page()[..n];
    let config = d[5];
    let mut at = 0;
    let mut interface: Option<u8> = None;
    while at + 2 <= n && d[at] >= 2 {
        let (len, kind) = (d[at] as usize, d[at + 1]);
        if at + len > n {
            break;
        }
        match kind {
            4 if len >= 9 => {
                let boot_keyboard = d[at + 5] == 3 && d[at + 6] == 1 && d[at + 7] == 1;
                interface = boot_keyboard.then_some(d[at + 2]);
            }
            5 if len >= 7 => {
                if let Some(i) = interface {
                    let (addr, attributes) = (d[at + 2], d[at + 3]);
                    if addr & 0x80 != 0 && attributes & 3 == 3 {
                        let mps = u16::from_le_bytes([d[at + 4], d[at + 5]]) as u64 & 0x7ff;
                        let ep = addr as u64 | mps << 8 | (d[at + 6] as u64) << 24;
                        return Ok(Some((config, i, ep)));
                    }
                }
            }
            _ => {}
        }
        at += len;
    }
    Ok(None)
}

impl Hid {
    /// Finds and sets up the keyboard.
    fn setup(&mut self) -> Result<(), Status> {
        self.keyboard = None;
        let info = usb_call([usb::INFO, usb::VERSION, 0, 0], None)?;
        for device in 0..info[1] {
            let Some((config, interface, ep)) = find_keyboard(device)? else {
                continue;
            };
            usb_call([usb::ATTACH, device, 0, 0], Some(REPORT_CAP))?;
            usb_call([usb::ENDPOINT, device, ep, 0], None)?;
            // SET_CONFIGURATION, SET_PROTOCOL (boot), SET_IDLE (only on change).
            control(device, 0x00, 9, config as u16, 0, 0)?;
            control(device, 0x21, 0x0b, 0, interface as u16, 0)?;
            control(device, 0x21, 0x0a, 0, interface as u16, 0)?;
            self.keyboard = Some(Keyboard {
                device,
                endpoint: ep as u8,
            });
            self.setups += 1;
            // Whatever was held before is let go; the next report says what
            // is held now.
            self.report([0; 8]);
            if self.setups == 1 {
                say!(
                    "ready: a boot keyboard on device {device}, interface {interface}, endpoint {:#04x}",
                    ep as u8
                );
            }
            return Ok(());
        }
        Err(Status::NotFound)
    }

    /// Takes every report the host controller driver has.
    fn drain(&mut self) {
        if self.keyboard.is_none() && self.setup().is_err() {
            return;
        }
        for _ in 0..64 {
            let Some(k) = self.keyboard else { return };
            match usb_call([usb::READ, k.device, k.endpoint as u64, 0], Some(PAGE)) {
                Ok(r) => {
                    if r[1] >= 8 {
                        let mut b = [0; 8];
                        b.copy_from_slice(&page()[..8]);
                        self.report(b);
                    }
                }
                Err(Status::Empty) => return,
                // Restarted, or forgot the endpoint: set up again.
                Err(_) => {
                    if self.setup().is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn push(&mut self, key: u8, pressed: bool, modifiers: u8) {
        self.events[self.added as usize % EVENTS] = KeyEvent {
            key,
            pressed,
            modifiers,
        };
        self.added += 1;
    }

    /// Turns a boot report into events: what it says against the last one.
    fn report(&mut self, r: [u8; 8]) {
        // All keys reported 1 (rollover): the keys are unknown; ignore it.
        if r[2..].iter().all(|&k| k == 1) {
            return;
        }
        let before = self.added;
        let last = self.last;
        for bit in 0..8 {
            let (was, is) = (last[0] >> bit & 1, r[0] >> bit & 1);
            if was != is {
                self.push(0xe0 + bit, is == 1, r[0]);
            }
        }
        for &k in last[2..].iter().filter(|&&k| k > 3) {
            if !r[2..].contains(&k) {
                self.push(k, false, r[0]);
            }
        }
        for &k in r[2..].iter().filter(|&&k| k > 3) {
            if !last[2..].contains(&k) {
                self.push(k, true, r[0]);
            }
        }
        self.last = r;
        if self.added != before {
            for (i, s) in self.subscribers.iter().enumerate() {
                if s.is_some() {
                    syscall(Syscall::Signal, SUB_NTFN + i as u64, [0; 4]);
                }
            }
        }
    }

    /// One client call: the reply, and whether MINT is granted with it.
    fn serve(&mut self, badge: u64, m: [u64; 4]) -> ([u64; 4], bool) {
        let status = |s: Status| [s as u64, 0, 0, 0];
        match m[0] {
            input::SUBSCRIBE if m[1] == input::VERSION => {
                let i = self
                    .subscribers
                    .iter()
                    .position(|s| matches!(s, Some(s) if s.owner == badge))
                    .or_else(|| self.subscribers.iter().position(|s| s.is_none()));
                let Some(i) = i else {
                    return (status(Status::NoSpace), false);
                };
                // Whoever had this notification before loses it.
                syscall(Syscall::CapRevoke, SUB_NTFN + i as u64, [0; 4]);
                syscall(Syscall::CapDelete, MINT, [0; 4]);
                let minted = syscall(
                    Syscall::CapMint,
                    SUB_NTFN + i as u64,
                    [MINT, READ | WRITE, 0, 0],
                );
                if minted.status != 0 {
                    return (status(Status::Invalid), false);
                }
                self.subscribers[i] = Some(Subscriber {
                    owner: badge,
                    cursor: self.added,
                });
                (status(Status::Ok), true)
            }
            input::READ => {
                let added = self.added;
                let Some(s) = self
                    .subscribers
                    .iter_mut()
                    .flatten()
                    .find(|s| s.owner == badge)
                else {
                    return (status(Status::Denied), false);
                };
                // One that fell behind loses the oldest.
                s.cursor = s.cursor.max(added.saturating_sub(EVENTS as u64));
                if s.cursor == added {
                    return (status(Status::Empty), false);
                }
                let e = self.events[s.cursor as usize % EVENTS];
                s.cursor += 1;
                (
                    [
                        Status::Ok as u64,
                        e.key as u64,
                        e.pressed as u64,
                        e.modifiers as u64,
                    ],
                    false,
                )
            }
            _ => (status(Status::Invalid), false),
        }
    }
}

fn start() -> Result<(), (&'static str, u64)> {
    let retype = |kind: ObjectType, slot: u64| {
        let r = syscall(Syscall::Retype, UNTYPED, [kind as u64, 0, slot, 0]);
        if r.status == 0 {
            Ok(())
        } else {
            Err(("out of memory", r.status))
        }
    };
    retype(ObjectType::Notification, SELF)?;
    if syscall(Syscall::NotificationBind, SELF, [0; 4]).status != 0 {
        return Err(("binding the notification", 0));
    }
    for (slot, badge) in [(TIMER_CAP, TIMER), (REPORT_CAP, REPORT)] {
        if syscall(Syscall::CapMint, SELF, [slot, WRITE, badge, 0]).status != 0 {
            return Err(("minting a copy of the notification", badge));
        }
    }
    retype(ObjectType::Frame, PAGE)?;
    if syscall(Syscall::FrameMap, PAGE, [PAGE_VA, 1, 0, 0]).status != 0 {
        return Err(("mapping the page", 0));
    }
    for i in 0..SUBSCRIBERS as u64 {
        retype(ObjectType::Notification, SUB_NTFN + i)?;
    }
    syscall(Syscall::TimerSignal, TIMER_CAP, [PERIOD, 0, 0, 0]);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    // SAFETY: the one thread is the only user of HID.
    let h = unsafe { &mut *(&raw mut HID) };
    if let Err((what, code)) = start() {
        say!("[fail] {what} ({code})");
        superior_sys::park()
    }
    // The host controller driver may still be finding its devices.
    for _ in 0..200 {
        if h.setup().is_ok() {
            break;
        }
        superior_sys::sleep(1);
    }
    if h.keyboard.is_none() {
        say!("no keyboard yet (status {})", h.setup().err().map_or(0, |s| s as u64));
    }
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    loop {
        let r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
        if r.status == Error::Notified.code() {
            if r.badge & TIMER != 0 {
                syscall(Syscall::TimerSignal, TIMER_CAP, [PERIOD, 0, 0, 0]);
            }
            h.drain();
            continue;
        }
        if r.status != 0 {
            continue;
        }
        if r.cap.is_some() {
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        let (reply, grant) = h.serve(r.badge, r.msg);
        let x = CapTransfer {
            grant: grant.then_some(MINT as u16),
            accept: None,
        };
        syscall_x(Syscall::Reply, 0, reply, x);
        if grant {
            syscall(Syscall::CapDelete, MINT, [0; 4]);
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
