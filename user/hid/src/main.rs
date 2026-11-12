//! A USB HID driver for keyboards and pointing devices: uses the `usb`
//! interface of a host controller driver and serves `input`
//! (`superior_objects::interfaces::input`).
//!
//! It finds the first device with a boot-protocol keyboard interface
//! (class 3, subclass 1, protocol 1) and up to two pointing devices: HID
//! interfaces whose report descriptor (`superior_driver::hid`) has an
//! input report with X and Y in it, relative (a mouse) or absolute (a
//! tablet), with buttons and a wheel or two. It claims them, has their
//! interrupt-IN endpoints polled and selects the configuration: the boot
//! protocol for the keyboard, the report protocol for a pointing device
//! that also speaks the boot one. Each 8-byte keyboard report becomes key
//! presses and releases, by comparing it with the one before; each
//! pointer report becomes button presses and releases (against the
//! last), a motion or a new position, and the wheels' steps. Events go
//! into a ring every subscriber reads from at its own pace.
//!
//! One `Recv` waits for calls, the host controller driver's signal that
//! reports have arrived, and a timer (`TimerSignal`), on which the driver
//! reads anything waiting and, if the host controller driver was restarted
//! and has forgotten the endpoints, sets the devices up again. Every
//! second it also looks for a kind of device it has not found yet.
//!
//! Slots: 0 the `usb` endpoint, 1 the `input` endpoint (receive), 2
//! untyped memory.

#![no_std]
#![no_main]

use superior_driver::hid::{self, Pointer};
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
/// Where a caller's capability arrives.
const LENT: u64 = 8;
/// Subscriber `i`'s notification, the driver's.
const SUB_NTFN: u64 = 9;
/// Subscriber `i`'s notification, if it lent one.
const SUB_LENT: u64 = SUB_NTFN + SUBSCRIBERS as u64;

const PAGE_VA: u64 = USER_BASE + 0x4000_0000;

const REPORT: u64 = 1;
const TIMER: u64 = 2;
/// Ticks between timer rounds.
const PERIOD: u64 = 10;
/// Timer rounds between looks for a kind of device not found yet.
const LOOK_ROUNDS: u64 = 10;
const READ: u64 = 1;
const WRITE: u64 = 2;
const ALL: u64 = 0x1f;

const SUBSCRIBERS: usize = 4;
const EVENTS: usize = 64;
/// The longest report descriptor read.
const MAX_DESCRIPTOR: u16 = 1024;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("hid: {}", format_args!($($t)*))) };
}

/// The devices' slots: the keyboard, then the pointing devices.
const KEYBOARD: usize = 0;
const SLOTS: usize = 3;

#[derive(Clone, Copy)]
struct Device {
    device: u64,
    endpoint: u8,
    /// Where its reports keep what they say, for a pointing device.
    layout: Option<Pointer>,
    /// The buttons held.
    buttons: u8,
    /// An absolute device's last position (each 0 to POSITION_MAX).
    position: (u64, u64),
}

#[derive(Clone, Copy, Default)]
struct Event {
    kind: u64,
    a: u64,
    b: u64,
}

struct Subscriber {
    owner: u64,
    /// Whether it lent its own notification.
    lent: bool,
    /// The number of the next event it reads.
    cursor: u64,
}

struct Hid {
    devices: [Option<Device>; SLOTS],
    /// The last keyboard report: modifiers, then up to six keys.
    last: [u8; 8],
    events: [Event; EVENTS],
    /// Events ever added; event `n` is at `n % EVENTS`.
    added: u64,
    subscribers: [Option<Subscriber>; SUBSCRIBERS],
    /// Times each slot was set up.
    setups: [u64; SLOTS],
    rounds: u64,
}

static mut HID: Hid = Hid {
    devices: [None; SLOTS],
    last: [0; 8],
    events: [Event { kind: 0, a: 0, b: 0 }; EVENTS],
    added: 0,
    subscribers: [const { None }; SUBSCRIBERS],
    setups: [0; SLOTS],
    rounds: 0,
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

/// A HID interface of a device's configuration.
#[derive(Clone, Copy)]
struct Interface {
    config: u8,
    number: u8,
    subclass: u8,
    protocol: u8,
    /// Its report descriptor's length (from its HID descriptor).
    report_len: u16,
    /// Its interrupt-IN endpoint descriptor: address | max packet << 8 |
    /// interval << 24.
    endpoint: u64,
}

impl Interface {
    fn boot_keyboard(&self) -> bool {
        self.subclass == 1 && self.protocol == 1
    }
}

/// Device `device`'s HID interfaces with an interrupt-IN endpoint, up to
/// four.
fn interfaces(device: u64) -> Result<([Option<Interface>; 4], usize), Status> {
    let mut found = [None; 4];
    let mut n = 0;
    // The configuration descriptor's header, for its length, then all of it.
    if control(device, 0x80, 6, 2 << 8, 0, 9)? < 9 {
        return Ok((found, 0));
    }
    let total = u16::from_le_bytes([page()[2], page()[3]]).min(1024);
    let len = control(device, 0x80, 6, 2 << 8, 0, total)? as usize;
    let d = &page()[..len];
    let config = d[5];
    let mut at = 0;
    let mut current: Option<Interface> = None;
    while at + 2 <= len && d[at] >= 2 {
        let (l, what) = (d[at] as usize, d[at + 1]);
        if at + l > len {
            break;
        }
        match what {
            4 if l >= 9 => {
                current = (d[at + 5] == 3).then_some(Interface {
                    config,
                    number: d[at + 2],
                    subclass: d[at + 6],
                    protocol: d[at + 7],
                    report_len: 0,
                    endpoint: 0,
                });
            }
            // The HID descriptor: the first class descriptor's type and
            // length.
            0x21 if l >= 9 => {
                if let Some(i) = current.as_mut() {
                    if d[at + 6] == 0x22 {
                        i.report_len = u16::from_le_bytes([d[at + 7], d[at + 8]]);
                    }
                }
            }
            5 if l >= 7 => {
                let (addr, attributes) = (d[at + 2], d[at + 3]);
                if let Some(mut i) = current.take_if(|_| addr & 0x80 != 0 && attributes & 3 == 3) {
                    let mps = u16::from_le_bytes([d[at + 4], d[at + 5]]) as u64 & 0x7ff;
                    i.endpoint = addr as u64 | mps << 8 | (d[at + 6] as u64) << 24;
                    if n < found.len() {
                        found[n] = Some(i);
                        n += 1;
                    }
                }
            }
            _ => {}
        }
        at += l;
    }
    Ok((found, n))
}

/// Interface `i`'s report descriptor read and searched for a pointer.
fn pointer_layout(device: u64, i: &Interface) -> Result<Option<Pointer>, Status> {
    if i.report_len == 0 {
        return Ok(None);
    }
    let len = control(device, 0x81, 6, 0x22 << 8, i.number as u16, i.report_len.min(MAX_DESCRIPTOR))? as usize;
    Ok(hid::pointer(&page()[..len]))
}

impl Hid {
    /// Finds and sets up every slot not set up yet (with `again`, all of
    /// them, as after the host controller driver restarted). Ok if any is
    /// set up after it.
    fn setup(&mut self, again: bool) -> Result<(), Status> {
        if again {
            // Whatever was held is let go; the next reports say what is
            // held now.
            let held: [u8; SLOTS] = core::array::from_fn(|s| self.devices[s].map_or(0, |d| d.buttons));
            held.into_iter().for_each(|h| self.release(h));
            self.devices = [None; SLOTS];
        }
        let info = usb_call([usb::INFO, usb::VERSION, 0, 0], None)?;
        for device in 0..info[1] {
            if self.devices.iter().all(Option::is_some) {
                break;
            }
            if self.devices.iter().flatten().any(|d| d.device == device) {
                continue;
            }
            let (found, n) = interfaces(device)?;
            for i in found[..n].iter().flatten() {
                let (slot, layout) = if i.boot_keyboard() {
                    (KEYBOARD, None)
                } else {
                    let Some(layout) = pointer_layout(device, i)? else { continue };
                    let Some(slot) = (1..SLOTS).find(|&s| self.devices[s].is_none()) else { continue };
                    (slot, Some(layout))
                };
                if self.devices[slot].is_some() {
                    continue;
                }
                self.claim(device, i, slot, layout)?;
                // One slot per device.
                break;
            }
        }
        if self.devices.iter().any(Option::is_some) { Ok(()) } else { Err(Status::NotFound) }
    }

    /// Claims interface `i` of `device` for `slot`.
    fn claim(&mut self, device: u64, i: &Interface, slot: usize, layout: Option<Pointer>) -> Result<(), Status> {
        usb_call([usb::ATTACH, device, 0, 0], Some(REPORT_CAP))?;
        usb_call([usb::ENDPOINT, device, i.endpoint, 0], None)?;
        // SET_CONFIGURATION; SET_PROTOCOL, boot for the keyboard, report
        // for a pointing device that has a boot protocol too; SET_IDLE
        // (only on change).
        control(device, 0x00, 9, i.config as u16, 0, 0)?;
        if layout.is_none() || i.subclass == 1 {
            control(device, 0x21, 0x0b, layout.is_some() as u16, i.number as u16, 0)?;
        }
        control(device, 0x21, 0x0a, 0, i.number as u16, 0)?;
        self.devices[slot] = Some(Device {
            device,
            endpoint: i.endpoint as u8,
            layout,
            buttons: 0,
            position: (0, 0),
        });
        if slot == KEYBOARD {
            self.key_report([0; 8]);
        }
        self.setups[slot] += 1;
        if self.setups[slot] > 1 {
            return Ok(());
        }
        let ep = i.endpoint as u8;
        match layout {
            None => say!("ready: a boot keyboard on device {device}, interface {}, endpoint {ep:#04x}", i.number),
            Some(p) => say!(
                "ready: a pointer on device {device}, interface {}, endpoint {ep:#04x}: {} buttons, {} X and Y{}{}, in {}-byte reports",
                i.number,
                p.button_count(),
                if p.x.relative { "relative" } else { "absolute" },
                if p.wheel.is_some() { ", a wheel" } else { "" },
                if p.pan.is_some() { ", a horizontal wheel" } else { "" },
                p.bytes
            ),
        }
        Ok(())
    }

    /// Takes every report the host controller driver has.
    fn drain(&mut self) {
        if self.devices.iter().all(Option::is_none) && self.setup(true).is_err() {
            return;
        }
        for slot in 0..SLOTS {
            for _ in 0..64 {
                let Some(d) = self.devices[slot] else { break };
                match usb_call([usb::READ, d.device, d.endpoint as u64, 0], Some(PAGE)) {
                    Ok(r) => {
                        let n = (r[1] as usize).min(64);
                        if slot == KEYBOARD && n >= 8 {
                            let mut b = [0; 8];
                            b.copy_from_slice(&page()[..8]);
                            self.key_report(b);
                        } else if let Some(layout) = d.layout {
                            let mut b = [0; 64];
                            b[..n].copy_from_slice(&page()[..n]);
                            self.pointer_report(slot, &layout, &b[..n]);
                        }
                    }
                    Err(Status::Empty) => break,
                    // Restarted, or forgot the endpoint: set up again.
                    Err(_) => {
                        if self.setup(true).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn push(&mut self, kind: u64, a: u64, b: u64) {
        self.events[self.added as usize % EVENTS] = Event { kind, a, b };
        self.added += 1;
    }

    /// Signals every subscriber that events arrived.
    fn tell(&mut self) {
        for (i, s) in self.subscribers.iter().enumerate() {
            if let Some(s) = s {
                let slot = if s.lent { SUB_LENT } else { SUB_NTFN };
                syscall(Syscall::Signal, slot + i as u64, [0; 4]);
            }
        }
    }

    /// Turns a keyboard boot report into events: what it says against the
    /// last one.
    fn key_report(&mut self, r: [u8; 8]) {
        // All keys reported 1 (rollover): the keys are unknown; ignore it.
        if r[2..].iter().all(|&k| k == 1) {
            return;
        }
        let before = self.added;
        let last = self.last;
        let key = |k: u8, pressed: bool| (k as u64, pressed as u64 | (r[0] as u64) << 8);
        for bit in 0..8 {
            let (was, is) = (last[0] >> bit & 1, r[0] >> bit & 1);
            if was != is {
                let (a, b) = key(0xe0 + bit, is == 1);
                self.push(input::KEY, a, b);
            }
        }
        for &k in last[2..].iter().filter(|&&k| k > 3) {
            if !r[2..].contains(&k) {
                let (a, b) = key(k, false);
                self.push(input::KEY, a, b);
            }
        }
        for &k in r[2..].iter().filter(|&&k| k > 3) {
            if !last[2..].contains(&k) {
                let (a, b) = key(k, true);
                self.push(input::KEY, a, b);
            }
        }
        self.last = r;
        if self.added != before {
            self.tell();
        }
    }

    /// Releases the buttons in `held`.
    fn release(&mut self, held: u8) {
        for bit in 0..hid::BUTTONS {
            if held >> bit & 1 != 0 {
                self.push(input::BUTTON, bit as u64, 0);
            }
        }
        if held != 0 {
            self.tell();
        }
    }

    /// Turns a pointer report into events: the buttons against the last
    /// report's, then the motion or the new position, then the wheels.
    fn pointer_report(&mut self, slot: usize, p: &Pointer, report: &[u8]) {
        let Some(body) = p.body(report) else { return };
        let Some(mut d) = self.devices[slot] else { return };
        let before = self.added;
        let mut buttons = 0u8;
        for (bit, f) in p.buttons.iter().enumerate() {
            if f.and_then(|f| f.read(body)).is_some_and(|v| v != 0) {
                buttons |= 1 << bit;
            }
        }
        for bit in 0..hid::BUTTONS {
            let (was, is) = (d.buttons >> bit & 1, buttons >> bit & 1);
            if was != is {
                self.push(input::BUTTON, bit as u64, is as u64);
            }
        }
        d.buttons = buttons;
        if let (Some(x), Some(y)) = (p.x.read(body), p.y.read(body)) {
            if p.x.relative {
                if x != 0 || y != 0 {
                    self.push(input::MOTION, x as i64 as u64, y as i64 as u64);
                }
            } else {
                let at = (p.x.scale(x, input::POSITION_MAX), p.y.scale(y, input::POSITION_MAX));
                if at != d.position {
                    d.position = at;
                    self.push(input::POSITION, at.0, at.1);
                }
            }
        }
        let steps = |f: Option<hid::Field>| f.and_then(|f| f.read(body)).unwrap_or(0) as i64;
        let (up, right) = (steps(p.wheel), steps(p.pan));
        if up != 0 || right != 0 {
            self.push(input::WHEEL, up as u64, right as u64);
        }
        self.devices[slot] = Some(d);
        if self.added != before {
            self.tell();
        }
    }

    /// One client call: the reply, and whether MINT is granted with it.
    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], bool) {
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
                syscall(Syscall::CapDelete, SUB_LENT + i as u64, [0; 4]);
                syscall(Syscall::CapDelete, MINT, [0; 4]);
                let minted = if lent {
                    syscall(Syscall::CapMint, LENT, [SUB_LENT + i as u64, ALL, 0, 0])
                } else {
                    syscall(Syscall::CapMint, SUB_NTFN + i as u64, [MINT, READ | WRITE, 0, 0])
                };
                if minted.status != 0 {
                    return (status(Status::Invalid), false);
                }
                self.subscribers[i] = Some(Subscriber {
                    owner: badge,
                    lent,
                    cursor: self.added,
                });
                (status(Status::Ok), !lent)
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
                ([Status::Ok as u64, e.kind, e.a, e.b], false)
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
        if h.setup(false).is_ok() {
            break;
        }
        superior_sys::sleep(1);
    }
    if h.devices.iter().all(Option::is_none) {
        say!("no keyboard or pointer yet (status {})", h.setup(false).err().map_or(0, |s| s as u64));
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
                h.rounds += 1;
                if h.rounds % LOOK_ROUNDS == 0 && h.devices.iter().any(Option::is_none) {
                    let _ = h.setup(false);
                }
            }
            h.drain();
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let (reply, grant) = h.serve(r.badge, r.msg, lent);
        if r.cap.is_some() {
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
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
