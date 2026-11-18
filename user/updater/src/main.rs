//! The updater: fetches the next system over the network and stages it in
//! the A/B slot not booted (`superior_objects::ab`).
//!
//! It runs in the system bundle with `update-control`. Once the network
//! server has an address, it confirms the system came up (`OP_BOOT_OK`:
//! the network working is its health check), then asks an update server
//! for a newer system: `GET /system?have=<version>` from port `arg & 0xffff`
//! of the gateway, over HTTP/1.1 (`superior_objects::http`). 204 means
//! there is none. 200 with a `Content-Length` that fits the slot is the
//! signed system bundle: it is written to the free slot as it arrives,
//! then the slot's header last, so a download cut short never looks like
//! a slot; the Component Manager checks its signature and version
//! (`OP_UPDATE_READY`), and the updater restarts the machine into it
//! (`OP_RESTART`). A download refused, cut short or failed is tried again,
//! up to `TRIES` times.
//!
//! With bit 16 of its argument set (for tests), it shuts the machine down
//! once there is no newer system (pass) or it gives up (fail).
//!
//! Slots: 0 the block service (the system disk), 1 the network service,
//! 2 the control capability, 3 untyped memory; 4 takes each connection's
//! notification, and it makes 5 the page lent to the network server and 6
//! the page lent to the disk.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::ab;
use superior_objects::http;
use superior_objects::interfaces::{Status, block, net, update};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x, ticks};

const BLOCK: u64 = 0;
const NET: u64 = 1;
const CONTROL: u64 = 2;
const MEMORY: u64 = 3;
const NTFN: u64 = 4;
const NET_PAGE: u64 = 5;
const DISK_PAGE: u64 = 6;
const NET_VA: u64 = USER_BASE + 0x4000_0000;
const DISK_VA: u64 = NET_VA + 0x1000;

/// How many downloads it tries before giving up.
const TRIES: u32 = 5;
/// How long a download may go without a byte arriving (ticks).
const STALL: u64 = 1000;
/// How long it waits for the network server's address (ticks).
const LEASE: u64 = 3000;
/// Bit 16 of its argument: shut the machine down when done.
const SHUT_DOWN_WHEN_DONE: u64 = 1 << 16;

const OK: u64 = Status::Ok as u64;
/// The Component Manager's shut-down call on the control capability.
const OP_SHUTDOWN: u64 = 2;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("updater: {}", format_args!($($t)*))) };
}

fn page(va: u64) -> &'static mut [u8; 4096] {
    // SAFETY: both pages are mapped for good at start.
    unsafe { &mut *(va as *mut [u8; 4096]) }
}

fn manager(m: [u64; 4]) -> [u64; 4] {
    let r = syscall(Syscall::Call, CONTROL, m);
    if r.status != 0 { [u64::MAX, 0, 0, 0] } else { r.msg }
}

fn net_call(m: [u64; 4]) -> Option<[u64; 4]> {
    let r = syscall_x(Syscall::Call, NET, m, CapTransfer { grant: Some(NET_PAGE as u16), accept: None });
    (r.status == 0).then_some(r.msg)
}

/// Writes `count` sectors (up to a page) of the disk page at `sector`.
fn disk_write(sector: u64, count: u64) -> bool {
    let lend = CapTransfer { grant: Some(DISK_PAGE as u16), accept: None };
    let r = syscall_x(Syscall::Call, BLOCK, [block::WRITE, sector, count, 0], lend);
    r.status == 0 && r.msg[0] == OK
}

fn disk_flush() -> bool {
    let r = syscall(Syscall::Call, BLOCK, [block::FLUSH, 0, 0, 0]);
    r.status == 0 && r.msg[0] == OK
}

/// An address word's IPv4 address, dotted.
struct Dotted(u64);

impl core::fmt::Display for Dotted {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let b = ((self.0 >> 16) as u32).to_be_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

/// How a download ended.
enum Got {
    /// No system newer than ours (204).
    Nothing,
    /// Written and staged: its length.
    Staged(usize),
    /// Written, and refused by the manager: its status.
    Refused(u64),
    /// The connection ended early: bytes got of those promised.
    Cut(usize, usize),
    /// Anything else.
    Failed(&'static str),
}

/// A TCP connection to the update server.
struct Conn(u64);

impl Conn {
    fn open(to: u64) -> Option<Conn> {
        syscall(Syscall::CapDelete, NTFN, [0; 4]);
        let x = CapTransfer { grant: None, accept: Some(NTFN as u16) };
        let r = syscall_x(Syscall::Call, NET, [net::TCP_CONNECT, to, 0, 0], x);
        (r.status == 0 && r.msg[0] == OK).then_some(Conn(r.msg[1]))
    }

    fn wait(&self, t: u64) {
        syscall(Syscall::TimerSignal, NTFN, [t, 0, 0, 0]);
        syscall(Syscall::Wait, NTFN, [0; 4]);
    }

    /// Sends the first `n` bytes of the network page, waiting for room.
    fn send_all(&self, n: usize) -> bool {
        let start = ticks();
        while ticks() < start + STALL {
            match net_call([net::SEND, self.0, 0, n as u64]) {
                Some(r) if r[0] == OK && r[1] == n as u64 => return true,
                Some(r) if r[0] == Status::Empty as u64 => self.wait(5),
                // Part taken: these requests are far below a segment.
                _ => return false,
            }
        }
        false
    }

    /// What has arrived, into the network page: `Ok(Some(0))` at the end,
    /// `Ok(None)` for nothing yet.
    fn recv(&self) -> Result<Option<usize>, ()> {
        match net_call([net::RECV, self.0, 0, 0]) {
            Some(r) if r[0] == OK => Ok(Some(r[1] as usize)),
            Some(r) if r[0] == Status::Empty as u64 => Ok(None),
            _ => Err(()),
        }
    }

    fn close(self) {
        net_call([net::CLOSE, self.0, 0, 0]);
        syscall(Syscall::CapDelete, NTFN, [0; 4]);
    }
}

/// The bytes of a body, written to the slot a page at a time after its
/// header sector.
struct Writer {
    first: u64,
    /// Sectors written after the header, and bytes waiting in the page.
    sectors: u64,
    fill: usize,
}

impl Writer {
    fn put(&mut self, mut b: &[u8]) -> bool {
        while !b.is_empty() {
            let n = b.len().min(4096 - self.fill);
            page(DISK_VA)[self.fill..self.fill + n].copy_from_slice(&b[..n]);
            self.fill += n;
            b = &b[n..];
            if self.fill == 4096 && !self.flush() {
                return false;
            }
        }
        true
    }

    /// Writes what waits in the page, its last sector padded.
    fn flush(&mut self) -> bool {
        let count = self.fill.div_ceil(ab::SECTOR) as u64;
        page(DISK_VA)[self.fill..count as usize * ab::SECTOR].fill(0);
        let ok = count == 0 || disk_write(self.first + 1 + self.sectors, count);
        self.sectors += count;
        self.fill = 0;
        ok
    }
}

/// Asks the server at `server` for a system newer than `have` and, if one
/// comes, writes it to the free slot and has the manager stage it.
fn download(server: u64, have: u64) -> Got {
    let r = manager([update::OP_UPDATE_SLOT, 0, 0, 0]);
    if r[0] != OK {
        return Got::Failed("no slot to write an update to");
    }
    let (first, sectors) = (r[2], r[3]);
    let room = (sectors as usize - 1) * ab::SECTOR;
    // No header until the whole system is written.
    page(DISK_VA)[..ab::SECTOR].fill(0);
    if !disk_write(first, 1) {
        return Got::Failed("the slot's header could not be cleared");
    }
    let Some(c) = Conn::open(server) else { return Got::Failed("no connection") };
    let got = fetch(&c, server, have, first, room);
    c.close();
    let len = match got {
        Ok(len) => len,
        Err(g) => return g,
    };
    page(DISK_VA)[..ab::SECTOR].copy_from_slice(&ab::slot_header(len));
    if !disk_write(first, 1) || !disk_flush() {
        return Got::Failed("the disk refused it");
    }
    match manager([update::OP_UPDATE_READY, 0, 0, 0])[0] {
        OK => Got::Staged(len),
        s => Got::Refused(s),
    }
}

/// Sends the request and writes the body to the slot at `first` (`room`
/// bytes at most): its length.
fn fetch(c: &Conn, server: u64, have: u64, first: u64, room: usize) -> Result<usize, Got> {
    let host = format_args!("{}:{}", Dotted(server), server & 0xffff);
    let n = http::get(page(NET_VA), host, format_args!("/system?have={have}")).ok_or(Got::Failed("request"))?;
    if !c.send_all(n) {
        return Err(Got::Failed("the request was not sent"));
    }
    let mut head = [0u8; http::MAX_HEAD + 4096];
    let mut held = 0;
    let mut body: Option<(http::Head, Writer, usize)> = None;
    let mut last = ticks();
    loop {
        let n = match c.recv() {
            Ok(Some(0)) => break,
            Ok(Some(n)) => n,
            Ok(None) if ticks() > last + STALL => return Err(Got::Failed("the server went quiet")),
            Ok(None) => {
                c.wait(10);
                continue;
            }
            Err(()) => return Err(Got::Failed("the connection failed")),
        };
        last = ticks();
        let bytes = &page(NET_VA)[..n];
        match &mut body {
            Some((h, w, got)) => {
                let take = n.min(h.length - *got);
                *got += take;
                if !w.put(&bytes[..take]) {
                    return Err(Got::Failed("the disk refused it"));
                }
            }
            None => {
                head[held..held + n].copy_from_slice(bytes);
                held += n;
                let h = match http::head(&head[..held]) {
                    Ok(h) => h,
                    Err(http::HttpError::Incomplete) => continue,
                    Err(_) => return Err(Got::Failed("a response it cannot read")),
                };
                match h.status {
                    204 => return Err(Got::Nothing),
                    200 if h.length <= room && h.length > 0 => {}
                    200 => return Err(Got::Failed("a system too big for the slot")),
                    _ => return Err(Got::Failed("the server answered with an error")),
                }
                let mut w = Writer { first, sectors: 0, fill: 0 };
                let take = (held - h.body).min(h.length);
                if !w.put(&head[h.body..h.body + take]) {
                    return Err(Got::Failed("the disk refused it"));
                }
                body = Some((h, w, take));
            }
        }
        if body.as_ref().is_some_and(|(h, _, got)| *got == h.length) {
            break;
        }
    }
    let Some((h, mut w, got)) = body else { return Err(Got::Failed("no response")) };
    if got < h.length {
        return Err(Got::Cut(got, h.length));
    }
    if !w.flush() {
        return Err(Got::Failed("the disk refused it"));
    }
    Ok(h.length)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let mut made = true;
    for (slot, va) in [(NET_PAGE, NET_VA), (DISK_PAGE, DISK_VA)] {
        made &= syscall(Syscall::Retype, MEMORY, [ObjectType::Frame as u64, 0, slot, 0]).status == 0
            && syscall(Syscall::FrameMap, slot, [va, 1, 0, 0]).status == 0;
    }
    let shut_down = arg & SHUT_DOWN_WHEN_DONE != 0;
    let done = |pass: bool| -> ! {
        if shut_down {
            syscall(Syscall::Call, CONTROL, [OP_SHUTDOWN, !pass as u64, 0, 0]);
        }
        superior_sys::park()
    };
    let info = manager([update::OP_BOOT_INFO, 0, 0, 0]);
    if !made || info[0] != OK {
        say!("[fail] no memory, or no system slot booted");
        done(false)
    }
    let (slot, version) = (if info[1] & 0xff == 0 { 'A' } else { 'B' }, info[2]);
    say!("running version {version} from slot {slot}");
    let start = ticks();
    let net_info = loop {
        match net_call([net::INFO, net::VERSION, 0, 0]) {
            Some(r) if r[0] == OK => break Some(r),
            _ if ticks() > start + LEASE => break None,
            _ => superior_sys::sleep(5),
        }
    };
    let Some(net_info) = net_info else {
        say!("[fail] the network never came up; not confirming version {version}");
        done(false)
    };
    if manager([update::OP_BOOT_OK, 0, 0, 0])[0] != OK {
        say!("[fail] the manager would not confirm version {version}");
        done(false)
    }
    say!("the network is up ({}): version {version} confirmed", Dotted(net_info[1]));
    let server = net_info[3] | (arg & 0xffff);
    say!("asking http://{}:{}/system?have={version}", Dotted(server), server & 0xffff);
    for k in 1..=TRIES {
        match download(server, version) {
            Got::Nothing => {
                say!("no system newer than version {version}");
                done(true)
            }
            Got::Staged(len) => {
                say!("download {k}: {len} bytes written to the free slot and staged; restarting into it");
                manager([update::OP_RESTART, 0, 0, 0]);
                say!("[fail] the manager did not restart the machine");
                done(false)
            }
            Got::Refused(s) => say!("download {k}: refused by the manager (status {s}); trying again"),
            Got::Cut(got, of) => say!("download {k}: cut short, {got} of {of} bytes; trying again"),
            Got::Failed(why) => say!("download {k} failed: {why}; trying again"),
        }
        superior_sys::sleep(50);
    }
    say!("[fail] gave up after {TRIES} downloads");
    done(false)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
