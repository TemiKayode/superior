//! The DNS resolver: serves the `dns` interface
//! (`superior_objects::interfaces::dns`), turning names into IPv4
//! addresses by asking a DNS server (RFC 1035) over the network server's
//! UDP.
//!
//! A client lends a page holding the name. The resolver answers from its
//! cache while the answer's time to live lasts; otherwise it sends a
//! recursive query (an A record) to the DNS server the network server got
//! from DHCP, sends it again every second for up to [`TRIES`] tries,
//! follows CNAME records in the answer to the address, and caches what it
//! learns, names that do not exist included (for [`NEGATIVE_TTL`]).
//!
//! It is crash-only: a restart loses the cache and the socket, and a call
//! it was serving fails with `PeerRestarted`, which the client retries. If
//! the network server restarts, the resolver's socket is gone: it binds
//! again and sends again.
//!
//! `arg` (for tests): a UDP port on the gateway to ask instead of port 53
//! of the DHCP-given server.
//!
//! Slots: 0 the `net` endpoint, 1 the `dns` endpoint (receive), 2 untyped
//! memory (one page).

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::interfaces::{Status, dns, net};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const NET: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 2;
/// The socket's notification.
const SOCKET: u64 = 3;
/// The page lent to the network server for each datagram.
const PAGE: u64 = 4;
/// Where a client's page arrives.
const LENT: u64 = 5;

const PAGE_VA: u64 = USER_BASE + 0x4000_0000;
const LENT_VA: u64 = PAGE_VA + 0x1000;

const SECOND: u64 = 100;
/// Queries sent for one name before giving up, a second apart.
const TRIES: u32 = 4;
/// Seconds a name that does not exist is remembered.
const NEGATIVE_TTL: u64 = 10;
/// The longest a cached answer is kept, whatever its TTL.
const MAX_TTL: u64 = 86_400;
const CACHE: usize = 16;
const MAX_NAME: usize = dns::MAX_NAME as usize;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("dns: {}", format_args!($($t)*))) };
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

fn page(va: u64) -> &'static mut [u8] {
    // SAFETY: PAGE is mapped for good, LENT while a client's page is.
    unsafe { core::slice::from_raw_parts_mut(va as *mut u8, 4096) }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A name, lower case, dot-separated, without a final dot.
#[derive(Clone, Copy)]
struct Name {
    len: usize,
    b: [u8; MAX_NAME],
}

impl Name {
    const EMPTY: Name = Name {
        len: 0,
        b: [0; MAX_NAME],
    };

    fn as_bytes(&self) -> &[u8] {
        &self.b[..self.len]
    }

    /// A client's name, checked: labels of 1 to 63 letters, digits,
    /// hyphens and underscores.
    fn parse(s: &[u8]) -> Option<Name> {
        let s = s.strip_suffix(b".").unwrap_or(s);
        if s.is_empty() || s.len() > MAX_NAME {
            return None;
        }
        let ok = s.split(|&c| c == b'.').all(|l| {
            (1..=63).contains(&l.len())
                && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        });
        if !ok {
            return None;
        }
        let mut n = Name::EMPTY;
        n.len = s.len();
        for (d, c) in n.b.iter_mut().zip(s) {
            *d = c.to_ascii_lowercase();
        }
        Some(n)
    }

    /// The name at `at` in message `m`, following compression pointers;
    /// and where the name ends in the message (after the first pointer).
    fn read(m: &[u8], mut at: usize) -> Option<(Name, usize)> {
        let mut n = Name::EMPTY;
        let mut end = None;
        for _ in 0..64 {
            let len = *m.get(at)? as usize;
            match len {
                0 => return Some((n, end.unwrap_or(at + 1))),
                l if l & 0xc0 == 0xc0 => {
                    end.get_or_insert(at + 2);
                    at = (l & 0x3f) << 8 | *m.get(at + 1)? as usize;
                }
                l if l <= 63 => {
                    let label = m.get(at + 1..at + 1 + l)?;
                    let dot = (n.len > 0) as usize;
                    if n.len + dot + l > MAX_NAME {
                        return None;
                    }
                    if dot == 1 {
                        n.b[n.len] = b'.';
                    }
                    for (d, c) in n.b[n.len + dot..].iter_mut().zip(label) {
                        *d = c.to_ascii_lowercase();
                    }
                    n.len += dot + l;
                    at += 1 + l;
                }
                _ => return None,
            }
        }
        None
    }

    /// Writes the name in wire form at `at`; returns where it ends.
    fn write(&self, m: &mut [u8], mut at: usize) -> usize {
        for label in self.as_bytes().split(|&c| c == b'.') {
            m[at] = label.len() as u8;
            m[at + 1..at + 1 + label.len()].copy_from_slice(label);
            at += 1 + label.len();
        }
        m[at] = 0;
        at + 1
    }
}

#[derive(Clone, Copy)]
struct Entry {
    name: Name,
    /// The address, or none: the name does not exist (or has no address).
    addr: Option<u32>,
    expires: u64,
}

/// How a query ended.
enum Answer {
    Address(u32, u64),
    NoSuchName,
    NoAnswer,
}

struct Resolver {
    /// The socket's handle; 0 when there is none.
    handle: u64,
    cache: [Option<Entry>; CACHE],
    next: usize,
    id: u16,
    /// A port on the gateway to ask instead (tests).
    port: u16,
}

/// A call to the network server lending `PAGE`; `None` if it was
/// restarted under the call.
fn net_call(m: [u64; 4]) -> Option<[u64; 4]> {
    let x = CapTransfer {
        grant: Some(PAGE as u16),
        accept: None,
    };
    let r = syscall_x(Syscall::Call, NET, m, x);
    (r.status == 0).then_some(r.msg)
}

impl Resolver {
    fn bind(&mut self) -> bool {
        syscall(Syscall::CapDelete, SOCKET, [0; 4]);
        let x = CapTransfer {
            grant: None,
            accept: Some(SOCKET as u16),
        };
        let r = syscall_x(Syscall::Call, NET, [net::UDP_BIND, 0, 0, 0], x);
        let ok = r.status == 0 && r.msg[0] == Status::Ok as u64 && r.cap == Some(SOCKET as u16);
        self.handle = if ok { r.msg[1] } else { 0 };
        ok
    }

    /// The DNS server to ask (as in `net::addr`), once the network server
    /// has a lease.
    fn server(&self) -> Option<u64> {
        let op = if self.port != 0 { net::INFO } else { net::LEASE };
        let r = syscall(Syscall::Call, NET, [op, net::VERSION, 0, 0]);
        if r.status != 0 || r.msg[0] != Status::Ok as u64 {
            return None;
        }
        Some(if self.port != 0 {
            r.msg[3] | self.port as u64
        } else {
            r.msg[2] | 53
        })
    }

    fn cached(&mut self, name: &Name) -> Option<Entry> {
        let now = ticks();
        self.cache
            .iter()
            .flatten()
            .find(|e| e.expires > now && e.name.as_bytes() == name.as_bytes())
            .copied()
    }

    fn remember(&mut self, name: &Name, addr: Option<u32>, ttl: u64) {
        if ttl == 0 {
            return;
        }
        let now = ticks();
        let slot = (0..CACHE)
            .find(|&i| {
                self.cache[i].is_none_or(|e| e.expires <= now || e.name.as_bytes() == name.as_bytes())
            })
            .unwrap_or_else(|| {
                self.next = (self.next + 1) % CACHE;
                self.next
            });
        self.cache[slot] = Some(Entry {
            name: *name,
            addr,
            expires: now + ttl.min(MAX_TTL) * SECOND,
        });
    }

    /// Asks the DNS server for `name`'s address.
    fn query(&mut self, name: &Name) -> Option<Answer> {
        for _ in 0..TRIES {
            let Some(server) = self.server() else {
                // No lease yet, or the network server is restarting.
                self.pause(SECOND / 10);
                continue;
            };
            if self.handle == 0 && !self.bind() {
                self.pause(SECOND / 10);
                continue;
            }
            self.id = self.id.wrapping_mul(25_173).wrapping_add(13_849) ^ ticks() as u16;
            let m = page(PAGE_VA);
            m[..12].fill(0);
            m[0..2].copy_from_slice(&self.id.to_be_bytes());
            m[2] = 0x01; // recursion desired
            m[5] = 1; // one question
            let end = name.write(m, 12);
            m[end..end + 4].copy_from_slice(&[0, TYPE_A as u8, 0, CLASS_IN as u8]);
            let len = end + 4;
            match net_call([net::SEND, self.handle, server, len as u64]) {
                Some(r) if r[0] == Status::Ok as u64 => {}
                Some(r) if r[0] == Status::NotFound as u64 => {
                    // The network server restarted: the socket is gone.
                    self.handle = 0;
                    continue;
                }
                _ => {
                    self.handle = 0;
                    self.pause(SECOND / 10);
                    continue;
                }
            }
            if let Some(a) = self.wait(server, name, ticks() + SECOND) {
                return Some(a);
            }
        }
        None
    }

    /// Waits until `deadline` for the answer to the query just sent.
    fn wait(&mut self, server: u64, name: &Name, deadline: u64) -> Option<Answer> {
        loop {
            loop {
                match net_call([net::RECV, self.handle, 0, 0]) {
                    Some(r) if r[0] == Status::Ok as u64 => {
                        if r[2] != server {
                            continue;
                        }
                        let len = (r[1] as usize).min(4096);
                        if let Some(a) = self.answer(&page(PAGE_VA)[..len], name) {
                            return Some(a);
                        }
                    }
                    Some(r) if r[0] == Status::Empty as u64 => break,
                    _ => {
                        self.handle = 0;
                        return None;
                    }
                }
            }
            let now = ticks();
            if now >= deadline {
                return None;
            }
            syscall(Syscall::TimerSignal, SOCKET, [deadline - now, 0, 0, 0]);
            if syscall(Syscall::Wait, SOCKET, [0; 4]).status != 0 {
                // The notification is gone: the network server restarted.
                self.handle = 0;
                return None;
            }
        }
    }

    /// Reads a response: `None` if it is not the answer to this query.
    fn answer(&self, m: &[u8], name: &Name) -> Option<Answer> {
        if m.len() < 12 || be16(m, 0) != self.id || m[2] & 0x80 == 0 || be16(m, 4) != 1 {
            return None;
        }
        let (q, mut at) = Name::read(m, 12)?;
        if q.as_bytes() != name.as_bytes() || be16(m, at) != TYPE_A || be16(m, at + 2) != CLASS_IN {
            return None;
        }
        at += 4;
        let rcode = be16(m, 2) & 0xf;
        if rcode == RCODE_NXDOMAIN {
            return Some(Answer::NoSuchName);
        }
        if rcode != 0 {
            return Some(Answer::NoAnswer);
        }
        // The answer records: (owner, type, TTL, where the data is, its
        // length), up to 16.
        let mut records = [(Name::EMPTY, 0u16, 0u32, 0usize, 0usize); 16];
        let count = (be16(m, 6) as usize).min(records.len());
        for r in records.iter_mut().take(count) {
            let (owner, end) = Name::read(m, at)?;
            if end + 10 > m.len() {
                return None;
            }
            let (kind, class) = (be16(m, end), be16(m, end + 2));
            let ttl = be32(m, end + 4);
            let len = be16(m, end + 8) as usize;
            if end + 10 + len > m.len() {
                return None;
            }
            if class == CLASS_IN {
                *r = (owner, kind, ttl, end + 10, len);
            }
            at = end + 10 + len;
        }
        // Follow CNAMEs from the name asked, whatever order they came in.
        let mut want = *name;
        let mut ttl = u32::MAX;
        for _ in 0..8 {
            let mut next = None;
            for (owner, kind, t, data, len) in &records[..count] {
                if owner.as_bytes() != want.as_bytes() {
                    continue;
                }
                match *kind {
                    TYPE_A if *len == 4 => {
                        return Some(Answer::Address(be32(m, *data), ttl.min(*t) as u64));
                    }
                    TYPE_CNAME => next = Name::read(m, *data).map(|(n, _)| (n, *t)),
                    _ => {}
                }
            }
            let (n, t) = next?;
            want = n;
            ttl = ttl.min(t);
        }
        Some(Answer::NoAnswer)
    }

    fn pause(&self, t: u64) {
        let end = ticks() + t;
        while ticks() < end {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
    }

    fn resolve(&mut self, m: [u64; 4], lent: bool) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        let len = m[2] as usize;
        if !lent || m[1] != dns::VERSION || len == 0 || len > MAX_NAME + 1 {
            return status(Status::Invalid);
        }
        if syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
            return status(Status::Invalid);
        }
        let name = Name::parse(&page(LENT_VA)[..len]);
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
        let Some(name) = name else {
            return status(Status::Invalid);
        };
        if let Some(e) = self.cached(&name) {
            let left = (e.expires - ticks()) / SECOND;
            return match e.addr {
                Some(a) => [Status::Ok as u64, (a as u64) << 16, left, 1],
                None => status(Status::NotFound),
            };
        }
        match self.query(&name) {
            Some(Answer::Address(a, ttl)) => {
                self.remember(&name, Some(a), ttl);
                [Status::Ok as u64, (a as u64) << 16, ttl.min(MAX_TTL), 0]
            }
            Some(Answer::NoSuchName) => {
                self.remember(&name, None, NEGATIVE_TTL);
                status(Status::NotFound)
            }
            Some(Answer::NoAnswer) => status(Status::NotFound),
            None => status(Status::Unreachable),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let made = syscall(Syscall::Retype, UNTYPED, [ObjectType::Frame as u64, 0, PAGE, 0]);
    if made.status != 0 || syscall(Syscall::FrameMap, PAGE, [PAGE_VA, 1, 0, 0]).status != 0 {
        say!("[fail] no page of its own");
        loop {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
    }
    let mut r = Resolver {
        handle: 0,
        cache: [None; CACHE],
        next: 0,
        id: ticks() as u16,
        port: arg as u16,
    };
    say!("ready");
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut call = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
    loop {
        let lent = call.cap == Some(LENT as u16);
        let reply = match call.msg[0] {
            dns::RESOLVE if call.status == 0 => r.resolve(call.msg, lent),
            _ => [Status::Invalid as u64, 0, 0, 0],
        };
        if lent {
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        call = syscall_x(Syscall::ReplyRecv, SERVICE, reply, accept);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
