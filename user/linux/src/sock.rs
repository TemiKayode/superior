//! Sockets: Linux's TCP, UDP and ping (ICMP echo) sockets, over IPv4 and
//! IPv6, each one of the network server's (`uses net` in the manifest),
//! called with this server's own buffer frame lent.
//!
//! Addresses are kept as IPv6's 16 bytes, an IPv4 address in its mapped
//! form (`::ffff:a.b.c.d`), which the server takes for either family:
//! datagrams go with `SEND6` and come with `RECV6`, connections are made
//! with `TCP_CONNECT6` and their peers asked with `TCP_PEER`.
//!
//! A ping socket (`SOCK_DGRAM`, `IPPROTO_ICMP` or `IPPROTO_ICMPV6`) is the
//! server's ICMP echo socket: the program sends an echo request's header
//! and payload, and the server is given the payload, with the request's
//! sequence number; a reply comes back with an echo reply's header made
//! for it here.
//!
//! The server never blocks: a call with nothing to give answers `Empty`,
//! and each socket's notification says when to look again. This server
//! waits on one notification only (bound to its thread), so it keeps a
//! socket's notification just to hold the socket, and a call that must
//! wait for one is tried again on every timer tick while any socket is
//! open ([`crate::wake`]).
//!
//! What has arrived and not yet been read is kept here, a page a socket
//! (TCP: what one `RECV` gave; a datagram otherwise), so `poll` can say a
//! socket is readable without losing what it found; the same goes for a
//! connection a listening socket has ready.

use superior_objects::abi::{CapTransfer, Syscall};
use superior_objects::interfaces::{Status, net};
use superior_sys::{USER_BASE, syscall, syscall_x};

/// The network service (`uses net` in the manifest).
pub const NET: u64 = 7;
/// The buffer frame lent with every call, and where it is mapped here.
pub const BUF: u64 = 1009;
pub const BUF_VA: u64 = USER_BASE + 0x1_6000_1000;
/// Socket `k`'s notification from the server, in slot `NOTE + k`.
const NOTE: u64 = 960;
/// Socket `k`'s stash page, in slot `STASH + k` (made from the state's
/// block by [`crate::setup`]), mapped at `STASH_VA` + `k` pages.
pub const STASH: u64 = 976;
pub const STASH_VA: u64 = USER_BASE + 0x1_6010_0000;
/// Sockets open at once, across every process.
pub const MAX: usize = 16;
const PAGE: usize = 4096;
/// An ICMP echo message's header: type, code, checksum, identifier and
/// sequence number.
const ECHO_HEADER: usize = 8;

pub const AF_INET: u64 = 2;
pub const AF_INET6: u64 = 10;
pub const SOCK_STREAM: u64 = 1;
pub const SOCK_DGRAM: u64 = 2;

pub const EPIPE: u64 = 32;
pub const EAGAIN: u64 = 11;
pub const EINVAL: u64 = 22;
const ENOTSOCK: u64 = 88;
const EDESTADDRREQ: u64 = 89;
const EADDRINUSE: u64 = 98;
const ENETDOWN: u64 = 100;
const ENETUNREACH: u64 = 101;
const ECONNRESET: u64 = 104;
const ENOBUFS: u64 = 105;
const EISCONN: u64 = 106;
const ENOTCONN: u64 = 107;
const ETIMEDOUT: u64 = 110;
const ECONNREFUSED: u64 = 111;
const EHOSTUNREACH: u64 = 113;
pub const EINPROGRESS: u64 = 115;

/// What a socket carries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    /// ICMP echo (ping).
    Echo,
}

/// An address and port, the address as IPv6's 16 bytes (an IPv4 one
/// mapped).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Addr {
    pub ip: [u8; 16],
    pub port: u16,
}

impl Addr {
    pub const NONE: Addr = Addr { ip: [0; 16], port: 0 };

    /// IPv4 address `ip` (its first byte the most significant), mapped.
    pub const fn v4(ip: [u8; 4], port: u16) -> Addr {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12] = ip[0];
        a[13] = ip[1];
        a[14] = ip[2];
        a[15] = ip[3];
        Addr { ip: a, port }
    }

    /// The IPv4 address, if it is one (mapped).
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        let mapped = self.ip[..10].iter().all(|&b| b == 0) && self.ip[10] == 0xff && self.ip[11] == 0xff;
        mapped.then(|| [self.ip[12], self.ip[13], self.ip[14], self.ip[15]])
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Free,
    /// Made, with no socket at the server yet.
    New,
    /// A UDP or ping socket at the server.
    Dgram,
    /// A TCP connection being made.
    Connecting,
    /// A TCP connection.
    Tcp,
    Listening,
}

#[derive(Clone, Copy)]
pub struct Sock {
    pub phase: Phase,
    pub proto: Proto,
    /// The family it was made for (`AF_INET` or `AF_INET6`): how its
    /// addresses are given.
    pub family: u64,
    /// The server's handle.
    handle: u64,
    /// The local port: bound, or the server's choice (0: none yet).
    port: u16,
    /// The peer: connected to, or accepted from.
    pub peer: Option<Addr>,
    /// What has arrived and not been read: `stash[at..len]`, from `from`;
    /// `full` the datagram's whole length.
    at: u16,
    len: u16,
    full: u32,
    from: Addr,
    /// The peer has sent all it will (TCP), or `SHUT_RD`.
    eof: bool,
    /// No more to send (`SHUT_WR`).
    shut: bool,
    /// An error to report (0: none): the connection's failure.
    error: u64,
    /// A listening socket's connection accepted from the server and not
    /// yet by the program: its socket, plus one (0: none).
    ready: u8,
    /// A ping socket's identifier, as the program last sent it: its
    /// replies carry it back.
    echo_id: u16,
}

const CLOSED: Sock = Sock {
    phase: Phase::Free,
    proto: Proto::Tcp,
    family: AF_INET,
    handle: 0,
    port: 0,
    peer: None,
    at: 0,
    len: 0,
    full: 0,
    from: Addr::NONE,
    eof: false,
    shut: false,
    error: 0,
    ready: 0,
    echo_id: 0,
};

struct Table {
    socks: [Sock; MAX],
}

static mut TABLE: Table = Table { socks: [CLOSED; MAX] };

fn table() -> &'static mut Table {
    // SAFETY: this server is single-threaded, and no reference returned
    // is kept across another call of this.
    unsafe { &mut *(&raw mut TABLE) }
}

/// Socket `k`'s stash page.
fn stash(k: usize) -> &'static mut [u8; PAGE] {
    // SAFETY: mapped at start for this server's life; single-threaded,
    // and no reference is kept across another call of this.
    unsafe { &mut *((STASH_VA + (k * PAGE) as u64) as *mut [u8; PAGE]) }
}

pub fn get(k: usize) -> Sock {
    table().socks[k]
}

fn buf() -> &'static mut [u8; PAGE] {
    // SAFETY: the buffer frame is mapped at BUF_VA for this server's life.
    unsafe { &mut *(BUF_VA as *mut [u8; PAGE]) }
}

/// Any socket open: calls waiting on sockets are tried each tick.
pub fn any_open() -> bool {
    table().socks.iter().any(|s| s.phase != Phase::Free)
}

/// Linux's error for a status.
fn errno(status: u64) -> u64 {
    match status {
        s if s == Status::Empty as u64 => EAGAIN,
        s if s == Status::InUse as u64 => EADDRINUSE,
        s if s == Status::NoSpace as u64 => ENOBUFS,
        s if s == Status::Unreachable as u64 => EHOSTUNREACH,
        s if s == Status::Refused as u64 => ECONNREFUSED,
        s if s == Status::TimedOut as u64 => ETIMEDOUT,
        s if s == Status::Invalid as u64 => EINVAL,
        // Reset, or a handle the server no longer knows (it restarted).
        _ => ECONNRESET,
    }
}

/// A call lending the buffer: the reply's words, or Linux's error (no
/// network service: `ENETDOWN`).
fn call(m: [u64; 4]) -> Result<[u64; 4], u64> {
    let r = syscall_x(Syscall::Call, NET, m, CapTransfer { grant: Some(BUF as u16), accept: None });
    match r.status {
        0 if r.msg[0] == Status::Ok as u64 => Ok(r.msg),
        0 => Err(errno(r.msg[0])),
        _ => Err(ENETDOWN),
    }
}

/// A call whose reply grants socket `k`'s notification, lending the
/// buffer when `lend` (for an address in it).
fn call_note(k: usize, m: [u64; 4], lend: bool) -> Result<[u64; 4], u64> {
    let slot = NOTE + k as u64;
    syscall(Syscall::CapDelete, slot, [0; 4]);
    let grant = lend.then_some(BUF as u16);
    let r = syscall_x(Syscall::Call, NET, m, CapTransfer { grant, accept: Some(slot as u16) });
    match r.status {
        0 if r.msg[0] == Status::Ok as u64 => Ok(r.msg),
        0 => Err(errno(r.msg[0])),
        _ => Err(ENETDOWN),
    }
}

/// A new socket: its number.
pub fn socket(family: u64, proto: Proto) -> Result<usize, u64> {
    let t = table();
    let k = t.socks.iter().position(|s| s.phase == Phase::Free).ok_or(ENOBUFS)?;
    t.socks[k] = Sock { phase: Phase::New, proto, family, ..CLOSED };
    Ok(k)
}

/// Closes socket `k` (and a connection it had ready to accept).
pub fn close(k: usize) {
    let s = get(k);
    if s.ready != 0 {
        close(s.ready as usize - 1);
    }
    if !matches!(s.phase, Phase::Free | Phase::New) {
        let _ = call([net::CLOSE, s.handle, 0, 0]);
    }
    syscall(Syscall::CapDelete, NOTE + k as u64, [0; 4]);
    table().socks[k] = CLOSED;
}

/// A UDP or ping socket's own at the server, made on `port` (UDP; 0:
/// any) if it has none yet.
fn open_dgram(k: usize, port: u16) -> Result<(), u64> {
    let s = get(k);
    if s.phase != Phase::New {
        return Ok(());
    }
    let r = match s.proto {
        Proto::Udp => call_note(k, [net::UDP_BIND, port as u64, 0, 0], false)?,
        Proto::Echo => call_note(k, [net::ICMP_BIND, 0, 0, 0], false)?,
        Proto::Tcp => return Err(EINVAL),
    };
    let s = &mut table().socks[k];
    (s.phase, s.handle, s.port) = (Phase::Dgram, r[1], r[2] as u16);
    Ok(())
}

/// `bind` to `port` (any address: there is one of each family).
pub fn bind(k: usize, port: u16) -> Result<(), u64> {
    let s = get(k);
    if s.phase != Phase::New || s.port != 0 {
        return Err(EINVAL);
    }
    match s.proto {
        // TCP: the port is taken at `listen` (or used by nothing).
        Proto::Tcp => {
            table().socks[k].port = port;
            Ok(())
        }
        _ => open_dgram(k, port),
    }
}

pub fn listen(k: usize) -> Result<(), u64> {
    let s = get(k);
    match s.phase {
        Phase::Listening => return Ok(()),
        Phase::New if s.proto == Proto::Tcp => {}
        _ => return Err(EINVAL),
    }
    if s.port == 0 {
        return Err(EINVAL);
    }
    let r = call_note(k, [net::TCP_LISTEN, s.port as u64, 0, 0], false)?;
    let s = &mut table().socks[k];
    (s.phase, s.handle) = (Phase::Listening, r[1]);
    Ok(())
}

/// A connection's peer, from the server.
fn tcp_peer(handle: u64) -> Option<Addr> {
    let r = call([net::TCP_PEER, handle, 0, 0]).ok()?;
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&buf()[..16]);
    Some(Addr { ip, port: r[1] as u16 })
}

/// A listening socket's next connection taken from the server, kept in
/// `ready`: whether there is one.
fn take_ready(k: usize) -> bool {
    let s = get(k);
    if s.phase != Phase::Listening {
        return false;
    }
    if s.ready != 0 {
        return true;
    }
    let Ok(c) = socket(s.family, Proto::Tcp) else { return false };
    match call_note(c, [net::TCP_ACCEPT, s.handle, 0, 0], false) {
        Ok(r) => {
            let peer = tcp_peer(r[1]);
            let n = &mut table().socks[c];
            (n.phase, n.handle, n.port, n.peer) = (Phase::Tcp, r[1], s.port, peer);
            table().socks[k].ready = c as u8 + 1;
            true
        }
        Err(_) => {
            table().socks[c] = CLOSED;
            false
        }
    }
}

/// `accept`: the next connection's socket, `EAGAIN` if none is waiting.
pub fn accept(k: usize) -> Result<usize, u64> {
    if get(k).phase != Phase::Listening {
        return Err(EINVAL);
    }
    if !take_ready(k) {
        return Err(EAGAIN);
    }
    let c = get(k).ready as usize - 1;
    table().socks[k].ready = 0;
    Ok(c)
}

/// `connect` to `to`: TCP answers `EINPROGRESS` until the connection is
/// made; the caller asks again.
pub fn connect(k: usize, to: Addr) -> Result<(), u64> {
    let s = get(k);
    if s.proto != Proto::Tcp {
        open_dgram(k, 0)?;
        table().socks[k].peer = Some(to);
        return Ok(());
    }
    match s.phase {
        Phase::New => {
            buf()[..16].copy_from_slice(&to.ip);
            let r = call_note(k, [net::TCP_CONNECT6, to.port as u64, 0, 0], true)
                .map_err(|e| if e == EHOSTUNREACH { ENETUNREACH } else { e })?;
            let s = &mut table().socks[k];
            (s.phase, s.handle, s.port, s.peer) = (Phase::Connecting, r[1], r[2] as u16, Some(to));
            Err(EINPROGRESS)
        }
        Phase::Connecting => match call([net::TCP_STATE, s.handle, 0, 0]) {
            Ok(r) if r[1] == net::TCP_SYN_SENT || r[1] == net::TCP_SYN_RECEIVED => Err(EINPROGRESS),
            Ok(r) if r[1] != net::TCP_CLOSED => {
                table().socks[k].phase = Phase::Tcp;
                Ok(())
            }
            // Failed: `RECV` says why.
            Ok(_) => Err(fail(k, call([net::RECV, s.handle, 0, 0]).err().unwrap_or(ECONNREFUSED))),
            Err(e) => Err(fail(k, e)),
        },
        Phase::Tcp => Err(EISCONN),
        _ => Err(EINVAL),
    }
}

/// Socket `k`'s connection failed with `e`: it stays so (`e`).
fn fail(k: usize, e: u64) -> u64 {
    let s = &mut table().socks[k];
    if s.phase == Phase::Connecting {
        s.phase = Phase::Tcp;
    }
    s.error = e;
    e
}

/// The Internet checksum of `bytes` (RFC 1071).
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// What has arrived, into the stash if it is empty.
fn fill(k: usize) {
    let s = get(k);
    if s.at < s.len || s.eof || s.error != 0 || !matches!(s.phase, Phase::Dgram | Phase::Tcp) {
        return;
    }
    if s.proto == Proto::Tcp {
        match call([net::RECV, s.handle, 0, 0]) {
            Ok(r) => {
                let n = (r[1] as usize).min(PAGE);
                let s = &mut table().socks[k];
                if n == 0 {
                    s.eof = true;
                    return;
                }
                stash(k)[..n].copy_from_slice(&buf()[..n]);
                (s.at, s.len, s.full, s.from) = (0, n as u16, n as u32, s.peer.unwrap_or(Addr::NONE));
            }
            Err(EAGAIN) => {}
            Err(e) => _ = fail(k, e),
        }
        return;
    }
    // A datagram: the sender's address, then the payload.
    match call([net::RECV6, s.handle, 0, 0]) {
        Ok(r) => {
            let b = buf();
            let mut from = Addr { ip: [0; 16], port: r[2] as u16 };
            from.ip.copy_from_slice(&b[..16]);
            let n = (r[1] as usize).min(PAGE - 16);
            let payload = &b[16..16 + n];
            let out = stash(k);
            let (len, full) = if s.proto == Proto::Echo {
                // An echo reply: the sequence number came as the port.
                let n = n.min(PAGE - ECHO_HEADER);
                let reply = if from.ipv4().is_some() { 0 } else { 129 };
                out[..ECHO_HEADER].copy_from_slice(&[reply, 0, 0, 0, 0, 0, 0, 0]);
                out[4..6].copy_from_slice(&s.echo_id.to_be_bytes());
                out[6..8].copy_from_slice(&from.port.to_be_bytes());
                out[ECHO_HEADER..ECHO_HEADER + n].copy_from_slice(&payload[..n]);
                let c = checksum(&out[..ECHO_HEADER + n]);
                out[2..4].copy_from_slice(&c.to_be_bytes());
                from.port = 0;
                (ECHO_HEADER + n, ECHO_HEADER as u32 + r[1] as u32)
            } else {
                out[..n].copy_from_slice(payload);
                (n, r[1] as u32)
            };
            let s = &mut table().socks[k];
            (s.at, s.len, s.full, s.from) = (0, len as u16, full, from);
        }
        Err(EAGAIN) => {}
        Err(e) => _ = fail(k, e),
    }
}

/// What a receive gave: the bytes copied, the datagram's whole length
/// (more than copied: the rest is lost), and the sender.
pub struct Got {
    pub n: usize,
    pub full: usize,
    pub from: Addr,
}

/// Receives into `out`, or `EAGAIN`. A datagram longer than `out` loses
/// the rest. `peek` leaves them.
pub fn recv(k: usize, out: &mut [u8], peek: bool) -> Result<Got, u64> {
    let s = get(k);
    match s.phase {
        Phase::Tcp | Phase::Dgram => {}
        Phase::New if s.proto != Proto::Tcp => return Err(EAGAIN),
        _ => return Err(ENOTCONN),
    }
    fill(k);
    let s = &mut table().socks[k];
    if s.at < s.len {
        let have = &stash(k)[s.at as usize..s.len as usize];
        let n = have.len().min(out.len());
        out[..n].copy_from_slice(&have[..n]);
        let full = if s.proto == Proto::Tcp { n } else { s.full as usize };
        if !peek {
            s.at = if s.proto == Proto::Tcp { s.at + n as u16 } else { s.len };
        }
        return Ok(Got { n, full, from: s.from });
    }
    if s.error != 0 {
        let e = s.error;
        s.error = 0;
        s.eof = true;
        return Err(e);
    }
    if s.eof {
        return Ok(Got { n: 0, full: 0, from: s.peer.unwrap_or(Addr::NONE) });
    }
    Err(EAGAIN)
}

/// Sends `data` (a page at most) to `to` (datagrams; `None`: the
/// connected peer): the bytes taken, or `EAGAIN` if there is no room yet.
pub fn send(k: usize, data: &[u8], to: Option<Addr>) -> Result<usize, u64> {
    let s = get(k);
    if s.error != 0 {
        table().socks[k].error = 0;
        return Err(s.error);
    }
    if s.proto == Proto::Tcp {
        match s.phase {
            Phase::Tcp if s.shut => return Err(EPIPE),
            Phase::Tcp => {}
            _ => return Err(ENOTCONN),
        }
        let n = data.len().min(PAGE);
        buf()[..n].copy_from_slice(&data[..n]);
        return match call([net::SEND, s.handle, 0, n as u64]) {
            Ok(r) => Ok(r[1] as usize),
            Err(EAGAIN) => Err(EAGAIN),
            Err(ECONNRESET) => Err(EPIPE),
            Err(e) => Err(fail(k, e)),
        };
    }
    open_dgram(k, 0)?;
    let s = get(k);
    let mut to = to.or(s.peer).ok_or(EDESTADDRREQ)?;
    let b = buf();
    b[..16].copy_from_slice(&to.ip);
    let payload = if s.proto == Proto::Echo {
        // An echo request: its payload to the server, its sequence number
        // in place of the port, its identifier kept for the reply.
        let request = if to.ipv4().is_some() { 8 } else { 128 };
        if data.len() < ECHO_HEADER || data[0] != request || data[1] != 0 {
            return Err(EINVAL);
        }
        table().socks[k].echo_id = u16::from_be_bytes([data[4], data[5]]);
        to.port = u16::from_be_bytes([data[6], data[7]]);
        &data[ECHO_HEADER..]
    } else {
        data
    };
    let n = payload.len().min(PAGE - 16);
    b[16..16 + n].copy_from_slice(&payload[..n]);
    call([net::SEND6, s.handle, to.port as u64, n as u64])?;
    Ok(data.len() - payload.len() + n)
}

/// `shutdown`: `how` 0 no more reading, 1 no more sending, 2 both.
pub fn shutdown(k: usize, how: u64) -> Result<(), u64> {
    let s = get(k);
    if how > 2 {
        return Err(EINVAL);
    }
    if s.phase != Phase::Tcp && s.proto == Proto::Tcp || s.phase == Phase::New {
        return Err(ENOTCONN);
    }
    if how != 1 {
        table().socks[k].eof = true;
    }
    if how != 0 && s.proto == Proto::Tcp && !s.shut {
        table().socks[k].shut = true;
        call([net::TCP_SHUTDOWN, s.handle, 0, 0])?;
    }
    Ok(())
}

/// Ready to read (or at its end, or failed): for `poll`.
pub fn readable(k: usize) -> bool {
    if get(k).phase == Phase::Listening {
        return take_ready(k);
    }
    fill(k);
    let s = get(k);
    s.at < s.len || s.eof || s.error != 0
}

/// Ready to send to.
pub fn writable(k: usize) -> bool {
    let s = get(k);
    match s.phase {
        Phase::New => s.proto != Proto::Tcp,
        Phase::Dgram | Phase::Tcp => true,
        // Made (or failed) yet?
        Phase::Connecting => !matches!(connect(k, Addr::NONE), Err(EINPROGRESS)),
        Phase::Listening | Phase::Free => false,
    }
}

/// Failed (`POLLERR`).
pub fn failed(k: usize) -> bool {
    get(k).error != 0
}

/// The socket's own address: this host's (of the socket's family) and
/// its port (a ping socket's identifier).
pub fn name(k: usize) -> Addr {
    let s = get(k);
    if s.family == AF_INET6 {
        // INFO6: link-local, then global, address.
        let mut a = Addr { ip: [0; 16], port: s.port };
        if call([net::INFO6, net::VERSION, 0, 0]).is_ok() {
            a.ip.copy_from_slice(&buf()[16..32]);
        }
        return a;
    }
    let ip = call([net::INFO, net::VERSION, 0, 0]).map_or(0, |r| (r[1] >> 16) as u32);
    Addr::v4(ip.to_be_bytes(), s.port)
}

/// The peer, `ENOTCONN` if none.
pub fn peer(k: usize) -> Result<Addr, u64> {
    let s = get(k);
    if s.phase == Phase::Connecting {
        return Err(ENOTCONN);
    }
    s.peer.ok_or(ENOTCONN)
}

/// A pending error, cleared (`SO_ERROR`).
pub fn take_error(k: usize) -> u64 {
    let e = get(k).error;
    if get(k).phase != Phase::Connecting {
        table().socks[k].error = 0;
    }
    e
}

/// Not a socket at all.
pub const NOT_A_SOCKET: u64 = ENOTSOCK;
