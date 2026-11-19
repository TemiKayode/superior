//! Sockets: Linux's IPv4 TCP and UDP sockets, each one of the network
//! server's (`uses net` in the manifest), called with this server's own
//! buffer frame lent.
//!
//! The server never blocks: a call with nothing to give answers `Empty`,
//! and each socket's notification says when to look again. This server
//! waits on one notification only (bound to its thread), so it keeps a
//! socket's notification just to hold the socket, and a call that must
//! wait for one is tried again on every timer tick while any socket is
//! open ([`crate::wake`]).
//!
//! What has arrived and not yet been read is kept here, a page a socket
//! (TCP: what one `RECV` gave; UDP: one datagram), so `poll` can say a
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

pub const AF_INET: u64 = 2;
pub const SOCK_STREAM: u64 = 1;
pub const SOCK_DGRAM: u64 = 2;

pub const EAGAIN: u64 = 11;
pub const EINVAL: u64 = 22;
const ENOTSOCK: u64 = 88;
pub const EDESTADDRREQ: u64 = 89;
const EADDRINUSE: u64 = 98;
const ENETDOWN: u64 = 100;
const ENETUNREACH: u64 = 101;
const ECONNRESET: u64 = 104;
const ENOBUFS: u64 = 105;
pub const EISCONN: u64 = 106;
pub const ENOTCONN: u64 = 107;
const ETIMEDOUT: u64 = 110;
const ECONNREFUSED: u64 = 111;
const EHOSTUNREACH: u64 = 113;
pub const EINPROGRESS: u64 = 115;
pub const EPIPE: u64 = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Free,
    /// Made, with no socket at the server yet.
    New,
    /// A UDP socket at the server.
    Udp,
    /// A TCP connection being made.
    Connecting,
    /// A TCP connection.
    Tcp,
    Listening,
}

#[derive(Clone, Copy)]
pub struct Sock {
    pub phase: Phase,
    pub stream: bool,
    /// The server's handle.
    handle: u64,
    /// The local port: bound, or the server's choice (0: none yet).
    port: u16,
    /// The peer's address word (`net::addr`): connected to, or accepted
    /// from; 0 for none.
    pub peer: u64,
    /// What has arrived and not been read: `stash[at..len]`, from `from`.
    at: u16,
    len: u16,
    from: u64,
    /// The peer has sent all it will (TCP), or `SHUT_RD`.
    eof: bool,
    /// No more to send (`SHUT_WR`).
    shut: bool,
    /// An error to report (0: none): the connection's failure.
    error: u64,
    /// A listening socket's connection accepted from the server and not
    /// yet by the program: its socket, plus one (0: none).
    ready: u8,
}

const CLOSED: Sock = Sock {
    phase: Phase::Free,
    stream: false,
    handle: 0,
    port: 0,
    peer: 0,
    at: 0,
    len: 0,
    from: 0,
    eof: false,
    shut: false,
    error: 0,
    ready: 0,
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

/// A call whose reply grants socket `k`'s notification.
fn call_note(k: usize, m: [u64; 4]) -> Result<[u64; 4], u64> {
    let slot = NOTE + k as u64;
    syscall(Syscall::CapDelete, slot, [0; 4]);
    let r = syscall_x(Syscall::Call, NET, m, CapTransfer { grant: None, accept: Some(slot as u16) });
    match r.status {
        0 if r.msg[0] == Status::Ok as u64 => Ok(r.msg),
        0 => Err(errno(r.msg[0])),
        _ => Err(ENETDOWN),
    }
}

/// A new socket: its number.
pub fn socket(stream: bool) -> Result<usize, u64> {
    let t = table();
    let k = t.socks.iter().position(|s| s.phase == Phase::Free).ok_or(ENOBUFS)?;
    t.socks[k] = Sock { phase: Phase::New, stream, ..CLOSED };
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

/// `bind` to `port` (any address: there is one).
pub fn bind(k: usize, port: u16) -> Result<(), u64> {
    let s = get(k);
    if s.phase != Phase::New || s.port != 0 {
        return Err(EINVAL);
    }
    if s.stream {
        // TCP: the port is taken at `listen` (or used by nothing).
        table().socks[k].port = port;
        return Ok(());
    }
    let r = call_note(k, [net::UDP_BIND, port as u64, 0, 0])?;
    let s = &mut table().socks[k];
    (s.phase, s.handle, s.port) = (Phase::Udp, r[1], r[2] as u16);
    Ok(())
}

pub fn listen(k: usize) -> Result<(), u64> {
    let s = get(k);
    match s.phase {
        Phase::Listening => return Ok(()),
        Phase::New if s.stream => {}
        _ => return Err(EINVAL),
    }
    if s.port == 0 {
        return Err(EINVAL);
    }
    let r = call_note(k, [net::TCP_LISTEN, s.port as u64, 0, 0])?;
    let s = &mut table().socks[k];
    (s.phase, s.handle) = (Phase::Listening, r[1]);
    Ok(())
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
    let Ok(c) = socket(true) else { return false };
    match call_note(c, [net::TCP_ACCEPT, s.handle, 0, 0]) {
        Ok(r) => {
            let n = &mut table().socks[c];
            (n.phase, n.handle, n.port, n.peer) = (Phase::Tcp, r[1], s.port, r[2]);
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

/// `connect` to `to` (an address word): TCP answers `EINPROGRESS` until
/// the connection is made; the caller asks again.
pub fn connect(k: usize, to: u64) -> Result<(), u64> {
    let s = get(k);
    if !s.stream {
        if s.phase == Phase::New {
            bind(k, 0)?;
        }
        table().socks[k].peer = to;
        return Ok(());
    }
    match s.phase {
        Phase::New => {
            let r = call_note(k, [net::TCP_CONNECT, to, 0, 0]).map_err(|e| if e == EHOSTUNREACH { ENETUNREACH } else { e })?;
            let s = &mut table().socks[k];
            (s.phase, s.handle, s.port, s.peer) = (Phase::Connecting, r[1], r[2] as u16, to);
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

/// What has arrived, into the stash if it is empty.
fn fill(k: usize) {
    let s = get(k);
    if s.at < s.len || s.eof || s.error != 0 || !matches!(s.phase, Phase::Udp | Phase::Tcp) {
        return;
    }
    match call([net::RECV, s.handle, 0, 0]) {
        Ok(r) => {
            let n = (r[1] as usize).min(PAGE);
            let s = &mut table().socks[k];
            if n == 0 && s.stream {
                s.eof = true;
                return;
            }
            stash(k)[..n].copy_from_slice(&buf()[..n]);
            (s.at, s.len, s.from) = (0, n as u16, r[2]);
        }
        Err(EAGAIN) => {}
        Err(e) => _ = fail(k, e),
    }
}

/// Receives into `out`: the bytes and their sender, or `EAGAIN`. A
/// datagram longer than `out` loses the rest. `peek` leaves them.
pub fn recv(k: usize, out: &mut [u8], peek: bool) -> Result<(usize, u64), u64> {
    let s = get(k);
    match s.phase {
        Phase::Tcp | Phase::Udp => {}
        Phase::New if !s.stream => return Err(EAGAIN),
        _ => return Err(ENOTCONN),
    }
    fill(k);
    let s = &mut table().socks[k];
    if s.at < s.len {
        let have = &stash(k)[s.at as usize..s.len as usize];
        let n = have.len().min(out.len());
        out[..n].copy_from_slice(&have[..n]);
        if !peek {
            s.at = if s.stream { s.at + n as u16 } else { s.len };
        }
        return Ok((n, s.from));
    }
    if s.error != 0 {
        let e = s.error;
        s.error = 0;
        s.eof = true;
        return Err(e);
    }
    if s.eof {
        return Ok((0, s.peer));
    }
    Err(EAGAIN)
}

/// Sends `data` (a page at most) to `to` (UDP; 0: the connected peer):
/// the bytes taken, or `EAGAIN` if there is no room yet.
pub fn send(k: usize, data: &[u8], to: u64) -> Result<usize, u64> {
    let s = get(k);
    if s.error != 0 {
        table().socks[k].error = 0;
        return Err(s.error);
    }
    if s.stream {
        match s.phase {
            Phase::Tcp if s.shut => return Err(EPIPE),
            Phase::Tcp => {}
            _ => return Err(ENOTCONN),
        }
    } else if s.phase == Phase::New {
        bind(k, 0)?;
    }
    let to = if s.stream { 0 } else if to != 0 { to } else { get(k).peer };
    if !s.stream && to == 0 {
        return Err(EDESTADDRREQ);
    }
    let n = data.len().min(PAGE);
    buf()[..n].copy_from_slice(&data[..n]);
    match call([net::SEND, s.handle, to, n as u64]) {
        Ok(r) if s.stream => Ok(r[1] as usize),
        Ok(_) => Ok(n),
        Err(EAGAIN) => Err(EAGAIN),
        Err(e) if s.stream => Err(if e == ECONNRESET { EPIPE } else { fail(k, e) }),
        Err(e) => Err(e),
    }
}

/// `shutdown`: `how` 0 no more reading, 1 no more sending, 2 both.
pub fn shutdown(k: usize, how: u64) -> Result<(), u64> {
    let s = get(k);
    if how > 2 {
        return Err(EINVAL);
    }
    if s.phase != Phase::Tcp && s.stream || s.phase == Phase::New {
        return Err(ENOTCONN);
    }
    if how != 1 {
        table().socks[k].eof = true;
    }
    if how != 0 && s.stream && !s.shut {
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
        Phase::New => !s.stream,
        Phase::Udp | Phase::Tcp => true,
        // Made (or failed) yet?
        Phase::Connecting => !matches!(connect(k, s.peer), Err(EINPROGRESS)),
        Phase::Listening | Phase::Free => false,
    }
}

/// Failed (`POLLERR`).
pub fn failed(k: usize) -> bool {
    get(k).error != 0
}

/// The socket's own address word: this host's address and its port.
pub fn name(k: usize) -> u64 {
    let ip = call([net::INFO, net::VERSION, 0, 0]).map_or(0, |r| r[1] >> 16);
    ip << 16 | get(k).port as u64
}

/// The peer's address word, `ENOTCONN` if none.
pub fn peer(k: usize) -> Result<u64, u64> {
    let s = get(k);
    if s.peer == 0 || s.phase == Phase::Connecting {
        return Err(ENOTCONN);
    }
    Ok(s.peer)
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
