//! Unix domain sockets (`AF_UNIX`, `SOCK_STREAM`): between this server's
//! own processes, so here rather than in the network server. A socket is
//! named by a path or, its first byte 0, an abstract name, kept here alone
//! (no file is made for it). Connecting to a listening socket makes its
//! other end, which waits to be accepted; a connected socket's bytes go to
//! its peer's buffer, and with them, in place, open files (`SCM_RIGHTS`),
//! which the peer's `recvmsg` takes as new descriptors.
//!
//! What the descriptors in flight refer to, and opening and closing files,
//! are the server's ([`crate::State`]): this module keeps the sockets.

/// Sockets at once, the bytes a socket's buffer holds, messages with
/// descriptors in flight to a socket, and descriptors a message carries.
pub const MAX_UNIX: usize = 16;
pub const BUF: usize = 2048;
pub const MAX_RIGHTS: usize = 8;
pub const RIGHTS_FDS: usize = 8;
/// The longest name (`sun_path`).
pub const NAME_MAX: usize = 108;
/// Connections waiting to be accepted.
pub const BACKLOG: usize = 8;

pub const AF_UNIX: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Free = 0,
    /// Made, perhaps named (bound).
    New,
    Listening,
    Connected,
}

/// Descriptors sent with the byte at stream offset `at`: open files
/// (indices into the server's), each holding a reference.
#[derive(Clone, Copy)]
pub struct Rights {
    pub at: u64,
    pub n: u8,
    pub files: [u8; RIGHTS_FDS],
}

pub struct Unix {
    pub phase: Phase,
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    /// The other end (its index + 1), while it is open.
    pub peer: u8,
    /// No more bytes will come (the peer shut its writing down, or
    /// closed); writing is refused (`EPIPE`) once the peer has closed.
    pub eof: bool,
    pub broken: bool,
    /// The process that made it, and its peer's when they were joined
    /// (`SO_PEERCRED`, which holds after the peer has gone).
    pub pid: u32,
    pub peer_pid: u32,
    pub backlog: [u8; BACKLOG],
    pub nback: u8,
    pub buf: [u8; BUF],
    pub head: usize,
    pub len: usize,
    /// Bytes read from the buffer so far: the next byte's stream offset.
    pub read: u64,
    pub rights: [Rights; MAX_RIGHTS],
    pub nrights: usize,
}

impl Unix {
    /// Empties it, for reuse.
    pub fn reset(&mut self, pid: u32) {
        self.phase = Phase::New;
        self.name_len = 0;
        self.peer = 0;
        self.eof = false;
        self.broken = false;
        self.pid = pid;
        self.peer_pid = 0;
        self.nback = 0;
        self.head = 0;
        self.len = 0;
        self.read = 0;
        self.nrights = 0;
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Room for bytes.
    pub fn room(&self) -> usize {
        BUF - self.len
    }

    /// Appends as many of `data` as there is room for, with `rights` (if
    /// any) at the first of them; how many, or `None` if there is no room
    /// for the rights.
    pub fn put(&mut self, data: &[u8], rights: Option<(u8, [u8; RIGHTS_FDS])>) -> Option<usize> {
        let n = data.len().min(self.room());
        if let Some((count, files)) = rights {
            if self.nrights == MAX_RIGHTS || n == 0 {
                return None;
            }
            self.rights[self.nrights] = Rights { at: self.read + self.len as u64, n: count, files };
            self.nrights += 1;
        }
        for (k, &b) in data[..n].iter().enumerate() {
            self.buf[(self.head + self.len + k) % BUF] = b;
        }
        self.len += n;
        Some(n)
    }

    /// Copies bytes into `out` without taking them, up to the next
    /// message that carries descriptors.
    pub fn peek(&self, out: &mut [u8]) -> usize {
        let next = self.rights[..self.nrights].iter().map(|r| r.at).find(|&at| at > self.read);
        let limit = next.map_or(self.len, |at| (at - self.read) as usize);
        let n = out.len().min(limit).min(self.len);
        for (k, b) in out[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head + k) % BUF];
        }
        n
    }

    /// Takes bytes into `out`, up to the next message that carries
    /// descriptors; and the descriptors that came with the first byte
    /// taken, if any (the caller gives or closes them).
    pub fn take(&mut self, out: &mut [u8]) -> (usize, Option<Rights>) {
        let mut rights = None;
        if self.nrights > 0 && self.rights[0].at == self.read {
            rights = Some(self.rights[0]);
            self.rights.copy_within(1..self.nrights, 0);
            self.nrights -= 1;
        }
        let limit = if self.nrights > 0 { (self.rights[0].at - self.read) as usize } else { self.len };
        let n = out.len().min(limit).min(self.len);
        for (k, b) in out[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head + k) % BUF];
        }
        self.head = (self.head + n) % BUF;
        self.len -= n;
        self.read += n as u64;
        (n, rights)
    }
}
