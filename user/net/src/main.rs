//! The network server: IPv4 over Ethernet with ARP, ICMP echo and UDP,
//! serving the `net` interface (`superior_objects::interfaces::net`) to
//! clients and using a NIC driver through the `nic` interface.
//!
//! It is crash-only. Its state is the ARP cache, the frames waiting for
//! an ARP answer and the sockets with their queued datagrams; a restart
//! loses all of it, which the interface allows: datagrams are unreliable,
//! and each socket's notification belongs to this server, so its deletion
//! wakes a waiting client to bind again.
//!
//! One thread serves everything. Its notification is bound to it, so one
//! `Recv` waits for client calls, for the driver's "frames are waiting"
//! (the driver holds a copy badged [`RX`]) and for a kernel timer (a copy
//! badged [`TIMER`], set with `TimerSignal` every [`PERIOD`] ticks). On the
//! timer it also drains the driver, which reattaches after the driver was
//! restarted (a restarted driver has lost the notification and says so),
//! and resends ARP requests that got no answer.
//!
//! The address is fixed for now: 10.0.2.15/24 with the gateway at
//! 10.0.2.2, QEMU's user-mode network.
//!
//! Slots: 0 the `nic` endpoint, 1 the `net` endpoint (receive), 2 untyped
//! memory (64 KiB).

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::interfaces::{Status, net, nic};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const NIC: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 2;
/// This thread's notification, bound to it.
const SELF: u64 = 3;
/// A copy of it badged TIMER, for `TimerSignal`.
const TIMER_CAP: u64 = 4;
/// A capability being granted.
const MINT: u64 = 5;
/// The page lent to the driver to receive into, and the one frames are
/// built in to send.
const RX_FRAME: u64 = 6;
const TX_FRAME: u64 = 7;
/// Where a client's page arrives.
const LENT: u64 = 8;
/// Socket `i`'s notification.
const SOCK_NTFN: u64 = 9;

const RX_VA: u64 = USER_BASE + 0x4000_0000;
const TX_VA: u64 = RX_VA + 0x1000;
const LENT_VA: u64 = RX_VA + 0x2000;

/// Badges on this thread's notification.
const RX: u64 = 1;
const TIMER: u64 = 2;
/// Ticks between timer wakeups (100 ms).
const PERIOD: u64 = 10;
/// Timer periods an unanswered ARP request is repeated before the frames
/// waiting on it are dropped.
const ARP_TRIES: u8 = 10;

const READ: u64 = 1;
const WRITE: u64 = 2;

const IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const NETMASK: u32 = 0xffff_ff00;

const SOCKETS: usize = 8;
/// Datagrams a socket keeps until they are received.
const QUEUE: usize = 4;
const ARP_CACHE: usize = 8;
const WAITING: usize = 4;
const MAX_FRAME: usize = nic::MAX_FRAME as usize;
const MAX_PAYLOAD: usize = net::MAX_PAYLOAD as usize;

const ETH_ARP: u16 = 0x0806;
const ETH_IP: u16 = 0x0800;
const PROTO_ICMP: u8 = 1;
const PROTO_UDP: u8 = 17;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO: u8 = 8;
/// Ephemeral ports for `UDP_BIND` with port 0.
const EPHEMERAL: u16 = 49152;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("net: {}", format_args!($($t)*))) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Udp(u16),
    /// ICMP echo, by identifier.
    Icmp(u16),
}

#[derive(Clone, Copy)]
struct Datagram {
    len: u16,
    from: u64,
    data: [u8; MAX_PAYLOAD],
}

struct Socket {
    kind: Kind,
    /// The client's badge.
    owner: u64,
    handle: u64,
    queue: [Datagram; QUEUE],
    head: usize,
    count: usize,
    dropped: u64,
}

#[derive(Clone, Copy)]
struct Waiting {
    /// The next hop whose MAC address the frame waits for.
    hop: u32,
    len: u16,
    tries: u8,
    frame: [u8; MAX_FRAME],
}

struct Net {
    mac: [u8; 6],
    arp: [Option<(u32, [u8; 6])>; ARP_CACHE],
    arp_next: usize,
    waiting: [Option<Waiting>; WAITING],
    sockets: [Option<Socket>; SOCKETS],
    /// Handles carry this, so an old instance's handles do not match.
    epoch: u64,
    next_id: u16,
    need_attach: bool,
    received: u64,
    sent: u64,
}

const EMPTY: Datagram = Datagram {
    len: 0,
    from: 0,
    data: [0; MAX_PAYLOAD],
};

static mut NET: Net = Net {
    mac: [0; 6],
    arp: [None; ARP_CACHE],
    arp_next: 0,
    waiting: [None; WAITING],
    sockets: [const { None }; SOCKETS],
    epoch: 0,
    next_id: 0,
    need_attach: true,
    received: 0,
    sent: 0,
};

fn ip_u32(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes(ip)
}

fn page(va: u64) -> &'static mut [u8] {
    // SAFETY: each page this is called for is mapped for good (RX, TX) or
    // while a client's page is mapped (LENT).
    unsafe { core::slice::from_raw_parts_mut(va as *mut u8, 4096) }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// The Internet checksum's running sum of `b` (RFC 1071).
fn sum(mut acc: u32, b: &[u8]) -> u32 {
    for pair in b.chunks(2) {
        acc += (pair[0] as u32) << 8 | pair.get(1).copied().unwrap_or(0) as u32;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The UDP checksum's pseudo-header sum.
fn pseudo(src: u32, dst: u32, proto: u8, len: usize) -> u32 {
    let mut b = [0u8; 12];
    put32(&mut b, 0, src);
    put32(&mut b, 4, dst);
    b[9] = proto;
    put16(&mut b, 10, len as u16);
    sum(0, &b)
}

/// Calls the driver, lending `frame`; tries again if it was restarted.
fn nic_call(m: [u64; 4], frame: u64) -> Option<[u64; 4]> {
    let x = CapTransfer {
        grant: Some(frame as u16),
        accept: None,
    };
    for _ in 0..3 {
        let r = syscall_x(Syscall::Call, NIC, m, x);
        if r.status == 0 {
            return Some(r.msg);
        }
        if r.status != Error::PeerRestarted.code() {
            break;
        }
    }
    None
}

impl Net {
    /// Gives the driver a copy of this thread's notification, badged RX.
    fn attach(&mut self) {
        syscall(Syscall::CapDelete, MINT, [0; 4]);
        if syscall(Syscall::CapMint, SELF, [MINT, WRITE, RX, 0]).status != 0 {
            return;
        }
        let x = CapTransfer {
            grant: Some(MINT as u16),
            accept: None,
        };
        let r = syscall_x(Syscall::Call, NIC, [nic::ATTACH, 0, 0, 0], x);
        syscall(Syscall::CapDelete, MINT, [0; 4]);
        self.need_attach = !(r.status == 0 && r.msg[0] == Status::Ok as u64);
    }

    /// Takes every frame the driver has.
    fn drain(&mut self) {
        for _ in 0..64 {
            let Some(r) = nic_call([nic::RECV, 0, 0, 0], RX_FRAME) else {
                self.need_attach = true;
                break;
            };
            if r[2] == 0 {
                self.need_attach = true;
            }
            if r[0] != Status::Ok as u64 {
                break;
            }
            self.received += 1;
            let len = (r[1] as usize).min(MAX_FRAME);
            self.frame(&page(RX_VA)[..len]);
        }
        if self.need_attach {
            self.attach();
        }
    }

    /// Sends the first `len` bytes of the transmit page.
    fn transmit(&mut self, len: usize) -> Status {
        match nic_call([nic::SEND, len as u64, 0, 0], TX_FRAME) {
            Some(r) if r[0] == Status::Ok as u64 => {
                self.sent += 1;
                Status::Ok
            }
            Some(r) => Status::from_u64(r[0]),
            None => Status::Unreachable,
        }
    }

    fn lookup(&self, ip: u32) -> Option<[u8; 6]> {
        self.arp.iter().flatten().find(|e| e.0 == ip).map(|e| e.1)
    }

    fn learn(&mut self, ip: u32, mac: [u8; 6]) {
        if let Some(e) = self.arp.iter_mut().flatten().find(|e| e.0 == ip) {
            e.1 = mac;
            return;
        }
        self.arp[self.arp_next] = Some((ip, mac));
        self.arp_next = (self.arp_next + 1) % ARP_CACHE;
        let i = ip.to_be_bytes();
        say!(
            "{}.{}.{}.{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            i[0],
            i[1],
            i[2],
            i[3],
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        // Frames that waited for it go now.
        for w in 0..WAITING {
            if let Some(f) = self.waiting[w].filter(|f| f.hop == ip) {
                self.waiting[w] = None;
                let tx = page(TX_VA);
                tx[..f.len as usize].copy_from_slice(&f.frame[..f.len as usize]);
                tx[0..6].copy_from_slice(&mac);
                self.transmit(f.len as usize);
            }
        }
    }

    /// Puts an Ethernet header on the transmit page.
    fn ether(&self, dst: [u8; 6], kind: u16) {
        let tx = page(TX_VA);
        tx[0..6].copy_from_slice(&dst);
        tx[6..12].copy_from_slice(&self.mac);
        put16(tx, 12, kind);
    }

    /// An ARP request or reply, built on the transmit page and sent.
    fn arp_send(&mut self, op: u16, target_mac: [u8; 6], target_ip: u32) {
        let dst = if op == 1 { [0xff; 6] } else { target_mac };
        self.ether(dst, ETH_ARP);
        let tx = page(TX_VA);
        let a = &mut tx[14..42];
        put16(a, 0, 1); // Ethernet
        put16(a, 2, ETH_IP);
        a[4] = 6;
        a[5] = 4;
        put16(a, 6, op);
        a[8..14].copy_from_slice(&self.mac);
        put32(a, 14, ip_u32(IP));
        a[18..24].copy_from_slice(&target_mac);
        put32(a, 24, target_ip);
        self.transmit(60);
    }

    /// Sends the IPv4 packet whose payload (`len` bytes) is already on the
    /// transmit page after the two headers; fills them in. A packet whose
    /// next hop is not yet known waits for the ARP answer.
    fn ip_send(&mut self, dst: u32, proto: u8, len: usize) -> Status {
        let total = 20 + len;
        let tx = page(TX_VA);
        let h = &mut tx[14..34];
        h.fill(0);
        h[0] = 0x45;
        put16(h, 2, total as u16);
        put16(h, 4, self.sent as u16); // identification
        h[8] = 64; // TTL
        h[9] = proto;
        put32(h, 12, ip_u32(IP));
        put32(h, 16, dst);
        let c = fold(sum(0, h));
        put16(h, 10, c);
        let hop = if dst & NETMASK == ip_u32(IP) & NETMASK {
            dst
        } else {
            ip_u32(GATEWAY)
        };
        let frame = (14 + total).max(60);
        if let Some(mac) = self.lookup(hop) {
            self.ether(mac, ETH_IP);
            return self.transmit(frame);
        }
        // Wait for ARP (dropping the oldest waiting frame if need be).
        let slot = (0..WAITING)
            .find(|&w| self.waiting[w].is_none())
            .unwrap_or(0);
        let mut w = Waiting {
            hop,
            len: frame as u16,
            tries: 0,
            frame: [0; MAX_FRAME],
        };
        self.ether([0; 6], ETH_IP);
        w.frame[..frame].copy_from_slice(&page(TX_VA)[..frame]);
        self.waiting[slot] = Some(w);
        self.arp_send(1, [0; 6], hop);
        Status::Ok
    }

    /// The timer: ARP requests again for frames still waiting.
    fn tick(&mut self) {
        for w in 0..WAITING {
            let Some(mut f) = self.waiting[w] else {
                continue;
            };
            f.tries += 1;
            if f.tries >= ARP_TRIES {
                self.waiting[w] = None;
                continue;
            }
            self.waiting[w] = Some(f);
            self.arp_send(1, [0; 6], f.hop);
        }
    }

    /// A received Ethernet frame.
    fn frame(&mut self, f: &[u8]) {
        if f.len() < 14 {
            return;
        }
        let to_us = f[0..6] == self.mac || f[0..6] == [0xff; 6];
        match be16(f, 12) {
            ETH_ARP if f.len() >= 42 => self.arp(&f[14..42]),
            ETH_IP if to_us => self.ip(&f[14..]),
            _ => {}
        }
    }

    fn arp(&mut self, a: &[u8]) {
        if be16(a, 0) != 1 || be16(a, 2) != ETH_IP || a[4] != 6 || a[5] != 4 {
            return;
        }
        let op = be16(a, 6);
        let mut sha = [0u8; 6];
        sha.copy_from_slice(&a[8..14]);
        let (spa, tpa) = (be32(a, 14), be32(a, 24));
        let for_us = tpa == ip_u32(IP);
        if for_us || self.lookup(spa).is_some() {
            self.learn(spa, sha);
        }
        if op == 1 && for_us {
            self.arp_send(2, sha, spa);
        }
    }

    fn ip(&mut self, p: &[u8]) {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return;
        }
        let ihl = (p[0] & 0xf) as usize * 4;
        let total = be16(p, 2) as usize;
        if ihl < 20 || total < ihl || total > p.len() || fold(sum(0, &p[..ihl])) != 0 {
            return;
        }
        // Fragments are not reassembled.
        if be16(p, 6) & 0x3fff != 0 {
            return;
        }
        let (src, dst) = (be32(p, 12), be32(p, 16));
        if dst != ip_u32(IP) {
            return;
        }
        let body = &p[ihl..total];
        match p[9] {
            PROTO_ICMP => self.icmp(src, body),
            PROTO_UDP => self.udp(src, dst, body),
            _ => {}
        }
    }

    fn icmp(&mut self, src: u32, m: &[u8]) {
        if m.len() < 8 || fold(sum(0, m)) != 0 {
            return;
        }
        let (id, seq) = (be16(m, 4), be16(m, 6));
        match m[0] {
            ICMP_ECHO => {
                // Answer with the same identifier, sequence and data.
                let len = m.len().min(MAX_PAYLOAD + 8);
                let tx = page(TX_VA);
                let r = &mut tx[34..34 + len];
                r.copy_from_slice(&m[..len]);
                r[0] = ICMP_ECHO_REPLY;
                r[2] = 0;
                r[3] = 0;
                let c = fold(sum(0, r));
                put16(r, 2, c);
                self.ip_send(src, PROTO_ICMP, len);
            }
            ICMP_ECHO_REPLY => self.deliver(Kind::Icmp(id), src, seq, &m[8..]),
            _ => {}
        }
    }

    fn udp(&mut self, src: u32, dst: u32, u: &[u8]) {
        if u.len() < 8 {
            return;
        }
        let len = be16(u, 4) as usize;
        if len < 8 || len > u.len() {
            return;
        }
        let u = &u[..len];
        if be16(u, 6) != 0 && fold(sum(pseudo(src, dst, PROTO_UDP, len), u)) != 0 {
            return;
        }
        self.deliver(Kind::Udp(be16(u, 2)), src, be16(u, 0), &u[8..]);
    }

    /// Queues a payload on the socket of `kind` and signals it.
    fn deliver(&mut self, kind: Kind, src: u32, port: u16, data: &[u8]) {
        let Some(i) = (0..SOCKETS).find(|&i| matches!(&self.sockets[i], Some(s) if s.kind == kind))
        else {
            return;
        };
        let s = self.sockets[i].as_mut().unwrap();
        if s.count == QUEUE {
            s.dropped += 1;
            return;
        }
        let d = &mut s.queue[(s.head + s.count) % QUEUE];
        let n = data.len().min(MAX_PAYLOAD);
        d.len = n as u16;
        d.from = (src as u64) << 16 | port as u64;
        d.data[..n].copy_from_slice(&data[..n]);
        s.count += 1;
        syscall(Syscall::Signal, SOCK_NTFN + i as u64, [0; 4]);
    }

    fn socket(&mut self, badge: u64, handle: u64) -> Option<usize> {
        let i = (handle & 0xff) as usize;
        match self.sockets.get(i) {
            Some(Some(s)) if s.handle == handle && s.owner == badge => Some(i),
            _ => None,
        }
    }

    /// A new socket of `kind` for client `badge`: its handle, and its
    /// notification minted to grant.
    fn bind(&mut self, badge: u64, kind: Kind) -> Result<u64, Status> {
        let i = (0..SOCKETS)
            .find(|&i| self.sockets[i].is_none())
            .ok_or(Status::NoSpace)?;
        // Whoever had this socket's notification before loses it.
        syscall(Syscall::CapRevoke, SOCK_NTFN + i as u64, [0; 4]);
        syscall(Syscall::CapDelete, MINT, [0; 4]);
        if syscall(
            Syscall::CapMint,
            SOCK_NTFN + i as u64,
            [MINT, READ | WRITE, 0, 0],
        )
        .status
            != 0
        {
            return Err(Status::Invalid);
        }
        self.next_id = self.next_id.wrapping_add(1);
        let handle = i as u64 | (self.next_id as u64) << 8 | self.epoch << 24;
        self.sockets[i] = Some(Socket {
            kind,
            owner: badge,
            handle,
            queue: [EMPTY; QUEUE],
            head: 0,
            count: 0,
            dropped: 0,
        });
        Ok(handle)
    }

    fn port_free(&self, port: u16) -> bool {
        !self
            .sockets
            .iter()
            .flatten()
            .any(|s| s.kind == Kind::Udp(port))
    }

    /// Sends `len` bytes of the client's page from socket `i` to `to`.
    fn send(&mut self, i: usize, to: u64, len: usize) -> Status {
        if len > MAX_PAYLOAD || syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        let data = &page(LENT_VA)[..len];
        let dst = (to >> 16) as u32;
        let tx = page(TX_VA);
        let status = match self.sockets[i].as_ref().unwrap().kind {
            Kind::Udp(port) => {
                let u = &mut tx[34..42 + len];
                put16(u, 0, port);
                put16(u, 2, to as u16);
                put16(u, 4, (8 + len) as u16);
                put16(u, 6, 0);
                u[8..].copy_from_slice(data);
                let c = fold(sum(pseudo(ip_u32(IP), dst, PROTO_UDP, 8 + len), u));
                put16(u, 6, if c == 0 { 0xffff } else { c });
                self.ip_send(dst, PROTO_UDP, 8 + len)
            }
            Kind::Icmp(id) => {
                let m = &mut tx[34..42 + len];
                m[0] = ICMP_ECHO;
                m[1] = 0;
                put16(m, 2, 0);
                put16(m, 4, id);
                put16(m, 6, to as u16);
                m[8..].copy_from_slice(data);
                let c = fold(sum(0, m));
                put16(m, 2, c);
                self.ip_send(dst, PROTO_ICMP, 8 + len)
            }
        };
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
        status
    }

    fn recv(&mut self, i: usize) -> [u64; 4] {
        let s = self.sockets[i].as_mut().unwrap();
        if s.count == 0 {
            return [Status::Empty as u64, 0, 0, 0];
        }
        if syscall(Syscall::FrameMap, LENT, [LENT_VA, 1, 0, 0]).status != 0 {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let d = &s.queue[s.head];
        let n = d.len as usize;
        page(LENT_VA)[..n].copy_from_slice(&d.data[..n]);
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
        let from = d.from;
        s.head = (s.head + 1) % QUEUE;
        s.count -= 1;
        [Status::Ok as u64, n as u64, from, 0]
    }

    /// One client call: the reply, and whether MINT is granted with it.
    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], bool) {
        let status = |s: Status| ([s as u64, 0, 0, 0], false);
        match m[0] {
            net::INFO if m[1] == net::VERSION => {
                let mac = self.mac.iter().fold(0, |a, &b| a << 8 | b as u64);
                (
                    [
                        Status::Ok as u64,
                        net::addr(IP, 0),
                        mac,
                        net::addr(GATEWAY, 0),
                    ],
                    false,
                )
            }
            net::UDP_BIND => {
                let port = match m[1] as u16 {
                    0 => match (EPHEMERAL..=u16::MAX).find(|&p| self.port_free(p)) {
                        Some(p) => p,
                        None => return status(Status::NoSpace),
                    },
                    p if !self.port_free(p) => return status(Status::InUse),
                    p => p,
                };
                match self.bind(badge, Kind::Udp(port)) {
                    Ok(h) => ([Status::Ok as u64, h, port as u64, 0], true),
                    Err(s) => status(s),
                }
            }
            net::ICMP_BIND => {
                let id = 0x5300 ^ self.next_id.wrapping_add(1) ^ (self.epoch as u16) << 8;
                match self.bind(badge, Kind::Icmp(id)) {
                    Ok(h) => ([Status::Ok as u64, h, id as u64, 0], true),
                    Err(s) => status(s),
                }
            }
            net::SEND if lent => match self.socket(badge, m[1]) {
                Some(i) => status(self.send(i, m[2], m[3] as usize)),
                None => status(Status::NotFound),
            },
            net::RECV if lent => match self.socket(badge, m[1]) {
                Some(i) => (self.recv(i), false),
                None => status(Status::NotFound),
            },
            net::CLOSE => match self.socket(badge, m[1]) {
                Some(i) => {
                    self.sockets[i] = None;
                    syscall(Syscall::CapRevoke, SOCK_NTFN + i as u64, [0; 4]);
                    status(Status::Ok)
                }
                None => status(Status::NotFound),
            },
            _ => status(Status::Invalid),
        }
    }
}

fn start(n: &mut Net) -> Result<(), (&'static str, u64)> {
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
    if syscall(Syscall::CapMint, SELF, [TIMER_CAP, WRITE, TIMER, 0]).status != 0 {
        return Err(("minting the timer's copy", 0));
    }
    for (slot, va) in [(RX_FRAME, RX_VA), (TX_FRAME, TX_VA)] {
        retype(ObjectType::Frame, slot)?;
        if syscall(Syscall::FrameMap, slot, [va, 1, 0, 0]).status != 0 {
            return Err(("mapping a frame page", slot));
        }
    }
    for i in 0..SOCKETS as u64 {
        retype(ObjectType::Notification, SOCK_NTFN + i)?;
    }
    n.epoch = syscall(Syscall::Ticks, 0, [0; 4]).msg[0] & 0xffff;
    let info = (0..100).find_map(|_| {
        let r = syscall(Syscall::Call, NIC, [nic::INFO, nic::VERSION, 0, 0]);
        if r.status == 0 && r.msg[0] == Status::Ok as u64 {
            return Some(r.msg);
        }
        syscall(Syscall::Yield, 0, [0; 4]);
        None
    });
    let info = info.ok_or(("the NIC driver does not answer", 0))?;
    for (i, b) in n.mac.iter_mut().enumerate() {
        *b = (info[1] >> (40 - 8 * i)) as u8;
    }
    n.attach();
    syscall(Syscall::TimerSignal, TIMER_CAP, [PERIOD, 0, 0, 0]);
    let m = n.mac;
    say!(
        "ready: {}.{}.{}.{}/24 via {}.{}.{}.{}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        IP[0],
        IP[1],
        IP[2],
        IP[3],
        GATEWAY[0],
        GATEWAY[1],
        GATEWAY[2],
        GATEWAY[3],
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    // SAFETY: the one thread is the only user of NET.
    let n = unsafe { &mut *(&raw mut NET) };
    if let Err((what, code)) = start(n) {
        say!("[fail] {what} ({code})");
        loop {
            syscall(Syscall::Yield, 0, [0; 4]);
        }
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
                n.tick();
            }
            n.drain();
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let (reply, grant) = n.serve(r.badge, r.msg, lent);
        if lent {
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
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
