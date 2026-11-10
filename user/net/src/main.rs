//! The network server: IPv4 over Ethernet with ARP, ICMP echo and UDP,
//! serving the `net` interface (`superior_objects::interfaces::net`) to
//! clients and using a NIC driver through the `nic` interface.
//!
//! It is crash-only. Its state is the ARP cache, the frames waiting for
//! an ARP answer and the sockets with their queued datagrams; a restart
//! loses all of it, which the interface allows: datagrams are unreliable,
//! and each socket's notification belongs to this server, so its deletion
//! wakes a waiting client to bind again. The one thing kept is the DHCP
//! lease, in the component's state page: a restarted server goes on with
//! the address it had, until the lease runs out.
//!
//! One thread serves everything. Its notification is bound to it, so one
//! `Recv` waits for client calls, for the driver's "frames are waiting"
//! (the driver holds a copy badged [`RX`]) and for a kernel timer (a copy
//! badged [`TIMER`], set with `TimerSignal` every [`PERIOD`] ticks). On the
//! timer it also drains the driver, which reattaches after the driver was
//! restarted (a restarted driver has lost the notification and says so),
//! and resends ARP requests that got no answer.
//!
//! The address, netmask, gateway and DNS server come from DHCP (RFC
//! 2131): DISCOVER, OFFER, REQUEST, ACK, sent again every second until
//! answered. The lease is renewed halfway through (or every `arg` ticks,
//! when the manifest gives one, for tests), and dropped, with DISCOVER
//! again, if it runs out or the server refuses it. Until there is a lease
//! the server has no address: `INFO` and `SEND` answer `Unreachable`.
//!
//! Slots: 0 the `nic` endpoint, 1 the `net` endpoint (receive), 2 untyped
//! memory (256 KiB), 17 the state page.
//!
//! Datagrams up to `net::MAX_DATAGRAM` bytes go and come in IPv4
//! fragments: a datagram too big for one frame is sent in 1480-byte
//! pieces, and fragments that arrive are put back together
//! (`superior_inet::Reassembler`), up to four datagrams at once, each
//! given 5 s; one that does not complete in time is dropped.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_inet::{Key, MAX_REASSEMBLED, Outcome, Reassembler};
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
/// The state page, which outlives instances: the DHCP lease.
const STATE: u64 = 17;
/// The sockets' queue pages, SOCKETS * QUEUE of them.
const QUEUE_PAGES: u64 = 18;

const RX_VA: u64 = USER_BASE + 0x4000_0000;
const TX_VA: u64 = RX_VA + 0x1000;
const LENT_VA: u64 = RX_VA + 0x2000;
const STATE_VA: u64 = RX_VA + 0x3000;
const QUEUE_VA: u64 = RX_VA + 0x10_0000;

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

/// Ticks a second.
const SECOND: u64 = 100;
const BROADCAST: u32 = 0xffff_ffff;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_COOKIE: u32 = 0x6382_5363;
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
/// REQUESTs sent for an offer before starting over with DISCOVER.
const REQUEST_TRIES: u8 = 4;
/// The state page's words: `LEASE_MAGIC` (written last, so a lease half
/// written by an instance that died is not taken), then the lease.
const LEASE_MAGIC: u64 = 0x4448_4350_6c65_6173;
/// Words of the state page after the lease: counts kept across restarts
/// of datagrams reassembled, sent in fragments, and dropped half
/// reassembled.
const STAT_REASSEMBLED: usize = 8;
const STAT_FRAGMENTED: usize = 9;
const STAT_DROPPED: usize = 10;
/// Datagrams reassembled at once, and how long one may take (5 s).
const REASSEMBLING: usize = 4;
const REASSEMBLY_TICKS: u64 = 500;
/// The most IP payload in one 1500-byte frame, a multiple of 8.
const FRAGMENT: usize = 1480;

const SOCKETS: usize = 8;
/// Datagrams a socket keeps until they are received.
const QUEUE: usize = 4;
const ARP_CACHE: usize = 8;
const WAITING: usize = 4;
const MAX_FRAME: usize = nic::MAX_FRAME as usize;
const MAX_DATAGRAM: usize = net::MAX_DATAGRAM as usize;

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

/// A queued datagram; its bytes are in its queue page (`queue_page`).
#[derive(Clone, Copy)]
struct Datagram {
    len: u16,
    from: u64,
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

/// A DHCP lease (in the kernel's ticks since boot).
#[derive(Clone, Copy)]
struct Lease {
    ip: u32,
    mask: u32,
    gateway: u32,
    dns: u32,
    server: u32,
    /// When it runs out, and when to renew it.
    expires: u64,
    renew: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// DISCOVER sent: waiting for an offer.
    Selecting,
    /// REQUEST sent for an offer.
    Requesting { offered: u32, server: u32, tries: u8 },
    Bound,
    /// REQUEST sent to keep the lease.
    Renewing,
}

/// An IPv4 address, printed dotted.
struct Ip(u32);

impl core::fmt::Display for Ip {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let b = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

struct Net {
    mac: [u8; 6],
    lease: Option<Lease>,
    phase: Phase,
    /// The current DHCP transaction.
    xid: u32,
    /// When to send the current DHCP message again.
    resend: u64,
    /// Ticks between renewals (0: halfway through the lease).
    renew_every: u64,
    reassembly: Reassembler<REASSEMBLING>,
    /// The last IPv4 identification used.
    ip_id: u16,
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

const EMPTY: Datagram = Datagram { len: 0, from: 0 };

/// The page holding the bytes of socket `i`'s queue entry `j`: one page
/// each, made at start, so the image stays small.
fn queue_page(i: usize, j: usize) -> &'static mut [u8] {
    page(QUEUE_VA + 0x1000 * (i * QUEUE + j) as u64)
}

/// A reassembled datagram, while it is handled.
static mut WHOLE: [u8; MAX_REASSEMBLED] = [0; MAX_REASSEMBLED];
/// A datagram's payload, while it is sent in fragments.
static mut PIECES: [u8; MAX_REASSEMBLED] = [0; MAX_REASSEMBLED];

static mut NET: Net = Net {
    mac: [0; 6],
    lease: None,
    phase: Phase::Selecting,
    xid: 0,
    resend: 0,
    renew_every: 0,
    reassembly: Reassembler::new(),
    ip_id: 0,
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

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

fn state() -> *mut u64 {
    STATE_VA as *mut u64
}

/// Adds `n` to the state page's count `word`.
fn count(word: usize, n: u64) {
    // SAFETY: the state page is mapped at STATE_VA for good.
    unsafe {
        let w = state().add(word);
        w.write_volatile(w.read_volatile() + n);
    }
}

fn counted(word: usize) -> u64 {
    // SAFETY: as in `count`.
    unsafe { state().add(word).read_volatile() }
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
    /// This host's address: 0 without a lease.
    fn addr(&self) -> u32 {
        self.lease.map_or(0, |l| l.ip)
    }

    /// Writes the lease (or its absence) to the state page.
    fn save(&self) {
        let s = state();
        // SAFETY: the state page is mapped at STATE_VA for good.
        unsafe {
            s.write_volatile(0);
            if let Some(l) = self.lease {
                let words = [l.ip, l.mask, l.gateway, l.dns, l.server].map(u64::from);
                for (i, w) in words.iter().chain(&[l.expires, l.renew]).enumerate() {
                    s.add(1 + i).write_volatile(*w);
                }
                s.write_volatile(LEASE_MAGIC);
            }
        }
    }

    /// Takes the lease a previous instance left, if it has not run out.
    fn load(&mut self) -> bool {
        let s = state();
        // SAFETY: as in `save`.
        let w = |i: usize| unsafe { s.add(i).read_volatile() };
        if w(0) != LEASE_MAGIC || ticks() >= w(6) {
            return false;
        }
        self.lease = Some(Lease {
            ip: w(1) as u32,
            mask: w(2) as u32,
            gateway: w(3) as u32,
            dns: w(4) as u32,
            server: w(5) as u32,
            expires: w(6),
            renew: w(7),
        });
        self.phase = Phase::Bound;
        true
    }

    /// A new DHCP transaction number.
    fn next_xid(&mut self) {
        self.xid = self.xid.wrapping_mul(1_103_515_245).wrapping_add(12_345) ^ ticks() as u32;
    }

    /// Sends a DHCP message of `kind` for the current phase, broadcast.
    fn dhcp_send(&mut self, kind: u8) {
        let (ciaddr, requested, server) = match self.phase {
            Phase::Requesting { offered, server, .. } => (0, offered, server),
            Phase::Renewing => (self.addr(), 0, 0),
            _ => (0, 0, 0),
        };
        const LEN: usize = 300;
        let tx = page(TX_VA);
        let d = &mut tx[42..42 + LEN];
        d.fill(0);
        d[0] = 1; // a request
        d[1] = 1; // Ethernet
        d[2] = 6;
        put32(d, 4, self.xid);
        // Without an address, ask for the answer to be broadcast.
        put16(d, 10, if ciaddr == 0 { 0x8000 } else { 0 });
        put32(d, 12, ciaddr);
        d[28..34].copy_from_slice(&self.mac);
        put32(d, 236, DHCP_COOKIE);
        let mut at = 240;
        let mut option = |d: &mut [u8], code: u8, v: &[u8]| {
            d[at] = code;
            d[at + 1] = v.len() as u8;
            d[at + 2..at + 2 + v.len()].copy_from_slice(v);
            at += 2 + v.len();
        };
        option(d, 53, &[kind]);
        if requested != 0 {
            option(d, 50, &requested.to_be_bytes());
        }
        if server != 0 {
            option(d, 54, &server.to_be_bytes());
        }
        // Netmask, router, DNS server, lease time.
        option(d, 55, &[1, 3, 6, 51]);
        d[at] = 255;
        let u = &mut tx[34..42 + LEN];
        put16(u, 0, DHCP_CLIENT_PORT);
        put16(u, 2, DHCP_SERVER_PORT);
        put16(u, 4, (8 + LEN) as u16);
        put16(u, 6, 0);
        let c = fold(sum(pseudo(ciaddr, BROADCAST, PROTO_UDP, 8 + LEN), u));
        put16(u, 6, if c == 0 { 0xffff } else { c });
        self.ip_header(ciaddr, BROADCAST, PROTO_UDP, 8 + LEN, 0);
        self.ether([0xff; 6], ETH_IP);
        self.transmit(14 + 20 + 8 + LEN);
        self.resend = ticks() + SECOND;
    }

    /// Drops any lease and starts over with DISCOVER.
    fn rediscover(&mut self) {
        self.lease = None;
        self.save();
        self.phase = Phase::Selecting;
        self.next_xid();
        self.dhcp_send(DHCP_DISCOVER);
    }

    /// A DHCP message to this host (the UDP payload).
    fn dhcp(&mut self, d: &[u8]) {
        if d.len() < 240
            || d[0] != 2
            || be32(d, 4) != self.xid
            || d[28..34] != self.mac
            || be32(d, 236) != DHCP_COOKIE
        {
            return;
        }
        let (mut kind, mut mask, mut gateway, mut dns, mut secs, mut server) = (0, 0, 0, 0, 0, 0);
        let mut at = 240;
        while at + 1 < d.len() && d[at] != 255 {
            if d[at] == 0 {
                at += 1;
                continue;
            }
            let n = d[at + 1] as usize;
            let Some(v) = d.get(at + 2..at + 2 + n) else {
                break;
            };
            let word = if n >= 4 { be32(v, 0) } else { 0 };
            match d[at] {
                53 if n >= 1 => kind = v[0],
                1 => mask = word,
                3 => gateway = word,
                6 => dns = word,
                51 => secs = word,
                54 => server = word,
                _ => {}
            }
            at += 2 + n;
        }
        let yiaddr = be32(d, 16);
        match (self.phase, kind) {
            (Phase::Selecting, DHCP_OFFER) if yiaddr != 0 && server != 0 => {
                self.phase = Phase::Requesting {
                    offered: yiaddr,
                    server,
                    tries: 1,
                };
                self.dhcp_send(DHCP_REQUEST);
            }
            (Phase::Requesting { .. } | Phase::Renewing, DHCP_ACK) if yiaddr != 0 => {
                let renewing = self.phase == Phase::Renewing;
                let now = ticks();
                // An infinite lease (all ones) is kept for good.
                let length = if secs == u32::MAX {
                    u64::MAX / 4
                } else {
                    (secs as u64).max(10) * SECOND
                };
                let renew = match self.renew_every {
                    0 => length / 2,
                    t => t.min(length / 2),
                };
                let old = self.lease;
                let l = Lease {
                    ip: yiaddr,
                    mask: if mask == 0 { 0xffff_ff00 } else { mask },
                    gateway: if gateway != 0 { gateway } else { old.map_or(0, |l| l.gateway) },
                    dns: if dns != 0 { dns } else { old.map_or(0, |l| l.dns) },
                    server: if server != 0 { server } else { old.map_or(0, |l| l.server) },
                    expires: now + length,
                    renew: now + renew,
                };
                self.lease = Some(l);
                self.phase = Phase::Bound;
                self.save();
                if renewing {
                    say!("lease renewed: {} for {secs} s", Ip(l.ip));
                } else {
                    say!(
                        "leased {}/{} from {} via {}, DNS {}, for {secs} s",
                        Ip(l.ip),
                        l.mask.count_ones(),
                        Ip(l.server),
                        Ip(l.gateway),
                        Ip(l.dns)
                    );
                }
            }
            (Phase::Requesting { .. } | Phase::Renewing, DHCP_NAK) => {
                say!("lease refused; asking again");
                self.rediscover();
            }
            _ => {}
        }
    }

    /// The timer, for DHCP: messages sent again, renewal, expiry.
    fn dhcp_tick(&mut self) {
        let now = ticks();
        match self.phase {
            Phase::Selecting if now >= self.resend => self.dhcp_send(DHCP_DISCOVER),
            Phase::Requesting {
                offered,
                server,
                tries,
            } if now >= self.resend => {
                if tries >= REQUEST_TRIES {
                    self.rediscover();
                } else {
                    self.phase = Phase::Requesting {
                        offered,
                        server,
                        tries: tries + 1,
                    };
                    self.dhcp_send(DHCP_REQUEST);
                }
            }
            Phase::Bound if self.lease.is_some_and(|l| now >= l.renew) => {
                self.phase = Phase::Renewing;
                self.next_xid();
                self.dhcp_send(DHCP_REQUEST);
            }
            Phase::Renewing => {
                if self.lease.is_none_or(|l| now >= l.expires) {
                    say!("lease ran out; asking again");
                    self.rediscover();
                } else if now >= self.resend {
                    self.dhcp_send(DHCP_REQUEST);
                }
            }
            _ => {}
        }
    }

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
        put32(a, 14, self.addr());
        a[18..24].copy_from_slice(&target_mac);
        put32(a, 24, target_ip);
        self.transmit(60);
    }

    /// Sends the IPv4 packet whose payload (`len` bytes) is already on the
    /// transmit page after the two headers; fills them in. A packet whose
    /// next hop is not yet known waits for the ARP answer. One too big for
    /// a frame goes in fragments, of [`FRAGMENT`] bytes but the last (it is
    /// not held for ARP: it answers `Unreachable` and asks).
    fn ip_send(&mut self, dst: u32, proto: u8, len: usize) -> Status {
        let Some(lease) = self.lease else {
            return Status::Unreachable;
        };
        let hop = if dst & lease.mask == lease.ip & lease.mask {
            dst
        } else {
            lease.gateway
        };
        if len > FRAGMENT {
            return self.fragments(lease.ip, dst, proto, len, hop);
        }
        let total = 20 + len;
        self.ip_header(lease.ip, dst, proto, len, 0);
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

    /// Sends the `len`-byte payload on the transmit page in fragments.
    fn fragments(&mut self, src: u32, dst: u32, proto: u8, len: usize, hop: u32) -> Status {
        let Some(mac) = self.lookup(hop) else {
            self.arp_send(1, [0; 6], hop);
            return Status::Unreachable;
        };
        // SAFETY: one thread; PIECES is used only here.
        let pieces = unsafe { &mut *(&raw mut PIECES) };
        pieces[..len].copy_from_slice(&page(TX_VA)[34..34 + len]);
        self.ip_id = self.ip_id.wrapping_add(1);
        let id = self.ip_id;
        let mut at = 0;
        while at < len {
            let n = (len - at).min(FRAGMENT);
            let more = at + n < len;
            page(TX_VA)[34..34 + n].copy_from_slice(&pieces[at..at + n]);
            // The same identification on every fragment: only the offset
            // (in 8-byte units) and "more fragments" differ.
            self.ip_header_as(src, dst, proto, n, id, (more as u16) << 13 | (at / 8) as u16);
            self.ether(mac, ETH_IP);
            let s = self.transmit((14 + 20 + n).max(60));
            if s != Status::Ok {
                return s;
            }
            at += n;
        }
        count(STAT_FRAGMENTED, 1);
        Status::Ok
    }

    /// Fills in the IPv4 header on the transmit page for a payload of
    /// `len` bytes, with a new identification.
    fn ip_header(&mut self, src: u32, dst: u32, proto: u8, len: usize, frag: u16) {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_header_as(src, dst, proto, len, self.ip_id, frag);
    }

    /// The same, with identification `id` and the flags and fragment
    /// offset word `frag`.
    fn ip_header_as(&self, src: u32, dst: u32, proto: u8, len: usize, id: u16, frag: u16) {
        let tx = page(TX_VA);
        let h = &mut tx[14..34];
        h.fill(0);
        h[0] = 0x45;
        put16(h, 2, (20 + len) as u16);
        put16(h, 4, id);
        put16(h, 6, frag);
        h[8] = 64; // TTL
        h[9] = proto;
        put32(h, 12, src);
        put32(h, 16, dst);
        let c = fold(sum(0, h));
        put16(h, 10, c);
    }

    /// The timer: DHCP, and ARP requests again for frames still waiting.
    fn tick(&mut self) {
        self.dhcp_tick();
        let expired = self.reassembly.expire(ticks(), REASSEMBLY_TICKS);
        count(STAT_DROPPED, expired as u64);
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
            ETH_IP if to_us => self.ipv4(&f[14..]),
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
        let for_us = tpa != 0 && tpa == self.addr();
        if for_us || self.lookup(spa).is_some() {
            self.learn(spa, sha);
        }
        if op == 1 && for_us {
            self.arp_send(2, sha, spa);
        }
    }

    fn ipv4(&mut self, p: &[u8]) {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return;
        }
        let ihl = (p[0] & 0xf) as usize * 4;
        let total = be16(p, 2) as usize;
        if ihl < 20 || total < ihl || total > p.len() || fold(sum(0, &p[..ihl])) != 0 {
            return;
        }
        let (src, dst) = (be32(p, 12), be32(p, 16));
        // DHCP answers may come before this host has an address, or
        // broadcast: UDP sorts them out.
        let ours = dst != 0 && dst == self.addr();
        let frag = be16(p, 6);
        let (more, offset) = (frag & 0x2000 != 0, (frag & 0x1fff) as usize * 8);
        let body = if more || offset != 0 {
            let key = Key {
                src,
                dst,
                proto: p[9],
                id: be16(p, 4),
            };
            // SAFETY: one thread; WHOLE holds this datagram until it has
            // been handled, and nothing else uses it.
            let whole = unsafe { &mut *(&raw mut WHOLE) };
            match self.reassembly.add(ticks(), key, offset, more, &p[ihl..total], whole) {
                Outcome::Complete(n) => {
                    count(STAT_REASSEMBLED, 1);
                    &whole[..n]
                }
                Outcome::Dropped => {
                    count(STAT_DROPPED, 1);
                    return;
                }
                Outcome::Pending => return,
            }
        } else {
            &p[ihl..total]
        };
        match p[9] {
            PROTO_ICMP if ours => self.icmp(src, body),
            PROTO_UDP => self.udp(src, dst, body, ours),
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
                let len = m.len().min(MAX_DATAGRAM + 8);
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

    fn udp(&mut self, src: u32, dst: u32, u: &[u8], ours: bool) {
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
        if be16(u, 2) == DHCP_CLIENT_PORT && be16(u, 0) == DHCP_SERVER_PORT {
            self.dhcp(&u[8..]);
        } else if ours {
            self.deliver(Kind::Udp(be16(u, 2)), src, be16(u, 0), &u[8..]);
        }
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
        let j = (s.head + s.count) % QUEUE;
        let n = data.len().min(MAX_DATAGRAM);
        s.queue[j] = Datagram {
            len: n as u16,
            from: (src as u64) << 16 | port as u64,
        };
        queue_page(i, j)[..n].copy_from_slice(&data[..n]);
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
        if self.lease.is_none() {
            return Status::Unreachable;
        }
        if len > MAX_DATAGRAM || syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
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
                let c = fold(sum(pseudo(self.addr(), dst, PROTO_UDP, 8 + len), u));
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
        let d = s.queue[s.head];
        let n = d.len as usize;
        page(LENT_VA)[..n].copy_from_slice(&queue_page(i, s.head)[..n]);
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
            net::STATS if m[1] == net::VERSION => (
                [
                    Status::Ok as u64,
                    counted(STAT_REASSEMBLED),
                    counted(STAT_FRAGMENTED),
                    counted(STAT_DROPPED),
                ],
                false,
            ),
            net::INFO | net::LEASE if m[1] == net::VERSION => {
                let Some(l) = self.lease else {
                    return status(Status::Unreachable);
                };
                let word = |ip: u32| (ip as u64) << 16;
                if m[0] == net::LEASE {
                    let left = l.expires.saturating_sub(ticks()) / SECOND;
                    return ([Status::Ok as u64, l.mask as u64, word(l.dns), left], false);
                }
                let mac = self.mac.iter().fold(0, |a, &b| a << 8 | b as u64);
                ([Status::Ok as u64, word(l.ip), mac, word(l.gateway)], false)
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
    for k in 0..(SOCKETS * QUEUE) as u64 {
        retype(ObjectType::Frame, QUEUE_PAGES + k)?;
        if syscall(Syscall::FrameMap, QUEUE_PAGES + k, [QUEUE_VA + 0x1000 * k, 1, 0, 0]).status != 0 {
            return Err(("mapping a queue page", k));
        }
    }
    if syscall(Syscall::FrameMap, STATE, [STATE_VA, 1, 0, 0]).status != 0 {
        return Err(("mapping the state page", STATE));
    }
    n.epoch = ticks() & 0xffff;
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
        "ready: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    );
    n.xid = u32::from_be_bytes([m[2], m[3], m[4], m[5]]);
    if n.load() {
        let l = n.lease.unwrap();
        say!(
            "lease kept: {}/{} via {} ({} s left)",
            Ip(l.ip),
            l.mask.count_ones(),
            Ip(l.gateway),
            l.expires.saturating_sub(ticks()) / SECOND
        );
    } else {
        n.rediscover();
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    // SAFETY: the one thread is the only user of NET.
    let n = unsafe { &mut *(&raw mut NET) };
    n.renew_every = arg;
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
