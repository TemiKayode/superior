//! The network server: IPv4 over Ethernet with ARP, ICMP echo, UDP and
//! TCP, serving the `net` interface (`superior_objects::interfaces::net`) to
//! clients and using a NIC driver through the `nic` interface.
//!
//! It is crash-only. Its state is the ARP cache, the frames waiting for
//! an ARP answer, the sockets with their queued datagrams and the TCP
//! connections; a restart loses all of it, which the interface allows:
//! datagrams are unreliable, a TCP peer that sends to a forgotten
//! connection is reset, and each socket's notification belongs to this
//! server, so its deletion wakes a waiting client to bind (or connect)
//! again. The one thing kept is the DHCP
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
//! Frames go to and from the driver through rings (`nic::ring`) in pages
//! the manifest shares (`shared 13 18`), which the server attaches to the
//! driver at start and again whenever the driver has been restarted:
//! under load there is no call per frame, and neither side signals the
//! other unless it sleeps. Nothing in those pages is trusted: a received
//! frame is copied out before it is looked at. While there is no ring
//! (none in the manifest, or the driver was just restarted) each frame
//! takes a call, as before; the timer's call to the driver is what finds
//! a restarted one.
//!
//! Slots: 0 the `nic` endpoint, 1 the `net` endpoint (receive), 2 untyped
//! memory (2 MiB), 17 the state page, 18 to 30 the ring's shared pages.
//!
//! TCP (`superior_inet::tcp`): up to [`CONNS`] connections, each with
//! 8 KiB rings each way in pages made at start, and using window scaling,
//! timestamps and SACK with peers that offer them. A connection the client
//! closed goes on until its FIN is acknowledged (or [`LINGER`] passes).
//! For tests, `arg`'s high 32 bits, when not 0, make the server drop one
//! TCP segment in that many at random, both ways.
//!
//! Packets to this host's own address go round a loopback queue, so a
//! client may talk to another on the same host.
//!
//! IPv6 (`ip6`) runs beside IPv4 on the same sockets and connections:
//! addresses are 128 bits everywhere, IPv4 ones mapped (`::ffff:a.b.c.d`).
//!
//! Datagrams up to `net::MAX_DATAGRAM` bytes (65,507) go and come in
//! fragments: a datagram too big for one frame is sent in 1480-byte
//! pieces (1448 over IPv6), and fragments that arrive are put back
//! together (`superior_inet::Reassembler`), up to four datagrams at once,
//! each given 5 s; one that does not complete in time is dropped. Queued
//! datagrams live in a pool of pages ([`POOL`]), a page for each 4 KiB
//! of a datagram, as do the pieces a client stages to send one too big for
//! its page (`SEND_PART`) and the rest of one too big for the page it
//! received into (`RECV_PART`); one socket holds at most [`SOCKET_POOL`]
//! of them, so one flooded socket cannot starve the others. The loopback
//! is a link like the Ethernet (a big datagram to this host goes round in
//! fragments), with room for [`LOOPBACK`] of them.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::interfaces::net::ring as cring;
use superior_objects::interfaces::nic::ring;
use superior_inet::tcp::{self, Bufs, Tcb};
use superior_inet::{Key, MAX_REASSEMBLED, Outcome, Reassembler, fold, ipv4, mapped, pseudo, sum};
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
/// The state page, which outlives instances: the DHCP lease.
const STATE: u64 = 17;
/// The frame rings' pages (`shared` in the manifest), and the driver's
/// doorbell.
const RING_SHARED: u64 = 18;
const DOORBELL: u64 = RING_SHARED + ring::PAGES;
/// The datagram pool's pages, POOL of them.
const POOL_PAGES: u64 = DOORBELL + 1;
/// The TCP connections' ring pages, CONNS * 4 of them.
const TCP_PAGES: u64 = POOL_PAGES + POOL as u64;
/// The loopback queue's pages, LOOPBACK of them.
const LOOP_PAGES: u64 = TCP_PAGES + (CONNS * 4) as u64;
/// A reassembled datagram's pages, and those a datagram is built in to
/// be sent in fragments (BIG_PAGES each).
const WHOLE_PAGES: u64 = LOOP_PAGES + LOOPBACK as u64;
const PIECES_PAGES: u64 = WHOLE_PAGES + BIG_PAGES as u64;
/// The reassembler's pages.
const REASM_PAGES: u64 = PIECES_PAGES + BIG_PAGES as u64;
/// Socket `i`'s notification.
const SOCK_NTFN: u64 = REASM_PAGES + REASM_SIZE.div_ceil(4096) as u64;

/// Clients' rings (`net::ring`): each one's completion notification,
/// the server's own doorbell (its notification, badged), and each one's
/// pages.
const MAX_CRINGS: usize = 4;
const CRING_NTFN: u64 = SOCK_NTFN + SOCKETS as u64;
const CRING_BELL: u64 = CRING_NTFN + MAX_CRINGS as u64;
const CRING_PAGES: u64 = CRING_BELL + 1;
const _: () = assert!(CRING_PAGES + MAX_CRINGS as u64 * cring::PAGES <= 512);

const RX_VA: u64 = USER_BASE + 0x4000_0000;
const TX_VA: u64 = RX_VA + 0x1000;
const LENT_VA: u64 = RX_VA + 0x2000;
const STATE_VA: u64 = RX_VA + 0x3000;
const POOL_VA: u64 = RX_VA + 0x10_0000;
const TCP_VA: u64 = RX_VA + 0x20_0000;
const LOOP_VA: u64 = RX_VA + 0x30_0000;
const WHOLE_VA: u64 = RX_VA + 0x40_0000;
const PIECES_VA: u64 = RX_VA + 0x50_0000;
const REASM_VA: u64 = RX_VA + 0x60_0000;
const RING_VA: u64 = RX_VA + 0x70_0000;
/// Client rings, `CRING_STRIDE` apart.
const CRING_VA: u64 = RX_VA + 0x80_0000;
const CRING_STRIDE: u64 = 0x2_0000;
const _: () = assert!(cring::PAGES * 4096 <= CRING_STRIDE);

/// Badges on this thread's notification.
const RX: u64 = 1;
const TIMER: u64 = 2;
/// A client rang its ring's doorbell (or the server its own, with ring
/// work left over).
const RINGBELL: u64 = 4;
/// Ticks between timer wakeups (100 ms).
const PERIOD: u64 = 10;
/// Timer periods an unanswered ARP request is repeated before the frames
/// waiting on it are dropped.
const ARP_TRIES: u8 = 10;
/// Ticks an IPv6 router that did not answer is passed over (30 s).
const ROUTER_SILENT: u64 = 3000;

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
/// reassembled; then of TCP segments sent again, dropped on purpose, and
/// kept out of order.
const STAT_REASSEMBLED: usize = 8;
const STAT_FRAGMENTED: usize = 9;
const STAT_DROPPED: usize = 10;
const STAT_TCP_RESENT: usize = 11;
const STAT_TCP_DROPPED: usize = 12;
const STAT_TCP_OUT_OF_ORDER: usize = 13;
/// Frames through the rings, frames by a call each, rings set up.
const STAT_RING_FRAMES: usize = 60;
const STAT_CALL_FRAMES: usize = 61;
const STAT_RINGS: usize = 62;
/// Datagrams reassembled at once, and how long one may take (5 s).
const REASSEMBLING: usize = 4;
const REASSEMBLY_TICKS: u64 = 500;
/// The most IP payload in one 1500-byte frame, a multiple of 8.
const FRAGMENT: usize = 1480;

const SOCKETS: usize = 16;
/// TCP connections, and each ring's size.
const CONNS: usize = 16;
const TCP_BUF: usize = 8192;
/// Connections a listening socket holds until they are accepted.
const BACKLOG: usize = 2;
/// How long a closed connection may take to finish (30 s).
const LINGER: u64 = 3000;
/// Packets to this host's own address waiting to be handled, a page
/// each (more are dropped, as a busy link would): room for a datagram of
/// the largest size in fragments, and the start of its answer.
const LOOPBACK: usize = 64;
/// Datagrams a socket keeps until they are received.
const QUEUE: usize = 4;
/// Pages in the datagram pool, and the most one socket may hold (three
/// datagrams of the largest size).
const POOL: usize = 160;
const SOCKET_POOL: usize = 3 * DATAGRAM_PAGES;
/// Pages a datagram of the largest size takes, and a whole IP payload.
const DATAGRAM_PAGES: usize = MAX_DATAGRAM.div_ceil(4096);
const BIG_PAGES: usize = MAX_REASSEMBLED.div_ceil(4096);
const REASM_SIZE: usize = core::mem::size_of::<Reassembler<REASSEMBLING>>();
const ARP_CACHE: usize = 12;
const WAITING: usize = 4;
const MAX_FRAME: usize = nic::MAX_FRAME as usize;
const MAX_DATAGRAM: usize = net::MAX_DATAGRAM as usize;

const ETH_ARP: u16 = 0x0806;
const ETH_IP: u16 = 0x0800;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO: u8 = 8;
const ICMP_UNREACHABLE: u8 = 3;
/// Ephemeral ports for `UDP_BIND` with port 0.
const EPHEMERAL: u16 = 49152;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("net: {}", format_args!($($t)*))) };
}

mod ip6;
use ip6::{ETH_IPV6, Ip6, NH_ICMP6, V6};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Udp(u16),
    /// ICMP echo, by identifier.
    Icmp(u16),
    /// A listening TCP port.
    Listen(u16),
    /// TCP connection `n`.
    Tcp(usize),
}

/// A TCP connection.
#[derive(Clone, Copy)]
struct Conn {
    tcb: Tcb,
    /// Its socket: from `TCP_CONNECT`, or once accepted.
    socket: Option<usize>,
    /// The listening socket it waits on until accepted.
    listener: Option<usize>,
    /// When its owner closed it; it goes on until finished.
    closed_at: Option<u64>,
    /// Its counts already added to the state page.
    counted: tcp::Stats,
}

/// A queued datagram; its bytes are in pool pages (`pool_page`), the
/// first `len.div_ceil(4096)` of `pages`.
#[derive(Clone, Copy)]
struct Datagram {
    len: u16,
    from: u128,
    port: u16,
    pages: [u8; DATAGRAM_PAGES],
}

impl Datagram {
    fn page_count(&self) -> usize {
        (self.len as usize).div_ceil(4096).max(1)
    }
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
    /// The datagram last received, while its rest may be fetched
    /// (`RECV_PART`).
    held: Option<Datagram>,
    /// The datagram being staged to send (`SEND_PART`): its bytes so far,
    /// in the first `stage_pages` of `stage`.
    staged: usize,
    stage_pages: usize,
    stage: [u8; DATAGRAM_PAGES],
    /// Pool pages it holds.
    pooled: usize,
}

#[derive(Clone, Copy)]
struct Waiting {
    /// The next hop whose MAC address the frame waits for.
    hop: u128,
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
    /// Which pool pages are in use.
    pool: [u64; POOL.div_ceil(64)],
    /// The last IPv4 identification used.
    ip_id: u16,
    /// MAC addresses learned from ARP and Neighbor Discovery.
    arp: [Option<(u128, [u8; 6])>; ARP_CACHE],
    v6: V6,
    arp_next: usize,
    waiting: [Option<Waiting>; WAITING],
    sockets: [Option<Socket>; SOCKETS],
    crings: [Option<ClientRing>; MAX_CRINGS],
    /// Requests taken from clients' rings, and doorbells that woke the
    /// server for them.
    cring_ops: u64,
    cring_bells: u64,
    /// Handles carry this, so an old instance's handles do not match.
    epoch: u64,
    next_id: u16,
    conns: [Option<Conn>; CONNS],
    /// The loopback queue: its first entry and how many are waiting.
    loop_head: usize,
    loop_count: usize,
    /// The next ephemeral TCP port tried.
    next_port: u16,
    /// Drop one TCP segment in this many (0: none), from `random`.
    drop_one_in: u64,
    random: u64,
    need_attach: bool,
    /// The frame rings are set up with the driver: frames go through
    /// them, not by calls.
    ring_up: bool,
    /// The manifest shares no pages for a ring.
    ring_absent: bool,
    ring_mapped: bool,
    /// The server's own ends of the rings: the next received frame to
    /// take, and where the next frame to send goes.
    rx_head: u32,
    tx_tail: u32,
    received: u64,
    sent: u64,
}

const EMPTY: Datagram = Datagram {
    len: 0,
    from: 0,
    port: 0,
    pages: [0; DATAGRAM_PAGES],
};

/// Pool page `p`, made at start, so the image stays small.
fn pool_page(p: u8) -> &'static mut [u8] {
    page(POOL_VA + 0x1000 * p as u64)
}

/// Copies bytes `at..at + out.len()` of the datagram in pool pages
/// `pages` to `out`.
fn pool_read(pages: &[u8], at: usize, out: &mut [u8]) {
    let mut done = 0;
    while done < out.len() {
        let (p, o) = ((at + done) / 4096, (at + done) % 4096);
        let n = (4096 - o).min(out.len() - done);
        out[done..done + n].copy_from_slice(&pool_page(pages[p])[o..o + n]);
        done += n;
    }
}

/// Copies `data` into the datagram in pool pages `pages` from byte `at`.
fn pool_write(pages: &[u8], at: usize, data: &[u8]) {
    let mut done = 0;
    while done < data.len() {
        let (p, o) = ((at + done) / 4096, (at + done) % 4096);
        let n = (4096 - o).min(data.len() - done);
        pool_page(pages[p])[o..o + n].copy_from_slice(&data[done..done + n]);
        done += n;
    }
}

/// A reassembled datagram, while it is handled.
fn whole() -> &'static mut [u8] {
    // SAFETY: BIG_PAGES pages are mapped at WHOLE_VA for good; one thread,
    // and each use ends before the next begins.
    unsafe { core::slice::from_raw_parts_mut(WHOLE_VA as *mut u8, MAX_REASSEMBLED) }
}

/// A datagram's IP payload, while it is sent in fragments.
fn pieces() -> &'static mut [u8] {
    // SAFETY: as for `whole`, at PIECES_VA.
    unsafe { core::slice::from_raw_parts_mut(PIECES_VA as *mut u8, MAX_REASSEMBLED) }
}

/// The reassembler, set up (`Reassembler::init`) at start.
fn reassembly() -> &'static mut Reassembler<REASSEMBLING> {
    // SAFETY: its pages are mapped at REASM_VA for good and it was set up
    // in `start`; one thread.
    unsafe { &mut *(REASM_VA as *mut Reassembler<REASSEMBLING>) }
}

/// The address word (`net::addr`) for `a` and `port`: 0 for an IPv6
/// address, which does not fit (the `*6` calls give those).
fn word(a: u128, port: u16) -> u64 {
    ipv4(a).map_or(0, |ip| (ip as u64) << 16 | port as u64)
}

/// Connection `c`'s rings.
fn bufs(c: usize) -> Bufs<'static> {
    let va = TCP_VA + 0x4000 * c as u64;
    // SAFETY: CONNS * 4 pages are mapped from TCP_VA for good, and only
    // connection `c` uses its four.
    unsafe {
        Bufs {
            tx: core::slice::from_raw_parts_mut(va as *mut u8, TCP_BUF),
            rx: core::slice::from_raw_parts_mut((va + 0x2000) as *mut u8, TCP_BUF),
        }
    }
}

/// The status for a connection that ended badly.
fn failed(e: tcp::Error) -> Status {
    match e {
        tcp::Error::Refused => Status::Refused,
        tcp::Error::Reset => Status::Reset,
        tcp::Error::TimedOut => Status::TimedOut,
        tcp::Error::Unreachable => Status::Unreachable,
    }
}

fn state_number(s: tcp::State) -> u64 {
    use tcp::State::*;
    match s {
        Closed => net::TCP_CLOSED,
        SynSent => net::TCP_SYN_SENT,
        SynReceived => net::TCP_SYN_RECEIVED,
        Established => net::TCP_ESTABLISHED,
        FinWait1 => net::TCP_FIN_WAIT_1,
        FinWait2 => net::TCP_FIN_WAIT_2,
        CloseWait => net::TCP_CLOSE_WAIT,
        Closing => net::TCP_CLOSING,
        LastAck => net::TCP_LAST_ACK,
        TimeWait => net::TCP_TIME_WAIT,
    }
}

static mut NET: Net = Net {
    mac: [0; 6],
    lease: None,
    phase: Phase::Selecting,
    xid: 0,
    resend: 0,
    renew_every: 0,
    pool: [0; POOL.div_ceil(64)],
    ip_id: 0,
    arp: [None; ARP_CACHE],
    v6: V6::new(),
    arp_next: 0,
    waiting: [None; WAITING],
    sockets: [const { None }; SOCKETS],
    crings: [None; MAX_CRINGS],
    cring_ops: 0,
    cring_bells: 0,
    epoch: 0,
    next_id: 0,
    conns: [None; CONNS],
    loop_head: 0,
    loop_count: 0,
    next_port: 0,
    drop_one_in: 0,
    random: 0x2545_f491_4f6c_dd1d,
    need_attach: true,
    ring_up: false,
    ring_absent: false,
    ring_mapped: false,
    rx_head: 0,
    tx_tail: 0,
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

/// Where the page a request lends is: `LENT_VA` for a call (mapped for
/// the time it is used), or a data page of the caller's ring.
static DATA: AtomicU64 = AtomicU64::new(LENT_VA);

/// Maps the page lent with a call; a ring's page is mapped already.
fn map_lent(writable: bool) -> bool {
    DATA.load(Ordering::Relaxed) != LENT_VA
        || syscall(Syscall::FrameMap, LENT, [LENT_VA, writable as u64, 0, 0]).status == 0
}

fn unmap_lent() {
    if DATA.load(Ordering::Relaxed) == LENT_VA {
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
    }
}

/// The page the request being served lends.
fn lent_page() -> &'static mut [u8] {
    page(DATA.load(Ordering::Relaxed))
}

/// A client's ring.
#[derive(Clone, Copy)]
struct ClientRing {
    /// The client's badge.
    owner: u64,
    /// Pages attached so far.
    attached: u64,
    started: bool,
}

/// A word of a client ring's header.
fn chdr(page: u64, off: usize) -> &'static AtomicU32 {
    // SAFETY: the ring page is mapped while the ring is attached, and the
    // offsets are inside it and aligned.
    unsafe { &*((page + off as u64) as *const AtomicU32) }
}

fn cring_va(r: usize) -> u64 {
    CRING_VA + r as u64 * CRING_STRIDE
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


/// How long (in ticks) the server waits, yielding the CPU, for a slot in
/// a full transmit ring before it gives the frame up. The driver may be
/// waiting for the device to send what it has, which takes real time.
const FULL_RING_TICKS: u64 = 5;

/// Word `off` of the ring's header page.
fn hdr(off: usize) -> &'static AtomicU32 {
    // SAFETY: only used once the ring's pages are mapped, for good.
    unsafe { &*((RING_VA + off as u64) as *const AtomicU32) }
}

/// Where frame `i` of a ring whose slots start at page `page` lies.
fn ring_slot(page: u64, i: u32, slots: u32) -> u64 {
    RING_VA + page * 4096 + (i % slots) as u64 * ring::SLOT
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
        let c = fold(sum(pseudo(mapped(ciaddr), mapped(BROADCAST), PROTO_UDP, 8 + LEN), u));
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

    /// Sets the frame rings up with the driver: maps the shared pages
    /// (once), attaches each, starts the ring and takes the doorbell.
    /// Without them, or if the driver refuses, frames go by calls.
    fn ring_setup(&mut self) {
        self.ring_up = false;
        if self.ring_absent {
            return;
        }
        if !self.ring_mapped {
            for p in 0..ring::PAGES {
                let va = RING_VA + p * 4096;
                if syscall(Syscall::FrameMap, RING_SHARED + p, [va, 1, 0, 0]).status != 0 {
                    // The manifest shares no pages for a ring.
                    self.ring_absent = true;
                    return;
                }
            }
            self.ring_mapped = true;
        }
        let ok = Status::Ok as u64;
        for p in 0..ring::PAGES {
            if nic_call([nic::RING_ATTACH, p, 0, 0], RING_SHARED + p).map(|r| r[0]) != Some(ok) {
                return;
            }
        }
        syscall(Syscall::CapDelete, DOORBELL, [0; 4]);
        let x = CapTransfer {
            grant: None,
            accept: Some(DOORBELL as u16),
        };
        let r = syscall_x(Syscall::Call, NIC, [nic::RING_START, 0, 0, 0], x);
        if r.status != 0 || r.msg[0] != ok || r.cap != Some(DOORBELL as u16) {
            return;
        }
        // The driver cleared the header: both rings are empty.
        (self.rx_head, self.tx_tail) = (0, 0);
        self.ring_up = true;
        count(STAT_RINGS, 1);
        say!("frame rings set up with the driver ({} times so far)", counted(STAT_RINGS));
    }

    /// Wakes the driver. False (and the ring is given up) if its doorbell
    /// is gone: the driver was restarted.
    fn ring_bell(&mut self) -> bool {
        if syscall(Syscall::Signal, DOORBELL, [0; 4]).status != 0 {
            self.ring_up = false;
            self.need_attach = true;
        }
        self.ring_up
    }

    /// Takes every frame in the receive ring.
    fn drain_ring(&mut self) {
        if !self.ring_up {
            return;
        }
        let tail = hdr(ring::RX_TAIL).load(Ordering::Acquire);
        let n = ring::waiting(self.rx_head, tail, ring::RX_SLOTS);
        for _ in 0..n {
            let at = self.rx_head % ring::RX_SLOTS;
            let len = hdr(ring::RX_LEN + 4 * at as usize).load(Ordering::Relaxed);
            let len = (len as usize).min(MAX_FRAME);
            // Copied out first: the driver can write to the ring at any
            // time, and what is parsed must hold still.
            // SAFETY: the ring's pages and the receive page are mapped;
            // `len` fits in a slot and in the page.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ring_slot(ring::RX_PAGE, self.rx_head, ring::RX_SLOTS) as *const u8,
                    RX_VA as *mut u8,
                    len,
                );
            }
            self.rx_head = self.rx_head.wrapping_add(1);
            hdr(ring::RX_HEAD).store(self.rx_head, Ordering::Release);
            self.received += 1;
            count(STAT_RING_FRAMES, 1);
            self.frame(&page(RX_VA)[..len]);
        }
        // The driver may be holding frames back from a ring that was
        // full: there is room now.
        if n > 0 {
            fence(Ordering::SeqCst);
            if hdr(ring::RX_STALLED).swap(0, Ordering::SeqCst) != 0 {
                self.ring_bell();
            }
        }
    }

    /// Before the server waits: empties the receive ring, says it sleeps,
    /// and looks once more, so a frame put there meanwhile is not left
    /// with nobody to signal.
    fn before_sleep(&mut self) {
        while self.ring_up {
            self.drain_ring();
            hdr(ring::CALLER_SLEEPS).store(1, Ordering::SeqCst);
            fence(Ordering::SeqCst);
            let tail = hdr(ring::RX_TAIL).load(Ordering::Acquire);
            if ring::waiting(self.rx_head, tail, ring::RX_SLOTS) == 0 {
                break;
            }
            hdr(ring::CALLER_SLEEPS).store(0, Ordering::SeqCst);
        }
    }

    /// Takes every frame the driver has by calls, which also finds a
    /// driver that was restarted: it has lost the notification and the
    /// ring, and gets both again.
    fn drain(&mut self) {
        for _ in 0..64 {
            let Some(r) = nic_call([nic::RECV, 0, 0, 0], RX_FRAME) else {
                self.need_attach = true;
                self.ring_up = false;
                break;
            };
            if r[2] == 0 {
                self.need_attach = true;
            }
            if r[3] == 0 {
                self.ring_up = false;
            }
            if r[0] != Status::Ok as u64 {
                break;
            }
            self.received += 1;
            count(STAT_CALL_FRAMES, 1);
            let len = (r[1] as usize).min(MAX_FRAME);
            self.frame(&page(RX_VA)[..len]);
        }
        if self.need_attach {
            self.attach();
        }
        if !self.ring_up {
            self.ring_setup();
        }
    }

    /// Puts the first `len` bytes of the transmit page in the transmit
    /// ring. `None` if there is no ring to put it in (any more).
    fn ring_transmit(&mut self, len: usize) -> Option<Status> {
        if !self.ring_up {
            return None;
        }
        // A full ring: the driver, on another CPU or about to be woken,
        // is on its way through it, so wait for a slot rather than lose
        // the frame (a datagram in 45 fragments fills the ring at once).
        // Not for ever: the device may be stuck, or the driver dead (a
        // dead driver's ring stays full, and waiting out the limit for
        // each of 45 fragments would hold every client up for seconds).
        let mut since = None;
        loop {
            let head = hdr(ring::TX_HEAD).load(Ordering::Acquire);
            if ring::waiting(head, self.tx_tail, ring::TX_SLOTS) < ring::TX_SLOTS {
                break;
            }
            // Ringing the doorbell wakes a sleeping driver, and fails at
            // once if the driver was killed (the doorbell was its own):
            // then the ring is given up and the frame goes by a call,
            // which waits for the new driver.
            hdr(ring::DRIVER_SLEEPS).store(0, Ordering::SeqCst);
            if !self.ring_bell() {
                return None;
            }
            let now = ticks();
            if now >= *since.get_or_insert(now) + FULL_RING_TICKS {
                // A driver that is there but not sending: the ring is set
                // up afresh at the next timer tick, rather than every
                // frame of a burst waiting this long in turn.
                self.ring_up = false;
                return None;
            }
            syscall(Syscall::Yield, 0, [0; 4]);
        }
        let at = self.tx_tail % ring::TX_SLOTS;
        // SAFETY: the transmit page and the ring's pages are mapped; `len`
        // (at most MAX_FRAME) fits in a slot.
        unsafe {
            core::ptr::copy_nonoverlapping(
                TX_VA as *const u8,
                ring_slot(ring::TX_PAGE, self.tx_tail, ring::TX_SLOTS) as *mut u8,
                len.min(MAX_FRAME),
            );
        }
        hdr(ring::TX_LEN + 4 * at as usize).store(len.min(MAX_FRAME) as u32, Ordering::Relaxed);
        self.tx_tail = self.tx_tail.wrapping_add(1);
        hdr(ring::TX_TAIL).store(self.tx_tail, Ordering::Release);
        fence(Ordering::SeqCst);
        if hdr(ring::DRIVER_SLEEPS).swap(0, Ordering::SeqCst) != 0 && !self.ring_bell() {
            // The driver is gone, and the frame with it: by a call, then.
            return None;
        }
        self.sent += 1;
        count(STAT_RING_FRAMES, 1);
        Some(Status::Ok)
    }

    /// Sends the first `len` bytes of the transmit page.
    fn transmit(&mut self, len: usize) -> Status {
        if let Some(s) = self.ring_transmit(len) {
            return s;
        }
        match nic_call([nic::SEND, len as u64, 0, 0], TX_FRAME) {
            Some(r) if r[0] == Status::Ok as u64 => {
                self.sent += 1;
                count(STAT_CALL_FRAMES, 1);
                Status::Ok
            }
            Some(r) => Status::from_u64(r[0]),
            None => Status::Unreachable,
        }
    }

    fn lookup(&self, ip: u128) -> Option<[u8; 6]> {
        self.arp.iter().flatten().find(|e| e.0 == ip).map(|e| e.1)
    }

    fn learn(&mut self, ip: u128, mac: [u8; 6]) {
        self.v6.routes.heard(ip);
        if let Some(e) = self.arp.iter_mut().flatten().find(|e| e.0 == ip) {
            e.1 = mac;
            return;
        }
        self.arp[self.arp_next] = Some((ip, mac));
        self.arp_next = (self.arp_next + 1) % ARP_CACHE;
        say!(
            "{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            Ip6(ip),
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
    fn ip_send(&mut self, dst: u128, proto: u8, len: usize) -> Status {
        match ipv4(dst) {
            Some(d) => self.ip4_send(d, proto, len),
            None => self.ip6_send(dst, proto, len),
        }
    }

    /// The source address for a packet to `dst`, if this host has one in
    /// its family.
    fn source_for(&self, dst: u128) -> Option<u128> {
        match ipv4(dst) {
            Some(_) => self.lease.map(|l| mapped(l.ip)),
            None => self.source6(dst),
        }
    }

    /// Where a payload to `dst` starts on the transmit page: after the
    /// Ethernet header and IPv4's or IPv6's.
    fn payload_at(dst: u128) -> usize {
        if ipv4(dst).is_some() { 34 } else { 54 }
    }

    /// Holds the frame on the transmit page (`frame` bytes) until `hop`'s
    /// MAC address is known (dropping the oldest waiting frame if need be).
    fn wait_for(&mut self, hop: u128, frame: usize) {
        let slot = (0..WAITING)
            .find(|&w| self.waiting[w].is_none())
            .unwrap_or(0);
        let mut w = Waiting {
            hop,
            len: frame as u16,
            tries: 0,
            frame: [0; MAX_FRAME],
        };
        w.frame[..frame].copy_from_slice(&page(TX_VA)[..frame]);
        self.waiting[slot] = Some(w);
    }

    /// Asks for `hop`'s MAC address: ARP, or a neighbour solicitation.
    fn solicit(&mut self, hop: u128) {
        match ipv4(hop) {
            Some(ip) => self.arp_send(1, [0; 6], ip),
            None => self.ns(hop, false),
        }
    }

    fn ip4_send(&mut self, dst: u32, proto: u8, len: usize) -> Status {
        let Some(lease) = self.lease else {
            return Status::Unreachable;
        };
        if dst == lease.ip {
            return self.loopback(proto, len);
        }
        let hop = if dst & lease.mask == lease.ip & lease.mask {
            dst
        } else {
            lease.gateway
        };
        if len > FRAGMENT {
            pieces()[..len].copy_from_slice(&page(TX_VA)[34..34 + len]);
            return self.fragments(lease.ip, dst, proto, len, Some(hop));
        }
        let total = 20 + len;
        self.ip_header(lease.ip, dst, proto, len, 0);
        let frame = (14 + total).max(60);
        if let Some(mac) = self.lookup(mapped(hop)) {
            self.ether(mac, ETH_IP);
            return self.transmit(frame);
        }
        self.ether([0; 6], ETH_IP);
        self.wait_for(mapped(hop), frame);
        self.arp_send(1, [0; 6], hop);
        Status::Ok
    }

    /// A packet to this host's own address (its payload on the transmit
    /// page): queued, and handled as if it had arrived once the current
    /// work is done ([`Net::run_loopback`]).
    fn loopback(&mut self, proto: u8, len: usize) -> Status {
        let ip = self.addr();
        let total = 20 + len;
        if self.loop_count == LOOPBACK || total > 4096 {
            return Status::Ok;
        }
        self.ip_header(ip, ip, proto, len, 0);
        self.loop_push(total);
        Status::Ok
    }

    /// Queues the packet on the transmit page (`total` bytes after the
    /// Ethernet header) on the loopback; dropped if the queue is full.
    fn loop_push(&mut self, total: usize) {
        if self.loop_count == LOOPBACK || total > 4096 {
            return;
        }
        let slot = (self.loop_head + self.loop_count) % LOOPBACK;
        page(LOOP_VA + 0x1000 * slot as u64)[..total].copy_from_slice(&page(TX_VA)[14..14 + total]);
        self.loop_count += 1;
    }

    /// Handles the packets this host sent itself, and those their answers
    /// send.
    fn run_loopback(&mut self) {
        // What a packet's handling sends itself is handled too, up to a
        // bound.
        for _ in 0..1024 {
            if self.loop_count == 0 {
                break;
            }
            // The entry stays queued while it is handled, so what it sends
            // goes after it.
            let p = page(LOOP_VA + 0x1000 * self.loop_head as u64);
            if p[0] >> 4 == 6 {
                let total = (40 + be16(p, 4) as usize).min(4096);
                self.ipv6(&p[..total]);
            } else {
                let total = (be16(p, 2) as usize).min(4096);
                self.ipv4(&p[..total]);
            }
            self.loop_head = (self.loop_head + 1) % LOOPBACK;
            self.loop_count -= 1;
        }
    }

    /// Sends a packet whose IP payload (`len` bytes) is in `pieces()`,
    /// in fragments if it does not fit a frame.
    fn send_pieces(&mut self, dst: u128, proto: u8, len: usize) -> Status {
        let Some(d) = ipv4(dst) else {
            return self.send_pieces6(dst, proto, len);
        };
        let Some(lease) = self.lease else {
            return Status::Unreachable;
        };
        if len <= FRAGMENT {
            page(TX_VA)[34..34 + len].copy_from_slice(&pieces()[..len]);
            return self.ip4_send(d, proto, len);
        }
        let hop = if d == lease.ip {
            None
        } else if d & lease.mask == lease.ip & lease.mask {
            Some(d)
        } else {
            Some(lease.gateway)
        };
        self.fragments(lease.ip, d, proto, len, hop)
    }

    /// Sends the `len`-byte payload in `pieces()` in fragments, to `hop`
    /// (`None`: round the loopback, to this host).
    fn fragments(&mut self, src: u32, dst: u32, proto: u8, len: usize, hop: Option<u32>) -> Status {
        let mac = match hop {
            None => None,
            Some(h) => match self.lookup(mapped(h)) {
                Some(m) => Some(m),
                None => {
                    self.arp_send(1, [0; 6], h);
                    return Status::Unreachable;
                }
            },
        };
        let pieces = pieces();
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
            let Some(mac) = mac else {
                self.loop_push(20 + n);
                at += n;
                continue;
            };
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
        self.tick6();
        let now = ticks();
        for c in 0..CONNS {
            let Some(k) = self.conns[c].as_mut() else {
                continue;
            };
            if k.closed_at.is_some_and(|t| now >= t + LINGER) {
                k.tcb.abort();
            }
            k.tcb.tick(now);
            self.pump(c);
        }
        let expired = reassembly().expire(ticks(), REASSEMBLY_TICKS);
        count(STAT_DROPPED, expired as u64);
        for w in 0..WAITING {
            let Some(mut f) = self.waiting[w] else {
                continue;
            };
            f.tries += 1;
            if f.tries >= ARP_TRIES {
                self.waiting[w] = None;
                // A router that does not answer is passed over for a
                // while, if another can be used.
                self.v6.routes.silent(f.hop, ticks() + ROUTER_SILENT);
                continue;
            }
            self.waiting[w] = Some(f);
            self.solicit(f.hop);
        }
    }

    /// A received Ethernet frame.
    fn frame(&mut self, f: &[u8]) {
        if f.len() < 14 {
            return;
        }
        // This host's MAC, broadcast, or IPv6 multicast (33:33:...).
        let to_us = f[0..6] == self.mac || f[0..6] == [0xff; 6] || f[0..2] == [0x33, 0x33];
        match be16(f, 12) {
            ETH_ARP if f.len() >= 42 => self.arp(&f[14..42]),
            ETH_IP if to_us => self.ipv4(&f[14..]),
            ETH_IPV6 if to_us => self.ipv6(&f[14..]),
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
        if for_us || self.lookup(mapped(spa)).is_some() {
            self.learn(mapped(spa), sha);
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
                src: mapped(src),
                dst: mapped(dst),
                proto: p[9],
                id: be16(p, 4) as u32,
            };
            // whole() holds this datagram until it has been handled.
            let whole = whole();
            match reassembly().add(ticks(), key, offset, more, &p[ihl..total], whole) {
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
            PROTO_UDP => self.udp(mapped(src), mapped(dst), body, ours, false),
            PROTO_TCP if ours => self.tcp(mapped(src), mapped(dst), body),
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
                // Answer with the same identifier, sequence and data: on
                // the transmit page, or if it does not fit there, built
                // for fragments (`m` is never in `pieces()`).
                let len = m.len().min(MAX_DATAGRAM + 8);
                let big = 34 + len > 4096;
                let r = if big {
                    &mut pieces()[..len]
                } else {
                    &mut page(TX_VA)[34..34 + len]
                };
                r.copy_from_slice(&m[..len]);
                r[0] = ICMP_ECHO_REPLY;
                r[2] = 0;
                r[3] = 0;
                let c = fold(sum(0, r));
                put16(r, 2, c);
                if big {
                    self.send_pieces(mapped(src), PROTO_ICMP, len);
                } else {
                    self.ip_send(mapped(src), PROTO_ICMP, len);
                }
            }
            ICMP_ECHO_REPLY => self.deliver(Kind::Icmp(id), mapped(src), seq, &m[8..]),
            ICMP_UNREACHABLE => self.unreachable(m[1], &m[8..]),
            _ => {}
        }
    }

    /// An ICMP "destination unreachable" with code `code`, quoting the
    /// start of the packet it is about: a TCP connection still
    /// connecting fails (QEMU's user network answers a refused connection
    /// with one, on some hosts, rather than a reset).
    fn unreachable(&mut self, code: u8, q: &[u8]) {
        if q.len() < 20 || q[9] != PROTO_TCP {
            return;
        }
        let ihl = (q[0] & 0xf) as usize * 4;
        let Some(t) = q.get(ihl..ihl + 8) else {
            return;
        };
        let (dst, sport, dport, seq) = (be32(q, 16), be16(t, 0), be16(t, 2), be32(t, 4));
        // Port or protocol unreachable: nothing listens there.
        self.tcp_unreachable(mapped(dst), sport, dport, seq, code == 2 || code == 3);
    }

    /// An ICMP or ICMPv6 "unreachable" about a TCP segment from `sport`
    /// to `dst`:`dport` numbered `seq`.
    fn tcp_unreachable(&mut self, dst: u128, sport: u16, dport: u16, seq: u32, refused: bool) {
        let found = (0..CONNS).find(|&c| {
            matches!(&self.conns[c], Some(k) if k.tcb.local_port == sport
                && k.tcb.remote == dst
                && k.tcb.remote_port == dport)
        });
        if let Some(c) = found {
            self.conns[c].as_mut().unwrap().tcb.unreachable(refused, seq);
            self.pump(c);
        }
    }

    /// A UDP datagram; over IPv6 (`six`) its checksum is required.
    fn udp(&mut self, src: u128, dst: u128, u: &[u8], ours: bool, six: bool) {
        if u.len() < 8 {
            return;
        }
        let len = be16(u, 4) as usize;
        if len < 8 || len > u.len() {
            return;
        }
        let u = &u[..len];
        if (six || be16(u, 6) != 0) && fold(sum(pseudo(src, dst, PROTO_UDP, len), u)) != 0 {
            return;
        }
        if !six && be16(u, 2) == DHCP_CLIENT_PORT && be16(u, 0) == DHCP_SERVER_PORT {
            self.dhcp(&u[8..]);
        } else if six && be16(u, 2) == ip6::DHCP6_CLIENT_PORT {
            // (Any source port: QEMU's replies come from 547 byte-swapped.
            // The transaction must match.)
            self.dhcp6(&u[8..]);
        } else if ours {
            self.deliver(Kind::Udp(be16(u, 2)), src, be16(u, 0), &u[8..]);
        }
    }

    /// Queues a payload on the socket of `kind` and signals it.
    fn deliver(&mut self, kind: Kind, src: u128, port: u16, data: &[u8]) {
        let Some(i) = (0..SOCKETS).find(|&i| matches!(&self.sockets[i], Some(s) if s.kind == kind))
        else {
            return;
        };
        let n = data.len().min(MAX_DATAGRAM);
        let mut d = Datagram {
            len: n as u16,
            from: src,
            port,
            pages: [0; DATAGRAM_PAGES],
        };
        let full = self.sockets[i].as_ref().unwrap().count == QUEUE;
        let k = d.page_count();
        if full || !self.take_pages(i, &mut d.pages[..k]) {
            self.sockets[i].as_mut().unwrap().dropped += 1;
            return;
        }
        pool_write(&d.pages, 0, &data[..n]);
        let s = self.sockets[i].as_mut().unwrap();
        let j = (s.head + s.count) % QUEUE;
        s.queue[j] = d;
        s.count += 1;
        syscall(Syscall::Signal, SOCK_NTFN + i as u64, [0; 4]);
    }

    /// Fills `out` with free pool pages for socket `i`, if it may have
    /// that many more and there are; false (and none taken) if not.
    fn take_pages(&mut self, i: usize, out: &mut [u8]) -> bool {
        if self.sockets[i].as_ref().unwrap().pooled + out.len() > SOCKET_POOL {
            return false;
        }
        for k in 0..out.len() {
            let Some(p) = (0..POOL).find(|&p| self.pool[p / 64] & 1 << (p % 64) == 0) else {
                self.give_pages(i, &out[..k]);
                return false;
            };
            self.pool[p / 64] |= 1 << (p % 64);
            out[k] = p as u8;
        }
        self.sockets[i].as_mut().unwrap().pooled += out.len();
        true
    }

    /// Returns socket `i`'s pool pages `pages`.
    fn give_pages(&mut self, i: usize, pages: &[u8]) {
        for &p in pages {
            self.pool[p as usize / 64] &= !(1 << (p % 64));
        }
        self.sockets[i].as_mut().unwrap().pooled -= pages.len();
    }

    /// Returns every pool page socket `i` holds: queued datagrams, the
    /// one held for `RECV_PART` and what is staged.
    fn release(&mut self, i: usize) {
        self.drop_held(i);
        self.drop_staged(i);
        while let Some(s) = self.sockets[i].as_mut().filter(|s| s.count > 0) {
            let d = s.queue[s.head];
            s.head = (s.head + 1) % QUEUE;
            s.count -= 1;
            self.give_pages(i, &d.pages[..d.page_count()]);
        }
    }

    fn drop_held(&mut self, i: usize) {
        if let Some(d) = self.sockets[i].as_mut().unwrap().held.take() {
            self.give_pages(i, &d.pages[..d.page_count()]);
        }
    }

    fn drop_staged(&mut self, i: usize) {
        let s = self.sockets[i].as_mut().unwrap();
        let (stage, n) = (s.stage, s.stage_pages);
        s.staged = 0;
        s.stage_pages = 0;
        self.give_pages(i, &stage[..n]);
    }

    /// Whether to drop this TCP segment (the test setting).
    fn drop_this(&mut self) -> bool {
        if self.drop_one_in == 0 {
            return false;
        }
        self.random ^= self.random << 13;
        self.random ^= self.random >> 7;
        self.random ^= self.random << 17;
        if self.random % self.drop_one_in == 0 {
            count(STAT_TCP_DROPPED, 1);
            return true;
        }
        false
    }

    /// Sends a TCP segment to `dst`.
    fn tcp_emit(&mut self, dst: u128, h: &tcp::Header, a: &[u8], b: &[u8]) {
        if self.drop_this() {
            return;
        }
        let Some(src) = self.source_for(dst) else {
            return;
        };
        let at = Net::payload_at(dst);
        let len = tcp::encode(&mut page(TX_VA)[at..], src, dst, h, a, b);
        self.ip_send(dst, PROTO_TCP, len);
    }

    /// An initial sequence number: a clock (RFC 9293's 4 µs one, from the
    /// tick) mixed with the instance and a count, so a restarted server's
    /// numbers do not repeat its predecessor's.
    fn iss(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        (ticks() as u32).wrapping_mul(2500)
            ^ (self.epoch as u32).wrapping_mul(0x9e37_79b9)
            ^ (self.next_id as u32) << 20
    }

    /// Sends what connection `c` has due, tells its owner of changes, and
    /// frees it once it is done with.
    fn pump(&mut self, c: usize) {
        let Some(k) = self.conns[c] else {
            return;
        };
        let mut t = k.tcb;
        let remote = t.remote;
        t.output(ticks(), &bufs(c), &mut |h, a, b| self.tcp_emit(remote, h, a, b));
        let k = self.conns[c].as_mut().unwrap();
        k.tcb = t;
        let s = t.stats;
        count(STAT_TCP_RESENT, s.retransmitted - k.counted.retransmitted);
        count(STAT_TCP_OUT_OF_ORDER, s.out_of_order - k.counted.out_of_order);
        k.counted = s;
        if t.changed {
            k.tcb.changed = false;
            if let Some(i) = k.socket {
                syscall(Syscall::Signal, SOCK_NTFN + i as u64, [0; 4]);
            } else if let Some(l) = k.listener.filter(|_| t.is_open()) {
                syscall(Syscall::Signal, SOCK_NTFN + l as u64, [0; 4]);
            }
        }
        if t.is_finished() && k.socket.is_none() {
            self.conns[c] = None;
        }
    }

    /// A TCP segment to this host.
    fn tcp(&mut self, src: u128, dst: u128, seg: &[u8]) {
        let Some((h, data)) = tcp::parse(seg, src, dst) else {
            return;
        };
        if self.drop_this() {
            return;
        }
        let now = ticks();
        let found = (0..CONNS).find(|&c| {
            matches!(&self.conns[c], Some(k) if k.tcb.local_port == h.dst_port
                && k.tcb.remote == src
                && k.tcb.remote_port == h.src_port
                && !k.tcb.is_finished())
        });
        if let Some(c) = found {
            let k = self.conns[c].as_mut().unwrap();
            k.tcb.input(now, &h, data, &mut bufs(c));
            self.pump(c);
            return;
        }
        if h.flags & (tcp::SYN | tcp::ACK | tcp::RST) == tcp::SYN {
            let listener = (0..SOCKETS)
                .find(|&i| matches!(&self.sockets[i], Some(s) if s.kind == Kind::Listen(h.dst_port)));
            if let Some(l) = listener {
                let pending = self.conns.iter().flatten().filter(|k| k.listener == Some(l)).count();
                let free = if pending < BACKLOG { self.free_conn() } else { None };
                if let Some(c) = free {
                    let iss = self.iss();
                    self.conns[c] = Some(Conn {
                        tcb: Tcb::accept(iss, src, &h, TCP_BUF, TCP_BUF),
                        socket: None,
                        listener: Some(l),
                        closed_at: None,
                        counted: tcp::Stats::default(),
                    });
                    self.pump(c);
                }
                // With no room, the SYN is dropped: the peer sends it again.
                return;
            }
        }
        if let Some(r) = tcp::reset_for(&h, data.len()) {
            self.tcp_emit(src, &r, &[], &[]);
        }
    }

    /// A free connection slot: an empty one, or else one whose owner is
    /// gone and which only waits out `TIME-WAIT` (the slots are few, and
    /// that wait guards against old segments, which a new connection's
    /// fresh port and sequence numbers already do).
    fn free_conn(&mut self) -> Option<usize> {
        if let Some(c) = (0..CONNS).find(|&c| self.conns[c].is_none()) {
            return Some(c);
        }
        let c = (0..CONNS).find(|&c| {
            matches!(&self.conns[c], Some(k) if k.socket.is_none() && k.tcb.state == tcp::State::TimeWait)
        })?;
        self.conns[c] = None;
        Some(c)
    }

    /// Whether a TCP port is in use, by a listener or a connection.
    fn tcp_port_free(&self, port: u16) -> bool {
        self.listen_port_free(port) && !self.conns.iter().flatten().any(|k| k.tcb.local_port == port)
    }

    /// Whether a TCP port can be listened on: no other listener has it.
    /// Connections on it (those an earlier listener accepted, still
    /// closing) do not stand in the way: segments find them first, by
    /// both ends.
    fn listen_port_free(&self, port: u16) -> bool {
        !self.sockets.iter().flatten().any(|s| s.kind == Kind::Listen(port))
    }

    /// A free ephemeral TCP port, starting somewhere each instance picks,
    /// so a restarted server does not reuse its predecessor's.
    fn tcp_port(&mut self) -> Option<u16> {
        let span = u16::MAX - EPHEMERAL;
        for _ in 0..span {
            self.next_port = self.next_port.wrapping_add(1);
            let p = EPHEMERAL + (self.next_port.wrapping_add((self.epoch as u16).wrapping_mul(97))) % span;
            if self.tcp_port_free(p) {
                return Some(p);
            }
        }
        None
    }

    /// `TCP_CONNECT`: a connection, with its handle and port.
    fn connect(&mut self, badge: u64, to: u128, to_port: u16) -> Result<(u64, u16), Status> {
        if self.source_for(to).is_none() {
            return Err(Status::Unreachable);
        }
        let c = self.free_conn().ok_or(Status::NoSpace)?;
        let port = self.tcp_port().ok_or(Status::NoSpace)?;
        let handle = self.bind(badge, Kind::Tcp(c))?;
        let iss = self.iss();
        self.conns[c] = Some(Conn {
            tcb: Tcb::connect(iss, port, to, to_port, TCP_BUF, TCP_BUF),
            socket: Some((handle & 0xff) as usize),
            listener: None,
            closed_at: None,
            counted: tcp::Stats::default(),
        });
        self.pump(c);
        Ok((handle, port))
    }

    /// `TCP_ACCEPT` on listening socket `l`.
    fn accept(&mut self, badge: u64, l: usize) -> Result<(u64, u64), Status> {
        let c = (0..CONNS)
            .find(|&c| matches!(&self.conns[c], Some(k) if k.listener == Some(l) && k.tcb.is_open()))
            .ok_or(Status::Empty)?;
        let handle = self.bind(badge, Kind::Tcp(c))?;
        let k = self.conns[c].as_mut().unwrap();
        k.listener = None;
        k.socket = Some((handle & 0xff) as usize);
        Ok((handle, word(k.tcb.remote, k.tcb.remote_port)))
    }

    /// `SEND` on connection `c`: bytes taken.
    fn tcp_send(&mut self, c: usize, len: usize) -> [u64; 4] {
        let t = self.conns[c].unwrap().tcb;
        if let Some(e) = t.error {
            return [failed(e) as u64, 0, 0, 0];
        }
        if !t.may_write() && !matches!(t.state, tcp::State::SynSent | tcp::State::SynReceived) {
            // Shut down already.
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let n = len.min(4096).min(t.writable());
        if n == 0 {
            return [Status::Empty as u64, 0, 0, 0];
        }
        if !map_lent(false) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let k = self.conns[c].as_mut().unwrap();
        let n = k.tcb.write(&mut bufs(c), &lent_page()[..n]);
        unmap_lent();
        self.pump(c);
        [Status::Ok as u64, n as u64, 0, 0]
    }

    /// `RECV` on connection `c`.
    fn tcp_recv(&mut self, c: usize) -> [u64; 4] {
        let t = self.conns[c].unwrap().tcb;
        let peer = word(t.remote, t.remote_port);
        if t.readable() == 0 {
            return if t.eof() {
                [Status::Ok as u64, 0, peer, 0]
            } else if let Some(e) = t.error {
                [failed(e) as u64, 0, 0, 0]
            } else {
                [Status::Empty as u64, 0, 0, 0]
            };
        }
        if !map_lent(true) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let k = self.conns[c].as_mut().unwrap();
        let n = k.tcb.read(&bufs(c), &mut lent_page()[..4096]);
        unmap_lent();
        self.pump(c);
        [Status::Ok as u64, n as u64, peer, 0]
    }

    /// Frees socket `i`; its notification is revoked.
    fn unbind(&mut self, i: usize) {
        match self.sockets[i].as_ref().map(|s| s.kind) {
            Some(Kind::Tcp(c)) => {
                if let Some(k) = self.conns[c].as_mut() {
                    k.socket = None;
                    k.closed_at = Some(ticks());
                    if k.tcb.error.is_some() {
                        k.tcb.abort();
                    } else {
                        k.tcb.close();
                    }
                }
                self.pump(c);
            }
            Some(Kind::Listen(_)) => {
                for c in 0..CONNS {
                    if let Some(k) = self.conns[c].as_mut().filter(|k| k.listener == Some(i)) {
                        k.tcb.abort();
                        k.listener = None;
                        self.pump(c);
                    }
                }
            }
            _ => {}
        }
        self.release(i);
        self.sockets[i] = None;
        syscall(Syscall::CapRevoke, SOCK_NTFN + i as u64, [0; 4]);
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
            held: None,
            staged: 0,
            stage_pages: 0,
            stage: [0; DATAGRAM_PAGES],
            pooled: 0,
        });
        Ok(handle)
    }

    fn kind(&self, i: usize) -> Kind {
        self.sockets[i].as_ref().unwrap().kind
    }

    fn port_free(&self, port: u16) -> bool {
        !self
            .sockets
            .iter()
            .flatten()
            .any(|s| s.kind == Kind::Udp(port))
    }

    /// Sends a `len`-byte datagram from socket `i` to `to` (`port` being
    /// the port, or an echo's sequence number); with no `to` (`SEND6`),
    /// the client's page starts with the address. The payload follows on
    /// the page, or, if it does not fit there, is what `SEND_PART`
    /// staged. One too big for the transmit page is built in `pieces()`
    /// and goes in fragments.
    fn send(&mut self, i: usize, to: Option<u128>, port: u16, len: usize) -> Status {
        if len > MAX_DATAGRAM || !map_lent(false) {
            return Status::Invalid;
        }
        let lent = lent_page();
        let (dst, at) = match to {
            Some(d) => (d, 0),
            None => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&lent[..16]);
                (u128::from_be_bytes(a), 16)
            }
        };
        let s = self.sockets[i].as_ref().unwrap();
        let staged = len > 4096 - at;
        if staged && s.staged != len {
            unmap_lent();
            return Status::Invalid;
        }
        let (kind, stage) = (s.kind, s.stage);
        let off = Net::payload_at(dst);
        let big = off + 8 + len > 4096;
        // Where the headers and payload are built.
        let out = if big {
            &mut pieces()[..8 + len]
        } else {
            &mut page(TX_VA)[off..off + 8 + len]
        };
        if staged {
            pool_read(&stage, 0, &mut out[8..]);
        } else {
            out[8..].copy_from_slice(&lent[at..at + len]);
        }
        unmap_lent();
        if staged {
            self.drop_staged(i);
        }
        let proto = match (self.source_for(dst), kind) {
            (None, _) => return Status::Unreachable,
            (Some(src), Kind::Udp(local)) => {
                put16(out, 0, local);
                put16(out, 2, port);
                put16(out, 4, (8 + len) as u16);
                put16(out, 6, 0);
                let c = fold(sum(pseudo(src, dst, PROTO_UDP, 8 + len), out));
                put16(out, 6, if c == 0 { 0xffff } else { c });
                PROTO_UDP
            }
            (Some(src), Kind::Icmp(id)) => {
                let six = ipv4(dst).is_none();
                out[0] = if six { 128 } else { ICMP_ECHO };
                out[1] = 0;
                put16(out, 2, 0);
                put16(out, 4, id);
                put16(out, 6, port);
                let c = if six {
                    fold(sum(pseudo(src, dst, NH_ICMP6, 8 + len), out))
                } else {
                    fold(sum(0, out))
                };
                put16(out, 2, c);
                if six { NH_ICMP6 } else { PROTO_ICMP }
            }
            (_, Kind::Listen(_) | Kind::Tcp(_)) => return Status::Invalid,
        };
        if big {
            self.send_pieces(dst, proto, 8 + len)
        } else {
            self.ip_send(dst, proto, 8 + len)
        }
    }

    /// `SEND_PART`: stages `len` bytes of the client's page as bytes
    /// `offset..` of socket `i`'s next datagram.
    fn send_part(&mut self, i: usize, offset: usize, len: usize) -> Status {
        if !matches!(self.kind(i), Kind::Udp(_) | Kind::Icmp(_)) {
            return Status::Invalid;
        }
        if offset == 0 {
            self.drop_staged(i);
        }
        let s = self.sockets[i].as_ref().unwrap();
        if offset != s.staged || len > 4096 || offset + len > MAX_DATAGRAM {
            return Status::Invalid;
        }
        let (have, need) = (s.stage_pages, (offset + len).div_ceil(4096));
        if need > have {
            let mut more = [0u8; DATAGRAM_PAGES];
            if !self.take_pages(i, &mut more[..need - have]) {
                return Status::NoSpace;
            }
            let s = self.sockets[i].as_mut().unwrap();
            s.stage[have..need].copy_from_slice(&more[..need - have]);
            s.stage_pages = need;
        }
        if !map_lent(false) {
            return Status::Invalid;
        }
        let s = self.sockets[i].as_mut().unwrap();
        pool_write(&s.stage, offset, &lent_page()[..len]);
        s.staged = offset + len;
        unmap_lent();
        Status::Ok
    }

    /// `RECV_PART`: payload bytes `offset..` of the datagram socket `i`
    /// last received, into the client's page.
    fn recv_part(&mut self, i: usize, offset: usize) -> [u64; 4] {
        let Some(d) = self.sockets[i].as_ref().unwrap().held else {
            return [Status::Empty as u64, 0, 0, 0];
        };
        if offset >= d.len as usize {
            return [Status::Empty as u64, 0, 0, 0];
        }
        if !map_lent(true) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let n = (d.len as usize - offset).min(4096);
        pool_read(&d.pages, offset, &mut lent_page()[..n]);
        unmap_lent();
        [Status::Ok as u64, n as u64, 0, 0]
    }

    /// `RECV`, or with `six` `RECV6` (the sender's address first in the
    /// page, then the payload).
    fn recv(&mut self, i: usize, six: bool) -> [u64; 4] {
        self.drop_held(i);
        let s = self.sockets[i].as_mut().unwrap();
        if s.count == 0 {
            return [Status::Empty as u64, 0, 0, 0];
        }
        if !map_lent(true) {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let d = s.queue[s.head];
        let n = d.len as usize;
        let lent = lent_page();
        let at = if six { 16 } else { 0 };
        let first = n.min(4096 - at);
        pool_read(&d.pages, 0, &mut lent[at..at + first]);
        if six {
            lent[..16].copy_from_slice(&d.from.to_be_bytes());
        }
        unmap_lent();
        s.head = (s.head + 1) % QUEUE;
        s.count -= 1;
        // Kept while the client may fetch the rest.
        if first < n {
            s.held = Some(d);
        } else {
            self.give_pages(i, &d.pages[..d.page_count()]);
        }
        let family = if ipv4(d.from).is_some() { 4 } else { 6 };
        if six {
            [Status::Ok as u64, n as u64, d.port as u64, family]
        } else {
            [Status::Ok as u64, n as u64, word(d.from, d.port), family]
        }
    }

    /// The address a client's page starts with (`TCP_CONNECT6`).
    fn lent_addr(&self) -> Option<u128> {
        if !map_lent(false) {
            return None;
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&lent_page()[..16]);
        unmap_lent();
        Some(u128::from_be_bytes(a))
    }

    /// Writes `addrs` to the start of the client's page.
    fn lend_addrs(&self, addrs: &[u128]) -> bool {
        if !map_lent(true) {
            return false;
        }
        for (k, a) in addrs.iter().enumerate() {
            lent_page()[16 * k..16 * k + 16].copy_from_slice(&a.to_be_bytes());
        }
        unmap_lent();
        true
    }

    fn cring_of(&self, owner: u64) -> Option<usize> {
        self.crings.iter().position(|r| r.is_some_and(|r| r.owner == owner))
    }

    /// `RING_ATTACH`: takes page `page` of `owner`'s ring, lent in this
    /// call.
    fn cring_attach(&mut self, owner: u64, page: u64, lent: bool) -> Status {
        if !lent || page >= cring::PAGES {
            return Status::Invalid;
        }
        if page == 0 {
            if let Some(r) = self.cring_of(owner) {
                self.cring_detach(r);
            }
            let Some(r) = self.crings.iter().position(|r| r.is_none()) else {
                return Status::InUse;
            };
            self.crings[r] = Some(ClientRing {
                owner,
                attached: 0,
                started: false,
            });
        }
        let Some(r) = self.cring_of(owner) else {
            return Status::Invalid;
        };
        let mut g = self.crings[r].unwrap();
        if g.started || page != g.attached {
            return Status::Invalid;
        }
        let slot = CRING_PAGES + r as u64 * cring::PAGES + page;
        // A copy of what was lent: the lent capability goes after the call.
        if syscall(Syscall::CapMint, LENT, [slot, 0x1f, 0, 0]).status != 0 {
            return Status::Invalid;
        }
        if syscall(Syscall::FrameMap, slot, [cring_va(r) + page * 4096, 1, 0, 0]).status != 0 {
            syscall(Syscall::CapDelete, slot, [0; 4]);
            return Status::Invalid;
        }
        g.attached += 1;
        self.crings[r] = Some(g);
        Status::Ok
    }

    /// Drops ring `r`: its pages, and the client's copies of its
    /// completion notification.
    fn cring_detach(&mut self, r: usize) {
        let Some(g) = self.crings[r].take() else {
            return;
        };
        for p in 0..g.attached {
            // Deleting the capability unmaps the page.
            syscall(Syscall::CapDelete, CRING_PAGES + r as u64 * cring::PAGES + p, [0; 4]);
        }
        syscall(Syscall::CapRevoke, CRING_NTFN + r as u64, [0; 4]);
    }

    /// `RING_START` and `RING_DOORBELL`: whether MINT now holds what the
    /// reply grants (the completion notification; the doorbell).
    fn cring_grant(&mut self, owner: u64, start: bool) -> Status {
        let Some(r) = self.cring_of(owner) else {
            return Status::NotFound;
        };
        let mut g = self.crings[r].unwrap();
        let (src, rights, badge) = if start {
            if g.started || g.attached != cring::PAGES {
                return Status::Invalid;
            }
            for off in (0..cring::SQ).step_by(4) {
                chdr(cring_va(r), off).store(0, Ordering::Relaxed);
            }
            fence(Ordering::SeqCst);
            g.started = true;
            self.crings[r] = Some(g);
            (CRING_NTFN + r as u64, READ, 0)
        } else {
            if !g.started {
                return Status::Invalid;
            }
            // From the notification itself: a badged copy cannot be badged.
            (SELF, WRITE, RINGBELL)
        };
        syscall(Syscall::CapDelete, MINT, [0; 4]);
        match syscall(Syscall::CapMint, src, [MINT, rights, badge, 0]).status {
            0 => Status::Ok,
            _ => Status::Invalid,
        }
    }

    /// Serves up to a ring's worth of submissions from each client's
    /// ring, completing each as it is served, and wakes the clients that
    /// sleep for completions.
    fn serve_rings(&mut self) {
        for r in 0..MAX_CRINGS {
            let mut served = 0;
            while served < cring::ENTRIES && self.cring_one(r) {
                served += 1;
            }
            if served > 0 && self.crings[r].is_some() {
                let page = cring_va(r);
                // The client sleeps until this many completions wait.
                let w = chdr(page, cring::CLIENT_WAITING);
                let want = w.load(Ordering::Acquire);
                let have = chdr(page, cring::CQ_TAIL)
                    .load(Ordering::Relaxed)
                    .wrapping_sub(chdr(page, cring::CQ_HEAD).load(Ordering::Acquire));
                let idle = chdr(page, cring::SQ_HEAD).load(Ordering::Relaxed)
                    == chdr(page, cring::SQ_TAIL).load(Ordering::Acquire);
                if want != 0
                    && (want <= have || idle)
                    && w.compare_exchange(want, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok()
                {
                    syscall(Syscall::Signal, CRING_NTFN + r as u64, [0; 4]);
                }
            }
        }
    }

    /// Serves ring `r`'s next submission, if it has one and room for its
    /// completion.
    fn cring_one(&mut self, r: usize) -> bool {
        let Some(g) = self.crings[r].filter(|g| g.started) else {
            return false;
        };
        let page = cring_va(r);
        let head = chdr(page, cring::SQ_HEAD).load(Ordering::Relaxed);
        let tail = chdr(page, cring::SQ_TAIL).load(Ordering::Acquire);
        let cq_tail = chdr(page, cring::CQ_TAIL).load(Ordering::Relaxed);
        let cq_head = chdr(page, cring::CQ_HEAD).load(Ordering::Acquire);
        if tail.wrapping_sub(head) > cring::ENTRIES || cq_tail.wrapping_sub(cq_head) > cring::ENTRIES {
            say!("client ring {r}: indices out of range; dropping it");
            self.cring_detach(r);
            return false;
        }
        if head == tail || cq_tail.wrapping_sub(cq_head) == cring::ENTRIES {
            return false; // nothing to do, or the client must reap first
        }
        let sqe = page as usize + cring::SQ + (head % cring::ENTRIES) as usize * cring::SQE;
        // SAFETY: inside the ring page, mapped while attached. Each word
        // is read once: the client may change it at any time.
        let w = |i: usize| unsafe { ((sqe + 8 * i) as *const u64).read_volatile() };
        let (op, tag, m, off) = (w(0), w(1), [w(0), w(2), w(3), w(4)], w(5));
        let lends = matches!(
            op,
            net::SEND | net::SEND6 | net::RECV | net::RECV6 | net::SEND_PART | net::RECV_PART
        );
        let reply = if !lends || off % 4096 != 0 || off >= cring::DATA {
            [Status::Invalid as u64, 0, 0, 0]
        } else {
            // The page the call would have lent is the ring's.
            DATA.store(page + 4096 + off, Ordering::Relaxed);
            let (reply, _) = self.serve(g.owner, m, true);
            DATA.store(LENT_VA, Ordering::Relaxed);
            reply
        };
        self.cring_ops += 1;
        let cqe = page as usize + cring::CQ + (cq_tail % cring::ENTRIES) as usize * cring::CQE;
        for (i, v) in [tag, reply[0], reply[1], reply[2], reply[3]].iter().enumerate() {
            // SAFETY: inside the ring page, mapped while attached.
            unsafe { ((cqe + 8 * i) as *mut u64).write_volatile(*v) };
        }
        chdr(page, cring::CQ_TAIL).store(cq_tail.wrapping_add(1), Ordering::Release);
        chdr(page, cring::SQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Whether some client's ring has a submission there is room to
    /// complete.
    fn cring_work(&self) -> bool {
        (0..MAX_CRINGS).any(|r| {
            let page = cring_va(r);
            self.crings[r].is_some_and(|g| g.started)
                && chdr(page, cring::SQ_HEAD).load(Ordering::Relaxed)
                    != chdr(page, cring::SQ_TAIL).load(Ordering::Acquire)
                && chdr(page, cring::CQ_TAIL)
                    .load(Ordering::Relaxed)
                    .wrapping_sub(chdr(page, cring::CQ_HEAD).load(Ordering::Acquire))
                    < cring::ENTRIES
        })
    }

    /// Tells every ring's client whether this server sleeps.
    fn cring_sleeps(&self, on: bool) {
        for r in 0..MAX_CRINGS {
            if self.crings[r].is_some_and(|g| g.started) {
                chdr(cring_va(r), cring::FLAGS).store(on as u32 * cring::NEED_WAKEUP, Ordering::SeqCst);
            }
        }
    }

    /// One client call: the reply, and whether MINT is granted with it.
    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], bool) {
        let status = |s: Status| ([s as u64, 0, 0, 0], false);
        match m[0] {
            net::RING_STATS if m[1] == net::VERSION => {
                ([Status::Ok as u64, self.cring_ops, self.cring_bells, 0], false)
            }
            net::RING_ATTACH => status(self.cring_attach(badge, m[1], lent)),
            net::RING_START | net::RING_DOORBELL => {
                let s = self.cring_grant(badge, m[0] == net::RING_START);
                ([s as u64, 0, 0, 0], s == Status::Ok)
            }
            net::LINK_STATS if m[1] == net::VERSION => (
                [
                    Status::Ok as u64,
                    counted(STAT_RING_FRAMES),
                    counted(STAT_CALL_FRAMES),
                    counted(STAT_RINGS),
                ],
                false,
            ),
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
            net::SEND if lent => match self.socket(badge, m[1]).map(|i| (i, self.kind(i))) {
                Some((_, Kind::Tcp(c))) => (self.tcp_send(c, m[3] as usize), false),
                Some((_, Kind::Listen(_))) => status(Status::Invalid),
                Some((i, _)) => status(self.send(i, Some(mapped((m[2] >> 16) as u32)), m[2] as u16, m[3] as usize)),
                None => status(Status::NotFound),
            },
            net::SEND6 if lent => match self.socket(badge, m[1]).map(|i| (i, self.kind(i))) {
                Some((i, Kind::Udp(_) | Kind::Icmp(_))) => status(self.send(i, None, m[2] as u16, m[3] as usize)),
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::SEND_PART if lent => match self.socket(badge, m[1]) {
                Some(i) => status(self.send_part(i, m[2] as usize, m[3] as usize)),
                None => status(Status::NotFound),
            },
            net::RECV_PART if lent => match self.socket(badge, m[1]).map(|i| (i, self.kind(i))) {
                Some((i, Kind::Udp(_) | Kind::Icmp(_))) => (self.recv_part(i, m[2] as usize), false),
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::RECV | net::RECV6 if lent => match self.socket(badge, m[1]).map(|i| (i, self.kind(i))) {
                Some((_, Kind::Tcp(c))) if m[0] == net::RECV => (self.tcp_recv(c), false),
                Some((i, Kind::Udp(_) | Kind::Icmp(_))) => (self.recv(i, m[0] == net::RECV6), false),
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::INFO6 if lent && m[1] == net::VERSION => {
                let v = self.v6;
                if v.global == 0 {
                    return status(Status::Unreachable);
                }
                if !self.lend_addrs(&[v.ll, v.global, v.router, v.dns]) {
                    return status(Status::Invalid);
                }
                let now = ticks();
                (
                    [
                        Status::Ok as u64,
                        v.prefix_len as u64,
                        v.valid_until.saturating_sub(now) / SECOND,
                        v.router_until.saturating_sub(now) / SECOND,
                    ],
                    false,
                )
            }
            net::TCP_CONNECT6 if lent => match self.lent_addr() {
                Some(a) => match self.connect(badge, a, m[1] as u16) {
                    Ok((h, port)) => ([Status::Ok as u64, h, port as u64, 0], true),
                    Err(s) => status(s),
                },
                None => status(Status::Invalid),
            },
            net::TCP_PEER if lent => match self.socket(badge, m[1]).map(|i| self.kind(i)) {
                Some(Kind::Tcp(c)) => {
                    let t = self.conns[c].unwrap().tcb;
                    if !self.lend_addrs(&[t.remote]) {
                        return status(Status::Invalid);
                    }
                    let family = if ipv4(t.remote).is_some() { 4 } else { 6 };
                    ([Status::Ok as u64, t.remote_port as u64, family, 0], false)
                }
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::CLOSE => match self.socket(badge, m[1]) {
                Some(i) => {
                    self.unbind(i);
                    status(Status::Ok)
                }
                None => status(Status::NotFound),
            },
            net::TCP_CONNECT => match self.connect(badge, mapped((m[1] >> 16) as u32), m[1] as u16) {
                Ok((h, port)) => ([Status::Ok as u64, h, port as u64, 0], true),
                Err(s) => status(s),
            },
            net::TCP_LISTEN => {
                let port = m[1] as u16;
                if port == 0 || m[1] > u16::MAX as u64 {
                    return status(Status::Invalid);
                }
                if !self.listen_port_free(port) {
                    return status(Status::InUse);
                }
                match self.bind(badge, Kind::Listen(port)) {
                    Ok(h) => ([Status::Ok as u64, h, port as u64, 0], true),
                    Err(s) => status(s),
                }
            }
            net::TCP_ACCEPT => match self.socket(badge, m[1]).map(|i| (i, self.kind(i))) {
                Some((l, Kind::Listen(_))) => match self.accept(badge, l) {
                    Ok((h, peer)) => ([Status::Ok as u64, h, peer, 0], true),
                    Err(s) => status(s),
                },
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::TCP_SHUTDOWN | net::TCP_STATE => match self.socket(badge, m[1]).map(|i| self.kind(i)) {
                Some(Kind::Tcp(c)) => {
                    if m[0] == net::TCP_SHUTDOWN {
                        self.conns[c].as_mut().unwrap().tcb.close();
                        self.pump(c);
                        return status(Status::Ok);
                    }
                    let t = self.conns[c].unwrap().tcb;
                    (
                        [Status::Ok as u64, state_number(t.state), t.unacked() as u64, t.readable() as u64],
                        false,
                    )
                }
                Some(_) => status(Status::Invalid),
                None => status(Status::NotFound),
            },
            net::TCP_STATS if m[1] == net::VERSION => (
                [
                    Status::Ok as u64,
                    counted(STAT_TCP_RESENT),
                    counted(STAT_TCP_DROPPED),
                    counted(STAT_TCP_OUT_OF_ORDER),
                ],
                false,
            ),
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
    for r in 0..MAX_CRINGS as u64 {
        retype(ObjectType::Notification, CRING_NTFN + r)?;
    }
    if syscall(Syscall::CapMint, SELF, [CRING_BELL, WRITE, RINGBELL, 0]).status != 0 {
        return Err(("minting the rings' doorbell", 0));
    }
    // Pages made at start: (first slot, where they go, how many).
    let runs = [
        (POOL_PAGES, POOL_VA, POOL, "a pool page"),
        (TCP_PAGES, TCP_VA, CONNS * 4, "a TCP page"),
        (LOOP_PAGES, LOOP_VA, LOOPBACK, "a loopback page"),
        (WHOLE_PAGES, WHOLE_VA, BIG_PAGES, "a reassembly page"),
        (PIECES_PAGES, PIECES_VA, BIG_PAGES, "a fragmenting page"),
        (REASM_PAGES, REASM_VA, REASM_SIZE.div_ceil(4096), "a reassembler page"),
    ];
    for (slot, va, n, what) in runs {
        for k in 0..n as u64 {
            retype(ObjectType::Frame, slot + k)?;
            if syscall(Syscall::FrameMap, slot + k, [va + 0x1000 * k, 1, 0, 0]).status != 0 {
                return Err((what, k));
            }
        }
    }
    // SAFETY: its pages were just mapped, writable, at REASM_VA.
    unsafe { Reassembler::init(REASM_VA as *mut Reassembler<REASSEMBLING>) };
    if syscall(Syscall::FrameMap, STATE, [STATE_VA, 1, 0, 0]).status != 0 {
        return Err(("mapping the state page", STATE));
    }
    n.epoch = ticks() & 0xffff;
    let info = (0..100).find_map(|_| {
        let r = syscall(Syscall::Call, NIC, [nic::INFO, nic::VERSION, 0, 0]);
        if r.status == 0 && r.msg[0] == Status::Ok as u64 {
            return Some(r.msg);
        }
        superior_sys::sleep(1);
        None
    });
    let info = info.ok_or(("the NIC driver does not answer", 0))?;
    for (i, b) in n.mac.iter_mut().enumerate() {
        *b = (info[1] >> (40 - 8 * i)) as u8;
    }
    n.attach();
    n.ring_setup();
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
    n.start6();
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    // SAFETY: the one thread is the only user of NET.
    let n = unsafe { &mut *(&raw mut NET) };
    n.renew_every = arg & 0xffff_ffff;
    n.drop_one_in = arg >> 32;
    if let Err((what, code)) = start(n) {
        say!("[fail] {what} ({code})");
        superior_sys::park()
    }
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    loop {
        // Clients' rings first: what they send goes out, and what they
        // ask to receive is answered, with no call. One pass, so calls get
        // their turn; if work is left the server rings its own doorbell
        // rather than sleep on it.
        n.serve_rings();
        n.run_loopback();
        n.cring_sleeps(true);
        fence(Ordering::SeqCst);
        if n.cring_work() {
            n.cring_sleeps(false);
            syscall(Syscall::Signal, CRING_BELL, [0; 4]);
        }
        // With a ring, received frames are taken here, whatever woke the
        // server, and never by a call.
        n.before_sleep();
        n.run_loopback();
        let r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
        n.cring_sleeps(false);
        if n.ring_up {
            hdr(ring::CALLER_SLEEPS).store(0, Ordering::SeqCst);
        }
        if r.status == Error::Notified.code() {
            n.cring_bells += (r.badge & RINGBELL != 0) as u64;
            let timer = r.badge & TIMER != 0;
            if timer {
                syscall(Syscall::TimerSignal, TIMER_CAP, [PERIOD, 0, 0, 0]);
                n.tick();
            }
            if timer || !n.ring_up {
                n.drain();
            }
            n.run_loopback();
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
        n.run_loopback();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
