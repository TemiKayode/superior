//! TCP (RFC 9293), as a state machine with no I/O of its own: the network
//! server feeds it segments ([`Tcb::input`]) and the timer
//! ([`Tcb::tick`]), and sends what [`Tcb::output`] hands it. Host tests
//! run two of them over a link that loses, reorders and repeats segments.
//!
//! What it does: the three-way handshake (active, passive and
//! simultaneous), the MSS option, sliding windows both ways, data that
//! arrives out of order kept (up to [`HOLES`] ranges) and handed on in
//! order, retransmission on a timer estimated from round trips (RFC 6298,
//! Karn's rule, backing off), fast retransmit after three duplicate ACKs,
//! slow start and congestion avoidance (RFC 5681), probes of a zero
//! window, half-close, `TIME-WAIT`, resets (RFC 5961's checks against
//! blind ones), and giving up after [`MAX_RETRIES`] timeouts. Not done:
//! window scaling, timestamps, SACK, urgent data.
//!
//! Times are in ticks of 10 ms. Each connection's bytes live in two rings
//! the caller owns ([`Bufs`]), powers of two in size, indexed by sequence
//! number: the byte numbered `s` is at `s % size`.

/// Flags.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// The largest segment sent over IPv4: a 1500-byte packet's payload less
/// the headers; and over IPv6, whose header is 20 bytes longer.
pub const MSS: u32 = 1460;
pub const MSS6: u32 = 1440;
/// The MSS assumed when the peer gives none (RFC 9293).
const DEFAULT_MSS: u32 = 536;
/// Retransmission timeouts: the first (1 s), the least and the most.
pub const INITIAL_RTO: u64 = 100;
pub const MIN_RTO: u64 = 20;
pub const MAX_RTO: u64 = 600;
/// Timeouts in a row with no ACK before the connection is given up.
pub const MAX_RETRIES: u32 = 10;
/// How long a connection stays in `TIME-WAIT` (2 s; RFC 9293's 2 MSL is
/// for the open internet).
pub const TIME_WAIT: u64 = 200;
/// Out-of-order ranges kept.
pub const HOLES: usize = 4;

/// Sequence number order (RFC 9293's modular comparisons).
fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Why a connection ended badly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The peer answered the SYN with a reset: nothing listens there.
    Refused,
    /// The peer reset the connection.
    Reset,
    /// No answer after [`MAX_RETRIES`] timeouts.
    TimedOut,
    /// An ICMP "destination unreachable" (other than for the port or the
    /// protocol) answered the SYN.
    Unreachable,
}

/// A segment's header.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Header {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// The MSS option, on a SYN.
    pub mss: Option<u16>,
}

use crate::{fold, pseudo, sum};

/// The header and payload of segment `b`, which came from `src` to `dst`;
/// `None` if it is malformed or its checksum is wrong.
pub fn parse(b: &[u8], src: u128, dst: u128) -> Option<(Header, &[u8])> {
    if b.len() < 20 || fold(sum(pseudo(src, dst, 6, b.len()), b)) != 0 {
        return None;
    }
    let off = (b[12] >> 4) as usize * 4;
    if off < 20 || off > b.len() {
        return None;
    }
    let be16 = |at: usize| u16::from_be_bytes([b[at], b[at + 1]]);
    let be32 = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let mut h = Header {
        src_port: be16(0),
        dst_port: be16(2),
        seq: be32(4),
        ack: be32(8),
        flags: b[13] & 0x3f,
        window: be16(14),
        mss: None,
    };
    let mut at = 20;
    while at < off {
        match b[at] {
            0 => break,
            1 => at += 1,
            kind => {
                let n = *b.get(at + 1)? as usize;
                if n < 2 || at + n > off {
                    return None;
                }
                if kind == 2 && n == 4 {
                    h.mss = Some(be16(at + 2));
                }
                at += n;
            }
        }
    }
    Some((h, &b[off..]))
}

/// Writes segment `h` with payload `a` then `b` into `out`, from `src` to
/// `dst`, checksum and all; returns its length.
pub fn encode(out: &mut [u8], src: u128, dst: u128, h: &Header, a: &[u8], b: &[u8]) -> usize {
    let hl = if h.mss.is_some() { 24 } else { 20 };
    let len = hl + a.len() + b.len();
    let s = &mut out[..len];
    s[0..2].copy_from_slice(&h.src_port.to_be_bytes());
    s[2..4].copy_from_slice(&h.dst_port.to_be_bytes());
    s[4..8].copy_from_slice(&h.seq.to_be_bytes());
    s[8..12].copy_from_slice(&h.ack.to_be_bytes());
    s[12] = (hl as u8 / 4) << 4;
    s[13] = h.flags;
    s[14..16].copy_from_slice(&h.window.to_be_bytes());
    s[16..20].fill(0);
    if let Some(m) = h.mss {
        s[20] = 2;
        s[21] = 4;
        s[22..24].copy_from_slice(&m.to_be_bytes());
    }
    s[hl..hl + a.len()].copy_from_slice(a);
    s[hl + a.len()..].copy_from_slice(b);
    let c = fold(sum(pseudo(src, dst, 6, len), s));
    s[16..18].copy_from_slice(&c.to_be_bytes());
    len
}

/// The answer to segment `h` (with `len` bytes of payload) that arrived
/// where no connection is (RFC 9293 3.10.7.1): a reset, unless it was one.
pub fn reset_for(h: &Header, len: usize) -> Option<Header> {
    if h.flags & RST != 0 {
        return None;
    }
    let mut r = Header {
        src_port: h.dst_port,
        dst_port: h.src_port,
        flags: RST,
        ..Header::default()
    };
    if h.flags & ACK != 0 {
        r.seq = h.ack;
    } else {
        let n = len as u32 + (h.flags & SYN != 0) as u32 + (h.flags & FIN != 0) as u32;
        r.ack = h.seq.wrapping_add(n);
        r.flags |= ACK;
    }
    Some(r)
}

/// A connection's two rings: bytes to send (until acknowledged) and bytes
/// received (until read). Each a power of two in size, at most 64 KiB.
pub struct Bufs<'a> {
    pub tx: &'a mut [u8],
    pub rx: &'a mut [u8],
}

/// Copies `out.len()` bytes from ring `r` starting at sequence `seq`.
fn ring_read(r: &[u8], seq: u32, out: &mut [u8]) {
    let at = seq as usize & (r.len() - 1);
    let first = out.len().min(r.len() - at);
    out[..first].copy_from_slice(&r[at..at + first]);
    let rest = out.len() - first;
    out[first..].copy_from_slice(&r[..rest]);
}

fn ring_write(r: &mut [u8], seq: u32, data: &[u8]) {
    let at = seq as usize & (r.len() - 1);
    let first = data.len().min(r.len() - at);
    r[at..at + first].copy_from_slice(&data[..first]);
    let rest = data.len() - first;
    r[..rest].copy_from_slice(&data[first..]);
}

/// The `len` bytes of ring `r` from `seq`, as up to two slices.
fn ring_slices(r: &[u8], seq: u32, len: usize) -> (&[u8], &[u8]) {
    let at = seq as usize & (r.len() - 1);
    let first = len.min(r.len() - at);
    (&r[at..at + first], &r[..len - first])
}

/// Counts for tests and statistics.
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    /// Segments sent again (on a timeout, or fast).
    pub retransmitted: u64,
    /// Fast retransmits, after three duplicate ACKs.
    pub fast: u64,
    /// Segments that arrived ahead of a gap and were kept.
    pub out_of_order: u64,
    /// Zero-window probes.
    pub probes: u64,
}

/// One connection: its transmission control block.
#[derive(Clone, Copy, Debug)]
pub struct Tcb {
    pub state: State,
    pub error: Option<Error>,
    pub local_port: u16,
    /// The peer's address (an IPv4 one as in [`crate::mapped`]).
    pub remote: u128,
    pub remote_port: u16,
    /// Something the owner may want to know happened: data or room
    /// arrived, the state changed. The caller clears it.
    pub changed: bool,
    pub stats: Stats,
    tx_size: u32,
    rx_size: u32,
    /// The largest segment this side takes and sends.
    max_seg: u32,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// The highest sequence number sent, plus one.
    snd_max: u32,
    /// The end of the data queued to send (the FIN's number, once queued).
    snd_end: u32,
    fin_queued: bool,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,
    fast_retransmit: bool,
    probe: bool,
    rcv_nxt: u32,
    /// The next byte the owner reads.
    rcv_read: u32,
    /// The window last advertised.
    adv_wnd: u32,
    fin_at: Option<u32>,
    fin_received: bool,
    holes: [Option<(u32, u32)>; HOLES],
    need_ack: bool,
    /// A reset to send, with this sequence number.
    pending_rst: Option<u32>,
    /// RFC 6298's estimates: SRTT times 8, RTTVAR times 4.
    srtt8: u64,
    rttvar4: u64,
    rto: u64,
    /// The segment being timed: its end, and when it went.
    timing: Option<(u32, u64)>,
    /// When the retransmission (or persist) timer fires.
    deadline: Option<u64>,
    retries: u32,
    time_wait_until: u64,
}

impl Tcb {
    fn new(iss: u32, local_port: u16, remote: u128, remote_port: u16, tx_size: usize, rx_size: usize) -> Tcb {
        assert!(tx_size.is_power_of_two() && rx_size.is_power_of_two() && rx_size <= 65536);
        Tcb {
            state: State::Closed,
            error: None,
            local_port,
            remote,
            remote_port,
            changed: false,
            stats: Stats::default(),
            tx_size: tx_size as u32,
            rx_size: rx_size as u32,
            max_seg: if crate::ipv4(remote).is_some() { MSS } else { MSS6 },
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_end: iss.wrapping_add(1),
            fin_queued: false,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            mss: DEFAULT_MSS,
            cwnd: 4 * MSS,
            ssthresh: u32::MAX,
            dupacks: 0,
            fast_retransmit: false,
            probe: false,
            rcv_nxt: 0,
            rcv_read: 0,
            adv_wnd: 0,
            fin_at: None,
            fin_received: false,
            holes: [None; HOLES],
            need_ack: false,
            pending_rst: None,
            srtt8: 0,
            rttvar4: 0,
            rto: INITIAL_RTO,
            timing: None,
            deadline: None,
            retries: 0,
            time_wait_until: 0,
        }
    }

    /// An active open to `remote`:`remote_port`; the SYN goes with the
    /// next [`Tcb::output`]. Segments are sized for `remote`'s family.
    pub fn connect(iss: u32, local_port: u16, remote: u128, remote_port: u16, tx_size: usize, rx_size: usize) -> Tcb {
        let mut t = Tcb::new(iss, local_port, remote, remote_port, tx_size, rx_size);
        t.state = State::SynSent;
        t
    }

    /// A passive open: the connection SYN `syn` from `remote` asks for, to
    /// a port listened on. The SYN-ACK goes with the next output.
    pub fn accept(iss: u32, remote: u128, syn: &Header, tx_size: usize, rx_size: usize) -> Tcb {
        let mut t = Tcb::new(iss, syn.dst_port, remote, syn.src_port, tx_size, rx_size);
        t.state = State::SynReceived;
        t.synchronize(syn);
        t
    }

    /// Takes the peer's sequence numbers and options from its SYN.
    fn synchronize(&mut self, syn: &Header) {
        self.rcv_nxt = syn.seq.wrapping_add(1);
        self.rcv_read = self.rcv_nxt;
        self.mss = syn.mss.map_or(DEFAULT_MSS, |m| (m as u32).clamp(64, self.max_seg));
        self.cwnd = 4 * self.mss;
        self.snd_wnd = syn.window as u32;
        self.snd_wl1 = syn.seq;
        self.snd_wl2 = syn.ack;
    }

    /// The receive window: room left in the receive ring.
    fn rcv_wnd(&self) -> u32 {
        self.rx_size - self.rcv_nxt.wrapping_sub(self.rcv_read)
    }

    /// The first byte of data not yet acknowledged.
    fn data_una(&self) -> u32 {
        let first = self.iss.wrapping_add(1);
        if lt(self.snd_una, first) { first } else { self.snd_una }
    }

    /// Bytes queued and not yet acknowledged.
    pub fn unacked(&self) -> usize {
        let una = self.data_una();
        if lt(self.snd_end, una) {
            0
        } else {
            self.snd_end.wrapping_sub(una) as usize
        }
    }

    /// Bytes that may be read now.
    pub fn readable(&self) -> usize {
        self.rcv_nxt.wrapping_sub(self.rcv_read) as usize - self.fin_received as usize
    }

    /// Room to write.
    pub fn writable(&self) -> usize {
        if self.may_write() {
            self.tx_size as usize - self.unacked()
        } else {
            0
        }
    }

    /// Whether the owner may still write: connected, and not shut down.
    pub fn may_write(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait) && !self.fin_queued
    }

    /// The peer has sent all it will, and it has all been read.
    pub fn eof(&self) -> bool {
        self.fin_received && self.readable() == 0
    }

    /// Whether the connection is synchronized and has not been closed by
    /// either side's FIN being acknowledged.
    pub fn is_open(&self) -> bool {
        !matches!(self.state, State::Closed | State::SynSent | State::SynReceived)
    }

    /// Whether this connection is done with: nothing more to send or wait
    /// for.
    pub fn is_finished(&self) -> bool {
        self.state == State::Closed && self.pending_rst.is_none()
    }

    /// Queues `data` to send; returns how much fitted.
    pub fn write(&mut self, b: &mut Bufs, data: &[u8]) -> usize {
        let n = data.len().min(self.writable());
        ring_write(b.tx, self.snd_end, &data[..n]);
        self.snd_end = self.snd_end.wrapping_add(n as u32);
        n
    }

    /// Reads what has arrived in order into `out`; returns how much.
    pub fn read(&mut self, b: &Bufs, out: &mut [u8]) -> usize {
        let n = out.len().min(self.readable());
        ring_read(b.rx, self.rcv_read, &mut out[..n]);
        self.rcv_read = self.rcv_read.wrapping_add(n as u32);
        // The window opened up: say so, rather than wait for the peer's
        // probe.
        let opened = self.rcv_wnd();
        let small = self.mss.min(self.rx_size / 2);
        if n > 0 && self.adv_wnd < small && opened >= small && self.is_open() {
            self.need_ack = true;
        }
        n
    }

    /// No more data from this side: a FIN follows what is queued.
    pub fn close(&mut self) {
        match self.state {
            State::SynSent => self.state = State::Closed,
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
                self.fin_queued = true;
            }
            State::CloseWait => {
                self.state = State::LastAck;
                self.fin_queued = true;
            }
            _ => {}
        }
    }

    /// Drops the connection, with a reset if the peer knows of it.
    pub fn abort(&mut self) {
        if !matches!(self.state, State::Closed | State::SynSent | State::TimeWait) {
            self.pending_rst = Some(self.snd_max);
        }
        self.state = State::Closed;
        self.deadline = None;
    }

    fn fail(&mut self, e: Error) {
        self.state = State::Closed;
        self.error = Some(e);
        self.deadline = None;
        self.changed = true;
    }

    /// A segment for this connection (its ports and addresses matched).
    pub fn input(&mut self, now: u64, h: &Header, data: &[u8], b: &mut Bufs) {
        match self.state {
            State::Closed => return,
            State::SynSent => return self.input_syn_sent(now, h),
            _ => {}
        }
        // A SYN again at the peer's first number (its SYN-ACK when both
        // opened at once, or one repeated because our ACK was lost)
        // counts for its ACK alone.
        let mut stripped;
        let mut h = h;
        if h.flags & SYN != 0 && h.seq.wrapping_add(1) == self.rcv_nxt.wrapping_sub(self.fin_received as u32) && self.fin_at.is_none() {
            self.need_ack = true;
            if h.flags & ACK == 0 {
                return;
            }
            stripped = *h;
            stripped.flags &= !SYN;
            stripped.seq = stripped.seq.wrapping_add(1);
            h = &stripped;
        }
        let syn_fin = (h.flags & SYN != 0) as u32 + (h.flags & FIN != 0) as u32;
        let seg_len = data.len() as u32 + syn_fin;
        let wnd = self.rcv_wnd();
        let in_window = |s: u32| le(self.rcv_nxt, s) && lt(s, self.rcv_nxt.wrapping_add(wnd));
        let acceptable = match (seg_len, wnd) {
            (0, 0) => h.seq == self.rcv_nxt,
            (0, _) => in_window(h.seq),
            (_, 0) => false,
            _ => in_window(h.seq) || in_window(h.seq.wrapping_add(seg_len - 1)),
        };
        if !acceptable {
            if h.flags & RST != 0 {
                return;
            }
            self.need_ack = true;
            if self.state == State::TimeWait && h.flags & FIN != 0 {
                self.time_wait_until = now + TIME_WAIT;
            }
            // With the window shut, data is refused but its ACK still
            // counts (RFC 9293 3.10.7.4).
            if wnd == 0 && h.seq == self.rcv_nxt && h.flags & ACK != 0 && self.is_open() {
                self.ack(now, h, data.len());
            }
            return;
        }
        if h.flags & RST != 0 {
            // TIME-WAIT ignores resets (RFC 1337): the peer, done, answers
            // our last ACK again with one.
            if self.state == State::TimeWait {
                return;
            }
            // Only a reset exactly at the next number counts; others get
            // a challenge ACK (RFC 5961).
            if h.seq == self.rcv_nxt {
                self.fail(Error::Reset);
            } else {
                self.need_ack = true;
            }
            return;
        }
        if h.flags & SYN != 0 {
            self.need_ack = true;
            return;
        }
        if h.flags & ACK == 0 {
            return;
        }
        if self.state == State::SynReceived {
            if lt(self.snd_una, h.ack) && le(h.ack, self.snd_max) {
                self.state = State::Established;
                self.snd_wnd = h.window as u32;
                self.snd_wl1 = h.seq;
                self.snd_wl2 = h.ack;
                self.changed = true;
            } else {
                self.pending_rst = Some(h.ack);
                return;
            }
        }
        self.ack(now, h, data.len());
        if self.state == State::Closed {
            return;
        }
        let receiving = matches!(self.state, State::Established | State::FinWait1 | State::FinWait2);
        if !data.is_empty() && receiving {
            self.receive(h.seq, data, b);
        }
        if h.flags & FIN != 0 && receiving {
            self.fin_at = Some(h.seq.wrapping_add(data.len() as u32));
        }
        if !data.is_empty() || h.flags & FIN != 0 {
            self.need_ack = true;
        }
        self.take_fin(now);
    }

    fn input_syn_sent(&mut self, now: u64, h: &Header) {
        let has_ack = h.flags & ACK != 0;
        let ack_ok = has_ack && lt(self.iss, h.ack) && le(h.ack, self.snd_max);
        if has_ack && !ack_ok {
            if h.flags & RST == 0 {
                self.pending_rst = Some(h.ack);
            }
            return;
        }
        if h.flags & RST != 0 {
            if ack_ok {
                self.fail(Error::Refused);
            }
            return;
        }
        if h.flags & SYN == 0 {
            return;
        }
        self.synchronize(h);
        if ack_ok {
            self.snd_una = h.ack;
            if let Some((end, at)) = self.timing.take() {
                if le(end, h.ack) {
                    self.sample(now - at);
                }
            }
            self.deadline = None;
            self.retries = 0;
            self.state = State::Established;
            self.changed = true;
        } else {
            // Both sides opened at once: answer with a SYN-ACK.
            self.state = State::SynReceived;
            self.snd_nxt = self.iss;
        }
        self.need_ack = true;
    }

    /// A round-trip sample of `r` ticks (RFC 6298).
    fn sample(&mut self, r: u64) {
        let r = r.max(1);
        if self.srtt8 == 0 {
            self.srtt8 = 8 * r;
            self.rttvar4 = 2 * r;
        } else {
            let srtt = self.srtt8 / 8;
            let delta = srtt.abs_diff(r);
            self.rttvar4 = self.rttvar4 - self.rttvar4 / 4 + delta;
            self.srtt8 = self.srtt8 - self.srtt8 / 8 + r;
        }
        self.rto = (self.srtt8 / 8 + self.rttvar4.max(1)).clamp(MIN_RTO, MAX_RTO);
    }

    /// The ACK field and window of an acceptable segment.
    fn ack(&mut self, now: u64, h: &Header, len: usize) {
        let ack = h.ack;
        if lt(self.snd_max, ack) {
            // Acknowledges what was never sent.
            self.need_ack = true;
            return;
        }
        if lt(ack, self.snd_una) {
            return;
        }
        // The peer is there: timeouts start counting again.
        self.retries = 0;
        let old_wnd = self.snd_wnd;
        if lt(self.snd_una, ack) {
            let acked = ack.wrapping_sub(self.snd_una);
            self.snd_una = ack;
            if lt(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            if let Some((end, at)) = self.timing {
                if le(end, ack) {
                    self.timing = None;
                    self.sample(now - at);
                }
            }
            self.dupacks = 0;
            // Slow start, then congestion avoidance.
            if self.cwnd < self.ssthresh {
                self.cwnd += acked.min(self.mss);
            } else {
                self.cwnd += (self.mss * self.mss / self.cwnd).max(1);
            }
            self.deadline = (self.snd_una != self.snd_max).then_some(now + self.rto);
            self.changed = true;
            if self.fin_queued && self.snd_una == self.snd_end.wrapping_add(1) {
                match self.state {
                    State::FinWait1 => self.state = State::FinWait2,
                    State::Closing => self.enter_time_wait(now),
                    State::LastAck => {
                        self.state = State::Closed;
                        self.deadline = None;
                    }
                    _ => {}
                }
            }
        } else if len == 0
            && h.flags & (SYN | FIN) == 0
            && h.window as u32 == self.snd_wnd
            && self.snd_wnd > 0
            && self.snd_una != self.snd_max
        {
            self.dupacks += 1;
            if self.dupacks == 3 {
                let flight = self.snd_max.wrapping_sub(self.snd_una);
                self.ssthresh = (flight / 2).max(2 * self.mss);
                self.cwnd = self.ssthresh + 3 * self.mss;
                self.fast_retransmit = true;
                self.stats.fast += 1;
            } else if self.dupacks > 3 {
                self.cwnd += self.mss;
            }
        }
        if lt(self.snd_wl1, h.seq) || (self.snd_wl1 == h.seq && le(self.snd_wl2, ack)) {
            self.snd_wnd = h.window as u32;
            self.snd_wl1 = h.seq;
            self.snd_wl2 = ack;
            if old_wnd == 0 && self.snd_wnd > 0 {
                // The window opened: anything probed past it goes again.
                self.snd_nxt = self.snd_una;
                self.changed = true;
            }
        }
    }

    /// Stores data that arrived; hands on what is now in order.
    fn receive(&mut self, seq: u32, data: &[u8], b: &mut Bufs) {
        let (mut seq, mut d) = (seq, data);
        if lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= d.len() {
                return;
            }
            d = &d[skip..];
            seq = self.rcv_nxt;
        }
        let room = self.rcv_nxt.wrapping_add(self.rcv_wnd()).wrapping_sub(seq) as usize;
        d = &d[..d.len().min(room)];
        if d.is_empty() {
            return;
        }
        ring_write(b.rx, seq, d);
        let end = seq.wrapping_add(d.len() as u32);
        if seq == self.rcv_nxt {
            self.rcv_nxt = end;
            // Fill from the ranges that arrived ahead.
            loop {
                let mut moved = false;
                for h in self.holes.iter_mut() {
                    if let Some((s, e)) = *h {
                        if le(s, self.rcv_nxt) {
                            if lt(self.rcv_nxt, e) {
                                self.rcv_nxt = e;
                            }
                            *h = None;
                            moved = true;
                        }
                    }
                }
                if !moved {
                    break;
                }
            }
            self.changed = true;
        } else {
            self.stats.out_of_order += 1;
            let (mut s, mut e) = (seq, end);
            for h in self.holes.iter_mut() {
                if let Some((hs, he)) = *h {
                    if le(hs, e) && le(s, he) {
                        if lt(hs, s) {
                            s = hs;
                        }
                        if lt(e, he) {
                            e = he;
                        }
                        *h = None;
                    }
                }
            }
            // With no room to note it, the range is simply sent again.
            if let Some(h) = self.holes.iter_mut().find(|h| h.is_none()) {
                *h = Some((s, e));
            }
        }
    }

    /// Takes the peer's FIN once everything before it has arrived.
    fn take_fin(&mut self, now: u64) {
        if self.fin_received || self.fin_at != Some(self.rcv_nxt) {
            return;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.need_ack = true;
        self.changed = true;
        match self.state {
            State::Established => self.state = State::CloseWait,
            State::FinWait1 => {
                if self.fin_queued && self.snd_una == self.snd_end.wrapping_add(1) {
                    self.enter_time_wait(now);
                } else {
                    self.state = State::Closing;
                }
            }
            State::FinWait2 => self.enter_time_wait(now),
            _ => {}
        }
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.state = State::TimeWait;
        self.time_wait_until = now + TIME_WAIT;
        self.deadline = None;
        self.changed = true;
    }

    /// An ICMP "destination unreachable" about this connection's segment
    /// numbered `seq`: while connecting, it ends the attempt (`refused`
    /// for a port or protocol unreachable). Later ones are soft errors,
    /// left to the retransmission timer (RFC 1122 4.2.3.9).
    pub fn unreachable(&mut self, refused: bool, seq: u32) {
        if self.state == State::SynSent && seq == self.iss {
            self.fail(if refused { Error::Refused } else { Error::Unreachable });
        }
    }

    /// The timer: retransmission, zero-window probes, the end of
    /// `TIME-WAIT`. Call it at least every 100 ms.
    pub fn tick(&mut self, now: u64) {
        if self.state == State::TimeWait {
            if now >= self.time_wait_until {
                self.state = State::Closed;
                self.changed = true;
            }
            return;
        }
        let Some(d) = self.deadline else {
            return;
        };
        if now < d || self.state == State::Closed {
            return;
        }
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.fail(Error::TimedOut);
            return;
        }
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.deadline = Some(now + self.rto);
        self.timing = None;
        self.dupacks = 0;
        if self.snd_wnd == 0 && self.is_open() {
            self.probe = true;
            self.snd_nxt = self.snd_una;
            return;
        }
        if self.snd_una == self.snd_max && self.is_open() {
            self.deadline = None;
            return;
        }
        // Go back to the oldest unacknowledged byte, starting slow.
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.snd_nxt = self.snd_una;
    }

    fn header(&self, seq: u32, flags: u8) -> Header {
        Header {
            src_port: self.local_port,
            dst_port: self.remote_port,
            seq,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.rcv_wnd().min(65535) as u16,
            mss: None,
        }
    }

    /// Sends what is due through `emit` (a header, and the payload in two
    /// pieces): a SYN, data the windows allow, a FIN, an ACK, a reset.
    pub fn output(&mut self, now: u64, b: &Bufs, emit: &mut dyn FnMut(&Header, &[u8], &[u8])) {
        if let Some(seq) = self.pending_rst.take() {
            let mut h = self.header(seq, RST);
            h.window = 0;
            emit(&h, &[], &[]);
        }
        match self.state {
            State::Closed => {
                self.need_ack = false;
                return;
            }
            State::TimeWait => {
                if self.need_ack {
                    let h = self.header(self.snd_max, ACK);
                    emit(&h, &[], &[]);
                    self.need_ack = false;
                }
                return;
            }
            State::SynSent | State::SynReceived => {
                let resend = self.state == State::SynReceived && self.need_ack;
                if self.snd_nxt == self.iss || resend {
                    let flags = if self.state == State::SynSent { SYN } else { SYN | ACK };
                    let mut h = self.header(self.iss, flags);
                    h.mss = Some(self.max_seg as u16);
                    emit(&h, &[], &[]);
                    if self.snd_max == self.iss {
                        self.timing = Some((self.iss.wrapping_add(1), now));
                    } else {
                        self.stats.retransmitted += 1;
                    }
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.snd_max = self.snd_nxt;
                    self.adv_wnd = h.window as u32;
                    if self.deadline.is_none() {
                        self.deadline = Some(now + self.rto);
                    }
                }
                self.need_ack = false;
                return;
            }
            _ => {}
        }
        let mut sent = false;
        if self.fast_retransmit {
            self.fast_retransmit = false;
            let n = (self.snd_end.wrapping_sub(self.snd_una) as usize).min(self.mss as usize);
            if lt(self.snd_una, self.snd_end) && n > 0 {
                let (a, c) = ring_slices(b.tx, self.snd_una, n);
                let h = self.header(self.snd_una, ACK);
                emit(&h, a, c);
                self.stats.retransmitted += 1;
                self.timing = None;
                sent = true;
            }
        }
        loop {
            let avail = if lt(self.snd_nxt, self.snd_end) {
                self.snd_end.wrapping_sub(self.snd_nxt)
            } else {
                0
            };
            let wnd = self.snd_wnd.min(self.cwnd);
            let edge = self.snd_una.wrapping_add(wnd);
            let room = if lt(self.snd_nxt, edge) { edge.wrapping_sub(self.snd_nxt) } else { 0 };
            let mut n = avail.min(room).min(self.mss);
            if n == 0 && avail > 0 && self.probe {
                n = 1;
                self.stats.probes += 1;
            }
            self.probe = false;
            let fin = self.fin_queued && n == avail && self.snd_nxt.wrapping_add(n) == self.snd_end;
            if n == 0 && !fin {
                break;
            }
            let mut flags = ACK;
            if fin {
                flags |= FIN;
            }
            if n > 0 && n == avail {
                flags |= PSH;
            }
            let h = self.header(self.snd_nxt, flags);
            let (a, c) = ring_slices(b.tx, self.snd_nxt, n as usize);
            emit(&h, a, c);
            self.adv_wnd = h.window as u32;
            let len = n + fin as u32;
            if self.snd_nxt == self.snd_max {
                if self.timing.is_none() {
                    self.timing = Some((self.snd_nxt.wrapping_add(len), now));
                }
            } else {
                self.stats.retransmitted += 1;
            }
            self.snd_nxt = self.snd_nxt.wrapping_add(len);
            if lt(self.snd_max, self.snd_nxt) {
                self.snd_max = self.snd_nxt;
            }
            sent = true;
            if fin {
                break;
            }
        }
        if self.need_ack && !sent {
            // At the highest number sent, not one gone back to: an ACK
            // below the peer's window would be dropped.
            let h = self.header(self.snd_max, ACK);
            emit(&h, &[], &[]);
            self.adv_wnd = h.window as u32;
        }
        self.need_ack = false;
        // The retransmission timer runs while anything is unacknowledged;
        // the persist timer while data waits on a shut window.
        let waiting = self.snd_wnd == 0 && lt(self.snd_nxt, self.snd_end);
        if self.deadline.is_none() && (self.snd_una != self.snd_max || waiting) {
            self.deadline = Some(now + self.rto);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const A: u128 = crate::mapped(0x0a00_0001);
    const B: u128 = crate::mapped(0x0a00_0002);
    /// Two IPv6 hosts, for the tests over IPv6.
    const A6: u128 = 0xfd00_0003_0000_0000_0000_0000_0000_0001;
    const B6: u128 = 0xfd00_0003_0000_0000_0000_0000_0000_0002;

    /// A tiny deterministic generator.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn chance(&mut self, percent: u64) -> bool {
            self.next() % 100 < percent
        }
    }

    struct Packet {
        at: u64,
        to_b: bool,
        bytes: Vec<u8>,
    }

    /// A link between A and B that loses, delays (so reorders) and
    /// repeats segments.
    struct Link {
        rng: Rng,
        loss: u64,
        dup: u64,
        jitter: u64,
        q: Vec<Packet>,
        sent: u64,
        /// A's address and B's.
        addrs: (u128, u128),
        /// The longest segment sent.
        biggest: usize,
    }

    impl Link {
        fn new(seed: u64, loss: u64, dup: u64, jitter: u64) -> Link {
            Link {
                rng: Rng(seed),
                loss,
                dup,
                jitter,
                q: Vec::new(),
                sent: 0,
                addrs: (A, B),
                biggest: 0,
            }
        }

        fn send(&mut self, now: u64, to_b: bool, h: &Header, a: &[u8], c: &[u8]) {
            let (x, y) = self.addrs;
            let (src, dst) = if to_b { (x, y) } else { (y, x) };
            let mut buf = vec![0u8; 24 + a.len() + c.len()];
            let n = encode(&mut buf, src, dst, h, a, c);
            buf.truncate(n);
            self.sent += 1;
            self.biggest = self.biggest.max(n);
            if self.rng.chance(self.loss) {
                return;
            }
            let copies = 1 + self.rng.chance(self.dup) as u64;
            for _ in 0..copies {
                let at = now + 1 + self.rng.next() % (self.jitter + 1);
                self.q.push(Packet {
                    at,
                    to_b,
                    bytes: buf.clone(),
                });
            }
        }

        fn due(&mut self, now: u64) -> Vec<Packet> {
            let (due, rest) = self.q.drain(..).partition(|p| p.at <= now);
            self.q = rest;
            due
        }
    }

    struct End {
        tcb: Option<Tcb>,
        tx: Vec<u8>,
        rx: Vec<u8>,
        /// Data to send, how much has been queued, and what arrived.
        out: Vec<u8>,
        queued: usize,
        got: Vec<u8>,
        /// Whether to close once everything is queued.
        close_after: bool,
        reading: bool,
        listening: Option<u16>,
    }

    impl End {
        fn new(size: usize, out: Vec<u8>) -> End {
            End {
                tcb: None,
                tx: vec![0; size],
                rx: vec![0; size],
                out,
                queued: 0,
                got: Vec::new(),
                close_after: true,
                reading: true,
                listening: None,
            }
        }

        fn app(&mut self) {
            let Some(t) = self.tcb.as_mut() else { return };
            let mut b = Bufs {
                tx: &mut self.tx,
                rx: &mut self.rx,
            };
            if self.queued < self.out.len() {
                self.queued += t.write(&mut b, &self.out[self.queued..]);
            }
            if self.queued == self.out.len() && self.close_after && t.may_write() {
                t.close();
            }
            if self.reading {
                let mut tmp = [0u8; 3000];
                loop {
                    let n = t.read(&b, &mut tmp);
                    if n == 0 {
                        break;
                    }
                    self.got.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt ^ (i >> 8) as u8)).collect()
    }

    /// Runs A and B over `link` until both are done or `limit` ticks pass.
    fn run(a: &mut End, b: &mut End, link: &mut Link, limit: u64) -> u64 {
        for now in 0..limit {
            for p in link.due(now) {
                let (x, y) = link.addrs;
                let (dst, src, end) = if p.to_b { (y, x, &mut *b) } else { (x, y, &mut *a) };
                let (h, data) = parse(&p.bytes, src, dst).expect("a good checksum");
                let mut bufs = Bufs {
                    tx: &mut end.tx,
                    rx: &mut end.rx,
                };
                match end.tcb.as_mut() {
                    Some(t) if !t.is_finished() => t.input(now, &h, data, &mut bufs),
                    _ => {
                        if end.listening == Some(h.dst_port) && h.flags & (SYN | ACK | RST) == SYN {
                            end.tcb = Some(Tcb::accept(0x8000_0000 ^ 77, src, &h, end.tx.len(), end.rx.len()));
                            end.listening = None;
                        } else if let Some(r) = reset_for(&h, data.len()) {
                            link.send(now, !p.to_b, &r, &[], &[]);
                        }
                    }
                }
            }
            for (end, to_b) in [(&mut *a, true), (&mut *b, false)] {
                end.app();
                if let Some(t) = end.tcb.as_mut() {
                    t.tick(now);
                    let bufs = Bufs {
                        tx: &mut end.tx,
                        rx: &mut end.rx,
                    };
                    t.output(now, &bufs, &mut |h, x, y| link.send(now, to_b, h, x, y));
                }
            }
            let done = |e: &End| e.tcb.is_some_and(|t| t.state == State::Closed);
            if done(a) && done(b) && link.q.is_empty() {
                return now;
            }
        }
        limit
    }

    fn pair(size: usize, a_out: Vec<u8>, b_out: Vec<u8>) -> (End, End) {
        let mut a = End::new(size, a_out);
        let mut b = End::new(size, b_out);
        a.tcb = Some(Tcb::connect(0xffff_fff0, 40000, B, 80, size, size));
        b.listening = Some(80);
        (a, b)
    }

    #[test]
    fn segments_round_trip() {
        let h = Header {
            src_port: 1,
            dst_port: 2,
            seq: 3,
            ack: 4,
            flags: SYN | ACK,
            window: 5,
            mss: Some(1460),
        };
        let mut buf = [0u8; 64];
        let n = encode(&mut buf, A, B, &h, b"he", b"llo");
        let (g, d) = parse(&buf[..n], A, B).unwrap();
        assert_eq!((g, d), (h, &b"hello"[..]));
        buf[25] ^= 1;
        assert!(parse(&buf[..n], A, B).is_none());
        // The pseudo-header counts.
        buf[25] ^= 1;
        assert!(parse(&buf[..n], A, B + 1).is_none());
    }

    #[test]
    fn a_clean_transfer_both_ways() {
        let (mut a, mut b) = pair(4096, pattern(100_000, 1), pattern(70_000, 2));
        let mut link = Link::new(1, 0, 0, 0);
        let t = run(&mut a, &mut b, &mut link, 20_000);
        assert!(t < 20_000, "not done");
        assert_eq!(b.got, a.out);
        assert_eq!(a.got, b.out);
        let (ta, tb) = (a.tcb.unwrap(), b.tcb.unwrap());
        assert_eq!((ta.error, tb.error), (None, None));
        assert_eq!(ta.stats.retransmitted + tb.stats.retransmitted, 0);
        // The sequence numbers wrapped past zero on A's side.
        assert!(ta.snd_una < 0x1000_0000);
    }

    #[test]
    fn a_lossy_reordering_repeating_link() {
        for seed in 1..=12 {
            let (mut a, mut b) = pair(8192, pattern(150_000, 3), pattern(90_000, 4));
            let mut link = Link::new(seed * 7919, 10, 5, 6);
            let t = run(&mut a, &mut b, &mut link, 200_000);
            assert!(t < 200_000, "seed {seed}: not done");
            assert_eq!(b.got.len(), a.out.len(), "seed {seed}");
            assert!(b.got == a.out && a.got == b.out, "seed {seed}: bytes differ");
            let (ta, tb) = (a.tcb.unwrap(), b.tcb.unwrap());
            assert_eq!((ta.error, tb.error), (None, None), "seed {seed}");
            let s = ta.stats;
            assert!(s.retransmitted > 0 && tb.stats.out_of_order > 0, "seed {seed}: {s:?}");
        }
    }

    #[test]
    fn over_ipv6_with_its_smaller_segments() {
        let size = 8192;
        let mut a = End::new(size, pattern(60_000, 11));
        let mut b = End::new(size, pattern(30_000, 12));
        a.tcb = Some(Tcb::connect(77, 40000, B6, 80, size, size));
        b.listening = Some(80);
        let mut link = Link::new(21, 5, 2, 4);
        link.addrs = (A6, B6);
        let t = run(&mut a, &mut b, &mut link, 100_000);
        assert!(t < 100_000);
        assert!(b.got == a.out && a.got == b.out);
        let ta = a.tcb.unwrap();
        assert_eq!((ta.mss, ta.remote), (MSS6, B6));
        // A checksum over IPv6's pseudo-header fails over IPv4's.
        let h = Header { flags: ACK, ..Header::default() };
        let mut buf = [0u8; 64];
        let n = encode(&mut buf, A6, B6, &h, b"x", &[]);
        assert!(parse(&buf[..n], A6, B6).is_some());
        assert!(parse(&buf[..n], A, B).is_none());
        assert_eq!(link.biggest, 20 + MSS6 as usize);
    }

    #[test]
    fn heavy_loss_still_gets_through() {
        let (mut a, mut b) = pair(4096, pattern(20_000, 5), pattern(5_000, 6));
        let mut link = Link::new(99, 30, 0, 3);
        let t = run(&mut a, &mut b, &mut link, 300_000);
        assert!(t < 300_000);
        assert!(b.got == a.out && a.got == b.out);
    }

    #[test]
    fn a_shut_window_is_probed_and_reopens() {
        let (mut a, mut b) = pair(2048, pattern(30_000, 7), Vec::new());
        b.reading = false;
        let mut link = Link::new(5, 0, 0, 0);
        // B does not read: its window shuts, and A probes it.
        run(&mut a, &mut b, &mut link, 1_500);
        let ta = a.tcb.unwrap();
        assert_eq!(ta.snd_wnd, 0);
        assert!(ta.stats.probes >= 2, "{:?}", ta.stats);
        assert_eq!(ta.error, None);
        assert_eq!(b.tcb.unwrap().readable(), 2048);
        // Now it reads, and everything comes through.
        b.reading = true;
        let t = run(&mut a, &mut b, &mut link, 20_000);
        assert!(t < 20_000);
        assert_eq!(b.got, a.out);
    }

    #[test]
    fn half_close_keeps_the_other_way_open() {
        let (mut a, mut b) = pair(4096, b"request".to_vec(), Vec::new());
        b.close_after = false;
        let mut link = Link::new(3, 0, 0, 0);
        run(&mut a, &mut b, &mut link, 200);
        let tb = b.tcb.unwrap();
        assert_eq!(tb.state, State::CloseWait);
        assert!(tb.eof());
        assert_eq!(a.tcb.unwrap().state, State::FinWait2);
        // B answers after A's FIN, then closes.
        b.out = pattern(10_000, 8);
        b.close_after = true;
        let t = run(&mut a, &mut b, &mut link, 5_000);
        assert!(t < 5_000);
        assert_eq!(a.got, b.out);
        assert_eq!(b.got, b"request");
    }

    #[test]
    fn nobody_listening_refuses() {
        let (mut a, mut b) = pair(4096, Vec::new(), Vec::new());
        b.listening = None;
        let mut link = Link::new(4, 0, 0, 0);
        run(&mut a, &mut b, &mut link, 50);
        let ta = a.tcb.unwrap();
        assert_eq!((ta.state, ta.error), (State::Closed, Some(Error::Refused)));
    }

    #[test]
    fn icmp_unreachable_ends_only_a_connection_attempt() {
        let mut t = Tcb::connect(500, 1, B, 2, 1024, 1024);
        t.unreachable(true, 499);
        assert_eq!(t.state, State::SynSent);
        t.unreachable(true, 500);
        assert_eq!((t.state, t.error), (State::Closed, Some(Error::Refused)));
        let mut t = Tcb::connect(500, 1, B, 2, 1024, 1024);
        t.unreachable(false, 500);
        assert_eq!(t.error, Some(Error::Unreachable));
        let (mut a, mut b) = pair(4096, Vec::new(), Vec::new());
        a.close_after = false;
        b.close_after = false;
        run(&mut a, &mut b, &mut Link::new(2, 0, 0, 0), 30);
        let ta = a.tcb.as_mut().unwrap();
        ta.unreachable(true, 0xffff_fff0);
        assert_eq!(ta.state, State::Established);
    }

    #[test]
    fn a_lost_syn_is_sent_again() {
        let (mut a, mut b) = pair(4096, b"x".to_vec(), b"y".to_vec());
        let mut link = Link::new(6, 0, 0, 0);
        link.loss = 100;
        run(&mut a, &mut b, &mut link, 150);
        assert!(a.tcb.unwrap().stats.retransmitted >= 1 && link.sent >= 2);
        link.loss = 0;
        let t = run(&mut a, &mut b, &mut link, 5_000);
        assert!(t < 5_000);
        assert_eq!((a.got.as_slice(), b.got.as_slice()), (&b"y"[..], &b"x"[..]));
    }

    #[test]
    fn a_vanished_peer_times_out() {
        let (mut a, mut b) = pair(4096, pattern(500_000, 9), Vec::new());
        b.close_after = false;
        let mut link = Link::new(8, 0, 0, 0);
        a.close_after = false;
        run(&mut a, &mut b, &mut link, 30);
        assert_eq!(a.tcb.unwrap().state, State::Established);
        // B goes silent: A gives up after its retries.
        link.loss = 100;
        run(&mut a, &mut b, &mut link, 10_000);
        let ta = a.tcb.unwrap();
        assert_eq!((ta.state, ta.error), (State::Closed, Some(Error::TimedOut)));
    }

    #[test]
    fn a_restarted_peer_resets_the_connection() {
        let (mut a, mut b) = pair(4096, Vec::new(), Vec::new());
        a.close_after = false;
        b.close_after = false;
        let mut link = Link::new(10, 0, 0, 0);
        run(&mut a, &mut b, &mut link, 30);
        assert_eq!(a.tcb.unwrap().state, State::Established);
        // B forgets the connection (a crash), then A sends.
        b.tcb = None;
        a.out = b"hello?".to_vec();
        a.queued = 0;
        run(&mut a, &mut b, &mut link, 50);
        let ta = a.tcb.unwrap();
        assert_eq!((ta.state, ta.error), (State::Closed, Some(Error::Reset)));
    }

    #[test]
    fn a_blind_reset_is_challenged_not_taken() {
        let (mut a, mut b) = pair(4096, Vec::new(), Vec::new());
        a.close_after = false;
        b.close_after = false;
        let mut link = Link::new(11, 0, 0, 0);
        run(&mut a, &mut b, &mut link, 30);
        let t = a.tcb.as_mut().unwrap();
        let h = Header {
            src_port: 80,
            dst_port: 40000,
            seq: t.rcv_nxt.wrapping_add(100),
            flags: RST,
            ..Header::default()
        };
        let mut bufs = Bufs {
            tx: &mut a.tx,
            rx: &mut a.rx,
        };
        t.input(31, &h, &[], &mut bufs);
        assert_eq!(t.state, State::Established);
        let mut acks = 0;
        t.output(31, &bufs, &mut |h, _, _| acks += (h.flags == ACK) as u32);
        assert_eq!(acks, 1);
    }

    #[test]
    fn both_open_at_once() {
        let size = 4096;
        let mut a = End::new(size, b"from a".to_vec());
        let mut b = End::new(size, b"from b".to_vec());
        a.tcb = Some(Tcb::connect(1000, 5000, B, 6000, size, size));
        b.tcb = Some(Tcb::connect(9000, 6000, A, 5000, size, size));
        let mut link = Link::new(12, 0, 0, 0);
        let t = run(&mut a, &mut b, &mut link, 5_000);
        assert!(t < 5_000);
        assert_eq!((a.got.as_slice(), b.got.as_slice()), (&b"from b"[..], &b"from a"[..]));
    }

    #[test]
    fn round_trips_set_the_timeout() {
        let (mut a, mut b) = pair(4096, pattern(40_000, 10), Vec::new());
        let mut link = Link::new(13, 0, 0, 0);
        run(&mut a, &mut b, &mut link, 20_000);
        // One tick each way: the timeout falls to its floor.
        assert_eq!(a.tcb.unwrap().rto, MIN_RTO);
    }

    #[test]
    fn a_reset_answers_strays() {
        let syn = Header {
            src_port: 1,
            dst_port: 2,
            seq: 100,
            flags: SYN,
            ..Header::default()
        };
        let r = reset_for(&syn, 0).unwrap();
        assert_eq!((r.flags, r.seq, r.ack), (RST | ACK, 0, 101));
        let data = Header {
            flags: ACK,
            ack: 555,
            ..syn
        };
        let r = reset_for(&data, 10).unwrap();
        assert_eq!((r.flags, r.seq), (RST, 555));
        assert!(reset_for(&Header { flags: RST, ..syn }, 0).is_none());
    }
}
