//! A DHCPv6 client for one address (RFC 8415): the stateful half, used
//! when a router advertisement says addresses are managed (its M flag).
//! Solicit, Advertise, Request, Reply; then Renew with the server that
//! gave the address at T1, Rebind with any server at T2, and the address
//! is lost when its valid lifetime ends.
//!
//! This is the exchange alone, with no I/O: [`Client::poll`] says what to
//! send (to `ff02::1:2`, port 547, from the link-local address, port
//! 546) and [`Client::receive`] takes what arrives. Times are the
//! caller's ticks, `second` of them to a second.

const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const RENEW: u8 = 5;
const REBIND: u8 = 6;
const REPLY: u8 = 7;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ORO: u16 = 6;
const OPT_ELAPSED: u16 = 8;
const OPT_STATUS: u16 = 13;
const OPT_DNS: u16 = 23;

/// The longest server identifier kept (RFC 8415 allows 130 bytes; none
/// in use comes near).
const MAX_DUID: usize = 40;
/// The most bytes a message of this client's takes.
pub const MAX_MESSAGE: usize = 4 + 14 + 4 + MAX_DUID + 6 + 6 + 16 + 28;
/// Requests to one server before soliciting again (REQ_MAX_RC).
const REQUEST_TRIES: u8 = 10;
/// The longest wait between retransmissions, in seconds.
const MAX_WAIT: u64 = 120;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Not asked to get an address.
    Idle,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// What [`Client::receive`] or [`Client::poll`] found out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// The address is the client's (or still is, renewed), valid for
    /// this many ticks; and the DNS server the reply named (0: none).
    Bound { addr: u128, valid: u64, dns: u128 },
    /// The address ran out, or the server took it back.
    Lost { addr: u128 },
}

#[derive(Clone, Copy)]
pub struct Client {
    /// This client's identifier: a DUID-LL, from the MAC address.
    duid: [u8; 10],
    iaid: u32,
    second: u64,
    pub state: State,
    xid: u32,
    server: [u8; MAX_DUID],
    server_len: usize,
    /// The address offered or held.
    pub addr: u128,
    preferred: u32,
    valid: u32,
    /// When the exchange in progress began, when to send next, and how
    /// many times it has been sent.
    began: u64,
    next: u64,
    tries: u8,
    t1_at: u64,
    t2_at: u64,
    valid_until: u64,
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The options in `b`: (code, data) for each, stopping at a malformed
/// one.
fn options(b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0;
    core::iter::from_fn(move || {
        if at + 4 > b.len() {
            return None;
        }
        let (code, n) = (be16(b, at), be16(b, at + 2) as usize);
        let data = b.get(at + 4..at + 4 + n)?;
        at += 4 + n;
        Some((code, data))
    })
}

impl Client {
    /// A client for the interface with this MAC address; `second` ticks
    /// make a second.
    pub const fn new(mac: [u8; 6], second: u64) -> Client {
        Client {
            // DUID-LL (type 3), hardware type Ethernet (1).
            duid: [0, 3, 0, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]],
            iaid: u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]),
            second,
            state: State::Idle,
            xid: 0,
            server: [0; MAX_DUID],
            server_len: 0,
            addr: 0,
            preferred: 0,
            valid: 0,
            began: 0,
            next: 0,
            tries: 0,
            t1_at: 0,
            t2_at: 0,
            valid_until: 0,
        }
    }

    /// Begins `state`'s exchange, with a new transaction.
    fn begin(&mut self, state: State, now: u64) {
        self.state = state;
        self.xid = self.xid.wrapping_mul(0x9e37_79b1).wrapping_add(0x7f4a_7c15 ^ now as u32) & 0xff_ffff;
        (self.began, self.next, self.tries) = (now, now, 0);
    }

    /// Starts looking for an address, if it is not already (or has one):
    /// a router said addresses are managed. `seed` varies the
    /// transaction numbers.
    pub fn start(&mut self, seed: u32, now: u64) {
        if self.state == State::Idle {
            self.xid ^= seed;
            self.begin(State::Soliciting, now);
        }
    }

    /// Gives up the address and stops (no router says addresses are
    /// managed any more).
    pub fn stop(&mut self) {
        self.state = State::Idle;
        self.addr = 0;
    }

    /// What is due at `now`: a message written to `out` (its length), to
    /// send to all DHCPv6 servers; and the address's loss, when its time
    /// runs out. Call it every tick or so.
    pub fn poll(&mut self, now: u64, out: &mut [u8; MAX_MESSAGE]) -> (Option<usize>, Option<Event>) {
        let mut event = None;
        match self.state {
            State::Idle => return (None, None),
            State::Bound if now >= self.t2_at => self.begin(State::Rebinding, now),
            State::Bound if now >= self.t1_at => self.begin(State::Renewing, now),
            State::Bound => return (None, None),
            State::Renewing if now >= self.t2_at => self.begin(State::Rebinding, now),
            State::Rebinding if now >= self.valid_until => {
                event = Some(Event::Lost { addr: self.addr });
                self.addr = 0;
                self.begin(State::Soliciting, now);
            }
            State::Requesting if self.tries >= REQUEST_TRIES => self.begin(State::Soliciting, now),
            _ => {}
        }
        if now < self.next {
            return (None, event);
        }
        // Sent again after 1 s, then twice as long each time.
        let wait = (1u64 << self.tries.min(7)).min(MAX_WAIT);
        self.next = now + wait * self.second;
        self.tries = self.tries.saturating_add(1);
        (Some(self.message(now, out)), event)
    }

    /// The message for the state the client is in.
    fn message(&self, now: u64, out: &mut [u8; MAX_MESSAGE]) -> usize {
        let (kind, to_server, with_addr) = match self.state {
            State::Requesting => (REQUEST, true, true),
            State::Renewing => (RENEW, true, true),
            State::Rebinding => (REBIND, false, true),
            _ => (SOLICIT, false, false),
        };
        out[0] = kind;
        out[1..4].copy_from_slice(&self.xid.to_be_bytes()[1..]);
        let mut at = 4;
        let mut option = |out: &mut [u8; MAX_MESSAGE], code: u16, data: &[u8]| {
            put16(out, at, code);
            put16(out, at + 2, data.len() as u16);
            out[at + 4..at + 4 + data.len()].copy_from_slice(data);
            at += 4 + data.len();
        };
        option(out, OPT_CLIENTID, &self.duid);
        if to_server {
            option(out, OPT_SERVERID, &self.server[..self.server_len]);
        }
        // Hundredths of a second since the exchange began.
        let elapsed = ((now - self.began) * 100 / self.second.max(1)).min(0xffff) as u16;
        option(out, OPT_ELAPSED, &elapsed.to_be_bytes());
        option(out, OPT_ORO, &OPT_DNS.to_be_bytes());
        // The identity association: its number, T1 and T2 left to the
        // server, and the address asked for once one is known.
        let mut ia = [0u8; 12 + 28];
        put32(&mut ia, 0, self.iaid);
        let mut len = 12;
        if with_addr {
            put16(&mut ia, 12, OPT_IAADDR);
            put16(&mut ia, 14, 24);
            ia[16..32].copy_from_slice(&self.addr.to_be_bytes());
            put32(&mut ia, 32, self.preferred);
            put32(&mut ia, 36, self.valid);
            len = 40;
        }
        option(out, OPT_IA_NA, &ia[..len]);
        at
    }

    /// A message from a server (the UDP payload).
    pub fn receive(&mut self, m: &[u8], now: u64) -> Option<Event> {
        if m.len() < 4 || m[1..4] != self.xid.to_be_bytes()[1..] {
            return None;
        }
        let (mut ours, mut server, mut dns) = (false, None, 0u128);
        // (address, preferred, valid, T1, T2) and whether the server
        // refused, here or in the association.
        let (mut lease, mut refused) = (None, false);
        for (code, d) in options(&m[4..]) {
            match code {
                OPT_CLIENTID => ours = d == self.duid,
                OPT_SERVERID if d.len() <= MAX_DUID => server = Some(d),
                OPT_DNS if d.len() >= 16 => dns = u128::from_be_bytes(d[..16].try_into().unwrap()),
                OPT_STATUS if d.len() >= 2 => refused |= be16(d, 0) != 0,
                OPT_IA_NA if d.len() >= 12 && be32(d, 0) == self.iaid => {
                    let (t1, t2) = (be32(d, 4), be32(d, 8));
                    for (code, a) in options(&d[12..]) {
                        match code {
                            OPT_IAADDR if a.len() >= 24 => {
                                let addr = u128::from_be_bytes(a[..16].try_into().unwrap());
                                lease = Some((addr, be32(a, 16), be32(a, 20), t1, t2));
                            }
                            OPT_STATUS if a.len() >= 2 => refused |= be16(a, 0) != 0,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        let server = server?;
        if !ours {
            return None;
        }
        // An address with no valid lifetime is one taken back.
        let lease = lease.filter(|l| l.2 > 0 && !refused);
        match (self.state, m[0]) {
            (State::Soliciting, ADVERTISE) => {
                let (addr, preferred, valid, _, _) = lease?;
                self.server[..server.len()].copy_from_slice(server);
                self.server_len = server.len();
                (self.addr, self.preferred, self.valid) = (addr, preferred, valid);
                self.begin(State::Requesting, now);
                None
            }
            (State::Requesting | State::Renewing | State::Rebinding, REPLY) => {
                let Some((addr, preferred, valid, t1, t2)) = lease else {
                    // Refused, or the binding is gone: from the start.
                    let lost = (self.state != State::Requesting).then_some(Event::Lost { addr: self.addr });
                    self.addr = 0;
                    self.begin(State::Soliciting, now);
                    return lost;
                };
                // A Rebind may be answered by another server.
                self.server[..server.len()].copy_from_slice(server);
                self.server_len = server.len();
                let lost = (self.addr != addr && self.state != State::Requesting)
                    .then_some(Event::Lost { addr: self.addr });
                (self.addr, self.preferred, self.valid) = (addr, preferred, valid);
                // Where the server names no times: half and four fifths
                // of the preferred lifetime (RFC 8415, 14.2).
                let life = |s: u32| if s == u32::MAX { u64::MAX / 4 } else { s as u64 * self.second };
                let pick = |t: u32, part: u64| match t {
                    0 => life(preferred.min(valid)) / 10 * part,
                    t => life(t),
                };
                self.t1_at = now.saturating_add(pick(t1, 5));
                self.t2_at = now.saturating_add(pick(t2, 8)).max(self.t1_at);
                self.valid_until = now.saturating_add(life(valid));
                self.state = State::Bound;
                // A changed address: the old one is gone first.
                lost.or(Some(Event::Bound {
                    addr,
                    valid: life(valid),
                    dns,
                }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const ADDR: u128 = 0x2001_0db8 << 96 | 0x1234;
    const DNS: u128 = 0x2001_0db8 << 96 | 0x53;
    const SERVER: &[u8] = &[0, 1, 0, 1, 9, 9, 9, 9, 1, 2, 3, 4, 5, 6];
    /// Ticks a second in these tests.
    const S: u64 = 100;

    fn option(v: &mut Vec<u8>, code: u16, data: &[u8]) {
        v.extend(code.to_be_bytes());
        v.extend((data.len() as u16).to_be_bytes());
        v.extend(data);
    }

    /// What a client message holds: its type, transaction, and options.
    fn parse(m: &[u8]) -> (u8, [u8; 3], Vec<(u16, Vec<u8>)>) {
        let opts = options(&m[4..]).map(|(c, d)| (c, d.to_vec())).collect();
        (m[0], [m[1], m[2], m[3]], opts)
    }

    fn find(opts: &[(u16, Vec<u8>)], code: u16) -> Option<&Vec<u8>> {
        opts.iter().find(|o| o.0 == code).map(|o| &o.1)
    }

    /// A server's answer to `m`: `kind`, giving `addr` for `valid`
    /// seconds (preferred for half), with T1 and T2 as given.
    fn answer(m: &[u8], kind: u8, addr: u128, valid: u32, t1: u32, t2: u32, server: &[u8]) -> Vec<u8> {
        let (_, xid, opts) = parse(m);
        let mut r = Vec::from([kind, xid[0], xid[1], xid[2]]);
        option(&mut r, OPT_CLIENTID, find(&opts, OPT_CLIENTID).unwrap());
        option(&mut r, OPT_SERVERID, server);
        let ia_in = find(&opts, OPT_IA_NA).unwrap();
        let mut ia = ia_in[..4].to_vec();
        ia.extend(t1.to_be_bytes());
        ia.extend(t2.to_be_bytes());
        let mut a = addr.to_be_bytes().to_vec();
        a.extend((valid / 2).to_be_bytes());
        a.extend(valid.to_be_bytes());
        option(&mut ia, OPT_IAADDR, &a);
        option(&mut r, OPT_IA_NA, &ia);
        option(&mut r, OPT_DNS, &DNS.to_be_bytes());
        r
    }

    fn sent(c: &mut Client, now: u64) -> Option<Vec<u8>> {
        let mut out = [0; MAX_MESSAGE];
        c.poll(now, &mut out).0.map(|n| out[..n].to_vec())
    }

    /// A client bound at tick 0 to `ADDR` for 1000 s, T1 400 s, T2 700 s.
    fn bound() -> Client {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        assert_eq!(c.receive(&answer(&solicit, ADVERTISE, ADDR, 1000, 400, 700, SERVER), 0), None);
        let request = sent(&mut c, 0).unwrap();
        let e = c.receive(&answer(&request, REPLY, ADDR, 1000, 400, 700, SERVER), 0);
        assert_eq!(
            e,
            Some(Event::Bound {
                addr: ADDR,
                valid: 1000 * S,
                dns: DNS
            })
        );
        c
    }

    #[test]
    fn idle_until_started() {
        let mut c = Client::new(MAC, S);
        assert_eq!(sent(&mut c, 0), None);
        c.start(1, 5);
        assert_eq!(parse(&sent(&mut c, 5).unwrap()).0, SOLICIT);
        // Starting again changes nothing.
        let xid = c.xid;
        c.start(2, 6);
        assert_eq!(c.xid, xid);
    }

    #[test]
    fn solicit_names_the_client_and_asks_for_an_address_and_dns() {
        let mut c = Client::new(MAC, S);
        c.start(1, 0);
        let (kind, _, opts) = parse(&sent(&mut c, 0).unwrap());
        assert_eq!(kind, SOLICIT);
        assert_eq!(find(&opts, OPT_CLIENTID).unwrap()[..], [0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        assert_eq!(find(&opts, OPT_ORO).unwrap()[..], OPT_DNS.to_be_bytes());
        // An association with no address in it yet, and no server named.
        assert_eq!(find(&opts, OPT_IA_NA).unwrap().len(), 12);
        assert!(find(&opts, OPT_SERVERID).is_none());
    }

    #[test]
    fn the_four_messages() {
        let mut c = bound();
        assert_eq!((c.state, c.addr), (State::Bound, ADDR));
        // Nothing to send while the address is good.
        assert_eq!(sent(&mut c, 399 * S), None);
    }

    #[test]
    fn the_request_names_the_server_and_the_address() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        c.receive(&answer(&solicit, ADVERTISE, ADDR, 1000, 0, 0, SERVER), 3);
        let (kind, xid, opts) = parse(&sent(&mut c, 3).unwrap());
        assert_eq!(kind, REQUEST);
        // A new transaction.
        assert_ne!(xid, parse(&solicit).1);
        assert_eq!(find(&opts, OPT_SERVERID).unwrap()[..], *SERVER);
        let ia = find(&opts, OPT_IA_NA).unwrap();
        assert_eq!(ia[16..32], ADDR.to_be_bytes());
    }

    #[test]
    fn solicits_again_after_1_2_4_seconds() {
        let mut c = Client::new(MAC, S);
        c.start(1, 0);
        let mut at = Vec::new();
        for now in 0..16 * S {
            if let Some(m) = sent(&mut c, now) {
                at.push(now / S);
                // Elapsed time, in hundredths of a second.
                let (_, _, opts) = parse(&m);
                assert_eq!(find(&opts, OPT_ELAPSED).unwrap()[..], ((now) as u16).to_be_bytes());
            }
        }
        assert_eq!(at, [0, 1, 3, 7, 15]);
    }

    #[test]
    fn ignores_what_is_not_its_own() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        let good = answer(&solicit, ADVERTISE, ADDR, 1000, 0, 0, SERVER);
        // Another transaction.
        let mut other = good.clone();
        other[3] ^= 1;
        assert_eq!(c.receive(&other, 0), None);
        assert_eq!(c.state, State::Soliciting);
        // Another client's identifier.
        let mut other = good.clone();
        other[4 + 4 + 9] ^= 1;
        c.receive(&other, 0);
        assert_eq!(c.state, State::Soliciting);
        // A Reply when an Advertise is due, and truncated messages.
        let mut reply = good.clone();
        reply[0] = REPLY;
        c.receive(&reply, 0);
        assert_eq!(c.state, State::Soliciting);
        // Cut anywhere before the address is whole (the DNS option after
        // it, 20 bytes, is one a server may leave out).
        for n in 0..good.len() - 20 {
            c.receive(&good[..n], 0);
            assert_eq!(c.state, State::Soliciting, "cut at {n}");
        }
        c.receive(&good, 0);
        assert_eq!(c.state, State::Requesting);
    }

    #[test]
    fn a_server_with_no_address_is_not_taken() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        // Status NoAddrsAvail (2) in the association.
        let (_, xid, opts) = parse(&solicit);
        let mut r = Vec::from([ADVERTISE, xid[0], xid[1], xid[2]]);
        option(&mut r, OPT_CLIENTID, find(&opts, OPT_CLIENTID).unwrap());
        option(&mut r, OPT_SERVERID, SERVER);
        let mut ia = find(&opts, OPT_IA_NA).unwrap().clone();
        option(&mut ia, OPT_STATUS, &[0, 2]);
        option(&mut r, OPT_IA_NA, &ia);
        assert_eq!(c.receive(&r, 0), None);
        assert_eq!(c.state, State::Soliciting);
    }

    #[test]
    fn unanswered_requests_end_in_soliciting_again() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        c.receive(&answer(&solicit, ADVERTISE, ADDR, 1000, 0, 0, SERVER), 0);
        let mut kinds = Vec::new();
        for now in 0..2000 * S {
            if let Some(m) = sent(&mut c, now) {
                kinds.push(m[0]);
            }
            if kinds.last() == Some(&SOLICIT) {
                break;
            }
        }
        assert_eq!(kinds.len(), REQUEST_TRIES as usize + 1);
        assert!(kinds[..REQUEST_TRIES as usize].iter().all(|&k| k == REQUEST));
    }

    #[test]
    fn renews_at_t1_with_its_server() {
        let mut c = bound();
        let renew = sent(&mut c, 400 * S).unwrap();
        let (kind, _, opts) = parse(&renew);
        assert_eq!((kind, c.state), (RENEW, State::Renewing));
        assert_eq!(find(&opts, OPT_SERVERID).unwrap()[..], *SERVER);
        let e = c.receive(&answer(&renew, REPLY, ADDR, 2000, 800, 1400, SERVER), 401 * S);
        assert_eq!(
            e,
            Some(Event::Bound {
                addr: ADDR,
                valid: 2000 * S,
                dns: DNS
            })
        );
        // The times start again from the reply.
        assert_eq!(sent(&mut c, 1200 * S), None);
        assert_eq!(parse(&sent(&mut c, 1201 * S).unwrap()).0, RENEW);
    }

    #[test]
    fn rebinds_at_t2_with_any_server_then_loses_the_address() {
        let mut c = bound();
        assert_eq!(parse(&sent(&mut c, 400 * S).unwrap()).0, RENEW);
        let rebind = sent(&mut c, 700 * S).unwrap();
        let (kind, _, opts) = parse(&rebind);
        assert_eq!((kind, c.state), (REBIND, State::Rebinding));
        assert!(find(&opts, OPT_SERVERID).is_none());
        // Another server answers: it is the one to renew with next.
        let other: &[u8] = &[0, 3, 0, 1, 7, 7, 7, 7, 7, 7];
        assert!(matches!(
            c.receive(&answer(&rebind, REPLY, ADDR, 1000, 400, 700, other), 701 * S),
            Some(Event::Bound { .. })
        ));
        let (_, _, opts) = parse(&sent(&mut c, 1101 * S).unwrap());
        assert_eq!(find(&opts, OPT_SERVERID).unwrap()[..], *other);
        // Nobody answers any more: the address ends with its lifetime.
        let mut out = [0; MAX_MESSAGE];
        let mut lost = None;
        for now in 1101 * S..1702 * S {
            if let (_, Some(e)) = c.poll(now, &mut out) {
                lost = Some((now / S, e));
                break;
            }
        }
        assert_eq!(lost, Some((1701, Event::Lost { addr: ADDR })));
        assert_eq!((c.state, c.addr), (State::Soliciting, 0));
    }

    #[test]
    fn times_the_server_leaves_out_come_from_the_preferred_lifetime() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        c.receive(&answer(&solicit, ADVERTISE, ADDR, 1000, 0, 0, SERVER), 0);
        let request = sent(&mut c, 0).unwrap();
        // Preferred 500 s: T1 at 250 s, T2 at 400 s.
        c.receive(&answer(&request, REPLY, ADDR, 1000, 0, 0, SERVER), 0);
        assert_eq!(sent(&mut c, 249 * S), None);
        assert_eq!(parse(&sent(&mut c, 250 * S).unwrap()).0, RENEW);
        assert_eq!(parse(&sent(&mut c, 400 * S).unwrap()).0, REBIND);
    }

    #[test]
    fn a_reply_that_takes_the_address_back() {
        let mut c = bound();
        let renew = sent(&mut c, 400 * S).unwrap();
        // A valid lifetime of 0: the address is no longer the client's.
        let e = c.receive(&answer(&renew, REPLY, ADDR, 0, 0, 0, SERVER), 400 * S);
        assert_eq!(e, Some(Event::Lost { addr: ADDR }));
        assert_eq!(c.state, State::Soliciting);
        assert_eq!(parse(&sent(&mut c, 400 * S).unwrap()).0, SOLICIT);
    }

    #[test]
    fn an_infinite_lifetime_never_renews() {
        let mut c = Client::new(MAC, S);
        c.start(7, 0);
        let solicit = sent(&mut c, 0).unwrap();
        c.receive(&answer(&solicit, ADVERTISE, ADDR, u32::MAX, u32::MAX, u32::MAX, SERVER), 0);
        let request = sent(&mut c, 0).unwrap();
        c.receive(&answer(&request, REPLY, ADDR, u32::MAX, u32::MAX, u32::MAX, SERVER), 0);
        assert_eq!(sent(&mut c, u64::MAX / 8), None);
    }
}
