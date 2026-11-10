//! IPv6 (RFC 8200): addresses by stateless autoconfiguration (RFC 4862)
//! from router advertisements, with the DNS server from their RDNSS
//! option (RFC 8106) or, when they carry none, from stateless DHCPv6
//! (RFC 8415's Information-Request); neighbours found with Neighbor Discovery (RFC 4861);
//! duplicate address detection before an address is used; ICMPv6 echo;
//! UDP and TCP; fragments sent and put back together.
//!
//! The link-local address comes from the MAC (modified EUI-64), and so
//! does the global one's interface half. Both, with the router, the DNS
//! server and detection's progress, are kept in the state page, so a
//! restarted server goes on with them at once.

use super::*;

pub const ETH_IPV6: u16 = 0x86dd;
const NH_HOP: u8 = 0;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_DEST: u8 = 60;
pub const NH_ICMP6: u8 = 58;
const ICMP6_UNREACHABLE: u8 = 1;
const ICMP6_ECHO: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;
const ICMP6_RS: u8 = 133;
const ICMP6_RA: u8 = 134;
const ICMP6_NS: u8 = 135;
const ICMP6_NA: u8 = 136;
const ALL_NODES: u128 = 0xff02 << 112 | 1;
const ALL_ROUTERS: u128 = 0xff02 << 112 | 2;
/// All DHCPv6 relay agents and servers (RFC 8415).
const ALL_DHCP6: u128 = 0xff02 << 112 | 1 << 16 | 2;
pub const DHCP6_CLIENT_PORT: u16 = 546;
const DHCP6_SERVER_PORT: u16 = 547;
const DHCP6_INFO_REQUEST: u8 = 11;
const DHCP6_REPLY: u8 = 7;
const DHCP6_OPT_ORO: u16 = 6;
const DHCP6_OPT_ELAPSED: u16 = 8;
const DHCP6_OPT_DNS: u16 = 23;
pub const LOCALHOST: u128 = 1;
/// The most payload in one 1500-byte frame's packet, and in one carrying
/// a fragment header (a multiple of 8).
const PAYLOAD6: usize = 1460;
const FRAGMENT6: usize = 1448;
/// Duplicate address detection: how long to wait for an objection (1 s).
const DAD_TICKS: u64 = 100;
/// Router solicitations, until a router answers: every 4 s.
const RS_TICKS: u64 = 400;
/// The state page's words for IPv6, after IPv4's: a magic word (written
/// last), then the global address, prefix length and on-link flag, the
/// router, how long it lasts, the DNS server, when the address runs out,
/// whether the link-local address passed detection, and the address on
/// trial with when it passes. Detection's progress is kept too, so a
/// server restarted more often than it takes (a second) still gets there.
const V6_WORDS: usize = 16;
const V6_MAGIC: u64 = 0x6970_7636_7374_6174;

/// An address: IPv4 ones dotted, IPv6 ones in RFC 5952's short form.
pub struct Ip6(pub u128);

impl core::fmt::Display for Ip6 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(ip) = ipv4(self.0) {
            return write!(f, "{}", Ip(ip));
        }
        let g: [u16; 8] = core::array::from_fn(|i| (self.0 >> (112 - 16 * i)) as u16);
        // The longest run of two or more zero groups becomes "::".
        let (mut best, mut len) = (8, 1);
        let mut i = 0;
        while i < 8 {
            let n = g[i..].iter().take_while(|&&x| x == 0).count();
            if n > len {
                (best, len) = (i, n);
            }
            i += n.max(1);
        }
        let mut i = 0;
        while i < 8 {
            if i == best {
                write!(f, "::")?;
                i += len;
                continue;
            }
            if i > 0 && i != best + len {
                write!(f, ":")?;
            }
            write!(f, "{:x}", g[i])?;
            i += 1;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct V6 {
    /// The link-local address, and whether it passed detection.
    pub ll: u128,
    pub ll_ready: bool,
    /// The global address (0: none yet), its prefix, and when it runs out.
    pub global: u128,
    pub prefix_len: u8,
    pub on_link: bool,
    pub valid_until: u64,
    /// The default router (its link-local address) and until when.
    pub router: u128,
    pub router_until: u64,
    pub dns: u128,
    /// An address on trial, and when it passes.
    pub tentative: Option<(u128, u64)>,
    pub rs_next: u64,
    /// When to ask DHCPv6 for the DNS server next, and the transaction.
    pub info_next: u64,
    pub info_xid: u32,
    pub frag_id: u32,
}

impl V6 {
    pub const fn new() -> V6 {
        V6 {
            ll: 0,
            ll_ready: false,
            global: 0,
            prefix_len: 0,
            on_link: false,
            valid_until: 0,
            router: 0,
            router_until: 0,
            dns: 0,
            tentative: None,
            rs_next: 0,
            info_next: 0,
            info_xid: 0,
            frag_id: 0,
        }
    }
}

fn link_local(a: u128) -> bool {
    a >> 118 == 0xfe80 >> 6
}

fn multicast(a: u128) -> bool {
    a >> 120 == 0xff
}

/// The solicited-node multicast address for `a`.
fn solicited(a: u128) -> u128 {
    0xff02_0000_0000_0000_0000_0001_ff00_0000 | (a & 0xff_ffff)
}

fn addr_at(b: &[u8], at: usize) -> u128 {
    let mut x = [0u8; 16];
    x.copy_from_slice(&b[at..at + 16]);
    u128::from_be_bytes(x)
}

fn put_addr(b: &mut [u8], at: usize, a: u128) {
    b[at..at + 16].copy_from_slice(&a.to_be_bytes());
}

impl Net {
    /// The interface half of this host's addresses: the MAC as a modified
    /// EUI-64 (RFC 4291).
    fn iid(&self) -> u128 {
        let m = self.mac;
        u64::from_be_bytes([m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]) as u128
    }

    /// Whether `a` is one of this host's usable IPv6 addresses.
    pub fn ours6(&self, a: u128) -> bool {
        (a == self.v6.ll && self.v6.ll_ready) || (a != 0 && a == self.v6.global) || a == LOCALHOST
    }

    /// Whether a packet to `dst` is for this host: one of its addresses,
    /// all nodes, or the solicited-node group of one (or of one on trial).
    fn accepts6(&self, dst: u128) -> bool {
        let v = &self.v6;
        self.ours6(dst)
            || dst == ALL_NODES
            || dst == solicited(v.ll)
            || (v.global != 0 && dst == solicited(v.global))
            || v.tentative.is_some_and(|(t, _)| dst == solicited(t))
    }

    /// The source address for a packet to `dst`: link-local for link-local
    /// and multicast destinations, else the global one.
    pub fn source6(&self, dst: u128) -> Option<u128> {
        if dst == LOCALHOST {
            return Some(LOCALHOST);
        }
        if self.ours6(dst) {
            return Some(dst);
        }
        if link_local(dst) || multicast(dst) {
            return self.v6.ll_ready.then_some(self.v6.ll);
        }
        (self.v6.global != 0).then_some(self.v6.global)
    }

    /// The next hop toward `dst`: itself if on the link, else the router.
    fn next_hop6(&self, dst: u128) -> Option<u128> {
        let v = &self.v6;
        let on_link = v.on_link && v.global != 0 && {
            let mask = !0u128 << (128 - v.prefix_len.min(128) as u32);
            dst & mask == v.global & mask
        };
        if link_local(dst) || multicast(dst) || on_link {
            return Some(dst);
        }
        (v.router != 0 && ticks() < v.router_until).then_some(v.router)
    }

    pub fn save6(&self) {
        let s = state();
        let v = &self.v6;
        let (t, until) = v.tentative.unwrap_or((0, 0));
        let words = [
            (v.global >> 64) as u64,
            v.global as u64,
            v.prefix_len as u64 | (v.on_link as u64) << 8,
            (v.router >> 64) as u64,
            v.router as u64,
            v.router_until,
            (v.dns >> 64) as u64,
            v.dns as u64,
            v.valid_until,
            v.ll_ready as u64 | (v.tentative.is_some() as u64) << 1,
            (t >> 64) as u64,
            t as u64,
            until,
        ];
        // SAFETY: the state page is mapped at STATE_VA for good.
        unsafe {
            s.add(V6_WORDS).write_volatile(0);
            for (i, w) in words.iter().enumerate() {
                s.add(V6_WORDS + 1 + i).write_volatile(*w);
            }
            s.add(V6_WORDS).write_volatile(V6_MAGIC);
        }
    }

    /// Takes what a predecessor left; whether it had a global address.
    fn load6(&mut self) -> bool {
        let s = state();
        // SAFETY: as in `save6`.
        let w = |i: usize| unsafe { s.add(V6_WORDS + i).read_volatile() };
        if w(0) != V6_MAGIC {
            return false;
        }
        let v = &mut self.v6;
        v.ll_ready = w(10) & 1 != 0;
        if w(10) & 2 != 0 {
            v.tentative = Some(((w(11) as u128) << 64 | w(12) as u128, w(13)));
        }
        v.global = (w(1) as u128) << 64 | w(2) as u128;
        v.prefix_len = w(3) as u8;
        v.on_link = w(3) >> 8 & 1 != 0;
        v.router = (w(4) as u128) << 64 | w(5) as u128;
        v.router_until = w(6);
        v.dns = (w(7) as u128) << 64 | w(8) as u128;
        v.valid_until = w(9);
        if v.global != 0 && ticks() >= v.valid_until {
            v.global = 0;
        }
        v.global != 0
    }

    /// At start: the addresses a predecessor left, or detection of the
    /// link-local one (then a router solicitation).
    pub fn start6(&mut self) {
        self.v6.ll = 0xfe80 << 112 | self.iid();
        if self.load6() {
            say!(
                "IPv6 kept: {}/{} via {}",
                Ip6(self.v6.global),
                self.v6.prefix_len,
                Ip6(self.v6.router)
            );
            return;
        }
        match self.v6.tentative {
            // A trial a predecessor began goes on; ask again.
            Some((t, _)) => self.ns(t, true),
            None if !self.v6.ll_ready => self.try_address(self.v6.ll),
            None => {}
        }
    }

    /// Puts `a` on trial: a neighbour solicitation from the unspecified
    /// address asks whether anyone has it.
    fn try_address(&mut self, a: u128) {
        self.v6.tentative = Some((a, ticks() + DAD_TICKS));
        self.save6();
        self.ns(a, true);
    }

    /// The timer: addresses passing detection, solicitations, expiry.
    pub fn tick6(&mut self) {
        let now = ticks();
        if let Some((a, t)) = self.v6.tentative {
            if now >= t {
                self.v6.tentative = None;
                if a == self.v6.ll {
                    self.v6.ll_ready = true;
                    self.save6();
                    say!("IPv6 link-local {}", Ip6(a));
                    self.v6.rs_next = now;
                } else {
                    self.v6.global = a;
                    self.save6();
                    say!(
                        "IPv6 address {}/{} via {}, DNS {}",
                        Ip6(a),
                        self.v6.prefix_len,
                        Ip6(self.v6.router),
                        Ip6(self.v6.dns)
                    );
                }
            }
        }
        let v = self.v6;
        if v.ll_ready && v.global == 0 && v.tentative.is_none() && now >= v.rs_next {
            self.v6.rs_next = now + RS_TICKS;
            self.rs();
        }
        if v.global != 0 && v.dns == 0 && now >= v.info_next {
            self.v6.info_next = now + RS_TICKS;
            self.info_request();
        }
        if v.global != 0 && now >= v.valid_until {
            say!("IPv6 address {} ran out", Ip6(v.global));
            self.v6.global = 0;
            self.save6();
        }
    }

    /// Writes the IPv6 header for a `len`-byte payload on the transmit
    /// page.
    fn ip6_header(&self, src: u128, dst: u128, next: u8, len: usize, hops: u8) {
        let h = &mut page(TX_VA)[14..54];
        h.fill(0);
        h[0] = 0x60;
        put16(h, 4, len as u16);
        h[6] = next;
        h[7] = hops;
        put_addr(h, 8, src);
        put_addr(h, 24, dst);
    }

    /// Sends the IPv6 packet whose payload (`len` bytes) is on the
    /// transmit page after the headers: in fragments if too big for a
    /// frame.
    pub fn ip6_send(&mut self, dst: u128, next: u8, len: usize) -> Status {
        let Some(src) = self.source6(dst) else {
            return Status::Unreachable;
        };
        if len > PAYLOAD6 {
            return self.fragments6(src, dst, next, len);
        }
        self.ip6_header(src, dst, next, len, 64);
        self.out6(dst, 40 + len)
    }

    /// Sends the packet (`total` bytes) on the transmit page: round the
    /// loopback if it is for this host, else to the next hop, which may
    /// first have to be found.
    fn out6(&mut self, dst: u128, total: usize) -> Status {
        if self.ours6(dst) {
            self.loop_push(total);
            return Status::Ok;
        }
        let Some(hop) = self.next_hop6(dst) else {
            return Status::Unreachable;
        };
        let frame = (14 + total).max(60);
        let mac = if multicast(hop) {
            let b = hop.to_be_bytes();
            Some([0x33, 0x33, b[12], b[13], b[14], b[15]])
        } else {
            self.lookup(hop)
        };
        if let Some(mac) = mac {
            self.ether(mac, ETH_IPV6);
            return self.transmit(frame);
        }
        self.ether([0; 6], ETH_IPV6);
        self.wait_for(hop, frame);
        self.ns(hop, false);
        Status::Ok
    }

    /// Sends the `len`-byte payload on the transmit page in fragments,
    /// each with a fragment header (RFC 8200 4.5).
    fn fragments6(&mut self, src: u128, dst: u128, next: u8, len: usize) -> Status {
        // SAFETY: one thread; PIECES is used only while fragmenting.
        let pieces = unsafe { &mut *(&raw mut PIECES) };
        pieces[..len].copy_from_slice(&page(TX_VA)[54..54 + len]);
        self.v6.frag_id = self.v6.frag_id.wrapping_add(1) ^ (self.epoch as u32) << 16;
        let id = self.v6.frag_id;
        let mut at = 0;
        while at < len {
            let n = (len - at).min(FRAGMENT6);
            let more = at + n < len;
            let tx = page(TX_VA);
            tx[54] = next;
            tx[55] = 0;
            put16(tx, 56, at as u16 | more as u16);
            put32(tx, 58, id);
            tx[62..62 + n].copy_from_slice(&pieces[at..at + n]);
            self.ip6_header(src, dst, NH_FRAGMENT, 8 + n, 64);
            let s = self.out6(dst, 40 + 8 + n);
            if s != Status::Ok {
                return s;
            }
            at += n;
        }
        count(STAT_FRAGMENTED, 1);
        Status::Ok
    }

    /// Sends an ICMPv6 message whose `len` bytes are on the transmit page
    /// after the IPv6 header, from `src`, checksummed; Neighbor Discovery
    /// goes with a hop limit of 255.
    fn icmp6_send(&mut self, src: u128, dst: u128, len: usize, hops: u8) -> Status {
        let m = &mut page(TX_VA)[54..54 + len];
        put16(m, 2, 0);
        let c = fold(sum(pseudo(src, dst, NH_ICMP6, len), m));
        put16(m, 2, c);
        self.ip6_header(src, dst, NH_ICMP6, len, hops);
        self.out6(dst, 40 + len)
    }

    /// A neighbour solicitation for `target`: from the unspecified address
    /// when detecting a duplicate, else with this host's MAC.
    pub fn ns(&mut self, target: u128, dad: bool) {
        let m = &mut page(TX_VA)[54..54 + 32];
        m.fill(0);
        m[0] = ICMP6_NS;
        put_addr(m, 8, target);
        let len = if dad {
            24
        } else {
            m[24] = 1;
            m[25] = 1;
            m[26..32].copy_from_slice(&self.mac);
            32
        };
        let src = if dad {
            0
        } else {
            match self.source6(target) {
                Some(s) => s,
                None => return,
            }
        };
        self.icmp6_send(src, solicited(target), len, 255);
    }

    /// A neighbour advertisement of `target` (ours) to `to`.
    fn na(&mut self, to: u128, target: u128, solicited_flag: bool) {
        let m = &mut page(TX_VA)[54..54 + 32];
        m.fill(0);
        m[0] = ICMP6_NA;
        // Solicited, and override.
        m[4] = 0x20 | if solicited_flag { 0x40 } else { 0 };
        put_addr(m, 8, target);
        m[24] = 2;
        m[25] = 1;
        m[26..32].copy_from_slice(&self.mac);
        self.icmp6_send(target, to, 32, 255);
    }

    /// A DHCPv6 Information-Request for the DNS server, to all DHCPv6
    /// servers, from the link-local address.
    fn info_request(&mut self) {
        self.v6.info_xid = (self.v6.info_xid + 0x9e37) & 0xff_ffff;
        let ll = self.v6.ll;
        let len = 8 + 4 + 6 + 6;
        let u = &mut page(TX_VA)[54..54 + len];
        u.fill(0);
        put16(u, 0, DHCP6_CLIENT_PORT);
        put16(u, 2, DHCP6_SERVER_PORT);
        put16(u, 4, len as u16);
        let m = &mut u[8..];
        m[0] = DHCP6_INFO_REQUEST;
        m[1..4].copy_from_slice(&self.v6.info_xid.to_be_bytes()[1..]);
        // Asking for DNS servers; no time elapsed.
        put16(m, 4, DHCP6_OPT_ORO);
        put16(m, 6, 2);
        put16(m, 8, DHCP6_OPT_DNS);
        put16(m, 10, DHCP6_OPT_ELAPSED);
        put16(m, 12, 2);
        let c = fold(sum(pseudo(ll, ALL_DHCP6, PROTO_UDP, len), u));
        put16(u, 6, if c == 0 { 0xffff } else { c });
        self.ip6_header(ll, ALL_DHCP6, PROTO_UDP, len, 1);
        self.out6(ALL_DHCP6, 40 + len);
    }

    /// A DHCPv6 message to the client port: a reply to this host's
    /// Information-Request gives the DNS server.
    pub fn dhcp6(&mut self, m: &[u8]) {
        if m.len() < 4 || m[0] != DHCP6_REPLY || m[1..4] != self.v6.info_xid.to_be_bytes()[1..] {
            return;
        }
        let mut at = 4;
        while at + 4 <= m.len() {
            let (code, n) = (be16(m, at), be16(m, at + 2) as usize);
            if at + 4 + n > m.len() {
                break;
            }
            if code == DHCP6_OPT_DNS && n >= 16 && self.v6.dns == 0 {
                self.v6.dns = addr_at(m, at + 4);
                self.save6();
                say!("IPv6 DNS {} (DHCPv6)", Ip6(self.v6.dns));
            }
            at += 4 + n;
        }
    }

    /// A router solicitation, to all routers.
    fn rs(&mut self) {
        let m = &mut page(TX_VA)[54..54 + 16];
        m.fill(0);
        m[0] = ICMP6_RS;
        m[8] = 1;
        m[9] = 1;
        m[10..16].copy_from_slice(&self.mac);
        let ll = self.v6.ll;
        self.icmp6_send(ll, ALL_ROUTERS, 16, 255);
    }

    /// A received IPv6 packet.
    pub fn ipv6(&mut self, p: &[u8]) {
        if p.len() < 40 || p[0] >> 4 != 6 {
            return;
        }
        let total = 40 + be16(p, 4) as usize;
        if total > p.len() {
            return;
        }
        let (src, dst, hops) = (addr_at(p, 8), addr_at(p, 24), p[7]);
        if !self.accepts6(dst) || multicast(src) {
            return;
        }
        // Past the extension headers to the payload.
        let (mut next, mut at) = (p[6], 40);
        let body = loop {
            match next {
                NH_HOP | NH_ROUTING | NH_DEST => {
                    if at + 8 > total {
                        return;
                    }
                    next = p[at];
                    at += (p[at + 1] as usize + 1) * 8;
                }
                NH_FRAGMENT => {
                    if at + 8 > total {
                        return;
                    }
                    let off = be16(p, at + 2);
                    let key = Key {
                        src,
                        dst,
                        proto: p[at],
                        id: be32(p, at + 4),
                    };
                    let (offset, more) = ((off & !7) as usize, off & 1 != 0);
                    // SAFETY: one thread; WHOLE holds this datagram until
                    // it has been handled, and nothing else uses it.
                    let whole = unsafe { &mut *(&raw mut WHOLE) };
                    match self.reassembly.add(ticks(), key, offset, more, &p[at + 8..total], whole) {
                        Outcome::Complete(n) => {
                            count(STAT_REASSEMBLED, 1);
                            next = key.proto;
                            break &whole[..n];
                        }
                        Outcome::Dropped => {
                            count(STAT_DROPPED, 1);
                            return;
                        }
                        Outcome::Pending => return,
                    }
                }
                _ => break &p[at.min(total)..total],
            }
            if at > total {
                return;
            }
        };
        let ours = self.ours6(dst);
        match next {
            NH_ICMP6 => self.icmp6(src, dst, body, hops),
            PROTO_UDP => self.udp(src, dst, body, ours, true),
            PROTO_TCP if ours => self.tcp(src, dst, body),
            _ => {}
        }
    }

    fn icmp6(&mut self, src: u128, dst: u128, m: &[u8], hops: u8) {
        if m.len() < 8 || fold(sum(pseudo(src, dst, NH_ICMP6, m.len()), m)) != 0 {
            return;
        }
        match m[0] {
            ICMP6_ECHO if self.ours6(dst) || dst == ALL_NODES => {
                let len = m.len().min(MAX_DATAGRAM + 8);
                let r = &mut page(TX_VA)[54..54 + len];
                r.copy_from_slice(&m[..len]);
                r[0] = ICMP6_ECHO_REPLY;
                let Some(me) = self.source6(src) else {
                    return;
                };
                if len > PAYLOAD6 {
                    put16(r, 2, 0);
                    let c = fold(sum(pseudo(me, src, NH_ICMP6, len), r));
                    put16(r, 2, c);
                    self.ip6_send(src, NH_ICMP6, len);
                } else {
                    self.icmp6_send(me, src, len, 64);
                }
            }
            ICMP6_ECHO_REPLY => self.deliver(Kind::Icmp(be16(m, 4)), src, be16(m, 6), &m[8..]),
            ICMP6_RA if hops == 255 && link_local(src) && m.len() >= 16 => self.ra(src, m),
            ICMP6_NS if hops == 255 && m.len() >= 24 => {
                let target = addr_at(m, 8);
                if src == 0 {
                    // Someone else is detecting this address.
                    if self.v6.tentative.is_some_and(|(t, _)| t == target) {
                        say!("IPv6 address {} is taken; not using it", Ip6(target));
                        self.v6.tentative = None;
                        self.save6();
                    } else if self.ours6(target) {
                        self.na(ALL_NODES, target, false);
                    }
                    return;
                }
                if let Some(mac) = self.link_option(&m[24..], 1) {
                    self.learn(src, mac);
                }
                if self.ours6(target) {
                    self.na(src, target, true);
                }
            }
            ICMP6_NA if hops == 255 && m.len() >= 24 => {
                let target = addr_at(m, 8);
                if self.v6.tentative.is_some_and(|(t, _)| t == target) {
                    say!("IPv6 address {} is taken; not using it", Ip6(target));
                    self.v6.tentative = None;
                    self.save6();
                    return;
                }
                if let Some(mac) = self.link_option(&m[24..], 2) {
                    self.learn(target, mac);
                }
            }
            ICMP6_UNREACHABLE if m.len() >= 8 + 48 => {
                let q = &m[8..];
                if q[6] == PROTO_TCP {
                    // Port unreachable: nothing listens there.
                    let t = &q[40..48];
                    self.tcp_unreachable(addr_at(q, 24), be16(t, 0), be16(t, 2), be32(t, 4), m[1] == 4);
                }
            }
            _ => {}
        }
    }

    /// The MAC address in a source (1) or target (2) link-layer address
    /// option among Neighbor Discovery options `o`.
    fn link_option(&self, o: &[u8], kind: u8) -> Option<[u8; 6]> {
        let mut at = 0;
        while at + 8 <= o.len() {
            let n = o[at + 1] as usize * 8;
            if n == 0 {
                return None;
            }
            if o[at] == kind && n >= 8 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&o[at + 2..at + 8]);
                return Some(mac);
            }
            at += n;
        }
        None
    }

    /// A router advertisement from `src`: the router, the prefix to make
    /// an address in, the DNS server.
    fn ra(&mut self, src: u128, m: &[u8]) {
        let now = ticks();
        let lifetime = be16(m, 6) as u64;
        if lifetime > 0 {
            self.v6.router = src;
            self.v6.router_until = now + lifetime * SECOND;
        }
        let mut candidate = None;
        let mut at = 16;
        while at + 8 <= m.len() {
            let n = m[at + 1] as usize * 8;
            if n == 0 || at + n > m.len() {
                break;
            }
            let o = &m[at..at + n];
            match o[0] {
                1 => {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&o[2..8]);
                    self.learn(src, mac);
                }
                // A prefix to make an address in (autonomous, /64).
                3 if n == 32 && o[2] == 64 && o[3] & 0x40 != 0 => {
                    let valid = be32(o, 4) as u64;
                    let prefix = addr_at(o, 16) & !0u128 << 64;
                    self.v6.prefix_len = 64;
                    self.v6.on_link = o[3] & 0x80 != 0;
                    self.v6.valid_until = if valid == u32::MAX as u64 {
                        u64::MAX / 4
                    } else {
                        now + valid * SECOND
                    };
                    candidate = Some(prefix | self.iid());
                }
                25 if n >= 24 => self.v6.dns = addr_at(o, 8),
                _ => {}
            }
            at += n;
        }
        match candidate {
            Some(a) if a != self.v6.global && self.v6.tentative.is_none_or(|(t, _)| t != a) => {
                self.try_address(a);
            }
            _ => {
                if self.v6.global != 0 {
                    self.save6();
                }
            }
        }
    }
}
