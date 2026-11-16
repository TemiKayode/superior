//! The Wi-Fi test's far end: a WPA2-Personal access point
//! (`superior_wifi::ap`) on the UDP socket QEMU's simulated radio sends its
//! 802.11 frames to, one frame a datagram, with a small network behind it:
//! a gateway that answers ARP, hands out an address by DHCP (its answers
//! broadcast, so they go under the group key), answers pings and echoes
//! UDP datagrams, fragments included. While the station's frames come, the
//! access point renews the keys: the pairwise keys and the group key in
//! turn, every `REKEY_EVERY` frames; after a new group key it asks for the
//! station's address by a broadcast ARP request, so a frame under the new
//! group key needs an answer.
//!
//! A second access point, WPA3-only (SAE, management frames protected),
//! serves the same network as "superior-wpa3": once a station has joined
//! it, it is sent a forged (unprotected) deauthentication, and two to
//! every station (one with no MMIE, one with a wrong MIC: BIP), which it
//! must ignore. An open network beacons too, on another channel and fainter,
//! for the station's survey. Every datagram to the radio starts with the
//! signal strength it is "heard" at (dBm, one signed byte), as a real
//! radio reports it.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use superior_wifi::ap::{AccessPoint, Peer};
use superior_wifi::frame::MAX;
use superior_wifi::handshake::Gtk;

pub const SSID: &[u8] = b"superior-test";
pub const PASSPHRASE: &[u8] = b"correct horse battery staple";
pub const BSSID: [u8; 6] = [0x02, 0x57, 0x49, 0x46, 0x49, 0x01];
/// The access point listens here; QEMU's radio sends from `RADIO_PORT`.
pub const AP_PORT: u16 = 47110;
pub const RADIO_PORT: u16 = 47111;
/// The network behind the access point.
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x05, 0x01];
const GATEWAY: [u8; 4] = [10, 0, 5, 1];
const LEASED: [u8; 4] = [10, 0, 5, 30];
const ECHO_PORT: u16 = 47001;
/// Frames from the station between rekeyings.
const REKEY_EVERY: u64 = 20;
/// The access point's signal at the radio, in dBm.
const SIGNAL: i8 = -45;
/// The WPA3 access point.
pub const WPA3_SSID: &[u8] = b"superior-wpa3";
pub const WPA3_BSSID: [u8; 6] = [0x02, 0x57, 0x49, 0x46, 0x49, 0x03];
const WPA3_SIGNAL: i8 = -60;

/// A network in range that only beacons: BSSID, SSID, capability, RSN
/// element (if any), channel, signal.
struct Neighbour {
    bssid: [u8; 6],
    ssid: &'static [u8],
    capability: u16,
    rsne: Option<&'static [u8]>,
    channel: u8,
    signal: i8,
}

const NEIGHBOURS: [Neighbour; 1] = [Neighbour {
    bssid: [0x02, 0x57, 0x49, 0x46, 0x49, 0x02],
    ssid: b"superior-guest",
    capability: 0x0001,
    rsne: None,
    channel: 11,
    signal: -71,
}];

impl Neighbour {
    /// Its beacon, with the signal byte before it.
    fn beacon(&self, seq: u16) -> Vec<u8> {
        use superior_wifi::frame::{BEACON, BROADCAST, DS_PARAMS, RATES, RATE_SET, SSID, element, header};
        let mut f = [0u8; 256];
        let mut n = header(&mut f, BEACON, 0, &BROADCAST, &self.bssid, &self.bssid, seq);
        f[n + 8..n + 10].copy_from_slice(&100u16.to_le_bytes());
        f[n + 10..n + 12].copy_from_slice(&self.capability.to_le_bytes());
        n += 12;
        n = element(&mut f, n, SSID, self.ssid);
        n = element(&mut f, n, RATES, &RATE_SET);
        n = element(&mut f, n, DS_PARAMS, &[self.channel]);
        if let Some(e) = self.rsne {
            f[n..n + e.len()].copy_from_slice(e);
            n += e.len();
        }
        let mut d = vec![self.signal as u8];
        d.extend_from_slice(&f[..n]);
        d
    }
}

/// What the access point saw, for the test to check.
#[derive(Default)]
pub struct Seen {
    /// The station was keyed (the handshake finished).
    pub keyed: AtomicBool,
    /// Ethernet frames carried each way, and DHCP answers sent.
    pub from_station: AtomicU64,
    pub to_station: AtomicU64,
    pub dhcp: AtomicU64,
    /// Frames the access point refused.
    pub refused: AtomicU64,
    /// Rekeyings finished (pairwise, group), and the station's ARP answers
    /// to the gateway's broadcast requests after a new group key.
    pub rekeys: AtomicU64,
    pub group_rekeys: AtomicU64,
    pub arp_answers: AtomicU64,
    /// The WPA3 access point: the station keyed by SAE, frames carried
    /// from it, forged deauthentications sent, frames refused.
    pub wpa3_keyed: AtomicBool,
    /// Whether that SAE exchange was by hash-to-element.
    pub wpa3_h2e: AtomicBool,
    /// Anti-clogging tokens it asked for before taking the commit.
    pub wpa3_tokens: AtomicU64,
    pub wpa3_from_station: AtomicU64,
    pub forged_deauths: AtomicU64,
    pub wpa3_refused: AtomicU64,
}

/// Runs the access point until `stop`.
pub fn start(stop: Arc<AtomicBool>, seen: Arc<Seen>) -> Result<JoinHandle<()>, String> {
    let sock = UdpSocket::bind(("127.0.0.1", AP_PORT)).map_err(|e| format!("access point socket: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(10))).map_err(|e| e.to_string())?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    let mut gtk = Gtk { index: 1, key: [0; 16] };
    getrandom::getrandom(&mut gtk.key).map_err(|e| e.to_string())?;
    let mut seed3 = [0u8; 32];
    getrandom::getrandom(&mut seed3).map_err(|e| e.to_string())?;
    let mut gtk3 = Gtk { index: 1, key: [0; 16] };
    getrandom::getrandom(&mut gtk3.key).map_err(|e| e.to_string())?;
    let mut later_gtks = [[0u8; 16]; 8];
    for k in later_gtks.iter_mut() {
        getrandom::getrandom(k).map_err(|e| e.to_string())?;
    }
    Ok(std::thread::spawn(move || {
        let mut ap = AccessPoint::new(BSSID, SSID, PASSPHRASE, gtk, seed);
        let mut ap3 = AccessPoint::new(WPA3_BSSID, WPA3_SSID, PASSPHRASE, gtk3, seed3).offering(false, true).hash_to_element().anti_clogging(0);
        let (mut next_rekey, mut rekeyings, mut group_rekeys) = (REKEY_EVERY, 0usize, 0);
        let started = Instant::now();
        let radio = ("127.0.0.1", RADIO_PORT);
        let mut next_beacon = 0;
        let mut beacons = 0u16;
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let now = started.elapsed().as_millis() as u64;
            let mut out: Vec<Vec<u8>> = Vec::new();
            let mut out3: Vec<Vec<u8>> = Vec::new();
            let mut neighbours = Vec::new();
            if now >= next_beacon {
                let mut b = [0u8; 200];
                let n = ap.beacon(&mut b);
                out.push(b[..n].to_vec());
                let n = ap3.beacon(&mut b);
                out3.push(b[..n].to_vec());
                next_beacon = now + 100;
                beacons = beacons.wrapping_add(1);
                neighbours.extend(NEIGHBOURS.iter().map(|nb| nb.beacon(beacons)));
            }
            ap.poll(now, &mut |f| out.push(f.to_vec()));
            ap3.poll(now, &mut |f| out3.push(f.to_vec()));
            if let Ok(n) = sock.recv(&mut buf) {
                let mut up3: Vec<Vec<u8>> = Vec::new();
                ap3.receive(&buf[..n], now, &mut |f| out3.push(f.to_vec()), &mut |e| up3.push(e.to_vec()));
                for e in up3 {
                    seen.wpa3_from_station.fetch_add(1, Ordering::Relaxed);
                    if let Some(reply) = answer(&e, &seen) {
                        let mut f = [0u8; MAX];
                        if let Some(n) = ap3.send(&reply, &mut f) {
                            out3.push(f[..n].to_vec());
                        }
                    }
                }
                let mut up: Vec<Vec<u8>> = Vec::new();
                ap.receive(&buf[..n], now, &mut |f| out.push(f.to_vec()), &mut |e| up.push(e.to_vec()));
                for e in up {
                    let from = seen.from_station.fetch_add(1, Ordering::Relaxed) + 1;
                    if from >= next_rekey && !ap.rekeying() {
                        // The pairwise keys and the group key in turn, the
                        // group key's ID alternating between 1 and 2.
                        let radio = &mut |f: &[u8]| out.push(f.to_vec());
                        let started = if rekeyings % 2 == 0 {
                            ap.rekey(now, radio)
                        } else {
                            let key = later_gtks[(rekeyings / 2) % later_gtks.len()];
                            ap.rekey_group(Gtk { index: 2 - (rekeyings / 2 % 2) as u8, key }, now, radio)
                        };
                        if started {
                            rekeyings += 1;
                            next_rekey = from + REKEY_EVERY;
                        }
                    }
                    if let Some(reply) = answer(&e, &seen) {
                        let mut f = [0u8; MAX];
                        if let Some(n) = ap.send(&reply, &mut f) {
                            seen.to_station.fetch_add(1, Ordering::Relaxed);
                            out.push(f[..n].to_vec());
                        }
                    }
                }
            }
            if ap.peer() == Peer::Up {
                seen.keyed.store(true, Ordering::Relaxed);
            }
            if ap.group_rekeys > group_rekeys {
                // The new group key in use: who has the leased address?
                group_rekeys = ap.group_rekeys;
                let mut f = [0u8; MAX];
                if let Some(n) = ap.send(&arp_request(), &mut f) {
                    out.push(f[..n].to_vec());
                }
            }
            seen.rekeys.store(ap.rekeys as u64, Ordering::Relaxed);
            seen.group_rekeys.store(ap.group_rekeys as u64, Ordering::Relaxed);
            seen.refused.store(ap.refused, Ordering::Relaxed);
            if ap3.peer() == Peer::Up && !seen.wpa3_keyed.swap(true, Ordering::Relaxed) {
                seen.wpa3_h2e.store(ap3.station_used_h2e(), Ordering::Relaxed);
                seen.wpa3_tokens.store(ap3.tokens_asked as u64, Ordering::Relaxed);
                // Keyed by SAE: a deauthentication forged in its name,
                // unprotected, which the station must not obey.
                let mut f = [0u8; 26];
                let n = superior_wifi::frame::header(&mut f, superior_wifi::frame::DEAUTH, 0, &ap3.station(), &WPA3_BSSID, &WPA3_BSSID, 0);
                f[n..n + 2].copy_from_slice(&[7, 0]);
                out3.push(f.to_vec());
                seen.forged_deauths.fetch_add(1, Ordering::Relaxed);
                // And two to every station: one with no MMIE, one whose
                // MMIE is under a key the station does not have (BIP).
                let mut g = [0u8; 64];
                let bc = superior_wifi::frame::BROADCAST;
                let n = superior_wifi::frame::header(&mut g, superior_wifi::frame::DEAUTH, 0, &bc, &WPA3_BSSID, &WPA3_BSSID, 0);
                g[n..n + 2].copy_from_slice(&[7, 0]);
                out3.push(g[..n + 2].to_vec());
                let forged = superior_wifi::handshake::Igtk { key: [0x42; 16], ..ap3.igtk() };
                if let Some(m) = superior_wifi::bip::protect(&forged, ap3.ipn() + 1, &mut g, n + 2) {
                    out3.push(g[..m].to_vec());
                }
                seen.forged_deauths.fetch_add(2, Ordering::Relaxed);
            }
            seen.wpa3_refused.store(ap3.refused, Ordering::Relaxed);
            for (frames, signal) in [(out, SIGNAL), (out3, WPA3_SIGNAL)] {
                for f in frames {
                    let mut d = vec![signal as u8];
                    d.extend_from_slice(&f);
                    let _ = sock.send_to(&d, radio);
                }
            }
            for d in neighbours {
                let _ = sock.send_to(&d, radio);
            }
        }
    }))
}

fn checksum(b: &[u8], mut acc: u32) -> u16 {
    for pair in b.chunks(2) {
        acc += (pair[0] as u32) << 8 | pair.get(1).copied().unwrap_or(0) as u32;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// An IPv4 packet from the gateway: header (no options) and `payload`.
fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p, 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ethernet(dst: [u8; 6], kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut e = dst.to_vec();
    e.extend_from_slice(&GATEWAY_MAC);
    e.extend_from_slice(&kind.to_be_bytes());
    e.extend_from_slice(payload);
    e
}

/// A broadcast ARP request from the gateway for the leased address.
fn arp_request() -> Vec<u8> {
    let mut r = vec![0, 1, 8, 0, 6, 4, 0, 1];
    r.extend_from_slice(&GATEWAY_MAC);
    r.extend_from_slice(&GATEWAY);
    r.extend_from_slice(&[0; 6]);
    r.extend_from_slice(&LEASED);
    ethernet([0xff; 6], 0x0806, &r)
}

/// The gateway's answer to an Ethernet frame from the station, if any.
fn answer(e: &[u8], seen: &Seen) -> Option<Vec<u8>> {
    let (dst, src, kind, p) = superior_wifi::frame::ethernet(e)?;
    let _ = dst;
    match kind {
        // ARP: a request (opcode 1) for the gateway's address.
        // ARP: the station's answer (opcode 2) to the gateway's request.
        0x0806 if p.len() >= 28 && p[6..8] == [0, 2] && p[14..18] == LEASED && p[24..28] == GATEWAY => {
            seen.arp_answers.fetch_add(1, Ordering::Relaxed);
            None
        }
        0x0806 if p.len() >= 28 && p[6..8] == [0, 1] && p[24..28] == GATEWAY => {
            let mut r = p[..28].to_vec();
            r[7] = 2;
            r[8..14].copy_from_slice(&GATEWAY_MAC);
            r[14..18].copy_from_slice(&GATEWAY);
            r[18..28].copy_from_slice(&p[8..18]);
            Some(ethernet(src, 0x0806, &r))
        }
        0x0800 if p.len() >= 20 && p[0] >> 4 == 4 => {
            let hl = (p[0] & 15) as usize * 4;
            let total = (u16::from_be_bytes([p[2], p[3]]) as usize).min(p.len());
            if total < hl {
                return None;
            }
            let (proto, s, d) = (p[9], [p[12], p[13], p[14], p[15]], [p[16], p[17], p[18], p[19]]);
            let frag = u16::from_be_bytes([p[6], p[7]]);
            let first = frag & 0x1fff == 0;
            let body = &p[hl..total];
            if proto == 17 && first && body.len() >= 8 && body[2..4] == 67u16.to_be_bytes() {
                return dhcp(&body[8..], seen);
            }
            if d != GATEWAY {
                return None;
            }
            match proto {
                // An echo request (type 8): the reply, type 0.
                1 if first && body.first() == Some(&8) => {
                    let mut r = body.to_vec();
                    r[0] = 0;
                    r[2..4].fill(0);
                    let c = checksum(&r, 0);
                    r[2..4].copy_from_slice(&c.to_be_bytes());
                    Some(ethernet(src, 0x0800, &ipv4(1, GATEWAY, s, &r)))
                }
                // UDP to the echo port, and fragments of datagrams (which
                // can only be UDP here): sent back with the addresses (and
                // in the first fragment the ports) swapped, which leaves
                // every checksum right.
                17 => {
                    if first && (body.len() < 8 || body[2..4] != ECHO_PORT.to_be_bytes()) {
                        return None;
                    }
                    let mut r = p[..total].to_vec();
                    r[12..16].copy_from_slice(&d);
                    r[16..20].copy_from_slice(&s);
                    if first {
                        let (a, b) = ([r[hl], r[hl + 1]], [r[hl + 2], r[hl + 3]]);
                        r[hl..hl + 2].copy_from_slice(&b);
                        r[hl + 2..hl + 4].copy_from_slice(&a);
                    }
                    Some(ethernet(src, 0x0800, &r))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// The DHCP server's answer to a DISCOVER (an OFFER) or a REQUEST (an
/// ACK), broadcast.
fn dhcp(m: &[u8], seen: &Seen) -> Option<Vec<u8>> {
    if m.len() < 240 || m[0] != 1 || m[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mut kind = 0;
    let mut o = 240;
    while o + 2 <= m.len() && m[o] != 255 {
        if m[o] == 0 {
            o += 1;
            continue;
        }
        if m[o] == 53 && m[o + 1] == 1 {
            kind = *m.get(o + 2)?;
        }
        o += 2 + m[o + 1] as usize;
    }
    let reply = match kind {
        1 => 2, // DISCOVER: OFFER
        3 => 5, // REQUEST: ACK
        _ => return None,
    };
    let mut r = vec![0u8; 240];
    r[0] = 2;
    r[1] = 1;
    r[2] = 6;
    r[4..8].copy_from_slice(&m[4..8]); // xid
    r[10..12].copy_from_slice(&m[10..12]); // flags
    r[16..20].copy_from_slice(&LEASED);
    r[20..24].copy_from_slice(&GATEWAY);
    r[28..44].copy_from_slice(&m[28..44]); // chaddr
    r[236..240].copy_from_slice(&[99, 130, 83, 99]);
    r.extend_from_slice(&[53, 1, reply]);
    r.extend_from_slice(&[54, 4]);
    r.extend_from_slice(&GATEWAY);
    r.extend_from_slice(&[51, 4, 0, 1, 0x51, 0x80]); // 86400 s
    r.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
    r.extend_from_slice(&[3, 4]);
    r.extend_from_slice(&GATEWAY);
    r.extend_from_slice(&[6, 4]);
    r.extend_from_slice(&GATEWAY);
    r.push(255);
    // UDP 67 to 68, its checksum over the pseudo-header.
    let broadcast = [255; 4];
    let mut u = vec![0, 67, 0, 68, 0, 0, 0, 0];
    u[4..6].copy_from_slice(&((8 + r.len()) as u16).to_be_bytes());
    u.extend_from_slice(&r);
    let mut pseudo = GATEWAY.to_vec();
    pseudo.extend_from_slice(&broadcast);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(u.len() as u16).to_be_bytes());
    let acc = pseudo.chunks(2).map(|c| (c[0] as u32) << 8 | c[1] as u32).sum();
    let c = checksum(&u, acc);
    u[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    seen.dhcp.fetch_add(1, Ordering::Relaxed);
    Some(ethernet([0xff; 6], 0x0800, &ipv4(17, GATEWAY, broadcast, &u)))
}
