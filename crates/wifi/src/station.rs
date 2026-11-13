//! A Wi-Fi station's joining and data path, as a state machine with no I/O
//! of its own: a radio driver feeds it the 802.11 frames it receives, the
//! time and the Ethernet frames its network server sends, and gives the
//! radio the 802.11 frames it hands back and the network server the
//! Ethernet frames it delivers.
//!
//! Joining a WPA2-Personal network: probe requests for its SSID until an
//! access point answers (a probe response, or a beacon) advertising WPA2
//! with CCMP and PSK; open system authentication; association, offering
//! the same RSN element; then the 4-way handshake ([`crate::handshake`])
//! in EAPOL frames, which are the only data frames taken unencrypted.
//! Once keyed the link is up: Ethernet frames go out as data frames to the
//! access point sealed with the temporal key, and data frames in are
//! taken only sealed, under the temporal key (to the station) or the group
//! key (to a group), each with its packet numbers rising. A step that gets
//! no answer is tried again a few times, then the station scans afresh;
//! so does a deauthentication or disassociation from its access point.
//!
//! Times are in milliseconds, of any clock that only goes forward.

use crate::ccmp;
use crate::frame::{self, *};
use crate::handshake::{Keys, RSNE_PSK_CCMP, Supplicant};
use crate::sha1::{prf, psk};

/// Where joining has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// No network to join.
    Idle,
    /// Probing for the network.
    Scanning,
    Authenticating,
    Associating,
    /// Associated, the 4-way handshake under way.
    Keying,
    /// Keyed: data flows.
    Up,
}

impl Link {
    pub fn code(self) -> u64 {
        self as u64
    }
}

/// How long each step waits for an answer, and how many times a step is
/// tried before the station scans again.
const PROBE_MS: u64 = 300;
const STEP_MS: u64 = 500;
const KEYING_MS: u64 = 4000;
const TRIES: u32 = 4;

pub struct Station {
    mac: [u8; 6],
    ssid: [u8; 32],
    ssid_len: usize,
    pmk: [u8; 32],
    seed: [u8; 32],
    nonces: u32,
    link: Link,
    bssid: [u8; 6],
    rsne: [u8; 64],
    rsne_len: usize,
    supplicant: Option<Supplicant>,
    keys: Option<Keys>,
    pn: u64,
    rx_pn: Option<u64>,
    group_pn: Option<u64>,
    seq: u16,
    deadline: u64,
    tries: u32,
    /// Frames refused (forged, replayed, unencrypted after keying).
    pub refused: u64,
}

impl Station {
    pub fn new(mac: [u8; 6]) -> Self {
        Station {
            mac,
            ssid: [0; 32],
            ssid_len: 0,
            pmk: [0; 32],
            seed: [0; 32],
            nonces: 0,
            link: Link::Idle,
            bssid: [0; 6],
            rsne: [0; 64],
            rsne_len: 0,
            supplicant: None,
            keys: None,
            pn: 0,
            rx_pn: None,
            group_pn: None,
            seq: 0,
            deadline: 0,
            tries: 0,
            refused: 0,
        }
    }

    /// Joins the WPA2-Personal network `ssid` (1 to 32 bytes) with
    /// `passphrase` (8 to 63 printable characters). `seed` should be
    /// random: the station's nonces are drawn from it. False if either is
    /// out of range.
    pub fn join(&mut self, ssid: &[u8], passphrase: &[u8], seed: [u8; 32], now: u64) -> bool {
        if !(1..=32).contains(&ssid.len()) || !(8..=63).contains(&passphrase.len()) || passphrase.iter().any(|&c| !(32..127).contains(&c)) {
            return false;
        }
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.ssid_len = ssid.len();
        self.pmk = psk(passphrase, ssid);
        self.seed = seed;
        self.scan(now);
        true
    }

    fn scan(&mut self, now: u64) {
        self.link = Link::Scanning;
        self.supplicant = None;
        self.keys = None;
        (self.rx_pn, self.group_pn) = (None, None);
        self.deadline = now;
        self.tries = 0;
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn bssid(&self) -> [u8; 6] {
        self.bssid
    }

    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }

    /// When [`poll`](Self::poll) next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        (!matches!(self.link, Link::Idle | Link::Up)).then_some(self.deadline)
    }

    fn next_seq(&mut self) -> u16 {
        self.seq = (self.seq + 1) & 0xfff;
        self.seq
    }

    /// Sends what is due: probes while scanning, a step again when its
    /// answer is late, or a fresh scan when a step has failed too often.
    pub fn poll(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) {
        if self.deadline().is_none_or(|d| now < d) {
            return;
        }
        match self.link {
            Link::Scanning => {
                self.probe(radio);
                self.deadline = now + PROBE_MS;
            }
            Link::Authenticating | Link::Associating if self.tries < TRIES => {
                self.tries += 1;
                if self.link == Link::Authenticating {
                    self.authenticate(radio);
                } else {
                    self.associate(radio);
                }
                self.deadline = now + STEP_MS;
            }
            _ => self.scan(now),
        }
    }

    fn probe(&mut self, radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 128];
        let seq = self.next_seq();
        let n = header(&mut f, PROBE_REQ, 0, &BROADCAST, &self.mac, &BROADCAST, seq);
        let n = element(&mut f, n, SSID, &self.ssid[..self.ssid_len]);
        let n = element(&mut f, n, RATES, &RATE_SET);
        radio(&f[..n]);
    }

    fn authenticate(&mut self, radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 32];
        let seq = self.next_seq();
        let n = header(&mut f, AUTH, 0, &self.bssid, &self.mac, &self.bssid, seq);
        // Open system, transaction 1, status 0.
        f[n..n + 6].copy_from_slice(&[0, 0, 1, 0, 0, 0]);
        radio(&f[..n + 6]);
    }

    fn associate(&mut self, radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 160];
        let seq = self.next_seq();
        let mut n = header(&mut f, ASSOC_REQ, 0, &self.bssid, &self.mac, &self.bssid, seq);
        f[n..n + 2].copy_from_slice(&CAPABILITY.to_le_bytes());
        f[n + 2..n + 4].copy_from_slice(&10u16.to_le_bytes()); // listen interval
        n += 4;
        n = element(&mut f, n, SSID, &self.ssid[..self.ssid_len]);
        n = element(&mut f, n, RATES, &RATE_SET);
        f[n..n + RSNE_PSK_CCMP.len()].copy_from_slice(&RSNE_PSK_CCMP);
        n += RSNE_PSK_CCMP.len();
        radio(&f[..n]);
    }

    /// A fresh nonce for a handshake, from the seed and a counter.
    fn nonce(&mut self) -> [u8; 32] {
        self.nonces += 1;
        let mut n = [0u8; 32];
        prf(&self.seed, b"Init Counter", &[&self.mac, &self.nonces.to_be_bytes()], &mut n);
        n
    }

    /// Takes a frame from the radio.
    pub fn receive(&mut self, f: &[u8], now: u64, radio: &mut dyn FnMut(&[u8]), up: &mut dyn FnMut(&[u8])) {
        if f.len() < HEADER || self.link == Link::Idle {
            return;
        }
        let (fc0, fc1) = (f[0], f[1]);
        let (a1, a2, a3) = (addr(f, 1), addr(f, 2), addr(f, 3));
        let to_us = a1 == self.mac;
        let body = &f[HEADER..];
        match fc0 {
            PROBE_RESP | BEACON if self.link == Link::Scanning => {
                // Timestamp, interval, capability, then elements.
                let Some(elems) = body.get(12..) else { return };
                let ssid = frame::elements(elems).find(|e| e.0 == SSID).map(|e| e.1);
                let rsne = find_element(elems, RSN);
                if ssid != Some(self.ssid()) || rsne != Some(&RSNE_PSK_CCMP[..]) {
                    return; // another network, or not WPA2-PSK with CCMP
                }
                let rsne = rsne.unwrap();
                self.rsne[..rsne.len()].copy_from_slice(rsne);
                self.rsne_len = rsne.len();
                self.bssid = a3;
                self.link = Link::Authenticating;
                self.tries = 0;
                self.deadline = now;
                self.poll(now, radio);
            }
            AUTH if to_us && a2 == self.bssid && self.link == Link::Authenticating => {
                if body.len() >= 6 && body[..6] == [0, 0, 2, 0, 0, 0] {
                    self.link = Link::Associating;
                    self.tries = 0;
                    self.deadline = now;
                    self.poll(now, radio);
                }
            }
            ASSOC_RESP if to_us && a2 == self.bssid && self.link == Link::Associating => {
                if body.len() >= 6 && body[2..4] == [0, 0] {
                    let snonce = self.nonce();
                    let theirs = &self.rsne[..self.rsne_len];
                    self.supplicant = Some(Supplicant::new(self.pmk, self.mac, self.bssid, snonce, &RSNE_PSK_CCMP, theirs));
                    self.link = Link::Keying;
                    self.deadline = now + KEYING_MS;
                } else {
                    self.scan(now);
                }
            }
            DEAUTH | DISASSOC if to_us && a2 == self.bssid && self.link != Link::Scanning => self.scan(now),
            DATA if fc1 & (TO_DS | FROM_DS) == FROM_DS && a2 == self.bssid => {
                self.data(f, fc1, a1, a3, now, radio, up);
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn data(&mut self, f: &[u8], fc1: u8, da: [u8; 6], sa: [u8; 6], now: u64, radio: &mut dyn FnMut(&[u8]), up: &mut dyn FnMut(&[u8])) {
        let group = multicast(&da);
        if !group && da != self.mac {
            return;
        }
        if fc1 & PROTECTED == 0 {
            // Only the handshake travels in the clear, and only while
            // keying.
            match frame::snap(&f[HEADER..]) {
                // While up, a message 3 sent again (its message 4 lost)
                // is answered again.
                Some((EAPOL, eapol)) if matches!(self.link, Link::Keying | Link::Up) && !group => self.eapol(eapol, now, radio),
                _ => self.refused += 1,
            }
            return;
        }
        let Some(keys) = self.keys.filter(|_| self.link == Link::Up) else {
            return;
        };
        let mut copy = [0u8; MAX];
        let Some(copy) = copy.get_mut(..f.len()) else { return };
        copy.copy_from_slice(f);
        let (key, last) = if group { (&keys.gtk.key, &mut self.group_pn) } else { (&keys.tk, &mut self.rx_pn) };
        let Ok((range, pn)) = ccmp::open(key, copy, *last) else {
            self.refused += 1;
            return;
        };
        *last = Some(pn);
        if let Some((kind, payload)) = frame::snap(&copy[range]) {
            if kind == EAPOL {
                return; // no rekeying yet
            }
            let mut eth = [0u8; 1514];
            if let Some(n) = to_ethernet(&mut eth, &da, &sa, kind, payload) {
                up(&eth[..n]);
            }
        }
    }

    fn eapol(&mut self, eapol: &[u8], now: u64, radio: &mut dyn FnMut(&[u8])) {
        let Some(s) = self.supplicant.as_mut() else { return };
        let Ok(reply) = s.receive(eapol) else {
            self.refused += 1;
            return;
        };
        let keys = s.keys();
        let mut f = [0u8; 400];
        let seq = self.next_seq();
        let n = header(&mut f, DATA, TO_DS, &self.bssid, &self.mac, &self.bssid, seq);
        let Some(b) = data_body(&mut f[n..], EAPOL, reply.bytes()) else { return };
        radio(&f[..n + b]);
        if let Some(keys) = keys.filter(|_| self.link == Link::Keying) {
            self.keys = Some(keys);
            self.link = Link::Up;
            self.pn = 0;
            self.deadline = now;
        }
    }

    /// An Ethernet frame from the network server, sealed for the radio
    /// into `out`: its length, or `None` while the link is not up.
    pub fn send(&mut self, eth: &[u8], out: &mut [u8]) -> Option<usize> {
        let keys = self.keys.filter(|_| self.link == Link::Up)?;
        let (da, _, kind, payload) = frame::ethernet(eth)?;
        let mut h = [0u8; HEADER];
        let seq = self.next_seq();
        header(&mut h, DATA, TO_DS, &self.bssid, &self.mac, &da, seq);
        let mut body = [0u8; 8 + 1500];
        let n = data_body(&mut body, kind, payload.get(..payload.len().min(1500))?)?;
        self.pn += 1;
        ccmp::seal(&keys.tk, self.pn, 0, &h, &body[..n], out)
    }
}
