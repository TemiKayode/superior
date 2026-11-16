//! A Wi-Fi station's joining and data path, as a state machine with no I/O
//! of its own: a radio driver feeds it the 802.11 frames it receives, the
//! time and the Ethernet frames its network server sends, and gives the
//! radio the 802.11 frames it hands back and the network server the
//! Ethernet frames it delivers.
//!
//! Joining a WPA2- or WPA3-Personal network: probe requests for its SSID
//! until an access point answers (a probe response, or a beacon)
//! advertising CCMP with PSK or SAE (SAE preferred when both are offered);
//! authentication, open system for PSK or SAE's commit and confirm
//! exchange ([`crate::sae`], which yields the PMK); association, offering
//! the RSN element of the suite chosen; then the 4-way handshake
//! ([`crate::handshake`]) in EAPOL frames, which are the only data frames
//! taken unencrypted. Under SAE management frame protection is on: once
//! keyed, a deauthentication or disassociation is obeyed only if it comes
//! sealed under the temporal key, or, sent to every station, with a valid
//! MMIE under the integrity group key ([`crate::bip`]), so a forged one
//! cannot knock the station off.
//! Once keyed the link is up: Ethernet frames go out as data frames to the
//! access point sealed with the temporal key, and data frames in are
//! taken only sealed, under the temporal key (to the station) or the group
//! key (to a group), each with its packet numbers rising. A step that gets
//! no answer is tried again a few times, then the station scans afresh;
//! so does a deauthentication or disassociation from its access point.
//!
//! The access point may renew the keys while the link is up (see
//! [`crate::handshake`]); handshake frames then travel sealed under the
//! keys in place. A new temporal key is used for sending as soon as it is
//! installed, while the old one still opens frames the access point sent
//! before it switched (until one comes under the new key); group keys are
//! held by key ID, so frames under the outgoing one still open.
//!
//! Apart from joining, the station can survey the networks in range
//! ([`Station::survey`]), linked or not: probe requests for any SSID, and
//! every beacon and probe response heard for a while recorded with its
//! signal strength, channel and security ([`Network`]), strongest first.
//!
//! Times are in milliseconds, of any clock that only goes forward. Each
//! frame received comes with its signal strength (dBm), as the radio
//! measured it.

use crate::ccmp;
use crate::frame::{self, *};
use crate::handshake::{Akm, Keys, Supplicant};
use crate::sae::{self, Sae};
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

/// How a network is secured, from its RSN element (or its absence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// No RSN element and no privacy bit: open.
    Open,
    /// WPA2-Personal with CCMP: what the station can join.
    Wpa2Psk,
    /// WPA3-Personal (SAE) only.
    Wpa3Sae,
    /// WPA2- and WPA3-Personal both offered (transition mode).
    Wpa2Wpa3,
    /// 802.1X (Enterprise).
    Enterprise,
    /// Anything else (WEP, TKIP only, unknown suites).
    Other,
}

impl Security {
    pub fn code(self) -> u8 {
        self as u8
    }

    /// From a beacon's capability field and RSN element (the whole
    /// element, if any).
    pub fn of(capability: u16, rsne: Option<&[u8]>) -> Security {
        let Some(e) = rsne else {
            return if capability & 0x10 != 0 { Security::Other } else { Security::Open };
        };
        // ID, length, version (2), group cipher (4), pairwise count and
        // suites, AKM count and suites.
        let suites = |at: usize| -> Option<(usize, &[u8])> {
            let n = u16::from_le_bytes([*e.get(at)?, *e.get(at + 1)?]) as usize;
            Some((at + 2 + 4 * n, e.get(at + 2..at + 2 + 4 * n)?))
        };
        let Some((akm_at, pairwise)) = suites(8) else { return Security::Other };
        let Some((_, akms)) = suites(akm_at) else { return Security::Other };
        let ccmp = pairwise.chunks(4).any(|c| c == [0x00, 0x0f, 0xac, 4]);
        let has = |t: u8| akms.chunks(4).any(|c| c == [0x00, 0x0f, 0xac, t]);
        match (has(2), has(8), has(1)) {
            _ if !ccmp => Security::Other,
            (true, true, _) => Security::Wpa2Wpa3,
            (true, false, _) => Security::Wpa2Psk,
            (false, true, _) => Security::Wpa3Sae,
            (false, false, true) => Security::Enterprise,
            _ => Security::Other,
        }
    }
}

/// A network heard while surveying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub bssid: [u8; 6],
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    /// The strongest signal heard from it, in dBm.
    pub signal: i8,
    /// Its channel (from its DS parameter set; 0 if it gave none).
    pub channel: u8,
    pub security: Security,
}

impl Network {
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
}

/// The networks a survey keeps, and how long it listens (a second wildcard
/// probe halfway).
pub const NETWORKS: usize = 32;
const SURVEY_MS: u64 = 400;

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
    /// The passphrase's PSK, and the passphrase itself (SAE's password).
    psk: [u8; 32],
    password: [u8; 63],
    password_len: usize,
    /// The suite chosen for the network found, and its PMK once known.
    akm: Akm,
    pmk: [u8; 32],
    sae: Option<Sae>,
    /// Whether the network found takes SAE by hash-to-element, and its
    /// password element PT (computed once per network joined).
    h2e: bool,
    pt: Option<crate::p256::Affine>,
    /// The anti-clogging token the access point asked to see with the
    /// commit (status 76), if it did.
    token: [u8; 32],
    token_len: usize,
    /// The last packet number of a sealed management frame taken.
    mgmt_pn: Option<u64>,
    /// The last BIP packet number accepted from the access point.
    bip_ipn: Option<u64>,
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
    /// The previous temporal key after a rekeying, and its last packet
    /// number, until a frame comes under the new one.
    old_tk: Option<([u8; 16], Option<u64>)>,
    /// Group keys by key ID, each with its last packet number.
    groups: [Option<([u8; 16], Option<u64>)>; 4],
    installs: u32,
    seq: u16,
    deadline: u64,
    tries: u32,
    /// Frames refused (forged, replayed, unencrypted after keying).
    pub refused: u64,
    /// Unprotected deauthentications and disassociations ignored under
    /// management frame protection (forgeries, as far as it can tell).
    pub ignored_deauths: u32,
    /// Of those, the ones sent to every station (BIP refused them), and
    /// why the last was refused.
    pub ignored_group_deauths: u32,
    pub last_bip_refusal: Option<crate::bip::Refused>,
    /// Rekeyings since the link came up: pairwise, and group.
    pub rekeys: u32,
    pub group_rekeys: u32,
    /// A survey: when its next step is due (the second probe, then the
    /// end), and whether the second probe has gone.
    survey: Option<(u64, bool)>,
    networks: [Option<Network>; NETWORKS],
    found: usize,
}

impl Station {
    pub fn new(mac: [u8; 6]) -> Self {
        Station {
            mac,
            ssid: [0; 32],
            ssid_len: 0,
            psk: [0; 32],
            password: [0; 63],
            password_len: 0,
            akm: Akm::Psk,
            pmk: [0; 32],
            sae: None,
            h2e: false,
            pt: None,
            token: [0; 32],
            token_len: 0,
            mgmt_pn: None,
            bip_ipn: None,
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
            old_tk: None,
            groups: [None; 4],
            installs: 0,
            seq: 0,
            deadline: 0,
            tries: 0,
            refused: 0,
            ignored_deauths: 0,
            ignored_group_deauths: 0,
            last_bip_refusal: None,
            rekeys: 0,
            group_rekeys: 0,
            survey: None,
            networks: [None; NETWORKS],
            found: 0,
        }
    }

    /// Starts surveying the networks in range (whatever the link is
    /// doing), forgetting the last survey's: false if one is under way.
    pub fn survey(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) -> bool {
        if self.survey.is_some() {
            return false;
        }
        (self.networks, self.found) = ([None; NETWORKS], 0);
        self.survey = Some((now + SURVEY_MS / 2, false));
        self.probe_any(radio);
        true
    }

    /// Whether a survey is under way.
    pub fn surveying(&self) -> bool {
        self.survey.is_some()
    }

    /// The last survey's networks, strongest first (once it has ended).
    pub fn networks(&self) -> impl Iterator<Item = &Network> {
        self.networks[..self.found].iter().flatten()
    }

    fn probe_any(&mut self, radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 64];
        let seq = self.next_seq();
        let n = header(&mut f, PROBE_REQ, 0, &BROADCAST, &self.mac, &BROADCAST, seq);
        let n = element(&mut f, n, SSID, &[]);
        let n = element(&mut f, n, RATES, &RATE_SET);
        radio(&f[..n]);
    }

    /// Records a beacon or probe response heard while surveying.
    fn heard(&mut self, bssid: [u8; 6], body: &[u8], signal: i8) {
        let Some(elems) = body.get(12..) else { return };
        let capability = u16::from_le_bytes([body[10], body[11]]);
        let ssid = frame::elements(elems).find(|e| e.0 == SSID).map_or(&[][..], |e| e.1);
        let channel = frame::elements(elems).find(|e| e.0 == DS_PARAMS).and_then(|e| e.1.first().copied()).unwrap_or(0);
        let mut n = Network {
            bssid,
            ssid: [0; 32],
            ssid_len: ssid.len().min(32) as u8,
            signal,
            channel,
            security: Security::of(capability, find_element(elems, RSN)),
        };
        n.ssid[..n.ssid_len as usize].copy_from_slice(&ssid[..n.ssid_len as usize]);
        match self.networks[..self.found].iter_mut().flatten().find(|k| k.bssid == bssid) {
            Some(k) => {
                // Heard again: the strongest signal is kept.
                let strongest = k.signal.max(signal);
                *k = n;
                k.signal = strongest;
            }
            None if self.found < NETWORKS => {
                self.networks[self.found] = Some(n);
                self.found += 1;
            }
            None => {}
        }
    }

    /// The survey's step when due: the second probe, then the end (the
    /// networks sorted, strongest first).
    fn survey_step(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) {
        let Some((due, probed)) = self.survey.filter(|s| now >= s.0) else { return };
        if !probed {
            self.survey = Some((due + SURVEY_MS / 2, true));
            self.probe_any(radio);
            return;
        }
        self.survey = None;
        // Strongest first: an insertion sort (32 at most; core's sorts
        // bring in code that does not link position-independent).
        let signal = |n: &Option<Network>| n.map_or(i8::MIN, |n| n.signal);
        for i in 1..self.found {
            let mut j = i;
            while j > 0 && signal(&self.networks[j - 1]) < signal(&self.networks[j]) {
                self.networks.swap(j - 1, j);
                j -= 1;
            }
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
        self.psk = psk(passphrase, ssid);
        self.password[..passphrase.len()].copy_from_slice(passphrase);
        self.password_len = passphrase.len();
        self.pt = None;
        self.seed = seed;
        self.scan(now);
        true
    }

    fn scan(&mut self, now: u64) {
        self.link = Link::Scanning;
        self.supplicant = None;
        (self.sae, self.mgmt_pn, self.bip_ipn) = (None, None, None);
        self.keys = None;
        (self.rx_pn, self.old_tk, self.groups, self.installs) = (None, None, [None; 4], 0);
        self.deadline = now;
        self.tries = 0;
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn bssid(&self) -> [u8; 6] {
        self.bssid
    }

    /// The suite chosen for the network being joined (or joined).
    /// Whether SAE runs by hash-to-element with this network.
    pub fn hash_to_element(&self) -> bool {
        self.akm == Akm::Sae && self.h2e
    }

    pub fn akm(&self) -> Akm {
        self.akm
    }

    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }

    /// When [`poll`](Self::poll) next has something to do.
    pub fn deadline(&self) -> Option<u64> {
        let join = (!matches!(self.link, Link::Idle | Link::Up)).then_some(self.deadline);
        let survey = self.survey.map(|s| s.0);
        match (join, survey) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn next_seq(&mut self) -> u16 {
        self.seq = (self.seq + 1) & 0xfff;
        self.seq
    }

    /// Sends what is due: probes while scanning, a step again when its
    /// answer is late, or a fresh scan when a step has failed too often.
    pub fn poll(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) {
        self.survey_step(now, radio);
        if matches!(self.link, Link::Idle | Link::Up) || now < self.deadline {
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

    /// Authentication, first or again: open system's request, or SAE's
    /// commit (the same one again until the access point's commit comes),
    /// then its confirm.
    fn authenticate(&mut self, radio: &mut dyn FnMut(&[u8])) {
        if self.akm == Akm::Psk {
            self.auth_frame(&[0, 0, 1, 0, 0, 0], &[], radio);
            return;
        }
        if self.sae.is_none() {
            // A few draws, in case one gives an unusable scalar.
            for _ in 0..4 {
                let mut r = [0u8; 64];
                r[..32].copy_from_slice(&self.nonce());
                r[32..].copy_from_slice(&self.nonce());
                self.sae = match self.h2e {
                    true => {
                        if self.pt.is_none() {
                            self.pt = sae::pt(&self.ssid[..self.ssid_len], &self.password[..self.password_len]);
                        }
                        self.pt.as_ref().and_then(|pt| Sae::new_h2e(pt, &self.mac, &self.bssid, &r))
                    }
                    false => Sae::new(&self.password[..self.password_len], &self.mac, &self.bssid, &r),
                };
                if self.sae.is_some() {
                    break;
                }
            }
        }
        let Some(sae) = self.sae.as_mut() else { return };
        match sae.confirm() {
            // The access point's commit came: our confirm again.
            Some(c) => self.auth_frame(&[3, 0, 2, 0, 0, 0], &c, radio),
            None => {
                // Status 126 marks a commit by hash-to-element. With the
                // token asked for: after the group under hunting and
                // pecking, in a container element after it all under H2E.
                let c = sae.commit();
                let status = if self.h2e { 126 } else { 0 };
                let (t, n) = (self.token, self.token_len);
                let mut b = [0u8; sae::COMMIT_LEN + 3 + 32];
                let len = match (n, self.h2e) {
                    (0, _) => {
                        b[..sae::COMMIT_LEN].copy_from_slice(&c);
                        sae::COMMIT_LEN
                    }
                    (_, false) => {
                        b[..2].copy_from_slice(&c[..2]);
                        b[2..2 + n].copy_from_slice(&t[..n]);
                        b[2 + n..sae::COMMIT_LEN + n].copy_from_slice(&c[2..]);
                        sae::COMMIT_LEN + n
                    }
                    (_, true) => {
                        b[..sae::COMMIT_LEN].copy_from_slice(&c);
                        b[sae::COMMIT_LEN..sae::COMMIT_LEN + 3].copy_from_slice(&[255, n as u8 + 1, 93]);
                        b[sae::COMMIT_LEN + 3..sae::COMMIT_LEN + 3 + n].copy_from_slice(&t[..n]);
                        sae::COMMIT_LEN + 3 + n
                    }
                };
                self.auth_frame(&[3, 0, 1, 0, status, 0], &b[..len], radio);
            }
        }
    }

    /// An authentication frame to the access point: algorithm, transaction
    /// and status (`head`), then `body`.
    fn auth_frame(&mut self, head: &[u8; 6], body: &[u8], radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 200];
        let seq = self.next_seq();
        let n = header(&mut f, AUTH, 0, &self.bssid, &self.mac, &self.bssid, seq);
        f[n..n + 6].copy_from_slice(head);
        f[n + 6..n + 6 + body.len()].copy_from_slice(body);
        radio(&f[..n + 6 + body.len()]);
    }

    /// Authenticated: on to association.
    fn authenticated(&mut self, pmk: [u8; 32], now: u64, radio: &mut dyn FnMut(&[u8])) {
        self.pmk = pmk;
        self.link = Link::Associating;
        self.tries = 0;
        self.deadline = now;
        self.poll(now, radio);
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
        let rsne = self.akm.rsne();
        f[n..n + rsne.len()].copy_from_slice(rsne);
        n += rsne.len();
        // It takes hash-to-element, and says so whatever it heard: an
        // access point that offers H2E then sees a downgrade if this
        // exchange was by hunting and pecking.
        if self.akm == Akm::Sae {
            n = element(&mut f, n, RSNX, &[RSNX_H2E]);
        }
        radio(&f[..n]);
    }

    /// A fresh nonce for a handshake, from the seed and a counter.
    fn nonce(&mut self) -> [u8; 32] {
        self.nonces += 1;
        let mut n = [0u8; 32];
        prf(&self.seed, b"Init Counter", &[&self.mac, &self.nonces.to_be_bytes()], &mut n);
        n
    }

    /// Takes a frame from the radio, heard at `signal` dBm.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(&mut self, f: &[u8], signal: i8, now: u64, radio: &mut dyn FnMut(&[u8]), up: &mut dyn FnMut(&[u8])) {
        if f.len() < HEADER {
            return;
        }
        let (fc0, fc1) = (f[0], f[1]);
        let (a1, a2, a3) = (addr(f, 1), addr(f, 2), addr(f, 3));
        let to_us = a1 == self.mac;
        let body = &f[HEADER..];
        if self.survey.is_some() && (fc0 == BEACON || fc0 == PROBE_RESP && to_us) && body.len() >= 12 {
            self.heard(a3, body, signal);
        }
        if self.link == Link::Idle {
            return;
        }
        match fc0 {
            PROBE_RESP | BEACON if self.link == Link::Scanning => {
                // Timestamp, interval, capability, then elements.
                let Some(elems) = body.get(12..) else { return };
                let ssid = frame::elements(elems).find(|e| e.0 == SSID).map(|e| e.1);
                let rsne = find_element(elems, RSN);
                let akm = match Security::of(u16::from_le_bytes([body[10], body[11]]), rsne) {
                    Security::Wpa3Sae | Security::Wpa2Wpa3 => Akm::Sae,
                    Security::Wpa2Psk => Akm::Psk,
                    _ => return, // not WPA2- or WPA3-Personal with CCMP
                };
                if ssid != Some(self.ssid()) || rsne.is_none_or(|e| e.len() > 64) {
                    return; // another network
                }
                let rsne = rsne.unwrap();
                self.akm = akm;
                self.sae = None;
                self.token_len = 0;
                let h2e = akm == Akm::Sae && find_element(elems, RSNX).is_some_and(|e| e.first().is_some_and(|b| b & RSNX_H2E != 0));
                if h2e != self.h2e {
                    self.pt = None;
                }
                self.h2e = h2e;
                self.rsne[..rsne.len()].copy_from_slice(rsne);
                self.rsne_len = rsne.len();
                self.bssid = a3;
                self.link = Link::Authenticating;
                self.tries = 0;
                self.deadline = now;
                self.poll(now, radio);
            }
            AUTH if to_us && a2 == self.bssid && self.link == Link::Authenticating && body.len() >= 6 => {
                match (self.akm, &body[..6]) {
                    (Akm::Psk, [0, 0, 2, 0, 0, 0]) => self.authenticated(self.psk, now, radio),
                    // SAE: the access point's commit, answered with our
                    // confirm; then its confirm, which gives the PMK.
                    // (Status 126 under hash-to-element, 0 otherwise.)
                    (Akm::Sae, [3, 0, 1, 0, status, 0]) if *status == if self.h2e { 126 } else { 0 } => {
                        let Some(s) = self.sae.as_mut() else { return };
                        match s.receive_commit(&body[6..]) {
                            Ok(c) => {
                                self.auth_frame(&[3, 0, 2, 0, 0, 0], &c, radio);
                                self.deadline = now + STEP_MS;
                            }
                            Err(_) => self.refused += 1,
                        }
                    }
                    // Status 76: our commit again, with the token it holds.
                    (Akm::Sae, [3, 0, 1, 0, 76, 0]) if body.len() > 8 && body[6..8] == [19, 0] && self.sae.is_some() => {
                        let t = &body[8..body.len().min(8 + 32)];
                        self.token[..t.len()].copy_from_slice(t);
                        self.token_len = t.len();
                        self.authenticate(radio);
                        self.deadline = now + STEP_MS;
                    }
                    (Akm::Sae, [3, 0, 2, 0, 0, 0]) => {
                        let Some(s) = self.sae.as_mut() else { return };
                        match s.receive_confirm(&body[6..]).map(|_| s.pmk()) {
                            Ok(Some(pmk)) => self.authenticated(pmk, now, radio),
                            _ => self.refused += 1,
                        }
                    }
                    _ => {}
                }
            }
            ASSOC_RESP if to_us && a2 == self.bssid && self.link == Link::Associating => {
                if body.len() >= 6 && body[2..4] == [0, 0] {
                    let snonce = self.nonce();
                    let theirs = &self.rsne[..self.rsne_len];
                    self.supplicant = Some(Supplicant::new(self.akm, self.pmk, self.mac, self.bssid, snonce, self.akm.rsne(), theirs));
                    self.link = Link::Keying;
                    self.deadline = now + KEYING_MS;
                } else {
                    self.scan(now);
                }
            }
            DEAUTH | DISASSOC if to_us && a2 == self.bssid && self.link != Link::Scanning => {
                // Under management frame protection, only a sealed one.
                if self.akm == Akm::Sae && self.link == Link::Up {
                    let Some(keys) = self.keys else { return };
                    let mut copy = [0u8; 64];
                    let Some(copy) = copy.get_mut(..f.len()) else { return };
                    copy.copy_from_slice(f);
                    match ccmp::open(&keys.tk, copy, self.mgmt_pn) {
                        Ok((_, pn)) if fc1 & PROTECTED != 0 => self.mgmt_pn = Some(pn),
                        _ => {
                            self.refused += 1;
                            self.ignored_deauths += (fc1 & PROTECTED == 0) as u32;
                            return;
                        }
                    }
                }
                self.scan(now);
            }
            DEAUTH | DISASSOC if a1 == BROADCAST && a2 == self.bssid && self.link != Link::Scanning => {
                // To every station: under management frame protection,
                // only with a valid MMIE under the integrity group key.
                if self.akm == Akm::Sae && self.link == Link::Up {
                    let Some(igtk) = self.keys.and_then(|k| k.igtk) else { return };
                    match crate::bip::verify(&igtk, f, self.bip_ipn) {
                        Ok(ipn) => self.bip_ipn = Some(ipn),
                        Err(why) => {
                            self.refused += 1;
                            self.ignored_deauths += 1;
                            self.ignored_group_deauths += 1;
                            self.last_bip_refusal = Some(why);
                            return;
                        }
                    }
                }
                self.scan(now);
            }
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
                Some((EAPOL, eapol)) if matches!(self.link, Link::Keying | Link::Up) && !group => self.eapol(eapol, false, now, radio),
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
        let opened = if group {
            let id = ccmp::header_len(copy).and_then(|h| copy.get(h + 3)).map_or(0, |b| (b >> 6) as usize);
            match self.groups[id] {
                Some((key, last)) => ccmp::open(&key, copy, last).inspect(|r| self.groups[id] = Some((key, Some(r.1)))),
                None => Err(ccmp::Refused::Forged),
            }
        } else {
            match ccmp::open(&keys.tk, copy, self.rx_pn) {
                Ok(r) => {
                    // The access point has switched to the new key.
                    self.old_tk = None;
                    self.rx_pn = Some(r.1);
                    Ok(r)
                }
                Err(_) if self.old_tk.is_some() => {
                    copy.copy_from_slice(f);
                    let (key, last) = self.old_tk.unwrap();
                    ccmp::open(&key, copy, last).inspect(|r| self.old_tk = Some((key, Some(r.1))))
                }
                Err(e) => Err(e),
            }
        };
        let Ok((range, _)) = opened else {
            self.refused += 1;
            return;
        };
        if let Some((kind, payload)) = frame::snap(&copy[range]) {
            if kind == EAPOL {
                // A rekeying, under the keys in place.
                if !group {
                    self.eapol(payload, true, now, radio);
                }
                return;
            }
            let mut eth = [0u8; 1514];
            if let Some(n) = to_ethernet(&mut eth, &da, &sa, kind, payload) {
                up(&eth[..n]);
            }
        }
    }

    fn eapol(&mut self, eapol: &[u8], sealed: bool, now: u64, radio: &mut dyn FnMut(&[u8])) {
        let Some(s) = self.supplicant.as_mut() else { return };
        let Ok(reply) = s.receive(eapol) else {
            self.refused += 1;
            return;
        };
        let (keys, installs) = (s.keys(), s.installs());
        let mut f = [0u8; 400];
        let seq = self.next_seq();
        let n = header(&mut f, DATA, TO_DS, &self.bssid, &self.mac, &self.bssid, seq);
        let Some(b) = data_body(&mut f[n..], EAPOL, reply.bytes()) else { return };
        // Sealed if what it answers was (a rekeying), under the keys in place
        // (so a message 4 goes under the old key, before the new is installed).
        match self.keys.filter(|_| sealed && self.link == Link::Up) {
            Some(k) => {
                let mut out = [0u8; 400 + ccmp::HEADER + ccmp::MIC];
                self.pn += 1;
                if let Some(m) = ccmp::seal(&k.tk, self.pn, 0, &f[..n], &f[n..n + b], &mut out) {
                    radio(&out[..m]);
                }
            }
            None => radio(&f[..n + b]),
        }
        if installs != self.installs {
            self.installs = installs;
            if let Some(new) = keys {
                self.install(new, now);
            }
        }
        if self.link == Link::Up && self.supplicant.as_ref().is_some_and(|s| s.needs_nonce()) {
            let n = self.nonce();
            if let Some(s) = self.supplicant.as_mut() {
                s.renew(n);
            }
        }
    }

    /// Puts keys the handshake installed in use: the first, bringing the
    /// link up, or renewed ones.
    fn install(&mut self, new: Keys, now: u64) {
        let g = (new.gtk.index & 3) as usize;
        match self.keys.filter(|_| self.link == Link::Up) {
            None => {
                self.keys = Some(new);
                self.link = Link::Up;
                self.pn = 0;
                (self.rx_pn, self.old_tk, self.groups) = (None, None, [None; 4]);
                self.groups[g] = Some((new.gtk.key, None));
                (self.rekeys, self.group_rekeys) = (0, 0);
                // BIP: only packet numbers above the one message 3 gave.
                self.bip_ipn = new.igtk.map(|i| i.pn);
                self.deadline = now;
            }
            Some(old) => {
                if new.tk != old.tk {
                    self.old_tk = Some((old.tk, self.rx_pn));
                    self.rx_pn = None;
                    self.pn = 0;
                    self.rekeys += 1;
                }
                if new.gtk != old.gtk {
                    if self.groups[g].map(|k| k.0) != Some(new.gtk.key) {
                        self.groups[g] = Some((new.gtk.key, None));
                    }
                    self.group_rekeys += 1;
                }
                if new.igtk.map(|i| (i.index, i.key)) != old.igtk.map(|i| (i.index, i.key)) {
                    self.bip_ipn = new.igtk.map(|i| i.pn);
                }
                self.keys = Some(new);
            }
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
