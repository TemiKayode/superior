//! A WPA2-Personal access point for one station, as a state machine with
//! no I/O of its own: what the test harness plays at the far end of the
//! simulated radio (and what a host test joins a [`Station`] to).
//!
//! It answers probe requests for its SSID, open system authentication and
//! association (if the station offers WPA2-PSK with CCMP), runs the access
//! point's side of the 4-way handshake ([`Authenticator`]), and then
//! carries Ethernet frames both ways: the station's, opened under the
//! temporal key, and its own, sealed with the temporal key to the station
//! or the group key to a group. Once the station is keyed it can renew the
//! pairwise keys ([`AccessPoint::rekey`]) or the group key
//! ([`AccessPoint::rekey_group`]), the handshake's frames then sealed
//! under the keys in place; it switches to new keys when the station
//! confirms them.
//!
//! [`Station`]: crate::station::Station

use crate::ccmp;
use crate::frame::{self, *};
use crate::handshake::{Authenticator, Gtk, RSNE_PSK_CCMP};
use crate::sha1::{prf, psk};

/// How long the access point waits for a handshake answer before sending
/// message 1 again.
const RESEND_MS: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    None,
    Authenticated,
    /// Associated, the handshake under way.
    Keying,
    Up,
}

pub struct AccessPoint {
    bssid: [u8; 6],
    ssid: [u8; 32],
    ssid_len: usize,
    pmk: [u8; 32],
    gtk: Gtk,
    seed: [u8; 32],
    nonces: u32,
    station: [u8; 6],
    peer: Peer,
    auth: Option<Authenticator>,
    tk: [u8; 16],
    pn: u64,
    group_pn: u64,
    rx_pn: Option<u64>,
    /// The last packet number taken under a pending new temporal key.
    pending_pn: Option<u64>,
    seq: u16,
    resend: u64,
    /// Data frames refused: forged, replayed, or in the clear.
    pub refused: u64,
    /// Rekeyings finished: pairwise, and group.
    pub rekeys: u32,
    pub group_rekeys: u32,
}

impl AccessPoint {
    pub fn new(bssid: [u8; 6], ssid: &[u8], passphrase: &[u8], gtk: Gtk, seed: [u8; 32]) -> Self {
        let mut s = [0u8; 32];
        let n = ssid.len().min(32);
        s[..n].copy_from_slice(&ssid[..n]);
        AccessPoint {
            bssid,
            ssid: s,
            ssid_len: n,
            pmk: psk(passphrase, &ssid[..n]),
            gtk,
            seed,
            nonces: 0,
            station: [0; 6],
            peer: Peer::None,
            auth: None,
            tk: [0; 16],
            pn: 0,
            group_pn: 0,
            rx_pn: None,
            pending_pn: None,
            seq: 0,
            resend: 0,
            refused: 0,
            rekeys: 0,
            group_rekeys: 0,
        }
    }

    pub fn peer(&self) -> Peer {
        self.peer
    }

    pub fn station(&self) -> [u8; 6] {
        self.station
    }

    fn next_seq(&mut self) -> u16 {
        self.seq = (self.seq + 1) & 0xfff;
        self.seq
    }

    /// A beacon or a probe response to `to`: timestamp, interval (100
    /// TU), capability, SSID, rates, channel 6, the RSN element.
    fn announce(&mut self, fc0: u8, to: &[u8; 6], out: &mut [u8]) -> usize {
        let seq = self.next_seq();
        let mut n = header(out, fc0, 0, to, &self.bssid, &self.bssid, seq);
        out[n..n + 12].fill(0);
        out[n + 8..n + 10].copy_from_slice(&100u16.to_le_bytes());
        out[n + 10..n + 12].copy_from_slice(&CAPABILITY.to_le_bytes());
        n += 12;
        n = element(out, n, SSID, &self.ssid[..self.ssid_len]);
        n = element(out, n, RATES, &RATE_SET);
        n = element(out, n, DS_PARAMS, &[6]);
        out[n..n + RSNE_PSK_CCMP.len()].copy_from_slice(&RSNE_PSK_CCMP);
        n + RSNE_PSK_CCMP.len()
    }

    /// A beacon, into `out` (200 bytes is room enough).
    pub fn beacon(&mut self, out: &mut [u8]) -> usize {
        self.announce(BEACON, &BROADCAST, out)
    }

    fn reply(&mut self, fc0: u8, body: &[u8], radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 64];
        let seq = self.next_seq();
        let n = header(&mut f, fc0, 0, &self.station, &self.bssid, &self.bssid, seq);
        f[n..n + body.len()].copy_from_slice(body);
        radio(&f[..n + body.len()]);
    }

    /// A handshake frame to the station: in the clear while it is being
    /// keyed, sealed under the temporal key in use once it is.
    fn eapol(&mut self, eapol: &[u8], radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 400];
        let seq = self.next_seq();
        let n = header(&mut f, DATA, FROM_DS, &self.station, &self.bssid, &self.bssid, seq);
        let Some(b) = data_body(&mut f[n..], EAPOL, eapol) else { return };
        if self.peer == Peer::Up {
            let mut out = [0u8; 400 + ccmp::HEADER + ccmp::MIC];
            self.pn += 1;
            if let Some(m) = ccmp::seal(&self.tk, self.pn, 0, &f[..n], &f[n..n + b], &mut out) {
                radio(&out[..m]);
            }
        } else {
            radio(&f[..n + b]);
        }
    }

    /// Starts renewing the station's pairwise keys (a new 4-way handshake
    /// under the keys in use). False unless it is keyed with no rekeying
    /// under way.
    pub fn rekey(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) -> bool {
        if self.peer != Peer::Up {
            return false;
        }
        let anonce = self.nonce();
        let Some(m1) = self.auth.as_mut().and_then(|a| a.rekey(anonce)) else { return false };
        self.pending_pn = None;
        self.resend = now + RESEND_MS;
        self.eapol(m1.bytes(), radio);
        true
    }

    /// Starts replacing the group key with `gtk` (whose key ID should
    /// differ from the one in use, so frames under either open). The old
    /// key carries group frames until the station confirms the new one.
    /// False unless it is keyed with no rekeying under way.
    pub fn rekey_group(&mut self, gtk: Gtk, now: u64, radio: &mut dyn FnMut(&[u8])) -> bool {
        if self.peer != Peer::Up {
            return false;
        }
        let Some(m) = self.auth.as_mut().and_then(|a| a.rekey_group(gtk)) else { return false };
        self.resend = now + RESEND_MS;
        self.eapol(m.bytes(), radio);
        true
    }

    /// Whether a rekeying is under way.
    pub fn rekeying(&self) -> bool {
        self.auth.as_ref().is_some_and(|a| a.rekeying())
    }

    /// A fresh nonce, from the seed and a counter.
    fn nonce(&mut self) -> [u8; 32] {
        self.nonces += 1;
        let mut n = [0u8; 32];
        prf(&self.seed, b"Init Counter", &[&self.bssid, &self.nonces.to_be_bytes()], &mut n);
        n
    }

    /// Sends the handshake's last message again if the station has not
    /// answered it (message 1, message 3, or a group key's message).
    pub fn poll(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) {
        if !matches!(self.peer, Peer::Keying | Peer::Up) || now < self.resend {
            return;
        }
        if let Some(m) = self.auth.as_mut().and_then(|a| a.retry()) {
            self.resend = now + RESEND_MS;
            self.eapol(m.bytes(), radio);
        }
    }

    /// Takes a frame from the radio; Ethernet frames the station sent go
    /// to `up`.
    pub fn receive(&mut self, f: &[u8], now: u64, radio: &mut dyn FnMut(&[u8]), up: &mut dyn FnMut(&[u8])) {
        if f.len() < HEADER {
            return;
        }
        let (fc0, fc1) = (f[0], f[1]);
        let (a1, sa, a3) = (addr(f, 1), addr(f, 2), addr(f, 3));
        let body = &f[HEADER..];
        let ours = a1 == self.bssid;
        match fc0 {
            PROBE_REQ => {
                let ssid = frame::elements(body).find(|e| e.0 == SSID).map(|e| e.1);
                if ssid.is_some_and(|s| s.is_empty() || s == &self.ssid[..self.ssid_len]) {
                    let mut out = [0u8; 200];
                    let n = self.announce(PROBE_RESP, &sa, &mut out);
                    radio(&out[..n]);
                }
            }
            AUTH if ours && body.len() >= 6 && body[..4] == [0, 0, 1, 0] => {
                self.station = sa;
                self.peer = Peer::Authenticated;
                self.auth = None;
                self.reply(AUTH, &[0, 0, 2, 0, 0, 0], radio);
            }
            ASSOC_REQ if ours && sa == self.station && self.peer != Peer::None => {
                let offered = body.get(4..).and_then(|e| find_element(e, RSN));
                if offered != Some(&RSNE_PSK_CCMP[..]) {
                    // Status 43: invalid AKMP (not WPA2-PSK with CCMP).
                    let cap = CAPABILITY.to_le_bytes();
                    self.reply(ASSOC_RESP, &[cap[0], cap[1], 43, 0, 0, 0], radio);
                    return;
                }
                let cap = CAPABILITY.to_le_bytes();
                // Status 0, association ID 1 (top two bits set).
                let mut resp = [cap[0], cap[1], 0, 0, 1, 0xc0, RATES, 8, 0, 0, 0, 0, 0, 0, 0, 0];
                resp[8..].copy_from_slice(&RATE_SET);
                self.reply(ASSOC_RESP, &resp, radio);
                let anonce = self.nonce();
                self.auth = Some(Authenticator::new(self.pmk, self.bssid, sa, anonce, &RSNE_PSK_CCMP, self.gtk));
                self.peer = Peer::Keying;
                self.rx_pn = None;
                self.resend = now;
                self.poll(now, radio);
            }
            DEAUTH | DISASSOC if ours && sa == self.station => {
                self.peer = Peer::None;
                self.auth = None;
            }
            DATA if ours && fc1 & (TO_DS | FROM_DS) == TO_DS && sa == self.station => self.data(f, fc1, sa, a3, now, radio, up),
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn data(&mut self, f: &[u8], fc1: u8, sa: [u8; 6], da: [u8; 6], now: u64, radio: &mut dyn FnMut(&[u8]), up: &mut dyn FnMut(&[u8])) {
        if fc1 & PROTECTED == 0 {
            match frame::snap(&f[HEADER..]) {
                Some((EAPOL, eapol)) if self.peer == Peer::Keying => self.handshake(eapol, now, radio),
                _ => self.refused += 1,
            }
            return;
        }
        if self.peer != Peer::Up {
            return;
        }
        let mut copy = [0u8; MAX];
        let Some(copy) = copy.get_mut(..f.len()) else { return };
        copy.copy_from_slice(f);
        // Under the key in use, or during a rekeying under the new one,
        // which the station uses as soon as it has installed it.
        let opened = match ccmp::open(&self.tk, copy, self.rx_pn) {
            Ok(r) => {
                self.rx_pn = Some(r.1);
                Ok(r)
            }
            Err(e) => match self.auth.as_ref().and_then(|a| a.pending_tk()) {
                Some(tk) => {
                    copy.copy_from_slice(f);
                    ccmp::open(&tk, copy, self.pending_pn).inspect(|r| self.pending_pn = Some(r.1))
                }
                None => Err(e),
            },
        };
        let Ok((range, _)) = opened else {
            self.refused += 1;
            return;
        };
        if let Some((kind, payload)) = frame::snap(&copy[range]) {
            if kind == EAPOL {
                self.handshake(payload, now, radio);
                return;
            }
            let mut eth = [0u8; 1514];
            if let Some(n) = to_ethernet(&mut eth, &da, &sa, kind, payload) {
                up(&eth[..n]);
            }
        }
    }

    /// A handshake frame from the station: answered, and new keys put in
    /// use once the station has confirmed them.
    fn handshake(&mut self, eapol: &[u8], now: u64, radio: &mut dyn FnMut(&[u8])) {
        let Some(a) = self.auth.as_mut() else { return };
        match a.receive(eapol) {
            Ok(Some(m3)) => {
                self.resend = now + RESEND_MS;
                self.eapol(m3.bytes(), radio);
            }
            Ok(None) => {
                let (tk, gtk) = (a.tk().unwrap_or([0; 16]), a.gtk());
                if self.peer == Peer::Keying {
                    self.peer = Peer::Up;
                    (self.tk, self.pn, self.rx_pn) = (tk, 0, None);
                } else if tk != self.tk {
                    // The station's frames under the new key so far.
                    (self.tk, self.pn, self.rx_pn) = (tk, 0, self.pending_pn);
                    self.pending_pn = None;
                    self.rekeys += 1;
                }
                if gtk != self.gtk {
                    (self.gtk, self.group_pn) = (gtk, 0);
                    self.group_rekeys += 1;
                }
            }
            Err(_) => self.refused += 1,
        }
    }

    /// An Ethernet frame for the station (or a group), sealed into `out`:
    /// its length, or `None` while no station is keyed.
    pub fn send(&mut self, eth: &[u8], out: &mut [u8]) -> Option<usize> {
        if self.peer != Peer::Up {
            return None;
        }
        let (da, sa, kind, payload) = frame::ethernet(eth)?;
        let group = multicast(&da);
        if !group && da != self.station {
            return None;
        }
        let mut h = [0u8; HEADER];
        let seq = self.next_seq();
        header(&mut h, DATA, FROM_DS, &da, &self.bssid, &sa, seq);
        let mut body = [0u8; 8 + 1500];
        let n = data_body(&mut body, kind, payload.get(..payload.len().min(1500))?)?;
        if group {
            self.group_pn += 1;
            ccmp::seal(&self.gtk.key, self.group_pn, self.gtk.index, &h, &body[..n], out)
        } else {
            self.pn += 1;
            ccmp::seal(&self.tk, self.pn, 0, &h, &body[..n], out)
        }
    }
}
