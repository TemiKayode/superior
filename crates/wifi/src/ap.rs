//! A WPA2-Personal access point for one station, as a state machine with
//! no I/O of its own: what the test harness plays at the far end of the
//! simulated radio (and what a host test joins a [`Station`] to).
//!
//! It answers probe requests for its SSID, open system authentication and
//! association (if the station offers WPA2-PSK with CCMP), runs the access
//! point's side of the 4-way handshake ([`Authenticator`]), and then
//! carries Ethernet frames both ways: the station's, opened under the
//! temporal key, and its own, sealed with the temporal key to the station
//! or the group key to a group.
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
    seq: u16,
    resend: u64,
    /// Data frames refused: forged, replayed, or in the clear.
    pub refused: u64,
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
            seq: 0,
            resend: 0,
            refused: 0,
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

    fn eapol(&mut self, eapol: &[u8], radio: &mut dyn FnMut(&[u8])) {
        let mut f = [0u8; 400];
        let seq = self.next_seq();
        let n = header(&mut f, DATA, FROM_DS, &self.station, &self.bssid, &self.bssid, seq);
        if let Some(b) = data_body(&mut f[n..], EAPOL, eapol) {
            radio(&f[..n + b]);
        }
    }

    /// Sends the handshake's last message again if the station has not
    /// answered it (message 1, or message 3).
    pub fn poll(&mut self, now: u64, radio: &mut dyn FnMut(&[u8])) {
        if self.peer != Peer::Keying || now < self.resend {
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
                self.nonces += 1;
                let mut anonce = [0u8; 32];
                prf(&self.seed, b"Init Counter", &[&self.bssid, &self.nonces.to_be_bytes()], &mut anonce);
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
                Some((EAPOL, eapol)) if self.peer == Peer::Keying => {
                    let Some(a) = self.auth.as_mut() else { return };
                    match a.receive(eapol) {
                        Ok(Some(m3)) => {
                            self.resend = now + RESEND_MS;
                            self.eapol(m3.bytes(), radio);
                        }
                        Ok(None) => {
                            self.tk = a.tk().unwrap_or([0; 16]);
                            self.peer = Peer::Up;
                            self.pn = 0;
                        }
                        Err(_) => self.refused += 1,
                    }
                }
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
        let Ok((range, pn)) = ccmp::open(&self.tk, copy, self.rx_pn) else {
            self.refused += 1;
            return;
        };
        self.rx_pn = Some(pn);
        if let Some((kind, payload)) = frame::snap(&copy[range]) {
            let mut eth = [0u8; 1514];
            if let Some(n) = to_ethernet(&mut eth, &da, &sa, kind, payload) {
                up(&eth[..n]);
            }
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
