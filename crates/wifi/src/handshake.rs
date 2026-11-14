//! WPA2-Personal's 4-way handshake (IEEE 802.11 12.7.6), both sides: the
//! station's (the supplicant) and the access point's (the authenticator,
//! which the test's simulated access point plays).
//!
//! Both hold the pairwise master key (from the passphrase, [`psk`]). The
//! access point sends a nonce (message 1); the station answers with its
//! own, and both derive the pairwise transient key from the two nonces and
//! two addresses: a key to sign handshake frames (KCK), one to encrypt
//! keys in them (KEK), and the temporal key for data frames (TK). Message
//! 2 is signed, proving the station knows the PMK; message 3, signed too,
//! carries the group key (GTK) wrapped under the KEK and the access
//! point's RSN element, which must match the one it advertised (so a
//! downgrade shows); message 4 confirms. Every frame after message 1 has
//! its MIC checked, and replay counters only go up.
//!
//! Keys are renewed while the link is up: the access point starts the
//! 4-way handshake again with a new nonce (the station answers with a new
//! one of its own, and the old keys carry data until message 3 installs
//! the new), and replaces the group key with the group key handshake
//! (12.7.7): one signed frame with the new GTK wrapped under the KEK,
//! answered by a signed confirmation. A message sent again because its
//! answer was lost is answered again, but keys already installed are not
//! installed again (that would start their packet numbers over).
//!
//! Frames are EAPOL-Key frames (802.1X, version 2, descriptor 2), as
//! carried after an LLC header with EtherType 0x888e. What the keys come
//! from and how frames are signed depends on the key management suite
//! ([`Akm`]): with WPA2's PSK the PMK is the passphrase's, the PTK comes
//! from the SHA-1 PRF and MICs are HMAC-SHA1 (key descriptor version 2);
//! with WPA3's SAE the PMK is the one SAE agreed ([`crate::sae`]), the PTK
//! comes from the SHA-256 KDF and MICs are AES-CMAC (version 0, "defined
//! by the AKM"), and message 3 also carries the integrity group key
//! (IGTK), as management frame protection, which WPA3 requires, wants.
//!
//! [`psk`]: crate::sha1::psk

use crate::aes::{cmac, key_unwrap, key_wrap};
use crate::sha1::{hmac_sha1, prf};
use crate::sha256::kdf_sha256;

/// Key information bits.
const VERSION_2: u16 = 2;
const PAIRWISE: u16 = 1 << 3;
const INSTALL: u16 = 1 << 6;
const ACK: u16 = 1 << 7;
const MIC: u16 = 1 << 8;
const SECURE: u16 = 1 << 9;
const ENCRYPTED: u16 = 1 << 12;

/// The 802.1X header (4 bytes) and the key descriptor before its key data
/// (95 bytes).
const FIXED: usize = 4 + 95;
const MIC_AT: usize = 4 + 77;
/// Room for a frame: the fixed part and key data up to 157 bytes.
pub const MAX_FRAME: usize = 256;
const MAX_KEY_DATA: usize = MAX_FRAME - FIXED;
/// Room for an RSN element.
const MAX_RSNE: usize = 64;

/// The RSN element of WPA2-Personal with CCMP: version 1, CCMP as group
/// and pairwise cipher, PSK as key management, no capabilities.
pub const RSNE_PSK_CCMP: [u8; 22] = [
    0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0,
];

/// The RSN element of WPA3-Personal: CCMP, SAE as key management, and
/// management frame protection required and capable (capabilities bits 6
/// and 7).
pub const RSNE_SAE: [u8; 22] = [
    0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 8, 0xc0, 0,
];

/// The key management suite a handshake runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Akm {
    /// WPA2-Personal: a pre-shared key from the passphrase.
    Psk,
    /// WPA3-Personal: the PMK from SAE.
    Sae,
}

impl Akm {
    /// The key descriptor version in key information.
    fn version(self) -> u16 {
        match self {
            Akm::Psk => VERSION_2,
            Akm::Sae => 0,
        }
    }

    /// The RSN element a station offers for it.
    pub fn rsne(self) -> &'static [u8] {
        match self {
            Akm::Psk => &RSNE_PSK_CCMP,
            Akm::Sae => &RSNE_SAE,
        }
    }
}

/// Why a handshake frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a whole EAPOL-Key frame of the kind expected here.
    Malformed,
    /// Its MIC is wrong: a different passphrase, or a forged frame.
    Mic,
    /// Its replay counter is not above the last one.
    Replay,
    /// It names a different nonce from the one this handshake uses.
    Nonce,
    /// The access point's RSN element in message 3 is not the one it
    /// advertised, or the station's in message 2 not WPA2-PSK with CCMP.
    Rsne,
    /// The key data would not unwrap, or holds no group key.
    KeyData,
    /// The frame does not belong at this point of the handshake.
    State,
}

/// An EAPOL-Key frame being built or received.
#[derive(Clone)]
pub struct Frame {
    buf: [u8; MAX_FRAME],
    len: usize,
}

impl Frame {
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn build(info: u16, key_len: u16, replay: u64, nonce: &[u8; 32], key_data: &[u8]) -> Frame {
        let mut f = Frame { buf: [0; MAX_FRAME], len: FIXED + key_data.len() };
        let body = (95 + key_data.len()) as u16;
        f.buf[..4].copy_from_slice(&[2, 3, (body >> 8) as u8, body as u8]);
        f.buf[4] = 2; // the RSN key descriptor
        f.buf[5..7].copy_from_slice(&info.to_be_bytes());
        f.buf[7..9].copy_from_slice(&key_len.to_be_bytes());
        f.buf[9..17].copy_from_slice(&replay.to_be_bytes());
        f.buf[17..49].copy_from_slice(nonce);
        f.buf[97..99].copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        f.buf[FIXED..f.len].copy_from_slice(key_data);
        f
    }

    /// Signs the frame with `kck`: the MIC over the whole frame with the
    /// MIC field zero.
    fn sign(mut self, akm: Akm, kck: &[u8; 16]) -> Frame {
        let mic = mic(akm, kck, self.bytes());
        self.buf[MIC_AT..MIC_AT + 16].copy_from_slice(&mic);
        self
    }
}

/// A received frame's fields.
struct Key<'a> {
    info: u16,
    replay: u64,
    nonce: [u8; 32],
    key_data: &'a [u8],
}

fn parse(f: &[u8]) -> Result<Key<'_>, Error> {
    if f.len() < FIXED || f[1] != 3 || f[4] != 2 {
        return Err(Error::Malformed);
    }
    let body = u16::from_be_bytes([f[2], f[3]]) as usize;
    let kd = u16::from_be_bytes([f[97], f[98]]) as usize;
    if body + 4 > f.len() || body != 95 + kd {
        return Err(Error::Malformed);
    }
    let info = u16::from_be_bytes([f[5], f[6]]);
    if info & 7 != VERSION_2 && info & 7 != 0 {
        return Err(Error::Malformed);
    }
    Ok(Key {
        info,
        replay: u64::from_be_bytes(f[9..17].try_into().unwrap()),
        nonce: f[17..49].try_into().unwrap(),
        key_data: &f[FIXED..FIXED + kd],
    })
}

/// Whether frame `f` (of `body` bytes after its 802.1X header) has the
/// right MIC under `kck`.
/// A frame's MIC under `kck`: HMAC-SHA1's first 16 bytes, or AES-CMAC.
fn mic(akm: Akm, kck: &[u8; 16], f: &[u8]) -> [u8; 16] {
    match akm {
        Akm::Psk => hmac_sha1(kck, &[f])[..16].try_into().unwrap(),
        Akm::Sae => cmac(kck, f),
    }
}

fn mic_ok(akm: Akm, f: &[u8], kck: &[u8; 16]) -> bool {
    let len = 4 + u16::from_be_bytes([f[2], f[3]]) as usize;
    let mut copy = [0u8; MAX_FRAME];
    if len > MAX_FRAME {
        return false;
    }
    copy[..len].copy_from_slice(&f[..len]);
    copy[MIC_AT..MIC_AT + 16].fill(0);
    let mic = mic(akm, kck, &copy[..len]);
    (0..16).fold(0, |d, i| d | (mic[i] ^ f[MIC_AT + i])) == 0
}

/// The pairwise transient key's parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ptk {
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 16],
}

/// The PTK (12.7.1.3): 48 bytes of the PRF under the PMK of the two
/// addresses and the two nonces, each pair lower first.
pub fn ptk(pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> Ptk {
    ptk_for(Akm::Psk, pmk, aa, spa, anonce, snonce)
}

/// The PTK under `akm`: SHA-1's PRF for PSK, the SHA-256 KDF for SAE.
pub fn ptk_for(akm: Akm, pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> Ptk {
    let (a1, a2) = if aa < spa { (aa, spa) } else { (spa, aa) };
    let (n1, n2) = if anonce < snonce { (anonce, snonce) } else { (snonce, anonce) };
    let mut k = [0u8; 48];
    match akm {
        Akm::Psk => prf(pmk, b"Pairwise key expansion", &[a1, a2, n1, n2], &mut k),
        Akm::Sae => kdf_sha256(pmk, b"Pairwise key expansion", &[a1, a2, n1, n2], &mut k),
    }
    Ptk {
        kck: k[..16].try_into().unwrap(),
        kek: k[16..32].try_into().unwrap(),
        tk: k[32..].try_into().unwrap(),
    }
}

/// The group key, as message 3 delivers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gtk {
    pub index: u8,
    pub key: [u8; 16],
}

/// The integrity group key, for management frames to a group (BIP), as
/// message 3 delivers it under SAE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Igtk {
    /// Its key ID: 4 or 5.
    pub index: u16,
    pub key: [u8; 16],
}

/// What a finished handshake gives the station: the keys for unicast and
/// group data frames, and under SAE the integrity group key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub tk: [u8; 16],
    pub gtk: Gtk,
    pub igtk: Option<Igtk>,
}

/// Elements and KDEs in key data: each one's type and contents.
fn elements(mut kd: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let (&t, &n) = (kd.first()?, kd.get(1)?);
        if t == 0xdd && n == 0 {
            return None; // padding
        }
        let body = kd.get(2..2 + n as usize)?;
        kd = &kd[2 + n as usize..];
        Some((t, body))
    })
}

/// The integrity group key in key data: the IGTK KDE (OUI 00-0f-ac, type
/// 9, key ID (2 bytes), packet number (6), key).
fn igtk_kde(kd: &[u8]) -> Option<Igtk> {
    elements(kd).find_map(|(t, body)| {
        (t == 0xdd && body.len() == 4 + 2 + 6 + 16 && body[..4] == [0x00, 0x0f, 0xac, 9])
            .then(|| Igtk { index: u16::from_le_bytes([body[4], body[5]]), key: body[12..].try_into().unwrap() })
    })
}

/// The group key in key data: the GTK KDE (OUI 00-0f-ac, type 1, key ID,
/// reserved, key).
fn gtk_kde(kd: &[u8]) -> Option<Gtk> {
    elements(kd).find_map(|(t, body)| {
        (t == 0xdd && body.len() == 6 + 16 && body[..4] == [0x00, 0x0f, 0xac, 1])
            .then(|| Gtk { index: body[4] & 3, key: body[6..].try_into().unwrap() })
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// The station waits for message 1 (or a new one), the access point
    /// for message 2.
    Start,
    /// The station has answered message 1 and waits for message 3; the
    /// access point has sent message 3 and waits for message 4.
    Keyed,
    Done,
}

/// An RSN element held by value.
#[derive(Clone, Copy)]
struct Rsne {
    b: [u8; MAX_RSNE],
    n: usize,
}

impl Rsne {
    fn new(e: &[u8]) -> Rsne {
        let mut r = Rsne { b: [0; MAX_RSNE], n: e.len().min(MAX_RSNE) };
        r.b[..r.n].copy_from_slice(&e[..r.n]);
        r
    }

    fn get(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

/// The station's side.
pub struct Supplicant {
    akm: Akm,
    pmk: [u8; 32],
    spa: [u8; 6],
    aa: [u8; 6],
    snonce: [u8; 32],
    /// The RSN element the station sends, and the one the access point
    /// advertised (in its beacon or probe response).
    own: Rsne,
    theirs: Rsne,
    anonce: [u8; 32],
    ptk: Option<Ptk>,
    replay: Option<u64>,
    keys: Option<Keys>,
    step: Step,
    /// The nonce for the next rekeying, given in advance ([`renew`]).
    ///
    /// [`renew`]: Supplicant::renew
    next: Option<[u8; 32]>,
    installs: u32,
}

impl Supplicant {
    /// A station with address `spa` joining access point `aa`, with nonce
    /// `snonce` (fresh random bytes, which the caller supplies).
    pub fn new(akm: Akm, pmk: [u8; 32], spa: [u8; 6], aa: [u8; 6], snonce: [u8; 32], own: &[u8], advertised: &[u8]) -> Self {
        Supplicant {
            akm,
            pmk,
            spa,
            aa,
            snonce,
            own: Rsne::new(own),
            theirs: Rsne::new(advertised),
            anonce: [0; 32],
            ptk: None,
            replay: None,
            keys: None,
            step: Step::Start,
            next: None,
            installs: 0,
        }
    }

    /// A fresh nonce for the access point's next rekeying: without one, a
    /// message 1 after keys are installed is refused.
    pub fn renew(&mut self, snonce: [u8; 32]) {
        self.next = Some(snonce);
    }

    /// Whether the next rekeying still wants a nonce.
    pub fn needs_nonce(&self) -> bool {
        self.next.is_none()
    }

    /// How many times keys have been installed (the first time, then once
    /// for every rekeying, pairwise or group): changes when [`keys`] does.
    ///
    /// [`keys`]: Supplicant::keys
    pub fn installs(&self) -> u32 {
        self.installs
    }

    /// The group key handshake's message 1: a new group key, under the
    /// pairwise keys in place.
    fn group(&mut self, f: &[u8], k: &Key) -> Result<Frame, Error> {
        let (Some(ptk), Some(mut keys)) = (self.ptk, self.keys) else {
            return Err(Error::State);
        };
        if self.step != Step::Done || k.info & (ACK | MIC | SECURE | ENCRYPTED) != ACK | MIC | SECURE | ENCRYPTED {
            return Err(Error::State);
        }
        if !mic_ok(self.akm, f, &ptk.kck) {
            return Err(Error::Mic);
        }
        let mut plain = [0u8; MAX_KEY_DATA];
        let n = k.key_data.len().checked_sub(8).ok_or(Error::KeyData)?;
        if !key_unwrap(&ptk.kek, k.key_data, &mut plain) {
            return Err(Error::KeyData);
        }
        let gtk = gtk_kde(&plain[..n]).ok_or(Error::KeyData)?;
        self.replay = Some(k.replay);
        if gtk != keys.gtk {
            keys.gtk = gtk;
            self.keys = Some(keys);
            self.installs += 1;
        }
        Ok(Frame::build(self.akm.version() | MIC | SECURE, 0, k.replay, &[0; 32], &[]).sign(self.akm, &ptk.kck))
    }

    /// Takes a frame from the access point: returns the answer to send.
    pub fn receive(&mut self, f: &[u8]) -> Result<Frame, Error> {
        let k = parse(f)?;
        if k.info & 7 != self.akm.version() {
            return Err(Error::Malformed);
        }
        if self.replay.is_some_and(|r| k.replay <= r) {
            return Err(Error::Replay);
        }
        if k.info & PAIRWISE == 0 {
            return self.group(f, &k);
        }
        if k.info & (PAIRWISE | ACK) != PAIRWISE | ACK {
            return Err(Error::State);
        }
        if k.info & MIC == 0 {
            // Message 1: a nonce, unsigned. A new one starts over; once
            // keys are installed it starts a rekeying, with the nonce
            // given for it (the keys in place carry on until message 3).
            if self.step == Step::Done {
                self.snonce = self.next.take().ok_or(Error::State)?;
            }
            let ptk = ptk_for(self.akm, &self.pmk, &self.aa, &self.spa, &k.nonce, &self.snonce);
            self.anonce = k.nonce;
            self.ptk = Some(ptk);
            self.replay = Some(k.replay);
            self.step = Step::Keyed;
            let info = self.akm.version() | PAIRWISE | MIC;
            return Ok(Frame::build(info, 0, k.replay, &self.snonce, self.own.get()).sign(self.akm, &ptk.kck));
        }
        // Message 3: signed, installing, with the group key encrypted. One
        // sent again (message 4 was lost) is answered again, but its keys
        // are not installed again: that would start the packet numbers
        // over, letting frames already sent be replayed.
        let ptk = self.ptk.ok_or(Error::State)?;
        if self.step == Step::Start || k.info & (INSTALL | SECURE | ENCRYPTED) != INSTALL | SECURE | ENCRYPTED {
            return Err(Error::State);
        }
        if !mic_ok(self.akm, f, &ptk.kck) {
            return Err(Error::Mic);
        }
        if k.nonce != self.anonce {
            return Err(Error::Nonce);
        }
        let mut plain = [0u8; MAX_KEY_DATA];
        let n = k.key_data.len().checked_sub(8).ok_or(Error::KeyData)?;
        if !key_unwrap(&ptk.kek, k.key_data, &mut plain) {
            return Err(Error::KeyData);
        }
        let theirs = self.theirs.get();
        let rsne_ok = elements(&plain[..n]).any(|(t, body)| t == 0x30 && body.len() + 2 == theirs.len() && body == &theirs[2..]);
        let gtk = gtk_kde(&plain[..n]);
        if !rsne_ok {
            return Err(Error::Rsne);
        }
        let gtk = gtk.ok_or(Error::KeyData)?;
        // Under SAE management frames are protected: the IGTK must come.
        let igtk = igtk_kde(&plain[..n]);
        if self.akm == Akm::Sae && igtk.is_none() {
            return Err(Error::KeyData);
        }
        self.replay = Some(k.replay);
        if self.step != Step::Done {
            self.keys = Some(Keys { tk: ptk.tk, gtk, igtk });
            self.step = Step::Done;
            self.installs += 1;
        }
        Ok(Frame::build(self.akm.version() | PAIRWISE | MIC | SECURE, 0, k.replay, &[0; 32], &[]).sign(self.akm, &ptk.kck))
    }

    /// The keys, once message 3 has been taken.
    pub fn keys(&self) -> Option<Keys> {
        self.keys
    }
}

/// The access point's side, for one station.
pub struct Authenticator {
    akm: Akm,
    igtk: Option<Igtk>,
    pmk: [u8; 32],
    aa: [u8; 6],
    spa: [u8; 6],
    anonce: [u8; 32],
    rsne: Rsne,
    gtk: Gtk,
    replay: u64,
    ptk: Option<Ptk>,
    step: Step,
    /// The pairwise keys in use while a rekeying is under way.
    current: Option<Ptk>,
    /// A new group key being delivered.
    group: Option<Gtk>,
}

impl Authenticator {
    /// Access point `aa`, advertising `rsne`, for station `spa`, with nonce
    /// `anonce` (fresh random bytes) and group key `gtk`.
    pub fn new(akm: Akm, pmk: [u8; 32], aa: [u8; 6], spa: [u8; 6], anonce: [u8; 32], rsne: &[u8], gtk: Gtk) -> Self {
        Authenticator {
            akm,
            igtk: None,
            pmk,
            aa,
            spa,
            anonce,
            rsne: Rsne::new(rsne),
            gtk,
            replay: 0,
            ptk: None,
            step: Step::Start,
            current: None,
            group: None,
        }
    }

    /// The integrity group key message 3 delivers (under SAE).
    pub fn with_igtk(mut self, igtk: Igtk) -> Self {
        self.igtk = Some(igtk);
        self
    }

    /// Starts renewing the pairwise keys, with new nonce `anonce`: message
    /// 1 again. `None` unless keyed with nothing else under way.
    pub fn rekey(&mut self, anonce: [u8; 32]) -> Option<Frame> {
        if self.step != Step::Done || self.group.is_some() {
            return None;
        }
        self.current = self.ptk;
        self.anonce = anonce;
        Some(self.start())
    }

    /// Starts replacing the group key with `gtk`: the group key
    /// handshake's message 1. `None` unless keyed with nothing else under
    /// way.
    pub fn rekey_group(&mut self, gtk: Gtk) -> Option<Frame> {
        let ptk = self.ptk.filter(|_| self.step == Step::Done && self.group.is_none())?;
        self.group = Some(gtk);
        Some(self.group_message(&ptk))
    }

    /// The group key in use (the new one once the station has confirmed
    /// it).
    pub fn gtk(&self) -> Gtk {
        self.gtk
    }

    /// Whether a rekeying (pairwise or group) is under way.
    pub fn rekeying(&self) -> bool {
        self.current.is_some() || self.group.is_some()
    }

    /// The new temporal key of a pairwise rekeying under way, once the
    /// station has answered message 1: the station's frames come under it
    /// once it has installed it, which may be before its message 4
    /// arrives (or if that is lost).
    pub fn pending_tk(&self) -> Option<[u8; 16]> {
        self.ptk.filter(|_| self.step == Step::Keyed && self.current.is_some()).map(|p| p.tk)
    }

    fn group_message(&mut self, ptk: &Ptk) -> Frame {
        self.replay += 1;
        let gtk = self.group.unwrap_or(self.gtk);
        let mut plain = [0u8; 24];
        plain[..8].copy_from_slice(&[0xdd, 22, 0x00, 0x0f, 0xac, 1, gtk.index & 3, 0]);
        plain[8..].copy_from_slice(&gtk.key);
        let mut wrapped = [0u8; 32];
        key_wrap(&ptk.kek, &plain, &mut wrapped);
        let info = self.akm.version() | ACK | MIC | SECURE | ENCRYPTED;
        Frame::build(info, 0, self.replay, &[0; 32], &wrapped).sign(self.akm, &ptk.kck)
    }

    /// Message 1 (sent again, with a higher replay counter, if no answer
    /// comes).
    pub fn start(&mut self) -> Frame {
        self.replay += 1;
        self.step = Step::Start;
        Frame::build(self.akm.version() | PAIRWISE | ACK, 16, self.replay, &self.anonce, &[])
    }

    /// What to send when the station has not answered: message 1 again
    /// before message 2 came, message 3 again (with a higher replay
    /// counter) before message 4 came, the group key's message again
    /// before its confirmation came; nothing once done.
    pub fn retry(&mut self) -> Option<Frame> {
        match (self.step, self.ptk) {
            (Step::Start, _) => Some(self.start()),
            (Step::Keyed, Some(ptk)) => Some(self.message3(&ptk)),
            (Step::Done, Some(ptk)) if self.group.is_some() => Some(self.group_message(&ptk)),
            _ => None,
        }
    }

    /// Message 3, with the next replay counter.
    fn message3(&mut self, ptk: &Ptk) -> Frame {
        self.replay += 1;
        // Key data: our RSN element and the GTK KDE, padded (0xdd then
        // zeros) to a multiple of 8, then wrapped.
        let mut plain = [0u8; MAX_KEY_DATA - 8];
        let mut n = self.rsne.n;
        plain[..n].copy_from_slice(self.rsne.get());
        let kde = [0xdd, 22, 0x00, 0x0f, 0xac, 1, self.gtk.index & 3, 0];
        plain[n..n + 8].copy_from_slice(&kde);
        plain[n + 8..n + 24].copy_from_slice(&self.gtk.key);
        n += 24;
        if let Some(igtk) = self.igtk.filter(|_| self.akm == Akm::Sae) {
            // The IGTK KDE: key ID, packet number 0, key.
            let id = igtk.index.to_le_bytes();
            plain[n..n + 12].copy_from_slice(&[0xdd, 28, 0x00, 0x0f, 0xac, 9, id[0], id[1], 0, 0, 0, 0]);
            plain[n + 12..n + 14].fill(0);
            plain[n + 14..n + 30].copy_from_slice(&igtk.key);
            n += 30;
        }
        if n % 8 != 0 {
            plain[n] = 0xdd;
            n = n.next_multiple_of(8);
        }
        let mut wrapped = [0u8; MAX_KEY_DATA];
        key_wrap(&ptk.kek, &plain[..n], &mut wrapped);
        let info = self.akm.version() | PAIRWISE | INSTALL | ACK | MIC | SECURE | ENCRYPTED;
        Frame::build(info, 16, self.replay, &self.anonce, &wrapped[..n + 8]).sign(self.akm, &ptk.kck)
    }

    /// Takes a frame from the station: message 2 is answered with message
    /// 3; message 4 finishes (no answer).
    pub fn receive(&mut self, f: &[u8]) -> Result<Option<Frame>, Error> {
        let k = parse(f)?;
        if k.info & 7 != self.akm.version() {
            return Err(Error::Malformed);
        }
        if k.replay != self.replay {
            return Err(Error::Replay);
        }
        if k.info & PAIRWISE == 0 {
            // The group key's confirmation: the new key is in use.
            let ptk = self.ptk.ok_or(Error::State)?;
            if self.step != Step::Done || self.group.is_none() || k.info & (MIC | ACK | SECURE) != MIC | SECURE {
                return Err(Error::State);
            }
            if !mic_ok(self.akm, f, &ptk.kck) {
                return Err(Error::Mic);
            }
            self.gtk = self.group.take().unwrap_or(self.gtk);
            return Ok(None);
        }
        if k.info & (PAIRWISE | MIC | ACK) != PAIRWISE | MIC {
            return Err(Error::State);
        }
        match self.step {
            Step::Start => {
                let ptk = ptk_for(self.akm, &self.pmk, &self.aa, &self.spa, &self.anonce, &k.nonce);
                if !mic_ok(self.akm, f, &ptk.kck) {
                    return Err(Error::Mic);
                }
                if k.key_data != self.akm.rsne() {
                    return Err(Error::Rsne);
                }
                self.ptk = Some(ptk);
                self.step = Step::Keyed;
                Ok(Some(self.message3(&ptk)))
            }
            Step::Keyed => {
                let ptk = self.ptk.ok_or(Error::State)?;
                if k.info & SECURE == 0 {
                    return Err(Error::State);
                }
                if !mic_ok(self.akm, f, &ptk.kck) {
                    return Err(Error::Mic);
                }
                self.step = Step::Done;
                self.current = None;
                Ok(None)
            }
            Step::Done => Err(Error::State),
        }
    }

    /// The temporal key, once message 4 has been taken.
    pub fn tk(&self) -> Option<[u8; 16]> {
        (self.step == Step::Done).then(|| self.ptk.map(|p| p.tk)).flatten()
    }
}
