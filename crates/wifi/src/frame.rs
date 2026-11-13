//! IEEE 802.11 frames as the station and the access point exchange them:
//! the management frames that find a network and join it (probe, beacon,
//! authentication, association, deauthentication), and data frames, whose
//! body is an LLC/SNAP header and an EtherType, so an Ethernet frame
//! becomes one and back.

/// Frame control's first byte for each frame used (type and subtype).
pub const ASSOC_REQ: u8 = 0x00;
pub const ASSOC_RESP: u8 = 0x10;
pub const PROBE_REQ: u8 = 0x40;
pub const PROBE_RESP: u8 = 0x50;
pub const BEACON: u8 = 0x80;
pub const DISASSOC: u8 = 0xa0;
pub const AUTH: u8 = 0xb0;
pub const DEAUTH: u8 = 0xc0;
pub const DATA: u8 = 0x08;

/// Frame control's second byte: to and from the distribution system, and
/// protected (the body is CCMP's).
pub const TO_DS: u8 = 0x01;
pub const FROM_DS: u8 = 0x02;
pub const PROTECTED: u8 = 0x40;

pub const BROADCAST: [u8; 6] = [0xff; 6];
/// A management frame's header, and a data frame's without a fourth
/// address or QoS.
pub const HEADER: usize = 24;
/// LLC/SNAP before the EtherType in a data frame's body.
pub const SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0, 0, 0];
pub const EAPOL: u16 = 0x888e;
/// The largest frame either side builds: a data frame carrying a whole
/// Ethernet payload (1500 bytes) with its CCMP header and MIC.
pub const MAX: usize = HEADER + 8 + 8 + 1500 + 8;

/// Element IDs.
pub const SSID: u8 = 0;
pub const RATES: u8 = 1;
pub const DS_PARAMS: u8 = 3;
pub const RSN: u8 = 48;
/// 1, 2, 5.5 and 11 Mb/s basic, 6, 9, 12 and 18 Mb/s supported (units of
/// 500 kb/s).
pub const RATE_SET: [u8; 8] = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
/// Capability: an infrastructure network (ESS) that requires privacy.
pub const CAPABILITY: u16 = 0x0011;

/// Writes an 802.11 header into `out`: frame control, no duration, three
/// addresses, sequence number `seq`. Returns its length.
pub fn header(out: &mut [u8], fc0: u8, fc1: u8, a1: &[u8; 6], a2: &[u8; 6], a3: &[u8; 6], seq: u16) -> usize {
    out[..HEADER].fill(0);
    out[0] = fc0;
    out[1] = fc1;
    out[4..10].copy_from_slice(a1);
    out[10..16].copy_from_slice(a2);
    out[16..22].copy_from_slice(a3);
    out[22..24].copy_from_slice(&(seq << 4).to_le_bytes());
    HEADER
}

/// Appends element `id` holding `body` at `out[at..]`; returns the end.
pub fn element(out: &mut [u8], at: usize, id: u8, body: &[u8]) -> usize {
    out[at] = id;
    out[at + 1] = body.len() as u8;
    out[at + 2..at + 2 + body.len()].copy_from_slice(body);
    at + 2 + body.len()
}

/// The elements in `b`: each one's ID and contents (whole ones only).
pub fn elements(mut b: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let (&id, &n) = (b.first()?, b.get(1)?);
        let body = b.get(2..2 + n as usize)?;
        b = &b[2 + n as usize..];
        Some((id, body))
    })
}

/// Element `id` in `b`, the whole element (ID and length included).
pub fn find_element(b: &[u8], id: u8) -> Option<&[u8]> {
    let mut at = 0;
    while at + 2 <= b.len() {
        let end = at + 2 + b[at + 1] as usize;
        if end > b.len() {
            return None;
        }
        if b[at] == id {
            return Some(&b[at..end]);
        }
        at = end;
    }
    None
}

/// A frame's addresses.
pub fn addr(f: &[u8], n: usize) -> [u8; 6] {
    let at = 4 + 6 * (n - 1);
    f[at..at + 6].try_into().unwrap()
}

pub fn multicast(a: &[u8; 6]) -> bool {
    a[0] & 1 != 0
}

/// An Ethernet frame's parts: destination, source, EtherType, payload.
pub type Ethernet<'a> = ([u8; 6], [u8; 6], u16, &'a [u8]);

/// An Ethernet frame's destination, source, EtherType and payload.
pub fn ethernet(eth: &[u8]) -> Option<Ethernet<'_>> {
    if eth.len() < 14 {
        return None;
    }
    let da = eth[..6].try_into().unwrap();
    let sa = eth[6..12].try_into().unwrap();
    Some((da, sa, u16::from_be_bytes([eth[12], eth[13]]), &eth[14..]))
}

/// A data frame's body (after its header, decrypted): its EtherType and
/// payload, if it starts with LLC/SNAP.
pub fn snap(body: &[u8]) -> Option<(u16, &[u8])> {
    (body.len() >= 8 && body[..6] == SNAP).then(|| (u16::from_be_bytes([body[6], body[7]]), &body[8..]))
}

/// Writes an Ethernet frame into `out` (at least 14 + payload bytes);
/// returns its length.
pub fn to_ethernet(out: &mut [u8], da: &[u8; 6], sa: &[u8; 6], kind: u16, payload: &[u8]) -> Option<usize> {
    let n = 14 + payload.len();
    let out = out.get_mut(..n)?;
    out[..6].copy_from_slice(da);
    out[6..12].copy_from_slice(sa);
    out[12..14].copy_from_slice(&kind.to_be_bytes());
    out[14..].copy_from_slice(payload);
    Some(n)
}

/// A data frame's body for EtherType `kind` and `payload`: LLC/SNAP, the
/// EtherType, the payload. Returns its length.
pub fn data_body(out: &mut [u8], kind: u16, payload: &[u8]) -> Option<usize> {
    let n = 8 + payload.len();
    let out = out.get_mut(..n)?;
    out[..6].copy_from_slice(&SNAP);
    out[6..8].copy_from_slice(&kind.to_be_bytes());
    out[8..].copy_from_slice(payload);
    Some(n)
}
