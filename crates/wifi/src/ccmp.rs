//! CCMP (IEEE 802.11 12.5.3): how a data frame is encrypted and
//! authenticated under the temporal key. The frame's header stays clear
//! but is authenticated (with the bits that may change in flight masked);
//! an 8-byte CCMP header carrying the 48-bit packet number follows it,
//! then the encrypted body and an 8-byte MIC. A receiver takes a frame
//! only if its packet number is above the last it took, so a recorded
//! frame cannot be replayed.

use crate::aes::{Aes128, ccm_open, ccm_seal};

/// The CCMP header's and MIC's sizes.
pub const HEADER: usize = 8;
pub const MIC: usize = 8;

/// Why a frame was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not a data frame with a whole CCMP header, or not marked protected.
    Malformed,
    /// Its packet number is not above the last one taken.
    Replayed,
    /// The MIC is wrong: changed in flight, or another key.
    Forged,
}

/// The length of a data frame's 802.11 header, from its frame control
/// field: 24 bytes, 30 with a fourth address (to and from the DS), 2 more
/// for QoS.
pub fn header_len(frame: &[u8]) -> Option<usize> {
    let (&fc0, &fc1) = (frame.first()?, frame.get(1)?);
    if fc0 >> 2 & 3 != 2 {
        return None; // not a data frame
    }
    let mut n = 24;
    if fc1 & 3 == 3 {
        n += 6;
    }
    if fc0 & 0x80 != 0 {
        n += 2;
    }
    (frame.len() >= n).then_some(n)
}

/// The additional authenticated data and nonce for a frame with 802.11
/// header `h` and packet number `pn`.
fn aad_nonce(h: &[u8], pn: u64) -> ([u8; 30], usize, [u8; 13]) {
    let qos = h[0] & 0x80 != 0;
    let mut aad = [0u8; 30];
    // Frame control: a data frame's subtype bits masked, as are retry,
    // power management and more data (and order in a QoS frame); the
    // protected bit set.
    aad[0] = h[0] & 0x8f;
    aad[1] = (h[1] & !0x38 & if qos { !0x80 } else { 0xff }) | 0x40;
    aad[2..20].copy_from_slice(&h[4..22]); // addresses 1, 2 and 3
    aad[20] = h[22] & 0x0f; // the fragment number, not the sequence number
    let mut n = 22;
    if h[1] & 3 == 3 {
        aad[n..n + 6].copy_from_slice(&h[24..30]);
        n += 6;
    }
    let mut priority = 0;
    if qos {
        let qc = h.len() - 2;
        priority = h[qc] & 0x0f;
        aad[n] = priority;
        n += 2;
    }
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&h[10..16]); // address 2, the sender
    nonce[7..].copy_from_slice(&pn.to_be_bytes()[2..]);
    (aad, n, nonce)
}

/// Seals a data frame: `header` (its 802.11 header) and `body` become, in
/// `out`, the header marked protected, the CCMP header with packet number
/// `pn` and key `key_id`, the encrypted body and the MIC. Returns the
/// sealed frame's length (`None` if `header` is no data frame's or `out`
/// is too small).
pub fn seal(tk: &[u8; 16], pn: u64, key_id: u8, header: &[u8], body: &[u8], out: &mut [u8]) -> Option<usize> {
    let h = header_len(header).filter(|&n| n == header.len())?;
    let total = h + HEADER + body.len() + MIC;
    if out.len() < total || pn >> 48 != 0 {
        return None;
    }
    out[..h].copy_from_slice(header);
    out[1] |= 0x40;
    let p = pn.to_le_bytes();
    out[h..h + HEADER].copy_from_slice(&[p[0], p[1], 0, 0x20 | (key_id & 3) << 6, p[2], p[3], p[4], p[5]]);
    let (aad, n, nonce) = aad_nonce(&out[..h], pn);
    let data = &mut out[h + HEADER..h + HEADER + body.len()];
    data.copy_from_slice(body);
    let mic = ccm_seal(&Aes128::new(tk), &nonce, &aad[..n], data);
    out[total - MIC..total].copy_from_slice(&mic);
    Some(total)
}

/// Opens a frame [`seal`] made, if its packet number is above `last` and
/// its MIC holds: the body is decrypted in place, and its range in `frame`
/// and its packet number are returned.
pub fn open(tk: &[u8; 16], frame: &mut [u8], last: Option<u64>) -> Result<(core::ops::Range<usize>, u64), Refused> {
    let h = header_len(frame).ok_or(Refused::Malformed)?;
    if frame.len() < h + HEADER + MIC || frame[1] & 0x40 == 0 || frame[h + 3] & 0x20 == 0 {
        return Err(Refused::Malformed);
    }
    let c = &frame[h..h + HEADER];
    let pn = u64::from_le_bytes([c[0], c[1], c[4], c[5], c[6], c[7], 0, 0]);
    if last.is_some_and(|l| pn <= l) {
        return Err(Refused::Replayed);
    }
    let (aad, n, nonce) = aad_nonce(&frame[..h], pn);
    let end = frame.len() - MIC;
    let mic: [u8; MIC] = frame[end..].try_into().unwrap();
    let body = h + HEADER..end;
    if !ccm_open(&Aes128::new(tk), &nonce, &aad[..n], &mut frame[body.clone()], &mic) {
        return Err(Refused::Forged);
    }
    Ok((body, pn))
}
