//! BIP (Broadcast/Multicast Integrity Protocol, BIP-CMAC-128): protecting
//! management frames sent to a group, which CCMP cannot (there is no one
//! temporal key to seal them under), with the integrity group key (IGTK)
//! the 4-way handshake delivers under SAE.
//!
//! The frame stays readable; a Management MIC element (MMIE) goes at the
//! end of its body: element 76, 16 bytes long, the IGTK's key ID, a 48-bit
//! packet number (IPN) that only ever rises, and the first 8 bytes of
//! AES-CMAC over the header's frame control (retry, power management and
//! more-data bits cleared) and three addresses, then the body with the
//! MMIE's MIC as zeros. A station with management frame protection obeys
//! a deauthentication or disassociation to a group only with a valid MMIE
//! under the IGTK, and a packet number above the last it accepted, so a
//! forged one (no MMIE, a wrong MIC) or one replayed cannot knock every
//! station off at once.

use crate::aes::cmac;
use crate::handshake::Igtk;

/// The MMIE: element ID 76, length 16.
const MMIE_ID: u8 = 76;
pub const MMIE_LEN: usize = 18;
/// The 802.11 management header: frame control, duration, three
/// addresses, sequence control.
const HEADER: usize = 24;

/// Why a frame was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No MMIE at the end of the body.
    Unprotected,
    /// An MMIE under another key ID.
    WrongKey,
    /// A packet number not above the last one accepted.
    Replayed,
    /// The MIC does not match.
    BadMic,
}

/// The MIC over `frame` (header and body, whose last 18 bytes are the
/// MMIE): AES-CMAC truncated to 8 bytes.
fn mic(igtk: &Igtk, frame: &[u8]) -> [u8; 8] {
    // AAD (20 bytes) then the body, the MMIE's MIC zeroed. Frames to a
    // group are short (a deauthentication's body is 2 bytes).
    let mut buf = [0u8; 20 + 256];
    let body = &frame[HEADER..];
    let n = 20 + body.len();
    buf[0] = frame[0];
    buf[1] = frame[1] & !(0x08 | 0x10 | 0x20);
    buf[2..20].copy_from_slice(&frame[4..22]);
    buf[20..n].copy_from_slice(body);
    buf[n - 8..n].fill(0);
    let full = cmac(&igtk.key, &buf[..n]);
    full[..8].try_into().unwrap()
}

/// Protects the management frame in `frame[..len]` (header and body) with
/// packet number `ipn`: appends its MMIE. Returns the new length, or
/// `None` if it does not fit (in `frame`, or a body over 238 bytes).
pub fn protect(igtk: &Igtk, ipn: u64, frame: &mut [u8], len: usize) -> Option<usize> {
    let end = len + MMIE_LEN;
    if len < HEADER || end > frame.len() || end - HEADER > 256 {
        return None;
    }
    let m = &mut frame[len..end];
    m[0] = MMIE_ID;
    m[1] = 16;
    m[2..4].copy_from_slice(&igtk.index.to_le_bytes());
    m[4..10].copy_from_slice(&ipn.to_le_bytes()[..6]);
    m[10..18].fill(0);
    let mic = mic(igtk, &frame[..end]);
    frame[end - 8..end].copy_from_slice(&mic);
    Some(end)
}

/// Checks the MMIE that ends `frame` under `igtk`, its packet number above
/// `last` (if one was accepted before). Returns its packet number.
pub fn verify(igtk: &Igtk, frame: &[u8], last: Option<u64>) -> Result<u64, Refused> {
    if frame.len() < HEADER + MMIE_LEN || frame.len() - HEADER > 256 {
        return Err(Refused::Unprotected);
    }
    let m = &frame[frame.len() - MMIE_LEN..];
    if m[0] != MMIE_ID || m[1] != 16 {
        return Err(Refused::Unprotected);
    }
    if u16::from_le_bytes([m[2], m[3]]) != igtk.index {
        return Err(Refused::WrongKey);
    }
    let mut pn = [0u8; 8];
    pn[..6].copy_from_slice(&m[4..10]);
    let ipn = u64::from_le_bytes(pn);
    if last.is_some_and(|l| ipn <= l) {
        return Err(Refused::Replayed);
    }
    if mic(igtk, frame) != m[10..18] {
        return Err(Refused::BadMic);
    }
    Ok(ipn)
}
