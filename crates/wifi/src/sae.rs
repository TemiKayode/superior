//! SAE (Simultaneous Authentication of Equals, IEEE 802.11 12.4), WPA3-
//! Personal's password exchange, on group 19 (P-256). Both sides run the
//! same steps, so one type serves the station and the access point.
//!
//! The password element (PWE) is a point found from the password and the
//! two addresses by hunting and pecking: up to 40 tries of HMAC-SHA256 and
//! the KDF give candidate x coordinates, and the first on the curve wins;
//! all 40 tries are always made, so the time taken does not say which one
//! did. Each side then picks secrets `rand` and `mask` and sends a commit:
//! the scalar `rand + mask` and the element `−mask·PWE`. From the peer's
//! commit both compute K = rand·(scalar′·PWE + element′), whose x
//! coordinate yields (through HMAC and the KDF) a key confirmation key and
//! the PMK. A confirm (an HMAC under the KCK of both commits) proves each
//! side reached the same K, which only knowing the password allows; an
//! eavesdropper learns nothing to test passwords against offline, unlike
//! WPA2's handshake.
//!
//! Frames carry the commit as the group (2 bytes, little-endian), the
//! scalar (32 bytes) and the element (x then y, 32 bytes each), and the
//! confirm as a send-confirm counter (2 bytes) and the HMAC (32 bytes).

use crate::p256::{Affine, FIELD, N, ORDER, P, U256, curve_rhs, from_be, is_square, is_zero, less, sqrt, to_be};
use crate::sha256::{hmac_sha256, kdf_sha256};

/// The group: 19, the NIST P-256 curve.
pub const GROUP: u16 = 19;
pub const COMMIT_LEN: usize = 2 + 32 + 64;
pub const CONFIRM_LEN: usize = 2 + 32;
/// Hunting and pecking's tries.
const TRIES: u8 = 40;

/// Why a commit or confirm was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not group 19 (an access point answers with status 77).
    Group,
    /// Too short.
    Malformed,
    /// The scalar is not between 1 and the group's order, exclusive.
    Scalar,
    /// The element is not a point on the curve.
    Element,
    /// The peer's commit is our own sent back.
    Reflection,
    /// The confirm's HMAC is wrong: another password.
    Confirm,
    /// Not expected now (a confirm before the peer's commit).
    State,
}

pub struct Sae {
    pwe: Affine,
    rand: U256,
    scalar: U256,
    element: Affine,
    peer: Option<(U256, Affine)>,
    kck: [u8; 32],
    pmk: [u8; 32],
    pmkid: [u8; 16],
    send_confirm: u16,
    confirmed: bool,
}

/// The password element for `password` between addresses `a` and `b`.
fn pwe(password: &[u8], a: &[u8; 6], b: &[u8; 6]) -> Option<Affine> {
    let mut macs = [0u8; 12];
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    macs[..6].copy_from_slice(hi);
    macs[6..].copy_from_slice(lo);
    let prime = to_be(&P);
    let mut found = None;
    for counter in 1..=TRIES {
        let seed = hmac_sha256(&macs, &[password, &[counter]]);
        let mut value = [0u8; 32];
        kdf_sha256(&seed, b"SAE Hunting and Pecking", &[&prime], &mut value);
        let x = from_be(&value);
        if !less(&x, &P) {
            continue;
        }
        let rhs = curve_rhs(&x);
        // Every try is made, whether or not one has already won.
        if is_square(&rhs) && found.is_none() {
            let y = FIELD.from_mont(&sqrt(&rhs));
            // The seed's lowest bit picks which of the two roots.
            let y = if seed[31] & 1 == y[0] as u8 & 1 { y } else { FIELD.sub(&[0; 4], &y) };
            found = Some(Affine { x, y });
        }
    }
    found
}

/// A scalar from 32 random bytes, if it is between 1 and the order
/// (exclusive).
fn scalar(b: &[u8; 32]) -> Option<U256> {
    let s = ORDER.reduce(&from_be(b));
    (s != [1, 0, 0, 0] && !is_zero(&s)).then_some(s)
}

impl Sae {
    /// An exchange of `password` between `own` and `peer` (addresses),
    /// with 64 fresh random bytes for `rand` and `mask`. `None` if those
    /// give an unusable scalar (draw again) or no PWE was found (all 40
    /// tries missed: about 2⁻⁴⁰).
    pub fn new(password: &[u8], own: &[u8; 6], peer: &[u8; 6], random: &[u8; 64]) -> Option<Sae> {
        let pwe = pwe(password, own, peer)?;
        let rand = scalar(random[..32].try_into().unwrap())?;
        let mask = scalar(random[32..].try_into().unwrap())?;
        let s = ORDER.add(&rand, &mask);
        if is_zero(&s) || s == [1, 0, 0, 0] {
            return None;
        }
        let element = pwe.point().mul(&mask).affine()?.neg();
        Some(Sae {
            pwe,
            rand,
            scalar: s,
            element,
            peer: None,
            kck: [0; 32],
            pmk: [0; 32],
            pmkid: [0; 16],
            send_confirm: 0,
            confirmed: false,
        })
    }

    /// Our commit: group, scalar, element.
    pub fn commit(&self) -> [u8; COMMIT_LEN] {
        let mut c = [0u8; COMMIT_LEN];
        c[..2].copy_from_slice(&GROUP.to_le_bytes());
        c[2..34].copy_from_slice(&to_be(&self.scalar));
        c[34..].copy_from_slice(&self.element.encode());
        c
    }

    /// Takes the peer's commit: the keys are derived, and our confirm
    /// returned. A commit again (ours lost, say) gives the same keys.
    pub fn receive_commit(&mut self, body: &[u8]) -> Result<[u8; CONFIRM_LEN], Error> {
        if body.len() < COMMIT_LEN {
            return Err(Error::Malformed);
        }
        if u16::from_le_bytes([body[0], body[1]]) != GROUP {
            return Err(Error::Group);
        }
        let s = from_be(body[2..34].try_into().unwrap());
        if !less(&s, &N) || is_zero(&s) || s == [1, 0, 0, 0] {
            return Err(Error::Scalar);
        }
        let e = Affine::decode(body[34..COMMIT_LEN].try_into().unwrap()).ok_or(Error::Element)?;
        if s == self.scalar && e == self.element {
            return Err(Error::Reflection);
        }
        let k = self.pwe.point().mul(&s).add(&e.point()).mul(&self.rand).affine().ok_or(Error::Element)?;
        let keyseed = hmac_sha256(&[0; 32], &[&to_be(&k.x)]);
        let context = to_be(&ORDER.add(&self.scalar, &s));
        let mut keys = [0u8; 64];
        kdf_sha256(&keyseed, b"SAE KCK and PMK", &[&context], &mut keys);
        self.kck.copy_from_slice(&keys[..32]);
        self.pmk.copy_from_slice(&keys[32..]);
        self.pmkid.copy_from_slice(&context[..16]);
        self.peer = Some((s, e));
        Ok(self.confirm().unwrap())
    }

    /// Our confirm (again), with the send-confirm counter one higher;
    /// `None` before the peer's commit.
    pub fn confirm(&mut self) -> Option<[u8; CONFIRM_LEN]> {
        let (ps, pe) = self.peer?;
        self.send_confirm = self.send_confirm.wrapping_add(1);
        let sc = self.send_confirm.to_le_bytes();
        let mac = hmac_sha256(&self.kck, &[&sc, &to_be(&self.scalar), &self.element.encode(), &to_be(&ps), &pe.encode()]);
        let mut c = [0u8; CONFIRM_LEN];
        c[..2].copy_from_slice(&sc);
        c[2..].copy_from_slice(&mac);
        Some(c)
    }

    /// Takes the peer's confirm: its HMAC over both commits (theirs
    /// first) must hold.
    pub fn receive_confirm(&mut self, body: &[u8]) -> Result<(), Error> {
        let (ps, pe) = self.peer.ok_or(Error::State)?;
        if body.len() < CONFIRM_LEN {
            return Err(Error::Malformed);
        }
        let want = hmac_sha256(&self.kck, &[&body[..2], &to_be(&ps), &pe.encode(), &to_be(&self.scalar), &self.element.encode()]);
        if (0..32).fold(0, |d, i| d | (want[i] ^ body[2 + i])) != 0 {
            return Err(Error::Confirm);
        }
        self.confirmed = true;
        Ok(())
    }

    /// The PMK, once the peer's confirm has held.
    pub fn pmk(&self) -> Option<[u8; 32]> {
        self.confirmed.then_some(self.pmk)
    }

    /// The PMKID: the first 16 bytes of the two scalars' sum.
    pub fn pmkid(&self) -> Option<[u8; 16]> {
        self.confirmed.then_some(self.pmkid)
    }
}
