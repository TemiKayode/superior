//! Ed25519 signature verification (RFC 8032), for the kernel to check a
//! signed boot bundle before it runs anything from it.
//!
//! Only verification: every input is public, so nothing here needs to run
//! in constant time. Field elements are five 51-bit limbs modulo
//! p = 2^255 - 19; points are in extended twisted Edwards coordinates.
//! Verification is the strict, cofactorless check: `S` must be below the
//! group order and `R` and `A` canonical encodings of curve points, and
//! then `[S]B` must equal `R + [k]A`, with `k = SHA-512(R || A || M) mod L`.

use super::sha2::Sha512;

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn small(n: u64) -> Fe {
        Fe([n, 0, 0, 0, 0])
    }

    /// The low 255 bits of `b`, little-endian (bit 255 is ignored).
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            (load(24) >> 12) & MASK,
        ])
    }

    /// Carries each limb into the next, so each is below 2^51 plus a little.
    fn carry(mut h: [u64; 5]) -> Fe {
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[0] += 19 * (h[4] >> 51);
        h[4] &= MASK;
        Fe(h)
    }

    /// The canonical encoding: fully reduced, little-endian.
    fn to_bytes(self) -> [u8; 32] {
        let mut h = Fe::carry(Fe::carry(self.0).0).0;
        // h < 2^255 + small: subtract p once if h >= p.
        let mut q = (h[0] + 19) >> 51;
        for limb in &h[1..] {
            q = (limb + q) >> 51;
        }
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[4] &= MASK;
        let mut out = [0u8; 32];
        let (mut acc, mut bits, mut i) = (0u128, 0, 0);
        for limb in h {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 {
                out[i] = acc as u8;
                acc >>= 8;
                bits -= 8;
                i += 1;
            }
        }
        out[31] = acc as u8;
        out
    }

    fn add(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        Fe::carry([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    fn sub(self, b: Fe) -> Fe {
        // Add 4p first so no limb goes below zero (both are carried).
        let a = self.0;
        let b = b.0;
        const P4_0: u64 = 4 * ((1 << 51) - 19);
        const P4: u64 = 4 * ((1 << 51) - 1);
        Fe::carry([
            a[0] + P4_0 - b[0],
            a[1] + P4 - b[1],
            a[2] + P4 - b[2],
            a[3] + P4 - b[3],
            a[4] + P4 - b[4],
        ])
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        let c0 = m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1);
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2);
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3);
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        let mask = MASK as u128;
        let c1 = c1 + (c0 >> 51);
        let c2 = c2 + (c1 >> 51);
        let c3 = c3 + (c2 >> 51);
        let c4 = c4 + (c3 >> 51);
        let r0 = (c0 & mask) + (c4 >> 51) * 19;
        let r1 = (c1 & mask) + (r0 >> 51);
        Fe::carry([
            (r0 & mask) as u64,
            r1 as u64,
            (c2 & mask) as u64,
            (c3 & mask) as u64,
            (c4 & mask) as u64,
        ])
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// `self` squared `k` times.
    fn pow2k(self, k: u32) -> Fe {
        let mut x = self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// (self^(2^250 - 1), self^11), the common start of inversion and the
    /// square root.
    fn pow22501(self) -> (Fe, Fe) {
        let t0 = self.square();
        let t1 = t0.pow2k(2);
        let t2 = self.mul(t1);
        let t3 = t0.mul(t2);
        let t4 = t3.square();
        let t5 = t2.mul(t4);
        let t7 = t5.pow2k(5).mul(t5);
        let t9 = t7.pow2k(10).mul(t7);
        let t11 = t9.pow2k(20).mul(t9);
        let t13 = t11.pow2k(10).mul(t7);
        let t15 = t13.pow2k(50).mul(t13);
        let t17 = t15.pow2k(100).mul(t15);
        let t19 = t17.pow2k(50).mul(t13);
        (t19, t3)
    }

    /// self^(p - 2) = 1/self (0 for 0).
    fn invert(self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(t3)
    }

    /// self^((p - 5) / 8).
    fn pow_p58(self) -> Fe {
        self.pow22501().0.pow2k(2).mul(self)
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0; 32]
    }

    fn eq(self, b: Fe) -> bool {
        self.to_bytes() == b.to_bytes()
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

/// The curve's constants, computed once per verification (a few field
/// inversions, nothing next to the scalar multiplications).
struct Curve {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
}

impl Curve {
    fn new() -> Curve {
        // d = -121665 / 121666; sqrt(-1) = 2^((p - 1) / 4).
        let d = Fe::small(121665).neg().mul(Fe::small(121666).invert());
        let sqrt_m1 = Fe::small(2).pow22501().0.pow2k(3).mul(Fe::small(8));
        Curve { d, d2: d.add(d), sqrt_m1 }
    }
}

#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    /// Decodes a point (RFC 8032, 5.1.3); `None` if `b` is not the
    /// canonical encoding of one.
    fn decode(c: &Curve, b: &[u8; 32]) -> Option<Point> {
        let y = Fe::from_bytes(b);
        let mut canonical = y.to_bytes();
        canonical[31] |= b[31] & 0x80;
        if canonical != *b {
            return None;
        }
        let sign = b[31] >> 7 == 1;
        let yy = y.square();
        let u = yy.sub(Fe::ONE);
        let v = c.d.mul(yy).add(Fe::ONE);
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow_p58());
        let vxx = v.mul(x.square());
        if vxx.eq(u) {
        } else if vxx.eq(u.neg()) {
            x = x.mul(c.sqrt_m1);
        } else {
            return None;
        }
        if x.is_zero() && sign {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point { x, y, z: Fe::ONE, t: x.mul(y) })
    }

    fn encode(self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(zi);
        let mut b = self.y.mul(zi).to_bytes();
        b[31] |= (x.is_negative() as u8) << 7;
        b
    }

    /// The complete addition law for a = -1 (add-2008-hwcd-3), which also
    /// doubles.
    fn add(self, c: &Curve, q: Point) -> Point {
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let cc = self.t.mul(c.d2).mul(q.t);
        let d = self.z.add(self.z).mul(q.z);
        let (e, f, g, h) = (b.sub(a), d.sub(cc), d.add(cc), b.add(a));
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }

    /// `[k]self`, `k` a little-endian 256-bit scalar.
    fn mul(self, c: &Curve, k: &[u8; 32]) -> Point {
        let mut r = Point::IDENTITY;
        for i in (0..256).rev() {
            r = r.add(c, r);
            if k[i / 8] >> (i % 8) & 1 == 1 {
                r = r.add(c, self);
            }
        }
        r
    }
}

/// The group order L = 2^252 + 27742317777372353535851937790883648493, as
/// little-endian 64-bit limbs.
const L: [u64; 4] = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000];

fn limbs(b: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn below_l(x: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if x[i] != L[i] {
            return x[i] < L[i];
        }
    }
    false
}

/// `h` (a 512-bit little-endian number) modulo L, a bit at a time.
fn reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        let bit = (h[i / 8] >> (i % 8) & 1) as u64;
        // r = 2r + bit; r < L < 2^253, so this fits.
        for j in (1..4).rev() {
            r[j] = r[j] << 1 | r[j - 1] >> 63;
        }
        r[0] = r[0] << 1 | bit;
        if !below_l(&r) {
            let mut borrow = 0u64;
            for j in 0..4 {
                let (d, b1) = r[j].overflowing_sub(L[j]);
                let (d, b2) = d.overflowing_sub(borrow);
                r[j] = d;
                borrow = (b1 | b2) as u64;
            }
        }
    }
    let mut out = [0u8; 32];
    for (j, limb) in r.iter().enumerate() {
        out[j * 8..j * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Whether `signature` is `public`'s Ed25519 signature of the message made
/// of `message`'s pieces, one after another.
pub fn verify(public: &[u8; 32], message: &[&[u8]], signature: &[u8; 64]) -> bool {
    let r_bytes: &[u8; 32] = signature[..32].try_into().unwrap();
    let s: &[u8; 32] = signature[32..].try_into().unwrap();
    if !below_l(&limbs(s)) {
        return false;
    }
    let c = Curve::new();
    let (Some(a), Some(r)) = (Point::decode(&c, public), Point::decode(&c, r_bytes)) else {
        return false;
    };
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(public);
    for m in message {
        h.update(m);
    }
    let k = reduce(&h.finish());
    // The base point: y = 4/5, x even.
    let mut b_enc = [0x66u8; 32];
    b_enc[0] = 0x58;
    let Some(b) = Point::decode(&c, &b_enc) else {
        return false;
    };
    b.mul(&c, s).encode() == r.add(&c, a.mul(&c, &k)).encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha2::hex;
    use ed25519_dalek::{Signer, SigningKey};

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn field_constants() {
        let c = Curve::new();
        assert!(c.sqrt_m1.square().eq(Fe::ONE.neg()));
        assert!(c.d.mul(Fe::small(121666)).eq(Fe::small(121665).neg()));
        let x = Fe::small(12345).mul(Fe::small(678));
        assert!(x.mul(x.invert()).eq(Fe::ONE));
        // p itself encodes as 0.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(Fe::from_bytes(&p).is_zero());
    }

    #[test]
    fn rfc8032_vectors() {
        let cases = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (public, message, signature) in cases {
            let (public, message, signature) = (arr(public), hex(message), arr::<64>(signature));
            assert!(verify(&public, &[&message], &signature));
            let mut wrong = message.clone();
            wrong.push(0);
            assert!(!verify(&public, &[&wrong], &signature));
        }
    }

    #[test]
    fn agrees_with_dalek() {
        // A fixed sequence of seeds and messages: dalek signs, this checks.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..40 {
            let seed: [u8; 32] = core::array::from_fn(|_| next() as u8);
            let key = SigningKey::from_bytes(&seed);
            let public = key.verifying_key().to_bytes();
            let message: std::vec::Vec<u8> = (0..round * 37).map(|_| next() as u8).collect();
            let signature = key.sign(&message).to_bytes();
            let (a, b) = message.split_at(message.len() / 3);
            assert!(verify(&public, &[a, b], &signature), "round {round}");
            // Any flipped bit in the message, signature or key fails.
            let mut m = message.clone();
            if !m.is_empty() {
                let at = round % m.len();
                m[at] ^= 1 << (round % 8);
                assert!(!verify(&public, &[&m], &signature));
            }
            let mut s = signature;
            s[round % 64] ^= 1 << (round % 8);
            assert!(!verify(&public, &[&message], &s));
            let mut p = public;
            p[round % 32] ^= 1 << (round % 8);
            assert!(!verify(&p, &[&message], &signature));
        }
    }

    #[test]
    fn s_at_or_above_the_order_is_refused() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        let mut signature = key.sign(b"hello").to_bytes();
        assert!(verify(&public, &[b"hello"], &signature));
        // S + L is the same scalar but not canonical.
        let mut carry = 0u128;
        for (j, l) in L.iter().enumerate() {
            let s = u64::from_le_bytes(signature[32 + j * 8..40 + j * 8].try_into().unwrap());
            let sum = s as u128 + *l as u128 + carry;
            signature[32 + j * 8..40 + j * 8].copy_from_slice(&(sum as u64).to_le_bytes());
            carry = sum >> 64;
        }
        assert!(!verify(&public, &[b"hello"], &signature));
    }
}
