//! The NIST P-256 curve (y² = x³ − 3x + b over the prime field of p =
//! 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1), which SAE's group 19 is: what WPA3's
//! password exchange computes on.
//!
//! Numbers are four 64-bit limbs, least significant first. Field elements
//! are kept in Montgomery form (times 2²⁵⁶ mod p); the constants Montgomery
//! multiplication needs are derived from the modulus at compile time, not
//! written out. Points are added and doubled in Jacobian coordinates
//! (formulas for a = −3: dbl-2001-b and add-2007-bl).
//!
//! Scalar multiplication is plain double-and-add: its timing depends on
//! the scalar. SAE's secrets live for one exchange and a radio attacker
//! measures time coarsely, but a constant-time ladder can replace it
//! behind the same call.

pub type U256 = [u64; 4];

/// A 32-byte big-endian number from 64 hex digits.
const fn hex(s: &str) -> U256 {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 64 {
        let c = b[i];
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not hex"),
        } as u64;
        let limb = 3 - i / 16;
        out[limb] = out[limb] << 4 | d;
        i += 1;
    }
    out
}

pub const P: U256 = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
/// The group's order.
pub const N: U256 = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const B: U256 = hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
const GX: U256 = hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const GY: U256 = hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

const fn lt(a: &U256, b: &U256) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a + b` and the carry out.
const fn add(a: &U256, b: &U256) -> (U256, bool) {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let s = a[i] as u128 + b[i] as u128 + carry as u128;
        r[i] = s as u64;
        carry = (s >> 64) as u64;
        i += 1;
    }
    (r, carry != 0)
}

/// `a − b` and the borrow out.
const fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let d = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow as u128);
        r[i] = d as u64;
        borrow = (d >> 127) as u64;
        i += 1;
    }
    (r, borrow != 0)
}

/// A modulus above 2²⁵⁵, with what Montgomery multiplication needs.
pub struct Modulus {
    pub m: U256,
    /// −m⁻¹ mod 2⁶⁴.
    inv: u64,
    /// 2⁵¹² mod m, to bring numbers into Montgomery form.
    r2: U256,
}

impl Modulus {
    const fn new(m: U256) -> Modulus {
        // m⁻¹ mod 2⁶⁴ by Newton's iteration (each step doubles the bits).
        let mut x = 1u64;
        let mut i = 0;
        while i < 6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(x)));
            i += 1;
        }
        // 2²⁵⁶ mod m is 2²⁵⁶ − m (m > 2²⁵⁵); doubled 256 times, 2⁵¹² mod m.
        let mut r = sub(&[0; 4], &m).0;
        let mut i = 0;
        while i < 256 {
            r = Self::add_mod_const(&r, &r, &m);
            i += 1;
        }
        Modulus { m, inv: x.wrapping_neg(), r2: r }
    }

    const fn add_mod_const(a: &U256, b: &U256, m: &U256) -> U256 {
        let (s, carry) = add(a, b);
        if carry || !lt(&s, m) { sub(&s, m).0 } else { s }
    }

    pub fn add(&self, a: &U256, b: &U256) -> U256 {
        Self::add_mod_const(a, b, &self.m)
    }

    pub fn sub(&self, a: &U256, b: &U256) -> U256 {
        let (d, borrow) = sub(a, b);
        if borrow { add(&d, &self.m).0 } else { d }
    }

    /// `a · b · 2⁻²⁵⁶ mod m` (CIOS).
    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        let m = &self.m;
        let mut t = [0u64; 6];
        for &bi in b {
            let mut c = 0u128;
            for j in 0..4 {
                let x = t[j] as u128 + a[j] as u128 * bi as u128 + c;
                t[j] = x as u64;
                c = x >> 64;
            }
            let x = t[4] as u128 + c;
            t[4] = x as u64;
            t[5] = (x >> 64) as u64;
            let u = t[0].wrapping_mul(self.inv);
            let mut c = (t[0] as u128 + u as u128 * m[0] as u128) >> 64;
            for j in 1..4 {
                let x = t[j] as u128 + u as u128 * m[j] as u128 + c;
                t[j - 1] = x as u64;
                c = x >> 64;
            }
            let x = t[4] as u128 + c;
            t[3] = x as u64;
            t[4] = t[5] + (x >> 64) as u64;
            t[5] = 0;
        }
        let r = [t[0], t[1], t[2], t[3]];
        if t[4] != 0 || !lt(&r, m) { sub(&r, m).0 } else { r }
    }

    pub fn to_mont(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &U256) -> U256 {
        self.mul(a, &[1, 0, 0, 0])
    }

    /// One, in Montgomery form.
    pub fn one(&self) -> U256 {
        self.to_mont(&[1, 0, 0, 0])
    }

    /// `aᵉ` (a in Montgomery form, e a plain number).
    pub fn pow(&self, a: &U256, e: &U256) -> U256 {
        let mut r = self.one();
        for i in (0..256).rev() {
            r = self.mul(&r, &r);
            if e[i / 64] >> (i % 64) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// `a⁻¹` (Fermat: a^(m−2); m is prime). 0 for 0.
    pub fn inv(&self, a: &U256) -> U256 {
        self.pow(a, &sub(&self.m, &[2, 0, 0, 0]).0)
    }

    /// `a mod m`, for a below 2²⁵⁶ (m > 2²⁵⁵, so one subtraction does).
    pub fn reduce(&self, a: &U256) -> U256 {
        if lt(a, &self.m) { *a } else { sub(a, &self.m).0 }
    }
}

pub static FIELD: Modulus = Modulus::new(P);
pub static ORDER: Modulus = Modulus::new(N);

pub fn from_be(b: &[u8; 32]) -> U256 {
    core::array::from_fn(|i| u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap()))
}

pub fn to_be(a: &U256) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[24 - 8 * i..32 - 8 * i].copy_from_slice(&a[i].to_be_bytes());
    }
    b
}

pub fn is_zero(a: &U256) -> bool {
    *a == [0; 4]
}

pub fn less(a: &U256, b: &U256) -> bool {
    lt(a, b)
}

/// `x³ − 3x + b` for plain `x`, in Montgomery form.
pub fn curve_rhs(x: &U256) -> U256 {
    let f = &FIELD;
    let xm = f.to_mont(x);
    let x3 = f.mul(&f.mul(&xm, &xm), &xm);
    let three_x = f.add(&f.add(&xm, &xm), &xm);
    f.add(&f.sub(&x3, &three_x), &f.to_mont(&B))
}

/// Whether `v` (Montgomery form, not 0) is a square mod p: Euler's
/// criterion, v^((p−1)/2) = 1.
pub fn is_square(v: &U256) -> bool {
    let f = &FIELD;
    let e = sub(&P, &[1, 0, 0, 0]).0;
    let e = [e[0] >> 1 | e[1] << 63, e[1] >> 1 | e[2] << 63, e[2] >> 1 | e[3] << 63, e[3] >> 1];
    f.pow(v, &e) == f.one()
}

/// A square root of square `v` (Montgomery form): v^((p+1)/4), p ≡ 3 mod 4.
pub fn sqrt(v: &U256) -> U256 {
    let e = add(&P, &[1, 0, 0, 0]).0;
    let e = [e[0] >> 2 | e[1] << 62, e[1] >> 2 | e[2] << 62, e[2] >> 2 | e[3] << 62, e[3] >> 2];
    FIELD.pow(v, &e)
}

/// A point in Jacobian coordinates (Montgomery form); Z = 0 is the point
/// at infinity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    x: U256,
    y: U256,
    z: U256,
}

/// An affine point as plain numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affine {
    pub x: U256,
    pub y: U256,
}

impl Affine {
    /// The generator.
    pub fn generator() -> Affine {
        Affine { x: GX, y: GY }
    }

    /// Whether it is on the curve, its coordinates below p.
    pub fn on_curve(&self) -> bool {
        let f = &FIELD;
        if !lt(&self.x, &P) || !lt(&self.y, &P) {
            return false;
        }
        let y = f.to_mont(&self.y);
        f.mul(&y, &y) == curve_rhs(&self.x)
    }

    /// x then y, 32 bytes each, big-endian.
    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&to_be(&self.x));
        b[32..].copy_from_slice(&to_be(&self.y));
        b
    }

    /// From [`encode`](Self::encode)'s form, if on the curve.
    pub fn decode(b: &[u8; 64]) -> Option<Affine> {
        let a = Affine { x: from_be(b[..32].try_into().unwrap()), y: from_be(b[32..].try_into().unwrap()) };
        a.on_curve().then_some(a)
    }

    pub fn neg(&self) -> Affine {
        Affine { x: self.x, y: if is_zero(&self.y) { self.y } else { sub(&P, &self.y).0 } }
    }

    pub fn point(&self) -> Point {
        Point { x: FIELD.to_mont(&self.x), y: FIELD.to_mont(&self.y), z: FIELD.one() }
    }
}

impl Point {
    pub const INFINITY: Point = Point { x: [0; 4], y: [0; 4], z: [0; 4] };

    pub fn is_infinity(&self) -> bool {
        is_zero(&self.z)
    }

    pub fn double(&self) -> Point {
        let f = &FIELD;
        if self.is_infinity() || is_zero(&self.y) {
            return Point::INFINITY;
        }
        let delta = f.mul(&self.z, &self.z);
        let gamma = f.mul(&self.y, &self.y);
        let beta = f.mul(&self.x, &gamma);
        let t = f.mul(&f.sub(&self.x, &delta), &f.add(&self.x, &delta));
        let alpha = f.add(&f.add(&t, &t), &t);
        let beta2 = f.add(&beta, &beta);
        let beta4 = f.add(&beta2, &beta2);
        let beta8 = f.add(&beta4, &beta4);
        let x3 = f.sub(&f.mul(&alpha, &alpha), &beta8);
        let yz = f.add(&self.y, &self.z);
        let z3 = f.sub(&f.sub(&f.mul(&yz, &yz), &gamma), &delta);
        let g2 = f.mul(&gamma, &gamma);
        let g2x2 = f.add(&g2, &g2);
        let g2x4 = f.add(&g2x2, &g2x2);
        let g2x8 = f.add(&g2x4, &g2x4);
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g2x8);
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn add(&self, q: &Point) -> Point {
        let f = &FIELD;
        if self.is_infinity() {
            return *q;
        }
        if q.is_infinity() {
            return *self;
        }
        let z1z1 = f.mul(&self.z, &self.z);
        let z2z2 = f.mul(&q.z, &q.z);
        let u1 = f.mul(&self.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&f.mul(&self.y, &q.z), &z2z2);
        let s2 = f.mul(&f.mul(&q.y, &self.z), &z1z1);
        let h = f.sub(&u2, &u1);
        let r = f.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&r) { self.double() } else { Point::INFINITY };
        }
        let r = f.add(&r, &r);
        let h2 = f.add(&h, &h);
        let i = f.mul(&h2, &h2);
        let j = f.mul(&h, &i);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.mul(&r, &r), &j), &f.add(&v, &v));
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let zz = f.add(&self.z, &q.z);
        let z3 = f.mul(&f.sub(&f.sub(&f.mul(&zz, &zz), &z1z1), &z2z2), &h);
        Point { x: x3, y: y3, z: z3 }
    }

    /// `k · self` (k a plain number).
    pub fn mul(&self, k: &U256) -> Point {
        let mut r = Point::INFINITY;
        for i in (0..256).rev() {
            r = r.double();
            if k[i / 64] >> (i % 64) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    /// The affine point, `None` at infinity.
    pub fn affine(&self) -> Option<Affine> {
        if self.is_infinity() {
            return None;
        }
        let f = &FIELD;
        let zi = f.inv(&self.z);
        let zi2 = f.mul(&zi, &zi);
        let x = f.from_mont(&f.mul(&self.x, &zi2));
        let y = f.from_mont(&f.mul(&self.y, &f.mul(&zi2, &zi)));
        Some(Affine { x, y })
    }
}
