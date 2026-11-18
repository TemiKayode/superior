//! X25519 (RFC 7748): Diffie-Hellman on Curve25519's Montgomery form, on
//! the field arithmetic Ed25519 uses. TLS's key exchange.

use super::ed25519::Fe;

/// The base point's u-coordinate.
pub const BASE: [u8; 32] = {
    let mut b = [0; 32];
    b[0] = 9;
    b
};

/// Swaps `a` and `b` if `swap` is 1, in constant time.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// The scalar `k` (clamped) times the point with u-coordinate `u`.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::small(1), Fe::small(0), x1, Fe::small(1));
    let mut swap = 0;
    for t in (0..255).rev() {
        let bit = (k[t / 8] >> (t % 8) & 1) as u64;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(Fe::small(121_665).mul(e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    x2.mul(z2.invert()).to_bytes()
}

/// The public key for the secret `k`.
pub fn public(k: &[u8; 32]) -> [u8; 32] {
    x25519(k, &BASE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let mut b = [0; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }

    #[test]
    fn rfc7748_vector() {
        let k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(x25519(&k, &u), h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(public(&a), h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(public(&b), h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &public(&b)), shared);
        assert_eq!(x25519(&b, &public(&a)), shared);
    }

    #[test]
    fn rfc7748_iterated_1000() {
        let (mut k, mut u) = (BASE, BASE);
        for _ in 0..1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
        }
        assert_eq!(k, h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }
}
