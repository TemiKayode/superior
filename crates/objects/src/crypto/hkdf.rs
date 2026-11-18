//! HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869) on it: TLS 1.3's key
//! schedule.

use super::sha2::Sha256;

/// HMAC-SHA256 of the parts, concatenated.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finish());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(&k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(&k.map(|b| b ^ 0x5c));
    outer.update(&inner.finish());
    outer.finish()
}

/// HKDF-Extract: the pseudorandom key from `salt` and `ikm`.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[ikm])
}

/// HKDF-Expand: `out.len()` bytes (at most 255 blocks) from `prk` and the
/// parts of `info`, concatenated.
pub fn expand(prk: &[u8; 32], info: &[&[u8]], out: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut have = 0;
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let counter = [i as u8 + 1];
        let mut parts: [&[u8]; 8] = [&[]; 8];
        parts[0] = &t[..have];
        let n = info.len().min(6);
        parts[1..1 + n].copy_from_slice(&info[..n]);
        parts[1 + n] = &counter;
        t = hmac_sha256(prk, &parts[..2 + n]);
        have = 32;
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// RFC 4231 test case 2 (a short key).
    #[test]
    fn hmac_rfc4231() {
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(mac.to_vec(), h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }

    /// RFC 5869 test case 1.
    #[test]
    fn hkdf_rfc5869() {
        let prk = extract(&h("000102030405060708090a0b0c"), &[0x0b; 22]);
        assert_eq!(prk.to_vec(), h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        let mut okm = [0u8; 42];
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        expand(&prk, &[&info[..4], &info[4..]], &mut okm);
        assert_eq!(okm.to_vec(), h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }
}
