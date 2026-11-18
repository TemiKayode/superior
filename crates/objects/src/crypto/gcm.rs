//! AES-128-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags: the
//! AEAD TLS 1.3's `TLS_AES_128_GCM_SHA256` protects records with.
//!
//! GHASH multiplies bit by bit, without tables (slow, but its timing does
//! not depend on the hash key's bits through memory).

use super::aes::Aes128;

pub const TAG: usize = 16;

/// A key, expanded, with its GHASH key.
#[derive(Clone)]
pub struct Gcm {
    aes: Aes128,
    h: u128,
}

/// The product in GF(2^128), GCM's bit order (block bytes big-endian).
fn mul(x: u128, y: u128) -> u128 {
    let mut z = 0;
    let mut v = y;
    for i in 0..128 {
        z ^= v & 0u128.wrapping_sub(x >> (127 - i) & 1);
        v = v >> 1 ^ (0xe1 << 120) & 0u128.wrapping_sub(v & 1);
    }
    z
}

fn block(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a[..b.len()].copy_from_slice(b);
    u128::from_be_bytes(a)
}

impl Gcm {
    pub fn new(key: &[u8; 16]) -> Gcm {
        let aes = Aes128::new(key);
        let mut h = [0u8; 16];
        aes.encrypt(&mut h);
        Gcm { aes, h: u128::from_be_bytes(h) }
    }

    fn ghash(&self, aad: &[u8], data: &[u8]) -> u128 {
        let mut y = 0;
        for c in aad.chunks(16).chain(data.chunks(16)) {
            y = mul(y ^ block(c), self.h);
        }
        let lengths = ((aad.len() as u128 * 8) << 64) | data.len() as u128 * 8;
        mul(y ^ lengths, self.h)
    }

    /// Counter block `i` (from 1 for J0) for `nonce`, encrypted.
    fn keystream(&self, nonce: &[u8; 12], i: u32) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[..12].copy_from_slice(nonce);
        c[12..].copy_from_slice(&i.to_be_bytes());
        self.aes.encrypt(&mut c);
        c
    }

    fn ctr(&self, nonce: &[u8; 12], data: &mut [u8]) {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let s = self.keystream(nonce, i as u32 + 2);
            for (d, s) in chunk.iter_mut().zip(s) {
                *d ^= s;
            }
        }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> [u8; TAG] {
        (self.ghash(aad, data) ^ u128::from_be_bytes(self.keystream(nonce, 1))).to_be_bytes()
    }

    /// Encrypts `data` in place; its tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; TAG] {
        self.ctr(nonce, data);
        self.tag(nonce, aad, data)
    }

    /// Checks `tag` and decrypts `data` in place: false (and `data` left
    /// encrypted) if the tag is wrong.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; TAG]) -> bool {
        let want = self.tag(nonce, aad, data);
        if want.iter().zip(tag).fold(0, |d, (a, b)| d | (a ^ b)) != 0 {
            return false;
        }
        self.ctr(nonce, data);
        true
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

    const KEY: &str = "feffe9928665731c6d6a8f9467308308";
    const IV: &str = "cafebabefacedbaddecaf888";
    const P: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    const C: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";

    fn gcm() -> (Gcm, [u8; 12]) {
        (Gcm::new(&h(KEY).try_into().unwrap()), h(IV).try_into().unwrap())
    }

    /// The GCM specification's test cases 1 and 2 (the zero key).
    #[test]
    fn zero_key() {
        let g = Gcm::new(&[0; 16]);
        assert_eq!(g.seal(&[0; 12], &[], &mut []).to_vec(), h("58e2fccefa7e3061367f1d57a4e7455a"));
        let mut d = [0u8; 16];
        let t = g.seal(&[0; 12], &[], &mut d);
        assert_eq!(d.to_vec(), h("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(t.to_vec(), h("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    /// Test case 3: no additional data.
    #[test]
    fn case_3() {
        let (g, n) = gcm();
        let mut d = h(P);
        let t = g.seal(&n, &[], &mut d);
        assert_eq!(d, h(C));
        assert_eq!(t.to_vec(), h("4d5c2af327cd64a62cf35abd2ba6fab4"));
        assert!(g.open(&n, &[], &mut d, &t));
        assert_eq!(d, h(P));
    }

    /// Test case 4: additional data, and a message not a whole number of
    /// blocks; any changed byte is refused.
    #[test]
    fn case_4() {
        let (g, n) = gcm();
        let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut d = h(P)[..60].to_vec();
        let t = g.seal(&n, &aad, &mut d);
        assert_eq!(d, h(C)[..60].to_vec());
        assert_eq!(t.to_vec(), h("5bc94fbc3221a5db94fae95ae7121a47"));
        let mut bad = d.clone();
        bad[7] ^= 1;
        assert!(!g.open(&n, &aad, &mut bad, &t));
        assert!(!g.open(&n, &aad[1..], &mut d.clone(), &t));
        assert!(g.open(&n, &aad, &mut d, &t));
        assert_eq!(d, h(P)[..60].to_vec());
    }
}
