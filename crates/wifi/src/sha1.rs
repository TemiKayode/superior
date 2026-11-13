//! SHA-1, and what WPA2 builds on it: HMAC-SHA1 (RFC 2104), PBKDF2 (RFC
//! 8018) for the passphrase, and IEEE 802.11's PRF for the session keys.
//! SHA-1 is weak against collisions, which none of these uses depends on.

/// SHA-1's running state.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    block: [u8; 64],
    fill: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Sha1 {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            block: [0; 64],
            fill: 0,
            total: 0,
        }
    }

    fn compress(&mut self) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(self.block[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a82_7999),
                20..40 => (b ^ c ^ d, 0x6ed9_eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (h, v) in self.h.iter_mut().zip([a, b, c, d, e]) {
            *h = h.wrapping_add(v);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let n = (64 - self.fill).min(data.len());
            self.block[self.fill..self.fill + n].copy_from_slice(&data[..n]);
            self.fill += n;
            data = &data[n..];
            if self.fill == 64 {
                self.compress();
                self.fill = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.total * 8;
        self.update(&[0x80]);
        while self.fill != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (o, h) in out.chunks_mut(4).zip(self.h) {
            o.copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

/// SHA-1 of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::new();
    s.update(data);
    s.finish()
}

/// HMAC-SHA1 under `key` of the concatenation of `parts`.
pub fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha1::new();
    inner.update(&k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha1::new();
    outer.update(&k.map(|b| b ^ 0x5c));
    outer.update(&inner.finish());
    outer.finish()
}

/// PBKDF2 with HMAC-SHA1: `out.len()` bytes from `password` and `salt`
/// after `rounds` iterations.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let mut u = hmac_sha1(password, &[salt, &(i as u32 + 1).to_be_bytes()]);
        let mut t = u;
        for _ in 1..rounds {
            u = hmac_sha1(password, &[&u]);
            for (t, u) in t.iter_mut().zip(u) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// The pairwise master key WPA2-Personal derives from a passphrase (8 to
/// 63 printable characters) and the network's SSID (802.11 Annex J.4).
pub fn psk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2_sha1(passphrase, ssid, 4096, &mut pmk);
    pmk
}

/// IEEE 802.11's PRF (12.7.1.2): `out.len()` bytes of HMAC-SHA1 under
/// `key` of `label`, a zero byte, `data` (the concatenation of its parts)
/// and a counter byte.
pub fn prf(key: &[u8], label: &[u8], data: &[&[u8]], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let mut parts: [&[u8]; 8] = [&[]; 8];
        parts[0] = label;
        parts[1] = &[0];
        let n = data.len().min(5);
        parts[2..2 + n].copy_from_slice(&data[..n]);
        let counter = [i as u8];
        parts[2 + n] = &counter;
        let block = hmac_sha1(key, &parts[..3 + n]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}
