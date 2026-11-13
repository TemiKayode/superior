//! AES-128 (FIPS 197), both ways, and what WPA2 builds on it: CCM (RFC
//! 3610), the mode CCMP encrypts and authenticates frames with, and AES
//! key wrap (RFC 3394), which carries the group key in the handshake.
//!
//! A table implementation: its timing depends on the data, which a radio
//! link's attacker cannot measure finely; a constant-time one can replace
//! it behind the same calls.

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// The S-box: each byte's inverse in GF(2^8) (0 for 0), then the affine
/// map.
const SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        let mut inv = 0u8;
        if x != 0 {
            let mut y = 1;
            while y < 256 {
                if gmul(x as u8, y as u8) == 1 {
                    inv = y as u8;
                    break;
                }
                y += 1;
            }
        }
        let b = inv;
        s[x] = b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
        x += 1;
    }
    s
};

const INV_SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        s[SBOX[x] as usize] = x as u8;
        x += 1;
    }
    s
};

/// An expanded AES-128 key.
#[derive(Clone)]
pub struct Aes128 {
    round: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round = [[0u8; 16]; 11];
        round[0] = *key;
        let mut rcon = 1u8;
        for r in 1..11 {
            let prev = round[r - 1];
            let mut t = [prev[13], prev[14], prev[15], prev[12]];
            for b in &mut t {
                *b = SBOX[*b as usize];
            }
            t[0] ^= rcon;
            rcon = gmul(rcon, 2);
            let mut next = [0u8; 16];
            for i in 0..16 {
                let before = if i < 4 { t[i] } else { next[i - 4] };
                next[i] = prev[i] ^ before;
            }
            round[r] = next;
        }
        Aes128 { round }
    }

    fn add(s: &mut [u8; 16], k: &[u8; 16]) {
        for (s, k) in s.iter_mut().zip(k) {
            *s ^= k;
        }
    }

    /// Byte `r + 4c` of the state is row `r`, column `c`.
    fn shift_rows(s: &mut [u8; 16], inverse: bool) {
        let old = *s;
        for r in 1..4 {
            for c in 0..4 {
                let from = if inverse { (c + 4 - r) % 4 } else { (c + r) % 4 };
                s[r + 4 * c] = old[r + 4 * from];
            }
        }
    }

    fn mix_columns(s: &mut [u8; 16], m: [u8; 4]) {
        for c in 0..4 {
            let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
            for r in 0..4 {
                s[4 * c + r] = (0..4).fold(0, |v, k| v ^ gmul(a[k], m[(k + 4 - r) % 4]));
            }
        }
    }

    pub fn encrypt(&self, block: &mut [u8; 16]) {
        Self::add(block, &self.round[0]);
        for (r, key) in self.round.iter().enumerate().skip(1) {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            Self::shift_rows(block, false);
            if r != 10 {
                Self::mix_columns(block, [2, 3, 1, 1]);
            }
            Self::add(block, key);
        }
    }

    pub fn decrypt(&self, block: &mut [u8; 16]) {
        Self::add(block, &self.round[10]);
        for r in (0..10).rev() {
            Self::shift_rows(block, true);
            for b in block.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
            Self::add(block, &self.round[r]);
            if r != 0 {
                Self::mix_columns(block, [14, 11, 13, 9]);
            }
        }
    }
}

/// CCM's length field (L) is 2 bytes and its tag (M) 8, as CCMP uses it.
const TAG: usize = 8;

/// The CBC-MAC of the message, under the CCM formatting for `nonce`, `aad`
/// and `data`, before it is encrypted.
fn cbc_mac(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], data: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[0] = (if aad.is_empty() { 0 } else { 0x40 }) | ((TAG as u8 - 2) / 2) << 3 | 1;
    x[1..14].copy_from_slice(nonce);
    x[14..].copy_from_slice(&(data.len() as u16).to_be_bytes());
    aes.encrypt(&mut x);
    let absorb =|x: &mut [u8; 16], bytes: &mut dyn Iterator<Item = u8>| {
        let mut i = 0;
        let mut any = false;
        for b in bytes {
            x[i] ^= b;
            i += 1;
            any = true;
            if i == 16 {
                aes.encrypt(x);
                i = 0;
                any = false;
            }
        }
        if any {
            aes.encrypt(x);
        }
    };
    if !aad.is_empty() {
        let len = (aad.len() as u16).to_be_bytes();
        absorb(&mut x, &mut len.iter().chain(aad).copied());
    }
    absorb(&mut x, &mut data.iter().copied());
    x
}

/// CCM's counter block `i` for `nonce`, encrypted.
fn keystream(aes: &Aes128, nonce: &[u8; 13], i: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 1;
    a[1..14].copy_from_slice(nonce);
    a[14..].copy_from_slice(&i.to_be_bytes());
    aes.encrypt(&mut a);
    a
}

fn ctr(aes: &Aes128, nonce: &[u8; 13], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let s = keystream(aes, nonce, i as u16 + 1);
        for (d, s) in chunk.iter_mut().zip(s) {
            *d ^= s;
        }
    }
}

/// Encrypts `data` in place under CCM and returns its 8-byte tag.
pub fn ccm_seal(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], data: &mut [u8]) -> [u8; TAG] {
    let t = cbc_mac(aes, nonce, aad, data);
    ctr(aes, nonce, data);
    let s0 = keystream(aes, nonce, 0);
    core::array::from_fn(|i| t[i] ^ s0[i])
}

/// Decrypts `data` in place under CCM if `tag` is right for it; if not,
/// leaves it as it was and returns false.
pub fn ccm_open(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], data: &mut [u8], tag: &[u8; TAG]) -> bool {
    ctr(aes, nonce, data);
    let t = cbc_mac(aes, nonce, aad, data);
    let s0 = keystream(aes, nonce, 0);
    let diff = (0..TAG).fold(0, |d, i| d | (t[i] ^ s0[i] ^ tag[i]));
    if diff != 0 {
        ctr(aes, nonce, data);
        return false;
    }
    true
}

const WRAP_IV: [u8; 8] = [0xa6; 8];

/// AES key wrap of `data` (a multiple of 8 bytes, 16 or more) under `kek`
/// into `out`, 8 bytes longer.
pub fn key_wrap(kek: &[u8; 16], data: &[u8], out: &mut [u8]) {
    let aes = Aes128::new(kek);
    let n = data.len() / 8;
    out[..8].copy_from_slice(&WRAP_IV);
    out[8..8 + data.len()].copy_from_slice(data);
    for j in 0..6 {
        for i in 1..=n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&out[..8]);
            b[8..].copy_from_slice(&out[8 * i..8 * i + 8]);
            aes.encrypt(&mut b);
            let t = (n * j + i) as u64;
            for (k, v) in t.to_be_bytes().iter().enumerate() {
                b[k] ^= v;
            }
            out[..8].copy_from_slice(&b[..8]);
            out[8 * i..8 * i + 8].copy_from_slice(&b[8..]);
        }
    }
}

/// Unwraps `wrapped` (24 bytes or more) under `kek` into `out`, 8 bytes
/// shorter, if its integrity check holds.
pub fn key_unwrap(kek: &[u8; 16], wrapped: &[u8], out: &mut [u8]) -> bool {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 || out.len() < wrapped.len() - 8 {
        return false;
    }
    let aes = Aes128::new(kek);
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    out[..8 * n].copy_from_slice(&wrapped[8..]);
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let t = (n * j + i) as u64;
            let mut b = [0u8; 16];
            for (k, v) in t.to_be_bytes().iter().enumerate() {
                b[k] = a[k] ^ v;
            }
            b[8..].copy_from_slice(&out[8 * (i - 1)..8 * i]);
            aes.decrypt(&mut b);
            a.copy_from_slice(&b[..8]);
            out[8 * (i - 1)..8 * i].copy_from_slice(&b[8..]);
        }
    }
    a == WRAP_IV
}
