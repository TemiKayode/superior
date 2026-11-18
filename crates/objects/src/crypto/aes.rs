//! AES-128 (FIPS 197), both ways: the block cipher Wi-Fi's CCMP and key
//! wrap and TLS's AES-128-GCM are built on.
//!
//! A table implementation: its timing depends on the data. Over a radio
//! link or a network an attacker cannot time it finely; a constant-time
//! one can replace it behind the same calls.

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
