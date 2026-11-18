//! What WPA2 builds on AES-128 (`superior_objects::crypto::aes`): CCM
//! (RFC 3610), the mode CCMP encrypts and authenticates frames with, and
//! AES key wrap (RFC 3394), which carries the group key in the handshake.

pub use superior_objects::crypto::aes::Aes128;

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

/// AES-CMAC (RFC 4493) of `data` under `key`: the MIC of EAPOL-Key frames
/// under SAE's key hierarchy.
pub fn cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let aes = Aes128::new(key);
    let dbl = |b: [u8; 16]| {
        let v = u128::from_be_bytes(b);
        ((v << 1) ^ if v >> 127 == 1 { 0x87 } else { 0 }).to_be_bytes()
    };
    let mut l = [0u8; 16];
    aes.encrypt(&mut l);
    let k1 = dbl(l);
    let k2 = dbl(k1);
    let blocks = data.len().div_ceil(16).max(1);
    let mut x = [0u8; 16];
    for i in 0..blocks {
        let chunk = &data[i * 16..data.len().min(i * 16 + 16)];
        let mut b = [0u8; 16];
        b[..chunk.len()].copy_from_slice(chunk);
        if i == blocks - 1 {
            let sub = if chunk.len() == 16 {
                k1
            } else {
                b[chunk.len()] = 0x80;
                k2
            };
            for j in 0..16 {
                b[j] ^= sub[j];
            }
        }
        for j in 0..16 {
            x[j] ^= b[j];
        }
        aes.encrypt(&mut x);
    }
    x
}

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
