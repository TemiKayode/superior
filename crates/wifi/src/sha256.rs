//! What WPA3 builds on SHA-256 (from `superior_objects::crypto`):
//! HMAC-SHA256 (RFC 2104) and 802.11's key derivation function
//! (12.7.1.6.2), which SAE and the SAE key hierarchy use where WPA2 used
//! the SHA-1 PRF.

use superior_objects::crypto::sha2::Sha256;

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

/// KDF-SHA256-`out.len()·8` (K, label, context): HMAC-SHA256 under `key`
/// of a 16-bit little-endian counter from 1, the label, the context and
/// the length in bits (16-bit little-endian), as many blocks as needed.
pub fn kdf_sha256(key: &[u8], label: &[u8], context: &[&[u8]], out: &mut [u8]) {
    let bits = ((out.len() * 8) as u16).to_le_bytes();
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let counter = (i as u16 + 1).to_le_bytes();
        let mut parts: [&[u8]; 8] = [&[]; 8];
        parts[0] = &counter;
        parts[1] = label;
        let n = context.len().min(5);
        parts[2..2 + n].copy_from_slice(&context[..n]);
        parts[2 + n] = &bits;
        let block = hmac_sha256(key, &parts[..3 + n]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}
