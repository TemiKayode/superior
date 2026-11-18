//! The cryptography the trust chain needs: SHA-256 for measurements and
//! Ed25519 (with SHA-512) to verify signatures, and for TLS 1.3 X25519,
//! HMAC and HKDF on SHA-256, and AES-128-GCM. Written here, `no_std` and
//! allocation-free, so the kernel can use it before anything else runs;
//! checked against the published test vectors and, on the host, against
//! ed25519-dalek.

pub mod aes;
pub mod ed25519;
pub mod gcm;
pub mod hkdf;
pub mod sha2;
pub mod x25519;
