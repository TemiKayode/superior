//! The cryptography the trust chain needs: SHA-256 for measurements and
//! Ed25519 (with SHA-512) to verify signatures. Written here, `no_std`
//! and allocation-free, so the kernel can use it before anything else
//! runs; checked against the published test vectors and, on the host,
//! against ed25519-dalek.

pub mod ed25519;
pub mod sha2;
