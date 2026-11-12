//! The boot bundle: named files packed into one image, which the kernel
//! maps read-only into the Component Manager (the root task). It holds the
//! component manifest and every component's executable.
//!
//! Layout, all integers little-endian:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `SUPBNDL1` |
//! | 8 | 4 | entry count |
//! | 12 | 4 | reserved, 0 |
//! | 16 | 40 × count | entries: name (32 bytes, NUL-padded), offset (4), length (4) |
//! | ... | | file data; each offset is from the start of the bundle |
//!
//! A signed bundle (what the kernel boots) is a bundle followed by a
//! trailer of [`TRAILER`] bytes: magic `SUPSIG01` (8), the bundle's
//! version (8; rollback protection compares it), and an Ed25519 signature
//! (64) of everything before the signature. Its measurement is the
//! SHA-256 of all of it, signature included.

pub const MAGIC: &[u8; 8] = b"SUPBNDL1";
pub const HEADER: usize = 16;
pub const ENTRY: usize = 40;
pub const NAME_MAX: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    BadMagic,
    Truncated,
    /// An entry's name is not UTF-8, or its data lies outside the bundle.
    BadEntry(usize),
}

/// A parsed bundle, borrowing its bytes.
#[derive(Clone, Copy, Debug)]
pub struct Bundle<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> Bundle<'a> {
    /// Checks the header and every entry.
    pub fn parse(bytes: &'a [u8]) -> Result<Bundle<'a>, BundleError> {
        if bytes.len() < HEADER {
            return Err(BundleError::Truncated);
        }
        if &bytes[..8] != MAGIC {
            return Err(BundleError::BadMagic);
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let table_end = count
            .checked_mul(ENTRY)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or(BundleError::Truncated)?;
        if bytes.len() < table_end {
            return Err(BundleError::Truncated);
        }
        let b = Bundle { bytes, count };
        for i in 0..count {
            b.entry(i).ok_or(BundleError::BadEntry(i))?;
        }
        Ok(b)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Entry `i`: its name and data.
    pub fn entry(&self, i: usize) -> Option<(&'a str, &'a [u8])> {
        if i >= self.count {
            return None;
        }
        let e = &self.bytes[HEADER + i * ENTRY..HEADER + (i + 1) * ENTRY];
        let name_len = e[..NAME_MAX]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(NAME_MAX);
        let name = core::str::from_utf8(&e[..name_len]).ok()?;
        let off = u32::from_le_bytes(e[32..36].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(e[36..40].try_into().unwrap()) as usize;
        let data = self.bytes.get(off..off.checked_add(len)?)?;
        Some((name, data))
    }

    /// The data of the entry called `name`.
    pub fn get(&self, name: &str) -> Option<&'a [u8]> {
        (0..self.count)
            .filter_map(|i| self.entry(i))
            .find(|(n, _)| *n == name)
            .map(|(_, d)| d)
    }
}

pub const SIG_MAGIC: &[u8; 8] = b"SUPSIG01";
pub const TRAILER: usize = 8 + 8 + 64;

/// A signed bundle, split into its parts; nothing checked yet.
#[derive(Clone, Copy, Debug)]
pub struct Signed<'a> {
    /// The bundle itself.
    pub payload: &'a [u8],
    pub version: u64,
    pub signature: &'a [u8; 64],
    /// What the signature covers: the bundle, the magic and the version.
    signed: &'a [u8],
    all: &'a [u8],
}

impl<'a> Signed<'a> {
    /// Splits `bytes` into bundle and trailer; `None` without a trailer.
    pub fn split(bytes: &'a [u8]) -> Option<Signed<'a>> {
        let t = bytes.len().checked_sub(TRAILER)?;
        if &bytes[t..t + 8] != SIG_MAGIC {
            return None;
        }
        Some(Signed {
            payload: &bytes[..t],
            version: u64::from_le_bytes(bytes[t + 8..t + 16].try_into().unwrap()),
            signature: bytes[t + 16..].try_into().unwrap(),
            signed: &bytes[..t + 16],
            all: bytes,
        })
    }

    /// Whether `key` signed it.
    pub fn verify(&self, key: &[u8; 32]) -> bool {
        crate::crypto::ed25519::verify(key, &[self.signed], self.signature)
    }

    /// Its measurement: the SHA-256 of all of it.
    pub fn measure(&self) -> [u8; 32] {
        crate::crypto::sha2::sha256(self.all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let mut off = HEADER + files.len() * ENTRY;
        for (name, data) in files {
            let mut n = [0u8; NAME_MAX];
            n[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&n);
            out.extend_from_slice(&(off as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            off += data.len();
        }
        for (_, data) in files {
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn finds_entries_by_name() {
        let bytes = build(&[("manifest", b"component a\n"), ("echo", b"\x7fELF...")]);
        let b = Bundle::parse(&bytes).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b.get("manifest"), Some(&b"component a\n"[..]));
        assert_eq!(b.get("echo"), Some(&b"\x7fELF..."[..]));
        assert_eq!(b.get("shell"), None);
    }

    #[test]
    fn rejects_bad_bundles() {
        assert_eq!(Bundle::parse(b"short").unwrap_err(), BundleError::Truncated);
        let mut bytes = build(&[("a", b"xyz")]);
        bytes[0] = b'X';
        assert_eq!(Bundle::parse(&bytes).unwrap_err(), BundleError::BadMagic);
        // An entry pointing past the end.
        let mut bytes = build(&[("a", b"xyz")]);
        let n = bytes.len();
        bytes.truncate(n - 1);
        assert_eq!(Bundle::parse(&bytes).unwrap_err(), BundleError::BadEntry(0));
        // A count larger than the table.
        let mut bytes = build(&[]);
        bytes[8] = 3;
        assert_eq!(Bundle::parse(&bytes).unwrap_err(), BundleError::Truncated);
    }

    fn sign(bundle: &[u8], version: u64, key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut out = bundle.to_vec();
        out.extend_from_slice(SIG_MAGIC);
        out.extend_from_slice(&version.to_le_bytes());
        let signature = key.sign(&out).to_bytes();
        out.extend_from_slice(&signature);
        out
    }

    #[test]
    fn signed_bundles() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let public = key.verifying_key().to_bytes();
        let bundle = build(&[("manifest", b"component a
")]);
        let bytes = sign(&bundle, 7, &key);
        let s = Signed::split(&bytes).unwrap();
        assert_eq!((s.payload, s.version), (&bundle[..], 7));
        assert!(s.verify(&public));
        assert_eq!(s.measure(), crate::crypto::sha2::sha256(&bytes));
        assert!(Bundle::parse(s.payload).is_ok());
        // Another key's signature, a changed byte or version: refused.
        let other = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        assert!(!s.verify(&other.verifying_key().to_bytes()));
        let mut changed = bytes.clone();
        changed[HEADER + ENTRY] ^= 1;
        assert!(!Signed::split(&changed).unwrap().verify(&public));
        let mut changed = bytes.clone();
        changed[bundle.len() + 8] = 8;
        assert!(!Signed::split(&changed).unwrap().verify(&public));
        // No trailer at all.
        assert!(Signed::split(&bundle).is_none());
    }
}
