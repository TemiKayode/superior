//! A/B system updates: where the two system slots are on the system disk,
//! the boot record that says which to boot, and the choice itself.
//!
//! The kernel boots the boot bundle built into it (verified, see
//! [`crate::bundle::Signed`]): the drivers that reach the disk. The
//! Component Manager then reads the system bundle from slot A or B, checks
//! its signature with the key in the boot bundle and its version against
//! the record's rollback floor, and starts it. Layout, in 512-byte sectors:
//!
//! | Sector | What |
//! | --- | --- |
//! | 0 | the boot record ([`Record`]) |
//! | [`SLOT_FIRST`]`[s]` | slot `s`: a header sector (magic `SUPSLOT1`, the bundle's length), then the signed bundle |
//!
//! Each slot spans [`SLOT_SECTORS`]. A new system is written to the slot
//! not booted, checked, and marked pending with one try; the next boot
//! tries it, using up the try. If the new system confirms it came up, it
//! becomes the active slot and its version the rollback floor; if not,
//! the boot after goes back to the active slot and drops the update.

use crate::crypto::sha2::sha256;

pub const SECTOR: usize = 512;
pub const RECORD_SECTOR: u64 = 0;
/// Each slot's first sector, and its size: 2 MiB each.
pub const SLOT_FIRST: [u64; 2] = [2048, 2048 + SLOT_SECTORS];
pub const SLOT_SECTORS: u64 = 4096;
/// The largest bundle a slot holds (its header takes a sector).
pub const SLOT_BYTES: usize = (SLOT_SECTORS as usize - 1) * SECTOR;
pub const SLOT_MAGIC: &[u8; 8] = b"SUPSLOT1";
pub const RECORD_MAGIC: &[u8; 8] = b"SUPABREC";
/// Tries a pending slot gets.
pub const TRIES: u8 = 1;

pub const fn slot_name(s: u8) -> char {
    if s == 0 { 'A' } else { 'B' }
}

/// A slot's header sector: the bundle's length, if the slot holds one
/// that fits.
pub fn slot_length(header: &[u8; SECTOR]) -> Option<usize> {
    if &header[..8] != SLOT_MAGIC {
        return None;
    }
    let len = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    (len > 0 && len <= SLOT_BYTES).then_some(len)
}

/// The header sector for a bundle of `len` bytes.
pub fn slot_header(len: usize) -> [u8; SECTOR] {
    let mut h = [0; SECTOR];
    h[..8].copy_from_slice(SLOT_MAGIC);
    h[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    h
}

/// The boot record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The slot that last came up and confirmed it.
    pub active: u8,
    /// A slot written since, and the tries it has left.
    pub pending: Option<(u8, u8)>,
    /// No system older than this version boots (the newest one confirmed).
    pub floor: u64,
}

impl Default for Record {
    /// A disk never updated: slot A, nothing pending, no floor.
    fn default() -> Self {
        Record { active: 0, pending: None, floor: 0 }
    }
}

impl Record {
    /// Reads the record sector; a blank or damaged one (bad magic or
    /// checksum) gives the default.
    pub fn decode(b: &[u8; SECTOR]) -> Record {
        let sum = sha256(&b[..32]);
        if &b[..8] != RECORD_MAGIC || b[32..40] != sum[..8] || b[8] > 1 {
            return Record::default();
        }
        let pending = match (b[9], b[10]) {
            (s @ (0 | 1), tries) if s != b[8] => Some((s, tries)),
            _ => None,
        };
        Record {
            active: b[8],
            pending,
            floor: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        }
    }

    pub fn encode(&self) -> [u8; SECTOR] {
        let mut b = [0; SECTOR];
        b[..8].copy_from_slice(RECORD_MAGIC);
        b[8] = self.active;
        let (s, tries) = self.pending.unwrap_or((0xff, 0));
        b[9] = s;
        b[10] = tries;
        b[16..24].copy_from_slice(&self.floor.to_le_bytes());
        let sum = sha256(&b[..32]);
        b[32..40].copy_from_slice(&sum[..8]);
        b
    }
}

/// What to boot, from a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Slots to try in order; the first that holds a good system boots.
    pub order: [Option<u8>; 2],
    /// The record to write before booting (a try used up, a failed update
    /// dropped), if it changed.
    pub write: Option<Record>,
    /// An update that used its tries without confirming, dropped now.
    pub dropped: Option<u8>,
}

/// The choice: a pending slot with tries left first (using one up), the
/// active slot after it; a pending slot out of tries is dropped; with
/// nothing pending, the active slot, then the other as a last resort.
pub fn plan(r: Record) -> Plan {
    match r.pending {
        Some((p, tries)) if tries > 0 => Plan {
            order: [Some(p), Some(r.active)],
            write: Some(Record { pending: Some((p, tries - 1)), ..r }),
            dropped: None,
        },
        Some((p, _)) => Plan {
            order: [Some(r.active), None],
            write: Some(Record { pending: None, ..r }),
            dropped: Some(p),
        },
        None => Plan { order: [Some(r.active), Some(1 - r.active)], write: None, dropped: None },
    }
}

/// The record once slot `booted`, version `version`, has confirmed it
/// came up: it becomes the active slot, and its version the floor.
pub fn confirmed(r: Record, booted: u8, version: u64) -> Record {
    let pending = r.pending.filter(|(p, _)| *p != booted);
    Record { active: booted, pending, floor: r.floor.max(version) }
}

/// The record with an update written to slot `s` (not the one booted).
pub fn staged(r: Record, s: u8) -> Record {
    Record { pending: Some((s, TRIES)), ..r }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip_and_damage() {
        let r = Record { active: 1, pending: Some((0, 1)), floor: 7 };
        let mut b = r.encode();
        assert_eq!(Record::decode(&b), r);
        b[16] ^= 1;
        assert_eq!(Record::decode(&b), Record::default(), "checksum");
        assert_eq!(Record::decode(&[0; SECTOR]), Record::default(), "blank");
        let none = Record { active: 0, pending: None, floor: 3 };
        assert_eq!(Record::decode(&none.encode()), none);
    }

    #[test]
    fn an_update_that_confirms() {
        // Slot A running, B written and staged.
        let r = staged(Record::default(), 1);
        let p = plan(r);
        assert_eq!(p.order, [Some(1), Some(0)]);
        let r = p.write.unwrap();
        assert_eq!(r.pending, Some((1, 0)));
        // B comes up and confirms: active, floor raised, nothing pending.
        let r = confirmed(r, 1, 4);
        assert_eq!(r, Record { active: 1, pending: None, floor: 4 });
        assert_eq!(plan(r), Plan { order: [Some(1), Some(0)], write: None, dropped: None });
    }

    #[test]
    fn an_update_that_never_confirms() {
        let r = plan(staged(Record { active: 0, pending: None, floor: 2 }, 1)).write.unwrap();
        // B booted but never confirmed: back to A, B dropped.
        let p = plan(r);
        assert_eq!(p.order, [Some(0), None]);
        assert_eq!(p.dropped, Some(1));
        assert_eq!(p.write, Some(Record { active: 0, pending: None, floor: 2 }));
    }

    #[test]
    fn slot_headers() {
        assert_eq!(slot_length(&slot_header(1234)), Some(1234));
        assert_eq!(slot_length(&slot_header(SLOT_BYTES + 1)), None);
        assert_eq!(slot_length(&[0; SECTOR]), None);
    }
}
