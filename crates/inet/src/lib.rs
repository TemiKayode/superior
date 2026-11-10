//! Internet protocol pieces for the network server (`user/net`), kept
//! apart so host tests can check them: IPv4 fragment reassembly and TCP
//! ([`tcp`]).

#![no_std]

pub mod tcp;

/// The largest IP payload reassembled (a UDP datagram of up to 4000 bytes
/// with its header, rounded up to whole 8-byte units).
pub const MAX_REASSEMBLED: usize = 4008;
const UNITS: usize = MAX_REASSEMBLED.div_ceil(8);

/// What identifies one datagram's fragments (RFC 791): source,
/// destination, protocol and identification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Key {
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub id: u16,
}

#[derive(Clone, Copy)]
struct Partial {
    key: Key,
    /// When its first fragment arrived.
    started: u64,
    /// The payload's length, once the last fragment has arrived.
    total: Option<usize>,
    /// Which 8-byte units have arrived.
    have: [u64; UNITS.div_ceil(64)],
    data: [u8; MAX_REASSEMBLED],
}

/// What happened to a fragment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Its datagram is whole: this many bytes were copied out.
    Complete(usize),
    /// Kept; more fragments are needed.
    Pending,
    /// Malformed or too big: it, and what had arrived of its datagram,
    /// are dropped.
    Dropped,
}

/// Reassembles up to `N` datagrams at once; when all are in progress, a
/// new one takes the place of the oldest.
pub struct Reassembler<const N: usize> {
    slots: [Option<Partial>; N],
    /// Datagrams completed, and dropped (malformed, too big, pushed out or
    /// timed out).
    pub completed: u64,
    pub dropped: u64,
}

impl<const N: usize> Default for Reassembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Reassembler<N> {
    pub const fn new() -> Self {
        Reassembler {
            slots: [None; N],
            completed: 0,
            dropped: 0,
        }
    }

    /// Datagrams in progress.
    pub fn pending(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Takes a fragment: its datagram's `key`, its byte `offset`, whether
    /// more fragments follow (`more`), and its `data`. When the datagram is
    /// whole, copies it to `out` and frees its slot.
    pub fn add(
        &mut self,
        now: u64,
        key: Key,
        offset: usize,
        more: bool,
        data: &[u8],
        out: &mut [u8],
    ) -> Outcome {
        let end = offset + data.len();
        let slot = self.slot(now, key);
        let bad = end > MAX_REASSEMBLED
            || end > out.len()
            || offset % 8 != 0
            // Every fragment but the last carries whole units.
            || (more && (data.is_empty() || data.len() % 8 != 0));
        let p = self.slots[slot].as_mut().unwrap();
        let bad = bad
            || match (p.total, more) {
                // Nothing may lie past the end, and there is one end.
                (Some(t), true) => end > t,
                (Some(t), false) => end != t,
                (None, false) => {
                    // No unit already received may lie past this end.
                    let last = end.div_ceil(8);
                    (last..UNITS).any(|u| p.have[u / 64] & 1 << (u % 64) != 0)
                }
                (None, true) => false,
            };
        if bad {
            self.slots[slot] = None;
            self.dropped += 1;
            return Outcome::Dropped;
        }
        p.data[offset..end].copy_from_slice(data);
        for u in offset / 8..end.div_ceil(8) {
            p.have[u / 64] |= 1 << (u % 64);
        }
        if !more {
            p.total = Some(end);
        }
        let Some(total) = p.total else {
            return Outcome::Pending;
        };
        if (0..total.div_ceil(8)).any(|u| p.have[u / 64] & 1 << (u % 64) == 0) {
            return Outcome::Pending;
        }
        out[..total].copy_from_slice(&p.data[..total]);
        self.slots[slot] = None;
        self.completed += 1;
        Outcome::Complete(total)
    }

    /// Drops every datagram whose first fragment came more than `timeout`
    /// before `now`; returns how many.
    pub fn expire(&mut self, now: u64, timeout: u64) -> usize {
        let mut n = 0;
        for s in &mut self.slots {
            if s.is_some_and(|p| now.saturating_sub(p.started) > timeout) {
                *s = None;
                n += 1;
            }
        }
        self.dropped += n as u64;
        n
    }

    /// The slot for `key`'s datagram: its own, a free one, or the oldest
    /// one's (that datagram is dropped).
    fn slot(&mut self, now: u64, key: Key) -> usize {
        if let Some(i) = (0..N).find(|&i| self.slots[i].is_some_and(|p| p.key == key)) {
            return i;
        }
        let i = (0..N).find(|&i| self.slots[i].is_none()).unwrap_or_else(|| {
            self.dropped += 1;
            (0..N)
                .min_by_key(|&i| self.slots[i].map_or(0, |p| p.started))
                .unwrap()
        });
        self.slots[i] = Some(Partial {
            key,
            started: now,
            total: None,
            have: [0; UNITS.div_ceil(64)],
            data: [0; MAX_REASSEMBLED],
        });
        i
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const KEY: Key = Key {
        src: 0x0a00_0302,
        dst: 0x0a00_031e,
        proto: 17,
        id: 7,
    };

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    /// Splits `p` into fragments of at most `size` bytes (a multiple of 8):
    /// (offset, more, data).
    fn split(p: &[u8], size: usize) -> Vec<(usize, bool, &[u8])> {
        let mut v = Vec::new();
        let mut at = 0;
        while at < p.len() {
            let end = (at + size).min(p.len());
            v.push((at, end < p.len(), &p[at..end]));
            at = end;
        }
        v
    }

    fn feed(r: &mut Reassembler<4>, frags: &[(usize, bool, &[u8])], out: &mut [u8]) -> Vec<Outcome> {
        frags
            .iter()
            .map(|&(o, m, d)| r.add(0, KEY, o, m, d, out))
            .collect()
    }

    #[test]
    fn in_order() {
        let p = payload(4008);
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 4096];
        let got = feed(&mut r, &split(&p, 1480), &mut out);
        assert_eq!(got.last(), Some(&Outcome::Complete(4008)));
        assert!(got[..got.len() - 1].iter().all(|o| *o == Outcome::Pending));
        assert_eq!(&out[..4008], &p[..]);
        assert_eq!((r.pending(), r.completed), (0, 1));
    }

    #[test]
    fn out_of_order_and_duplicates() {
        let p = payload(3000);
        let mut f = split(&p, 1000 / 8 * 8);
        f.reverse();
        f.insert(1, f[0]);
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 4096];
        let got = feed(&mut r, &f, &mut out);
        assert_eq!(got.last(), Some(&Outcome::Complete(3000)));
        assert_eq!(&out[..3000], &p[..]);
    }

    #[test]
    fn overlapping_pieces() {
        let p = payload(2000);
        let f = [(0, true, &p[0..1200]), (800, true, &p[800..1600]), (1600, false, &p[1600..])];
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 4096];
        assert_eq!(feed(&mut r, &f, &mut out)[2], Outcome::Complete(2000));
        assert_eq!(&out[..2000], &p[..]);
    }

    #[test]
    fn missing_piece_waits_then_expires() {
        let p = payload(3000);
        let f = split(&p, 1480);
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 4096];
        assert_eq!(r.add(10, KEY, f[0].0, f[0].1, f[0].2, &mut out), Outcome::Pending);
        assert_eq!(r.add(20, KEY, f[2].0, f[2].1, f[2].2, &mut out), Outcome::Pending);
        assert_eq!(r.expire(300, 500), 0);
        assert_eq!(r.expire(511, 500), 1);
        assert_eq!((r.pending(), r.dropped), (0, 1));
        // The late piece starts a datagram of its own, which never completes.
        assert_eq!(r.add(600, KEY, f[1].0, f[1].1, f[1].2, &mut out), Outcome::Pending);
    }

    #[test]
    fn interleaved_datagrams() {
        let (a, b) = (payload(2500), payload(1600));
        let kb = Key { id: 8, ..KEY };
        let (fa, fb) = (split(&a, 1480), split(&b, 1480));
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 4096];
        assert_eq!(r.add(0, KEY, fa[0].0, true, fa[0].2, &mut out), Outcome::Pending);
        assert_eq!(r.add(0, kb, fb[1].0, false, fb[1].2, &mut out), Outcome::Pending);
        assert_eq!(r.add(0, kb, fb[0].0, true, fb[0].2, &mut out), Outcome::Complete(1600));
        assert_eq!(&out[..1600], &b[..]);
        assert_eq!(r.add(0, KEY, fa[1].0, false, fa[1].2, &mut out), Outcome::Complete(2500));
        assert_eq!(&out[..2500], &a[..]);
    }

    #[test]
    fn too_big_or_malformed_is_dropped() {
        let p = payload(4100);
        let mut r = Reassembler::<4>::new();
        let mut out = [0u8; 8192];
        assert_eq!(r.add(0, KEY, 0, true, &p[..1480], &mut out), Outcome::Pending);
        // Past the largest datagram: the whole datagram goes.
        assert_eq!(r.add(0, KEY, 2960, false, &p[2960..], &mut out), Outcome::Dropped);
        assert_eq!(r.pending(), 0);
        // A middle piece not a whole number of units.
        assert_eq!(r.add(0, KEY, 0, true, &p[..100], &mut out), Outcome::Dropped);
        // Data past the end the last fragment gave.
        assert_eq!(r.add(0, KEY, 800, false, &p[800..1000], &mut out), Outcome::Pending);
        assert_eq!(r.add(0, KEY, 1000, true, &p[1000..1480], &mut out), Outcome::Dropped);
        // A second, different end.
        assert_eq!(r.add(0, KEY, 800, false, &p[800..1000], &mut out), Outcome::Pending);
        assert_eq!(r.add(0, KEY, 800, false, &p[800..1200], &mut out), Outcome::Dropped);
        // A last fragment ending before data already received.
        assert_eq!(r.add(0, KEY, 1480, true, &p[1480..2960], &mut out), Outcome::Pending);
        assert_eq!(r.add(0, KEY, 0, false, &p[..800], &mut out), Outcome::Dropped);
        assert_eq!(r.dropped, 5);
    }

    #[test]
    fn full_table_pushes_out_the_oldest() {
        let p = payload(3000);
        let mut r = Reassembler::<2>::new();
        let mut out = [0u8; 4096];
        for (t, id) in [(1, 1), (2, 2), (3, 3)] {
            let k = Key { id, ..KEY };
            assert_eq!(r.add(t, k, 0, true, &p[..1480], &mut out), Outcome::Pending);
        }
        assert_eq!((r.pending(), r.dropped), (2, 1));
        // Datagram 1 was pushed out: its last piece starts it over.
        let k1 = Key { id: 1, ..KEY };
        assert_eq!(r.add(4, k1, 1480, false, &p[1480..], &mut out), Outcome::Pending);
        // Datagram 3 is still there.
        let k3 = Key { id: 3, ..KEY };
        assert_eq!(r.add(5, k3, 1480, false, &p[1480..], &mut out), Outcome::Complete(3000));
    }
}
