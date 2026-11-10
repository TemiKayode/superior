//! Internet protocol pieces for the network server (`user/net`), kept
//! apart so host tests can check them: fragment reassembly (IPv4's and
//! IPv6's), checksums, and TCP ([`tcp`]). Addresses are 128 bits, IPv4
//! ones mapped into IPv6 ([`mapped`]).

#![no_std]

pub mod tcp;

/// IPv4 address `ip` as the server keeps every address: an IPv4-mapped
/// IPv6 address, `::ffff:a.b.c.d` (RFC 4291).
pub const fn mapped(ip: u32) -> u128 {
    0xffff_0000_0000 | ip as u128
}

/// The IPv4 address in `a`, if it is one (as in [`mapped`]).
pub const fn ipv4(a: u128) -> Option<u32> {
    if a >> 32 == 0xffff { Some(a as u32) } else { None }
}

/// The Internet checksum's running sum of `b` (RFC 1071); `b` must start
/// at an even offset of what is summed.
pub fn sum(mut acc: u32, b: &[u8]) -> u32 {
    for pair in b.chunks(2) {
        acc = acc.wrapping_add((pair[0] as u32) << 8 | pair.get(1).copied().unwrap_or(0) as u32);
    }
    acc
}

/// The checksum from a running sum: folded and complemented.
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The sum of the pseudo-header that UDP, TCP and ICMPv6 checksums cover:
/// IPv4's (RFC 768) when both addresses are IPv4, else IPv6's (RFC 8200
/// 8.1).
pub fn pseudo(src: u128, dst: u128, proto: u8, len: usize) -> u32 {
    if let (Some(s), Some(d)) = (ipv4(src), ipv4(dst)) {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&s.to_be_bytes());
        b[4..8].copy_from_slice(&d.to_be_bytes());
        b[9] = proto;
        b[10..12].copy_from_slice(&(len as u16).to_be_bytes());
        return sum(0, &b);
    }
    let mut b = [0u8; 40];
    b[0..16].copy_from_slice(&src.to_be_bytes());
    b[16..32].copy_from_slice(&dst.to_be_bytes());
    b[32..36].copy_from_slice(&(len as u32).to_be_bytes());
    b[39] = proto;
    sum(0, &b)
}

/// The largest IP payload reassembled: a UDP datagram of the largest
/// size (65,507 bytes, `net::MAX_DATAGRAM`) with its 8-byte header,
/// rounded up to whole 8-byte units.
pub const MAX_REASSEMBLED: usize = 65_520;
const UNITS: usize = MAX_REASSEMBLED.div_ceil(8);

/// What identifies one datagram's fragments (RFC 791, RFC 8200): source,
/// destination (as in [`mapped`] for IPv4), protocol and identification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Key {
    pub src: u128,
    pub dst: u128,
    pub proto: u8,
    /// The identification: 16 bits in IPv4, 32 in IPv6's fragment header.
    pub id: u32,
}

/// One datagram being put together. All zeros is an unused slot.
struct Partial {
    used: bool,
    key: Key,
    /// When its first fragment arrived.
    started: u64,
    /// The payload's length, once the last fragment has arrived (`ended`).
    ended: bool,
    total: usize,
    /// Which 8-byte units have arrived.
    have: [u64; UNITS.div_ceil(64)],
    data: [u8; MAX_REASSEMBLED],
}

impl Partial {
    fn has(&self, u: usize) -> bool {
        self.have[u / 64] & 1 << (u % 64) != 0
    }
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
///
/// Each slot holds a whole datagram (64 KiB), so the network server keeps
/// this in pages of its own rather than in its image: all zeros is an
/// empty reassembler ([`Reassembler::init`]).
pub struct Reassembler<const N: usize> {
    slots: [Partial; N],
    /// Datagrams completed, and dropped (malformed, too big, pushed out or
    /// timed out).
    pub completed: u64,
    pub dropped: u64,
}

impl<const N: usize> Reassembler<N> {
    /// An empty reassembler in the memory at `p`.
    ///
    /// # Safety
    /// `p` must be valid for writes of a `Reassembler<N>` and aligned.
    pub unsafe fn init(p: *mut Self) -> &'static mut Self {
        // SAFETY: the caller's promise; all zeros is a valid, empty value
        // (bools false, numbers 0).
        unsafe {
            p.write_bytes(0, 1);
            &mut *p
        }
    }

    /// Datagrams in progress.
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|p| p.used).count()
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
        let p = &mut self.slots[slot];
        let bad = bad
            || match (p.ended, more) {
                // Nothing may lie past the end, and there is one end.
                (true, true) => end > p.total,
                (true, false) => end != p.total,
                // No unit already received may lie past this end.
                (false, false) => (end.div_ceil(8)..UNITS).any(|u| p.has(u)),
                (false, true) => false,
            };
        if bad {
            p.used = false;
            self.dropped += 1;
            return Outcome::Dropped;
        }
        p.data[offset..end].copy_from_slice(data);
        for u in offset / 8..end.div_ceil(8) {
            p.have[u / 64] |= 1 << (u % 64);
        }
        if !more {
            p.ended = true;
            p.total = end;
        }
        if !p.ended || (0..p.total.div_ceil(8)).any(|u| !p.has(u)) {
            return Outcome::Pending;
        }
        let total = p.total;
        out[..total].copy_from_slice(&p.data[..total]);
        p.used = false;
        self.completed += 1;
        Outcome::Complete(total)
    }

    /// Drops every datagram whose first fragment came more than `timeout`
    /// before `now`; returns how many.
    pub fn expire(&mut self, now: u64, timeout: u64) -> usize {
        let mut n = 0;
        for p in &mut self.slots {
            if p.used && now.saturating_sub(p.started) > timeout {
                p.used = false;
                n += 1;
            }
        }
        self.dropped += n as u64;
        n
    }

    /// The slot for `key`'s datagram: its own, a free one, or the oldest
    /// one's (that datagram is dropped). Set up in place: only the record
    /// of which units arrived is cleared, not the data.
    fn slot(&mut self, now: u64, key: Key) -> usize {
        if let Some(i) = (0..N).find(|&i| self.slots[i].used && self.slots[i].key == key) {
            return i;
        }
        let i = (0..N).find(|&i| !self.slots[i].used).unwrap_or_else(|| {
            self.dropped += 1;
            (0..N).min_by_key(|&i| self.slots[i].started).unwrap()
        });
        let p = &mut self.slots[i];
        p.used = true;
        p.key = key;
        p.started = now;
        p.ended = false;
        p.total = 0;
        p.have = [0; UNITS.div_ceil(64)];
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

    /// A reassembler on the heap (each is N times 64 KiB).
    fn new<const N: usize>() -> std::boxed::Box<Reassembler<N>> {
        let layout = std::alloc::Layout::new::<Reassembler<N>>();
        // SAFETY: the layout is the type's; init zeroes it, which is a
        // valid empty reassembler, and the box takes the allocation.
        unsafe {
            let p = std::alloc::alloc(layout) as *mut Reassembler<N>;
            Reassembler::init(p);
            std::boxed::Box::from_raw(p)
        }
    }

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
        let mut r = new::<4>();
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
        let mut r = new::<4>();
        let mut out = [0u8; 4096];
        let got = feed(&mut r, &f, &mut out);
        assert_eq!(got.last(), Some(&Outcome::Complete(3000)));
        assert_eq!(&out[..3000], &p[..]);
    }

    #[test]
    fn overlapping_pieces() {
        let p = payload(2000);
        let f = [(0, true, &p[0..1200]), (800, true, &p[800..1600]), (1600, false, &p[1600..])];
        let mut r = new::<4>();
        let mut out = [0u8; 4096];
        assert_eq!(feed(&mut r, &f, &mut out)[2], Outcome::Complete(2000));
        assert_eq!(&out[..2000], &p[..]);
    }

    #[test]
    fn missing_piece_waits_then_expires() {
        let p = payload(3000);
        let f = split(&p, 1480);
        let mut r = new::<4>();
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
        let mut r = new::<4>();
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
        let mut r = new::<4>();
        let mut out = std::vec![0u8; 70_000];
        assert_eq!(r.add(0, KEY, 0, true, &p[..1480], &mut out), Outcome::Pending);
        // Past the largest datagram: the whole datagram goes.
        assert_eq!(r.add(0, KEY, 65_000, false, &p[..600], &mut out), Outcome::Dropped);
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
    fn the_largest_datagram_in_any_order() {
        // A UDP datagram of 65,507 bytes with its header, in 1480-byte
        // pieces (as IPv4 sends it), shuffled, two of them twice.
        let p = payload(65_515);
        let mut f = split(&p, 1480);
        let n = f.len();
        for i in 0..n {
            f.swap(i, (i * 17 + 5) % n);
        }
        f.push(f[3]);
        f.insert(10, f[20]);
        let mut r = new::<4>();
        let mut out = std::vec![0u8; MAX_REASSEMBLED];
        let got = feed(&mut r, &f, &mut out);
        let done: Vec<_> = got.iter().filter(|o| **o == Outcome::Complete(65_515)).collect();
        assert_eq!(done.len(), 1);
        assert_eq!(&out[..65_515], &p[..]);
        // The duplicate after completion starts a datagram of its own.
        assert_eq!(r.completed, 1);
        // A slot used for a big datagram is clean for the next: a small
        // one after it in the same slot completes with its own bytes.
        let q = payload(2000);
        let k = Key { id: 99, ..KEY };
        let mut r = new::<1>();
        for (o, m, d) in split(&p, 1480).into_iter().take(5) {
            r.add(0, KEY, o, m, d, &mut out);
        }
        assert_eq!(r.add(1, k, 1480, false, &q[1480..], &mut out), Outcome::Pending);
        assert_eq!(r.add(1, k, 0, true, &q[..1480], &mut out), Outcome::Complete(2000));
        assert_eq!(&out[..2000], &q[..]);
    }

    #[test]
    fn full_table_pushes_out_the_oldest() {
        let p = payload(3000);
        let mut r = new::<2>();
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
