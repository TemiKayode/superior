//! The Memory Server's page bookkeeping (`user/memserver`), kept here so it
//! is tested on the host: against a model of the kernel, with random
//! sequences of requests, as the kernel's own IPC engine is.
//!
//! The server keeps one frame capability per page in its own CSpace, slots
//! [`FIRST_PAGE`] to `end`. A page it gives away is always reachable from
//! the original it keeps, so revoking the original takes back every copy
//! and every mapping. What it asks of the kernel is the [`Frames`] trait.
//!
//! Copy-on-write: [`Server::share`] makes a component's heap pages
//! read-only and shared; [`Server::clone`] maps them, read-only, at the same
//! addresses in another component, each mapping through a copy of the
//! page's original capability. A write faults, and [`Server::fault`] gives
//! the writer its own copy, or the frame itself once no one else maps it.
//! Each mapping is charged to its holder, so breaking the sharing never
//! needs more quota.

use crate::interfaces::{Status, mem};

/// The first slot holding a page; the ones below are the server's own.
pub const FIRST_PAGE: u64 = 8;
const PAGE: u64 = 4096;

/// What the server asks of the kernel. Slots are in the server's CSpace;
/// "lent" is the address space the current request lent it.
pub trait Frames {
    /// Makes a new, zeroed frame in empty slot `s`. False if the pool is
    /// spent.
    fn make(&mut self, s: u64) -> bool;
    /// Maps frame `s` at `va` in the lent address space.
    fn map_lent(&mut self, s: u64, va: u64, writable: bool) -> bool;
    /// Unmaps frame `s`, wherever it is mapped (nothing if it is not).
    fn unmap(&mut self, s: u64);
    /// Removes every capability derived from `s`, unmapping each.
    fn revoke(&mut self, s: u64);
    /// Empties slot `s` (unmapping it first).
    fn delete(&mut self, s: u64);
    /// Copies the capability in `from` into empty slot `to`, derived from
    /// it.
    fn copy_cap(&mut self, from: u64, to: u64) -> bool;
    /// Zeroes frame `s`, which must not be mapped.
    fn zero(&mut self, s: u64) -> bool;
    /// Copies frame `from` into frame `to`; neither may be mapped.
    fn copy_page(&mut self, from: u64, to: u64) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// Not made yet (or a slot a copy-on-write mapping gave back).
    Unmade,
    /// Made, zeroed, nobody's.
    Free,
    /// Mapped writable in the owner's heap at `va` (always an original).
    Heap(u16),
    /// Granted to the owner.
    Given(u16),
    /// Mapped read-only in the owner's heap at `va`, sharing the frame
    /// whose original is `base`. The slot is the original itself or a copy
    /// of it.
    Cow(u16),
    /// An original no one maps any more whose copies are still mapped.
    Backing,
    /// Could not be zeroed: never handed out again.
    Retired,
}

pub struct Server<F: Frames, const SLOTS: usize, const CLIENTS: usize> {
    pub frames: F,
    pages: [Page; SLOTS],
    /// Where a `Heap` or `Cow` slot is mapped.
    va: [u64; SLOTS],
    /// For a `Cow` slot: the slot of the frame's original.
    base: [u16; SLOTS],
    /// For an original: how many `Cow` slots map its frame.
    refs: [u16; SLOTS],
    /// Slots in use for pages: FIRST_PAGE..end.
    end: u64,
    /// Pages the pool can still make.
    pool_left: u64,
    used: [u64; CLIENTS],
}

impl<F: Frames, const SLOTS: usize, const CLIENTS: usize> Server<F, SLOTS, CLIENTS> {
    /// A server with slots `FIRST_PAGE..end` for pages and a pool that can
    /// make `pool` of them.
    pub fn new(frames: F, end: u64, pool: u64) -> Self {
        Server {
            frames,
            pages: [Page::Unmade; SLOTS],
            va: [0; SLOTS],
            base: [0; SLOTS],
            refs: [0; SLOTS],
            end: end.min(SLOTS as u64),
            pool_left: pool,
            used: [0; CLIENTS],
        }
    }

    pub fn slots(&self) -> core::ops::Range<u64> {
        FIRST_PAGE..self.end
    }

    pub fn page(&self, s: u64) -> Page {
        self.pages[s as usize]
    }

    pub fn va(&self, s: u64) -> u64 {
        self.va[s as usize]
    }

    pub fn base(&self, s: u64) -> u64 {
        self.base[s as usize] as u64
    }

    pub fn refs(&self, s: u64) -> u64 {
        self.refs[s as usize] as u64
    }

    pub fn used(&self, client: u64) -> u64 {
        self.used.get(client as usize).copied().unwrap_or(0)
    }

    /// A zeroed page nobody holds, made if need be.
    fn take(&mut self) -> Option<u64> {
        if let Some(s) = self.slots().find(|&s| self.page(s) == Page::Free) {
            return Some(s);
        }
        if self.pool_left == 0 {
            return None;
        }
        let s = self.slots().find(|&s| self.page(s) == Page::Unmade)?;
        // Fresh frames come zeroed from the kernel.
        if !self.frames.make(s) {
            self.pool_left = 0;
            return None;
        }
        self.pool_left -= 1;
        self.pages[s as usize] = Page::Free;
        Some(s)
    }

    /// Pages that can still be handed out: free ones, and ones the pool
    /// can make into the slots left (copy-on-write copies use slots too).
    pub fn free_pages(&self) -> u64 {
        let count = |p: Page| self.slots().filter(|&s| self.page(s) == p).count() as u64;
        count(Page::Free) + self.pool_left.min(count(Page::Unmade))
    }

    /// Takes page `s` back from whoever has it: every copy and mapping
    /// goes, and it is zeroed for the next owner.
    fn reclaim(&mut self, s: u64) -> bool {
        self.frames.unmap(s);
        self.frames.revoke(s);
        self.refs[s as usize] = 0;
        let zeroed = self.frames.zero(s);
        self.pages[s as usize] = if zeroed { Page::Free } else { Page::Retired };
        zeroed
    }

    /// Drops copy-on-write mapping `s` (unmapping it): a copy's slot is
    /// emptied, an original kept as `Backing` while copies remain, and a
    /// frame no one maps any more is reclaimed.
    fn drop_cow(&mut self, s: u64) {
        let b = self.base(s);
        self.frames.unmap(s);
        self.refs[b as usize] -= 1;
        if s == b {
            self.pages[s as usize] = Page::Backing;
        } else {
            self.frames.delete(s);
            self.pages[s as usize] = Page::Unmade;
        }
        if self.refs[b as usize] == 0 && self.page(b) == Page::Backing {
            self.reclaim(b);
        }
    }

    /// Charges a page to `client` if its quota allows.
    fn charge(&mut self, client: u64, quota: u64) -> Result<u64, Status> {
        let c = client as usize;
        if c == 0 || c >= CLIENTS {
            return Err(Status::Invalid);
        }
        if self.used[c] >= quota {
            return Err(Status::Denied);
        }
        let s = self.take().ok_or(Status::InUse)?;
        self.used[c] += 1;
        Ok(s)
    }

    /// `[INFO]`: status, quota, pages in use, pages free in the pool.
    pub fn info(&self, client: u64, quota: u64) -> [u64; 4] {
        [Status::Ok as u64, quota, self.used(client), self.free_pages()]
    }

    /// `[FRAME]`: a page granted to `client`; its slot.
    pub fn frame(&mut self, client: u64, quota: u64) -> Result<u64, Status> {
        let s = self.charge(client, quota)?;
        self.pages[s as usize] = Page::Given(client as u16);
        Ok(s)
    }

    /// `[FREE, handle]`.
    pub fn free(&mut self, client: u64, handle: u64) -> Status {
        if !self.slots().contains(&handle) || self.page(handle) != Page::Given(client as u16) {
            return Status::Invalid;
        }
        self.reclaim(handle);
        self.used[client as usize] -= 1;
        Status::Ok
    }

    /// The slot mapping `client`'s heap at `va`, if any.
    pub fn mapping(&self, client: u64, va: u64) -> Option<u64> {
        let o = client as u16;
        self.slots().find(|&s| {
            matches!(self.page(s), Page::Heap(x) | Page::Cow(x) if x == o) && self.va(s) == va
        })
    }

    /// `[FAULT]`: `client`'s heap faulted at `addr`. A zeroed page if
    /// nothing is mapped there, or its own copy of a copy-on-write page.
    pub fn fault(&mut self, client: u64, quota: u64, addr: u64, lent: bool) -> Status {
        if !lent {
            return Status::Invalid;
        }
        let va = addr & !(PAGE - 1);
        match self.mapping(client, va) {
            // Another of its threads got here first.
            Some(s) if matches!(self.page(s), Page::Heap(_)) => return Status::Ok,
            Some(s) => return self.unshare(client, s, va),
            None => {}
        }
        let s = match self.charge(client, quota) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if !self.frames.map_lent(s, va, true) {
            self.used[client as usize] -= 1;
            return Status::Invalid;
        }
        self.pages[s as usize] = Page::Heap(client as u16);
        self.va[s as usize] = va;
        Status::Ok
    }

    /// `client` wrote to copy-on-write mapping `s` at `va`. The charge
    /// stays the same: one page for one page.
    fn unshare(&mut self, client: u64, s: u64, va: u64) -> Status {
        let b = self.base(s);
        let owner = Page::Heap(client as u16);
        if self.refs[b as usize] == 1 {
            // The last mapping: the frame is the writer's alone. It keeps
            // the original, so taking it back later revokes the right one.
            self.frames.unmap(s);
            if s != b {
                self.frames.delete(s);
                self.pages[s as usize] = Page::Unmade;
            }
            self.refs[b as usize] = 0;
            if !self.frames.map_lent(b, va, true) {
                self.reclaim(b);
                self.used[client as usize] -= 1;
                return Status::Invalid;
            }
            self.pages[b as usize] = owner;
            self.va[b as usize] = va;
            return Status::Ok;
        }
        let Some(n) = self.take() else {
            return Status::InUse;
        };
        self.frames.unmap(s);
        if !self.frames.copy_page(s, n) || !self.frames.map_lent(n, va, true) {
            // Put the shared page back; the writer faults again or crashes.
            let _ = self.frames.map_lent(s, va, false);
            self.reclaim(n);
            return Status::Invalid;
        }
        self.pages[n as usize] = owner;
        self.va[n as usize] = va;
        self.drop_cow(s);
        Status::Ok
    }

    /// `[SHARE, client]`: every heap page `client` holds becomes
    /// copy-on-write. Returns how many.
    pub fn share(&mut self, client: u64, lent: bool) -> Result<u64, Status> {
        if !lent {
            return Err(Status::Invalid);
        }
        let mut n = 0;
        for s in self.slots() {
            if self.page(s) != Page::Heap(client as u16) {
                continue;
            }
            let va = self.va(s);
            self.frames.unmap(s);
            if !self.frames.map_lent(s, va, false) {
                // Leave it writable and private, as it was.
                let _ = self.frames.map_lent(s, va, true);
                return Err(Status::Invalid);
            }
            self.pages[s as usize] = Page::Cow(client as u16);
            self.base[s as usize] = s as u16;
            self.refs[s as usize] = 1;
            n += 1;
        }
        Ok(n)
    }

    /// `[CLONE, parent, child, quota]`: the child maps every copy-on-write
    /// page of the parent, read-only, at the same address. Returns how
    /// many.
    pub fn clone(&mut self, parent: u64, child: u64, quota: u64, lent: bool) -> Result<u64, Status> {
        let c = child as usize;
        if !lent || c == 0 || c >= CLIENTS || parent == child {
            return Err(Status::Invalid);
        }
        let shared = Page::Cow(parent as u16);
        let n = self.slots().filter(|&s| self.page(s) == shared).count() as u64;
        if self.used[c] + n > quota {
            return Err(Status::Denied);
        }
        let room = self.slots().filter(|&s| self.page(s) == Page::Unmade).count() as u64;
        if room < n {
            return Err(Status::InUse);
        }
        for s in self.slots() {
            if self.page(s) != shared {
                continue;
            }
            let b = self.base[s as usize];
            let va = self.va(s);
            let Some(k) = self.slots().find(|&k| self.page(k) == Page::Unmade) else {
                return Err(Status::InUse);
            };
            // A copy of the original, so revoking the original takes it.
            if !self.frames.copy_cap(b as u64, k) {
                return Err(Status::InUse);
            }
            if !self.frames.map_lent(k, va, false) {
                self.frames.delete(k);
                return Err(Status::Invalid);
            }
            self.pages[k as usize] = Page::Cow(child as u16);
            self.base[k as usize] = b;
            self.va[k as usize] = va;
            self.refs[b as usize] += 1;
            self.used[c] += 1;
        }
        Ok(n)
    }

    /// `[RELEASE, client]`: every page `client` holds comes back. Returns
    /// how many.
    pub fn release(&mut self, client: u64) -> u64 {
        let o = client as u16;
        let mut n = 0;
        for s in self.slots() {
            match self.page(s) {
                Page::Heap(x) | Page::Given(x) if x == o => {
                    self.reclaim(s);
                }
                Page::Cow(x) if x == o => self.drop_cow(s),
                _ => continue,
            }
            n += 1;
        }
        if let Some(u) = self.used.get_mut(client as usize) {
            *u = 0;
        }
        n
    }

    /// One request, as it arrives: the badge (0 from the manager), the
    /// message, and whether an address space was lent with it. The reply,
    /// and the slot of a page to grant with it.
    pub fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], Option<u64>) {
        let status = |s: Status| ([s as u64, 0, 0, 0], None);
        let count = |r: Result<u64, Status>| match r {
            Ok(n) => ([Status::Ok as u64, n, 0, 0], None),
            Err(e) => ([e as u64, 0, 0, 0], None),
        };
        let manager = badge == 0;
        let (client, quota) = mem::from_badge(badge);
        match m[0] {
            mem::INFO if m[1] == mem::VERSION && !manager => (self.info(client, quota), None),
            mem::FRAME if !manager => match self.frame(client, quota) {
                Ok(s) => ([Status::Ok as u64, s, 0, 0], Some(s)),
                Err(e) => status(e),
            },
            mem::FREE if !manager => status(self.free(client, m[1])),
            mem::FAULT if manager => status(self.fault(m[1], m[2], m[3], lent)),
            mem::RELEASE if manager => ([Status::Ok as u64, self.release(m[1]), 0, 0], None),
            mem::SHARE if manager => count(self.share(m[1], lent)),
            mem::CLONE if manager => count(self.clone(m[1], m[2], m[3], lent)),
            mem::FAULT | mem::RELEASE | mem::SHARE | mem::CLONE => status(Status::Denied),
            _ => status(Status::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    //! A model kernel (frames with contents, capability slots with their
    //! derivation, mappings per address space) and random request
    //! sequences, checking after every step that each component sees
    //! exactly the memory it should and the server's books balance.

    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    const SLOTS: usize = 64;
    const CLIENTS: usize = 5;
    const PAGES: u64 = 6;
    const QUOTA: u64 = 8;

    #[derive(Default)]
    struct Model {
        /// Frame contents, by frame number.
        frames: Vec<u64>,
        /// Slot: (frame, the slot it was copied from).
        caps: BTreeMap<u64, (usize, Option<u64>)>,
        /// (address space, page address): (slot, writable).
        maps: BTreeMap<(u64, u64), (u64, bool)>,
        /// Which address space the current request lent.
        lent: u64,
        pool: u64,
        /// Fail the next n `copy_page` calls (an out-of-memory path).
        fail_copies: u32,
    }

    impl Model {
        fn mapped(&self, s: u64) -> bool {
            self.maps.values().any(|&(x, _)| x == s)
        }
    }

    impl Frames for Model {
        fn make(&mut self, s: u64) -> bool {
            if self.pool == 0 || self.caps.contains_key(&s) {
                return false;
            }
            self.pool -= 1;
            self.frames.push(0);
            self.caps.insert(s, (self.frames.len() - 1, None));
            true
        }
        fn map_lent(&mut self, s: u64, va: u64, writable: bool) -> bool {
            if !self.caps.contains_key(&s) || self.mapped(s) || self.maps.contains_key(&(self.lent, va))
            {
                return false;
            }
            self.maps.insert((self.lent, va), (s, writable));
            true
        }
        fn unmap(&mut self, s: u64) {
            self.maps.retain(|_, &mut (x, _)| x != s);
        }
        fn revoke(&mut self, s: u64) {
            let mut gone: Vec<u64> = Vec::new();
            loop {
                let more: Vec<u64> = self
                    .caps
                    .iter()
                    .filter(|&(k, &(_, from))| {
                        !gone.contains(k) && (from == Some(s) || from.is_some_and(|f| gone.contains(&f)))
                    })
                    .map(|(&k, _)| k)
                    .collect();
                if more.is_empty() {
                    break;
                }
                gone.extend(more);
            }
            for k in gone {
                self.unmap(k);
                self.caps.remove(&k);
            }
        }
        fn delete(&mut self, s: u64) {
            self.unmap(s);
            self.caps.remove(&s);
        }
        fn copy_cap(&mut self, from: u64, to: u64) -> bool {
            let Some(&(f, _)) = self.caps.get(&from) else { return false };
            if self.caps.contains_key(&to) {
                return false;
            }
            self.caps.insert(to, (f, Some(from)));
            true
        }
        fn zero(&mut self, s: u64) -> bool {
            match self.caps.get(&s) {
                Some(&(f, _)) if !self.mapped(s) => {
                    self.frames[f] = 0;
                    true
                }
                _ => false,
            }
        }
        fn copy_page(&mut self, from: u64, to: u64) -> bool {
            if self.fail_copies > 0 {
                self.fail_copies -= 1;
                return false;
            }
            match (self.caps.get(&from), self.caps.get(&to)) {
                (Some(&(a, _)), Some(&(b, _))) if !self.mapped(from) && !self.mapped(to) => {
                    self.frames[b] = self.frames[a];
                    true
                }
                _ => false,
            }
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    type S = Server<Model, SLOTS, CLIENTS>;

    /// What each component should see: page address to value.
    type Expect = [BTreeMap<u64, u64>; CLIENTS];

    fn va(p: u64) -> u64 {
        0x2000_0000 + p * PAGE
    }

    /// The value at `va` in client `c`'s address space, if mapped.
    fn read(s: &S, c: u64, va: u64) -> Option<(u64, bool)> {
        let &(slot, w) = s.frames.maps.get(&(c, va))?;
        let (f, _) = s.frames.caps[&slot];
        Some((s.frames.frames[f], w))
    }

    /// Client `c` writes `v` at `va`, faulting first as the hardware
    /// would. False if the server refused the fault.
    fn write(s: &mut S, c: u64, va: u64, v: u64) -> bool {
        for _ in 0..2 {
            if let Some((_, true)) = read(s, c, va) {
                let &(slot, _) = s.frames.maps.get(&(c, va)).unwrap();
                let (f, _) = s.frames.caps[&slot];
                s.frames.frames[f] = v;
                return true;
            }
            s.frames.lent = c;
            if s.fault(c, QUOTA, va, true) != Status::Ok {
                return false;
            }
        }
        panic!("client {c}: still not writable at {va:#x} after its fault was served");
    }

    fn check(s: &S, want: &Expect, step: usize, seed: u64) {
        let ctx = || std::format!("seed {seed}, step {step}");
        for c in 1..CLIENTS as u64 {
            // Every page it should have reads back what it should.
            for (&va, &v) in &want[c as usize] {
                let got = read(s, c, va).map(|(x, _)| x);
                assert_eq!(got, Some(v), "client {c} at {va:#x}: {}", ctx());
            }
            // And it has nothing else.
            let maps = s.frames.maps.keys().filter(|&&(x, _)| x == c).count();
            assert_eq!(maps, want[c as usize].len(), "client {c}'s mappings: {}", ctx());
            assert_eq!(s.used(c), maps as u64, "client {c}'s charge: {}", ctx());
        }
        for slot in s.slots() {
            let mapping = s.frames.maps.iter().find(|&(_, &(x, _))| x == slot);
            match s.page(slot) {
                Page::Heap(o) => {
                    let (&(c, v), &(_, w)) = mapping.expect("a heap page is mapped");
                    assert!(w && c == o as u64 && v == s.va(slot), "heap slot {slot}: {}", ctx());
                }
                Page::Cow(o) => {
                    let (&(c, v), &(_, w)) = mapping.expect("a shared page is mapped");
                    assert!(!w && c == o as u64 && v == s.va(slot), "shared slot {slot}: {}", ctx());
                    let b = s.base(slot);
                    assert!(matches!(s.page(b), Page::Cow(_) | Page::Backing), "base of {slot}: {}", ctx());
                    // The copy maps the original's frame.
                    assert_eq!(s.frames.caps[&slot].0, s.frames.caps[&b].0, "{}", ctx());
                }
                Page::Backing => {
                    assert!(mapping.is_none(), "{}", ctx());
                    assert!(s.refs(slot) > 0, "a backing page nobody maps: {}", ctx());
                }
                Page::Free => {
                    assert!(mapping.is_none(), "{}", ctx());
                    let (f, _) = s.frames.caps[&slot];
                    assert_eq!(s.frames.frames[f], 0, "free page {slot} not zeroed: {}", ctx());
                }
                Page::Unmade => assert!(!s.frames.caps.contains_key(&slot), "{}", ctx()),
                Page::Given(_) | Page::Retired => {}
            }
            // References counted right.
            if matches!(s.page(slot), Page::Cow(_) | Page::Backing) && s.base(slot) == slot {
                let n = s
                    .slots()
                    .filter(|&k| matches!(s.page(k), Page::Cow(_)) && s.base(k) == slot)
                    .count() as u64;
                assert_eq!(s.refs(slot), n, "refs of {slot}: {}", ctx());
            }
        }
        // No frame lost: each one made is in exactly one original slot.
        let originals = s.frames.caps.values().filter(|(_, from)| from.is_none()).count();
        assert_eq!(originals, s.frames.frames.len(), "a frame leaked: {}", ctx());
    }

    fn run(seed: u64, steps: usize) {
        let mut rng = Rng(seed);
        let model = Model {
            pool: 40,
            ..Default::default()
        };
        let mut s = S::new(model, SLOTS as u64, 40);
        let mut want: Expect = Default::default();
        for step in 0..steps {
            let c = 1 + rng.below(CLIENTS as u64 - 1);
            match rng.below(10) {
                // Writes and reads, the common case.
                0..=4 => {
                    let v = va(rng.below(PAGES));
                    let x = rng.next() | 1;
                    if rng.below(6) == 0 {
                        s.frames.fail_copies = 1;
                    }
                    let before = want[c as usize].get(&v).copied();
                    if write(&mut s, c, v, x) {
                        want[c as usize].insert(v, x);
                    } else if let Some(b) = before {
                        // Refused: what was there stays.
                        assert_eq!(read(&s, c, v).map(|r| r.0), Some(b), "seed {seed}");
                    }
                    s.frames.fail_copies = 0;
                }
                5 => {
                    let v = va(rng.below(PAGES));
                    if read(&s, c, v).is_none() {
                        s.frames.lent = c;
                        if s.fault(c, QUOTA, v, true) == Status::Ok {
                            want[c as usize].insert(v, 0);
                        }
                    }
                }
                // Clone c into a stopped child.
                6 | 7 => {
                    let child = 1 + rng.below(CLIENTS as u64 - 1);
                    if child == c {
                        continue;
                    }
                    s.release(child);
                    want[child as usize].clear();
                    s.frames.lent = c;
                    s.share(c, true).unwrap();
                    s.frames.lent = child;
                    if s.clone(c, child, QUOTA, true).is_ok() {
                        want[child as usize] = want[c as usize].clone();
                    }
                }
                // Stop one.
                8 => {
                    s.release(c);
                    want[c as usize].clear();
                }
                // Granted frames come and go too.
                _ => {
                    if let Ok(h) = s.frame(c, QUOTA) {
                        if rng.below(2) == 0 {
                            assert_eq!(s.free(c, h), Status::Ok);
                        } else {
                            // Not a heap page: count it, then give it back
                            // at once to keep the model's view simple.
                            assert_eq!(s.used(c), want[c as usize].len() as u64 + 1);
                            assert_eq!(s.free(c, h), Status::Ok);
                        }
                    }
                }
            }
            check(&s, &want, step, seed);
        }
        // Everything comes back.
        for c in 1..CLIENTS as u64 {
            s.release(c);
        }
        assert!(s.frames.maps.is_empty(), "seed {seed}: mappings left");
        let held = s
            .slots()
            .filter(|&k| !matches!(s.page(k), Page::Free | Page::Unmade))
            .count();
        assert_eq!(held, 0, "seed {seed}: pages still held after every release");
    }

    #[test]
    fn copy_on_write_keeps_every_component_s_view_under_random_requests() {
        for seed in 0..300 {
            run(seed, 400);
        }
    }

    #[test]
    #[ignore = "long: cargo test -p superior-objects --release -- --ignored"]
    fn copy_on_write_long_run() {
        for seed in 0..20_000 {
            run(seed, 1_000);
        }
    }

    #[test]
    fn a_clone_shares_until_written_then_each_side_has_its_own() {
        let model = Model {
            pool: 16,
            ..Default::default()
        };
        let mut s = S::new(model, SLOTS as u64, 16);
        assert!(write(&mut s, 1, va(0), 7));
        assert!(write(&mut s, 1, va(1), 8));
        s.frames.lent = 1;
        assert_eq!(s.share(1, true), Ok(2));
        s.frames.lent = 2;
        assert_eq!(s.clone(1, 2, QUOTA, true), Ok(2));
        // Shared: one frame each, read-only on both sides.
        assert_eq!(s.frames.frames.len(), 2);
        assert_eq!(read(&s, 2, va(0)), Some((7, false)));
        // The child writes: it gets a copy, the parent keeps 7.
        assert!(write(&mut s, 2, va(0), 9));
        assert_eq!(read(&s, 1, va(0)), Some((7, false)));
        assert_eq!(read(&s, 2, va(0)), Some((9, true)));
        // The parent writes its now-unshared page: no copy needed.
        let frames = s.frames.frames.len();
        assert!(write(&mut s, 1, va(0), 10));
        assert_eq!(s.frames.frames.len(), frames);
        // The parent goes; the child's still-shared page stays readable.
        s.release(1);
        assert_eq!(read(&s, 2, va(1)), Some((8, false)));
        assert!(write(&mut s, 2, va(1), 11), "the last sharer writes in place");
        assert_eq!(s.used(2), 2);
        // Over quota, a clone is refused whole.
        s.frames.lent = 2;
        s.share(2, true).unwrap();
        s.frames.lent = 3;
        assert_eq!(s.clone(2, 3, 1, true), Err(Status::Denied));
        assert_eq!(s.used(3), 0);
    }
}
