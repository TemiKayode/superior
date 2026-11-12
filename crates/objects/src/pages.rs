//! The Memory Server's page bookkeeping (`user/memserver`), kept here so it
//! is tested on the host: against a model of the kernel, with random
//! sequences of requests, as the kernel's own IPC engine is.
//!
//! The server keeps one frame capability per page in its own CSpace, slots
//! `first` to `end`. A page it gives away is always reachable from the
//! original it keeps, so revoking the original takes back every copy and
//! every mapping. What it asks of the kernel is the [`Frames`] trait.
//!
//! Copy-on-write: [`Server::share`] makes a component's heap pages
//! read-only and shared; [`Server::clone`] maps them, read-only, at the same
//! addresses in another component, each mapping through a copy of the
//! page's original capability. A write faults, and [`Server::fault`] gives
//! the writer its own copy, or the frame itself once no one else maps it.
//! Each mapping is charged to its holder, so breaking the sharing never
//! needs more quota.
//!
//! The books scale to all of RAM (a slot per page, over a hundred
//! thousand): each slot's [`Book`] is in memory the server is handed, free
//! and unmade slots are on lists, and a hash index finds the slot mapping
//! a component's heap at an address. So a fault, a grant or a free takes
//! the same time however many pages there are; only whole-component
//! requests (release, share, clone) walk every slot.

use crate::interfaces::{Status, mem};

/// The first slot holding a page by default; the ones below are the
/// server's own.
pub const FIRST_PAGE: u64 = 8;
const PAGE: u64 = 4096;
/// No slot: the end of a list, an empty place in the index.
const NONE: u32 = u32::MAX;

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

/// One slot's books.
#[derive(Clone, Copy, Debug)]
pub struct Book {
    page: Page,
    /// Where a `Heap` or `Cow` slot is mapped.
    va: u64,
    /// For a `Cow` slot: the slot of the frame's original.
    base: u32,
    /// For an original: how many `Cow` slots map its frame.
    refs: u32,
    /// The next slot on the free or the unmade list (counted from
    /// `first`).
    next: u32,
}

impl Book {
    pub const EMPTY: Book = Book {
        page: Page::Unmade,
        va: 0,
        base: 0,
        refs: 0,
        next: NONE,
    };
}

pub struct Server<'a, F: Frames, const CLIENTS: usize> {
    pub frames: F,
    /// Slot `first + i`'s books.
    books: &'a mut [Book],
    /// The slots mapping heaps, by (owner, address): open addressing with
    /// linear probing, a power of two at least twice the slots.
    index: &'a mut [u32],
    first: u64,
    /// Heads of the free and unmade lists, and their lengths.
    free: u32,
    unmade: u32,
    free_count: u64,
    unmade_count: u64,
    /// Pages the pool can still make.
    pool_left: u64,
    used: [u64; CLIENTS],
}

impl<'a, F: Frames, const CLIENTS: usize> Server<'a, F, CLIENTS> {
    /// Bytes of books one slot takes.
    pub const BOOK_BYTES: usize = core::mem::size_of::<Book>();

    /// Entries the index needs for `slots` slots.
    pub const fn index_len(slots: usize) -> usize {
        (2 * slots).next_power_of_two()
    }

    /// A server with a slot for each of `books`, from `first`, and a pool
    /// that can make `pool` pages. `index` has [`Server::index_len`]
    /// entries (any beyond the largest power of two are left unused).
    pub fn new(
        frames: F,
        books: &'a mut [Book],
        index: &'a mut [u32],
        first: u64,
        pool: u64,
    ) -> Self {
        let n = books.len();
        for (i, b) in books.iter_mut().enumerate() {
            *b = Book {
                next: if i + 1 < n { (i + 1) as u32 } else { NONE },
                ..Book::EMPTY
            };
        }
        let len = match index.len() {
            0 => 0,
            l => 1 << l.ilog2(),
        };
        let index = &mut index[..len];
        index.iter_mut().for_each(|e| *e = NONE);
        Server {
            frames,
            books,
            index,
            first,
            free: NONE,
            unmade: if n > 0 { 0 } else { NONE },
            free_count: 0,
            unmade_count: n as u64,
            pool_left: pool,
            used: [0; CLIENTS],
        }
    }

    pub fn slots(&self) -> core::ops::Range<u64> {
        self.first..self.first + self.books.len() as u64
    }

    fn book(&self, s: u64) -> &Book {
        &self.books[(s - self.first) as usize]
    }

    fn book_mut(&mut self, s: u64) -> &mut Book {
        &mut self.books[(s - self.first) as usize]
    }

    pub fn page(&self, s: u64) -> Page {
        self.book(s).page
    }

    pub fn va(&self, s: u64) -> u64 {
        self.book(s).va
    }

    pub fn base(&self, s: u64) -> u64 {
        self.book(s).base as u64
    }

    pub fn refs(&self, s: u64) -> u64 {
        self.book(s).refs as u64
    }

    pub fn used(&self, client: u64) -> u64 {
        self.used.get(client as usize).copied().unwrap_or(0)
    }

    // ---- the free and unmade lists ----

    fn push(&mut self, s: u64, free: bool) {
        let i = (s - self.first) as u32;
        let head = if free { self.free } else { self.unmade };
        self.book_mut(s).next = head;
        if free {
            self.free = i;
            self.free_count += 1;
        } else {
            self.unmade = i;
            self.unmade_count += 1;
        }
    }

    fn pop(&mut self, free: bool) -> Option<u64> {
        let head = if free { self.free } else { self.unmade };
        if head == NONE {
            return None;
        }
        let next = core::mem::replace(&mut self.books[head as usize].next, NONE);
        if free {
            self.free = next;
            self.free_count -= 1;
        } else {
            self.unmade = next;
            self.unmade_count -= 1;
        }
        Some(self.first + head as u64)
    }

    // ---- the index of heap mappings ----

    /// What the index files slot `s` under, if anything.
    fn key(&self, s: u64) -> Option<(u16, u64)> {
        match self.page(s) {
            Page::Heap(o) | Page::Cow(o) => Some((o, self.va(s))),
            _ => None,
        }
    }

    fn home(&self, (owner, va): (u16, u64)) -> usize {
        let x = ((va >> 12) ^ (owner as u64) << 52).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (x >> 32) as usize & (self.index.len() - 1)
    }

    /// Where in the index the slot filed under `key` is, and the slot.
    fn find(&self, key: (u16, u64)) -> Option<(usize, u64)> {
        if self.index.is_empty() {
            return None;
        }
        let mut i = self.home(key);
        loop {
            let e = self.index[i];
            if e == NONE {
                return None;
            }
            let s = self.first + e as u64;
            if self.key(s) == Some(key) {
                return Some((i, s));
            }
            i = (i + 1) & (self.index.len() - 1);
        }
    }

    fn file(&mut self, s: u64) {
        let Some(key) = self.key(s) else { return };
        let mask = self.index.len() - 1;
        let mut i = self.home(key);
        while self.index[i] != NONE {
            i = (i + 1) & mask;
        }
        self.index[i] = (s - self.first) as u32;
    }

    /// Takes slot `s` out of the index, moving later entries back so no
    /// lookup stops short at the hole.
    fn unfile(&mut self, s: u64) {
        let Some(key) = self.key(s) else { return };
        let Some((mut i, found)) = self.find(key) else { return };
        debug_assert_eq!(found, s);
        let mask = self.index.len() - 1;
        let mut j = i;
        loop {
            j = (j + 1) & mask;
            let e = self.index[j];
            if e == NONE {
                break;
            }
            let k = self.home(self.key(self.first + e as u64).unwrap_or((0, 0)));
            // An entry whose home lies cyclically in (i, j] is reachable
            // already; any other must move into the hole.
            let stays = if i <= j { i < k && k <= j } else { i < k || k <= j };
            if !stays {
                self.index[i] = e;
                i = j;
            }
        }
        self.index[i] = NONE;
    }

    /// Puts slot `s` in state `page` (mapped at `va`), keeping the lists
    /// and the index right. A slot going `Free` or `Unmade` must be on
    /// no list.
    fn set(&mut self, s: u64, page: Page, va: u64) {
        self.unfile(s);
        let b = self.book_mut(s);
        b.page = page;
        b.va = va;
        match page {
            Page::Heap(_) | Page::Cow(_) => self.file(s),
            Page::Free => self.push(s, true),
            Page::Unmade => self.push(s, false),
            _ => {}
        }
    }

    /// A zeroed page nobody holds, made if need be. It is on no list: the
    /// caller puts it in its next state with [`Server::set`].
    fn take(&mut self) -> Option<u64> {
        if let Some(s) = self.pop(true) {
            return Some(s);
        }
        if self.pool_left == 0 {
            return None;
        }
        let s = self.pop(false)?;
        // Fresh frames come zeroed from the kernel.
        if !self.frames.make(s) {
            self.pool_left = 0;
            self.push(s, false);
            return None;
        }
        self.pool_left -= 1;
        self.book_mut(s).page = Page::Free;
        Some(s)
    }

    /// Pages that can still be handed out: free ones, and ones the pool
    /// can make into the slots left (copy-on-write copies use slots too).
    pub fn free_pages(&self) -> u64 {
        self.free_count + self.pool_left.min(self.unmade_count)
    }

    /// Takes page `s` back from whoever has it: every copy and mapping
    /// goes, and it is zeroed for the next owner.
    fn reclaim(&mut self, s: u64) -> bool {
        self.frames.unmap(s);
        self.frames.revoke(s);
        self.book_mut(s).refs = 0;
        let zeroed = self.frames.zero(s);
        self.set(s, if zeroed { Page::Free } else { Page::Retired }, 0);
        zeroed
    }

    /// Drops copy-on-write mapping `s` (unmapping it): a copy's slot is
    /// emptied, an original kept as `Backing` while copies remain, and a
    /// frame no one maps any more is reclaimed.
    fn drop_cow(&mut self, s: u64) {
        let b = self.base(s);
        self.frames.unmap(s);
        self.book_mut(b).refs -= 1;
        if s == b {
            self.set(s, Page::Backing, 0);
        } else {
            self.frames.delete(s);
            self.set(s, Page::Unmade, 0);
        }
        if self.refs(b) == 0 && self.page(b) == Page::Backing {
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
        self.set(s, Page::Given(client as u16), 0);
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
        let c = u16::try_from(client).ok()?;
        self.find((c, va)).map(|(_, s)| s)
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
            self.set(s, Page::Free, 0);
            return Status::Invalid;
        }
        self.set(s, Page::Heap(client as u16), va);
        Status::Ok
    }

    /// `client` wrote to copy-on-write mapping `s` at `va`. The charge
    /// stays the same: one page for one page.
    fn unshare(&mut self, client: u64, s: u64, va: u64) -> Status {
        let b = self.base(s);
        let owner = Page::Heap(client as u16);
        if self.refs(b) == 1 {
            // The last mapping: the frame is the writer's alone. It keeps
            // the original, so taking it back later revokes the right one.
            self.frames.unmap(s);
            if s != b {
                self.frames.delete(s);
                self.set(s, Page::Unmade, 0);
            }
            self.book_mut(b).refs = 0;
            if !self.frames.map_lent(b, va, true) {
                self.reclaim(b);
                self.used[client as usize] -= 1;
                return Status::Invalid;
            }
            self.set(b, owner, va);
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
        self.set(n, owner, va);
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
            self.set(s, Page::Cow(client as u16), va);
            let b = self.book_mut(s);
            b.base = s as u32;
            b.refs = 1;
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
        if self.unmade_count < n {
            return Err(Status::InUse);
        }
        for s in self.slots() {
            if self.page(s) != shared {
                continue;
            }
            let b = self.base(s);
            let va = self.va(s);
            let Some(k) = self.pop(false) else {
                return Err(Status::InUse);
            };
            // A copy of the original, so revoking the original takes it.
            if !self.frames.copy_cap(b, k) {
                self.push(k, false);
                return Err(Status::InUse);
            }
            if !self.frames.map_lent(k, va, false) {
                self.frames.delete(k);
                self.push(k, false);
                return Err(Status::Invalid);
            }
            self.set(k, Page::Cow(child as u16), va);
            self.book_mut(k).base = b as u32;
            self.book_mut(b).refs += 1;
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

    /// Checks the lists, counts and index agree with the books (for the
    /// tests): every free slot on the free list and every unmade one on
    /// the unmade list, nothing else on either, and every heap or shared
    /// slot found by the index under its owner and address.
    #[cfg(test)]
    pub(crate) fn check_books(&self) -> Result<(), std::string::String> {
        use std::format;
        let walk = |mut head: u32, want: Page| -> Result<u64, std::string::String> {
            let mut n = 0;
            while head != NONE {
                let s = self.first + head as u64;
                if self.page(s) != want {
                    return Err(format!("slot {s} on the {want:?} list is {:?}", self.page(s)));
                }
                n += 1;
                if n > self.books.len() as u64 {
                    return Err(format!("the {want:?} list loops"));
                }
                head = self.book(s).next;
            }
            Ok(n)
        };
        let count = |p: Page| self.slots().filter(|&s| self.page(s) == p).count() as u64;
        let (free, unmade) = (walk(self.free, Page::Free)?, walk(self.unmade, Page::Unmade)?);
        if (free, self.free_count) != (count(Page::Free), count(Page::Free)) {
            return Err(format!("{free} on the free list, {} counted", self.free_count));
        }
        if (unmade, self.unmade_count) != (count(Page::Unmade), count(Page::Unmade)) {
            return Err(format!("{unmade} on the unmade list, {} counted", self.unmade_count));
        }
        let mut filed = 0;
        for s in self.slots() {
            if let Some(key) = self.key(s) {
                filed += 1;
                if self.find(key).map(|(_, x)| x) != Some(s) {
                    return Err(format!("slot {s} not found under {key:?}"));
                }
            }
        }
        let entries = self.index.iter().filter(|&&e| e != NONE).count();
        if entries != filed {
            return Err(format!("{entries} index entries for {filed} mapped slots"));
        }
        Ok(())
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

    type S = Server<'static, Model, CLIENTS>;

    /// A server with slots `FIRST_PAGE..SLOTS` (books on the heap, kept for
    /// the test's life) and a pool of `pool` pages.
    fn server(pool: u64) -> S {
        server_with(SLOTS - FIRST_PAGE as usize, pool)
    }

    /// The same with `n` slots.
    fn server_with(n: usize, pool: u64) -> S {
        let model = Model {
            pool,
            ..Default::default()
        };
        let books = std::vec![Book::EMPTY; n].leak();
        let index = std::vec![0u32; S::index_len(n)].leak();
        S::new(model, books, index, FIRST_PAGE, pool)
    }

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
        if let Err(e) = s.check_books() {
            panic!("{e}: {}", ctx());
        }
        // No frame lost: each one made is in exactly one original slot.
        let originals = s.frames.caps.values().filter(|(_, from)| from.is_none()).count();
        assert_eq!(originals, s.frames.frames.len(), "a frame leaked: {}", ctx());
    }

    fn run(seed: u64, steps: usize) {
        let mut rng = Rng(seed);
        let mut s = server(40);
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
        let mut s = server(16);
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

    #[test]
    fn the_index_finds_every_mapping_through_many_collisions() {
        // Far more mappings than a small index's home places, filed and
        // taken out in a scrambled order, the books checked each step.
        let mut s = server(48);
        let mut rng = Rng(7);
        let mut live: Vec<(u64, u64)> = Vec::new();
        for _ in 0..2_000 {
            let c = 1 + rng.below(CLIENTS as u64 - 1);
            if live.len() < 40 && rng.below(3) != 0 {
                let v = va(rng.below(64));
                s.frames.lent = c;
                if s.mapping(c, v).is_none() && s.fault(c, 64, v, true) == Status::Ok {
                    live.push((c, v));
                }
            } else if !live.is_empty() {
                let (c, v) = live.swap_remove(rng.below(live.len() as u64) as usize);
                let slot = s.mapping(c, v).expect("a live mapping is found");
                s.frames.unmap(slot);
                s.reclaim(slot);
                s.used[c as usize] -= 1;
                assert_eq!(s.mapping(c, v), None);
            }
            for &(c, v) in &live {
                assert!(s.mapping(c, v).is_some(), "lost {c}:{v:#x}");
            }
            s.check_books().unwrap();
        }
    }

    // ---- bounded exhaustive exploration, as the kernel's capability
    // derivation is model-checked: every sequence of requests up to a
    // depth, on a machine small enough to reach every refusal (two
    // clients, two heap pages each, few slots, a tiny pool) ----

    #[derive(Clone, Copy, Debug)]
    enum Op {
        /// Client, page, and whether the copy a write needs fails.
        Write(u64, u64, bool),
        /// A read that faults the page in.
        Touch(u64, u64),
        /// Clone the client into the other.
        Clone(u64),
        Release(u64),
        /// A granted frame, freed again.
        Frame(u64),
    }

    fn alphabet() -> Vec<Op> {
        let mut ops = Vec::new();
        for c in 1..=2 {
            for p in 0..2 {
                ops.push(Op::Write(c, p, false));
                ops.push(Op::Write(c, p, true));
                ops.push(Op::Touch(c, p));
            }
            ops.extend([Op::Clone(c), Op::Release(c), Op::Frame(c)]);
        }
        ops
    }

    fn apply(s: &mut S, want: &mut Expect, op: Op) {
        match op {
            Op::Write(c, p, fail) => {
                let v = va(p);
                // The same value for the same client and page, so equal
                // states reached two ways look equal.
                let x = 1 + 10 * c + p;
                s.frames.fail_copies = fail as u32;
                let before = want[c as usize].get(&v).copied();
                if write(s, c, v, x) {
                    want[c as usize].insert(v, x);
                } else if let Some(b) = before {
                    assert_eq!(read(s, c, v).map(|r| r.0), Some(b));
                }
                s.frames.fail_copies = 0;
            }
            Op::Touch(c, p) => {
                let v = va(p);
                if read(s, c, v).is_none() {
                    s.frames.lent = c;
                    if s.fault(c, QUOTA, v, true) == Status::Ok {
                        want[c as usize].insert(v, 0);
                    }
                }
            }
            Op::Clone(c) => {
                let child = 3 - c;
                s.release(child);
                want[child as usize].clear();
                s.frames.lent = c;
                s.share(c, true).unwrap();
                s.frames.lent = child;
                if s.clone(c, child, QUOTA, true).is_ok() {
                    want[child as usize] = want[c as usize].clone();
                }
            }
            Op::Release(c) => {
                s.release(c);
                want[c as usize].clear();
            }
            Op::Frame(c) => {
                if let Ok(h) = s.frame(c, QUOTA) {
                    assert_eq!(s.free(c, h), Status::Ok);
                }
            }
        }
    }

    fn fingerprint(s: &S, want: &Expect) -> u64 {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let text = std::format!(
            "{:?}|{:?}|{}|{:?}|{:?}|{:?}|{:?}",
            s.books,
            s.used,
            s.pool_left,
            s.frames.caps,
            s.frames.maps,
            s.frames.frames,
            want
        );
        let mut h = DefaultHasher::new();
        text.hash(&mut h);
        h.finish()
    }

    /// Explores every sequence of up to `depth` requests from the empty
    /// server, pruning states already seen; every step is checked as the
    /// randomized runs check them. Returns the states reached.
    fn explore(depth: usize, slots: usize, pool: u64) -> usize {
        let ops = alphabet();
        let mut seen = std::collections::HashSet::new();
        let mut stack: Vec<Vec<Op>> = std::vec![Vec::new()];
        while let Some(seq) = stack.pop() {
            let mut s = server_with(slots, pool);
            let mut want: Expect = Default::default();
            for (step, &op) in seq.iter().enumerate() {
                apply(&mut s, &mut want, op);
                check(&s, &want, step, 0);
            }
            if !seen.insert(fingerprint(&s, &want)) {
                continue;
            }
            if seq.len() < depth {
                for &op in &ops {
                    let mut next = seq.clone();
                    next.push(op);
                    stack.push(next);
                }
            }
        }
        seen.len()
    }

    #[test]
    fn every_short_request_sequence_keeps_the_books() {
        // Six slots and a pool of three: clones run out of slots, faults
        // out of pages.
        let states = explore(8, 6, 3);
        assert!(states > 1_000, "only {states} states");
    }

    #[test]
    #[ignore = "long: cargo test -p superior-objects --release -- --ignored"]
    fn every_request_sequence_to_depth_20_keeps_the_books() {
        let states = explore(20, 6, 3);
        assert!(states > 100_000, "only {states} states");
    }
}
