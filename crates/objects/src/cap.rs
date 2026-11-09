//! Capabilities and CNodes.
//!
//! A capability is an unforgeable reference to a kernel object plus the
//! rights its holder has over it. Capabilities live in CNode slots, and
//! every capability made from another records its parent, forming a
//! derivation tree. Revoking a capability destroys everything derived from
//! it, which is how authority handed out is taken back.
//!
//! Invariants enforced here (and tested below):
//! 1. A derived capability never has a right its parent lacks.
//! 2. A badge, once set, can never be changed by deriving.
//! 3. Revoke removes every descendant and nothing else.
//! 4. Deleting a capability keeps its descendants revocable through its
//!    parent (they are re-parented, never orphaned).
//! 5. No byte of untyped memory is handed out twice: only an untyped
//!    capability that is not a copy, and has no copies, may be retyped, and
//!    its watermark is reset only when nothing made from it is left: by
//!    revoking it, which destroys every object made from it, or at retype
//!    once every object's capability has been deleted. Memory the kernel carved for itself
//!    ([`CNode::retype`], no child capabilities) is never reset.

use core::fmt;

/// Rights over an object, as a bit set.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    /// May pass capabilities onward through IPC.
    pub const GRANT: Rights = Rights(1 << 2);
    /// May pass capabilities back through a reply only.
    pub const GRANT_REPLY: Rights = Rights(1 << 3);
    /// May map the object (frames) into an address space.
    pub const MAP: Rights = Rights(1 << 4);
    pub const ALL: Rights = Rights(0b1_1111);

    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Rights from a bit set, ignoring unknown bits.
    pub const fn from_bits_truncate(bits: u8) -> Rights {
        Rights(bits & Rights::ALL.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (Rights::READ, 'R'),
            (Rights::WRITE, 'W'),
            (Rights::GRANT, 'G'),
            (Rights::GRANT_REPLY, 'g'),
            (Rights::MAP, 'M'),
        ];
        for (r, c) in names {
            write!(f, "{}", if self.contains(r) { c } else { '-' })?;
        }
        Ok(())
    }
}

/// The kernel object a capability refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Object {
    Untyped {
        base: u64,
        size_bits: u8,
    },
    Endpoint {
        id: u32,
    },
    Notification {
        id: u32,
    },
    Frame {
        paddr: u64,
        size_bits: u8,
    },
    /// A thread (an entry in the kernel's thread table).
    Thread {
        id: u32,
    },
    /// A CNode: `1 << size_bits` slots of the kernel's capability table,
    /// starting at `base`.
    CNode {
        base: u32,
        size_bits: u8,
    },
    /// The right to use I/O ports `base .. base + count`. Handed out by the
    /// kernel at boot to driver processes; never made by retype.
    IoPort {
        base: u16,
        count: u16,
    },
    /// The right to receive one interrupt line. Handed out at boot.
    Irq {
        line: u8,
    },
    /// An address space (an entry in the kernel's address-space table).
    /// Its top-level page table and every table under it come out of the
    /// untyped memory it was retyped from.
    AddressSpace {
        id: u32,
    },
    /// Device memory (memory-mapped registers): carved like `Untyped`, but
    /// only into frames, which are not zeroed (they are a device's
    /// registers, not RAM), and into smaller device-memory blocks. Never
    /// into kernel objects. Handed out by the kernel at boot.
    DeviceUntyped {
        base: u64,
        size_bits: u8,
    },
}

impl Object {
    /// Untyped memory of either kind, as (base, size in bits).
    pub const fn untyped(&self) -> Option<(u64, u8)> {
        match *self {
            Object::Untyped { base, size_bits } | Object::DeviceUntyped { base, size_bits } => {
                Some((base, size_bits))
            }
            _ => None,
        }
    }

    /// Only communication objects carry badges; the badge tells a server
    /// which client or which object a message is about.
    pub const fn badgeable(&self) -> bool {
        matches!(self, Object::Endpoint { .. } | Object::Notification { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capability {
    pub object: Object,
    pub rights: Rights,
    /// 0 means unbadged.
    pub badge: u64,
}

impl Capability {
    pub const fn new(object: Object, rights: Rights) -> Self {
        Capability {
            object,
            rights,
            badge: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    SlotOutOfRange,
    SlotOccupied,
    SlotEmpty,
    /// Tried to set a badge on a capability that already has one.
    BadgeAlreadySet,
    /// Tried to badge an object type that does not take badges.
    NotBadgeable,
    /// The operation needs a different object type (e.g. retype on a non-untyped cap).
    WrongObjectType,
    /// Retype refused: copies derived from this untyped cap still exist and
    /// could hand out the same memory twice.
    HasChildren,
    /// The untyped block has no aligned room left of the requested size.
    OutOfMemory,
}

#[derive(Clone, Copy)]
struct Slot {
    cap: Option<Capability>,
    parent: Option<u32>,
    /// Scratch mark used during revoke; always false between calls.
    doomed: bool,
    /// For untyped caps: bytes already handed out from the block's start.
    free_index: u64,
    /// For untyped caps: the kernel carved memory from this block for its
    /// own use, with no child capability to revoke, so the watermark may
    /// never be reset.
    raw: bool,
    /// Made by derive: refers to the same object as its parent, rather
    /// than being an object retyped from it.
    copy: bool,
}

const EMPTY: Slot = Slot {
    cap: None,
    parent: None,
    doomed: false,
    free_index: 0,
    raw: false,
    copy: false,
};

/// One slot's full state: capability, parent, copy, raw, watermark.
#[cfg(test)]
pub(crate) type SlotState = (Option<Capability>, Option<u32>, bool, bool, u64);

/// A fixed-size table of capability slots.
#[derive(Clone)]
pub struct CNode<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Default for CNode<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CNode<N> {
    pub const fn new() -> Self {
        CNode { slots: [EMPTY; N] }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn get(&self, slot: usize) -> Option<&Capability> {
        self.slots.get(slot)?.cap.as_ref()
    }

    pub fn parent_of(&self, slot: usize) -> Option<usize> {
        self.slots.get(slot)?.parent.map(|p| p as usize)
    }

    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.cap.is_some()).count()
    }

    /// Places an original capability (one with no parent) in an empty slot.
    /// Only the kernel does this, at boot, for the root task.
    pub fn insert_root(&mut self, slot: usize, cap: Capability) -> Result<(), CapError> {
        let s = self.empty_slot(slot)?;
        *s = Slot {
            cap: Some(cap),
            ..EMPTY
        };
        Ok(())
    }

    /// Places `cap`, an object made from the untyped capability in
    /// `parent` (see [`CNode::carve`]), in the empty slot `dst` as a child
    /// of `parent`, so revoking `parent` destroys it.
    pub fn insert_child(
        &mut self,
        parent: usize,
        dst: usize,
        cap: Capability,
    ) -> Result<(), CapError> {
        self.get(parent).ok_or(self.missing(parent))?;
        let s = self.empty_slot(dst)?;
        *s = Slot {
            cap: Some(cap),
            parent: Some(parent as u32),
            ..EMPTY
        };
        Ok(())
    }

    /// Every capability in the table.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.slots.iter().filter_map(|s| s.cap.as_ref())
    }

    /// Derives a new capability from `src` into the empty slot `dst`.
    ///
    /// The new rights are `src.rights ∩ mask`, so rights can only shrink.
    /// `badge` may be given only if `src` is unbadged and its object type
    /// takes badges.
    pub fn derive(
        &mut self,
        src: usize,
        dst: usize,
        mask: Rights,
        badge: Option<u64>,
    ) -> Result<(), CapError> {
        let parent = *self.get(src).ok_or(self.missing(src))?;
        let mut child = Capability {
            rights: parent.rights.intersect(mask),
            ..parent
        };
        if let Some(b) = badge {
            if !parent.object.badgeable() {
                return Err(CapError::NotBadgeable);
            }
            if parent.badge != 0 {
                return Err(CapError::BadgeAlreadySet);
            }
            child.badge = b;
        }
        let s = self.empty_slot(dst)?;
        *s = Slot {
            cap: Some(child),
            parent: Some(src as u32),
            copy: true,
            ..EMPTY
        };
        Ok(())
    }

    /// Carves memory for the kernel's own use (page tables, user pages):
    /// like [`CNode::carve`], but no child capability will record it, so
    /// this block's watermark is never reset.
    pub fn retype(&mut self, slot: usize, size_bits: u8) -> Result<u64, CapError> {
        let pa = self.carve(slot, size_bits)?;
        self.slots[slot].raw = true;
        Ok(pa)
    }

    /// Carves a naturally aligned `2^size_bits` byte region out of the
    /// untyped block in `slot` and returns its physical base address. The
    /// caller records the object made from it with [`CNode::insert_child`].
    ///
    /// Memory is handed out by a bump watermark, reset when the untyped
    /// capability is revoked. To guarantee no byte is handed out twice, an
    /// untyped capability that is a copy, or has copies, may not be carved.
    pub fn carve(&mut self, slot: usize, size_bits: u8) -> Result<u64, CapError> {
        let cap = *self.get(slot).ok_or(self.missing(slot))?;
        let Some((base, block_bits)) = cap.object.untyped() else {
            return Err(CapError::WrongObjectType);
        };
        if self.is_copy(slot) || self.has_copies(slot) {
            return Err(CapError::HasChildren);
        }
        // Nothing made from the block is left (each object's capability
        // was deleted): all of it is free again, as after a revoke.
        if !self.slots[slot].raw && !self.has_children(slot) {
            self.slots[slot].free_index = 0;
        }
        if size_bits > block_bits || size_bits >= 64 {
            return Err(CapError::OutOfMemory);
        }
        let align = 1u64 << size_bits;
        let offset = (self.slots[slot].free_index + align - 1) & !(align - 1);
        let end = offset.checked_add(align).ok_or(CapError::OutOfMemory)?;
        if end > 1u64 << block_bits {
            return Err(CapError::OutOfMemory);
        }
        self.slots[slot].free_index = end;
        Ok(base + offset)
    }

    /// Bytes still free (ignoring alignment) in the untyped block in `slot`.
    pub fn untyped_free(&self, slot: usize) -> Option<u64> {
        let (_, size_bits) = self.get(slot)?.object.untyped()?;
        Some((1u64 << size_bits) - self.slots[slot].free_index)
    }

    /// A copy refers to the same object as its parent (made by derive);
    /// an object retyped from an untyped capability is not a copy, even a
    /// sub-block covering the whole of its parent.
    fn is_copy(&self, slot: usize) -> bool {
        self.slots[slot].copy
    }

    fn has_children(&self, slot: usize) -> bool {
        self.slots
            .iter()
            .any(|s| s.cap.is_some() && s.parent == Some(slot as u32))
    }

    fn has_copies(&self, slot: usize) -> bool {
        self.slots
            .iter()
            .any(|s| s.cap.is_some() && s.copy && s.parent == Some(slot as u32))
    }

    /// Removes every capability derived (directly or transitively) from
    /// `slot`, leaving `slot` itself in place. Returns how many were removed.
    /// Revoking an untyped capability destroys every object made from it,
    /// so its memory is free again (unless the kernel carved some for
    /// itself).
    pub fn revoke(&mut self, slot: usize) -> Result<usize, CapError> {
        self.revoke_each(slot, |_, _| {})
    }

    /// [`CNode::revoke`], calling `removed` with the slot and capability of
    /// each one removed (before it is gone, so its slot can be cleaned up).
    pub fn revoke_each(
        &mut self,
        slot: usize,
        mut removed: impl FnMut(usize, Capability),
    ) -> Result<usize, CapError> {
        self.get(slot).ok_or(self.missing(slot))?;
        // Mark first, then clear: clearing as we go would cut ancestor
        // chains that later slots still need to walk.
        for i in 0..N {
            if i != slot && self.slots[i].cap.is_some() && self.descends_from(i, slot) {
                self.slots[i].doomed = true;
            }
        }
        let mut count = 0;
        for (i, s) in self.slots.iter_mut().enumerate().filter(|(_, s)| s.doomed) {
            if let Some(c) = s.cap {
                removed(i, c);
            }
            *s = EMPTY;
            count += 1;
        }
        let s = &mut self.slots[slot];
        if !s.raw && s.cap.is_some_and(|c| c.object.untyped().is_some()) {
            s.free_index = 0;
        }
        Ok(count)
    }

    /// Deletes the capability in `slot`. Its children are re-parented to
    /// its own parent, so revoking an ancestor still reaches them.
    pub fn delete(&mut self, slot: usize) -> Result<(), CapError> {
        self.get(slot).ok_or(self.missing(slot))?;
        let grandparent = self.slots[slot].parent;
        for s in self.slots.iter_mut() {
            if s.parent == Some(slot as u32) {
                s.parent = grandparent;
            }
        }
        self.slots[slot] = EMPTY;
        Ok(())
    }

    fn descends_from(&self, mut i: usize, ancestor: usize) -> bool {
        // A chain can be no longer than N; the bound guards against a
        // corrupted (cyclic) table rather than looping forever.
        for _ in 0..N {
            match self.slots[i].parent {
                Some(p) if p as usize == ancestor => return true,
                Some(p) => i = p as usize,
                None => return false,
            }
        }
        false
    }

    /// Whether `slot` holds a copy made by derive (for the model checker).
    #[cfg(test)]
    pub(crate) fn is_copy_slot(&self, slot: usize) -> bool {
        self.slots[slot].copy
    }

    /// The whole table's state, to tell explored states apart.
    #[cfg(test)]
    pub(crate) fn fingerprint(&self) -> std::vec::Vec<SlotState> {
        self.slots
            .iter()
            .map(|s| (s.cap, s.parent, s.copy, s.raw, s.free_index))
            .collect()
    }

    fn empty_slot(&mut self, slot: usize) -> Result<&mut Slot, CapError> {
        let s = self.slots.get_mut(slot).ok_or(CapError::SlotOutOfRange)?;
        if s.cap.is_some() {
            return Err(CapError::SlotOccupied);
        }
        Ok(s)
    }

    fn missing(&self, slot: usize) -> CapError {
        if slot < N {
            CapError::SlotEmpty
        } else {
            CapError::SlotOutOfRange
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const EP: Object = Object::Endpoint { id: 7 };
    const MEM: Object = Object::Untyped {
        base: 0x10_0000,
        size_bits: 20,
    };

    fn root_with_endpoint() -> CNode<16> {
        let mut c = CNode::new();
        c.insert_root(0, Capability::new(EP, Rights::ALL)).unwrap();
        c
    }

    #[test]
    fn derive_cannot_add_rights() {
        let mut c = CNode::<16>::new();
        c.insert_root(0, Capability::new(EP, Rights::READ)).unwrap();
        c.derive(0, 1, Rights::ALL, None).unwrap();
        assert_eq!(c.get(1).unwrap().rights, Rights::READ);
    }

    #[test]
    fn derive_masks_rights() {
        let mut c = root_with_endpoint();
        c.derive(0, 1, Rights::READ | Rights::GRANT, None).unwrap();
        assert_eq!(c.get(1).unwrap().rights, Rights::READ | Rights::GRANT);
        c.derive(1, 2, Rights::WRITE, None).unwrap();
        assert_eq!(c.get(2).unwrap().rights, Rights::NONE);
    }

    #[test]
    fn badge_is_set_once() {
        let mut c = root_with_endpoint();
        c.derive(0, 1, Rights::ALL, Some(42)).unwrap();
        assert_eq!(c.get(1).unwrap().badge, 42);
        assert_eq!(
            c.derive(1, 2, Rights::ALL, Some(43)),
            Err(CapError::BadgeAlreadySet)
        );
        // Deriving without a badge keeps the existing one.
        c.derive(1, 2, Rights::ALL, None).unwrap();
        assert_eq!(c.get(2).unwrap().badge, 42);
    }

    #[test]
    fn untyped_cannot_be_badged() {
        let mut c = CNode::<4>::new();
        c.insert_root(0, Capability::new(MEM, Rights::ALL)).unwrap();
        assert_eq!(
            c.derive(0, 1, Rights::ALL, Some(1)),
            Err(CapError::NotBadgeable)
        );
    }

    #[test]
    fn slot_errors() {
        let mut c = root_with_endpoint();
        assert_eq!(
            c.derive(0, 0, Rights::ALL, None),
            Err(CapError::SlotOccupied)
        );
        assert_eq!(c.derive(5, 6, Rights::ALL, None), Err(CapError::SlotEmpty));
        assert_eq!(
            c.derive(0, 99, Rights::ALL, None),
            Err(CapError::SlotOutOfRange)
        );
        assert_eq!(c.revoke(99), Err(CapError::SlotOutOfRange));
    }

    #[test]
    fn revoke_removes_all_descendants_and_nothing_else() {
        // 0 ─┬─ 1 ── 3 ── 4
        //    └─ 2
        // 5 (unrelated root) ── 6
        let mut c = root_with_endpoint();
        c.derive(0, 1, Rights::ALL, None).unwrap();
        c.derive(0, 2, Rights::ALL, None).unwrap();
        c.derive(1, 3, Rights::ALL, None).unwrap();
        c.derive(3, 4, Rights::ALL, None).unwrap();
        c.insert_root(5, Capability::new(MEM, Rights::ALL)).unwrap();
        c.derive(5, 6, Rights::READ, None).unwrap();

        assert_eq!(c.revoke(1), Ok(2));
        assert!(c.get(1).is_some(), "revoke keeps the target");
        assert!(c.get(3).is_none() && c.get(4).is_none());
        assert!(c.get(0).is_some() && c.get(2).is_some());

        assert_eq!(c.revoke(0), Ok(2)); // 1 and 2
        assert_eq!(c.occupied(), 3); // 0, 5, 6
        assert!(c.get(6).is_some(), "unrelated tree untouched");
    }

    #[test]
    fn delete_reparents_children() {
        let mut c = root_with_endpoint();
        c.derive(0, 1, Rights::ALL, None).unwrap();
        c.derive(1, 2, Rights::ALL, None).unwrap();
        c.delete(1).unwrap();
        assert_eq!(c.parent_of(2), Some(0));
        assert_eq!(c.revoke(0), Ok(1));
        assert!(c.get(2).is_none());
    }

    #[test]
    fn slot_reuse_after_revoke_has_no_stale_parent() {
        let mut c = root_with_endpoint();
        c.derive(0, 1, Rights::ALL, None).unwrap();
        c.revoke(0).unwrap();
        c.insert_root(1, Capability::new(MEM, Rights::ALL)).unwrap();
        assert_eq!(c.parent_of(1), None);
        assert_eq!(c.revoke(0), Ok(0));
        assert!(c.get(1).is_some());
    }

    #[test]
    fn retype_bumps_aligned_and_exhausts() {
        let mut c = CNode::<4>::new();
        // A 16 KiB block at 0x4000.
        let mem = Object::Untyped {
            base: 0x4000,
            size_bits: 14,
        };
        c.insert_root(0, Capability::new(mem, Rights::ALL)).unwrap();
        assert_eq!(c.retype(0, 10), Ok(0x4000)); // 1 KiB
        assert_eq!(c.retype(0, 12), Ok(0x5000)); // aligned up past the 1 KiB
        assert_eq!(c.retype(0, 13), Ok(0x6000));
        assert_eq!(c.untyped_free(0), Some(0));
        assert_eq!(c.retype(0, 12), Err(CapError::OutOfMemory));
    }

    #[test]
    fn retype_rejects_bad_requests() {
        let mut c = root_with_endpoint();
        assert_eq!(c.retype(0, 12), Err(CapError::WrongObjectType));
        c.insert_root(1, Capability::new(MEM, Rights::ALL)).unwrap();
        assert_eq!(c.retype(1, 21), Err(CapError::OutOfMemory));
        // A derived copy shares the memory, so neither may retype.
        c.derive(1, 2, Rights::ALL, None).unwrap();
        assert_eq!(c.retype(1, 12), Err(CapError::HasChildren));
        assert_eq!(c.retype(2, 12), Err(CapError::HasChildren));
        c.revoke(1).unwrap();
        assert_eq!(c.retype(1, 12), Ok(0x10_0000));
    }

    #[test]
    fn rights_debug_format() {
        extern crate std;
        use std::format;
        assert_eq!(format!("{:?}", Rights::READ | Rights::MAP), "R---M");
    }
    fn untyped_root(c: &mut CNode<16>, slot: usize, base: u64, bits: u8) {
        let mem = Object::Untyped {
            base,
            size_bits: bits,
        };
        c.insert_root(slot, Capability::new(mem, Rights::ALL))
            .unwrap();
    }

    #[test]
    fn retyped_objects_are_children_not_copies() {
        let mut c = CNode::<16>::new();
        untyped_root(&mut c, 0, 0x8000, 15);
        let pa = c.carve(0, 4).unwrap();
        let ep = Capability::new(Object::Endpoint { id: 1 }, Rights::ALL);
        c.insert_child(0, 1, ep).unwrap();
        assert_eq!(pa, 0x8000);
        // A retyped child does not block further retypes.
        assert_eq!(c.carve(0, 4), Ok(0x8010));
        assert_eq!(c.parent_of(1), Some(0));
    }

    #[test]
    fn revoke_untyped_destroys_objects_and_frees_memory() {
        let mut c = CNode::<16>::new();
        untyped_root(&mut c, 0, 0x8000, 15);
        let sub = c.carve(0, 15).unwrap(); // the whole block
        let sub_cap = Capability::new(
            Object::Untyped {
                base: sub,
                size_bits: 15,
            },
            Rights::ALL,
        );
        c.insert_child(0, 1, sub_cap).unwrap();
        c.carve(1, 4).unwrap();
        let ep = Capability::new(Object::Endpoint { id: 2 }, Rights::ALL);
        c.insert_child(1, 2, ep).unwrap();
        c.derive(2, 3, Rights::WRITE, Some(9)).unwrap();
        assert_eq!(c.carve(0, 12), Err(CapError::OutOfMemory));

        let mut gone = std::vec::Vec::new();
        assert_eq!(c.revoke_each(0, |_, cap| gone.push(cap.object)), Ok(3));
        assert!(gone.contains(&Object::Endpoint { id: 2 }));
        assert_eq!(c.untyped_free(0), Some(1 << 15), "watermark reset");
        assert_eq!(c.carve(0, 15), Ok(0x8000), "memory reusable");
    }

    #[test]
    fn kernel_carved_untyped_is_never_reset() {
        let mut c = CNode::<16>::new();
        untyped_root(&mut c, 0, 0x8000, 15);
        c.retype(0, 12).unwrap(); // kernel use, no child capability
        c.revoke(0).unwrap();
        assert_eq!(c.carve(0, 12), Ok(0x9000), "first page still in use");
    }

    #[test]
    fn copies_of_untyped_block_carving_until_revoked() {
        let mut c = CNode::<16>::new();
        untyped_root(&mut c, 0, 0x8000, 15);
        c.derive(0, 1, Rights::ALL, None).unwrap();
        assert_eq!(c.carve(0, 4), Err(CapError::HasChildren));
        assert_eq!(c.carve(1, 4), Err(CapError::HasChildren));
        c.revoke(0).unwrap();
        assert!(c.carve(0, 4).is_ok());
    }

    #[test]
    fn device_memory_carves_and_resets_like_untyped() {
        let mut c = CNode::<16>::new();
        let dev = Object::DeviceUntyped {
            base: 0xe000_0000,
            size_bits: 16,
        };
        c.insert_root(0, Capability::new(dev, Rights::ALL)).unwrap();
        assert_eq!(c.untyped_free(0), Some(1 << 16));
        let pa = c.carve(0, 12).unwrap();
        assert_eq!(pa, 0xe000_0000);
        let frame = Object::Frame {
            paddr: pa,
            size_bits: 12,
        };
        c.insert_child(0, 1, Capability::new(frame, Rights::ALL))
            .unwrap();
        assert_eq!(c.carve(0, 12), Ok(0xe000_1000));
        c.revoke(0).unwrap();
        assert_eq!(c.untyped_free(0), Some(1 << 16), "watermark reset");
    }

    #[test]
    fn rights_from_bits_drops_unknown() {
        assert_eq!(Rights::from_bits_truncate(0xff), Rights::ALL);
        assert_eq!(Rights::from_bits_truncate(0b10), Rights::WRITE);
    }
}
