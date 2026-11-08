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

use core::fmt;

/// Rights over an object, as a bit set.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    Untyped { base: u64, size_bits: u8 },
    Endpoint { id: u32 },
    Notification { id: u32 },
    Frame { paddr: u64, size_bits: u8 },
}

impl Object {
    /// Only communication objects carry badges; the badge tells a server
    /// which client or which object a message is about.
    pub const fn badgeable(&self) -> bool {
        matches!(self, Object::Endpoint { .. } | Object::Notification { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

#[derive(Clone, Copy)]
struct Slot {
    cap: Option<Capability>,
    parent: Option<u32>,
    /// Scratch mark used during revoke; always false between calls.
    doomed: bool,
}

const EMPTY: Slot = Slot {
    cap: None,
    parent: None,
    doomed: false,
};

/// A fixed-size table of capability slots.
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
            parent: None,
            doomed: false,
        };
        Ok(())
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
            doomed: false,
        };
        Ok(())
    }

    /// Removes every capability derived (directly or transitively) from
    /// `slot`, leaving `slot` itself in place. Returns how many were removed.
    pub fn revoke(&mut self, slot: usize) -> Result<usize, CapError> {
        self.get(slot).ok_or(self.missing(slot))?;
        // Mark first, then clear: clearing as we go would cut ancestor
        // chains that later slots still need to walk.
        for i in 0..N {
            if i != slot && self.slots[i].cap.is_some() && self.descends_from(i, slot) {
                self.slots[i].doomed = true;
            }
        }
        let mut removed = 0;
        for s in self.slots.iter_mut().filter(|s| s.doomed) {
            *s = EMPTY;
            removed += 1;
        }
        Ok(removed)
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
    fn rights_debug_format() {
        extern crate std;
        use std::format;
        assert_eq!(format!("{:?}", Rights::READ | Rights::MAP), "R---M");
    }
}
