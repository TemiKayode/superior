//! A formal model of capability derivation, checked against [`CNode`].
//!
//! The model is an independent specification: the derivation tree is a
//! forest of nodes with explicit child lists (the implementation uses
//! parent pointers in a flat table), and memory safety is stated as a
//! property of the live objects rather than computed from a watermark.
//!
//! [`explore`] runs every operation from every reachable state of a small
//! table, breadth first, until no new state appears (or a depth bound is
//! hit), and after each step checks that:
//!
//! - **Refinement:** the implementation's result (success or the error)
//!   is the one the model allows, and its derivation tree, capabilities
//!   and copy flags equal the model's.
//! - **No rights amplification:** every capability's rights are a subset
//!   of its parent's (and so of every ancestor's).
//! - **Badge integrity:** a copy has its parent's badge, or a new one only
//!   if the parent had none.
//! - **Well-formed tree:** every parent is an occupied slot, and there are
//!   no cycles.
//! - **Memory safety:** the model gives every carve a ghost identity and
//!   remembers which carve it came from. Live objects of two different
//!   carves may overlap only if one was carved, directly or through
//!   sub-blocks, from the other, so no byte is ever handed out twice. Every
//!   object made from an untyped block lies inside it.
//! - **Reuse:** an untyped block with nothing made from it (never used, or
//!   revoked) can always be carved again, so revoke really frees memory.
//!
//! Revoke removes exactly the model's subtree and delete splices children
//! into the grandparent, so both are covered by refinement.

use crate::cap::{CNode, CapError, Capability, Object, Rights};
use std::collections::{HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

/// Slots in the table the model checks: two boot-time roots (an untyped
/// block and an endpoint) and two free slots. With five slots the space
/// grows about sevenfold per step and no longer fits a test run.
pub const SLOTS: usize = 4;
/// The root untyped block: 64 bytes, room for four 16-byte objects.
const ROOT_MEM: Object = Object::Untyped {
    base: 0x1000,
    size_bits: 6,
};
const ROOT_EP: Object = Object::Endpoint { id: 1 };

/// One operation on the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Derive {
        src: usize,
        dst: usize,
        mask: Rights,
        badge: Option<u64>,
    },
    /// Carve an object from an untyped block, as the kernel's `Retype`
    /// does: the destination is checked first, then memory is carved.
    Retype {
        src: usize,
        dst: usize,
        frame: bool,
        bits: u8,
    },
    Delete(usize),
    Revoke(usize),
}

/// Every operation the explorer tries in every state.
pub fn alphabet() -> Vec<Op> {
    let mut ops = Vec::new();
    for src in 0..SLOTS {
        for dst in 0..SLOTS {
            if src == dst {
                continue;
            }
            for mask in [Rights::ALL, Rights::READ] {
                for badge in [None, Some(7)] {
                    ops.push(Op::Derive {
                        src,
                        dst,
                        mask,
                        badge,
                    });
                }
            }
            for (frame, bits) in [(false, 4), (false, 5), (false, 6), (true, 4)] {
                ops.push(Op::Retype {
                    src,
                    dst,
                    frame,
                    bits,
                });
            }
        }
        ops.push(Op::Delete(src));
        ops.push(Op::Revoke(src));
    }
    ops
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Node {
    slot: usize,
    cap: Capability,
    /// Made by derive (the same object as its parent).
    copy: bool,
    /// Ghost: which carve made this object (copies share it).
    origin: usize,
    children: Vec<Node>,
}

/// The specification: a forest of derivation trees.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Model {
    roots: Vec<Node>,
    /// Ghost: for each carve, the carve it was made from (None for the
    /// boot-time roots).
    carved_from: Vec<Option<usize>>,
}

/// One slot as the implementation and the model both describe it:
/// capability, parent slot, copy flag.
type Row = Option<(Capability, Option<usize>, bool)>;

impl Model {
    fn initial() -> Model {
        let leaf = |slot, object| Node {
            slot,
            cap: Capability::new(object, Rights::ALL),
            copy: false,
            origin: slot,
            children: vec![],
        };
        Model {
            roots: vec![leaf(0, ROOT_MEM), leaf(1, ROOT_EP)],
            carved_from: vec![None, None],
        }
    }

    fn find(&self, slot: usize) -> Option<&Node> {
        fn go(ns: &[Node], slot: usize) -> Option<&Node> {
            ns.iter().find_map(|n| {
                if n.slot == slot {
                    Some(n)
                } else {
                    go(&n.children, slot)
                }
            })
        }
        go(&self.roots, slot)
    }

    fn find_mut(&mut self, slot: usize) -> Option<&mut Node> {
        fn go(ns: &mut [Node], slot: usize) -> Option<&mut Node> {
            for n in ns {
                if n.slot == slot {
                    return Some(n);
                }
                if let Some(x) = go(&mut n.children, slot) {
                    return Some(x);
                }
            }
            None
        }
        go(&mut self.roots, slot)
    }

    /// Removes the node in `slot`, putting its children where it was.
    fn splice_out(&mut self, slot: usize) {
        fn go(ns: &mut Vec<Node>, slot: usize) -> bool {
            if let Some(i) = ns.iter().position(|n| n.slot == slot) {
                let n = ns.remove(i);
                // A copy of an original object (not untyped) becomes the
                // original.
                let original = !n.copy && n.cap.object.untyped().is_none();
                for (k, mut c) in n.children.into_iter().enumerate() {
                    c.copy &= !original;
                    ns.insert(i + k, c);
                }
                return true;
            }
            ns.iter_mut().any(|n| go(&mut n.children, slot))
        }
        go(&mut self.roots, slot);
    }

    fn occupied(&self, slot: usize) -> bool {
        self.find(slot).is_some()
    }

    fn slot_check(&self, slot: usize) -> Result<(), CapError> {
        if slot >= SLOTS {
            Err(CapError::SlotOutOfRange)
        } else if self.occupied(slot) {
            Err(CapError::SlotOccupied)
        } else {
            Ok(())
        }
    }

    fn need(&self, slot: usize) -> Result<&Node, CapError> {
        self.find(slot).ok_or(if slot < SLOTS {
            CapError::SlotEmpty
        } else {
            CapError::SlotOutOfRange
        })
    }

    /// Applies `op` and says what the implementation must return. For a
    /// retype the model cannot know the address (it does not model the
    /// allocator), so `carved` supplies the one the implementation chose;
    /// memory safety is then checked as an invariant.
    fn apply(&mut self, op: Op, carved: Option<u64>) -> Result<Expect, CapError> {
        match op {
            Op::Derive {
                src,
                dst,
                mask,
                badge,
            } => {
                let p = self.need(src)?.cap;
                let mut cap = Capability {
                    rights: p.rights.intersect(mask),
                    ..p
                };
                if let Some(b) = badge {
                    if !p.object.badgeable() {
                        return Err(CapError::NotBadgeable);
                    }
                    if p.badge != 0 {
                        return Err(CapError::BadgeAlreadySet);
                    }
                    cap.badge = b;
                }
                self.slot_check(dst)?;
                let origin = self.find(src).unwrap().origin;
                self.find_mut(src).unwrap().children.push(Node {
                    slot: dst,
                    cap,
                    copy: true,
                    origin,
                    children: vec![],
                });
                Ok(Expect::Done)
            }
            Op::Retype {
                src,
                dst,
                frame,
                bits,
            } => {
                let n = self.need(src)?;
                let Object::Untyped { size_bits, .. } = n.cap.object else {
                    return Err(CapError::WrongObjectType);
                };
                self.slot_check(dst)?;
                let n = self.find(src).unwrap();
                if n.copy || n.children.iter().any(|c| c.copy) {
                    return Err(CapError::HasChildren);
                }
                if bits > size_bits {
                    return Err(CapError::OutOfMemory);
                }
                let fresh = n.children.is_empty();
                let Some(base) = carved else {
                    // Out of memory is allowed only if something is still
                    // made from the block.
                    return if fresh {
                        Ok(Expect::MustCarve)
                    } else {
                        Ok(Expect::MayRunOut)
                    };
                };
                let object = if frame {
                    Object::Frame {
                        paddr: base,
                        size_bits: bits,
                    }
                } else {
                    Object::Untyped {
                        base,
                        size_bits: bits,
                    }
                };
                let origin = self.carved_from.len();
                self.carved_from.push(Some(self.find(src).unwrap().origin));
                self.find_mut(src).unwrap().children.push(Node {
                    slot: dst,
                    cap: Capability::new(object, Rights::ALL),
                    copy: false,
                    origin,
                    children: vec![],
                });
                Ok(Expect::Done)
            }
            Op::Delete(slot) => {
                self.need(slot)?;
                self.splice_out(slot);
                Ok(Expect::Done)
            }
            Op::Revoke(slot) => {
                self.need(slot)?;
                self.find_mut(slot).unwrap().children.clear();
                Ok(Expect::Done)
            }
        }
    }

    /// Whether carve `a` was made, directly or through sub-blocks, from
    /// carve `b`.
    fn within(&self, mut a: usize, b: usize) -> bool {
        while let Some(p) = self.carved_from[a] {
            if p == b {
                return true;
            }
            a = p;
        }
        false
    }

    /// No byte is handed out twice: live objects of different carves
    /// overlap only if one was carved from the other.
    fn memory_safe(&self) -> Result<(), String> {
        fn all(ns: &[Node], out: &mut Vec<(usize, usize, Object)>) {
            for n in ns {
                out.push((n.slot, n.origin, n.cap.object));
                all(&n.children, out);
            }
        }
        let mut live = Vec::new();
        all(&self.roots, &mut live);
        for &(i, oa, a) in &live {
            let Some((a0, a1)) = region(&a) else { continue };
            for &(j, ob, b) in &live {
                let Some((b0, b1)) = region(&b) else { continue };
                if oa >= ob || a0 >= b1 || b0 >= a1 {
                    continue;
                }
                if !(self.within(oa, ob) || self.within(ob, oa)) {
                    return Err(format!("slots {i} and {j}: memory handed out twice"));
                }
            }
        }
        Ok(())
    }

    /// The model as table rows, to compare with the implementation.
    fn rows(&self) -> [Row; SLOTS] {
        fn go(ns: &[Node], parent: Option<usize>, out: &mut [Row; SLOTS]) {
            for n in ns {
                out[n.slot] = Some((n.cap, parent, n.copy));
                go(&n.children, Some(n.slot), out);
            }
        }
        let mut out = [None; SLOTS];
        go(&self.roots, None, &mut out);
        out
    }
}

/// What the model says a successful-so-far operation must do.
#[derive(Debug, PartialEq)]
enum Expect {
    Done,
    /// A retype from a block with nothing made from it must succeed.
    MustCarve,
    /// A retype from a block in use may succeed or run out of memory.
    MayRunOut,
}

fn rows_of(c: &CNode<SLOTS>) -> [Row; SLOTS] {
    core::array::from_fn(|i| {
        c.get(i)
            .map(|cap| (*cap, c.parent_of(i), c.is_copy_slot(i)))
    })
}

fn region(o: &Object) -> Option<(u64, u64)> {
    match *o {
        Object::Untyped { base, size_bits } => Some((base, base + (1 << size_bits))),
        Object::Frame { paddr, size_bits } => Some((paddr, paddr + (1 << size_bits))),
        _ => None,
    }
}

/// Checks the safety invariants on the implementation's table.
fn invariants(rows: &[Row; SLOTS]) -> Result<(), String> {
    let ancestors = |mut i: usize| {
        let mut out = Vec::new();
        for _ in 0..SLOTS {
            match rows[i].and_then(|r| r.1) {
                Some(p) => {
                    out.push(p);
                    i = p;
                }
                None => return Ok(out),
            }
        }
        Err(format!("cycle through slot {i}"))
    };
    for (i, r) in rows.iter().enumerate() {
        let Some((cap, parent, copy)) = r else {
            continue;
        };
        let Some(p) = parent else { continue };
        let Some((pcap, _, _)) = rows[*p] else {
            return Err(format!("slot {i}: parent {p} is empty"));
        };
        if !pcap.rights.contains(cap.rights) {
            return Err(format!(
                "slot {i}: rights {:?} exceed parent's {:?}",
                cap.rights, pcap.rights
            ));
        }
        if *copy && pcap.badge != 0 && cap.badge != pcap.badge {
            return Err(format!("slot {i}: badge changed from {}", pcap.badge));
        }
        ancestors(i)?;
    }
    // Objects made from an untyped block lie inside it.
    for (i, r) in rows.iter().enumerate() {
        let Some((cap, Some(p), false)) = r else {
            continue;
        };
        let (Some((a0, a1)), Some((pcap, _, _))) = (region(&cap.object), rows[*p]) else {
            continue;
        };
        if let Some((p0, p1)) = region(&pcap.object)
            && (a0 < p0 || a1 > p1)
        {
            return Err(format!("slot {i}: object outside its untyped parent"));
        }
    }
    Ok(())
}

/// Runs `op` on the implementation the way the kernel does.
fn run(c: &mut CNode<SLOTS>, op: Op) -> Result<Option<u64>, CapError> {
    match op {
        Op::Derive {
            src,
            dst,
            mask,
            badge,
        } => c.derive(src, dst, mask, badge).map(|_| None),
        Op::Retype {
            src,
            dst,
            frame,
            bits,
        } => {
            let ut = *c.get(src).ok_or(if src < SLOTS {
                CapError::SlotEmpty
            } else {
                CapError::SlotOutOfRange
            })?;
            if !matches!(ut.object, Object::Untyped { .. }) {
                return Err(CapError::WrongObjectType);
            }
            if c.get(dst).is_some() {
                return Err(CapError::SlotOccupied);
            }
            let base = c.carve(src, bits)?;
            let object = if frame {
                Object::Frame {
                    paddr: base,
                    size_bits: bits,
                }
            } else {
                Object::Untyped {
                    base,
                    size_bits: bits,
                }
            };
            c.insert_child(src, dst, Capability::new(object, Rights::ALL))?;
            Ok(Some(base))
        }
        Op::Delete(s) => c.delete(s).map(|_| None),
        Op::Revoke(s) => c.revoke(s).map(|_| None),
    }
}

/// Result of an exploration.
#[derive(Debug)]
pub struct Report {
    pub states: usize,
    pub transitions: usize,
    pub depth: usize,
    /// True if no new state was left unexplored (the whole reachable space
    /// was covered), false if the depth bound stopped the search.
    pub exhaustive: bool,
}

/// Explores every state reachable within `max_depth` operations, checking
/// refinement and the invariants after each step. Returns the first
/// violation as an error, with the operations that lead to it.
pub fn explore(max_depth: usize) -> Result<Report, String> {
    let ops = alphabet();
    let mut init = CNode::<SLOTS>::new();
    init.insert_root(0, Capability::new(ROOT_MEM, Rights::ALL))
        .unwrap();
    init.insert_root(1, Capability::new(ROOT_EP, Rights::ALL))
        .unwrap();
    let model = Model::initial();
    assert_eq!(rows_of(&init), model.rows());

    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    seen.insert(init.fingerprint());
    queue.push_back((init, model, Vec::<Op>::new()));
    let (mut transitions, mut depth, mut cut) = (0, 0, false);
    while let Some((imp, model, trace)) = queue.pop_front() {
        depth = depth.max(trace.len());
        for &op in &ops {
            transitions += 1;
            let mut i2 = imp.clone();
            let mut m2 = model.clone();
            let got = run(&mut i2, op);
            let fail = |why: String| format!("{why}\n  after {trace:?}\n  then {op:?}");
            let want = m2.apply(op, got.ok().flatten());
            match (&got, &want) {
                (Ok(_), Ok(Expect::Done)) => {}
                (Err(CapError::OutOfMemory), Ok(Expect::MayRunOut)) => {}
                (Err(e), Ok(Expect::MustCarve)) => {
                    return Err(fail(format!(
                        "a block with nothing made from it refused: {e:?}"
                    )));
                }
                (Err(a), Err(b)) if a == b => {}
                _ => return Err(fail(format!("implementation {got:?}, model {want:?}"))),
            }
            if got.is_err() {
                continue;
            }
            let rows = rows_of(&i2);
            if rows != m2.rows() {
                return Err(fail(format!(
                    "tables differ:\n  impl  {rows:?}\n  model {:?}",
                    m2.rows()
                )));
            }
            invariants(&rows).map_err(fail)?;
            i2.check_links().map_err(fail)?;
            m2.memory_safe().map_err(fail)?;
            if seen.insert(i2.fingerprint()) {
                if trace.len() + 1 >= max_depth {
                    cut = true;
                    continue;
                }
                let mut t = trace.clone();
                t.push(op);
                queue.push_back((i2, m2, t));
            }
        }
    }
    Ok(Report {
        states: seen.len(),
        transitions,
        depth: depth + 1,
        exhaustive: !cut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn capability_derivation_model_holds_to_depth_6() {
        let r = explore(6).unwrap_or_else(|e| panic!("model violated: {e}"));
        assert!(r.states > 10_000, "explored too little: {r:?}");
    }

    /// The whole reachable state space: run by `cargo xtask test` in
    /// release mode (about two minutes).
    #[test]
    #[ignore]
    fn capability_derivation_model_holds_on_every_reachable_state() {
        let r = explore(usize::MAX).unwrap_or_else(|e| panic!("model violated: {e}"));
        std::println!(
            "model: {} states, {} transitions, longest path {} operations, exhaustive {}",
            r.states,
            r.transitions,
            r.depth,
            r.exhaustive
        );
        assert!(r.exhaustive, "the whole state space must be covered");
    }

    #[test]
    fn the_checker_catches_a_rights_amplifying_bug() {
        // Corrupt one derived capability's rights: the invariant must fail.
        let mut rows: [Row; SLOTS] = [None; SLOTS];
        let ep = Capability::new(ROOT_EP, Rights::READ);
        rows[0] = Some((ep, None, false));
        rows[1] = Some((Capability::new(ROOT_EP, Rights::ALL), Some(0), true));
        assert!(invariants(&rows).unwrap_err().contains("rights"));
    }

    #[test]
    fn the_checker_catches_memory_handed_out_twice() {
        // Two carves from the root block, both given the same address (as
        // a broken allocator would): memory safety must fail.
        let mut m = Model::initial();
        let carve = |m: &mut Model, dst| {
            m.apply(
                Op::Retype {
                    src: 0,
                    dst,
                    frame: true,
                    bits: 4,
                },
                Some(0x1000),
            )
            .unwrap()
        };
        carve(&mut m, 2);
        assert!(m.memory_safe().is_ok(), "one frame is fine");
        carve(&mut m, 3);
        assert!(m.memory_safe().unwrap_err().contains("twice"));
    }

    #[test]
    fn the_checker_catches_a_badge_change_and_a_cycle() {
        let mut rows: [Row; SLOTS] = [None; SLOTS];
        let mut b = Capability::new(ROOT_EP, Rights::ALL);
        b.badge = 5;
        rows[0] = Some((b, None, false));
        let mut c = b;
        c.badge = 6;
        rows[1] = Some((c, Some(0), true));
        assert!(invariants(&rows).unwrap_err().contains("badge"));
        rows[0] = Some((b, Some(1), false));
        rows[1] = Some((b, Some(0), true));
        assert!(invariants(&rows).unwrap_err().contains("cycle"));
    }
}
