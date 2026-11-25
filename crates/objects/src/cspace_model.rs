//! A model of two-level CSpace addressing, checked against
//! [`Table::resolve`].
//!
//! The specification works forwards: from what each root slot holds it
//! lists every address that slot gives meaning to and the slot each one
//! names (root index, then the CNode's guard, then every index of the
//! CNode). The implementation works backwards, decoding an address. They
//! must agree on every address up to one bit past the CSpace's depth.
//!
//! Three checks, each stating the same properties after every step:
//!
//! - **Agreement:** every address resolves exactly as the specification
//!   says, or not at all where it says none.
//! - **Containment:** a resolved slot lies inside the CNode the address's
//!   root slot names, and the address carries that CNode's guard; so an
//!   address never resolves through a table its root slot does not name.
//! - **Guard integrity:** every CNode capability's badge is a guard, and
//!   a copy has its parent's guard, or a new one only if the parent had
//!   none.
//!
//! [`single_slots`] tries every content of one root slot (resolution reads
//! only the root slot an address names, so slots are independent) for
//! every root size and depth. [`explore`] runs every sequence of copies
//! (with and without guards), deletes and revokes from a small table,
//! breadth first, to a depth bound. [`simulate`] runs seeded
//! random sequences on a bigger table.

use crate::cap::{CNode, CapError, Capability, Object, Rights, Table, guard, guard_of};
use std::collections::{HashMap, HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec::Vec;

/// The slots every address up to `depth + 1` bits names, by the
/// specification: forwards from each root slot's capability.
fn spec(table: &Table, root: usize, root_bits: u8, depth: u8) -> HashMap<u64, usize> {
    let mut map = HashMap::new();
    if root_bits >= depth {
        return map;
    }
    let rest = depth - root_bits;
    for ri in 0..1u64 << root_bits {
        let Some(cap) = table.get(root + ri as usize) else {
            continue;
        };
        let Object::CNode { base, size_bits } = cap.object else {
            continue;
        };
        let Some((value, bits)) = guard_of(cap.badge) else {
            continue;
        };
        if bits as u32 + size_bits as u32 != rest as u32 {
            continue;
        }
        for li in 0..1u64 << size_bits {
            let addr = ri << rest | (value as u64) << size_bits | li;
            let old = map.insert(addr, base as usize + li as usize);
            assert!(old.is_none(), "the specification names address {addr:#x} twice");
        }
    }
    map
}

/// Checks agreement and containment for every address of up to
/// `depth + 1` bits.
fn check(table: &Table, root: usize, root_bits: u8, depth: u8) -> Result<(), String> {
    check_with(table, root, root_bits, depth, |cptr| table.resolve(root, root_bits, depth, cptr))
}

/// [`check`] of the resolver `resolve` (to show a wrong one is caught).
fn check_with(
    table: &Table,
    root: usize,
    root_bits: u8,
    depth: u8,
    resolve: impl Fn(u64) -> Option<usize>,
) -> Result<(), String> {
    let want = spec(table, root, root_bits, depth);
    for cptr in 0..1u64 << (depth + 1).min(20) {
        let got = resolve(cptr);
        if got != want.get(&cptr).copied() {
            return Err(format!(
                "root bits {root_bits}, depth {depth}: address {cptr:#x} resolves to {got:?}, \
                 the specification says {:?}",
                want.get(&cptr)
            ));
        }
        let Some(slot) = got else { continue };
        let rest = depth - root_bits;
        let named = table.get(root + (cptr >> rest) as usize).map(|c| (c.object, c.badge));
        let Some((Object::CNode { base, size_bits }, badge)) = named else {
            return Err(format!("address {cptr:#x} resolved through a root slot with no CNode"));
        };
        let (value, _) = guard_of(badge).ok_or("a CNode's badge is no guard")?;
        let inside = (base as usize..base as usize + (1 << size_bits)).contains(&slot);
        let low = cptr & ((1 << rest) - 1);
        if !inside || low >> size_bits != value as u64 {
            return Err(format!("address {cptr:#x} resolved outside its CNode or past its guard"));
        }
    }
    Ok(())
}

/// Guard integrity over the whole table.
fn guards_hold(table: &Table) -> Result<(), String> {
    for s in 0..table.capacity() {
        let Some(c) = table.get(s) else { continue };
        if matches!(c.object, Object::CNode { .. }) && guard_of(c.badge).is_none() {
            return Err(format!("slot {s}: CNode badge {:#x} is no guard", c.badge));
        }
        if let Some(p) = table.parent_of(s).and_then(|p| table.get(p)) {
            if p.object == c.object && p.badge != 0 && p.badge != c.badge {
                return Err(format!("slot {s}: a copy changed its parent's guard"));
            }
        }
    }
    Ok(())
}

/// Every content one root slot can have, for [`single_slots`]: nothing,
/// an endpoint, and CNodes of 1 to 8 slots with every guard of up to 3
/// bits, plus badges that are no guard (a CNode cannot be given one, but
/// the resolver must still refuse it).
fn slot_contents() -> Vec<Option<Capability>> {
    let mut v = std::vec![None, Some(Capability::new(Object::Endpoint { id: 1 }, Rights::ALL))];
    for size_bits in 0..=3u8 {
        let cnode = Object::CNode { base: 64, size_bits };
        for bits in 0..=3u8 {
            for value in 0..1u32 << bits {
                v.push(Some(Capability { badge: guard(value, bits), ..Capability::new(cnode, Rights::ALL) }));
            }
        }
        for badge in [guard(2, 1), guard(0, 33), 1 << 40, guard(5, 0)] {
            v.push(Some(Capability { badge, ..Capability::new(cnode, Rights::ALL) }));
        }
    }
    v
}

/// Every content of every root slot, for root CNodes of 1 to 4 bits and
/// every depth from one past the root to 9 bits. Returns the cases tried.
pub fn single_slots() -> Result<usize, String> {
    let mut cases = 0;
    for content in slot_contents() {
        for root_bits in 1..=4u8 {
            for ri in [0, (1usize << root_bits) - 1] {
                let mut t = CNode::<128>::new();
                if let Some(cap) = content {
                    t.insert_root(ri, cap).unwrap();
                }
                for depth in root_bits..=9 {
                    check(&t, 0, root_bits, depth)?;
                    cases += 1;
                }
            }
        }
    }
    Ok(cases)
}

/// The explored table: a root CNode of 2 slots (0, 1); two second-level
/// CNodes' originals, of 2 slots at 8 and of 4 slots at 12 (slots 2 and
/// 3); an endpoint (4); a free slot (5). Slots 8 to 15 are the
/// second-level CNodes' own slots.
const ROOT_BITS: u8 = 1;
const SLOTS: usize = 16;
const PICKS: [usize; 6] = [0, 1, 2, 3, 4, 5];

fn initial() -> CNode<SLOTS> {
    let mut t = CNode::new();
    let cnode = |base, size_bits| Capability::new(Object::CNode { base, size_bits }, Rights::ALL);
    t.insert_root(2, cnode(8, 1)).unwrap();
    t.insert_root(3, cnode(12, 2)).unwrap();
    t.insert_root(4, Capability::new(Object::Endpoint { id: 1 }, Rights::ALL)).unwrap();
    t
}

/// One operation of [`explore`] and [`simulate`].
#[derive(Clone, Copy, Debug)]
pub enum Op {
    Copy { src: usize, dst: usize, badge: Option<u64> },
    Delete(usize),
    Revoke(usize),
}

/// Badges tried on copies: none, guards of 0 to 2 bits, and badges that
/// are no guard.
const BADGES: [Option<u64>; 8] = [
    None,
    Some(guard(0, 1)),
    Some(guard(1, 1)),
    Some(guard(1, 2)),
    Some(guard(3, 2)),
    Some(guard(2, 1)),
    Some(guard(0, 40)),
    Some(1 << 41),
];

fn alphabet() -> Vec<Op> {
    let mut ops = Vec::new();
    for src in PICKS {
        for dst in PICKS {
            if src != dst {
                for badge in BADGES {
                    ops.push(Op::Copy { src, dst, badge });
                }
            }
        }
        ops.push(Op::Delete(src));
        ops.push(Op::Revoke(src));
    }
    ops
}

/// Applies `op`, checking the result is the one the rules allow: a copy
/// keeps rights and object, and takes a badge only onto an unbadged
/// badgeable capability, and onto a CNode only a guard (the badge is
/// checked before the destination, as `derive` does).
fn step<const N: usize>(t: &mut CNode<N>, op: Op) -> Result<(), String> {
    match op {
        Op::Copy { src, dst, badge } => {
            let parent = t.get(src).copied();
            let occupied = t.get(dst).is_some();
            let r = t.derive(src, dst, Rights::ALL, badge);
            let want = match (parent, badge) {
                (None, _) => Err(CapError::SlotEmpty),
                (Some(p), Some(_)) if !p.object.badgeable() => Err(CapError::NotBadgeable),
                (Some(p), Some(_)) if p.badge != 0 => Err(CapError::BadgeAlreadySet),
                (Some(Capability { object: Object::CNode { .. }, .. }), Some(b)) if guard_of(b).is_none() => {
                    Err(CapError::BadGuard)
                }
                (Some(_), _) if occupied => Err(CapError::SlotOccupied),
                _ => Ok(()),
            };
            if r != want {
                return Err(format!("{op:?}: got {r:?}, the rules say {want:?}"));
            }
            if r.is_ok() {
                let p = parent.unwrap();
                let c = *t.get(dst).unwrap();
                if c.object != p.object || c.badge != badge.unwrap_or(p.badge) {
                    return Err(format!("{op:?}: the copy is not its parent's object and guard"));
                }
            }
            Ok(())
        }
        Op::Delete(s) => {
            let _ = t.delete(s);
            Ok(())
        }
        Op::Revoke(s) => {
            let _ = t.revoke(s);
            Ok(())
        }
    }
}

fn all_checks(t: &Table) -> Result<(), String> {
    guards_hold(t)?;
    for depth in ROOT_BITS + 1..=5 {
        check(t, 0, ROOT_BITS, depth)?;
    }
    Ok(())
}

/// The result of [`explore`].
#[derive(Debug)]
pub struct Report {
    pub states: usize,
    pub transitions: usize,
    pub depth: usize,
}

/// Every reachable state of the table, breadth first, to `max_depth`
/// operations (or until no new state appears), with every check after
/// every step.
pub fn explore(max_depth: usize) -> Result<Report, String> {
    let ops = alphabet();
    let start = initial();
    let mut seen = HashSet::new();
    seen.insert(start.fingerprint());
    let mut queue = VecDeque::from([(start, 0usize)]);
    let (mut transitions, mut deepest) = (0, 0);
    all_checks(&initial())?;
    while let Some((t, d)) = queue.pop_front() {
        deepest = deepest.max(d);
        if d == max_depth {
            continue;
        }
        for &op in &ops {
            let mut next = t.clone();
            step(&mut next, op)?;
            next.check_links()?;
            all_checks(&next).map_err(|e| format!("after {op:?} at depth {}: {e}", d + 1))?;
            transitions += 1;
            if seen.insert(next.fingerprint()) {
                queue.push_back((next, d + 1));
            }
        }
    }
    Ok(Report { states: seen.len(), transitions, depth: deepest })
}

/// Seeded random sequences of `steps` operations on a table with a root
/// CNode of 8 slots and six second-level CNodes, every check after every
/// step. Each seed replays identically.
pub fn simulate(seed: u64, steps: usize) -> Result<(), String> {
    const N: usize = 128;
    let mut t = CNode::<N>::new();
    // Originals of second-level CNodes of 1 to 16 slots, at 64 on, in
    // slots 8 to 13; an endpoint in 14; 15 to 19 free.
    let mut base = 64u32;
    for (i, size_bits) in [0u8, 1, 2, 3, 4, 2].into_iter().enumerate() {
        t.insert_root(8 + i, Capability::new(Object::CNode { base, size_bits }, Rights::ALL)).unwrap();
        base += 1 << size_bits;
    }
    t.insert_root(14, Capability::new(Object::Endpoint { id: 1 }, Rights::ALL)).unwrap();
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rand = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    for i in 0..steps {
        let pick = |r: u64| r as usize;
        let op = match rand(4) {
            0 | 1 => {
                let bits = rand(4) as u8;
                let badge = match rand(5) {
                    0 => None,
                    1 => Some(rand(1 << 41)),
                    _ => Some(guard(rand(1 << bits) as u32, bits)),
                };
                Op::Copy { src: pick(rand(20)), dst: pick(rand(20)), badge }
            }
            2 => Op::Delete(pick(rand(20))),
            _ => Op::Revoke(pick(rand(20))),
        };
        let mut checked = t.clone();
        step(&mut checked, op).map_err(|e| format!("seed {seed} step {i}: {e}"))?;
        t = checked;
        t.check_links().map_err(|e| format!("seed {seed} step {i}: {e}"))?;
        guards_hold(&t).map_err(|e| format!("seed {seed} step {i}: {e}"))?;
        for depth in 4..=8 {
            check(&t, 0, 3, depth).map_err(|e| format!("seed {seed} step {i} {op:?}: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_root_slot_content_resolves_as_specified() {
        let cases = single_slots().unwrap();
        assert!(cases > 4_000, "{cases} cases");
    }

    #[test]
    fn two_level_resolution_holds_to_depth_3() {
        let r = explore(3).unwrap();
        std::println!("{r:?}");
        assert!(r.states > 1_000 && r.depth == 3, "{r:?}");
    }

    #[test]
    #[ignore]
    fn two_level_resolution_holds_to_depth_5() {
        let r = explore(5).unwrap();
        std::println!("{r:?}");
        assert_eq!(r.depth, 5, "{r:?}");
    }

    #[test]
    fn two_level_resolution_holds_in_random_runs() {
        for seed in 0..200 {
            simulate(seed, 400).unwrap();
        }
    }

    #[test]
    #[ignore]
    fn two_level_resolution_holds_in_long_random_runs() {
        for seed in 0..5_000 {
            simulate(seed, 2_000).unwrap();
        }
    }

    #[test]
    fn the_checker_catches_wrong_resolvers() {
        // A CNode of 2 slots in root slot 1 with guard 1 of 1 bit, depth 3:
        // address 0b111 is its slot 1 (table index 9), 0b101 is nothing.
        let mut t = CNode::<16>::new();
        let cn = Capability {
            badge: guard(1, 1),
            ..Capability::new(Object::CNode { base: 8, size_bits: 1 }, Rights::ALL)
        };
        t.insert_root(1, cn).unwrap();
        check(&t, 0, 1, 3).unwrap();
        // One that ignores the guard takes 0b101 to slot 9 too.
        let no_guard = |c: u64| ((c >> 2) == 1).then(|| 8 + (c & 1) as usize);
        assert!(check_with(&t, 0, 1, 3, no_guard).is_err());
        // One that ignores the depth also takes 0b1111 (4 bits) somewhere.
        let no_depth = |c: u64| t.resolve(0, 1, 3, c & 0b111);
        assert!(check_with(&t, 0, 1, 3, no_depth).is_err());
        // One that indexes past the CNode's end lands outside it.
        let overrun = |c: u64| t.resolve(0, 1, 3, c).map(|s| s + 1);
        assert!(check_with(&t, 0, 1, 3, overrun).is_err());
    }
}
