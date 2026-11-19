//! Just enough of a flattened device tree reader to find RAM (the `reg`
//! ranges of the root's `memory` nodes), a device's properties by its
//! `compatible` string (at any depth, with the address and size cells its
//! parent and it declare), and a 64-bit property of `/chosen`. Every read
//! is bounds-checked against the tree's stated size.

/// RAM ranges read: as many as the UEFI loader writes.
pub const MAX_RANGES: usize = 32;
const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;
/// Refuse absurd sizes before trusting the header (QEMU's `virt` pads its
/// tree to just over 1 MiB).
const MAX_SIZE: u64 = 4 << 20;

fn be32(addr: u64) -> u32 {
    // SAFETY: callers bounds-check against the tree, which lies in RAM
    // the kernel maps.
    u32::from_be(unsafe { core::ptr::read_unaligned(super::vm::phys_ptr(addr) as *const u32) })
}

fn byte(addr: u64) -> u8 {
    // SAFETY: as in `be32`.
    unsafe { core::ptr::read(super::vm::phys_ptr(addr)) }
}

/// Whether a device tree header is at `dtb`, which must lie in the RAM the
/// kernel maps.
pub fn valid(dtb: u64) -> bool {
    dtb.is_multiple_of(8)
        && (0x4000_0000..0x8000_0000).contains(&dtb)
        && be32(dtb) == MAGIC
        && (40..=MAX_SIZE).contains(&size(dtb))
}

/// The tree's total size in bytes.
pub fn size(dtb: u64) -> u64 {
    be32(dtb + 4) as u64
}

/// The value of `n` 32-bit cells at `addr` (at most two count).
pub fn cells(addr: u64, n: u32) -> u64 {
    (0..n as u64).fold(0, |acc, i| (acc << 32) | be32(addr + 4 * i) as u64)
}

/// Fills `out` with the (base, size) RAM ranges; returns how many, or
/// `None` if there is no valid tree or no memory node.
pub fn memory(dtb: u64, out: &mut [(u64, u64); MAX_RANGES]) -> Option<usize> {
    if !valid(dtb) {
        return None;
    }
    let end = dtb + size(dtb);
    let structs = dtb + be32(dtb + 8) as u64;
    let strings = dtb + be32(dtb + 12) as u64;
    // A NUL-terminated name in the strings block.
    let name_is = |off: u32, want: &[u8]| -> bool {
        let at = strings + off as u64;
        at + (want.len() as u64) < end
            && want
                .iter()
                .enumerate()
                .all(|(i, &c)| byte(at + i as u64) == c)
            && byte(at + want.len() as u64) == 0
    };
    let (mut addr_cells, mut size_cells) = (2u32, 1u32);
    let mut depth = 0u32;
    let mut in_memory = false;
    let mut n = 0;
    let mut p = structs;
    while p + 4 <= end {
        let token = be32(p);
        p += 4;
        match token {
            BEGIN_NODE => {
                depth += 1;
                let start = p;
                while p < end && byte(p) != 0 {
                    p += 1;
                }
                let name_len = p - start;
                in_memory = depth == 2
                    && name_len >= 6
                    && b"memory"
                        .iter()
                        .enumerate()
                        .all(|(i, &c)| byte(start + i as u64) == c);
                p = (p + 1 + 3) & !3;
            }
            END_NODE => {
                depth = depth.saturating_sub(1);
                in_memory = false;
            }
            PROP => {
                if p + 8 > end {
                    return None;
                }
                let len = be32(p) as u64;
                let name = be32(p + 4);
                let value = p + 8;
                if value + len > end {
                    return None;
                }
                if depth == 1 && len == 4 && name_is(name, b"#address-cells") {
                    addr_cells = be32(value);
                } else if depth == 1 && len == 4 && name_is(name, b"#size-cells") {
                    size_cells = be32(value);
                } else if in_memory && name_is(name, b"reg") {
                    if !(1..=2).contains(&addr_cells) || !(1..=2).contains(&size_cells) {
                        return None;
                    }
                    let entry = 4 * (addr_cells + size_cells) as u64;
                    let mut q = value;
                    while q + entry <= value + len && n < MAX_RANGES {
                        let base = cells(q, addr_cells);
                        let sz = cells(q + 4 * addr_cells as u64, size_cells);
                        if sz > 0 {
                            out[n] = (base, sz);
                            n += 1;
                        }
                        q += entry;
                    }
                }
                p = (value + len + 3) & !3;
            }
            NOP => {}
            END => break,
            _ => return None,
        }
    }
    (n > 0).then_some(n)
}

/// The 64-bit value of the property `want` of `/chosen` (two cells, as
/// the UEFI loader writes them), if it has one.
pub fn chosen_u64(dtb: u64, want: &[u8]) -> Option<u64> {
    if !valid(dtb) {
        return None;
    }
    let end = dtb + size(dtb);
    let structs = dtb + be32(dtb + 8) as u64;
    let strings = dtb + be32(dtb + 12) as u64;
    let name_is = |off: u32| -> bool {
        let at = strings + off as u64;
        at + (want.len() as u64) < end
            && want
                .iter()
                .enumerate()
                .all(|(i, &c)| byte(at + i as u64) == c)
            && byte(at + want.len() as u64) == 0
    };
    let mut depth = 0u32;
    let mut in_chosen = false;
    let mut p = structs;
    while p + 4 <= end {
        let token = be32(p);
        p += 4;
        match token {
            BEGIN_NODE => {
                depth += 1;
                let start = p;
                while p < end && byte(p) != 0 {
                    p += 1;
                }
                in_chosen = depth == 2
                    && p - start == 6
                    && b"chosen"
                        .iter()
                        .enumerate()
                        .all(|(i, &c)| byte(start + i as u64) == c);
                p = (p + 1 + 3) & !3;
            }
            END_NODE => {
                depth = depth.saturating_sub(1);
                in_chosen = false;
            }
            PROP => {
                if p + 8 > end {
                    return None;
                }
                let len = be32(p) as u64;
                let name = be32(p + 4);
                let value = p + 8;
                if value + len > end {
                    return None;
                }
                if in_chosen && len == 8 && name_is(name) {
                    return Some(cells(value, 2));
                }
                p = (value + len + 3) & !3;
            }
            NOP => {}
            END => break,
            _ => return None,
        }
    }
    None
}

/// Nodes nested deeper than this are not looked into.
const MAX_DEPTH: usize = 16;

/// A property of a node: where its value is and how long, the address and
/// size cells its parent declares (which its `reg` is written in), and
/// those it declares (which its children's, and its `ranges`'s child
/// side, are).
#[derive(Clone, Copy)]
pub struct Prop {
    pub at: u64,
    pub len: u64,
    pub parent_cells: (u32, u32),
    pub own_cells: (u32, u32),
}

impl Prop {
    /// The `i`th 32-bit cell.
    pub fn cell(&self, i: u64) -> Option<u32> {
        (4 * i + 4 <= self.len).then(|| be32(self.at + 4 * i))
    }

    /// `n` cells from cell `i`, as one number.
    pub fn cells(&self, i: u64, n: u32) -> Option<u64> {
        (n <= 2 && 4 * (i + n as u64) <= self.len).then(|| cells(self.at + 4 * i, n))
    }

    /// Whether it is the string `value`.
    pub fn is(&self, value: &[u8]) -> bool {
        self.len == value.len() as u64 + 1
            && value.iter().enumerate().all(|(i, &c)| byte(self.at + i as u64) == c)
            && byte(self.at + value.len() as u64) == 0
    }
}

/// Property `name` of the first node, at any depth, whose `compatible`
/// list includes `compat`.
pub fn prop(dtb: u64, compat: &[u8], name: &[u8]) -> Option<Prop> {
    if !valid(dtb) {
        return None;
    }
    let end = dtb + size(dtb);
    let structs = dtb + be32(dtb + 8) as u64;
    let strings = dtb + be32(dtb + 12) as u64;
    let bytes_are = |at: u64, want: &[u8]| -> bool {
        at + (want.len() as u64) < end
            && want
                .iter()
                .enumerate()
                .all(|(i, &c)| byte(at + i as u64) == c)
            && byte(at + want.len() as u64) == 0
    };
    // Whether the NUL-separated string list at [value, value + len)
    // contains `compat`.
    let list_has = |value: u64, len: u64| -> bool {
        let mut s = value;
        while s < value + len {
            if bytes_are(s, compat) {
                return true;
            }
            while s < value + len && byte(s) != 0 {
                s += 1;
            }
            s += 1;
        }
        false
    };
    // Per depth: the cells the node there declares (2 and 1 unless it
    // says), whether it matched, and the wanted property's value.
    let mut decl = [(2u32, 1u32); MAX_DEPTH + 1];
    let mut matched = [false; MAX_DEPTH + 1];
    let mut found: [Option<(u64, u64)>; MAX_DEPTH + 1] = [None; MAX_DEPTH + 1];
    let mut depth = 0usize;
    let mut p = structs;
    while p + 4 <= end {
        let token = be32(p);
        p += 4;
        match token {
            BEGIN_NODE => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return None;
                }
                (decl[depth], matched[depth], found[depth]) = ((2, 1), false, None);
                while p < end && byte(p) != 0 {
                    p += 1;
                }
                p = (p + 1 + 3) & !3;
            }
            END_NODE => {
                if depth == 0 {
                    return None;
                }
                if matched[depth] {
                    if let Some((at, len)) = found[depth] {
                        return Some(Prop { at, len, parent_cells: decl[depth - 1], own_cells: decl[depth] });
                    }
                }
                depth -= 1;
            }
            PROP => {
                if p + 8 > end {
                    return None;
                }
                let len = be32(p) as u64;
                let n = strings + be32(p + 4) as u64;
                let v = p + 8;
                if v + len > end {
                    return None;
                }
                if len == 4 && bytes_are(n, b"#address-cells") {
                    decl[depth].0 = be32(v);
                } else if len == 4 && bytes_are(n, b"#size-cells") {
                    decl[depth].1 = be32(v);
                }
                if bytes_are(n, b"compatible") {
                    matched[depth] |= list_has(v, len);
                }
                if bytes_are(n, name) {
                    found[depth] = Some((v, len));
                }
                p = (v + len + 3) & !3;
            }
            NOP => {}
            END => break,
            _ => return None,
        }
    }
    None
}

/// The `i`th `reg` entry (base, size) of the first node compatible with
/// `compat`.
pub fn reg(dtb: u64, compat: &[u8], i: u64) -> Option<(u64, u64)> {
    let r = prop(dtb, compat, b"reg")?;
    let (a, s) = r.parent_cells;
    if !(1..=2).contains(&a) || s > 2 {
        return None;
    }
    let at = i * (a + s) as u64;
    Some((r.cells(at, a)?, if s == 0 { 0 } else { r.cells(at + a as u64, s)? }))
}

/// The GIC interrupt ID of the `i`th `interrupts` entry (three cells: SPI
/// or PPI, number, flags) of the first node compatible with `compat`.
pub fn irq(dtb: u64, compat: &[u8], i: u64) -> Option<u32> {
    let r = prop(dtb, compat, b"interrupts")?;
    // SPIs are numbered from ID 32, PPIs from 16.
    let base = if r.cell(3 * i)? == 0 { 32 } else { 16 };
    Some(base + r.cell(3 * i + 1)?)
}

/// The first `reg` entry's base and the first interrupt of the first node
/// compatible with `want`.
pub fn find_device(dtb: u64, want: &[u8]) -> Option<(u64, Option<u32>)> {
    Some((reg(dtb, want, 0)?.0, irq(dtb, want, 0)))
}

/// Whether the first node compatible with `compat` has the string
/// property `name` equal to `value`.
pub fn device_prop_is(dtb: u64, compat: &[u8], name: &[u8], value: &[u8]) -> bool {
    prop(dtb, compat, name).is_some_and(|p| p.is(value))
}
