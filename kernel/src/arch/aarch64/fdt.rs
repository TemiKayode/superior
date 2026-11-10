//! Just enough of a flattened device tree reader to find RAM: the `reg`
//! ranges of the root's `memory` nodes. Every read is bounds-checked
//! against the tree's stated size.

pub const MAX_RANGES: usize = 4;
const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;
/// Refuse absurd sizes before trusting the header.
const MAX_SIZE: u64 = 1 << 20;

fn be32(addr: u64) -> u32 {
    // SAFETY: callers bounds-check against the tree, which lies in RAM
    // identity-mapped for the kernel.
    u32::from_be(unsafe { core::ptr::read_unaligned(addr as *const u32) })
}

fn byte(addr: u64) -> u8 {
    // SAFETY: as in `be32`.
    unsafe { core::ptr::read(addr as *const u8) }
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

fn cells(addr: u64, n: u32) -> u64 {
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

/// The base address (first `reg` entry) of the first top-level node whose
/// `compatible` list includes `want`, and the GIC interrupt ID of its first
/// `interrupts` entry (three cells: SPI or PPI, number, flags), if any.
pub fn find_device(dtb: u64, want: &[u8]) -> Option<(u64, Option<u32>)> {
    if !valid(dtb) {
        return None;
    }
    let end = dtb + size(dtb);
    let structs = dtb + be32(dtb + 8) as u64;
    let strings = dtb + be32(dtb + 12) as u64;
    let name_is = |off: u32, want: &[u8]| -> bool {
        let at = strings + off as u64;
        at + (want.len() as u64) < end
            && want
                .iter()
                .enumerate()
                .all(|(i, &c)| byte(at + i as u64) == c)
            && byte(at + want.len() as u64) == 0
    };
    // Whether the NUL-separated string list at [value, value + len)
    // contains `want`.
    let list_has = |value: u64, len: u64| -> bool {
        let mut s = value;
        while s < value + len {
            let mut e = s;
            while e < value + len && byte(e) != 0 {
                e += 1;
            }
            if e - s == want.len() as u64
                && want
                    .iter()
                    .enumerate()
                    .all(|(i, &c)| byte(s + i as u64) == c)
            {
                return true;
            }
            s = e + 1;
        }
        false
    };
    let mut addr_cells = 2u32;
    let mut depth = 0u32;
    let (mut matched, mut reg, mut irq) = (false, None, None);
    let mut p = structs;
    while p + 4 <= end {
        let token = be32(p);
        p += 4;
        match token {
            BEGIN_NODE => {
                depth += 1;
                while p < end && byte(p) != 0 {
                    p += 1;
                }
                p = (p + 1 + 3) & !3;
                if depth == 2 {
                    (matched, reg, irq) = (false, None, None);
                }
            }
            END_NODE => {
                if depth == 2 && matched {
                    if let Some(r) = reg {
                        return Some((r, irq));
                    }
                }
                depth = depth.saturating_sub(1);
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
                } else if depth == 2 && name_is(name, b"compatible") {
                    matched |= list_has(value, len);
                } else if depth == 2
                    && name_is(name, b"reg")
                    && (1..=2).contains(&addr_cells)
                    && len >= 4 * addr_cells as u64
                {
                    reg = Some(cells(value, addr_cells));
                } else if depth == 2 && name_is(name, b"interrupts") && len >= 12 {
                    // SPIs are numbered from ID 32, PPIs from 16.
                    let base = if be32(value) == 0 { 32 } else { 16 };
                    irq = Some(base + be32(value + 4));
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
