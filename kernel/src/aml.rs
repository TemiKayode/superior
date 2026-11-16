//! Just enough of ACPI's AML to find how the PCI root bridge's interrupt
//! pins reach the I/O APIC (its `_PRT`, PCI routing table, on x86-64) and
//! the windows of addresses it decodes (its `_CRS`, on AArch64), read from
//! the DSDT's bytecode without running any of it.
//!
//! The DSDT is walked as a tree of definitions (scopes, devices, names,
//! methods and the like); the root bridge is the device named PNP0A08 or
//! PNP0A03 (`_HID` or `_CID`). Its `_PRT` is either a package or, as on
//! most machines, a method that returns one of two packages: one for PIC
//! mode, one for APIC mode, chosen by what the OS said through `_PIC`.
//! Without running the method, the kernel reads every package it returns
//! by name and keeps the one whose entries all reach the I/O APIC: an
//! entry that names its GSI outright (source `Zero`), or names a link
//! device whose `_CRS` is a fixed extended interrupt (QEMU's GSIA-GSIH).
//! The PIC-mode package's links have `_CRS` methods and fail that.
//!
//! An opcode the walk does not know where it expects a definition ends it:
//! the routing is then unknown, and legacy PCI interrupts unavailable.

/// A `_PRT` entry for a function on the root bus: GSI and how it signals.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Route {
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

/// The routes of the root bus's 32 devices' four pins.
pub type Routes = [[Option<Route>; 4]; 32];

const DEPTH: usize = 16;

/// An absolute namespace path.
#[derive(Clone, Copy, PartialEq)]
struct Path {
    segs: [[u8; 4]; DEPTH],
    n: usize,
}

impl Path {
    const ROOT: Path = Path { segs: [[0; 4]; DEPTH], n: 0 };

    fn last(&self) -> Option<[u8; 4]> {
        self.n.checked_sub(1).map(|i| self.segs[i])
    }

    fn parent(&self) -> Path {
        let mut p = *self;
        p.n = p.n.saturating_sub(1);
        p
    }

    fn child(&self, seg: [u8; 4]) -> Option<Path> {
        let mut p = *self;
        *p.segs.get_mut(p.n)? = seg;
        p.n += 1;
        Some(p)
    }
}

/// A name as written: from the root, or up `ups` levels from the current
/// scope, then its segments.
#[derive(Clone, Copy)]
struct Name {
    root: bool,
    ups: usize,
    segs: [[u8; 4]; DEPTH],
    n: usize,
}

impl Name {
    /// The path it names from `scope`, for a definition.
    fn in_scope(&self, scope: &Path) -> Option<Path> {
        let mut p = if self.root { Path::ROOT } else { *scope };
        p.n = p.n.checked_sub(self.ups)?;
        for &s in &self.segs[..self.n] {
            p = p.child(s)?;
        }
        Some(p)
    }

    /// A one-segment name with no prefix is looked for in `scope` and then
    /// each scope above it (ACPI's search rules); any other names one path.
    fn candidates(&self, scope: &Path) -> impl Iterator<Item = Path> {
        let search = !self.root && self.ups == 0 && self.n == 1;
        let (this, scope) = (*self, *scope);
        let mut at = Some(scope);
        core::iter::from_fn(move || {
            let s = at.take()?;
            if !search {
                return this.in_scope(&scope);
            }
            at = (s.n > 0).then(|| s.parent());
            s.child(this.segs[0])
        })
    }
}

/// What the walk finds.
enum Def {
    /// `Name(path, object)`: where the object starts.
    Name(usize),
    /// A method: its body.
    Method(usize, usize),
}

struct Aml<'a> {
    d: &'a [u8],
}

fn lead(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b'_'
}

impl Aml<'_> {
    fn byte(&self, at: usize) -> Option<u8> {
        self.d.get(at).copied()
    }

    /// A package length at `at`: the length (counting its own bytes) and
    /// how many bytes encode it.
    fn pkg_len(&self, at: usize) -> Option<(usize, usize)> {
        let b0 = self.byte(at)?;
        let extra = (b0 >> 6) as usize;
        if extra == 0 {
            return Some(((b0 & 0x3f) as usize, 1));
        }
        let mut v = (b0 & 0x0f) as usize;
        for k in 0..extra {
            v |= (self.byte(at + 1 + k)? as usize) << (4 + 8 * k);
        }
        Some((v, extra + 1))
    }

    /// The end of the package whose length is at `at`, and where its
    /// contents start.
    fn package(&self, at: usize) -> Option<(usize, usize)> {
        let (len, used) = self.pkg_len(at)?;
        let end = at.checked_add(len)?;
        (end <= self.d.len() && len >= used).then_some((at + used, end))
    }

    fn name(&self, mut at: usize) -> Option<(Name, usize)> {
        let start = at;
        let mut n = Name { root: false, ups: 0, segs: [[0; 4]; DEPTH], n: 0 };
        if self.byte(at)? == b'\\' {
            n.root = true;
            at += 1;
        } else {
            while self.byte(at)? == b'^' {
                n.ups += 1;
                at += 1;
            }
        }
        let count = match self.byte(at)? {
            0x00 => {
                at += 1;
                0
            }
            0x2e => {
                at += 1;
                2
            }
            0x2f => {
                at += 2;
                self.byte(at - 1)? as usize
            }
            b if lead(b) => 1,
            _ => return None,
        };
        if count > DEPTH {
            return None;
        }
        for i in 0..count {
            let seg: [u8; 4] = self.d.get(at..at + 4)?.try_into().ok()?;
            if !lead(seg[0]) {
                return None;
            }
            n.segs[i] = seg;
            at += 4;
        }
        n.n = count;
        (at > start).then_some((n, at))
    }

    /// An integer constant at `at`: its value and where it ends.
    fn integer(&self, at: usize) -> Option<(u64, usize)> {
        let le = |n: usize| -> Option<u64> {
            let b = self.d.get(at + 1..at + 1 + n)?;
            Some(b.iter().rev().fold(0u64, |v, &x| v << 8 | x as u64))
        };
        Some(match self.byte(at)? {
            0x00 => (0, at + 1),
            0x01 => (1, at + 1),
            0xff => (u64::MAX, at + 1),
            0x0a => (le(1)?, at + 2),
            0x0b => (le(2)?, at + 3),
            0x0c => (le(4)?, at + 5),
            0x0e => (le(8)?, at + 9),
            _ => return None,
        })
    }

    /// Skips a data object (a `Name`'s value or a package element).
    fn skip_data(&self, at: usize) -> Option<usize> {
        if let Some((_, end)) = self.integer(at) {
            return Some(end);
        }
        match self.byte(at)? {
            // String: ASCII up to a NUL.
            0x0d => Some(at + 1 + self.d.get(at + 1..)?.iter().position(|&b| b == 0)? + 1),
            // Buffer, package, variable package.
            0x11..=0x13 => self.package(at + 1).map(|(_, end)| end),
            // Revision.
            0x5b if self.byte(at + 1)? == 0x30 => Some(at + 2),
            _ => self.name(at).map(|(_, end)| end),
        }
    }

    /// Skips an argument a definition takes (an operation region's offset
    /// and length): a constant, a name, a local or an argument.
    fn skip_arg(&self, at: usize) -> Option<usize> {
        match self.byte(at)? {
            0x60..=0x6e => Some(at + 1),
            _ => self.skip_data(at),
        }
    }

    /// Walks the definitions in `at..end` in `scope`, telling `visit` of
    /// each name and method.
    fn walk(&self, mut at: usize, end: usize, scope: &Path, depth: usize, visit: &mut dyn FnMut(&Path, Def)) -> Option<()> {
        if depth > DEPTH {
            return None;
        }
        while at < end {
            let op = self.byte(at)?;
            at = match op {
                // Scope(name) { ... }
                0x10 => {
                    let (body, pend) = self.package(at + 1)?;
                    let (n, body) = self.name(body)?;
                    self.walk(body, pend, &n.in_scope(scope)?, depth + 1, visit)?;
                    pend
                }
                // Name(name, object)
                0x08 => {
                    let (n, obj) = self.name(at + 1)?;
                    visit(&n.in_scope(scope)?, Def::Name(obj));
                    self.skip_data(obj)?
                }
                // Method(name, flags) { ... }
                0x14 => {
                    let (body, pend) = self.package(at + 1)?;
                    let (n, body) = self.name(body)?;
                    visit(&n.in_scope(scope)?, Def::Method(body + 1, pend));
                    pend
                }
                // Alias(name, name)
                0x06 => {
                    let (_, next) = self.name(at + 1)?;
                    self.name(next)?.1
                }
                // External(name, type, argument count)
                0x15 => self.name(at + 1)?.1 + 2,
                // If and Else: run-time choices, left alone.
                0xa0 | 0xa1 => self.package(at + 1)?.1,
                0x5b => {
                    let ext = self.byte(at + 1)?;
                    let at = at + 2;
                    match ext {
                        // Mutex(name, sync level), Event(name)
                        0x01 => self.name(at)?.1 + 1,
                        0x02 => self.name(at)?.1,
                        // OperationRegion(name, space, offset, length)
                        0x80 => {
                            let (_, next) = self.name(at)?;
                            let next = self.skip_arg(next + 1)?;
                            self.skip_arg(next)?
                        }
                        // Field, IndexField, BankField: no names the
                        // kernel needs.
                        0x81 | 0x86 | 0x87 => self.package(at)?.1,
                        // Device, Processor, PowerResource, ThermalZone:
                        // scopes of their own, after some fixed fields.
                        0x82 | 0x83 | 0x84 | 0x85 => {
                            let (body, pend) = self.package(at)?;
                            let (n, body) = self.name(body)?;
                            let fixed = match ext {
                                0x83 => 6,
                                0x84 => 3,
                                _ => 0,
                            };
                            self.walk(body + fixed, pend, &n.in_scope(scope)?, depth + 1, visit)?;
                            pend
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            };
        }
        (at == end).then_some(())
    }

    fn walk_all(&self, visit: &mut dyn FnMut(&Path, Def)) -> Option<()> {
        // After the 36-byte table header.
        self.walk(36, self.d.len(), &Path::ROOT, 0, visit)
    }

    /// The first definition at any of `paths` (tried in order).
    fn lookup(&self, paths: impl Iterator<Item = Path>) -> Option<(Path, DefAt)> {
        for p in paths {
            let mut found = None;
            self.walk_all(&mut |at, def| {
                if *at == p && found.is_none() {
                    found = Some(match def {
                        Def::Name(o) => DefAt::Name(o),
                        Def::Method(b, e) => DefAt::Method(b, e),
                    });
                }
            });
            if let Some(f) = found {
                return Some((p, f));
            }
        }
        None
    }

    /// Where a link device's `_CRS` sends it: its one extended interrupt,
    /// if `_CRS` is a fixed buffer holding one.
    fn link(&self, n: &Name, scope: &Path) -> Option<Route> {
        let device = n.candidates(scope).find(|p| {
            let crs = p.child(*b"_CRS");
            crs.is_some_and(|c| self.lookup(core::iter::once(c)).is_some())
        })?;
        let (_, def) = self.lookup(core::iter::once(device.child(*b"_CRS")?))?;
        let DefAt::Name(o) = def else { return None };
        if self.byte(o)? != 0x11 {
            return None;
        }
        let (body, end) = self.package(o + 1)?;
        let (_, mut r) = self.integer(body)?; // the buffer's size
        while r < end {
            let tag = self.byte(r)?;
            if tag & 0x80 == 0 {
                if tag >> 3 == 0x0f {
                    break; // end tag
                }
                r += 1 + (tag & 7) as usize; // a small item: IRQ and the like
                continue;
            }
            let len = u16::from_le_bytes([self.byte(r + 1)?, self.byte(r + 2)?]) as usize;
            if tag == 0x89 && len >= 6 && self.byte(r + 4)? >= 1 {
                let flags = self.byte(r + 3)?;
                let gsi = u32::from_le_bytes(self.d.get(r + 5..r + 9)?.try_into().ok()?);
                return Some(Route { gsi, level: flags & 2 == 0, active_low: flags & 4 != 0 });
            }
            r += 3 + len;
        }
        None
    }

    /// Reads a routing package at `o` (defined in `scope`) into `routes`,
    /// if every entry reaches a GSI.
    fn table(&self, o: usize, scope: &Path) -> Option<(Routes, usize)> {
        if self.byte(o)? != 0x12 {
            return None;
        }
        let (body, end) = self.package(o + 1)?;
        let count = self.byte(body)? as usize;
        let mut routes: Routes = [[None; 4]; 32];
        // Links already looked up (each is named many times over).
        let mut links: [Option<([u8; 4], Option<Route>)>; 16] = [None; 16];
        let mut e = body + 1;
        for _ in 0..count {
            if self.byte(e)? != 0x12 {
                return None;
            }
            let (fields, eend) = self.package(e + 1)?;
            if self.byte(fields)? != 4 {
                return None;
            }
            let (address, f) = self.integer(fields + 1)?;
            let (pin, f) = self.integer(f)?;
            let route = match self.integer(f) {
                // Source Zero: the index is the GSI; PCI's level, low.
                Some((0, f)) => Route { gsi: self.integer(f)?.0 as u32, level: true, active_low: true },
                _ => {
                    let (n, _) = self.name(f)?;
                    let key = n.segs[n.n.checked_sub(1)?];
                    match links.iter().flatten().find(|(k, _)| *k == key) {
                        Some((_, r)) => (*r)?,
                        None => {
                            let r = self.link(&n, scope);
                            if let Some(slot) = links.iter_mut().find(|s| s.is_none()) {
                                *slot = Some((key, r));
                            }
                            r?
                        }
                    }
                }
            };
            let dev = (address >> 16) as usize;
            if address & 0xffff != 0xffff || dev >= 32 || pin >= 4 {
                return None;
            }
            routes[dev][pin as usize] = Some(route);
            e = eend;
        }
        (e <= end && count > 0).then_some((routes, count))
    }
}

#[derive(Clone, Copy)]
enum DefAt {
    Name(usize),
    Method(usize, usize),
}

/// PNP0A08 (PCI Express root bridge) and PNP0A03 (PCI root bridge) as
/// `EisaId` dwords.
const ROOT_BRIDGE: [u64; 2] = [0x080a_d041, 0x030a_d041];

impl Aml<'_> {
    /// The first root bridge's path: the device whose `_HID` or `_CID` is
    /// PNP0A08 or PNP0A03 (as an EisaId or a string).
    fn root_bridge(&self) -> Option<Path> {
        let mut bridge = None;
        self.walk_all(&mut |p, def| {
            if let (None, Def::Name(o), Some(b"_HID" | b"_CID")) = (bridge, def, p.last().as_ref()) {
                // An EisaId, or the ID as a string (QEMU's Arm tables).
                let eisa = self.integer(o).is_some_and(|(v, _)| ROOT_BRIDGE.contains(&v));
                let string = self.byte(o) == Some(0x0d)
                    && [&b"PNP0A08 "[..], b"PNP0A03 "].iter().any(|id| self.d.get(o + 1..o + 9) == Some(*id));
                if eisa || string {
                    bridge = Some(p.parent());
                }
            }
        })?;
        bridge
    }
}

/// A window of addresses the root bridge decodes: PCI addresses `pci` on,
/// `len` long, which the CPU reaches at `cpu` on; memory or I/O ports.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
pub struct Window {
    pub io: bool,
    pub pci: u64,
    pub cpu: u64,
    pub len: u64,
}

/// The root bridge's memory and I/O windows from the DSDT `d` (whole,
/// header included), from its `_CRS`: a buffer, or a method returning one
/// (written out, or by name). Fills `out`, returning how many.
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
pub fn root_windows(d: &[u8], out: &mut [Window]) -> Option<usize> {
    let aml = Aml { d };
    let bridge = aml.root_bridge()?;
    let buffer = match aml.lookup(core::iter::once(bridge.child(*b"_CRS")?))?.1 {
        DefAt::Name(o) => o,
        DefAt::Method(at, end) => {
            // The first Return of a buffer, written out or by name.
            let mut at = at;
            loop {
                if at >= end {
                    return None;
                }
                if aml.byte(at)? == 0xa4 {
                    if aml.byte(at + 1)? == 0x11 {
                        break at + 1;
                    }
                    if let Some((n, _)) = aml.name(at + 1) {
                        if let Some((_, DefAt::Name(o))) = aml.lookup(n.candidates(&bridge)) {
                            break o;
                        }
                    }
                }
                at += 1;
            }
        }
    };
    if aml.byte(buffer)? != 0x11 {
        return None;
    }
    let (body, end) = aml.package(buffer + 1)?;
    let (_, mut r) = aml.integer(body)?; // the buffer's size
    let le = |at: usize, n: usize| -> Option<u64> {
        Some(d.get(at..at + n)?.iter().rev().fold(0u64, |v, &x| v << 8 | x as u64))
    };
    let mut n = 0;
    while r < end {
        let tag = aml.byte(r)?;
        if tag & 0x80 == 0 {
            if tag >> 3 == 0x0f {
                break; // end tag
            }
            r += 1 + (tag & 7) as usize;
            continue;
        }
        let len = le(r + 1, 2)? as usize;
        // Address space descriptors: resource type (0 memory, 1 I/O, 2
        // bus numbers), then minimum, maximum, translation and length.
        let w = match tag {
            0x87 if len >= 23 => Some((aml.byte(r + 3)?, le(r + 10, 4)?, le(r + 14, 4)?, le(r + 18, 4)?, le(r + 22, 4)?)),
            0x8a if len >= 43 => Some((aml.byte(r + 3)?, le(r + 14, 8)?, le(r + 22, 8)?, le(r + 30, 8)?, le(r + 38, 8)?)),
            0x88 if len >= 13 => Some((aml.byte(r + 3)?, le(r + 8, 2)?, le(r + 10, 2)?, le(r + 12, 2)?, le(r + 14, 2)?)),
            _ => None,
        };
        if let Some((kind @ (0 | 1), min, max, tra, length)) = w {
            let length = if length == 0 { max.wrapping_sub(min).wrapping_add(1) } else { length };
            if n < out.len() && length > 0 {
                out[n] = Window { io: kind == 1, pci: min, cpu: min.wrapping_add(tra), len: length };
                n += 1;
            }
        }
        r += 3 + len;
    }
    Some(n)
}

/// The root bridge's routes from the DSDT `d` (whole, header included),
/// and how many entries its table has; `None` if the walk cannot tell.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub fn root_routes(d: &[u8]) -> Option<(Routes, usize)> {
    let aml = Aml { d };
    let bridge = aml.root_bridge()?;
    let (_, prt) = aml.lookup(core::iter::once(bridge.child(*b"_PRT")?))?;
    match prt {
        DefAt::Name(o) => aml.table(o, &bridge),
        DefAt::Method(mut at, end) => {
            // Every package the method returns by name: keep the first
            // that reaches the I/O APIC throughout.
            while at < end {
                if aml.byte(at)? == 0xa4 {
                    if let Some((n, next)) = aml.name(at + 1) {
                        let found = aml.lookup(n.candidates(&bridge));
                        if let Some((p, DefAt::Name(o))) = found {
                            if let Some(t) = aml.table(o, &p.parent()) {
                                return Some(t);
                            }
                        }
                        at = next;
                        continue;
                    }
                }
                at += 1;
            }
            None
        }
    }
}
