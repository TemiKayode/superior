//! Minimal ELF64 reader for loading statically linked x86-64 and AArch64
//! executables, fixed-address (`ET_EXEC`) or position-independent
//! (`ET_DYN`, static-pie).
//!
//! Only what a loader needs: the machine, the entry point, the `PT_LOAD`
//! segments and, for position-independent images, the RELATIVE relocations
//! (`R_X86_64_RELATIVE`, `R_AARCH64_RELATIVE`).
//! Every offset and size is bounds-checked against the image, because the
//! image is untrusted input.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    /// Not 64-bit, little-endian, x86-64 or AArch64.
    WrongArch,
    /// Neither `ET_EXEC` nor `ET_DYN`.
    NotExecutable,
    BadProgramHeaders,
    /// A segment's file bytes fall outside the image, or memsz < filesz.
    BadSegment,
    /// The dynamic section or relocation table is malformed.
    BadDynamic,
    /// The image needs a dynamic linker feature this loader lacks
    /// (`DT_REL`, `DT_JMPREL`, or a relocation other than RELATIVE).
    UnsupportedRelocation,
}

/// A relocation the loader must apply: write `base + addend` at `base + offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relative {
    pub offset: u64,
    pub addend: u64,
}

/// A loadable segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// The instruction set an image is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    X86_64,
    Aarch64,
}

impl Machine {
    const fn relative(self) -> u32 {
        match self {
            Machine::X86_64 => R_X86_64_RELATIVE,
            Machine::Aarch64 => R_AARCH64_RELATIVE,
        }
    }
}

pub struct Elf<'a> {
    data: &'a [u8],
    pub machine: Machine,
    pub entry: u64,
    /// Position-independent: load at any base and apply [`Elf::relocations`].
    pub pie: bool,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_REL: u64 = 17;
const DT_JMPREL: u64 = 23;
const R_X86_64_NONE: u32 = 0;
const R_X86_64_RELATIVE: u32 = 8;
#[cfg(test)]
const R_AARCH64_NONE: u32 = 0;
const R_AARCH64_RELATIVE: u32 = 1027;
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;
const RELA_SIZE: u64 = 24;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PHDR_SIZE: usize = 56;

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 64 {
            return Err(ElfError::TooShort);
        }
        if data[0..4] != *b"\x7fELF" {
            return Err(ElfError::BadMagic);
        }
        // EI_CLASS = 64-bit, EI_DATA = little-endian.
        if data[4] != 2 || data[5] != 1 {
            return Err(ElfError::WrongArch);
        }
        let machine = match u16_at(data, 18) {
            Some(EM_X86_64) => Machine::X86_64,
            Some(EM_AARCH64) => Machine::Aarch64,
            _ => return Err(ElfError::WrongArch),
        };
        let pie = match u16_at(data, 16) {
            Some(2) => false,
            Some(3) => true,
            _ => return Err(ElfError::NotExecutable),
        };
        let entry = u64_at(data, 24).ok_or(ElfError::TooShort)?;
        let phoff = u64_at(data, 32).ok_or(ElfError::TooShort)? as usize;
        let phentsize = u16_at(data, 54).ok_or(ElfError::TooShort)? as usize;
        let phnum = u16_at(data, 56).ok_or(ElfError::TooShort)? as usize;
        let table_end = phnum
            .checked_mul(phentsize)
            .and_then(|n| n.checked_add(phoff));
        if phentsize < PHDR_SIZE || table_end.is_none_or(|end| end > data.len()) {
            return Err(ElfError::BadProgramHeaders);
        }
        Ok(Elf {
            data,
            machine,
            entry,
            pie,
            phoff,
            phentsize,
            phnum,
        })
    }

    /// The `PT_LOAD` segments, validated. Iteration yields an error for
    /// the first malformed segment.
    pub fn segments(&self) -> impl Iterator<Item = Result<Segment, ElfError>> + '_ {
        (0..self.phnum).filter_map(move |i| {
            let o = self.phoff + i * self.phentsize;
            let d = self.data;
            if u32_at(d, o)? != PT_LOAD {
                return None;
            }
            let flags = u32_at(d, o + 4)?;
            let seg = Segment {
                file_offset: u64_at(d, o + 8)?,
                vaddr: u64_at(d, o + 16)?,
                file_size: u64_at(d, o + 32)?,
                mem_size: u64_at(d, o + 40)?,
                readable: flags & PF_R != 0,
                writable: flags & PF_W != 0,
                executable: flags & PF_X != 0,
            };
            let file_end = seg.file_offset.checked_add(seg.file_size);
            let ok = file_end.is_some_and(|e| e <= d.len() as u64)
                && seg.mem_size >= seg.file_size
                && seg.vaddr.checked_add(seg.mem_size).is_some();
            Some(if ok {
                Ok(seg)
            } else {
                Err(ElfError::BadSegment)
            })
        })
    }

    /// Where the program headers are in the file, and how many there are
    /// (an ELF loader passes them on: Linux's `AT_PHDR` and `AT_PHNUM`).
    pub fn program_headers(&self) -> (u64, usize) {
        (self.phoff as u64, self.phnum)
    }

    /// The interpreter a dynamically linked executable names (`PT_INTERP`),
    /// without its terminating NUL.
    pub fn interpreter(&self) -> Option<&'a [u8]> {
        let d = self.data;
        let o = (0..self.phnum)
            .map(|i| self.phoff + i * self.phentsize)
            .find(|&o| u32_at(d, o) == Some(PT_INTERP))?;
        let off = u64_at(d, o + 8)? as usize;
        let size = u64_at(d, o + 32)? as usize;
        let s = d.get(off..off.checked_add(size)?)?;
        Some(s.split(|&b| b == 0).next().unwrap_or(s))
    }

    /// The file bytes of a segment returned by [`segments`](Self::segments).
    pub fn file_bytes(&self, seg: &Segment) -> &'a [u8] {
        &self.data[seg.file_offset as usize..(seg.file_offset + seg.file_size) as usize]
    }

    /// Converts a link-time virtual address to a file offset, if `len`
    /// bytes there lie within a loaded segment's file bytes.
    fn vaddr_to_offset(&self, vaddr: u64, len: u64) -> Option<usize> {
        self.segments().filter_map(Result::ok).find_map(|s| {
            let rel = vaddr.checked_sub(s.vaddr)?;
            (rel.checked_add(len)? <= s.file_size).then(|| (s.file_offset + rel) as usize)
        })
    }

    /// The relocations of a position-independent image, all RELATIVE for
    /// its machine. Anything else is refused, since there is no symbol
    /// table to resolve against. Empty for fixed-address images.
    pub fn relocations(&self) -> Result<impl Iterator<Item = Relative> + '_, ElfError> {
        let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, RELA_SIZE);
        let d = self.data;
        let dynamic = (0..self.phnum)
            .map(|i| self.phoff + i * self.phentsize)
            .find(|&o| u32_at(d, o) == Some(PT_DYNAMIC));
        if let Some(o) = dynamic {
            let off = u64_at(d, o + 8).ok_or(ElfError::BadDynamic)? as usize;
            let size = u64_at(d, o + 32).ok_or(ElfError::BadDynamic)? as usize;
            let end = off.checked_add(size).ok_or(ElfError::BadDynamic)?;
            let table = d.get(off..end).ok_or(ElfError::BadDynamic)?;
            for entry in table.as_chunks::<16>().0 {
                let tag = u64_at(entry, 0).unwrap();
                let val = u64_at(entry, 8).unwrap();
                match tag {
                    DT_NULL => break,
                    DT_RELA => rela = val,
                    DT_RELASZ => relasz = val,
                    DT_RELAENT => relaent = val,
                    DT_REL | DT_JMPREL if val != 0 => {
                        return Err(ElfError::UnsupportedRelocation);
                    }
                    _ => {}
                }
            }
        }
        if relaent != RELA_SIZE || relasz % RELA_SIZE != 0 {
            return Err(ElfError::BadDynamic);
        }
        let start = if relasz == 0 {
            0
        } else {
            self.vaddr_to_offset(rela, relasz)
                .ok_or(ElfError::BadDynamic)?
        };
        let table = &d[start..start + relasz as usize];
        let relative = self.machine.relative();
        for r in table.as_chunks::<{ RELA_SIZE as usize }>().0 {
            let kind = u32_at(r, 8).unwrap();
            // R_X86_64_NONE and R_AARCH64_NONE are both 0.
            if kind != relative && kind != R_X86_64_NONE {
                return Err(ElfError::UnsupportedRelocation);
            }
        }
        Ok(table
            .as_chunks::<{ RELA_SIZE as usize }>()
            .0
            .iter()
            .filter(move |r| u32_at(&r[..], 8) == Some(relative))
            .map(|r| Relative {
                offset: u64_at(r, 0).unwrap(),
                addend: u64_at(r, 16).unwrap(),
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Builds a minimal ELF: header + one PT_LOAD program header + payload.
    fn image(load_vaddr: u64, payload: &[u8], mem_size: u64) -> Vec<u8> {
        let mut d = vec![0u8; 64 + PHDR_SIZE];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[16..18].copy_from_slice(&2u16.to_le_bytes());
        d[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        d[24..32].copy_from_slice(&(load_vaddr + 0x10).to_le_bytes());
        d[32..40].copy_from_slice(&64u64.to_le_bytes());
        d[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        d[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        d[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        d[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        d[ph + 8..ph + 16].copy_from_slice(&((64 + PHDR_SIZE) as u64).to_le_bytes());
        d[ph + 16..ph + 24].copy_from_slice(&load_vaddr.to_le_bytes());
        d[ph + 32..ph + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        d[ph + 40..ph + 48].copy_from_slice(&mem_size.to_le_bytes());
        d.extend_from_slice(payload);
        d
    }

    #[test]
    fn parses_entry_and_segment() {
        let img = image(0x7000_0000_0000, b"code", 0x2000);
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.entry, 0x7000_0000_0010);
        let segs: Vec<_> = elf.segments().collect::<Result<_, _>>().unwrap();
        assert_eq!(segs.len(), 1);
        let s = segs[0];
        assert_eq!(
            (s.vaddr, s.mem_size, s.file_size),
            (0x7000_0000_0000, 0x2000, 4)
        );
        assert!(s.readable && s.executable && !s.writable);
        assert_eq!(elf.file_bytes(&s), b"code");
    }

    #[test]
    fn rejects_malformed_headers() {
        let good = image(0x1000, b"x", 1);
        assert_eq!(Elf::parse(&good[..10]).err(), Some(ElfError::TooShort));
        let mut bad = good.clone();
        bad[1] = b'X';
        assert_eq!(Elf::parse(&bad).err(), Some(ElfError::BadMagic));
        let mut bad = good.clone();
        bad[18] = 0xf3; // RISC-V
        assert_eq!(Elf::parse(&bad).err(), Some(ElfError::WrongArch));
        let mut bad = good.clone();
        bad[16] = 1; // ET_REL
        assert_eq!(Elf::parse(&bad).err(), Some(ElfError::NotExecutable));
        let mut bad = good.clone();
        bad[56] = 200; // phnum past end of file
        assert_eq!(Elf::parse(&bad).err(), Some(ElfError::BadProgramHeaders));
    }

    #[test]
    fn rejects_segment_outside_file_or_memsz_too_small() {
        let mut img = image(0x1000, b"abcd", 4);
        let ph = 64;
        img[ph + 32..ph + 40].copy_from_slice(&1000u64.to_le_bytes()); // filesz past EOF
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next(), Some(Err(ElfError::BadSegment)));

        let img = image(0x1000, b"abcd", 2); // memsz < filesz
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.segments().next(), Some(Err(ElfError::BadSegment)));
    }
    /// A static-pie image: one RW PT_LOAD holding a dynamic table and two
    /// RELA entries, plus a PT_DYNAMIC header covering the table.
    fn pie_image(second_reloc_type: u32) -> Vec<u8> {
        pie_image_for(EM_X86_64, R_X86_64_RELATIVE, second_reloc_type)
    }

    fn pie_image_for(machine: u16, relative: u32, second_reloc_type: u32) -> Vec<u8> {
        let payload_off = 64 + 2 * PHDR_SIZE;
        let dyn_va = payload_off as u64; // vaddr == file offset, as lld lays out PIE
        let rela_va = dyn_va + 64;
        let mut payload = Vec::new();
        for (tag, val) in [
            (DT_RELA, rela_va),
            (DT_RELASZ, 48),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ] {
            payload.extend_from_slice(&tag.to_le_bytes());
            payload.extend_from_slice(&val.to_le_bytes());
        }
        let relocs = [
            (0x2000u64, 0x1234u64, relative),
            (0x2008, 0x10, second_reloc_type),
        ];
        for (off, add, ty) in relocs {
            payload.extend_from_slice(&off.to_le_bytes());
            payload.extend_from_slice(&(ty as u64).to_le_bytes());
            payload.extend_from_slice(&add.to_le_bytes());
        }
        let mut d = vec![0u8; payload_off];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        d[18..20].copy_from_slice(&machine.to_le_bytes());
        d[24..32].copy_from_slice(&0x100u64.to_le_bytes());
        d[32..40].copy_from_slice(&64u64.to_le_bytes());
        d[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        d[56..58].copy_from_slice(&2u16.to_le_bytes());
        let len = payload.len() as u64;
        for (i, (ty, size)) in [(PT_LOAD, len), (PT_DYNAMIC, 64)].into_iter().enumerate() {
            let ph = 64 + i * PHDR_SIZE;
            d[ph..ph + 4].copy_from_slice(&ty.to_le_bytes());
            d[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_W).to_le_bytes());
            d[ph + 8..ph + 16].copy_from_slice(&(payload_off as u64).to_le_bytes());
            d[ph + 16..ph + 24].copy_from_slice(&dyn_va.to_le_bytes());
            d[ph + 32..ph + 40].copy_from_slice(&size.to_le_bytes());
            d[ph + 40..ph + 48].copy_from_slice(&size.to_le_bytes());
        }
        d.extend_from_slice(&payload);
        d
    }

    #[test]
    fn pie_relocations_are_read() {
        let img = pie_image(R_X86_64_NONE);
        let elf = Elf::parse(&img).unwrap();
        assert!(elf.pie);
        let relocs: Vec<_> = elf.relocations().unwrap().collect();
        assert_eq!(
            relocs,
            [Relative {
                offset: 0x2000,
                addend: 0x1234
            }]
        );
    }

    #[test]
    fn pie_with_symbolic_relocation_is_refused() {
        let img = pie_image(1); // R_X86_64_64 needs a symbol table
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(
            elf.relocations().err(),
            Some(ElfError::UnsupportedRelocation)
        );
    }

    #[test]
    fn fixed_address_image_has_no_relocations() {
        let img = image(0x1000, b"x", 1);
        assert_eq!(Elf::parse(&img).unwrap().relocations().unwrap().count(), 0);
    }

    #[test]
    fn aarch64_relative_relocations() {
        let img = pie_image_for(EM_AARCH64, R_AARCH64_RELATIVE, R_AARCH64_NONE);
        let elf = Elf::parse(&img).unwrap();
        assert_eq!(elf.machine, Machine::Aarch64);
        let relocs: Vec<_> = elf.relocations().unwrap().collect();
        assert_eq!(
            relocs,
            [Relative {
                offset: 0x2000,
                addend: 0x1234
            }]
        );
        // An x86-64 relocation type in an AArch64 image is refused.
        let img = pie_image_for(EM_AARCH64, R_AARCH64_RELATIVE, R_X86_64_RELATIVE);
        assert_eq!(
            Elf::parse(&img).unwrap().relocations().err(),
            Some(ElfError::UnsupportedRelocation)
        );
    }
}
