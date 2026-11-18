//! The personality's files: an in-memory tree (directories, files,
//! symbolic links, the programs from the bundle, `/dev/null`), pipes, and
//! the open-file descriptions processes share through their descriptors.
//!
//! Everything lives in pages this server maps at start (all zero is a
//! valid empty state). A file's data is up to [`FILE_BLOCKS`] pages from a
//! pool; directories hold no entries of their own: an inode names its
//! parent, and a directory's entries are the inodes that name it.

pub const MAX_INODES: usize = 256;
pub const FILE_BLOCKS: usize = 16;
pub const POOL_PAGES: usize = 224;
pub const NAME_MAX: usize = 27;
pub const PIPE_BUF: usize = 4096;
pub const MAX_PIPES: usize = 8;
pub const MAX_FILES: usize = 64;
const PAGE: usize = 4096;
pub const ROOT: u16 = 1;

// Linux error numbers.
pub const ENOENT: u64 = 2;
pub const EBADF: u64 = 9;
pub const EEXIST: u64 = 17;
pub const ENOTDIR: u64 = 20;
pub const EISDIR: u64 = 21;
pub const EINVAL: u64 = 22;
pub const ENFILE: u64 = 23;
pub const EFBIG: u64 = 27;
pub const ENOSPC: u64 = 28;
pub const ENAMETOOLONG: u64 = 36;
pub const ENOTEMPTY: u64 = 39;
pub const ELOOP: u64 = 40;
pub const EPIPE: u64 = 32;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Free = 0,
    Dir,
    File,
    Symlink,
    /// The program from the bundle (BusyBox).
    Program,
    /// Its interpreter (musl's dynamic linker).
    Interp,
    Null,
}

#[derive(Clone, Copy)]
pub struct Inode {
    pub kind: Kind,
    pub parent: u16,
    nlen: u8,
    name: [u8; NAME_MAX],
    pub size: u32,
    /// Pool pages, 1-based (0: none yet, a hole of zeros).
    blocks: [u16; FILE_BLOCKS],
}

pub struct Fs {
    pub inodes: [Inode; MAX_INODES],
    used: [u64; POOL_PAGES.div_ceil(64)],
    /// Where the pool and the two images are mapped here.
    pub pool: u64,
    pub program: (u64, u64),
    pub interp: (u64, u64),
}

impl Fs {
    /// Makes the root and the tree a new system starts with.
    pub fn init(&mut self, pool: u64, program: &[u8], interp: &[u8], interp_path: &[u8], applets: &[&str]) {
        self.pool = pool;
        self.program = (program.as_ptr() as u64, program.len() as u64);
        self.interp = (interp.as_ptr() as u64, interp.len() as u64);
        let root = &mut self.inodes[ROOT as usize];
        root.kind = Kind::Dir;
        root.parent = ROOT;
        let bin = self.create(ROOT, b"bin", Kind::Dir).unwrap_or(ROOT);
        let _ = self.create(bin, b"busybox", Kind::Program);
        for a in applets {
            if let Ok(l) = self.create(bin, a.as_bytes(), Kind::Symlink) {
                let _ = self.write(l, 0, b"busybox");
            }
        }
        // The interpreter where the program says it is.
        if let Ok((dir, name)) = self.make_dirs_for(interp_path) {
            let _ = self.create(dir, name, Kind::Interp);
        }
        let _ = self.create(ROOT, b"tmp", Kind::Dir);
        let _ = self.create(ROOT, b"home", Kind::Dir);
        if let Ok(dev) = self.create(ROOT, b"dev", Kind::Dir) {
            let _ = self.create(dev, b"null", Kind::Null);
        }
    }

    fn make_dirs_for<'a>(&mut self, path: &'a [u8]) -> Result<(u16, &'a [u8]), u64> {
        let mut dir = ROOT;
        let mut parts = path.split(|&b| b == b'/').filter(|p| !p.is_empty()).peekable();
        while let Some(p) = parts.next() {
            if parts.peek().is_none() {
                return Ok((dir, p));
            }
            dir = match self.lookup(dir, p) {
                Some(d) => d,
                None => self.create(dir, p, Kind::Dir)?,
            };
        }
        Err(EINVAL)
    }

    pub fn name(&self, ino: u16) -> &[u8] {
        let i = &self.inodes[ino as usize];
        &i.name[..i.nlen as usize]
    }

    pub fn kind(&self, ino: u16) -> Kind {
        self.inodes[ino as usize].kind
    }

    pub fn size(&self, ino: u16) -> u64 {
        let i = &self.inodes[ino as usize];
        match i.kind {
            Kind::Program => self.program.1,
            Kind::Interp => self.interp.1,
            _ => i.size as u64,
        }
    }

    pub fn lookup(&self, dir: u16, name: &[u8]) -> Option<u16> {
        match name {
            b"." => return Some(dir),
            b".." => return Some(self.inodes[dir as usize].parent),
            _ => {}
        }
        (2..MAX_INODES as u16).find(|&i| {
            let n = &self.inodes[i as usize];
            n.kind != Kind::Free && n.parent == dir && self.name(i) == name
        })
    }

    pub fn create(&mut self, dir: u16, name: &[u8], kind: Kind) -> Result<u16, u64> {
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        if name.is_empty() || name == b"." || name == b".." {
            return Err(EEXIST);
        }
        if self.kind(dir) != Kind::Dir {
            return Err(ENOTDIR);
        }
        if self.lookup(dir, name).is_some() {
            return Err(EEXIST);
        }
        let ino = (2..MAX_INODES as u16).find(|&i| self.inodes[i as usize].kind == Kind::Free).ok_or(ENOSPC)?;
        let n = &mut self.inodes[ino as usize];
        *n = Inode { kind, parent: dir, nlen: name.len() as u8, name: [0; NAME_MAX], size: 0, blocks: [0; FILE_BLOCKS] };
        n.name[..name.len()].copy_from_slice(name);
        Ok(ino)
    }

    /// The entry after position `pos` of directory `dir`: positions 0 and
    /// 1 are `.` and `..`, then each inode's number plus 2.
    pub fn entry(&self, dir: u16, pos: u64) -> Option<(u64, u16, &[u8])> {
        match pos {
            0 => return Some((1, dir, b".")),
            1 => return Some((2, self.inodes[dir as usize].parent, b"..")),
            _ => {}
        }
        (pos.saturating_sub(2) as usize..MAX_INODES).find_map(|i| {
            let n = &self.inodes[i];
            (i >= 2 && n.kind != Kind::Free && n.parent == dir).then(|| (i as u64 + 3, i as u16, self.name(i as u16)))
        })
    }

    /// Follows `path` from `cwd` (or the root, if absolute). The last part
    /// is followed through symbolic links only if `follow`.
    pub fn resolve(&self, cwd: u16, path: &[u8], follow: bool) -> Result<u16, u64> {
        self.walk(cwd, path, follow, 0)
    }

    fn walk(&self, cwd: u16, path: &[u8], follow: bool, depth: u32) -> Result<u16, u64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut at = if path[0] == b'/' { ROOT } else { cwd };
        let mut parts = path.split(|&b| b == b'/').filter(|p| !p.is_empty()).peekable();
        while let Some(p) = parts.next() {
            if self.kind(at) != Kind::Dir {
                return Err(ENOTDIR);
            }
            let next = self.lookup(at, p).ok_or(ENOENT)?;
            let last = parts.peek().is_none();
            if self.kind(next) == Kind::Symlink && (follow || !last || path.ends_with(b"/")) {
                if depth >= 8 {
                    return Err(ELOOP);
                }
                let mut target = [0u8; 256];
                let n = self.read(next, 0, &mut target);
                at = self.walk(at, &target[..n], true, depth + 1)?;
            } else {
                at = next;
            }
        }
        Ok(at)
    }

    /// The directory `path`'s last part is in, and that part.
    pub fn parent_of<'a>(&self, cwd: u16, path: &'a [u8]) -> Result<(u16, &'a [u8]), u64> {
        let trimmed = {
            let mut e = path.len();
            while e > 1 && path[e - 1] == b'/' {
                e -= 1;
            }
            &path[..e]
        };
        let (dir, name) = match trimmed.iter().rposition(|&b| b == b'/') {
            Some(0) => (ROOT, &trimmed[1..]),
            Some(i) => (self.resolve(cwd, &trimmed[..i], true)?, &trimmed[i + 1..]),
            None => (cwd, trimmed),
        };
        if self.kind(dir) != Kind::Dir {
            return Err(ENOTDIR);
        }
        // "/" itself: it is there, and has no parent to change.
        if name.is_empty() {
            return Err(if path.is_empty() { ENOENT } else { EEXIST });
        }
        Ok((dir, name))
    }

    fn page(&self, block: u16) -> *mut u8 {
        (self.pool + (block as u64 - 1) * PAGE as u64) as *mut u8
    }

    /// Reads from `off`; the bytes read.
    pub fn read(&self, ino: u16, off: u64, buf: &mut [u8]) -> usize {
        let size = self.size(ino);
        if off >= size {
            return 0;
        }
        let n = buf.len().min((size - off) as usize);
        let i = &self.inodes[ino as usize];
        match i.kind {
            Kind::Program | Kind::Interp => {
                let base = if i.kind == Kind::Program { self.program.0 } else { self.interp.0 };
                // SAFETY: the image is mapped for this server's life and
                // off + n is within its length.
                let src = unsafe { core::slice::from_raw_parts((base + off) as *const u8, n) };
                buf[..n].copy_from_slice(src);
            }
            _ => {
                for (k, b) in buf[..n].iter_mut().enumerate() {
                    let at = off as usize + k;
                    let block = i.blocks[at / PAGE];
                    // SAFETY: a used block is a mapped pool page.
                    *b = if block == 0 { 0 } else { unsafe { *self.page(block).add(at % PAGE) } };
                }
            }
        }
        n
    }

    /// Writes at `off`, growing the file; the bytes written.
    pub fn write(&mut self, ino: u16, off: u64, data: &[u8]) -> Result<usize, u64> {
        if self.kind(ino) != Kind::File && self.kind(ino) != Kind::Symlink {
            return Err(EINVAL);
        }
        let end = off.checked_add(data.len() as u64).ok_or(EFBIG)?;
        if end > (FILE_BLOCKS * PAGE) as u64 {
            return Err(EFBIG);
        }
        for (k, &b) in data.iter().enumerate() {
            let at = off as usize + k;
            let mut block = self.inodes[ino as usize].blocks[at / PAGE];
            if block == 0 {
                block = self.alloc().ok_or(ENOSPC)?;
                self.inodes[ino as usize].blocks[at / PAGE] = block;
            }
            // SAFETY: as in `read`.
            unsafe { *self.page(block).add(at % PAGE) = b };
        }
        let i = &mut self.inodes[ino as usize];
        i.size = i.size.max(end as u32);
        Ok(data.len())
    }

    pub fn truncate(&mut self, ino: u16, len: u64) -> Result<(), u64> {
        if self.kind(ino) != Kind::File {
            return Err(EINVAL);
        }
        if len > (FILE_BLOCKS * PAGE) as u64 {
            return Err(EFBIG);
        }
        let old = self.inodes[ino as usize].size as u64;
        // Zero what is cut off in the last page, free whole pages past it.
        for at in len..old.min(len.next_multiple_of(PAGE as u64)) {
            let block = self.inodes[ino as usize].blocks[at as usize / PAGE];
            if block != 0 {
                // SAFETY: as in `read`.
                unsafe { *self.page(block).add(at as usize % PAGE) = 0 };
            }
        }
        for p in (len as usize).div_ceil(PAGE)..FILE_BLOCKS {
            let block = core::mem::take(&mut self.inodes[ino as usize].blocks[p]);
            self.free(block);
        }
        self.inodes[ino as usize].size = len as u32;
        Ok(())
    }

    /// Removes `ino` (a directory only if empty).
    pub fn remove(&mut self, ino: u16) -> Result<(), u64> {
        if ino == ROOT {
            return Err(EINVAL);
        }
        if self.kind(ino) == Kind::Dir && self.entry(ino, 2).is_some() {
            return Err(ENOTEMPTY);
        }
        for p in 0..FILE_BLOCKS {
            let block = core::mem::take(&mut self.inodes[ino as usize].blocks[p]);
            self.free(block);
        }
        self.inodes[ino as usize].kind = Kind::Free;
        Ok(())
    }

    /// Moves `ino` to `name` in `dir`, replacing what is there (not a
    /// non-empty directory).
    pub fn rename(&mut self, ino: u16, dir: u16, name: &[u8]) -> Result<(), u64> {
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        // Not into itself.
        let mut d = dir;
        loop {
            if d == ino {
                return Err(EINVAL);
            }
            if d == ROOT {
                break;
            }
            d = self.inodes[d as usize].parent;
        }
        if let Some(old) = self.lookup(dir, name) {
            if old == ino {
                return Ok(());
            }
            if self.kind(old) == Kind::Dir && self.kind(ino) != Kind::Dir {
                return Err(EISDIR);
            }
            self.remove(old)?;
        }
        let n = &mut self.inodes[ino as usize];
        n.parent = dir;
        n.nlen = name.len() as u8;
        n.name = [0; NAME_MAX];
        n.name[..name.len()].copy_from_slice(name);
        Ok(())
    }

    fn alloc(&mut self) -> Option<u16> {
        let b = (0..POOL_PAGES).find(|&b| self.used[b / 64] & (1 << (b % 64)) == 0)?;
        self.used[b / 64] |= 1 << (b % 64);
        let block = b as u16 + 1;
        // SAFETY: a pool page, mapped.
        unsafe { core::ptr::write_bytes(self.page(block), 0, PAGE) };
        Some(block)
    }

    fn free(&mut self, block: u16) {
        if block != 0 {
            let b = block as usize - 1;
            self.used[b / 64] &= !(1 << (b % 64));
        }
    }
}

/// A pipe: a ring and how many descriptions read and write it.
pub struct Pipe {
    pub readers: u8,
    pub writers: u8,
    head: u16,
    pub len: u16,
    buf: [u8; PIPE_BUF],
}

impl Pipe {
    pub fn put(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(PIPE_BUF - self.len as usize);
        for (k, &b) in data[..n].iter().enumerate() {
            self.buf[(self.head as usize + self.len as usize + k) % PIPE_BUF] = b;
        }
        self.len += n as u16;
        n
    }

    pub fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len as usize);
        for (k, b) in buf[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head as usize + k) % PIPE_BUF];
        }
        self.head = ((self.head as usize + n) % PIPE_BUF) as u16;
        self.len -= n as u16;
        n
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Closed = 0,
    /// The console: output printed a line at a time, input at its end.
    Console,
    Node,
    PipeRead,
    PipeWrite,
}

/// An open-file description, shared by the descriptors `dup` and `fork`
/// make of it.
#[derive(Clone, Copy)]
pub struct Open {
    pub kind: FileKind,
    pub refs: u8,
    pub ino: u16,
    pub pipe: u8,
    /// The flags it was opened with (`O_ACCMODE`, `O_APPEND`, ...).
    pub flags: u32,
    pub off: u64,
}
