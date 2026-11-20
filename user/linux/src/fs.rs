//! The personality's files: an in-memory tree (directories, files,
//! symbolic links, the programs from the bundle, `/dev/null`, the
//! terminal) laid over the filesystem server's tree; pipes; and the
//! open-file descriptions processes share through their descriptors.
//!
//! Everything lives in pages this server maps at start (all zero is a
//! valid empty state). A file's data is pages from a pool: the first
//! [`DIRECT`] named in its inode, the rest (up to [`MAX_FILE_PAGES`]) in an
//! indirect page the inode's last entry names; directories hold no entries of their own: an inode names its
//! parent, and a directory's entries are the inodes that name it.
//!
//! The root is the server's ([`Fs::mount`], [`remote`]): what is made
//! there (`/home`, `/etc`, anything) is on its disk. What the system
//! starts with stays here, in memory, laid over it: `/bin`, `/usr`, `/lib`
//! (the bundle's programs and libraries), `/dev`, and `/tmp`, as a
//! `tmpfs`. A name looked up in a directory of the server's becomes an
//! inode here, marked remote, holding the server's handle and the size,
//! its path the names up to the root. So walking paths, the working
//! directory and `getcwd` are as for the rest; reads, writes and changes
//! go to the server, and a directory's entries are listed from it (the
//! root's after its own, a name it has hiding the server's). Such inodes
//! no descriptor or directory needs are let go when inodes run short
//! ([`Fs::evict`]).

use crate::remote;
use core::cell::Cell;
use superior_objects::interfaces::fs as server;

pub const MAX_INODES: usize = 256;
pub const FILE_BLOCKS: usize = 16;
/// A file's pages named in its inode; its last entry names the indirect
/// page, which names the rest.
const DIRECT: usize = FILE_BLOCKS - 1;
const INDIRECT: usize = FILE_BLOCKS - 1;
/// The most pages a file of the tree may have.
const MAX_FILE_PAGES: usize = DIRECT + PAGE / 2;
pub const POOL_PAGES: usize = 192;
/// The filesystem server's longest name.
pub const NAME_MAX: usize = server::MAX_NAME;
/// Bytes of a path on the server, as it is given it.
const PATH_MAX: usize = 1024;
/// Where a remote directory's listing goes on to the server's entries,
/// after the ones of its own here (the root's).
const SERVER_POS: u64 = 1 << 20;
pub const PIPE_BUF: usize = 4096;
pub const MAX_PIPES: usize = 8;
pub const MAX_FILES: usize = 64;
const PAGE: usize = 4096;
pub const ROOT: u16 = 1;

// Linux error numbers.
pub const ENOENT: u64 = 2;
pub const EBADF: u64 = 9;
pub const EBUSY: u64 = 16;
pub const EXDEV: u64 = 18;
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
    /// A file from the bundle (a program or a library), mapped here:
    /// [`Fs::images`], at the index its `size` holds.
    Image,
    Null,
    /// The terminal (`/dev/tty`, `/dev/console`).
    Tty,
    /// The framebuffer (`/dev/fb0`): a window on the compositor's screen.
    Fb,
    /// An input device (`/dev/input/event0`, the keys, and `event1`, the
    /// pointer, its number in `size`): the framebuffer window's events.
    Input,
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
    /// The filesystem server's, and its handle there (0 for a link).
    remote: bool,
    handle: u64,
}

/// A directory entry, as [`Fs::entry`] gives it.
pub struct Dirent {
    /// The position of the entry after it.
    pub next: u64,
    pub ino: u64,
    pub kind: Kind,
    len: u8,
    name: [u8; NAME_MAX],
}

impl Dirent {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len as usize]
    }
}

pub struct Fs {
    pub inodes: [Inode; MAX_INODES],
    used: [u64; POOL_PAGES.div_ceil(64)],
    /// Where the pool and the bundle's files are mapped here (address,
    /// length).
    pub pool: u64,
    pub images: [(u64, u64); MAX_IMAGES],
    /// The root's inode once it is the server's (0 until then).
    pub mount: u16,
    /// The entries the buffer holds from the server's last `READDIR`, if
    /// no call since: the directory's handle, the position asked for, the
    /// entries before it (as [`Fs::entry`] counts them), how many came,
    /// the position after them, and [`remote::calls`] then.
    listed: Cell<[u64; 6]>,
}

/// Files from the bundle at most.
pub const MAX_IMAGES: usize = 34;

impl Fs {
    /// Makes the tree: each of `images` (the bundle's files) at its path,
    /// a link in `/bin` to `/bin/busybox` for each of `applets`, and the
    /// rest a new system starts with.
    pub fn init(&mut self, pool: u64, images: &[(&[u8], &[u8])], applets: &[&str]) {
        self.pool = pool;
        let root = &mut self.inodes[ROOT as usize];
        root.kind = Kind::Dir;
        root.parent = ROOT;
        let bin = self.create(ROOT, b"bin", Kind::Dir).unwrap_or(ROOT);
        for (k, &(path, bytes)) in images.iter().enumerate().take(MAX_IMAGES) {
            self.images[k] = (bytes.as_ptr() as u64, bytes.len() as u64);
            if let Ok((dir, name)) = self.make_dirs_for(path) {
                if let Ok(ino) = self.create(dir, name, Kind::Image) {
                    self.inodes[ino as usize].size = k as u32;
                }
            }
        }
        for a in applets {
            if let Ok(l) = self.create(bin, a.as_bytes(), Kind::Symlink) {
                let _ = self.write(l, 0, b"busybox");
            }
        }
        let _ = self.create(ROOT, b"tmp", Kind::Dir);
        if let Ok(dev) = self.create(ROOT, b"dev", Kind::Dir) {
            let _ = self.create(dev, b"null", Kind::Null);
            let _ = self.create(dev, b"tty", Kind::Tty);
            let _ = self.create(dev, b"console", Kind::Tty);
            let _ = self.create(dev, b"fb0", Kind::Fb);
            if let Ok(input) = self.create(dev, b"input", Kind::Dir) {
                for (k, name) in [b"event0", b"event1"].iter().enumerate() {
                    if let Ok(ino) = self.create(input, *name, Kind::Input) {
                        self.inodes[ino as usize].size = k as u32;
                    }
                }
            }
        }
    }

    /// Adds a file (or, with `link`, a symbolic link to `data`) at
    /// `path`, making the directories on the way: what the toolchain's
    /// archive holds.
    pub fn add(&mut self, path: &[u8], data: &[u8], link: bool) -> Result<(), u64> {
        let (dir, name) = self.make_dirs_for(path)?;
        let ino = self.create(dir, name, if link { Kind::Symlink } else { Kind::File })?;
        self.write(ino, 0, data).map(drop)
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

    /// Lays the tree here over the filesystem server's (its root made if
    /// this is the first time), with a `/home` there; whether the server
    /// answered. If not, `/home` is made here.
    pub fn mount(&mut self) -> bool {
        let Ok((handle, _, _)) = remote::open(b"", server::CREATE) else {
            let _ = self.create(ROOT, b"home", Kind::Dir);
            return false;
        };
        let n = &mut self.inodes[ROOT as usize];
        (n.remote, n.handle) = (true, handle);
        self.mount = ROOT;
        if self.lookup(ROOT, b"home").is_none() {
            let _ = self.create(ROOT, b"home", Kind::Dir);
        }
        true
    }

    pub fn is_remote(&self, ino: u16) -> bool {
        self.inodes[ino as usize].remote
    }

    /// Remote inode `ino`'s path on the server, into `out`: the names
    /// from `/home` down, `/` between. Its length.
    fn path(&self, ino: u16, out: &mut [u8; PATH_MAX]) -> Result<usize, u64> {
        let mut chain = [0u16; 32];
        let (mut n, mut at) = (0, ino);
        while at != self.mount {
            if !self.is_remote(at) || n == chain.len() {
                return Err(EINVAL);
            }
            chain[n] = at;
            n += 1;
            at = self.inodes[at as usize].parent;
        }
        let mut len = 0;
        for &k in chain[..n].iter().rev() {
            let name = self.name(k);
            if len + name.len() + 1 > PATH_MAX {
                return Err(ENAMETOOLONG);
            }
            if len > 0 {
                out[len] = b'/';
                len += 1;
            }
            out[len..len + name.len()].copy_from_slice(name);
            len += name.len();
        }
        Ok(len)
    }

    /// The server's path for `name` in remote directory `dir`.
    fn child_path(&self, dir: u16, name: &[u8], out: &mut [u8; PATH_MAX]) -> Result<usize, u64> {
        let mut len = self.path(dir, out)?;
        if len + name.len() + 1 > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        if len > 0 {
            out[len] = b'/';
            len += 1;
        }
        out[len..len + name.len()].copy_from_slice(name);
        Ok(len + name.len())
    }

    /// An inode for the server's `name` in `dir`.
    fn proxy(&mut self, dir: u16, name: &[u8], kind: Kind, handle: u64, size: u64) -> Result<u16, u64> {
        let ino = self.alloc_inode(dir, name, kind)?;
        let n = &mut self.inodes[ino as usize];
        (n.remote, n.handle, n.size) = (true, handle, size.min(u32::MAX as u64) as u32);
        Ok(ino)
    }

    /// Frees remote inode `ino`, and any under it.
    fn drop_proxy(&mut self, ino: u16) {
        for k in 2..MAX_INODES as u16 {
            let n = &self.inodes[k as usize];
            if n.kind != Kind::Free && n.parent == ino && k != ino {
                self.drop_proxy(k);
            }
        }
        self.inodes[ino as usize].kind = Kind::Free;
    }

    /// Inodes free.
    pub fn free_inodes(&self) -> usize {
        self.inodes[2..].iter().filter(|n| n.kind == Kind::Free).count()
    }

    /// Lets go of remote inodes nothing needs: not `/home`, not `busy`
    /// (open, or a working directory), with nothing under them. They are
    /// looked up again when next named. How many.
    pub fn evict(&mut self, busy: impl Fn(u16) -> bool) -> usize {
        let mut freed = 0;
        loop {
            let mut any = false;
            for k in 2..MAX_INODES as u16 {
                let n = &self.inodes[k as usize];
                if n.kind == Kind::Free || !n.remote || k == self.mount || busy(k) {
                    continue;
                }
                if self.inodes.iter().any(|c| c.kind != Kind::Free && c.parent == k) {
                    continue;
                }
                self.inodes[k as usize].kind = Kind::Free;
                (any, freed) = (true, freed + 1);
            }
            if !any {
                return freed;
            }
        }
    }

    pub fn name(&self, ino: u16) -> &[u8] {
        let i = &self.inodes[ino as usize];
        &i.name[..i.nlen as usize]
    }

    pub fn kind(&self, ino: u16) -> Kind {
        self.inodes[ino as usize].kind
    }

    /// The bundle file inode `ino` is, if it is one: its index in
    /// [`Fs::images`].
    pub fn image(&self, ino: u16) -> Option<usize> {
        let i = &self.inodes[ino as usize];
        (i.kind == Kind::Image).then_some(i.size as usize)
    }

    pub fn size(&self, ino: u16) -> u64 {
        let i = &self.inodes[ino as usize];
        match i.kind {
            Kind::Image => self.images[i.size as usize].1,
            _ => i.size as u64,
        }
    }

    /// What `name` names in `dir`: an inode already here, or, in a
    /// remote directory, the server's (an inode made for it).
    pub fn lookup(&mut self, dir: u16, name: &[u8]) -> Option<u16> {
        if let Some(ino) = self.cached(dir, name) {
            return Some(ino);
        }
        if !self.is_remote(dir) || self.kind(dir) != Kind::Dir || name.len() > NAME_MAX {
            return None;
        }
        let mut p = [0u8; PATH_MAX];
        let n = self.child_path(dir, name, &mut p).ok()?;
        let (kind, handle, size) = match remote::open(&p[..n], server::NOFOLLOW) {
            Ok((h, s, k)) => (if k == server::KIND_DIR { Kind::Dir } else { Kind::File }, h, s),
            // A link (`NOFOLLOW`): its size is its target's length.
            Err(ELOOP) => (Kind::Symlink, 0, remote::readlink(&p[..n], &mut [0; PATH_MAX]).ok()? as u64),
            Err(_) => return None,
        };
        self.proxy(dir, name, kind, handle, size).ok()
    }

    /// What `name` names in `dir` among the inodes here.
    fn cached(&self, dir: u16, name: &[u8]) -> Option<u16> {
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

    /// Checks that `name` may be made in `dir`.
    fn may_create(&mut self, dir: u16, name: &[u8]) -> Result<(), u64> {
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
        Ok(())
    }

    /// Makes an empty file or directory (or a node of another kind, but
    /// not under `/home`).
    pub fn create(&mut self, dir: u16, name: &[u8], kind: Kind) -> Result<u16, u64> {
        self.may_create(dir, name)?;
        if !self.is_remote(dir) {
            return self.alloc_inode(dir, name, kind);
        }
        let mut p = [0u8; PATH_MAX];
        let n = self.child_path(dir, name, &mut p)?;
        let path = &p[..n];
        let (handle, size, _) = match kind {
            Kind::File => remote::open(path, server::CREATE | server::EXCL)?,
            Kind::Dir => {
                remote::mkdir(path)?;
                remote::open(path, server::DIRECTORY)?
            }
            _ => return Err(EINVAL),
        };
        self.proxy(dir, name, kind, handle, size)
    }

    /// Makes a symbolic link to `target`.
    pub fn symlink(&mut self, dir: u16, name: &[u8], target: &[u8]) -> Result<u16, u64> {
        self.may_create(dir, name)?;
        if !self.is_remote(dir) {
            let l = self.alloc_inode(dir, name, Kind::Symlink)?;
            return self.write(l, 0, target).map(|_| l);
        }
        let mut p = [0u8; PATH_MAX];
        let n = self.child_path(dir, name, &mut p)?;
        remote::symlink(&p[..n], target)?;
        self.proxy(dir, name, Kind::Symlink, 0, target.len() as u64)
    }

    fn alloc_inode(&mut self, dir: u16, name: &[u8], kind: Kind) -> Result<u16, u64> {
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        let ino = (2..MAX_INODES as u16).find(|&i| self.inodes[i as usize].kind == Kind::Free).ok_or(ENOSPC)?;
        let n = &mut self.inodes[ino as usize];
        *n = Inode {
            kind,
            parent: dir,
            nlen: name.len() as u8,
            name: [0; NAME_MAX],
            size: 0,
            blocks: [0; FILE_BLOCKS],
            remote: false,
            handle: 0,
        };
        n.name[..name.len()].copy_from_slice(name);
        Ok(ino)
    }

    /// The entry at position `pos` of directory `dir`, or after it:
    /// positions 0 and 1 are `.` and `..`; then, in memory, each inode's
    /// number plus 2, and in a remote directory the server's entries in
    /// its order, counted from 2.
    pub fn entry(&self, dir: u16, pos: u64) -> Option<Dirent> {
        let make = |next, ino: u64, kind, name: &[u8]| {
            let mut d = Dirent { next, ino, kind, len: name.len().min(NAME_MAX) as u8, name: [0; NAME_MAX] };
            d.name[..d.len as usize].copy_from_slice(&name[..d.len as usize]);
            d
        };
        match pos {
            0 => return Some(make(1, dir as u64, Kind::Dir, b".")),
            1 => return Some(make(2, self.inodes[dir as usize].parent as u64, Kind::Dir, b"..")),
            _ => {}
        }
        // Its own entries here (in a remote directory, those that are not
        // the server's: the root's).
        let remote = self.is_remote(dir);
        let own = |i: usize| {
            let n = &self.inodes[i];
            i >= 2 && n.kind != Kind::Free && n.parent == dir && !(remote && n.remote)
        };
        if pos < SERVER_POS {
            let found = (pos.saturating_sub(2) as usize..MAX_INODES)
                .find(|&i| own(i))
                .map(|i| make(i as u64 + 3, i as u64, self.inodes[i].kind, self.name(i as u16)));
            if found.is_some() || !remote {
                return found;
            }
        }
        // Then the server's, but for those hidden by its own.
        let mut k = pos.saturating_sub(SERVER_POS);
        loop {
            let (ino, kind, name, len) = self.remote_entry(dir, k)?;
            let hidden = self.cached(dir, &name[..len]).is_some_and(|i| !self.is_remote(i));
            if !hidden {
                return Some(make(SERVER_POS + k + 1, ino, kind, &name[..len]));
            }
            k += 1;
        }
    }

    /// Remote directory `dir`'s entry `k` (from 0): its inode number (the
    /// one here if it has one), kind and name. Entries come from the
    /// server 64 at a time, the last batch kept while the buffer holds it.
    fn remote_entry(&self, dir: u16, k: u64) -> Option<(u64, Kind, [u8; NAME_MAX], usize)> {
        let handle = self.inodes[dir as usize].handle;
        let [h, cookie, base, count, next, stamp] = self.listed.get();
        let kept = h == handle && stamp == remote::calls() && base <= k;
        let at = if kept && k < base + count {
            k - base
        } else {
            let (mut cookie, mut base) = if kept { (next, base + count) } else { (0, 0) };
            loop {
                let (count, next) = remote::readdir(handle, cookie).ok()?;
                if count == 0 {
                    return None;
                }
                if k < base + count as u64 {
                    self.listed.set([handle, cookie, base, count as u64, next, remote::calls()]);
                    break k - base;
                }
                base += count as u64;
                cookie = next;
            }
        };
        let _ = cookie;
        let e = server::Entry(&remote::buf()[at as usize * server::ENTRY..(at as usize + 1) * server::ENTRY]);
        let mut name = [0u8; NAME_MAX];
        let len = e.name().len();
        name[..len].copy_from_slice(e.name());
        let kind = match e.kind() {
            server::KIND_DIR => Kind::Dir,
            server::KIND_LINK => Kind::Symlink,
            _ => Kind::File,
        };
        let theirs = u32::from_le_bytes(e.0[..4].try_into().unwrap()) as u64;
        let ino = self.cached(dir, &name[..len]).map_or(MAX_INODES as u64 + theirs, |i| i as u64);
        Some((ino, kind, name, len))
    }

    /// Follows `path` from `cwd` (or the root, if absolute). The last part
    /// is followed through symbolic links only if `follow`.
    pub fn resolve(&mut self, cwd: u16, path: &[u8], follow: bool) -> Result<u16, u64> {
        self.walk(cwd, path, follow, 0)
    }

    fn walk(&mut self, cwd: u16, path: &[u8], follow: bool, depth: u32) -> Result<u16, u64> {
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
    pub fn parent_of<'a>(&mut self, cwd: u16, path: &'a [u8]) -> Result<(u16, &'a [u8]), u64> {
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
        if i.remote {
            if i.kind == Kind::Symlink {
                let mut p = [0u8; PATH_MAX];
                let mut t = [0u8; PATH_MAX];
                let Ok(len) = self.path(ino, &mut p).and_then(|len| remote::readlink(&p[..len], &mut t)) else { return 0 };
                let n = n.min(len.saturating_sub(off as usize));
                buf[..n].copy_from_slice(&t[off as usize..off as usize + n]);
                return n;
            }
            return remote::read(i.handle, off, &mut buf[..n]).unwrap_or(0);
        }
        match i.kind {
            Kind::Image => {
                let base = self.images[i.size as usize].0;
                // SAFETY: the image is mapped for this server's life and
                // off + n is within its length.
                let src = unsafe { core::slice::from_raw_parts((base + off) as *const u8, n) };
                buf[..n].copy_from_slice(src);
            }
            _ => {
                for (k, b) in buf[..n].iter_mut().enumerate() {
                    let at = off as usize + k;
                    let block = self.block(ino, at / PAGE);
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
        if self.is_remote(ino) {
            if end > u32::MAX as u64 || self.kind(ino) != Kind::File {
                return Err(EFBIG);
            }
            remote::write(self.inodes[ino as usize].handle, off, data)?;
            let i = &mut self.inodes[ino as usize];
            i.size = i.size.max(end as u32);
            return Ok(data.len());
        }
        if end > (MAX_FILE_PAGES * PAGE) as u64 {
            return Err(EFBIG);
        }
        for (k, &b) in data.iter().enumerate() {
            let at = off as usize + k;
            let mut block = self.block(ino, at / PAGE);
            if block == 0 {
                block = self.alloc().ok_or(ENOSPC)?;
                if let Err(e) = self.set_block(ino, at / PAGE, block) {
                    self.free(block);
                    return Err(e);
                }
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
        if self.is_remote(ino) {
            if len > u32::MAX as u64 {
                return Err(EFBIG);
            }
            remote::truncate(self.inodes[ino as usize].handle, len)?;
            self.inodes[ino as usize].size = len as u32;
            return Ok(());
        }
        if len > (MAX_FILE_PAGES * PAGE) as u64 {
            return Err(EFBIG);
        }
        let old = self.inodes[ino as usize].size as u64;
        // Zero what is cut off in the last page, free whole pages past it.
        for at in len..old.min(len.next_multiple_of(PAGE as u64)) {
            let block = self.block(ino, at as usize / PAGE);
            if block != 0 {
                // SAFETY: as in `read`.
                unsafe { *self.page(block).add(at as usize % PAGE) = 0 };
            }
        }
        self.free_from(ino, (len as usize).div_ceil(PAGE));
        self.inodes[ino as usize].size = len as u32;
        Ok(())
    }

    /// Page `p` of file `ino`'s pool page (0: none, a hole).
    fn block(&self, ino: u16, p: usize) -> u16 {
        let i = &self.inodes[ino as usize];
        if p < DIRECT {
            return i.blocks[p];
        }
        match i.blocks[INDIRECT] {
            0 => 0,
            // SAFETY: a used block is a mapped pool page, of PAGE / 2 u16s.
            ind => unsafe { *(self.page(ind) as *const u16).add(p - DIRECT) },
        }
    }

    /// Makes `block` page `p` of file `ino`, making its indirect page if
    /// it needs one.
    fn set_block(&mut self, ino: u16, p: usize, block: u16) -> Result<(), u64> {
        if p < DIRECT {
            self.inodes[ino as usize].blocks[p] = block;
            return Ok(());
        }
        let mut ind = self.inodes[ino as usize].blocks[INDIRECT];
        if ind == 0 {
            ind = self.alloc().ok_or(ENOSPC)?;
            self.inodes[ino as usize].blocks[INDIRECT] = ind;
        }
        // SAFETY: as in `block`; p - DIRECT < PAGE / 2 (checked by the
        // callers against MAX_FILE_PAGES).
        unsafe { *(self.page(ind) as *mut u16).add(p - DIRECT) = block };
        Ok(())
    }

    /// Frees file `ino`'s pages from page `first` on, and its indirect page
    /// if none it names is left.
    fn free_from(&mut self, ino: u16, first: usize) {
        for p in first..DIRECT {
            let block = core::mem::take(&mut self.inodes[ino as usize].blocks[p]);
            self.free(block);
        }
        let ind = self.inodes[ino as usize].blocks[INDIRECT];
        if ind == 0 {
            return;
        }
        for p in first.max(DIRECT)..MAX_FILE_PAGES {
            // SAFETY: as in `set_block`.
            let block = unsafe { core::mem::take(&mut *(self.page(ind) as *mut u16).add(p - DIRECT)) };
            self.free(block);
        }
        if first <= DIRECT {
            self.inodes[ino as usize].blocks[INDIRECT] = 0;
            self.free(ind);
        }
    }

    /// Removes `ino` (a directory only if empty).
    pub fn remove(&mut self, ino: u16) -> Result<(), u64> {
        if ino == ROOT {
            return Err(EINVAL);
        }
        if ino == self.mount {
            return Err(EBUSY);
        }
        if self.is_remote(ino) {
            let mut p = [0u8; PATH_MAX];
            let n = self.path(ino, &mut p)?;
            remote::unlink(&p[..n])?;
            self.drop_proxy(ino);
            return Ok(());
        }
        if self.kind(ino) == Kind::Dir && self.entry(ino, 2).is_some() {
            return Err(ENOTEMPTY);
        }
        self.free_from(ino, 0);
        self.inodes[ino as usize].kind = Kind::Free;
        Ok(())
    }

    /// Moves `ino` to `name` in `dir`, replacing what is there (not a
    /// non-empty directory).
    pub fn rename(&mut self, ino: u16, dir: u16, name: &[u8]) -> Result<(), u64> {
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        if ino == self.mount {
            return Err(EBUSY);
        }
        // Not across the server's edge.
        if self.is_remote(ino) != self.is_remote(dir) {
            return Err(EXDEV);
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
        let old = self.lookup(dir, name);
        if let Some(old) = old {
            if old == ino {
                return Ok(());
            }
            if self.kind(old) == Kind::Dir && self.kind(ino) != Kind::Dir {
                return Err(EISDIR);
            }
            if self.kind(old) != Kind::Dir && self.kind(ino) == Kind::Dir {
                return Err(ENOTDIR);
            }
        }
        if self.is_remote(ino) {
            // The server replaces what is there.
            let (mut from, mut to) = ([0u8; PATH_MAX], [0u8; PATH_MAX]);
            let f = self.path(ino, &mut from)?;
            let t = self.child_path(dir, name, &mut to)?;
            remote::rename(&from[..f], &to[..t])?;
            if let Some(old) = old {
                self.drop_proxy(old);
            }
        } else if let Some(old) = old {
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
    /// The terminal ([`crate::tty`]).
    Tty,
    /// A socket ([`crate::sock`]), its number in `pipe`.
    Socket,
    /// An epoll instance, its number in `pipe` (`State::epolls`).
    Epoll,
    /// A Unix domain socket ([`crate::unix`]), its number in `pipe`.
    Unix,
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
