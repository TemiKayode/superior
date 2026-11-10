//! The filesystem server (spec section 4): a POSIX-shaped tree of files and
//! directories on a block device, with a write-ahead journal so that no
//! acknowledged write is ever lost.
//!
//! **No global namespace.** Each client sees only its own container, a
//! tree under its own root directory, picked by the badge the Component
//! Manager put on its capability (its component number, the same across
//! its restarts). The root is made on the first change.
//!
//! **Crash-only.** Starting is recovery: mount replays a committed journal
//! transaction left by an instance (or a machine) that stopped before
//! finishing it, then checks that every block and inode is accounted for.
//! Every change is one transaction of at most [`JMAX`] blocks:
//!
//! 1. the changed blocks (data, directory, indirect, inode, bitmap) are
//!    written to the journal area, then a flush;
//! 2. the journal header, naming their home blocks and holding a checksum
//!    over them, is written, then a flush. The transaction is committed:
//!    only now is the client answered;
//! 3. after the reply, the blocks are written home, a flush, and the
//!    header is cleared.
//!
//! A crash before step 2 completes leaves no valid header (the checksum
//! fails or it is the cleared one), and the change was never acknowledged.
//! A crash after it replays at the next mount. An operation that fails
//! half-way (no space) reloads the inodes and bitmap from the disk, which
//! between requests always holds the latest state. Block calls the driver
//! fails with `PeerRestarted` (it was restarted) are retried.
//!
//! Disk layout, in 4 KiB blocks: 0 superblock, 1 journal header, 2-9
//! journal blocks, 10-17 inodes (512 of 64 bytes; 0 is never used), 18 the
//! block bitmap, then data. An unformatted disk is formatted at mount.
//!
//! Symbolic links (`fs::SYMLINK`) are inodes of their own kind whose one
//! data block holds the target. A path is walked one component at a time
//! from the container's root; meeting a link, the walker splices its
//! target in front of the rest of the path and goes on, from the root for
//! an absolute target, at most `fs::MAX_LINKS` times. `..` (allowed only
//! in targets) goes to the parent, and stays at the root.
//!
//! Inode: container (u16), kind (u8), flags (u8: 1 = root), generation
//! (u32), size (u64), parent (u32), 4 spare bytes, 9 direct blocks and one
//! indirect block (u32 each). A handle is `inode | generation << 32`, so a
//! handle to a removed file never reaches the inode's next owner.
//! Directory entry, 64 bytes: inode (u32), kind (u8), name length (u8),
//! name.
//!
//! **Rings.** A client may also submit requests through a ring (spec
//! section 3, Tier 2): a page of submission and completion queues and data
//! pages, shared with this server ([`fs::ring`]). The server takes
//! submissions while there are any, and sleeps only after saying so in
//! the ring's flags; a client that submits then rings its doorbell, a
//! notification bound to this server's thread, so one `Recv` waits for
//! both calls and doorbells. A completion is posted only once the change
//! is committed, and the client's completion notification is signalled
//! only if it said it sleeps. The ring pages belong to the manager, not
//! the client, so a client restarting cannot unmap them from under this
//! server.
//!
//! Slots: 0 the `block` service, 1 the `fs` endpoint (receive), 2 untyped
//! memory, 3 where a client's frame arrives.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering, fence};
use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::interfaces::fs::ring;
use superior_objects::interfaces::{Status, block, fs};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const BLOCK_EP: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 2;
const LENT: u64 = 3;
/// Buffers, one frame each, mapped at `BUF_VA + 4096 * (slot - BUF0)`.
const BUF0: u64 = 8;
const B_HDR: u64 = BUF0;
const B_INODES: u64 = BUF0 + 1; // INODE_BLOCKS of them
const B_BITMAP: u64 = B_INODES + INODE_BLOCKS;
/// Replay, format and the mount check.
const B_SCRATCH: u64 = B_BITMAP + 1;
/// Directory blocks read while looking names up.
const B_LOOK: u64 = B_SCRATCH + 1;
/// Indirect blocks read to map a file block.
const B_IND: u64 = B_LOOK + 1;
/// File data on its way to a client, or from one.
const B_DATA: u64 = B_IND + 1;
/// The path(s) of the request.
const B_PATH: u64 = B_DATA + 1;
/// Paths being walked, with link targets spliced in (two: a rename walks
/// both of its paths).
const B_WALK: u64 = B_PATH + 1;
const B_WALK2: u64 = B_WALK + 1;
/// A link's target, read while walking.
const B_LINK: u64 = B_WALK2 + 1;
/// Blocks a transaction changes that have no buffer of their own.
const B_TX: u64 = B_LINK + 1;
const NTX: u64 = 6;
const BUFS: u64 = B_TX + NTX - BUF0;
const BUF_VA: u64 = USER_BASE + 0x4000_0000;
const LENT_VA: u64 = USER_BASE + 0x5000_0000;

/// Rings, one per client container at most.
const MAX_RINGS: usize = 4;
/// Each ring's pages, `ring::PAGES` slots per ring.
const RING_PAGES: u64 = B_TX + NTX;
/// Each ring's completion notification.
const RING_NTFN: u64 = RING_PAGES + MAX_RINGS as u64 * ring::PAGES;
/// The doorbell: a notification bound to this thread.
const DOORBELL: u64 = RING_NTFN + MAX_RINGS as u64;
/// A capability being granted in a reply.
const MINT: u64 = DOORBELL + 1;
/// Ring `r`'s pages are mapped at `RING_VA + r * RING_STRIDE`.
const RING_VA: u64 = USER_BASE + 0x7000_0000;
const RING_STRIDE: u64 = 0x10_0000;
// Rights masks.
const READ: u64 = 1;
const WRITE: u64 = 2;
const ALL: u64 = 0x1f;

// Disk layout, in blocks.
const SUPER: u64 = 0;
const JHDR: u64 = 1;
const JDATA: u64 = 2;
const JMAX: usize = 8;
const INODES: u64 = JDATA + JMAX as u64;
const INODE_BLOCKS: u64 = 8;
const BITMAP: u64 = INODES + INODE_BLOCKS;
const DATA: u64 = BITMAP + 1;
/// Blocks one bitmap block covers.
const MAX_DISK: u64 = 8 * fs::BLOCK;
const INODE_SIZE: u64 = 64;
const NINODES: u64 = INODE_BLOCKS * fs::BLOCK / INODE_SIZE;
const DIRECT: u64 = 9;
const PER_IND: u64 = fs::BLOCK / 4;
const ENTRIES: u64 = fs::BLOCK / fs::ENTRY as u64;

const KIND_FILE: u8 = fs::KIND_FILE as u8;
const KIND_DIR: u8 = fs::KIND_DIR as u8;
const KIND_LINK: u8 = fs::KIND_LINK as u8;
const ROOT: u8 = 1;

const SUPER_MAGIC: u64 = u64::from_le_bytes(*b"SUPFS002");
const JOURNAL_MAGIC: u64 = u64::from_le_bytes(*b"SUPJRNL2");
const FNV: u64 = 0xcbf2_9ce4_8422_2325;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("fs: {}", format_args!($($t)*))) };
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// Stops this instance: the manager restarts it, and mount recovers.
fn crash(why: &str) -> ! {
    say!("cannot go on: {why}; crashing so a new instance recovers");
    // SAFETY: deliberately not: nothing is mapped here, so this faults.
    unsafe { ((USER_BASE + 0x6000_0000) as *const u64).read_volatile() };
    superior_sys::park()
}

fn buf(slot: u64) -> &'static mut [u8] {
    // SAFETY: every buffer frame is mapped at its address for good, and
    // the server is single-threaded.
    unsafe { core::slice::from_raw_parts_mut((BUF_VA + 4096 * (slot - BUF0)) as *mut u8, 4096) }
}

fn word(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn set_word(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn u32_at(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64
}

fn set_u32(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
}

fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// A block call to the driver, lending buffer `slot`; retried while the
/// driver is being restarted under it.
fn block_call(op: u64, blockno: u64, slot: Option<u64>) {
    let x = CapTransfer {
        grant: slot.map(|s| s as u16),
        accept: None,
    };
    let sectors = fs::BLOCK / block::SECTOR;
    for _ in 0..100 {
        let r = syscall_x(
            Syscall::Call,
            BLOCK_EP,
            [op, blockno * sectors, sectors, 0],
            x,
        );
        if r.status == 0 && r.msg[0] == Status::Ok as u64 {
            return;
        }
        if r.status != Error::PeerRestarted.code() && r.status != 0 {
            break;
        }
        syscall(Syscall::Yield, 0, [0; 4]);
    }
    crash("the block device keeps failing");
}

fn read_block(b: u64, slot: u64) {
    block_call(block::READ, b, Some(slot));
}

fn write_block(b: u64, slot: u64) {
    block_call(block::WRITE, b, Some(slot));
}

fn flush() {
    block_call(block::FLUSH, 0, None);
}

/// Maps the client's frame (writable or not); false if it cannot be.
fn map_lent(writable: bool) -> bool {
    syscall(Syscall::FrameMap, LENT, [LENT_VA, writable as u64, 0, 0]).status == 0
}

fn unmap_lent() {
    syscall(Syscall::FrameUnmap, LENT, [0; 4]);
}

fn lent_bytes() -> &'static mut [u8] {
    // SAFETY: called only while the client's frame is mapped at LENT_VA
    // (writable when written).
    unsafe { core::slice::from_raw_parts_mut(LENT_VA as *mut u8, 4096) }
}

/// Where a request's data is: the frame a call lent, or a ring's data
/// pages (a byte range of them).
#[derive(Clone, Copy)]
enum Io {
    None,
    Lent,
    Shared { va: u64, len: usize },
}

impl Io {
    /// The data, mapped; `None` if there is none or it cannot be mapped.
    /// Every call is paired with [`Io::end`].
    fn begin(self, writable: bool) -> Option<&'static mut [u8]> {
        match self {
            Io::None => None,
            Io::Lent => map_lent(writable).then(lent_bytes),
            // SAFETY: a ring's pages stay mapped while it is attached, and
            // the range lies inside its data pages. The client may change
            // them meanwhile; that only garbles its own request.
            Io::Shared { va, len } => {
                Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) })
            }
        }
    }

    fn end(self) {
        if let Io::Lent = self {
            unmap_lent();
        }
    }
}

type R<T> = Result<T, Status>;

fn reply(r: R<[u64; 3]>) -> [u64; 4] {
    match r {
        Ok([a, b, c]) => [Status::Ok as u64, a, b, c],
        Err(s) => [s as u64, 0, 0, 0],
    }
}

/// An inode, in its buffer.
#[derive(Clone, Copy)]
struct Inode {
    ino: u64,
    slot: u64,
    off: usize,
}

impl Inode {
    fn of(ino: u64) -> Inode {
        Inode {
            ino,
            slot: B_INODES + ino * INODE_SIZE / fs::BLOCK,
            off: (ino * INODE_SIZE % fs::BLOCK) as usize,
        }
    }
    fn bytes(&self) -> &'static mut [u8] {
        &mut buf(self.slot)[self.off..self.off + INODE_SIZE as usize]
    }
    fn container(&self) -> u64 {
        u16::from_le_bytes(self.bytes()[0..2].try_into().unwrap()) as u64
    }
    fn kind(&self) -> u8 {
        self.bytes()[2]
    }
    fn is_root(&self) -> bool {
        self.bytes()[3] & ROOT != 0
    }
    fn generation(&self) -> u64 {
        u32_at(self.bytes(), 4)
    }
    fn handle(&self) -> u64 {
        self.ino | self.generation() << 32
    }
    fn size(&self) -> u64 {
        word(self.bytes(), 8)
    }
    fn set_size(&self, n: u64) {
        set_word(self.bytes(), 8, n);
    }
    fn parent(&self) -> u64 {
        u32_at(self.bytes(), 16)
    }
    fn set_parent(&self, p: u64) {
        set_u32(self.bytes(), 16, p);
    }
    /// Direct block `i` (`i < DIRECT`), or the indirect block (`DIRECT`).
    fn ptr(&self, i: u64) -> u64 {
        u32_at(self.bytes(), 24 + 4 * i as usize)
    }
    fn set_ptr(&self, i: u64, b: u64) {
        set_u32(self.bytes(), 24 + 4 * i as usize, b);
    }
    fn home(&self) -> u64 {
        INODES + (self.slot - B_INODES)
    }
    fn is_free(&self) -> bool {
        self.kind() == 0
    }
}

/// The blocks one change touches: (home block, buffer).
struct Tx {
    e: [(u64, u64); JMAX],
    n: usize,
    used: u64,
}

impl Tx {
    fn new() -> Tx {
        Tx {
            e: [(0, 0); JMAX],
            n: 0,
            used: 0,
        }
    }

    fn add(&mut self, home: u64, slot: u64) {
        if self.e[..self.n].iter().any(|&(h, _)| h == home) {
            return;
        }
        if self.n == JMAX {
            crash("a transaction outgrew the journal");
        }
        self.e[self.n] = (home, slot);
        self.n += 1;
    }

    /// Block `home` in a buffer of this transaction: zeroed if `fresh`,
    /// else as on the disk (or as this transaction already changed it).
    fn get(&mut self, home: u64, fresh: bool) -> &'static mut [u8] {
        if let Some(&(_, s)) = self.e[..self.n].iter().find(|&&(h, _)| h == home) {
            return buf(s);
        }
        if self.used == NTX {
            crash("a transaction ran out of buffers");
        }
        let slot = B_TX + self.used;
        self.used += 1;
        if fresh {
            buf(slot).fill(0);
        } else {
            read_block(home, slot);
        }
        self.add(home, slot);
        buf(slot)
    }

    fn inode(&mut self, n: Inode) {
        self.add(n.home(), n.slot);
    }

    fn bitmap(&mut self) {
        self.add(BITMAP, B_BITMAP);
    }
}

/// A client's path: no `..`, no long names, no NUL.
fn plain(path: &[u8]) -> R<()> {
    let bad = path
        .split(|&c| c == b'/')
        .any(|c| c == b".." || c.len() > fs::MAX_NAME || c.contains(&0));
    if bad { Err(Status::Invalid) } else { Ok(()) }
}

/// The next component of `p` from `at`, skipping `/` and `.`: its range.
fn next_component(p: &[u8], mut at: usize) -> Option<(usize, usize)> {
    loop {
        while at < p.len() && p[at] == b'/' {
            at += 1;
        }
        if at == p.len() {
            return None;
        }
        let end = p[at..].iter().position(|&c| c == b'/').map_or(p.len(), |i| at + i);
        if &p[at..end] != b"." {
            return Some((at, end));
        }
        at = end;
    }
}

/// Where a path leads.
#[derive(Clone, Copy)]
enum Walked {
    /// A directory reached with no last name: the root, or through `..`.
    Dir(Inode),
    /// The last component, in its directory (it may not exist).
    Entry(Inode, &'static [u8]),
}

/// A directory entry found by name: the entry's block and index, and
/// what it names.
#[derive(Clone, Copy)]
struct Found {
    blockno: u64,
    idx: usize,
    ino: u64,
}

struct Fs {
    blocks: u64,
    seq: u64,
    /// Committed but not yet written home: (home block, buffer).
    pending: [(u64, u64); JMAX],
    npending: usize,
    rings: [Option<Ring>; MAX_RINGS],
    /// Requests taken from rings, doorbells that woke this server, and
    /// completion signals sent.
    ring_ops: u64,
    wakeups: u64,
    signals: u64,
}

/// A client's ring.
#[derive(Clone, Copy)]
struct Ring {
    container: u64,
    /// Pages attached so far.
    attached: u64,
    started: bool,
}

/// A word of a ring's header.
fn hdr(page: u64, off: usize) -> &'static AtomicU32 {
    // SAFETY: the ring page is mapped while the ring is attached, and the
    // offsets are inside it and aligned.
    unsafe { &*((page + off as u64) as *const AtomicU32) }
}

impl Fs {
    fn mount() -> Fs {
        let start = ticks();
        for i in 0..BUFS {
            let slot = BUF0 + i;
            let made = syscall(
                Syscall::Retype,
                UNTYPED,
                [ObjectType::Frame as u64, 0, slot, 0],
            );
            let mapped = syscall(Syscall::FrameMap, slot, [BUF_VA + 4096 * i, 1, 0, 0]);
            if made.status != 0 || mapped.status != 0 {
                crash("no memory for buffers");
            }
        }
        let info = syscall(Syscall::Call, BLOCK_EP, [block::INFO, block::VERSION, 0, 0]);
        let blocks = (info.msg[1] * block::SECTOR / fs::BLOCK).min(MAX_DISK);
        if info.status != 0 || blocks <= DATA + 8 {
            crash("no usable block device");
        }
        let mut f = Fs {
            blocks,
            seq: 0,
            pending: [(0, 0); JMAX],
            npending: 0,
            rings: [None; MAX_RINGS],
            ring_ops: 0,
            wakeups: 0,
            signals: 0,
        };
        // The doorbell, and each ring's completion notification.
        for slot in (RING_NTFN..RING_NTFN + MAX_RINGS as u64).chain([DOORBELL]) {
            let made = syscall(
                Syscall::Retype,
                UNTYPED,
                [ObjectType::Notification as u64, 0, slot, 0],
            );
            if made.status != 0 {
                crash("no memory for notifications");
            }
        }
        if syscall(Syscall::NotificationBind, DOORBELL, [0; 4]).status != 0 {
            crash("cannot bind the doorbell");
        }
        read_block(SUPER, B_SCRATCH);
        if word(buf(B_SCRATCH), 0) != SUPER_MAGIC {
            f.format();
        }
        let replayed = f.replay();
        f.reload();
        say!(
            "mounted in {} ticks: {} blocks{}",
            ticks() - start,
            f.blocks,
            match replayed {
                0 => "; journal clean",
                _ => "; replayed a committed transaction",
            }
        );
        f.check();
        f
    }

    /// Reads the inodes and the bitmap from the disk, dropping changes
    /// not committed.
    fn reload(&self) {
        for i in 0..INODE_BLOCKS {
            read_block(INODES + i, B_INODES + i);
        }
        read_block(BITMAP, B_BITMAP);
    }

    fn format(&mut self) {
        // Said first: the injector may kill the server before the end.
        say!("formatting {} blocks", self.blocks);
        buf(B_SCRATCH).fill(0);
        write_block(JHDR, B_SCRATCH);
        for b in 0..INODE_BLOCKS {
            write_block(INODES + b, B_SCRATCH);
        }
        write_block(BITMAP, B_SCRATCH);
        flush();
        set_word(buf(B_SCRATCH), 0, SUPER_MAGIC);
        set_word(buf(B_SCRATCH), 8, self.blocks);
        write_block(SUPER, B_SCRATCH);
        flush();
        say!("formatted {} blocks", self.blocks);
    }

    /// The checksum of the header (magic, sequence, count and homes) and
    /// the journal blocks, whose hashes `each` gives.
    fn header_sum(hdr: &[u8], mut each: impl FnMut(usize) -> u64) -> u64 {
        let count = word(hdr, 16) as usize;
        let mut h = fnv(fnv(FNV, &hdr[..24]), &hdr[32..32 + 8 * count]);
        for j in 0..count {
            h ^= each(j);
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        h
    }

    /// Replays a committed transaction, if the header holds one. Returns
    /// how many blocks it wrote home.
    fn replay(&mut self) -> usize {
        read_block(JHDR, B_HDR);
        let hdr = buf(B_HDR);
        let count = word(hdr, 16) as usize;
        if word(hdr, 0) != JOURNAL_MAGIC || count == 0 || count > JMAX {
            return 0;
        }
        self.seq = word(hdr, 8);
        // Every journal block must match the checksum before any goes home.
        let sum = Fs::header_sum(hdr, |j| {
            read_block(JDATA + j as u64, B_SCRATCH);
            fnv(FNV, buf(B_SCRATCH))
        });
        if sum != word(hdr, 24) {
            return 0; // torn: never committed, never acknowledged
        }
        for j in 0..count {
            let home = word(buf(B_HDR), 32 + 8 * j);
            read_block(JDATA + j as u64, B_SCRATCH);
            write_block(home, B_SCRATCH);
        }
        flush();
        self.clear_header();
        count
    }

    fn clear_header(&self) {
        buf(B_HDR).fill(0);
        write_block(JHDR, B_HDR);
        flush();
    }

    /// Steps 1 and 2: makes the transaction durable in the journal. Step 3
    /// is [`Fs::checkpoint`].
    fn commit(&mut self, tx: &Tx) {
        let blocks = &tx.e[..tx.n];
        if blocks.is_empty() {
            return;
        }
        for (j, &(_, slot)) in blocks.iter().enumerate() {
            write_block(JDATA + j as u64, slot);
        }
        flush();
        self.seq += 1;
        let hdr = buf(B_HDR);
        hdr.fill(0);
        set_word(hdr, 0, JOURNAL_MAGIC);
        set_word(hdr, 8, self.seq);
        set_word(hdr, 16, blocks.len() as u64);
        for (j, &(home, _)) in blocks.iter().enumerate() {
            set_word(hdr, 32 + 8 * j, home);
        }
        let sum = Fs::header_sum(hdr, |j| fnv(FNV, buf(blocks[j].1)));
        set_word(hdr, 24, sum);
        write_block(JHDR, B_HDR);
        flush();
        self.pending[..blocks.len()].copy_from_slice(blocks);
        self.npending = blocks.len();
    }

    /// Step 3: writes the committed blocks home and clears the header.
    fn checkpoint(&mut self) {
        if self.npending == 0 {
            return;
        }
        for &(home, slot) in &self.pending[..self.npending] {
            write_block(home, slot);
        }
        flush();
        self.clear_header();
        self.npending = 0;
    }

    /// Commits `tx` if `r` succeeded; otherwise undoes its changes to the
    /// inodes and bitmap.
    fn finish<T>(&mut self, tx: Tx, r: R<T>) -> R<T> {
        match r {
            Ok(v) => {
                self.commit(&tx);
                Ok(v)
            }
            Err(e) => {
                self.reload();
                Err(e)
            }
        }
    }

    // ---- blocks ----

    fn is_used(&self, b: u64) -> bool {
        buf(B_BITMAP)[b as usize / 8] & 1 << (b % 8) != 0
    }

    fn alloc(&self, tx: &mut Tx) -> R<u64> {
        let b = (DATA..self.blocks)
            .find(|&b| !self.is_used(b))
            .ok_or(Status::NoSpace)?;
        buf(B_BITMAP)[b as usize / 8] |= 1 << (b % 8);
        tx.bitmap();
        Ok(b)
    }

    fn free(&self, tx: &mut Tx, b: u64) {
        if (DATA..self.blocks).contains(&b) {
            buf(B_BITMAP)[b as usize / 8] &= !(1 << (b % 8));
            tx.bitmap();
        }
    }

    /// The disk block holding file block `bi`, or 0 (a hole).
    fn bmap(&self, n: Inode, bi: u64) -> u64 {
        if bi < DIRECT {
            return n.ptr(bi);
        }
        match n.ptr(DIRECT) {
            0 => 0,
            ind if bi < fs::MAX_BLOCKS => {
                read_block(ind, B_IND);
                u32_at(buf(B_IND), 4 * (bi - DIRECT) as usize)
            }
            _ => 0,
        }
    }

    /// The disk block holding file block `bi`, made if it is a hole, in
    /// a buffer of the transaction.
    fn bmap_write(&self, tx: &mut Tx, n: Inode, bi: u64) -> R<&'static mut [u8]> {
        if bi >= fs::MAX_BLOCKS {
            return Err(Status::NoSpace);
        }
        let (b, fresh) = if bi < DIRECT {
            match n.ptr(bi) {
                0 => {
                    let b = self.alloc(tx)?;
                    n.set_ptr(bi, b);
                    tx.inode(n);
                    (b, true)
                }
                b => (b, false),
            }
        } else {
            let ind = match n.ptr(DIRECT) {
                0 => {
                    let b = self.alloc(tx)?;
                    n.set_ptr(DIRECT, b);
                    tx.inode(n);
                    tx.get(b, true);
                    b
                }
                b => b,
            };
            let at = 4 * (bi - DIRECT) as usize;
            match u32_at(tx.get(ind, false), at) {
                0 => {
                    let b = self.alloc(tx)?;
                    set_u32(tx.get(ind, false), at, b);
                    (b, true)
                }
                b => (b, false),
            }
        };
        Ok(tx.get(b, fresh))
    }

    /// Frees every block of `n` from file block `from` on.
    fn free_from(&self, tx: &mut Tx, n: Inode, from: u64) {
        for bi in from..DIRECT {
            let b = n.ptr(bi);
            if b != 0 {
                self.free(tx, b);
                n.set_ptr(bi, 0);
                tx.inode(n);
            }
        }
        let ind = n.ptr(DIRECT);
        if ind == 0 {
            return;
        }
        if from <= DIRECT {
            read_block(ind, B_IND);
            for i in 0..PER_IND as usize {
                let b = u32_at(buf(B_IND), 4 * i);
                if b != 0 {
                    self.free(tx, b);
                }
            }
            self.free(tx, ind);
            n.set_ptr(DIRECT, 0);
            tx.inode(n);
        } else {
            let t = tx.get(ind, false);
            for i in (from - DIRECT) as usize..PER_IND as usize {
                let b = u32_at(t, 4 * i);
                if b != 0 {
                    self.free(tx, b);
                    set_u32(t, 4 * i, 0);
                }
            }
        }
    }

    // ---- inodes and directories ----

    fn root(&self, c: u64) -> Option<Inode> {
        (1..NINODES)
            .map(Inode::of)
            .find(|n| n.container() == c && n.kind() == KIND_DIR && n.is_root())
    }

    /// The caller's root, made (and committed on its own) if it has none.
    fn ensure_root(&mut self, c: u64) -> R<Inode> {
        if let Some(r) = self.root(c) {
            return Ok(r);
        }
        let mut tx = Tx::new();
        let r = self.alloc_inode(&mut tx, c, KIND_DIR, 0).map(|r| {
            r.bytes()[3] = ROOT;
            r
        });
        let r = self.finish(tx, r)?;
        // Home at once: the request's own transaction follows.
        self.checkpoint();
        Ok(r)
    }

    fn alloc_inode(&self, tx: &mut Tx, c: u64, kind: u8, parent: u64) -> R<Inode> {
        let n = (1..NINODES)
            .map(Inode::of)
            .find(|n| n.is_free())
            .ok_or(Status::NoSpace)?;
        let generation = (n.generation() + 1) & 0xffff_ffff;
        let b = n.bytes();
        b.fill(0);
        b[0..2].copy_from_slice(&(c as u16).to_le_bytes());
        b[2] = kind;
        set_u32(b, 4, generation.max(1));
        n.set_parent(parent);
        tx.inode(n);
        Ok(n)
    }

    /// Frees `n` and its blocks. Its generation stays, so the next owner
    /// gets a new one.
    fn free_inode(&self, tx: &mut Tx, n: Inode) {
        self.free_from(tx, n, 0);
        let generation = n.generation();
        n.bytes().fill(0);
        set_u32(n.bytes(), 4, generation);
        tx.inode(n);
    }

    /// The caller's handle `h`.
    fn node(&self, c: u64, h: u64) -> R<Inode> {
        let ino = h & 0xffff_ffff;
        if ino == 0 || ino >= NINODES {
            return Err(Status::NotFound);
        }
        let n = Inode::of(ino);
        if n.is_free() || n.container() != c || n.generation() != h >> 32 {
            return Err(Status::NotFound);
        }
        Ok(n)
    }

    fn lookup(&self, dir: Inode, name: &[u8]) -> Option<Found> {
        for bi in 0..dir.size() / fs::BLOCK {
            let b = self.bmap(dir, bi);
            if b == 0 {
                continue;
            }
            read_block(b, B_LOOK);
            let blk = buf(B_LOOK);
            for idx in 0..ENTRIES as usize {
                let e = &blk[idx * fs::ENTRY..(idx + 1) * fs::ENTRY];
                let ino = u32_at(e, 0);
                if ino != 0 && fs::Entry(e).name() == name {
                    return Some(Found {
                        blockno: b,
                        idx,
                        ino,
                    });
                }
            }
        }
        None
    }

    fn is_empty_dir(&self, dir: Inode) -> bool {
        (0..dir.size() / fs::BLOCK).all(|bi| match self.bmap(dir, bi) {
            0 => true,
            b => {
                read_block(b, B_LOOK);
                (0..ENTRIES as usize).all(|i| u32_at(buf(B_LOOK), i * fs::ENTRY) == 0)
            }
        })
    }

    /// Reads link `n`'s target into `B_LINK`; its length.
    fn target(&self, n: Inode) -> usize {
        let len = (n.size() as usize).min(fs::MAX_LINK as usize);
        match n.ptr(0) {
            0 => buf(B_LINK)[..len].fill(0),
            b => read_block(b, B_LINK),
        }
        len
    }

    /// Walks `path` from `root`, in buffer `wb`, following symbolic links
    /// in every component but the last, and in the last if `follow`.
    fn walk(&self, root: Inode, path: &[u8], follow: bool, wb: u64) -> R<Walked> {
        plain(path)?;
        let w = buf(wb);
        let mut len = path.len().min(w.len());
        w[..len].copy_from_slice(&path[..len]);
        let (mut dir, mut at, mut links) = (root, 0, 0);
        loop {
            let Some((s, e)) = next_component(&w[..len], at) else {
                return Ok(Walked::Dir(dir));
            };
            at = e;
            let c = &buf(wb)[s..e];
            if c == b".." {
                // Only from a link's target; never above the root.
                if !dir.is_root() {
                    dir = Inode::of(dir.parent());
                }
                continue;
            }
            if c.len() > fs::MAX_NAME || c.contains(&0) {
                return Err(Status::Invalid);
            }
            let last = next_component(&w[..len], at).is_none();
            let found = self.lookup(dir, c);
            let n = found.map(|f| Inode::of(f.ino));
            match n {
                Some(n) if n.kind() == KIND_LINK && (follow || !last) => {
                    links += 1;
                    if links > fs::MAX_LINKS {
                        return Err(Status::TooManyLinks);
                    }
                    // The target, then the rest of the path.
                    let t = self.target(n);
                    let rest = len - at;
                    if t == 0 || t + 1 + rest > w.len() {
                        return Err(Status::Invalid);
                    }
                    w.copy_within(at..len, t + 1);
                    w[..t].copy_from_slice(&buf(B_LINK)[..t]);
                    w[t] = b'/';
                    len = t + 1 + rest;
                    at = 0;
                    if w[0] == b'/' {
                        dir = root;
                    }
                }
                _ if last => return Ok(Walked::Entry(dir, c)),
                Some(n) if n.kind() == KIND_DIR => dir = n,
                Some(_) => return Err(Status::NotDir),
                None => return Err(Status::NotFound),
            }
        }
    }

    /// The directory and last name `path` names, its last component not
    /// followed; `Invalid` for a directory reached with no last name.
    fn entry(&self, root: Inode, path: &[u8], wb: u64) -> R<(Inode, &'static [u8])> {
        match self.walk(root, path, false, wb)? {
            Walked::Entry(d, n) => Ok((d, n)),
            Walked::Dir(_) => Err(Status::Invalid),
        }
    }

    fn add_entry(&self, tx: &mut Tx, dir: Inode, name: &[u8], n: Inode) -> R<()> {
        let mut at = None;
        'find: for bi in 0..dir.size() / fs::BLOCK {
            let b = self.bmap(dir, bi);
            if b == 0 {
                continue;
            }
            read_block(b, B_LOOK);
            for idx in 0..ENTRIES as usize {
                if u32_at(buf(B_LOOK), idx * fs::ENTRY) == 0 {
                    at = Some((tx.get(b, false), idx));
                    break 'find;
                }
            }
        }
        let (blk, idx) = match at {
            Some(a) => a,
            None => {
                let bi = dir.size() / fs::BLOCK;
                let blk = self.bmap_write(tx, dir, bi)?;
                dir.set_size(dir.size() + fs::BLOCK);
                tx.inode(dir);
                (blk, 0)
            }
        };
        let e = &mut blk[idx * fs::ENTRY..(idx + 1) * fs::ENTRY];
        e.fill(0);
        set_u32(e, 0, n.ino);
        e[4] = n.kind();
        e[5] = name.len() as u8;
        e[6..6 + name.len()].copy_from_slice(name);
        Ok(())
    }

    fn entry_mut(tx: &mut Tx, f: Found) -> &'static mut [u8] {
        &mut tx.get(f.blockno, false)[f.idx * fs::ENTRY..(f.idx + 1) * fs::ENTRY]
    }

    // ---- operations ----

    /// Copies the path(s) out of the request's data.
    fn take_path(len: u64, io: Io) -> R<&'static [u8]> {
        let src = io.begin(false).ok_or(Status::Invalid)?;
        let ok = len <= fs::BLOCK && len as usize <= src.len();
        let p = &mut buf(B_PATH)[..len.min(fs::BLOCK) as usize];
        if ok {
            p.copy_from_slice(&src[..len as usize]);
        }
        io.end();
        ok.then_some(&*p).ok_or(Status::Invalid)
    }

    fn open(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let path = Fs::take_path(m[1], io)?;
        let flags = m[2];
        let create = flags & fs::CREATE != 0;
        let root = match create {
            true => self.ensure_root(c)?,
            false => self.root(c).ok_or(Status::NotFound)?,
        };
        // With EXCL a link is not followed: its name is taken.
        let follow = flags & fs::NOFOLLOW == 0 && !(create && flags & fs::EXCL != 0);
        let (dir, name) = match self.walk(root, path, follow, B_WALK)? {
            Walked::Dir(d) if flags & fs::EXCL != 0 && create => {
                let _ = d;
                return Err(Status::Exists);
            }
            Walked::Dir(d) => return Ok([d.handle(), d.size(), fs::KIND_DIR]),
            Walked::Entry(d, n) => (d, n),
        };
        let mut tx = Tx::new();
        let r = match self.lookup(dir, name) {
            Some(f) => {
                let n = Inode::of(f.ino);
                if n.kind() == KIND_LINK && !(create && flags & fs::EXCL != 0) {
                    // Only with NOFOLLOW is a link the last thing reached.
                    Err(Status::TooManyLinks)
                } else if create && flags & fs::EXCL != 0 {
                    Err(Status::Exists)
                } else if flags & fs::DIRECTORY != 0 && n.kind() != KIND_DIR {
                    Err(Status::NotDir)
                } else if flags & fs::TRUNC != 0 && n.kind() == KIND_FILE {
                    self.truncate_to(&mut tx, n, 0).map(|_| n)
                } else {
                    Ok(n)
                }
            }
            None if !create || flags & fs::DIRECTORY != 0 => Err(Status::NotFound),
            None => self
                .alloc_inode(&mut tx, c, KIND_FILE, dir.ino)
                .and_then(|n| {
                    self.add_entry(&mut tx, dir, name, n)?;
                    Ok(n)
                }),
        };
        let n = self.finish(tx, r)?;
        Ok([n.handle(), n.size(), n.kind() as u64])
    }

    fn mkdir(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let path = Fs::take_path(m[1], io)?;
        let root = self.ensure_root(c)?;
        let (dir, name) = match self.walk(root, path, false, B_WALK)? {
            Walked::Entry(d, n) => (d, n),
            Walked::Dir(_) => return Err(Status::Exists),
        };
        if let Some(f) = self.lookup(dir, name) {
            return match Inode::of(f.ino).kind() {
                KIND_DIR => Ok([0; 3]),
                _ => Err(Status::Exists),
            };
        }
        let mut tx = Tx::new();
        let r = self
            .alloc_inode(&mut tx, c, KIND_DIR, dir.ino)
            .and_then(|n| self.add_entry(&mut tx, dir, name, n));
        self.finish(tx, r).map(|_| [0; 3])
    }

    fn unlink(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let path = Fs::take_path(m[1], io)?;
        let root = self.root(c).ok_or(Status::NotFound)?;
        let (dir, name) = self.entry(root, path, B_WALK)?;
        let f = self.lookup(dir, name).ok_or(Status::NotFound)?;
        let n = Inode::of(f.ino);
        if n.kind() == KIND_DIR && !self.is_empty_dir(n) {
            return Err(Status::NotEmpty);
        }
        let mut tx = Tx::new();
        Fs::entry_mut(&mut tx, f).fill(0);
        self.free_inode(&mut tx, n);
        self.finish(tx, Ok([0; 3]))
    }

    fn rename(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let (l1, l2) = (m[1], m[2]);
        let both = Fs::take_path(l1.saturating_add(l2), io)?;
        let (from, to) = both.split_at(l1 as usize);
        let root = self.root(c).ok_or(Status::NotFound)?;
        let (sdir, sname) = self.entry(root, from, B_WALK)?;
        let (ddir, dname) = self.entry(root, to, B_WALK2)?;
        let src = self.lookup(sdir, sname).ok_or(Status::NotFound)?;
        let n = Inode::of(src.ino);
        let dst = self.lookup(ddir, dname);
        if dst.is_some_and(|d| d.ino == src.ino) {
            return Ok([0; 3]);
        }
        if n.kind() == KIND_DIR {
            // Not into itself: walk up from the new parent to the root.
            let mut up = ddir;
            loop {
                if up.ino == n.ino {
                    return Err(Status::Invalid);
                }
                if up.is_root() || up.parent() == 0 {
                    break;
                }
                up = Inode::of(up.parent());
            }
        }
        let mut tx = Tx::new();
        let r = match dst {
            Some(d) => {
                let old = Inode::of(d.ino);
                match (n.kind(), old.kind()) {
                    (KIND_DIR, KIND_FILE | KIND_LINK) => Err(Status::NotDir),
                    (KIND_FILE | KIND_LINK, KIND_DIR) => Err(Status::IsDir),
                    (KIND_DIR, _) if !self.is_empty_dir(old) => Err(Status::NotEmpty),
                    _ => {
                        self.free_inode(&mut tx, old);
                        let e = Fs::entry_mut(&mut tx, d);
                        set_u32(e, 0, n.ino);
                        e[4] = n.kind();
                        Ok(())
                    }
                }
            }
            None => self.add_entry(&mut tx, ddir, dname, n),
        };
        let r = r.map(|_| {
            Fs::entry_mut(&mut tx, src).fill(0);
            if n.parent() != ddir.ino {
                n.set_parent(ddir.ino);
                tx.inode(n);
            }
            [0; 3]
        });
        self.finish(tx, r)
    }

    fn symlink(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let (l1, l2) = (m[1], m[2]);
        let both = Fs::take_path(l1.saturating_add(l2), io)?;
        let (path, target) = both.split_at(l1 as usize);
        if target.is_empty() || target.len() as u64 > fs::MAX_LINK || target.contains(&0) {
            return Err(Status::Invalid);
        }
        let root = self.ensure_root(c)?;
        let (dir, name) = match self.walk(root, path, false, B_WALK)? {
            Walked::Entry(d, n) => (d, n),
            Walked::Dir(_) => return Err(Status::Exists),
        };
        if let Some(f) = self.lookup(dir, name) {
            let n = Inode::of(f.ino);
            let t = if n.kind() == KIND_LINK { self.target(n) } else { 0 };
            return match n.kind() == KIND_LINK && buf(B_LINK)[..t] == *target {
                true => Ok([0; 3]),
                false => Err(Status::Exists),
            };
        }
        let mut tx = Tx::new();
        let r = self.alloc_inode(&mut tx, c, KIND_LINK, dir.ino).and_then(|n| {
            let blk = self.bmap_write(&mut tx, n, 0)?;
            blk[..target.len()].copy_from_slice(target);
            n.set_size(target.len() as u64);
            tx.inode(n);
            self.add_entry(&mut tx, dir, name, n)
        });
        self.finish(tx, r).map(|_| [0; 3])
    }

    fn readlink(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let path = Fs::take_path(m[1], io)?;
        let root = self.root(c).ok_or(Status::NotFound)?;
        let (dir, name) = self.entry(root, path, B_WALK)?;
        let n = Inode::of(self.lookup(dir, name).ok_or(Status::NotFound)?.ino);
        if n.kind() != KIND_LINK {
            return Err(Status::Invalid);
        }
        let t = self.target(n);
        let out = io.begin(true).ok_or(Status::Invalid)?;
        let ok = out.len() >= t;
        if ok {
            out[..t].copy_from_slice(&buf(B_LINK)[..t]);
        }
        io.end();
        if ok { Ok([t as u64, 0, 0]) } else { Err(Status::Invalid) }
    }

    fn truncate_to(&self, tx: &mut Tx, n: Inode, size: u64) -> R<()> {
        if n.kind() != KIND_FILE {
            return Err(Status::IsDir);
        }
        if size > fs::MAX_FILE {
            return Err(Status::NoSpace);
        }
        if size < n.size() {
            // Bytes past the end read as zero, so the end's block is
            // cleared beyond it.
            let tail = size % fs::BLOCK;
            if tail != 0 {
                let b = self.bmap(n, size / fs::BLOCK);
                if b != 0 {
                    tx.get(b, false)[tail as usize..].fill(0);
                }
            }
            self.free_from(tx, n, size.div_ceil(fs::BLOCK));
        }
        n.set_size(size);
        tx.inode(n);
        Ok(())
    }

    fn truncate(&mut self, c: u64, m: [u64; 4]) -> R<[u64; 3]> {
        let n = self.node(c, m[1])?;
        let mut tx = Tx::new();
        let r = self.truncate_to(&mut tx, n, m[2]);
        self.finish(tx, r).map(|_| [0; 3])
    }

    /// A file's range `[off, off + len)` of at most a block, as up to two
    /// (file block, offset in it, bytes) pieces.
    fn pieces(off: u64, len: u64) -> [(u64, usize, usize); 2] {
        let first = (fs::BLOCK - off % fs::BLOCK).min(len);
        [
            (off / fs::BLOCK, (off % fs::BLOCK) as usize, first as usize),
            (off / fs::BLOCK + 1, 0, (len - first) as usize),
        ]
    }

    fn read(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let n = self.node(c, m[1])?;
        let (off, len) = (m[2], m[3]);
        if n.kind() != KIND_FILE {
            return Err(Status::IsDir);
        }
        if len > fs::BLOCK {
            return Err(Status::Invalid);
        }
        let len = len.min(n.size().saturating_sub(off));
        let out = io.begin(true).ok_or(Status::Invalid)?;
        if out.len() < len as usize {
            io.end();
            return Err(Status::Invalid);
        }
        let mut at = 0;
        for (bi, o, k) in Fs::pieces(off, len) {
            if k == 0 {
                continue;
            }
            let dst = &mut out[at..at + k];
            match self.bmap(n, bi) {
                0 => dst.fill(0),
                b => {
                    read_block(b, B_DATA);
                    dst.copy_from_slice(&buf(B_DATA)[o..o + k]);
                }
            }
            at += k;
        }
        io.end();
        Ok([len, 0, 0])
    }

    fn write(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let n = self.node(c, m[1])?;
        let (off, len) = (m[2], m[3]);
        if n.kind() != KIND_FILE {
            return Err(Status::IsDir);
        }
        if len == 0 || len > fs::BLOCK {
            return Err(Status::Invalid);
        }
        if off.saturating_add(len) > fs::MAX_FILE {
            return Err(Status::NoSpace);
        }
        // The data first: data it cannot reach is refused before anything
        // changes. (A copy: a ring client may change its pages meanwhile.)
        let src = io.begin(false).ok_or(Status::Invalid)?;
        let ok = src.len() >= len as usize;
        if ok {
            buf(B_DATA)[..len as usize].copy_from_slice(&src[..len as usize]);
        }
        io.end();
        if !ok {
            return Err(Status::Invalid);
        }
        let mut tx = Tx::new();
        let mut at = 0;
        let mut r = Ok(());
        for (bi, o, k) in Fs::pieces(off, len) {
            if k == 0 {
                continue;
            }
            match self.bmap_write(&mut tx, n, bi) {
                Ok(blk) => blk[o..o + k].copy_from_slice(&buf(B_DATA)[at..at + k]),
                Err(e) => {
                    r = Err(e);
                    break;
                }
            }
            at += k;
        }
        if r.is_ok() && off + len > n.size() {
            n.set_size(off + len);
            tx.inode(n);
        }
        self.finish(tx, r).map(|_| [0; 3])
    }

    fn readdir(&mut self, c: u64, m: [u64; 4], io: Io) -> R<[u64; 3]> {
        let n = self.node(c, m[1])?;
        if n.kind() != KIND_DIR {
            return Err(Status::NotDir);
        }
        let out = io.begin(true).ok_or(Status::Invalid)?;
        let room = out.len().min(fs::BLOCK as usize) / fs::ENTRY;
        let total = n.size() / fs::BLOCK * ENTRIES;
        let (mut i, mut count) = (m[2], 0usize);
        let mut loaded = u64::MAX;
        while i < total && count < room {
            let bi = i / ENTRIES;
            if bi != loaded {
                match self.bmap(n, bi) {
                    0 => buf(B_LOOK).fill(0),
                    b => read_block(b, B_LOOK),
                }
                loaded = bi;
            }
            let idx = (i % ENTRIES) as usize;
            let e = &buf(B_LOOK)[idx * fs::ENTRY..(idx + 1) * fs::ENTRY];
            if u32_at(e, 0) != 0 {
                out[count * fs::ENTRY..(count + 1) * fs::ENTRY].copy_from_slice(e);
                count += 1;
            }
            i += 1;
        }
        io.end();
        Ok([count as u64, i, 0])
    }

    fn statfs(&self) -> [u64; 3] {
        let blocks = (DATA..self.blocks).filter(|&b| !self.is_used(b)).count();
        let inodes = (1..NINODES).filter(|&i| Inode::of(i).is_free()).count();
        [blocks as u64, inodes as u64, 0]
    }

    /// The mount check: every block in use belongs to exactly one inode,
    /// every inode in use to exactly one directory entry (roots to none),
    /// and the bitmap says so.
    fn check(&self) {
        let seen = buf(B_SCRATCH);
        seen.fill(0);
        let mut refs = [0u8; NINODES as usize];
        let (mut used, mut files, mut dirs, mut links) = (0u64, 0u64, 0u64, 0u64);
        let mut bad: Option<(&str, u64)> = None;
        let mut mark = |b: u64, bad: &mut Option<(&str, u64)>| {
            if !(DATA..self.blocks).contains(&b) {
                bad.get_or_insert(("a block outside the data area", b));
            } else if seen[b as usize / 8] & 1 << (b % 8) != 0 {
                bad.get_or_insert(("a block used twice", b));
            } else {
                seen[b as usize / 8] |= 1 << (b % 8);
                used += 1;
            }
        };
        for ino in 1..NINODES {
            let n = Inode::of(ino);
            if n.is_free() {
                continue;
            }
            match n.kind() {
                KIND_FILE => files += 1,
                KIND_LINK => {
                    links += 1;
                    if n.size() == 0 || n.size() > fs::MAX_LINK || n.ptr(0) == 0 {
                        bad.get_or_insert(("a link without a target", ino));
                    }
                }
                _ => dirs += 1,
            }
            for i in 0..DIRECT {
                if n.ptr(i) != 0 {
                    mark(n.ptr(i), &mut bad);
                }
            }
            let ind = n.ptr(DIRECT);
            if ind != 0 {
                mark(ind, &mut bad);
                read_block(ind, B_IND);
                for i in 0..PER_IND as usize {
                    let b = u32_at(buf(B_IND), 4 * i);
                    if b != 0 {
                        mark(b, &mut bad);
                    }
                }
            }
            if n.kind() == KIND_DIR {
                for bi in 0..n.size() / fs::BLOCK {
                    let b = self.bmap(n, bi);
                    if b == 0 {
                        continue;
                    }
                    read_block(b, B_LOOK);
                    for idx in 0..ENTRIES as usize {
                        let e = &buf(B_LOOK)[idx * fs::ENTRY..];
                        let child = u32_at(e, 0);
                        if child == 0 {
                            continue;
                        }
                        let k = Inode::of(child.min(NINODES - 1));
                        if child >= NINODES
                            || k.is_free()
                            || k.container() != n.container()
                            || k.kind() != e[4]
                            || k.parent() != ino
                        {
                            bad.get_or_insert(("an entry naming the wrong inode", ino));
                        } else {
                            refs[child as usize] = refs[child as usize].saturating_add(1);
                        }
                    }
                }
            }
        }
        for ino in 1..NINODES {
            let n = Inode::of(ino);
            let want = match n.is_free() || n.is_root() {
                true => 0,
                false => 1,
            };
            if refs[ino as usize] != want {
                bad.get_or_insert(("an inode not in exactly one directory", ino));
            }
        }
        for b in DATA..self.blocks {
            if (seen[b as usize / 8] & 1 << (b % 8) != 0) != self.is_used(b) {
                bad.get_or_insert(("the bitmap disagrees about a block", b));
            }
        }
        match bad {
            None if links == 0 => say!(
                "check: {used} blocks used by {files} files and {dirs} directories; all accounted for"
            ),
            None => say!(
                "check: {used} blocks used by {files} files, {dirs} directories and {links} symbolic links; all accounted for"
            ),
            Some((what, n)) => say!("check FAILED: {what} ({n})"),
        }
    }

    /// One request of container `c`, from a call or a ring.
    fn op(&mut self, c: u64, m: [u64; 4], io: Io) -> [u64; 4] {
        reply(match m[0] {
            fs::OPEN => self.open(c, m, io),
            fs::READ => self.read(c, m, io),
            fs::WRITE => self.write(c, m, io),
            fs::STAT => self.node(c, m[1]).map(|n| [n.size(), n.kind() as u64, 0]),
            fs::MKDIR => self.mkdir(c, m, io),
            fs::UNLINK => self.unlink(c, m, io),
            fs::RENAME => self.rename(c, m, io),
            fs::READDIR => self.readdir(c, m, io),
            fs::TRUNCATE => self.truncate(c, m),
            fs::STATFS => Ok(self.statfs()),
            fs::SYMLINK => self.symlink(c, m, io),
            fs::READLINK => self.readlink(c, m, io),
            _ => Err(Status::Invalid),
        })
    }

    /// A call: the reply, and a capability to grant with it.
    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> ([u64; 4], Option<u64>) {
        let c = badge & 0xffff;
        if c == 0 {
            return (reply(Err(Status::Denied)), None);
        }
        match m[0] {
            fs::RING_ATTACH => (reply(self.ring_attach(c, m[1], lent)), None),
            fs::RING_START => match self.ring_start(c) {
                Ok(g) => (reply(Ok([0; 3])), Some(g)),
                Err(e) => (reply(Err(e)), None),
            },
            fs::RING_DOORBELL => match self.ring_doorbell(c) {
                Ok(g) => (reply(Ok([0; 3])), Some(g)),
                Err(e) => (reply(Err(e)), None),
            },
            _ => {
                let io = if lent { Io::Lent } else { Io::None };
                (self.op(c, m, io), None)
            }
        }
    }

    // ---- rings ----

    fn ring_of(&self, c: u64) -> Option<usize> {
        self.rings
            .iter()
            .position(|r| r.is_some_and(|r| r.container == c))
    }

    /// Takes page `page` of container `c`'s ring, lent in this call.
    fn ring_attach(&mut self, c: u64, page: u64, lent: bool) -> R<[u64; 3]> {
        if !lent || page >= ring::PAGES {
            return Err(Status::Invalid);
        }
        if page == 0 {
            if let Some(r) = self.ring_of(c) {
                self.detach(r);
            }
            let r = self
                .rings
                .iter()
                .position(|r| r.is_none())
                .ok_or(Status::InUse)?;
            self.rings[r] = Some(Ring {
                container: c,
                attached: 0,
                started: false,
            });
        }
        let r = self.ring_of(c).ok_or(Status::Invalid)?;
        let mut g = self.rings[r].unwrap();
        if g.started || page != g.attached {
            return Err(Status::Invalid);
        }
        let slot = RING_PAGES + r as u64 * ring::PAGES + page;
        // A copy of what was lent: the lent capability goes after the call.
        if syscall(Syscall::CapMint, LENT, [slot, ALL, 0, 0]).status != 0 {
            return Err(Status::Invalid);
        }
        let va = RING_VA + r as u64 * RING_STRIDE + page * 4096;
        if syscall(Syscall::FrameMap, slot, [va, 1, 0, 0]).status != 0 {
            syscall(Syscall::CapDelete, slot, [0; 4]);
            return Err(Status::Invalid);
        }
        g.attached += 1;
        self.rings[r] = Some(g);
        Ok([0; 3])
    }

    /// Drops ring `r`: its pages, and the client's copies of its
    /// completion notification.
    fn detach(&mut self, r: usize) {
        let Some(g) = self.rings[r].take() else {
            return;
        };
        for p in 0..g.attached {
            // Deleting the capability unmaps the page.
            syscall(
                Syscall::CapDelete,
                RING_PAGES + r as u64 * ring::PAGES + p,
                [0; 4],
            );
        }
        syscall(Syscall::CapRevoke, RING_NTFN + r as u64, [0; 4]);
    }

    /// Starts container `c`'s ring; the completion notification to grant.
    fn ring_start(&mut self, c: u64) -> R<u64> {
        let r = self.ring_of(c).ok_or(Status::NotFound)?;
        let mut g = self.rings[r].unwrap();
        if g.started || g.attached != ring::PAGES {
            return Err(Status::Invalid);
        }
        let page = RING_VA + r as u64 * RING_STRIDE;
        for off in (0..ring::SQ).step_by(4) {
            hdr(page, off).store(0, Ordering::Relaxed);
        }
        fence(Ordering::SeqCst);
        g.started = true;
        self.rings[r] = Some(g);
        Fs::mint(RING_NTFN + r as u64, READ, 0)
    }

    /// The doorbell, badged with ring `r`'s bit, to grant.
    fn ring_doorbell(&mut self, c: u64) -> R<u64> {
        let r = self.ring_of(c).ok_or(Status::NotFound)?;
        if !self.rings[r].unwrap().started {
            return Err(Status::Invalid);
        }
        Fs::mint(DOORBELL, WRITE, 1 << r)
    }

    fn mint(src: u64, rights: u64, badge: u64) -> R<u64> {
        syscall(Syscall::CapDelete, MINT, [0; 4]);
        match syscall(Syscall::CapMint, src, [MINT, rights, badge, 0]).status {
            0 => Ok(MINT),
            _ => Err(Status::Invalid),
        }
    }

    /// Takes every submission there is room to complete. Returns whether
    /// there were any.
    fn poll_rings(&mut self) -> bool {
        let mut any = false;
        for r in 0..MAX_RINGS {
            let Some(g) = self.rings[r].filter(|g| g.started) else {
                continue;
            };
            let page = RING_VA + r as u64 * RING_STRIDE;
            let mut posted = false;
            loop {
                let head = hdr(page, ring::SQ_HEAD).load(Ordering::Relaxed);
                let tail = hdr(page, ring::SQ_TAIL).load(Ordering::Acquire);
                let cq_tail = hdr(page, ring::CQ_TAIL).load(Ordering::Relaxed);
                let cq_head = hdr(page, ring::CQ_HEAD).load(Ordering::Acquire);
                if head == tail {
                    break;
                }
                if tail.wrapping_sub(head) > ring::ENTRIES
                    || cq_tail.wrapping_sub(cq_head) > ring::ENTRIES
                {
                    say!("ring {r}: indices out of range; dropping it");
                    self.detach(r);
                    break;
                }
                if cq_tail.wrapping_sub(cq_head) == ring::ENTRIES {
                    break; // no room for the completion: the client reaps first
                }
                let sqe = page as usize + ring::SQ + (head % ring::ENTRIES) as usize * ring::SQE;
                // SAFETY: inside the ring page, mapped while attached.
                let w = |i: usize| unsafe { ((sqe + 8 * i) as *const u64).read_volatile() };
                let (op, tag, m, off) = (w(0), w(1), [w(0), w(2), w(3), w(4)], w(5));
                let reply = if op >= fs::RING_ATTACH || off >= ring::DATA {
                    reply(Err(Status::Invalid))
                } else {
                    let io = Io::Shared {
                        va: page + 4096 + off,
                        len: (ring::DATA - off).min(fs::BLOCK) as usize,
                    };
                    self.op(g.container, m, io)
                };
                let cqe = page as usize + ring::CQ + (cq_tail % ring::ENTRIES) as usize * ring::CQE;
                for (i, v) in [tag, reply[0], reply[1], reply[2], reply[3]]
                    .iter()
                    .enumerate()
                {
                    // SAFETY: inside the ring page, mapped while attached.
                    unsafe { ((cqe + 8 * i) as *mut u64).write_volatile(*v) };
                }
                // Committed already: the completion is the acknowledgement.
                hdr(page, ring::CQ_TAIL).store(cq_tail.wrapping_add(1), Ordering::Release);
                hdr(page, ring::SQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
                self.checkpoint();
                self.ring_ops += 1;
                posted = true;
                any = true;
                // Coalesced: wake a sleeping client once it has as many
                // completions as it asked for.
                let pending = cq_tail.wrapping_add(1).wrapping_sub(cq_head);
                self.wake_client(r, page, pending);
            }
            // Out of work (or room): wake a sleeping client whatever it
            // asked for, so it can refill the queue.
            if posted && self.rings[r].is_some() {
                fence(Ordering::SeqCst);
                self.wake_client(r, page, ring::ENTRIES);
            }
        }
        any
    }

    /// Signals ring `r`'s client if it sleeps waiting for at most
    /// `pending` completions; clears its request, so it is signalled once.
    fn wake_client(&mut self, r: usize, page: u64, pending: u32) {
        let w = hdr(page, ring::CLIENT_WAITING);
        let want = w.load(Ordering::Acquire);
        if want != 0
            && want <= pending
            && w.compare_exchange(want, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            syscall(Syscall::Signal, RING_NTFN + r as u64, [0; 4]);
            self.signals += 1;
        }
    }

    /// Whether some ring has a submission it has room to complete.
    fn ring_work(&self) -> bool {
        (0..MAX_RINGS).any(|r| {
            let page = RING_VA + r as u64 * RING_STRIDE;
            self.rings[r].is_some_and(|g| g.started)
                && hdr(page, ring::SQ_HEAD).load(Ordering::Relaxed)
                    != hdr(page, ring::SQ_TAIL).load(Ordering::Acquire)
                && hdr(page, ring::CQ_TAIL)
                    .load(Ordering::Relaxed)
                    .wrapping_sub(hdr(page, ring::CQ_HEAD).load(Ordering::Acquire))
                    < ring::ENTRIES
        })
    }

    /// Tells every ring's client whether this server sleeps.
    fn need_wakeup(&self, on: bool) {
        for r in 0..MAX_RINGS {
            if self.rings[r].is_some_and(|g| g.started) {
                let page = RING_VA + r as u64 * RING_STRIDE;
                hdr(page, ring::FLAGS).store(on as u32 * ring::NEED_WAKEUP, Ordering::Relaxed);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut f = Fs::mount();
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    loop {
        // Under load, take ring submissions without sleeping.
        if f.poll_rings() {
            continue;
        }
        // About to sleep: ask for the doorbell, then look once more, so a
        // submission made meanwhile is either seen here or rings it.
        f.need_wakeup(true);
        fence(Ordering::SeqCst);
        if f.ring_work() {
            f.need_wakeup(false);
            continue;
        }
        let r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
        f.need_wakeup(false);
        if r.status == Error::Notified.code() {
            f.wakeups += 1;
            if f.wakeups % 64 == 0 {
                say!(
                    "rings: {} requests, {} doorbells, {} completion signals",
                    f.ring_ops,
                    f.wakeups,
                    f.signals
                );
            }
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let (reply, grant) = f.serve(r.badge, r.msg, lent);
        if lent {
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        // Committed: acknowledge, then write the blocks home.
        let x = CapTransfer {
            grant: grant.map(|g| g as u16),
            accept: None,
        };
        syscall_x(Syscall::Reply, 0, reply, x);
        if grant.is_some() {
            syscall(Syscall::CapDelete, MINT, [0; 4]);
        }
        f.checkpoint();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    crash("panic")
}
