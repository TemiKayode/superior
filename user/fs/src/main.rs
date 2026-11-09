//! The filesystem server (spec section 4): files on a block device, with
//! a write-ahead journal so that no acknowledged write is ever lost.
//!
//! **No global namespace.** Each client sees only its own container of
//! files, picked by the badge the Component Manager put on its capability
//! (its component number, the same across its restarts).
//!
//! **Crash-only.** Starting is recovery: mount replays a committed journal
//! transaction left by an instance (or a machine) that stopped before
//! finishing it. Every change goes through one path:
//!
//! 1. the changed blocks (file data, inode, bitmap) are written to the
//!    journal area, then a flush;
//! 2. the journal header, naming their home blocks and holding a checksum
//!    over them, is written, then a flush. The transaction is committed:
//!    only now is the client's write acknowledged;
//! 3. after the reply, the blocks are written home, a flush, and the
//!    header is cleared.
//!
//! A crash before step 2 completes leaves no valid header (the checksum
//! fails or it is the cleared one), and the write was never acknowledged.
//! A crash after it replays at the next mount. Every block call the
//! driver fails with `PeerRestarted` (it was restarted) is retried, and
//! every operation clients send is idempotent, so they retry too.
//!
//! Disk layout, in 4 KiB blocks: 0 superblock, 1 journal header, 2-5
//! journal blocks, 6-7 inodes (128 of 64 bytes), 8 the block bitmap, then
//! file data. An unformatted disk is formatted at mount.
//!
//! Slots: 0 the `block` service, 1 the `fs` endpoint (receive), 2 untyped
//! memory, 3 where a client's frame arrives.

#![no_std]
#![no_main]

use superior_objects::abi::{CapTransfer, Error, ObjectType, Syscall};
use superior_objects::interfaces::{Status, block, fs};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const BLOCK_EP: u64 = 0;
const SERVICE: u64 = 1;
const UNTYPED: u64 = 2;
const LENT: u64 = 3;
/// Buffers, one frame each, mapped at `BUF_VA + 4096 * (slot - BUF0)`.
const BUF0: u64 = 8;
const B_HDR: u64 = BUF0;
const B_INODES: u64 = BUF0 + 1; // two
const B_BITMAP: u64 = BUF0 + 3;
const B_DATA: u64 = BUF0 + 4;
const B_SCRATCH: u64 = BUF0 + 5;
const BUFS: u64 = 6;
const BUF_VA: u64 = USER_BASE + 0x4000_0000;
const LENT_VA: u64 = USER_BASE + 0x5000_0000;

// Disk layout, in blocks.
const SUPER: u64 = 0;
const JHDR: u64 = 1;
const JDATA: u64 = 2;
const JMAX: usize = 4;
const INODES: u64 = 6;
const INODE_BLOCKS: u64 = 2;
const BITMAP: u64 = 8;
const DATA: u64 = 9;
const INODE_SIZE: u64 = 64;
const NINODES: u64 = INODE_BLOCKS * fs::BLOCK / INODE_SIZE;
const FILE_BLOCKS: u64 = fs::MAX_FILE / fs::BLOCK;

const SUPER_MAGIC: u64 = u64::from_le_bytes(*b"SUPFS001");
const JOURNAL_MAGIC: u64 = u64::from_le_bytes(*b"SUPJRNL1");

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
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
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

/// An inode, in its buffer.
struct Inode {
    slot: u64,
    off: usize,
}

impl Inode {
    fn of(ino: u64) -> Inode {
        Inode {
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
    fn size(&self) -> u64 {
        u32::from_le_bytes(self.bytes()[4..8].try_into().unwrap()) as u64
    }
    fn set_size(&self, n: u64) {
        self.bytes()[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    }
    fn name(&self) -> [u64; 3] {
        let b = self.bytes();
        [word(b, 8), word(b, 16), word(b, 24)]
    }
    fn block(&self, i: u64) -> u64 {
        let o = 32 + 4 * i as usize;
        u32::from_le_bytes(self.bytes()[o..o + 4].try_into().unwrap()) as u64
    }
    fn set_block(&self, i: u64, b: u64) {
        let o = 32 + 4 * i as usize;
        self.bytes()[o..o + 4].copy_from_slice(&(b as u32).to_le_bytes());
    }
    fn home(&self) -> u64 {
        INODES + (self.slot - B_INODES)
    }
}

struct Fs {
    blocks: u64,
    seq: u64,
    /// Committed but not yet written home: (home block, buffer).
    pending: [(u64, u64); JMAX],
    npending: usize,
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
        let blocks = (info.msg[1] * block::SECTOR / fs::BLOCK).min(DATA + 8 * fs::BLOCK);
        if info.status != 0 || blocks <= DATA {
            crash("no usable block device");
        }
        let mut f = Fs {
            blocks,
            seq: 0,
            pending: [(0, 0); JMAX],
            npending: 0,
        };
        read_block(SUPER, B_SCRATCH);
        if word(buf(B_SCRATCH), 0) != SUPER_MAGIC {
            f.format();
        }
        let replayed = f.replay();
        for i in 0..INODE_BLOCKS {
            read_block(INODES + i, B_INODES + i);
        }
        read_block(BITMAP, B_BITMAP);
        let files = (0..NINODES)
            .filter(|&i| Inode::of(i).container() != 0)
            .count();
        say!(
            "mounted in {} ticks: {} blocks, {files} files{}",
            ticks() - start,
            f.blocks,
            match replayed {
                0 => "; journal clean",
                _ => "; replayed a committed transaction",
            }
        );
        f
    }

    fn format(&mut self) {
        buf(B_SCRATCH).fill(0);
        for b in [JHDR, INODES, INODES + 1, BITMAP] {
            write_block(b, B_SCRATCH);
        }
        flush();
        set_word(buf(B_SCRATCH), 0, SUPER_MAGIC);
        set_word(buf(B_SCRATCH), 8, self.blocks);
        write_block(SUPER, B_SCRATCH);
        flush();
        say!("formatted {} blocks", self.blocks);
    }

    /// The checksum of the header (its first 56 bytes) and the journal
    /// blocks, which are in buffer `data` one at a time via `each`.
    fn header_sum(hdr: &[u8], mut each: impl FnMut(usize) -> u64) -> u64 {
        let count = word(hdr, 16) as usize;
        let mut h = fnv(0xcbf2_9ce4_8422_2325, &hdr[..56]);
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
            fnv(0xcbf2_9ce4_8422_2325, buf(B_SCRATCH))
        });
        if sum != word(hdr, 56) {
            return 0; // torn: never committed, never acknowledged
        }
        for j in 0..count {
            let home = word(buf(B_HDR), 24 + 8 * j);
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

    /// Steps 1 and 2: makes `blocks` (home block, buffer) durable in the
    /// journal. Step 3 is [`Fs::checkpoint`].
    fn commit(&mut self, blocks: &[(u64, u64)]) {
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
            set_word(hdr, 24 + 8 * j, home);
        }
        let sum = Fs::header_sum(hdr, |j| fnv(0xcbf2_9ce4_8422_2325, buf(blocks[j].1)));
        set_word(hdr, 56, sum);
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

    fn find(&self, container: u64, name: [u64; 3]) -> Option<u64> {
        (0..NINODES).find(|&i| {
            let n = Inode::of(i);
            n.container() == container && n.name() == name
        })
    }

    fn open(&mut self, container: u64, name: [u64; 3], create: bool) -> [u64; 4] {
        if name == [0; 3] || container == 0 || container > u16::MAX as u64 {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        if let Some(i) = self.find(container, name) {
            return [Status::Ok as u64, i, Inode::of(i).size(), 0];
        }
        if !create {
            return [Status::NotFound as u64, 0, 0, 0];
        }
        let Some(i) = (0..NINODES).find(|&i| Inode::of(i).container() == 0) else {
            return [Status::InUse as u64, 0, 0, 0];
        };
        let n = Inode::of(i);
        let b = n.bytes();
        b.fill(0);
        b[0..2].copy_from_slice(&(container as u16).to_le_bytes());
        for (k, w) in name.iter().enumerate() {
            set_word(b, 8 + 8 * k, *w);
        }
        self.commit(&[(n.home(), n.slot)]);
        [Status::Ok as u64, i, 0, 0]
    }

    /// The caller's inode `ino`, and the block a range lies in, if the
    /// range is valid.
    fn range(&self, container: u64, ino: u64, off: u64, len: u64) -> Option<(Inode, u64)> {
        if ino >= NINODES || len == 0 || len > fs::BLOCK {
            return None;
        }
        let n = Inode::of(ino);
        if n.container() != container || n.container() == 0 {
            return None;
        }
        let bi = off / fs::BLOCK;
        if bi >= FILE_BLOCKS || off % fs::BLOCK + len > fs::BLOCK {
            return None;
        }
        Some((n, bi))
    }

    fn read(&mut self, container: u64, m: [u64; 4], lent: bool) -> [u64; 4] {
        let (ino, off, len) = (m[1], m[2], m[3]);
        let Some((n, bi)) = self.range(container, ino, off, len).filter(|_| lent) else {
            return [Status::Invalid as u64, 0, 0, 0];
        };
        let size = n.size();
        let len = len.min(size.saturating_sub(off));
        let data = buf(B_DATA);
        match n.block(bi) {
            0 => data.fill(0),
            b => read_block(b, B_DATA),
        }
        if syscall(Syscall::FrameMap, LENT, [LENT_VA, 1, 0, 0]).status != 0 {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let at = (off % fs::BLOCK) as usize;
        // SAFETY: the client's frame is mapped at LENT_VA, writable.
        unsafe {
            core::ptr::copy_nonoverlapping(data[at..].as_ptr(), LENT_VA as *mut u8, len as usize)
        };
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
        [Status::Ok as u64, len, 0, 0]
    }

    fn write(&mut self, container: u64, m: [u64; 4], lent: bool) -> [u64; 4] {
        let (ino, off, len) = (m[1], m[2], m[3]);
        let Some((n, bi)) = self.range(container, ino, off, len).filter(|_| lent) else {
            return [Status::Invalid as u64, 0, 0, 0];
        };
        // The data first: a client's frame it cannot map is refused
        // before anything changes.
        if syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
            return [Status::Invalid as u64, 0, 0, 0];
        }
        let mut blocks = [(0u64, 0u64); 3];
        let mut nb = 0;
        let mut b = n.block(bi);
        if b == 0 {
            let bitmap = buf(B_BITMAP);
            let Some(free) =
                (DATA..self.blocks).find(|&x| bitmap[x as usize / 8] & 1 << (x % 8) == 0)
            else {
                syscall(Syscall::FrameUnmap, LENT, [0; 4]);
                return [Status::InUse as u64, 0, 0, 0];
            };
            bitmap[free as usize / 8] |= 1 << (free % 8);
            n.set_block(bi, free);
            buf(B_DATA).fill(0);
            blocks[nb] = (BITMAP, B_BITMAP);
            nb += 1;
            b = free;
        } else {
            read_block(b, B_DATA);
        }
        let at = (off % fs::BLOCK) as usize;
        // SAFETY: the client's frame is mapped at LENT_VA, readable.
        let src = unsafe { core::slice::from_raw_parts(LENT_VA as *const u8, len as usize) };
        buf(B_DATA)[at..at + len as usize].copy_from_slice(src);
        syscall(Syscall::FrameUnmap, LENT, [0; 4]);
        n.set_size(n.size().max(off + len));
        blocks[nb] = (b, B_DATA);
        blocks[nb + 1] = (n.home(), n.slot);
        nb += 2;
        self.commit(&blocks[..nb]);
        [Status::Ok as u64, 0, 0, 0]
    }

    fn serve(&mut self, badge: u64, m: [u64; 4], lent: bool) -> [u64; 4] {
        let container = badge & 0xffff;
        match m[0] {
            fs::CREATE => self.open(container, [m[1], m[2], m[3]], true),
            fs::OPEN => self.open(container, [m[1], m[2], m[3]], false),
            fs::READ => self.read(container, m, lent),
            fs::WRITE => self.write(container, m, lent),
            fs::STAT => match self.range(container, m[1], 0, 1) {
                Some((n, _)) => [Status::Ok as u64, n.size(), 0, 0],
                None => [Status::NotFound as u64, 0, 0, 0],
            },
            _ => [Status::Invalid as u64, 0, 0, 0],
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
        let r = syscall_x(Syscall::Recv, SERVICE, [0; 4], accept);
        if r.status != 0 {
            continue;
        }
        let lent = r.cap == Some(LENT as u16);
        let reply = f.serve(r.badge, r.msg, lent);
        if lent {
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        // Committed: acknowledge, then write the blocks home.
        syscall(Syscall::Reply, 0, reply);
        f.checkpoint();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    crash("panic")
}
