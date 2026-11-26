//! The filesystem server underneath `/home`: calls to it, each lending
//! this server's one buffer frame for the path or the data, and Linux's
//! errors for its statuses.
//!
//! The server's tree is this component's own container (spec section 4),
//! so nothing else changes it: [`crate::fs`] keeps what it has looked up
//! there as inodes of its own, and they stay true.

use core::sync::atomic::{AtomicU64, Ordering};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::interfaces::{Status, fs};
use superior_sys::{USER_BASE, syscall_x};

/// The `fs` service (`uses fs` in the manifest).
pub const FS: u64 = 6;
/// The buffer frame lent with every call, and where it is mapped here.
pub const BUF: u64 = 1008;
pub const BUF_VA: u64 = USER_BASE + 0x1_6000_0000;
/// Bytes one call moves at most.
pub const CHUNK: usize = fs::BLOCK as usize;

const EIO: u64 = 5;

/// Calls made so far: what the buffer last held is known by the count
/// after the call that filled it.
static CALLS: AtomicU64 = AtomicU64::new(0);

pub fn calls() -> u64 {
    CALLS.load(Ordering::Relaxed)
}

pub fn buf() -> &'static mut [u8] {
    // SAFETY: the buffer frame is mapped at BUF_VA for this server's life,
    // and only this (single-threaded) server touches it.
    unsafe { core::slice::from_raw_parts_mut(BUF_VA as *mut u8, CHUNK) }
}

/// Linux's error for a status.
fn errno(status: u64) -> u64 {
    const E: [(Status, u64); 8] = [
        (Status::NotFound, 2),
        (Status::Exists, 17),
        (Status::NotDir, 20),
        (Status::IsDir, 21),
        (Status::Invalid, 22),
        (Status::NoSpace, 28),
        (Status::NotEmpty, 39),
        (Status::TooManyLinks, 40),
    ];
    E.iter().find(|e| e.0 as u64 == status).map_or(EIO, |e| e.1)
}

/// A call lending the buffer, made again while the server (or the disk
/// driver under it) is being restarted. The reply's words after the
/// status, or Linux's error.
pub fn call(m: [u64; 4]) -> Result<[u64; 3], u64> {
    let x = CapTransfer { grant: Some(BUF as u16), accept: None };
    for _ in 0..50 {
        let r = syscall_x(Syscall::Call, FS, m, x);
        CALLS.fetch_add(1, Ordering::Relaxed);
        if r.status == 0 {
            return if r.msg[0] == Status::Ok as u64 { Ok([r.msg[1], r.msg[2], r.msg[3]]) } else { Err(errno(r.msg[0])) };
        }
        if r.status != Error::PeerRestarted.code() {
            break;
        }
        superior_sys::sleep(1);
    }
    Err(EIO)
}

/// A call naming `paths` (back to back in the buffer): `[op, their
/// lengths..., extra]`.
fn with_paths(op: u64, paths: &[&[u8]], extra: u64) -> Result<[u64; 3], u64> {
    let b = buf();
    let mut m = [op, 0, 0, 0];
    let mut at = 0;
    for (k, p) in paths.iter().enumerate() {
        b.get_mut(at..at + p.len()).ok_or(36u64)?.copy_from_slice(p);
        at += p.len();
        m[1 + k] = p.len() as u64;
    }
    m[1 + paths.len()] = extra;
    call(m)
}

/// What `OPEN` found: its handle, size and kind (`fs::KIND_*`).
pub fn open(path: &[u8], flags: u64) -> Result<(u64, u64, u64), u64> {
    with_paths(fs::OPEN, &[path], flags).map(|r| (r[0], r[1], r[2]))
}

pub fn mkdir(path: &[u8]) -> Result<(), u64> {
    with_paths(fs::MKDIR, &[path], 0).map(drop)
}

/// Removes a file, link or empty directory. A retry that finds it gone
/// had removed it.
pub fn unlink(path: &[u8]) -> Result<(), u64> {
    with_paths(fs::UNLINK, &[path], 0).map(drop)
}

pub fn rename(from: &[u8], to: &[u8]) -> Result<(), u64> {
    with_paths(fs::RENAME, &[from, to], 0).map(drop)
}

pub fn symlink(path: &[u8], target: &[u8]) -> Result<(), u64> {
    with_paths(fs::SYMLINK, &[path, target], 0).map(drop)
}

/// A link's target, into `out`; its length.
pub fn readlink(path: &[u8], out: &mut [u8]) -> Result<usize, u64> {
    let n = with_paths(fs::READLINK, &[path], 0)?[0] as usize;
    let n = n.min(out.len()).min(CHUNK);
    out[..n].copy_from_slice(&buf()[..n]);
    Ok(n)
}

/// Reads at `off` into `out`, a buffer at a time; the bytes read.
pub fn read(handle: u64, off: u64, out: &mut [u8]) -> Result<usize, u64> {
    let mut done = 0;
    while done < out.len() {
        let want = (out.len() - done).min(CHUNK);
        let n = (call([fs::READ, handle, off + done as u64, want as u64])?[0] as usize).min(want);
        out[done..done + n].copy_from_slice(&buf()[..n]);
        done += n;
        if n < want {
            break;
        }
    }
    Ok(done)
}

/// Writes `data` at `off`, a buffer at a time, each piece durable before
/// the next.
pub fn write(handle: u64, off: u64, data: &[u8]) -> Result<(), u64> {
    for (k, piece) in data.chunks(CHUNK).enumerate() {
        buf()[..piece.len()].copy_from_slice(piece);
        call([fs::WRITE, handle, off + (k * CHUNK) as u64, piece.len() as u64])?;
    }
    Ok(())
}

/// The disk's free blocks and inodes.
pub fn statfs() -> Result<(u64, u64), u64> {
    call([fs::STATFS, 0, 0, 0]).map(|r| (r[0], r[1]))
}

pub fn truncate(handle: u64, len: u64) -> Result<(), u64> {
    call([fs::TRUNCATE, handle, len, 0]).map(drop)
}

/// Directory `handle`'s entries from position `cookie`, into the buffer,
/// each one's position after them (see [`position`]): how many, and the
/// position after them.
pub fn readdir(handle: u64, cookie: u64) -> Result<(usize, u64), u64> {
    call([fs::READDIR, handle, cookie, fs::READDIR_POSITIONS]).map(|r| (r[0] as usize, r[1]))
}

/// The position of entry `k` the last [`readdir`] put in the buffer.
pub fn position(k: usize) -> u64 {
    let at = fs::POSITIONS_AT + 4 * k;
    u32::from_le_bytes(buf()[at..at + 4].try_into().unwrap()) as u64
}
