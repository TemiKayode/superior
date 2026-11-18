//! The Linux personality (Phase 3): runs unmodified Linux programs.
//!
//! Each Linux process is an address space of its own with one thread the
//! kernel marks foreign (`ThreadRegisters`, `REGS_FOREIGN`): its `syscall`
//! (x86-64) or `svc` (AArch64) does not reach the kernel's system calls but
//! comes here as a [`FaultKind::ForeignSyscall`] fault, badged with the
//! process's slot. This server reads the arguments, does what Linux would,
//! and resumes the thread after the instruction with the result, every
//! other register as it was. A call that must wait (`wait4` for a child
//! that is still running, reading an empty pipe, writing a full one) is set
//! aside (`ReplySave`) and answered (`ReplyTo`) when it can be.
//!
//! Loading is Linux's: the program (a position-independent executable)
//! and the interpreter it names (`PT_INTERP`, musl's dynamic linker, also
//! its C library) are mapped, a stack built with the arguments, environment
//! and auxiliary vector, and the thread started at the interpreter. Pages
//! that are never written (code and read-only data) are the bundle file's
//! own pages, shared by every process; the rest are each process's own and
//! also mapped here, in a mirror window per process, so system calls read
//! and write a process's memory in place.
//!
//! Processes: `fork` (or `clone` without `CLONE_VM`) copies the address
//! space's own pages and the descriptors, and the kernel copies the
//! thread's registers (`REGS_FORK_FROM`); `execve` replaces the address
//! space and thread under the same pid; `exit` leaves a zombie for
//! `wait4`. Files ([`fs`]): an in-memory tree with `/bin` (BusyBox and a
//! link per applet), the interpreter, `/tmp`, `/dev/null`; pipes; the
//! console. They last as long as this server.
//!
//! Slots: 0 the untyped memory everything is made from, cut into eight
//! blocks (slots 8 to 15): seven for processes, revoked when one exits or
//! execs, and one for this server's state and the files' pages (from
//! [`STATE_SLOTS`]). 1 the manager's control endpoint, 2 the endpoint
//! faults arrive on. The interpreter's pages from 16, the program's from
//! 200 (`file` in the manifest). Process `i` owns the slots from
//! `PROC_SLOTS + i * PROC_SPAN`: its address space, thread, badged fault
//! endpoint, then its pages.
//!
//! Signals ([`signal`]): actions, masks, `kill`, handlers run on the
//! process's stack and returned from. The terminal ([`tty`]): the serial
//! console with Linux's line discipline, settings and foreground process
//! group, so `^C` interrupts a job; `poll` and `nanosleep` wait on it and
//! on the timer.
//!
//! Not yet: threads (`clone` with `CLONE_VM`), stopping and continuing
//! jobs (`^Z`), the filesystem server underneath, fixed-address (non-PIE)
//! executables.

#![no_std]
#![no_main]

mod fs;
mod signal;
mod tty;

use fs::{FileKind, Fs, Kind, Open, Pipe, MAX_FILES, MAX_PIPES, PIPE_BUF, ROOT};
use signal::{Action, Next, SA_RESTART, SIGCHLD, SIGPIPE, SIGSEGV, SYSCALL_LEN, TRAMPOLINE, TRAMPOLINE_CODE};
use superior_objects::abi::{
    Error, FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType, REGS_COUNT, REGS_FOREIGN, REGS_FORK_FROM, REGS_GET,
    REGS_SET, REGS_SET_TLS, REGS_SYSCALL, REGS_SYSCALL_MORE, REGS_TLS, Syscall, TICK_HZ,
};
use superior_objects::elf::{Elf, Machine};
use superior_sys::{USER_BASE, print_line, syscall};

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

const UNTYPED: u64 = 0;
const CONTROL: u64 = 1;
const EP: u64 = 2;
/// The notification this server's thread is bound to (so `Recv` also
/// returns when it is signalled), and two badged copies of it: the UART's
/// interrupt (bit 0) and the timer for sleepers (bit 1).
const NTFN: u64 = 5;
const NTFN_UART: u64 = 6;
const NTFN_TIMER: u64 = 7;
const BLOCKS: u64 = 8;
const BLOCK_BITS: u64 = 20;
const INTERP_FILE: u64 = 16;
const PROGRAM_FILE: u64 = 200;
const STATE_SLOTS: u64 = 512;
const STATE_PAGES: u64 = 24;
const POOL_SLOTS: u64 = STATE_SLOTS + STATE_PAGES;
/// The signal restorer's page ([`signal::TRAMPOLINE`]).
const TRAMPOLINE_SLOT: u64 = 1000;
const PROC_SLOTS: u64 = 1024;
const PROC_SPAN: u64 = 1024;
const MAX_PROCS: usize = 7;
const FS_BLOCK: u64 = BLOCKS + MAX_PROCS as u64;
const OP_SHUTDOWN: u64 = 2;
const ALL: u64 = 0x1f;
const WRITE_RIGHT: u64 = 1 << 1;
const PAGE: u64 = 4096;
const MAX_FDS: usize = 32;

/// Where things are mapped here.
const INTERP_VA: u64 = USER_BASE + 0x1_0000_0000;
const PROGRAM_VA: u64 = USER_BASE + 0x1_1000_0000;
const STATE_VA: u64 = USER_BASE + 0x1_2000_0000;
const POOL_VA: u64 = USER_BASE + 0x1_3000_0000;
const TRAMPOLINE_VA: u64 = USER_BASE + 0x1_4000_0000;

/// A process's address space: everything inside [`CHILD`, `CHILD_END`).
const CHILD: u64 = USER_BASE + 0x40_0000_0000;
const SPAN: u64 = 0x400_0000;
const CHILD_END: u64 = CHILD + SPAN;
const PROGRAM_BASE: u64 = CHILD + 0x40_0000;
const INTERP_BASE: u64 = CHILD + 0x100_0000;
const MMAP_BASE: u64 = CHILD + 0x180_0000;
const STACK_TOP: u64 = CHILD_END - 0x10_0000;
const STACK_PAGES: u64 = 32;
const BRK_MAX: u64 = 0x80_0000;
/// Process `i`'s page at `va` is here at `va - CHILD + MIRROR + i * SPAN`.
const MIRROR: u64 = USER_BASE + 0x48_0000_0000;
const CHILD_PAGES: usize = (SPAN / PAGE) as usize;

const MACHINE: Machine = if cfg!(target_arch = "x86_64") { Machine::X86_64 } else { Machine::Aarch64 };
const PLATFORM: &str = if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" };

// Linux error numbers (and those in `fs`).
use fs::{EBADF, EEXIST, EINVAL, EISDIR, ENFILE, ENOENT, ENOTDIR, EPIPE};
const EPERM: u64 = 1;
const ESRCH: u64 = 3;
const EINTR: u64 = 4;
const ENOEXEC: u64 = 8;
const ECHILD: u64 = 10;
const EAGAIN: u64 = 11;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const ENODEV: u64 = 19;
const EMFILE: u64 = 24;
const ENOTTY: u64 = 25;
const ESPIPE: u64 = 29;
const ERANGE: u64 = 34;
const ENOSYS: u64 = 38;

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_ACCMODE: u32 = 3;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_DIRECTORY: u32 = if cfg!(target_arch = "x86_64") { 0o200000 } else { 0o40000 };
const O_NOFOLLOW: u32 = if cfg!(target_arch = "x86_64") { 0o400000 } else { 0o100000 };
const O_CLOEXEC: u32 = 0o2000000;
const CLONE_VM: u64 = 0x100;
const WNOHANG: u64 = 1;

const fn err(e: u64) -> u64 {
    e.wrapping_neg()
}

/// The system calls answered, Linux's names; [`decode`] maps each ISA's
/// numbers and turns the old x86-64 path calls into their `*at` forms.
// Some exist only in x86-64's table (`fork`, `dup2`, `arch_prctl`, `pause`).
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sys {
    Read,
    Write,
    Writev,
    Openat,
    Close,
    Fstat,
    Fstatat,
    Lseek,
    Mmap,
    Munmap,
    Brk,
    Ioctl,
    Faccessat,
    Pipe2,
    Dup,
    Dup2,
    Dup3,
    Fcntl,
    Fork,
    Clone,
    Execve,
    Exit,
    Wait4,
    Uname,
    Ftruncate,
    Getdents64,
    Getcwd,
    Chdir,
    Fchdir,
    Renameat,
    Mkdirat,
    Unlinkat,
    Symlinkat,
    Readlinkat,
    Umask,
    Getpid,
    Getppid,
    Getpgid,
    Setpgid,
    Zero,
    ArchPrctl,
    ClockGettime,
    Gettimeofday,
    Getrandom,
    Prlimit,
    Getrlimit,
    Times,
    /// Answered with `ENOSYS` without a word: callers expect it.
    Quiet,
    /// `EINVAL`: callers copy by reading and writing instead.
    Sendfile,
    Sigaction,
    Sigprocmask,
    Sigpending,
    Sigsuspend,
    Sigreturn,
    Pause,
    Kill,
    /// `tkill` and `tgkill`, the thread id first: a process's one thread
    /// is the process.
    Tkill,
    /// `clock_nanosleep`'s arguments; `nanosleep` becomes one.
    Nanosleep,
    Getsid,
    Setsid,
    /// `poll`'s arguments, the timeout in milliseconds.
    Poll,
    /// `ppoll`'s, the timeout a `timespec`.
    Ppoll,
    Unsupported(u64),
}

/// The call and its arguments, normalized.
fn decode(nr: u64, a: [u64; 6]) -> (Sys, [u64; 6]) {
    // x86-64's old path calls become their `*at` forms.
    #[cfg(target_arch = "x86_64")]
    let cwd = AT_FDCWD as i64 as u64;
    #[cfg(target_arch = "x86_64")]
    let s = match nr {
        0 => Sys::Read,
        1 => Sys::Write,
        2 => return (Sys::Openat, [cwd, a[0], a[1], a[2], 0, 0]),
        3 => Sys::Close,
        4 => return (Sys::Fstatat, [cwd, a[0], a[1], 0, 0, 0]),
        5 => Sys::Fstat,
        6 => return (Sys::Fstatat, [cwd, a[0], a[1], AT_SYMLINK_NOFOLLOW, 0, 0]),
        8 => Sys::Lseek,
        9 => Sys::Mmap,
        10 | 28 | 131 | 273 | 90..=94 | 268 | 260 | 280 | 105 | 106 | 24 => Sys::Zero,
        7 => Sys::Poll,
        271 => Sys::Ppoll,
        13 => Sys::Sigaction,
        14 => Sys::Sigprocmask,
        15 => Sys::Sigreturn,
        34 => Sys::Pause,
        35 => return (Sys::Nanosleep, [0, 0, a[0], a[1], 0, 0]),
        62 => Sys::Kill,
        127 => Sys::Sigpending,
        130 => Sys::Sigsuspend,
        200 => Sys::Tkill,
        230 => Sys::Nanosleep,
        234 => return (Sys::Tkill, [a[1], a[2], 0, 0, 0, 0]),
        11 => Sys::Munmap,
        12 => Sys::Brk,
        16 => Sys::Ioctl,
        20 => Sys::Writev,
        21 => return (Sys::Faccessat, [cwd, a[0], a[1], 0, 0, 0]),
        22 => return (Sys::Pipe2, [a[0], 0, 0, 0, 0, 0]),
        25 => return (Sys::Mmap, [0; 6]),
        32 => Sys::Dup,
        33 => Sys::Dup2,
        39 | 186 | 218 => Sys::Getpid,
        40 => Sys::Sendfile,
        56 => Sys::Clone,
        57 | 58 => Sys::Fork,
        59 => Sys::Execve,
        60 | 231 => Sys::Exit,
        61 => Sys::Wait4,
        63 => Sys::Uname,
        72 => Sys::Fcntl,
        77 => Sys::Ftruncate,
        79 => Sys::Getcwd,
        80 => Sys::Chdir,
        81 => Sys::Fchdir,
        82 => return (Sys::Renameat, [cwd, a[0], cwd, a[1], 0, 0]),
        83 => return (Sys::Mkdirat, [cwd, a[0], a[1], 0, 0, 0]),
        84 => return (Sys::Unlinkat, [cwd, a[0], AT_REMOVEDIR, 0, 0, 0]),
        87 => return (Sys::Unlinkat, [cwd, a[0], 0, 0, 0, 0]),
        88 => return (Sys::Symlinkat, [a[0], cwd, a[1], 0, 0, 0]),
        89 => return (Sys::Readlinkat, [cwd, a[0], a[1], a[2], 0, 0]),
        95 => Sys::Umask,
        96 => Sys::Gettimeofday,
        97 => Sys::Getrlimit,
        100 => Sys::Times,
        102 | 104 | 107 | 108 => Sys::Zero,
        109 => Sys::Setpgid,
        110 => Sys::Getppid,
        111 => return (Sys::Getpgid, [0; 6]),
        112 => Sys::Setsid,
        121 => Sys::Getpgid,
        124 => Sys::Getsid,
        158 => Sys::ArchPrctl,
        217 => Sys::Getdents64,
        228 => Sys::ClockGettime,
        257 => Sys::Openat,
        258 => Sys::Mkdirat,
        262 => Sys::Fstatat,
        263 => Sys::Unlinkat,
        264 | 316 => Sys::Renameat,
        266 => Sys::Symlinkat,
        267 => Sys::Readlinkat,
        269 | 439 => Sys::Faccessat,
        292 => Sys::Dup3,
        293 => Sys::Pipe2,
        302 => Sys::Prlimit,
        318 => Sys::Getrandom,
        332 | 334 | 157 => Sys::Quiet,
        n => Sys::Unsupported(n),
    };
    #[cfg(target_arch = "aarch64")]
    let s = match nr {
        17 => Sys::Getcwd,
        23 => Sys::Dup,
        24 => Sys::Dup3,
        25 => Sys::Fcntl,
        29 => Sys::Ioctl,
        34 => Sys::Mkdirat,
        35 => Sys::Unlinkat,
        36 => Sys::Symlinkat,
        38 | 276 => Sys::Renameat,
        46 => Sys::Ftruncate,
        48 | 439 => Sys::Faccessat,
        49 => Sys::Chdir,
        50 => Sys::Fchdir,
        56 => Sys::Openat,
        57 => Sys::Close,
        59 => Sys::Pipe2,
        61 => Sys::Getdents64,
        62 => Sys::Lseek,
        63 => Sys::Read,
        64 => Sys::Write,
        66 => Sys::Writev,
        71 => Sys::Sendfile,
        78 => Sys::Readlinkat,
        79 => Sys::Fstatat,
        80 => Sys::Fstat,
        93 | 94 => Sys::Exit,
        96 | 172 | 178 => Sys::Getpid,
        113 => Sys::ClockGettime,
        153 => Sys::Times,
        154 => Sys::Setpgid,
        155 => Sys::Getpgid,
        156 => Sys::Getsid,
        157 => Sys::Setsid,
        160 => Sys::Uname,
        163 => Sys::Getrlimit,
        166 => Sys::Umask,
        169 => Sys::Gettimeofday,
        173 => Sys::Getppid,
        174..=177 | 99 | 124 | 132 | 144 | 146 | 52..=55 | 88 | 226 | 233 => Sys::Zero,
        101 => return (Sys::Nanosleep, [0, 0, a[0], a[1], 0, 0]),
        115 => Sys::Nanosleep,
        73 => Sys::Ppoll,
        129 => Sys::Kill,
        130 => Sys::Tkill,
        131 => return (Sys::Tkill, [a[1], a[2], 0, 0, 0, 0]),
        133 => Sys::Sigsuspend,
        134 => Sys::Sigaction,
        135 => Sys::Sigprocmask,
        136 => Sys::Sigpending,
        139 => Sys::Sigreturn,
        214 => Sys::Brk,
        215 => Sys::Munmap,
        216 => return (Sys::Mmap, [0; 6]),
        220 => Sys::Clone,
        221 => Sys::Execve,
        222 => Sys::Mmap,
        260 => Sys::Wait4,
        261 => Sys::Prlimit,
        278 => Sys::Getrandom,
        291 | 293 | 167 => Sys::Quiet,
        n => Sys::Unsupported(n),
    };
    (s, a)
}

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> Result<[u64; 4], u64> {
    let r = syscall(nr, a0, m);
    if r.status == 0 { Ok(r.msg) } else { Err(r.status) }
}

/// Maps the pages of the `file` in consecutive slots from `slot` at `va`
/// (read-only), as many as there are; the file's bytes, padded to a page.
fn map_file(slot: u64, va: u64, max: u64) -> &'static [u8] {
    let mut n = 0;
    while n < max && sys(Syscall::FrameMap, slot + n, [va + n * PAGE, 0, 0, 0]).is_ok() {
        n += 1;
    }
    // SAFETY: the n pages from va were just mapped and stay mapped.
    unsafe { core::slice::from_raw_parts(va as *const u8, (n * PAGE) as usize) }
}

/// A call that waits, to be tried again when something changes.
#[repr(u8)]
#[derive(Clone, Copy)]
enum Blocked {
    None = 0,
    Read { fd: u64, buf: u64, len: u64 },
    Write { fd: u64, buf: u64, len: u64 },
    Writev { fd: u64, iov: u64, cnt: u64 },
    Wait { pid: i64, status: u64, options: u64 },
    /// `nanosleep`, until this tick.
    Sleep { until: u64 },
    /// `sigsuspend` or `pause`: until a signal is taken.
    Suspend,
    /// `poll`: until a descriptor is ready, or the tick `until`.
    Poll { fds: u64, n: u64, until: u64 },
}

/// What a system call comes to.
enum Out {
    Ret(u64),
    /// Resume elsewhere (`rt_sigreturn`): at `pc`, with `value` in the
    /// result register.
    Resume { pc: u64, value: u64 },
    Block(Blocked),
    /// The thread that asked is gone (it exited or became another
    /// program): no answer.
    Gone,
}

struct Proc {
    used: bool,
    zombie: bool,
    pid: u32,
    ppid: u32,
    /// Its process group and session.
    pgid: u32,
    sid: u32,
    /// Signals sent and not yet taken; held back; the mask to restore
    /// after a `sigsuspend` (`suspended`); what each signal does.
    pending: u64,
    mask: u64,
    saved_mask: u64,
    suspended: bool,
    actions: [Action; 64],
    /// Its wait status once a zombie.
    status: u32,
    /// Slots used of its span.
    cursor: u64,
    cwd: u16,
    /// Open-file description + 1, per descriptor.
    fds: [u8; MAX_FDS],
    cloexec: u32,
    brk_start: u64,
    brk: u64,
    mmap_next: u64,
    blocked: Blocked,
    /// Where its waiting call was set aside, and where it resumes.
    place: u64,
    pc: u64,
    /// Its own pages (mapped in the mirror too).
    present: [u64; CHILD_PAGES / 64],
}

/// A run of pages every process maps from a bundle file: [start, end) at
/// `ptr` here, the file's page slots from `slot`, with `flags`.
#[derive(Clone, Copy)]
struct Shared {
    start: u64,
    end: u64,
    ptr: u64,
    slot: u64,
    flags: u64,
}

struct State {
    fs: Fs,
    files: [Open; MAX_FILES],
    pipes: [Pipe; MAX_PIPES],
    procs: [Proc; MAX_PROCS],
    next_pid: u32,
    shared: [Shared; 12],
    nshared: usize,
    /// Console output not yet printed: the line being written.
    line: [u8; 160],
    len: usize,
    /// The wait status of the run's first process, once it is gone.
    top_status: Option<u32>,
    program: &'static [u8],
    interp: &'static [u8],
    /// The terminal (the serial console).
    tty: tty::Tty,
}

const _: () = assert!(core::mem::size_of::<State>() as u64 <= STATE_PAGES * PAGE);

/// Strings gathered from a process (arguments, environment).
struct Strs {
    buf: [u8; 2048],
    len: usize,
    off: [(u16, u16); 32],
    n: usize,
}

impl Strs {
    const fn new() -> Strs {
        Strs { buf: [0; 2048], len: 0, off: [(0, 0); 32], n: 0 }
    }
    fn push(&mut self, s: &[u8]) -> bool {
        if self.n == self.off.len() || self.len + s.len() > self.buf.len() {
            return false;
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.off[self.n] = (self.len as u16, s.len() as u16);
        self.len += s.len();
        self.n += 1;
        true
    }
    fn get(&self, k: usize) -> &[u8] {
        let (o, l) = self.off[k];
        &self.buf[o as usize..(o + l) as usize]
    }
}

fn slot_base(i: usize) -> u64 {
    PROC_SLOTS + i as u64 * PROC_SPAN
}
fn space_slot(i: usize) -> u64 {
    slot_base(i)
}
fn thread_slot(i: usize) -> u64 {
    slot_base(i) + 1
}
fn fault_slot(i: usize) -> u64 {
    slot_base(i) + 2
}
fn block_slot(i: usize) -> u64 {
    BLOCKS + i as u64
}

impl State {
    // ---- memory ------------------------------------------------------

    fn is_present(&self, i: usize, va: u64) -> bool {
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].present[k / 64] & (1 << (k % 64)) != 0
    }

    /// Where byte `va` of process `i` is here, if it is mapped, and
    /// whether it is the process's own (writable) page.
    fn locate(&self, i: usize, va: u64) -> Option<(*mut u8, bool)> {
        if !(CHILD..CHILD_END).contains(&va) {
            return None;
        }
        if self.is_present(i, va) {
            return Some(((va - CHILD + MIRROR + i as u64 * SPAN) as *mut u8, true));
        }
        self.shared[..self.nshared]
            .iter()
            .find(|s| (s.start..s.end).contains(&va))
            .map(|s| ((s.ptr + va - s.start) as *mut u8, false))
    }

    fn copy_in(&self, i: usize, va: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let at = va + done as u64;
            let Some((p, _)) = self.locate(i, at) else { return false };
            let n = (PAGE - at % PAGE).min((buf.len() - done) as u64) as usize;
            // SAFETY: p..p+n lies in one mapped page.
            unsafe { core::ptr::copy_nonoverlapping(p, buf[done..].as_mut_ptr(), n) };
            done += n;
        }
        true
    }

    fn copy_out(&self, i: usize, va: u64, data: &[u8]) -> bool {
        let mut done = 0;
        while done < data.len() {
            let at = va + done as u64;
            let Some((p, true)) = self.locate(i, at) else { return false };
            let n = (PAGE - at % PAGE).min((data.len() - done) as u64) as usize;
            // SAFETY: p..p+n lies in one of the process's own pages, mapped
            // writable here; the process waits on this server meanwhile.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), p, n) };
            done += n;
        }
        true
    }

    fn put(&self, i: usize, va: u64, data: &[u8]) -> Result<u64, u64> {
        if self.copy_out(i, va, data) { Ok(0) } else { Err(EFAULT) }
    }

    fn word(&self, i: usize, va: u64) -> Option<u64> {
        let mut b = [0; 8];
        self.copy_in(i, va, &mut b).then(|| u64::from_le_bytes(b))
    }

    /// A NUL-terminated string at `va`, into `buf`; its length.
    fn cstr(&self, i: usize, va: u64, buf: &mut [u8]) -> Result<usize, u64> {
        for k in 0..buf.len() {
            let mut b = [0];
            if !self.copy_in(i, va + k as u64, &mut b) {
                return Err(EFAULT);
            }
            if b[0] == 0 {
                return Ok(k);
            }
            buf[k] = b[0];
        }
        Err(fs::ENAMETOOLONG)
    }

    /// A fresh zeroed page of process `i`'s own at page-aligned `va`
    /// (writable), mapped in the mirror too, unless it has one there.
    fn map_private(&mut self, i: usize, va: u64) -> Result<(), u64> {
        if !(CHILD..CHILD_END).contains(&va) {
            return Err(EFAULT);
        }
        if self.is_present(i, va) {
            return Ok(());
        }
        let p = &mut self.procs[i];
        if p.cursor + 2 > PROC_SPAN {
            return Err(ENOMEM);
        }
        let slot = slot_base(i) + p.cursor;
        sys(Syscall::Retype, block_slot(i), [ObjectType::Frame as u64, 0, slot, 0]).map_err(|_| ENOMEM)?;
        sys(Syscall::CapMint, slot, [slot + 1, ALL, 0, 0]).map_err(|_| ENOMEM)?;
        p.cursor += 2;
        sys(Syscall::FrameMap, slot + 1, [va - CHILD + MIRROR + i as u64 * SPAN, 1, 0, 0]).map_err(|_| ENOMEM)?;
        sys(Syscall::FrameMapInto, slot, [va, MAP_WRITE, space_slot(i), 0]).map_err(|_| ENOMEM)?;
        let k = ((va - CHILD) / PAGE) as usize;
        p.present[k / 64] |= 1 << (k % 64);
        Ok(())
    }

    /// Maps the bundle file's page in `file_slot` at `va` in process `i`
    /// (read-only, or executable).
    fn map_shared(&mut self, i: usize, va: u64, file_slot: u64, flags: u64) -> Result<(), u64> {
        let p = &mut self.procs[i];
        if p.cursor + 1 > PROC_SPAN {
            return Err(ENOMEM);
        }
        let slot = slot_base(i) + p.cursor;
        sys(Syscall::CapMint, file_slot, [slot, ALL, 0, 0]).map_err(|_| ENOMEM)?;
        p.cursor += 1;
        sys(Syscall::FrameMapInto, slot, [va, flags, space_slot(i), 0]).map_err(|_| ENOMEM)?;
        Ok(())
    }

    /// Maps every shared run in process `i`, but where it has its own page.
    fn map_all_shared(&mut self, i: usize) -> Result<(), u64> {
        for k in 0..self.nshared {
            let s = self.shared[k];
            for va in (s.start..s.end).step_by(PAGE as usize) {
                if !self.is_present(i, va) {
                    self.map_shared(i, va, s.slot + (va - s.start) / PAGE, s.flags)?;
                }
            }
        }
        Ok(())
    }

    /// Loads a position-independent image (the file whose pages are in
    /// slots from `file_slot`) at `base` in process `i`: (entry, program
    /// headers' address, their count, the image's end). Pages that are
    /// written get a copy; the rest are the file's own, shared.
    fn load(&mut self, i: usize, image: &'static [u8], file_slot: u64, base: u64) -> Result<(u64, u64, u64, u64), &'static str> {
        let elf = Elf::parse(image).map_err(|_| "not an ELF executable")?;
        if elf.machine != MACHINE {
            return Err("not for this machine");
        }
        if !elf.pie {
            return Err("a fixed-address executable (not position-independent)");
        }
        let mut end = 0;
        for seg in elf.segments() {
            let seg = seg.map_err(|_| "a bad segment")?;
            if seg.mem_size == 0 {
                continue;
            }
            let (lo, hi) = (seg.vaddr & !(PAGE - 1), (seg.vaddr + seg.mem_size).next_multiple_of(PAGE));
            end = end.max(hi);
            if seg.writable {
                for page in (lo..hi).step_by(PAGE as usize) {
                    self.map_private(i, base + page).map_err(|_| "out of memory")?;
                }
                if !self.copy_out(i, base + seg.vaddr, elf.file_bytes(&seg)) {
                    return Err("out of memory");
                }
                continue;
            }
            if seg.vaddr % PAGE != seg.file_offset % PAGE || seg.executable && seg.writable {
                return Err("an unsupported segment layout");
            }
            let first_page = (seg.file_offset - (seg.vaddr - lo)) / PAGE;
            let run = Shared {
                start: base + lo,
                end: base + hi,
                ptr: image.as_ptr() as u64 + first_page * PAGE,
                slot: file_slot + first_page,
                flags: if seg.executable { MAP_EXEC } else { 0 },
            };
            if (first_page + (hi - lo) / PAGE) * PAGE > image.len() as u64 {
                return Err("a segment past the file's end");
            }
            if !self.shared[..self.nshared].iter().any(|s| s.start == run.start) {
                if self.nshared == self.shared.len() {
                    return Err("too many segments");
                }
                self.shared[self.nshared] = run;
                self.nshared += 1;
            }
        }
        let (phoff, phnum) = elf.program_headers();
        Ok((base + elf.entry, base + phoff, phnum as u64, base + end))
    }

    // ---- processes ---------------------------------------------------

    fn new_proc(&mut self, ppid: u32) -> Option<usize> {
        let i = self.procs.iter().position(|p| !p.used)?;
        let pid = self.next_pid;
        self.next_pid += 1;
        let p = &mut self.procs[i];
        p.used = true;
        p.zombie = false;
        p.pid = pid;
        p.ppid = ppid;
        p.status = 0;
        p.cursor = 0;
        p.cwd = ROOT;
        p.fds = [0; MAX_FDS];
        p.cloexec = 0;
        p.blocked = Blocked::None;
        p.present = [0; CHILD_PAGES / 64];
        (p.pgid, p.sid) = (pid, pid);
        (p.pending, p.mask, p.saved_mask, p.suspended) = (0, 0, 0, false);
        p.actions = [Action { handler: 0, flags: 0, restorer: 0, mask: 0 }; 64];
        Some(i)
    }

    /// Makes process `i`'s address space, thread and fault endpoint.
    fn make_space(&mut self, i: usize) -> Result<(), &'static str> {
        let b = slot_base(i);
        let made = |r: Result<[u64; 4], u64>, what| r.map(drop).map_err(|_| what);
        made(sys(Syscall::Retype, block_slot(i), [ObjectType::AddressSpace as u64, 17, b, 0]), "no address space")?;
        made(sys(Syscall::Retype, block_slot(i), [ObjectType::Thread as u64, 0, b + 1, 0]), "no thread")?;
        made(sys(Syscall::CapMint, EP, [b + 2, WRITE_RIGHT, i as u64 + 1, 0]), "no endpoint")?;
        self.procs[i].cursor = 3;
        Ok(())
    }

    /// Starts process `i`'s thread: at `entry` with stack `top`, or with
    /// another process's registers (`fork`).
    fn start(&mut self, i: usize, entry: u64, top: u64, fork_from: Option<usize>) -> Result<(), &'static str> {
        let t = thread_slot(i);
        let made = |r: Result<[u64; 4], u64>, what| r.map(drop).map_err(|_| what);
        made(sys(Syscall::ThreadSetVSpace, t, [space_slot(i), 0, 0, 0]), "set address space")?;
        made(sys(Syscall::ThreadConfigure, t, [entry, top, 0, 5]), "configure the thread")?;
        made(sys(Syscall::ThreadSetFaultHandler, t, [fault_slot(i), 0, 0, 0]), "set fault handler")?;
        made(sys(Syscall::ThreadRegisters, t, [REGS_FOREIGN, 1, 0, 0]), "make the thread foreign")?;
        if let Some(f) = fork_from {
            made(sys(Syscall::ThreadRegisters, t, [REGS_FORK_FROM, thread_slot(f), 0, 0]), "copy registers")?;
        }
        made(sys(Syscall::ThreadResume, t, [0; 4]), "start the thread")
    }

    /// Destroys process `i`'s address space, thread and pages.
    fn unmake_space(&mut self, i: usize) {
        for s in slot_base(i)..slot_base(i) + self.procs[i].cursor {
            let _ = syscall(Syscall::CapDelete, s, [0; 4]);
        }
        let _ = syscall(Syscall::CapRevoke, block_slot(i), [0; 4]);
        let p = &mut self.procs[i];
        p.cursor = 0;
        p.present = [0; CHILD_PAGES / 64];
    }

    /// Runs the program in process `i` (its address space made afresh)
    /// with `argv` and `envp`.
    fn exec(&mut self, i: usize, argv: &Strs, envp: &Strs, execfn: &[u8]) -> Result<(), &'static str> {
        self.make_space(i)?;
        let program = self.program;
        let interp = self.interp;
        let (entry, phdr, phnum, end) = self.load(i, program, PROGRAM_FILE, PROGRAM_BASE)?;
        let (interp_entry, ..) = self.load(i, interp, INTERP_FILE, INTERP_BASE)?;
        for p in 1..=STACK_PAGES {
            self.map_private(i, STACK_TOP - p * PAGE).map_err(|_| "out of memory")?;
        }
        self.map_all_shared(i).map_err(|_| "out of memory")?;
        let p = &mut self.procs[i];
        p.brk_start = end + PAGE;
        p.brk = p.brk_start;
        p.mmap_next = MMAP_BASE;

        // The stack Linux gives a new program: strings at the top, then
        // the auxiliary vector, environment and argument pointers, argc.
        let mut top = STACK_TOP;
        let mut push_str = |st: &State, s: &[u8]| -> Result<u64, &'static str> {
            top -= s.len() as u64 + 1;
            if st.copy_out(i, top, s) && st.copy_out(i, top + s.len() as u64, &[0]) { Ok(top) } else { Err("stack") }
        };
        let mut argp = [0u64; 32];
        let mut envp_at = [0u64; 32];
        for k in 0..argv.n {
            argp[k] = push_str(self, argv.get(k))?;
        }
        for k in 0..envp.n {
            envp_at[k] = push_str(self, envp.get(k))?;
        }
        let execfn = push_str(self, execfn)?;
        let platform = push_str(self, PLATFORM.as_bytes())?;
        let random = push_str(self, &superior_sys::random().unwrap_or([0x5a; 32])[..16])?;
        let aux: [(u64, u64); 17] = [
            (3, phdr),
            (4, 56),
            (5, phnum),
            (6, PAGE),
            (7, INTERP_BASE),
            (8, 0),
            (9, entry),
            (11, 0),
            (12, 0),
            (13, 0),
            (14, 0),
            (15, platform),
            (16, 0),
            (17, TICK_HZ),
            (23, 0),
            (25, random),
            (31, execfn),
        ];
        let words = 1 + argv.n + 1 + envp.n + 1 + 2 * (aux.len() + 1);
        let mut sp = (top - 8 * words as u64) & !15;
        // x86-64 threads start as if called (8 below a 16-byte boundary);
        // the interpreter realigns its stack itself.
        let thread_top = if cfg!(target_arch = "x86_64") {
            sp -= 8;
            sp + 8
        } else {
            sp
        };
        let mut words = [0u64; 1 + 32 + 1 + 32 + 1 + 36];
        let mut n = 0;
        let mut w = |v: u64| {
            words[n] = v;
            n += 1;
        };
        w(argv.n as u64);
        argp[..argv.n].iter().for_each(|&p| w(p));
        w(0);
        envp_at[..envp.n].iter().for_each(|&p| w(p));
        w(0);
        for (k, v) in aux {
            w(k);
            w(v);
        }
        w(0);
        w(0);
        for (k, v) in words[..n].iter().enumerate() {
            if !self.copy_out(i, sp + 8 * k as u64, &v.to_le_bytes()) {
                return Err("stack");
            }
        }
        self.start(i, interp_entry, thread_top, None)
    }

    /// Process `i` ends with wait status `status`: its descriptors are
    /// closed, its address space destroyed, and it waits as a zombie for
    /// its parent (if it has one).
    fn exit(&mut self, i: usize, status: u32) {
        for fd in 0..MAX_FDS {
            self.close(i, fd);
        }
        self.unmake_space(i);
        let pid = self.procs[i].pid;
        for c in 0..MAX_PROCS {
            if self.procs[c].used && self.procs[c].ppid == pid && c != i {
                self.procs[c].ppid = 0;
                if self.procs[c].zombie {
                    self.procs[c].used = false;
                }
            }
        }
        let ppid = self.procs[i].ppid;
        if let Some(parent) = self.procs.iter().position(|q| q.used && !q.zombie && q.pid == ppid) {
            self.post(parent, SIGCHLD);
        }
        let p = &mut self.procs[i];
        p.zombie = true;
        p.status = status;
        p.blocked = Blocked::None;
        if p.ppid == 0 {
            p.used = false;
            if self.top_status.is_none() && pid == self.first_pid() {
                self.top_status = Some(status);
            }
        }
    }

    fn first_pid(&self) -> u32 {
        RUN_PID.load(core::sync::atomic::Ordering::Relaxed)
    }

    // ---- descriptors -------------------------------------------------

    fn file(&self, i: usize, fd: u64) -> Option<usize> {
        let f = *self.procs[i].fds.get(fd as usize)?;
        (f != 0).then(|| f as usize - 1)
    }

    fn new_file(&mut self, kind: FileKind, ino: u16, pipe: u8, flags: u32) -> Option<usize> {
        let f = self.files.iter().position(|f| f.kind == FileKind::Closed)?;
        self.files[f] = Open { kind, refs: 1, ino, pipe, flags, off: 0 };
        Some(f)
    }

    /// The lowest free descriptor from `min`, given open file `f`.
    fn new_fd(&mut self, i: usize, f: usize, min: u64, cloexec: bool) -> Result<u64, u64> {
        let p = &mut self.procs[i];
        let fd = (min as usize..MAX_FDS).find(|&d| p.fds[d] == 0).ok_or(EMFILE)?;
        p.fds[fd] = f as u8 + 1;
        p.cloexec = if cloexec { p.cloexec | 1 << fd } else { p.cloexec & !(1 << fd) };
        Ok(fd as u64)
    }

    fn close(&mut self, i: usize, fd: usize) {
        let Some(f) = self.file(i, fd as u64) else { return };
        self.procs[i].fds[fd] = 0;
        self.procs[i].cloexec &= !(1 << fd);
        let o = &mut self.files[f];
        o.refs -= 1;
        if o.refs == 0 {
            match o.kind {
                FileKind::PipeRead => self.pipes[o.pipe as usize].readers -= 1,
                FileKind::PipeWrite => self.pipes[o.pipe as usize].writers -= 1,
                _ => {}
            }
            o.kind = FileKind::Closed;
        }
    }

    /// The directory `dirfd` names for a path relative to it.
    fn dir_of(&self, i: usize, dirfd: u64) -> Result<u16, u64> {
        if dirfd as i32 == AT_FDCWD {
            return Ok(self.procs[i].cwd);
        }
        let f = self.file(i, dirfd).ok_or(EBADF)?;
        let o = &self.files[f];
        if o.kind != FileKind::Node || self.fs.kind(o.ino) != Kind::Dir {
            return Err(ENOTDIR);
        }
        Ok(o.ino)
    }

    // ---- console -----------------------------------------------------

    fn output(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' || self.len == self.line.len() {
                self.flush();
            }
            if b != b'\n' {
                self.line[self.len] = b;
                self.len += 1;
            }
        }
    }

    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        if let Ok(s) = core::str::from_utf8(&self.line[..self.len]) {
            say!("linux: > {s}");
        }
        self.len = 0;
    }
}

static RUN_PID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Linux's `struct stat` for an inode (or a console or pipe: `ino` 0).
fn stat_bytes(mode: u32, ino: u64, size: u64) -> [u8; 144] {
    let mut s = [0u8; 144];
    let mut put = |at: usize, v: &[u8]| s[at..at + v.len()].copy_from_slice(v);
    put(0, &1u64.to_le_bytes());
    put(8, &ino.to_le_bytes());
    if cfg!(target_arch = "x86_64") {
        put(16, &1u64.to_le_bytes());
        put(24, &mode.to_le_bytes());
        put(56, &4096u64.to_le_bytes());
    } else {
        put(16, &mode.to_le_bytes());
        put(20, &1u32.to_le_bytes());
        put(56, &4096u32.to_le_bytes());
    }
    put(48, &size.to_le_bytes());
    put(64, &size.div_ceil(512).to_le_bytes());
    s
}

const STAT_LEN: usize = if cfg!(target_arch = "x86_64") { 144 } else { 128 };

fn mode_of(kind: Kind) -> u32 {
    match kind {
        Kind::Dir => 0o40755,
        Kind::File => 0o100644,
        Kind::Symlink => 0o120777,
        Kind::Program | Kind::Interp => 0o100755,
        Kind::Null => 0o20666,
        Kind::Tty => 0o20620,
        Kind::Free => 0,
    }
}

/// Does what Linux would for process `i`'s call.
fn answer(st: &mut State, i: usize, call: Sys, a: [u64; 6]) -> Out {
    use Out::Ret;
    let r = |v: Result<u64, u64>| Ret(v.unwrap_or_else(err));
    match call {
        Sys::Exit => {
            st.exit(i, ((a[0] & 0xff) << 8) as u32);
            Out::Gone
        }
        Sys::Read => read(st, i, a[0], a[1], a[2]),
        Sys::Write => write(st, i, a[0], a[1], a[2]),
        Sys::Writev => writev(st, i, a[0], a[1], a[2]),
        Sys::Openat => r(openat(st, i, a)),
        Sys::Close => {
            if st.file(i, a[0]).is_none() {
                return Ret(err(EBADF));
            }
            st.close(i, a[0] as usize);
            Ret(0)
        }
        Sys::Fstat => r(fstat(st, i, a[0], a[1])),
        Sys::Fstatat => r(fstatat(st, i, a)),
        Sys::Lseek => r(lseek(st, i, a[0], a[1] as i64, a[2])),
        Sys::Getdents64 => r(getdents(st, i, a[0], a[1], a[2])),
        Sys::Ioctl => r(ioctl(st, i, a[0], a[1], a[2])),
        Sys::Sigaction => r(st.sigaction(i, a[0], a[1], a[2])),
        Sys::Sigprocmask => r(st.sigprocmask(i, a[0], a[1], a[2])),
        Sys::Sigpending => {
            let p = &st.procs[i];
            let pending = p.pending & p.mask;
            r(st.put(i, a[0], &pending.to_le_bytes()))
        }
        Sys::Sigsuspend => st.sigsuspend(i, Some(a[0])),
        Sys::Pause => st.sigsuspend(i, None),
        Sys::Sigreturn => match st.sigreturn(i) {
            Some((pc, value)) => Out::Resume { pc, value },
            None => {
                st.exit(i, SIGSEGV);
                Out::Gone
            }
        },
        Sys::Kill => r(st.kill(i, a[0] as i32 as i64, a[1])),
        Sys::Tkill if (a[0] as i32) <= 0 => Ret(err(EINVAL)),
        Sys::Tkill => r(st.kill(i, a[0] as i32 as i64, a[1])),
        Sys::Nanosleep => nanosleep(st, i, a[1], a[2]),
        Sys::Poll => {
            let ms = a[2] as i32;
            let until = if ms < 0 { u64::MAX } else { superior_sys::ticks() + (ms as u64 * TICK_HZ).div_ceil(1000) };
            poll(st, i, a[0], a[1], until)
        }
        Sys::Ppoll => {
            let until = if a[2] == 0 {
                u64::MAX
            } else {
                match (st.word(i, a[2]), st.word(i, a[2] + 8)) {
                    (Some(sec), Some(ns)) => superior_sys::ticks() + sec * TICK_HZ + (ns * TICK_HZ).div_ceil(1_000_000_000),
                    _ => return Ret(err(EFAULT)),
                }
            };
            poll(st, i, a[0], a[1], until)
        }
        Sys::Getsid => r(group_of(st, i, a[0]).map(|k| st.procs[k].sid as u64)),
        Sys::Setsid => {
            let p = &mut st.procs[i];
            if p.pgid == p.pid {
                return Ret(err(EPERM));
            }
            (p.sid, p.pgid) = (p.pid, p.pid);
            Ret(p.pid as u64)
        }
        Sys::Faccessat => r(st.dir_of(i, a[0]).and_then(|d| {
            let mut path = [0u8; 256];
            let n = st.cstr(i, a[1], &mut path)?;
            st.fs.resolve(d, &path[..n], true).map(|_| 0)
        })),
        Sys::Pipe2 => r(pipe2(st, i, a[0], a[1] as u32)),
        Sys::Dup => r(st.file(i, a[0]).ok_or(EBADF).and_then(|f| {
            st.files[f].refs += 1;
            st.new_fd(i, f, 0, false).inspect_err(|_| st.files[f].refs -= 1)
        })),
        Sys::Dup2 if a[0] == a[1] => r(st.file(i, a[0]).map(|_| a[1]).ok_or(EBADF)),
        Sys::Dup2 | Sys::Dup3 => r(dup3(st, i, a[0], a[1], if call == Sys::Dup3 { a[2] as u32 } else { 0 })),
        Sys::Fcntl => r(fcntl(st, i, a[0], a[1], a[2])),
        Sys::Ftruncate => r(st.file(i, a[0]).ok_or(EBADF).and_then(|f| {
            let o = st.files[f];
            if o.kind != FileKind::Node || o.flags & O_ACCMODE == 0 {
                return Err(EINVAL);
            }
            st.fs.truncate(o.ino, a[1]).map(|_| 0)
        })),
        Sys::Fork => r(fork(st, i)),
        Sys::Clone if a[0] & CLONE_VM != 0 => Ret(err(ENOSYS)),
        Sys::Clone => r(fork(st, i)),
        Sys::Execve => match execve(st, i, a[0], a[1], a[2]) {
            Ok(()) => Out::Gone,
            Err(e) => Ret(err(e)),
        },
        Sys::Wait4 => wait4(st, i, a[0] as i32 as i64, a[1], a[2]),
        Sys::Getcwd => r(getcwd(st, i, a[0], a[1])),
        Sys::Chdir => r({
            let mut path = [0u8; 256];
            st.cstr(i, a[0], &mut path).and_then(|n| {
                let d = st.fs.resolve(st.procs[i].cwd, &path[..n], true)?;
                if st.fs.kind(d) != Kind::Dir {
                    return Err(ENOTDIR);
                }
                st.procs[i].cwd = d;
                Ok(0)
            })
        }),
        Sys::Fchdir => r(st.dir_of(i, a[0]).map(|d| {
            st.procs[i].cwd = d;
            0
        })),
        Sys::Mkdirat => r(path_op(st, i, a[0], a[1], |fs, dir, name| fs.create(dir, name, Kind::Dir).map(|_| 0))),
        Sys::Unlinkat => r(path_op(st, i, a[0], a[1], |fs, dir, name| {
            let ino = fs.lookup(dir, name).ok_or(ENOENT)?;
            match (fs.kind(ino) == Kind::Dir, a[2] & AT_REMOVEDIR != 0) {
                (true, false) => Err(EISDIR),
                (false, true) => Err(ENOTDIR),
                _ => fs.remove(ino).map(|_| 0),
            }
        })),
        Sys::Symlinkat => r({
            let mut target = [0u8; 256];
            st.cstr(i, a[0], &mut target).and_then(|n| {
                path_op(st, i, a[1], a[2], |fs, dir, name| {
                    let l = fs.create(dir, name, Kind::Symlink)?;
                    fs.write(l, 0, &target[..n]).map(|_| 0)
                })
            })
        }),
        Sys::Renameat => r(renameat(st, i, a)),
        Sys::Readlinkat => r(readlinkat(st, i, a)),
        Sys::Umask => Ret(0o22),
        Sys::Getpid => Ret(st.procs[i].pid as u64),
        Sys::Getpgid => r(group_of(st, i, a[0]).map(|k| st.procs[k].pgid as u64)),
        Sys::Getppid => Ret(st.procs[i].ppid as u64),
        Sys::Setpgid => r(setpgid(st, i, a[0], a[1])),
        Sys::Zero => Ret(0),
        Sys::Brk => Ret(brk(st, i, a[0])),
        Sys::Mmap => r(mmap(st, i, a)),
        Sys::Munmap => Ret(0),
        Sys::Uname => {
            let mut u = [0u8; 6 * 65];
            for (k, f) in ["Linux", "superior", "6.1.0-superior", "#1 Superior", PLATFORM, ""].iter().enumerate() {
                u[k * 65..k * 65 + f.len()].copy_from_slice(f.as_bytes());
            }
            r(st.put(i, a[0], &u))
        }
        Sys::ArchPrctl => {
            const ARCH_SET_FS: u64 = 0x1002;
            const ARCH_GET_FS: u64 = 0x1003;
            let t = thread_slot(i);
            match a[0] {
                ARCH_SET_FS => r(sys(Syscall::ThreadRegisters, t, [REGS_SET_TLS, a[1], 0, 0]).map(|_| 0).map_err(|_| EINVAL)),
                ARCH_GET_FS => {
                    let fs = sys(Syscall::ThreadRegisters, t, [REGS_TLS, 0, 0, 0]).map_or(0, |m| m[0]);
                    r(st.put(i, a[1], &fs.to_le_bytes()))
                }
                _ => Ret(err(EINVAL)),
            }
        }
        Sys::ClockGettime | Sys::Gettimeofday => {
            let t = superior_sys::ticks();
            let (sec, frac) = (t / TICK_HZ, t % TICK_HZ);
            let mut ts = [0u8; 16];
            ts[..8].copy_from_slice(&sec.to_le_bytes());
            let sub = if call == Sys::ClockGettime { frac * (1_000_000_000 / TICK_HZ) } else { frac * (1_000_000 / TICK_HZ) };
            ts[8..].copy_from_slice(&sub.to_le_bytes());
            let at = if call == Sys::ClockGettime { a[1] } else { a[0] };
            if at == 0 { Ret(0) } else { r(st.put(i, at, &ts)) }
        }
        Sys::Getrandom => {
            let n = a[1].min(256);
            let mut b = [0u8; 256];
            for chunk in b[..n as usize].chunks_mut(32) {
                let r = superior_sys::random().unwrap_or([0x5a; 32]);
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            r(st.put(i, a[0], &b[..n as usize]).map(|_| n))
        }
        Sys::Prlimit | Sys::Getrlimit => {
            let at = if call == Sys::Prlimit { a[3] } else { a[1] };
            let mut l = [0xffu8; 16];
            if a[if call == Sys::Prlimit { 1 } else { 0 }] == 7 {
                // RLIMIT_NOFILE: the descriptors there are.
                l[..8].copy_from_slice(&(MAX_FDS as u64).to_le_bytes());
                l[8..].copy_from_slice(&(MAX_FDS as u64).to_le_bytes());
            }
            if at == 0 { Ret(0) } else { r(st.put(i, at, &l)) }
        }
        Sys::Times => Ret(superior_sys::ticks()),
        Sys::Quiet => Ret(err(ENOSYS)),
        Sys::Sendfile => Ret(err(EINVAL)),
        Sys::Unsupported(n) => {
            say!("linux: system call {n} not implemented");
            Ret(err(ENOSYS))
        }
    }
}

/// A path call relative to `dirfd`: `op` on the directory the path's last
/// part is in, and that part.
fn path_op(st: &mut State, i: usize, dirfd: u64, path: u64, op: impl FnOnce(&mut Fs, u16, &[u8]) -> Result<u64, u64>) -> Result<u64, u64> {
    let base = st.dir_of(i, dirfd)?;
    let mut p = [0u8; 256];
    let n = st.cstr(i, path, &mut p)?;
    let (dir, name) = st.fs.parent_of(base, &p[..n])?;
    op(&mut st.fs, dir, name)
}

fn openat(st: &mut State, i: usize, a: [u64; 6]) -> Result<u64, u64> {
    let base = st.dir_of(i, a[0])?;
    let mut p = [0u8; 256];
    let n = st.cstr(i, a[1], &mut p)?;
    let path = &p[..n];
    let flags = a[2] as u32;
    let ino = if flags & O_CREAT != 0 {
        let (dir, name) = st.fs.parent_of(base, path)?;
        match st.fs.lookup(dir, name) {
            Some(_) if flags & O_EXCL != 0 => return Err(EEXIST),
            Some(_) => st.fs.resolve(base, path, flags & O_NOFOLLOW == 0)?,
            None => st.fs.create(dir, name, Kind::File)?,
        }
    } else {
        st.fs.resolve(base, path, flags & O_NOFOLLOW == 0)?
    };
    let kind = st.fs.kind(ino);
    let writing = flags & O_ACCMODE != 0;
    if flags & O_DIRECTORY != 0 && kind != Kind::Dir {
        return Err(ENOTDIR);
    }
    if kind == Kind::Dir && writing {
        return Err(EISDIR);
    }
    if writing && matches!(kind, Kind::Program | Kind::Interp) {
        return Err(EACCES);
    }
    if flags & O_TRUNC != 0 && writing && kind == Kind::File {
        st.fs.truncate(ino, 0)?;
    }
    let fk = if kind == Kind::Tty { FileKind::Tty } else { FileKind::Node };
    let f = st.new_file(fk, ino, 0, flags).ok_or(ENFILE)?;
    st.new_fd(i, f, 0, flags & O_CLOEXEC != 0).inspect_err(|_| st.files[f].kind = FileKind::Closed)
}

fn fstat(st: &mut State, i: usize, fd: u64, buf: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    let s = match o.kind {
        FileKind::Node => stat_bytes(mode_of(st.fs.kind(o.ino)), o.ino as u64, st.fs.size(o.ino)),
        FileKind::Console | FileKind::Tty => stat_bytes(0o20620, 0, 0),
        _ => stat_bytes(0o10600, 0, st.pipes[o.pipe as usize].len as u64),
    };
    st.put(i, buf, &s[..STAT_LEN])
}

fn fstatat(st: &mut State, i: usize, a: [u64; 6]) -> Result<u64, u64> {
    let mut p = [0u8; 256];
    let n = st.cstr(i, a[1], &mut p)?;
    if n == 0 && a[3] & AT_EMPTY_PATH != 0 {
        return fstat(st, i, a[0], a[2]);
    }
    let base = st.dir_of(i, a[0])?;
    let ino = st.fs.resolve(base, &p[..n], a[3] & AT_SYMLINK_NOFOLLOW == 0)?;
    let s = stat_bytes(mode_of(st.fs.kind(ino)), ino as u64, st.fs.size(ino));
    st.put(i, a[2], &s[..STAT_LEN])
}

fn lseek(st: &mut State, i: usize, fd: u64, off: i64, whence: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    if o.kind != FileKind::Node {
        return Err(ESPIPE);
    }
    let base = match whence {
        0 => 0,
        1 => o.off as i64,
        2 => st.fs.size(o.ino) as i64,
        _ => return Err(EINVAL),
    };
    let to = base.checked_add(off).filter(|&t| t >= 0).ok_or(EINVAL)?;
    st.files[f].off = to as u64;
    Ok(to as u64)
}

fn getdents(st: &mut State, i: usize, fd: u64, buf: u64, count: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    if o.kind != FileKind::Node || st.fs.kind(o.ino) != Kind::Dir {
        return Err(ENOTDIR);
    }
    let (mut pos, mut out) = (o.off, 0u64);
    while let Some((next, ino, name)) = st.fs.entry(o.ino, pos) {
        let reclen = (19 + name.len() as u64 + 1).next_multiple_of(8);
        if out + reclen > count {
            if out == 0 {
                return Err(EINVAL);
            }
            break;
        }
        let mut rec = [0u8; 56];
        rec[..8].copy_from_slice(&(ino as u64).to_le_bytes());
        rec[8..16].copy_from_slice(&next.to_le_bytes());
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = match st.fs.kind(ino) {
            Kind::Dir => 4,
            Kind::Symlink => 10,
            Kind::Null => 2,
            _ => 8,
        };
        rec[19..19 + name.len()].copy_from_slice(name);
        st.put(i, buf + out, &rec[..reclen as usize])?;
        out += reclen;
        pos = next;
    }
    st.files[f].off = pos;
    Ok(out)
}

fn pipe2(st: &mut State, i: usize, at: u64, flags: u32) -> Result<u64, u64> {
    let k = (0..MAX_PIPES).find(|&k| st.pipes[k].readers == 0 && st.pipes[k].writers == 0).ok_or(ENFILE)?;
    let pipe = &mut st.pipes[k];
    pipe.take(&mut [0; PIPE_BUF]);
    pipe.readers = 1;
    pipe.writers = 1;
    let cloexec = flags & O_CLOEXEC != 0;
    let r = st.new_file(FileKind::PipeRead, 0, k as u8, 0);
    let w = st.new_file(FileKind::PipeWrite, 0, k as u8, O_WRONLY);
    let (Some(r), Some(w)) = (r, w) else {
        r.map(|r| st.files[r].kind = FileKind::Closed);
        w.map(|w| st.files[w].kind = FileKind::Closed);
        st.pipes[k].readers = 0;
        st.pipes[k].writers = 0;
        return Err(ENFILE);
    };
    let rfd = st.new_fd(i, r, 0, cloexec)?;
    let wfd = st.new_fd(i, w, 0, cloexec)?;
    let mut fds = [0u8; 8];
    fds[..4].copy_from_slice(&(rfd as u32).to_le_bytes());
    fds[4..].copy_from_slice(&(wfd as u32).to_le_bytes());
    st.put(i, at, &fds)
}

fn dup3(st: &mut State, i: usize, old: u64, new: u64, flags: u32) -> Result<u64, u64> {
    let f = st.file(i, old).ok_or(EBADF)?;
    if new as usize >= MAX_FDS {
        return Err(EBADF);
    }
    if old == new {
        return Err(EINVAL);
    }
    st.files[f].refs += 1;
    st.close(i, new as usize);
    st.new_fd(i, f, new, flags & O_CLOEXEC != 0)
}

fn fcntl(st: &mut State, i: usize, fd: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    match cmd {
        0 | 1030 => {
            st.files[f].refs += 1;
            st.new_fd(i, f, arg, cmd == 1030).inspect_err(|_| st.files[f].refs -= 1)
        }
        1 => Ok((st.procs[i].cloexec >> fd & 1) as u64),
        2 => {
            let p = &mut st.procs[i];
            p.cloexec = if arg & 1 != 0 { p.cloexec | 1 << fd } else { p.cloexec & !(1 << fd) };
            Ok(0)
        }
        3 => Ok(st.files[f].flags as u64),
        4 => {
            let keep = O_APPEND | O_NONBLOCK;
            let o = &mut st.files[f];
            o.flags = o.flags & !keep | arg as u32 & keep;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

fn read(st: &mut State, i: usize, fd: u64, buf: u64, len: u64) -> Out {
    let Some(f) = st.file(i, fd) else { return Out::Ret(err(EBADF)) };
    let o = st.files[f];
    let mut tmp = [0u8; 4096];
    let want = len.min(tmp.len() as u64) as usize;
    let n = match o.kind {
        FileKind::Console => 0,
        FileKind::Tty if !st.tty.readable() => {
            if o.flags & O_NONBLOCK != 0 {
                return Out::Ret(err(EAGAIN));
            }
            return Out::Block(Blocked::Read { fd, buf, len });
        }
        FileKind::Tty => st.tty.read(&mut tmp[..want]),
        FileKind::Node => match st.fs.kind(o.ino) {
            Kind::Dir => return Out::Ret(err(EISDIR)),
            _ if o.flags & O_ACCMODE == O_WRONLY => return Out::Ret(err(EBADF)),
            _ => {
                let n = st.fs.read(o.ino, o.off, &mut tmp[..want]);
                st.files[f].off += n as u64;
                n
            }
        },
        FileKind::PipeRead => {
            let pipe = &mut st.pipes[o.pipe as usize];
            if pipe.len == 0 {
                if pipe.writers == 0 {
                    return Out::Ret(0);
                }
                if o.flags & O_NONBLOCK != 0 {
                    return Out::Ret(err(EAGAIN));
                }
                return Out::Block(Blocked::Read { fd, buf, len });
            }
            pipe.take(&mut tmp[..want])
        }
        _ => return Out::Ret(err(EBADF)),
    };
    Out::Ret(st.put(i, buf, &tmp[..n]).map_or_else(err, |_| n as u64))
}

fn write(st: &mut State, i: usize, fd: u64, buf: u64, len: u64) -> Out {
    let Some(f) = st.file(i, fd) else { return Out::Ret(err(EBADF)) };
    let o = st.files[f];
    let mut tmp = [0u8; 4096];
    let n = match o.kind {
        FileKind::PipeWrite => {
            let pipe = &st.pipes[o.pipe as usize];
            if pipe.readers == 0 {
                st.post(i, SIGPIPE);
                return Out::Ret(err(EPIPE));
            }
            let room = PIPE_BUF - pipe.len as usize;
            if room == 0 {
                if o.flags & O_NONBLOCK != 0 {
                    return Out::Ret(err(EAGAIN));
                }
                return Out::Block(Blocked::Write { fd, buf, len });
            }
            room.min(len as usize)
        }
        FileKind::Node if o.flags & O_ACCMODE == 0 => return Out::Ret(err(EBADF)),
        FileKind::Console | FileKind::Tty | FileKind::Node => len.min(tmp.len() as u64) as usize,
        _ => return Out::Ret(err(EBADF)),
    };
    if !st.copy_in(i, buf, &mut tmp[..n]) {
        return Out::Ret(err(EFAULT));
    }
    Out::Ret(match o.kind {
        FileKind::Console => {
            st.output(&tmp[..n]);
            n as u64
        }
        FileKind::Tty => {
            st.tty.write(&tmp[..n]);
            n as u64
        }
        FileKind::PipeWrite => st.pipes[o.pipe as usize].put(&tmp[..n]) as u64,
        _ => match st.fs.kind(o.ino) {
            Kind::Null => n as u64,
            _ => {
                let at = if o.flags & O_APPEND != 0 { st.fs.size(o.ino) } else { o.off };
                match st.fs.write(o.ino, at, &tmp[..n]) {
                    Ok(w) => {
                        st.files[f].off = at + w as u64;
                        w as u64
                    }
                    Err(e) => err(e),
                }
            }
        },
    })
}

fn writev(st: &mut State, i: usize, fd: u64, iov: u64, cnt: u64) -> Out {
    let mut total = 0;
    for k in 0..cnt.min(64) {
        let (Some(base), Some(len)) = (st.word(i, iov + 16 * k), st.word(i, iov + 16 * k + 8)) else {
            return Out::Ret(err(EFAULT));
        };
        let mut done = 0;
        while done < len {
            match write(st, i, fd, base + done, len - done) {
                Out::Ret(v) if (v as i64) < 0 => return Out::Ret(if total > 0 { total } else { v }),
                Out::Ret(v) => {
                    done += v;
                    total += v;
                }
                Out::Block(_) if total == 0 => return Out::Block(Blocked::Writev { fd, iov, cnt }),
                _ => return Out::Ret(total),
            }
        }
    }
    Out::Ret(total)
}

fn getcwd(st: &mut State, i: usize, buf: u64, size: u64) -> Result<u64, u64> {
    // Walk up to the root, writing names backwards.
    let mut path = [0u8; 256];
    let mut at = path.len();
    let mut d = st.procs[i].cwd;
    while d != ROOT {
        let name = st.fs.name(d);
        if at < name.len() + 1 {
            return Err(ERANGE);
        }
        at -= name.len();
        path[at..at + name.len()].copy_from_slice(name);
        at -= 1;
        path[at] = b'/';
        d = st.fs.inodes[d as usize].parent;
    }
    if at == path.len() {
        at -= 1;
        path[at] = b'/';
    }
    let s = &path[at..];
    if s.len() as u64 + 1 > size {
        return Err(ERANGE);
    }
    st.put(i, buf, s)?;
    st.put(i, buf + s.len() as u64, &[0])?;
    Ok(s.len() as u64 + 1)
}

fn renameat(st: &mut State, i: usize, a: [u64; 6]) -> Result<u64, u64> {
    let (b1, b2) = (st.dir_of(i, a[0])?, st.dir_of(i, a[2])?);
    let (mut p1, mut p2) = ([0u8; 256], [0u8; 256]);
    let n1 = st.cstr(i, a[1], &mut p1)?;
    let n2 = st.cstr(i, a[3], &mut p2)?;
    let (d1, name1) = st.fs.parent_of(b1, &p1[..n1])?;
    let ino = st.fs.lookup(d1, name1).ok_or(ENOENT)?;
    let (d2, name2) = st.fs.parent_of(b2, &p2[..n2])?;
    st.fs.rename(ino, d2, name2).map(|_| 0)
}

fn readlinkat(st: &mut State, i: usize, a: [u64; 6]) -> Result<u64, u64> {
    let base = st.dir_of(i, a[0])?;
    let mut p = [0u8; 256];
    let n = st.cstr(i, a[1], &mut p)?;
    let ino = st.fs.resolve(base, &p[..n], false)?;
    if st.fs.kind(ino) != Kind::Symlink {
        return Err(EINVAL);
    }
    let mut t = [0u8; 256];
    let m = st.fs.read(ino, 0, &mut t).min(a[3] as usize);
    st.put(i, a[2], &t[..m]).map(|_| m as u64)
}

fn brk(st: &mut State, i: usize, want: u64) -> u64 {
    let p = &st.procs[i];
    let (start, cur) = (p.brk_start, p.brk);
    if want <= start || want > start + BRK_MAX {
        return cur;
    }
    let mut at = cur.next_multiple_of(PAGE);
    while at < want {
        if st.map_private(i, at).is_err() {
            return st.procs[i].brk;
        }
        at += PAGE;
    }
    st.procs[i].brk = want;
    want
}

fn mmap(st: &mut State, i: usize, a: [u64; 6]) -> Result<u64, u64> {
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    let (addr, len, flags) = (a[0], a[1].next_multiple_of(PAGE), a[3]);
    if flags & MAP_ANONYMOUS == 0 {
        return Err(if len == 0 { ENOMEM } else { ENODEV });
    }
    if len == 0 {
        return Err(EINVAL);
    }
    let at = if flags & MAP_FIXED != 0 {
        addr
    } else {
        let at = st.procs[i].mmap_next;
        st.procs[i].mmap_next += len + PAGE;
        at
    };
    if at % PAGE != 0 || at < CHILD || at + len > STACK_TOP - STACK_PAGES * PAGE {
        return Err(ENOMEM);
    }
    for p in (at..at + len).step_by(PAGE as usize) {
        let was = st.is_present(i, p);
        st.map_private(i, p)?;
        if was {
            st.copy_out(i, p, &[0; PAGE as usize]);
        }
    }
    Ok(at)
}

/// `fork`: a new process with a copy of `i`'s own pages, its descriptors
/// and directory, and its registers (0 in the result).
fn fork(st: &mut State, i: usize) -> Result<u64, u64> {
    let c = st.new_proc(st.procs[i].pid).ok_or(EAGAIN)?;
    let fail = |st: &mut State, e| {
        st.unmake_space(c);
        st.procs[c].used = false;
        Err(e)
    };
    if st.make_space(c).is_err() {
        return fail(st, ENOMEM);
    }
    for k in 0..CHILD_PAGES {
        if st.procs[i].present[k / 64] & (1 << (k % 64)) == 0 {
            continue;
        }
        let va = CHILD + k as u64 * PAGE;
        if st.map_private(c, va).is_err() {
            return fail(st, ENOMEM);
        }
        let (from, to) = (va - CHILD + MIRROR + i as u64 * SPAN, va - CHILD + MIRROR + c as u64 * SPAN);
        // SAFETY: both are whole pages mapped in the mirrors.
        unsafe { core::ptr::copy_nonoverlapping(from as *const u8, to as *mut u8, PAGE as usize) };
    }
    if st.map_all_shared(c).is_err() {
        return fail(st, ENOMEM);
    }
    let (fds, cloexec, cwd) = (st.procs[i].fds, st.procs[i].cloexec, st.procs[i].cwd);
    let (b0, b1, m) = (st.procs[i].brk_start, st.procs[i].brk, st.procs[i].mmap_next);
    for &f in fds.iter().filter(|&&f| f != 0) {
        st.files[f as usize - 1].refs += 1;
    }
    let (pgid, sid, mask, actions) = (st.procs[i].pgid, st.procs[i].sid, st.procs[i].mask, st.procs[i].actions);
    let p = &mut st.procs[c];
    (p.fds, p.cloexec, p.cwd, p.brk_start, p.brk, p.mmap_next) = (fds, cloexec, cwd, b0, b1, m);
    (p.pgid, p.sid, p.mask, p.actions) = (pgid, sid, mask, actions);
    if st.start(c, CHILD + PAGE, CHILD + 2 * PAGE, Some(i)).is_err() {
        for fd in 0..MAX_FDS {
            st.close(c, fd);
        }
        return fail(st, ENOMEM);
    }
    Ok(st.procs[c].pid as u64)
}

/// `execve`: the program `path` names replaces process `i`'s.
fn execve(st: &mut State, i: usize, path: u64, argv: u64, envp: u64) -> Result<(), u64> {
    let mut name = [0u8; 256];
    let n = st.cstr(i, path, &mut name)?;
    let ino = st.fs.resolve(st.procs[i].cwd, &name[..n], true)?;
    match st.fs.kind(ino) {
        Kind::Program => {}
        Kind::Dir => return Err(EACCES),
        _ => return Err(ENOEXEC),
    }
    let (mut args, mut env) = (Strs::new(), Strs::new());
    for (list, at) in [(&mut args, argv), (&mut env, envp)] {
        if at == 0 {
            continue;
        }
        for k in 0.. {
            let ptr = st.word(i, at + 8 * k).ok_or(EFAULT)?;
            if ptr == 0 {
                break;
            }
            let mut s = [0u8; 512];
            let len = st.cstr(i, ptr, &mut s)?;
            if !list.push(&s[..len]) {
                return Err(fs::ENAMETOOLONG);
            }
        }
    }
    // Past here there is no going back: the old program is gone.
    st.unmake_space(i);
    let cloexec = st.procs[i].cloexec;
    for fd in 0..MAX_FDS {
        if cloexec & 1 << fd != 0 {
            st.close(i, fd);
        }
    }
    st.reset_handlers(i);
    if let Err(why) = st.exec(i, &args, &env, &name[..n]) {
        say!("linux: pid {}: exec failed after the old program was gone: {why}", st.procs[i].pid);
        st.exit(i, 127 << 8);
    }
    Ok(())
}

fn wait4(st: &mut State, i: usize, pid: i64, status: u64, options: u64) -> Out {
    let me = st.procs[i].pid;
    let mine = |p: &Proc| p.used && p.ppid == me && (pid <= 0 || p.pid as i64 == pid);
    if !st.procs.iter().any(|p| mine(p)) {
        return Out::Ret(err(ECHILD));
    }
    let Some(c) = st.procs.iter().position(|p| mine(p) && p.zombie) else {
        if options & WNOHANG != 0 {
            return Out::Ret(0);
        }
        return Out::Block(Blocked::Wait { pid, status, options });
    };
    let (cpid, cstatus) = (st.procs[c].pid, st.procs[c].status);
    if status != 0 && st.put(i, status, &cstatus.to_le_bytes()).is_err() {
        return Out::Ret(err(EFAULT));
    }
    st.procs[c].used = false;
    Out::Ret(cpid as u64)
}

/// Answers process `i`'s call with `value`, resuming at `pc` (the call
/// just received if `place` is `None`, else the one set aside there),
/// unless a signal it must take comes first: then it ends, or starts in
/// the handler with that answer saved for after.
fn finish(st: &mut State, i: usize, pc: u64, value: u64, place: Option<u64>) {
    let (pc, value) = match st.next_signal(i) {
        Next::None => (pc, value),
        Next::Kill(sig) => {
            st.exit(i, sig);
            return;
        }
        Next::Handle(sig) => match st.enter_handler(i, sig, pc, Some(value)) {
            Some(at) => at,
            None => {
                st.exit(i, SIGSEGV);
                return;
            }
        },
    };
    let msg = [FaultReply::ResumeAt as u64, pc, value, 0];
    match place {
        None => syscall(Syscall::Reply, 0, msg),
        Some(place) => syscall(Syscall::ReplyTo, place, msg),
    };
}

/// Tries every waiting call again, answering those that can go on, and
/// acts on signals: a process waiting in a call is interrupted for a
/// handler, and any process a signal ends is ended. Until nothing moves.
fn wake(st: &mut State) {
    loop {
        let mut moved = false;
        for i in 0..MAX_PROCS {
            let p = &st.procs[i];
            if !p.used || p.zombie {
                continue;
            }
            let blocked = p.blocked;
            let out = match blocked {
                Blocked::None => {
                    // Running: only a signal that ends it acts now.
                    if let Next::Kill(sig) = st.next_signal(i) {
                        st.exit(i, sig);
                        moved = true;
                    }
                    continue;
                }
                Blocked::Read { fd, buf, len } => read(st, i, fd, buf, len),
                Blocked::Write { fd, buf, len } => write(st, i, fd, buf, len),
                Blocked::Writev { fd, iov, cnt } => writev(st, i, fd, iov, cnt),
                Blocked::Wait { pid, status, options } => wait4(st, i, pid, status, options),
                Blocked::Sleep { until } if superior_sys::ticks() >= until => Out::Ret(0),
                Blocked::Poll { fds, n, until } => poll(st, i, fds, n, until),
                Blocked::Sleep { .. } | Blocked::Suspend => Out::Block(blocked),
            };
            let (place, pc) = (st.procs[i].place, st.procs[i].pc);
            if let Out::Ret(v) = out {
                st.procs[i].blocked = Blocked::None;
                finish(st, i, pc, v, Some(place));
                moved = true;
                continue;
            }
            match st.next_signal(i) {
                Next::None => {}
                Next::Kill(sig) => {
                    st.exit(i, sig);
                    moved = true;
                }
                Next::Handle(sig) => {
                    // Interrupted: EINTR after the handler, or with
                    // SA_RESTART the call made again.
                    let restart = st.procs[i].actions[sig as usize - 1].flags & SA_RESTART != 0
                        && matches!(blocked, Blocked::Read { .. } | Blocked::Write { .. } | Blocked::Writev { .. } | Blocked::Wait { .. });
                    st.procs[i].blocked = Blocked::None;
                    let entered = if restart {
                        st.enter_handler(i, sig, pc - SYSCALL_LEN, None)
                    } else {
                        st.enter_handler(i, sig, pc, Some(err(EINTR)))
                    };
                    match entered {
                        Some((at, v)) => {
                            syscall(Syscall::ReplyTo, place, [FaultReply::ResumeAt as u64, at, v, 0]);
                        }
                        None => st.exit(i, SIGSEGV),
                    }
                    moved = true;
                }
            }
        }
        if !moved {
            break;
        }
    }
    // The timer for the next sleeper to wake, if any.
    let next = st
        .procs
        .iter()
        .filter(|p| p.used && !p.zombie)
        .filter_map(|p| match p.blocked {
            Blocked::Sleep { until } => Some(until),
            Blocked::Poll { until, .. } if until != u64::MAX => Some(until),
            _ => None,
        })
        .min();
    let ticks = next.map_or(0, |until| until.saturating_sub(superior_sys::ticks()).max(1));
    syscall(Syscall::TimerSignal, NTFN_TIMER, [ticks, 0, 0, 0]);
}

/// Typed bytes from the UART: into the terminal, signals to its
/// foreground group.
fn uart_input(st: &mut State) {
    while let Some(b) = tty::uart::try_read() {
        if let Some(sig) = st.tty.input(b) {
            let fg = st.tty.fg;
            st.post_group(fg, sig);
        }
    }
    tty::uart::clear_interrupt();
    syscall(Syscall::IrqAck, tty::UART_IRQ, [0; 4]);
}

/// Runs `argv` as a new process (pid 1 in the first run, then counting
/// on) until it and every process it made are gone. Its standard input
/// and output are the console log (output a line at a time, input empty),
/// or, `interactive`, the terminal, with the process leading its session
/// and in the foreground. Its wait status.
fn run(st: &mut State, argv: &[&str], env: &[&str], interactive: bool) -> Result<u32, &'static str> {
    let i = st.new_proc(0).ok_or("no process slot")?;
    let pid = st.procs[i].pid;
    RUN_PID.store(pid, core::sync::atomic::Ordering::Relaxed);
    st.top_status = None;
    let kind = if interactive { FileKind::Tty } else { FileKind::Console };
    let console = st.new_file(kind, 0, 0, O_RDWR).ok_or("no open file")?;
    st.files[console].refs = 3;
    st.procs[i].fds[..3].fill(console as u8 + 1);
    if interactive {
        st.tty.reset(pid);
    }
    let (mut args, mut envs) = (Strs::new(), Strs::new());
    argv.iter().for_each(|a| _ = args.push(a.as_bytes()));
    env.iter().for_each(|e| _ = envs.push(e.as_bytes()));
    let execfn = [b"/bin/" as &[u8], argv[0].as_bytes()].concat_into::<64>();
    if let Err(why) = st.exec(i, &args, &envs, execfn.as_slice()) {
        st.exit(i, 127 << 8);
        return Err(why);
    }
    let interp = Elf::parse(st.program).ok().and_then(|e| e.interpreter()).unwrap_or(b"?");
    let interp = core::str::from_utf8(interp).unwrap_or("?").trim_end_matches(char::from(0));
    say!("linux: running {} (pid {pid}, interpreter {interp})", Joined(argv));
    while st.procs.iter().any(|p| p.used && !p.zombie) {
        let r = syscall(Syscall::Recv, EP, [0; 4]);
        if r.status == Error::Notified as u64 {
            if r.badge & 1 != 0 {
                uart_input(st);
            }
            wake(st);
            continue;
        }
        let [kind, nr, pc, _] = r.msg;
        let Some(i) = (r.badge as usize).checked_sub(1).filter(|&i| i < MAX_PROCS && st.procs[i].used) else {
            continue;
        };
        if r.status != 0 || FaultKind::from_u64(kind) != Some(FaultKind::ForeignSyscall) {
            st.flush();
            let (what, signal) = match FaultKind::from_u64(kind) {
                Some(FaultKind::PageFault) => ("page fault", 11),
                Some(FaultKind::InvalidOpcode) => ("invalid instruction", 4),
                Some(FaultKind::DivideError) => ("arithmetic fault", 8),
                _ => ("general protection fault", 11),
            };
            say!("linux: pid {} killed: {what} at pc {pc:#x}, address {nr:#x}", st.procs[i].pid);
            st.exit(i, signal);
            wake(st);
            continue;
        }
        let t = thread_slot(i);
        let x = sys(Syscall::ThreadRegisters, t, [REGS_SYSCALL, 0, 0, 0]).unwrap_or([0; 4]);
        let y = sys(Syscall::ThreadRegisters, t, [REGS_SYSCALL_MORE, 0, 0, 0]).unwrap_or([0; 4]);
        let (call, args) = decode(nr, [x[1], x[2], x[3], y[0], y[1], y[2]]);
        match answer(st, i, call, args) {
            Out::Ret(v) => finish(st, i, pc, v, None),
            Out::Resume { pc, value } => finish(st, i, pc, value, None),
            Out::Block(b) => {
                let saved = syscall(Syscall::ReplySave, 0, [0; 4]);
                let p = &mut st.procs[i];
                p.blocked = b;
                p.place = saved.msg[0];
                p.pc = pc;
            }
            Out::Gone => {}
        }
        wake(st);
    }
    st.flush();
    st.top_status.ok_or("lost track of the first process")
}

/// `poll`: which of the `n` descriptors in the `pollfd`s at `fds` are
/// ready to read (`POLLIN`) or write (`POLLOUT`), or hung up; waits for
/// one until tick `until` (`u64::MAX`: no limit).
fn poll(st: &mut State, i: usize, fds: u64, n: u64, until: u64) -> Out {
    const POLLIN: u16 = 1;
    const POLLOUT: u16 = 4;
    const POLLERR: u16 = 8;
    const POLLHUP: u16 = 0x10;
    const POLLNVAL: u16 = 0x20;
    if n > 64 {
        return Out::Ret(err(EINVAL));
    }
    let mut ready = 0;
    for k in 0..n {
        let at = fds + 8 * k;
        let mut e = [0u8; 8];
        if !st.copy_in(i, at, &mut e) {
            return Out::Ret(err(EFAULT));
        }
        let fd = i32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let events = u16::from_le_bytes([e[4], e[5]]);
        let revents = if fd < 0 {
            0
        } else {
            match st.file(i, fd as u64).map(|f| st.files[f]) {
                None => POLLNVAL,
                Some(o) => match o.kind {
                    FileKind::Tty => (if st.tty.readable() { POLLIN } else { 0 }) | POLLOUT,
                    FileKind::PipeRead => {
                        let pipe = &st.pipes[o.pipe as usize];
                        (if pipe.len > 0 { POLLIN } else { 0 }) | if pipe.writers == 0 { POLLHUP } else { 0 }
                    }
                    FileKind::PipeWrite => {
                        let pipe = &st.pipes[o.pipe as usize];
                        if pipe.readers == 0 {
                            POLLERR
                        } else if (pipe.len as usize) < PIPE_BUF {
                            POLLOUT
                        } else {
                            0
                        }
                    }
                    _ => POLLIN | POLLOUT,
                },
            }
        } & (events | POLLERR | POLLHUP | POLLNVAL);
        ready += (revents != 0) as u64;
        if !st.copy_out(i, at + 6, &revents.to_le_bytes()) {
            return Out::Ret(err(EFAULT));
        }
    }
    if ready > 0 || superior_sys::ticks() >= until {
        return Out::Ret(ready);
    }
    Out::Block(Blocked::Poll { fds, n, until })
}

/// The process `pid` names for `getpgid` and `getsid` (0: the caller).
fn group_of(st: &State, i: usize, pid: u64) -> Result<usize, u64> {
    if pid == 0 {
        return Ok(i);
    }
    st.procs.iter().position(|p| p.used && p.pid as u64 == pid).ok_or(ESRCH)
}

/// `setpgid`: the caller or a child of its into group `pgid` (0: its own
/// pid), within its session.
fn setpgid(st: &mut State, i: usize, pid: u64, pgid: u64) -> Result<u64, u64> {
    let me = st.procs[i].pid;
    let k = if pid == 0 { i } else { group_of(st, i, pid)? };
    let p = &st.procs[k];
    if k != i && p.ppid != me {
        return Err(ESRCH);
    }
    if p.sid != st.procs[i].sid || p.pid == p.sid {
        return Err(EPERM);
    }
    let pgid = if pgid == 0 { p.pid } else { pgid as u32 };
    if pgid != p.pid && !st.procs.iter().any(|q| q.used && q.pgid == pgid && q.sid == p.sid) {
        return Err(EPERM);
    }
    st.procs[k].pgid = pgid;
    Ok(0)
}

/// `clock_nanosleep` (`nanosleep` with clock 0 and no flags): sleeps
/// until the time in `req`, relative or (`TIMER_ABSTIME`) absolute, to
/// the tick.
fn nanosleep(st: &mut State, i: usize, flags: u64, req: u64) -> Out {
    let (Some(sec), Some(nsec)) = (st.word(i, req), st.word(i, req + 8)) else { return Out::Ret(err(EFAULT)) };
    if nsec >= 1_000_000_000 {
        return Out::Ret(err(EINVAL));
    }
    let ticks = sec.saturating_mul(TICK_HZ).saturating_add((nsec * TICK_HZ).div_ceil(1_000_000_000));
    let until = if flags & 1 != 0 { ticks } else { superior_sys::ticks().saturating_add(ticks) };
    if until <= superior_sys::ticks() {
        return Out::Ret(0);
    }
    Out::Block(Blocked::Sleep { until })
}

/// The terminal's `ioctl`s: its settings, window size and foreground
/// group. Anything else is not a terminal.
fn ioctl(st: &mut State, i: usize, fd: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCSCTTY: u64 = 0x540e;
    const TIOCGPGRP: u64 = 0x540f;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541b;
    const TIOCNOTTY: u64 = 0x5422;
    const TIOCGSID: u64 = 0x5429;
    let f = st.file(i, fd).ok_or(EBADF)?;
    if st.files[f].kind != FileKind::Tty {
        return Err(ENOTTY);
    }
    match cmd {
        TCGETS => {
            let t = st.tty.termios;
            st.put(i, arg, &t)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let mut t = [0u8; tty::TERMIOS_LEN];
            if !st.copy_in(i, arg, &mut t) {
                return Err(EFAULT);
            }
            st.tty.set(t, cmd == TCSETSF);
            Ok(0)
        }
        TIOCGPGRP => {
            let fg = st.tty.fg;
            st.put(i, arg, &fg.to_le_bytes())
        }
        TIOCSPGRP => {
            let mut b = [0u8; 4];
            if !st.copy_in(i, arg, &mut b) {
                return Err(EFAULT);
            }
            let pgid = u32::from_le_bytes(b);
            if !st.procs.iter().any(|p| p.used && !p.zombie && p.pgid == pgid) {
                return Err(EPERM);
            }
            st.tty.fg = pgid;
            Ok(0)
        }
        TIOCGWINSZ => {
            let mut w = [0u8; 8];
            w[..2].copy_from_slice(&st.tty.rows.to_le_bytes());
            w[2..4].copy_from_slice(&st.tty.cols.to_le_bytes());
            st.put(i, arg, &w)
        }
        TIOCSWINSZ => {
            let mut w = [0u8; 8];
            if !st.copy_in(i, arg, &mut w) {
                return Err(EFAULT);
            }
            st.tty.rows = u16::from_le_bytes([w[0], w[1]]);
            st.tty.cols = u16::from_le_bytes([w[2], w[3]]);
            Ok(0)
        }
        FIONREAD => {
            let n = st.tty.available() as u32;
            st.put(i, arg, &n.to_le_bytes())
        }
        TIOCGSID => {
            let sid = st.procs[i].sid;
            st.put(i, arg, &sid.to_le_bytes())
        }
        TIOCSCTTY | TIOCNOTTY => Ok(0),
        _ => Err(EINVAL),
    }
}

/// Bytes joined into a fixed buffer.
trait ConcatInto {
    fn concat_into<const N: usize>(&self) -> Buf<N>;
}

struct Buf<const N: usize> {
    b: [u8; N],
    n: usize,
}

impl<const N: usize> Buf<N> {
    fn as_slice(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

impl ConcatInto for [&[u8]] {
    fn concat_into<const N: usize>(&self) -> Buf<N> {
        let mut out = Buf { b: [0; N], n: 0 };
        for part in self {
            let m = part.len().min(N - out.n);
            out.b[out.n..out.n + m].copy_from_slice(&part[..m]);
            out.n += m;
        }
        out
    }
}

/// Joins words with spaces, for messages.
struct Joined<'a>(&'a [&'a str]);

impl core::fmt::Display for Joined<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for (i, w) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(w)?;
        }
        Ok(())
    }
}

/// The applets `/bin` links to BusyBox.
const APPLETS: &[&str] = &[
    "sh", "ash", "echo", "cat", "ls", "wc", "seq", "mkdir", "rmdir", "rm", "touch", "true", "false", "uname", "awk",
    "sort", "head", "tail", "grep", "tr", "env", "pwd", "test", "[", "basename", "dirname", "cp", "mv", "ln", "printf",
    "expr", "cut", "uniq", "sed", "xargs", "find", "stat", "readlink", "sleep", "yes", "tee", "od", "stty",
    "kill",
];

/// What the test runs, and the exit status each must end with. They share
/// one file tree, so the last sees what the others left.
const RUNS: &[(&[&str], u32)] = &[
    (&["busybox", "echo", "hello from Linux"], 0),
    (&["busybox", "uname", "-sm"], 0),
    (&["busybox", "sh", "-c", "echo $((6 * 7)) from the shell; exit 3"], 3),
    // Floating point: the FPU's registers are the thread's own.
    (&["busybox", "awk", "BEGIN { printf \"pi is %.6f\\n\", atan2(0, -1) }"], 0),
    // Processes: fork, execve and wait4, the exit status passed on.
    (&["sh", "-c", "false; echo false said $?; /bin/true && echo true said $?"], 0),
    // A pipeline: two children joined by a pipe.
    (&["sh", "-c", "seq 1 1000 | wc -l"], 0),
    (&["sh", "-c", "seq 1 5 | sort -r | tr '\\n' ' '; echo"], 0),
    // Files: redirections, directories, renames, removal.
    (&["sh", "-c", "mkdir -p /tmp/notes && echo first line > /tmp/notes/a && echo second line >> /tmp/notes/a && cat /tmp/notes/a"], 0),
    (&["sh", "-c", "cd /tmp/notes && cp a b && mv b c && ls && wc -c < c && rm a && ls"], 0),
    // What the last run left is still there.
    (&["cat", "/tmp/notes/c"], 0),
    (&["sh", "-c", "cat /tmp/missing; echo cat said $?"], 0),
    // Signals: a handler (the shell's trap) run and returned from; a
    // sleeping child ended by one, its status 128 + 15; a writer ended by
    // SIGPIPE when its reader is gone; a timed sleep.
    (&["sh", "-c", "trap 'echo trapped USR1' USR1; kill -USR1 $$; echo after the trap"], 0),
    (&["sh", "-c", "sleep 30 & kill $!; wait $!; echo status after kill $?"], 0),
    (&["sh", "-c", "yes | head -n 3 | wc -l"], 0),
    (&["sh", "-c", "sleep 1 && echo slept"], 0),
];

/// Then a shell on the terminal, until it exits (the test types into it).
const SESSION: &[&str] = &["sh"];
const SESSION_ENV: &[&str] = &["PATH=/bin", "HOME=/home", "PS1=linux$ "];

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let failures = setup().map_or_else(
        |why| {
            say!("linux: could not start: {why}");
            1
        },
        |st| {
            let mut failures = 0;
            let runs = RUNS.iter().map(|&(argv, want)| (argv, want, false)).chain([(SESSION, 0, true)]);
            for (argv, want, interactive) in runs {
                let line = Joined(argv);
                let env: &[&str] = if interactive { SESSION_ENV } else { &["PATH=/bin", "HOME=/home"] };
                match run(st, argv, env, interactive) {
                    Ok(status) if status & 0x7f == 0 => {
                        let code = status >> 8;
                        say!("linux: {line} exited with status {code}");
                        failures += (code != want) as u64;
                    }
                    Ok(status) => {
                        say!("linux: {line} killed by signal {}", status & 0x7f);
                        failures += 1;
                    }
                    Err(why) => {
                        say!("linux: {line} could not run: {why}");
                        failures += 1;
                    }
                }
            }
            failures
        },
    );
    syscall(Syscall::Call, CONTROL, [OP_SHUTDOWN, failures, 0, 0]);
    superior_sys::park()
}

/// Cuts the memory into blocks, maps the state and the files' pool, and
/// makes the file tree.
fn setup() -> Result<&'static mut State, &'static str> {
    for b in 0..8 {
        sys(Syscall::Retype, UNTYPED, [ObjectType::Untyped as u64, BLOCK_BITS, BLOCKS + b, 0]).map_err(|_| "no memory")?;
    }
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Endpoint as u64, 0, EP, 0]).map_err(|_| "no endpoint")?;
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Notification as u64, 0, NTFN, 0]).map_err(|_| "no notification")?;
    sys(Syscall::CapMint, NTFN, [NTFN_UART, ALL, 1, 0]).map_err(|_| "no notification")?;
    sys(Syscall::CapMint, NTFN, [NTFN_TIMER, ALL, 2, 0]).map_err(|_| "no notification")?;
    sys(Syscall::NotificationBind, NTFN, [0; 4]).map_err(|_| "could not bind the notification")?;
    if tty::uart::init() != 0 {
        return Err("could not map the UART");
    }
    sys(Syscall::IrqSetNotification, tty::UART_IRQ, [NTFN_UART, 0, 0, 0]).map_err(|_| "no UART interrupt")?;
    for p in 0..STATE_PAGES + fs::POOL_PAGES as u64 {
        let slot = STATE_SLOTS + p;
        let va = if p < STATE_PAGES { STATE_VA + p * PAGE } else { POOL_VA + (slot - POOL_SLOTS) * PAGE };
        sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, slot, 0]).map_err(|_| "no memory for files")?;
        sys(Syscall::FrameMap, slot, [va, 1, 0, 0]).map_err(|_| "no room for files")?;
    }
    // SAFETY: STATE_PAGES zeroed pages are mapped at STATE_VA, for this
    // server's life; all zero is a valid empty State (every enum's zero
    // is its empty variant), and this is its only reference.
    let st = unsafe { &mut *(STATE_VA as *mut State) };
    st.interp = map_file(INTERP_FILE, INTERP_VA, PROGRAM_FILE - INTERP_FILE);
    st.program = map_file(PROGRAM_FILE, PROGRAM_VA, STATE_SLOTS - PROGRAM_FILE);
    st.next_pid = 1;
    // The restorer page, executable in every process.
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, TRAMPOLINE_SLOT, 0]).map_err(|_| "no memory")?;
    sys(Syscall::FrameMap, TRAMPOLINE_SLOT, [TRAMPOLINE_VA, 1, 0, 0]).map_err(|_| "no room")?;
    // SAFETY: the page was just mapped, writable, at TRAMPOLINE_VA.
    unsafe { core::ptr::copy_nonoverlapping(TRAMPOLINE_CODE.as_ptr(), TRAMPOLINE_VA as *mut u8, TRAMPOLINE_CODE.len()) };
    st.shared[0] = Shared { start: TRAMPOLINE, end: TRAMPOLINE + PAGE, ptr: TRAMPOLINE_VA, slot: TRAMPOLINE_SLOT, flags: MAP_EXEC };
    st.nshared = 1;
    let interp_path = Elf::parse(st.program).ok().and_then(|e| e.interpreter()).ok_or("the program is not dynamically linked")?;
    let (program, interp) = (st.program, st.interp);
    st.fs.init(POOL_VA, program, interp, interp_path, APPLETS);
    Ok(st)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
