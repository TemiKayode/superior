//! The Linux personality (Phase 3): runs unmodified Linux programs.
//!
//! Each Linux process is an address space of its own with one or more
//! threads (tasks) the kernel marks foreign (`ThreadRegisters`,
//! `REGS_FOREIGN`): a thread's `syscall` (x86-64) or `svc` (AArch64) does
//! not reach the kernel's system calls but comes here as a
//! [`FaultKind::ForeignSyscall`] fault, badged with the task's index. This
//! server reads the arguments, does what Linux would,
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
//! and write a process's memory in place. A shared library musl's linker
//! maps (`mmap` of a bundle file) is loaded the same way. Anonymous
//! mappings and the stack are made a page at a time as they are first
//! touched (a page fault, retried once the page is there).
//!
//! Processes: `fork` (or `clone` without `CLONE_VM`) copies the address
//! space's own pages and the descriptors, and the kernel copies the
//! thread's registers (`REGS_FORK_FROM`); `execve` replaces the address
//! space and thread under the same pid; `exit` leaves a zombie for
//! `wait4`. Threads: `clone` with `CLONE_THREAD` adds a task to the
//! process, its registers the caller's but for its stack (and thread
//! pointer); `futex` waits and wakes on a word of the process's memory;
//! `exit` ends a thread (clearing its `CLONE_CHILD_CLEARTID` word and
//! waking its joiner), `exit_group` the process. Files ([`fs`]): an
//! in-memory tree with `/bin` (BusyBox and a link per applet), the
//! interpreter, pigz, fptest, smptest and mmaptest (`user/linux-fptest`,
//! `user/linux-smptest`, `user/linux-mmaptest`, for the test) in
//! `/usr/bin` and zlib in `/lib`, `/tmp`,
//! `/dev/null`; pipes; the console. They last as long as this server,
//! but for what is made outside them, which is the filesystem server's
//! (this component's container there: the root, with `/home`), and so on
//! its disk.
//!
//! Slots: 0 the untyped memory everything is made from, cut into eight
//! blocks (slots 8 to 15): seven for processes, revoked when one exits or
//! execs, and one for this server's state and the files' pages (from
//! [`STATE_SLOTS`]). 5 more untyped memory, cut into spare blocks (from
//! [`SPARE_BLOCKS`]) lent to a process that outgrows its own. 1 the
//! manager's control endpoint, 2 the endpoint faults arrive on, 6 the
//! filesystem server (its buffer frame in [`remote::BUF`]). The
//! bundle's files' pages from 16: musl's, mmaptest's from 177, pigz's
//! from 180, smptest's
//! from 213, zlib's from 216, fptest's from 250, BusyBox's from 252 (`file` in the manifest;
//! a file's first slot is below 256). Process `i` owns the
//! slots from `PROC_SLOTS + i * PROC_SPAN`: its address space, then its
//! threads (each with a badged fault endpoint) and pages as made.
//!
//! Signals ([`signal`]): actions per process, masks per thread, `kill`
//! and `tkill`, handlers run on the thread's stack and returned from. The terminal ([`tty`]): the serial
//! console with Linux's line discipline, settings and foreground process
//! group, so `^C` interrupts a job and `^Z` stops one (job control:
//! [`signal`]); `poll` and `nanosleep` wait on it and on the timer.
//!
//! A process's threads run on any CPU, at once: `sched_getaffinity`
//! gives every CPU online, and `membarrier` has each CPU in the address
//! space pass a barrier (`REGS_BARRIER`).
//!
//! `munmap` gives a process's own pages back: unmapped, their frames are
//! kept and used (zeroed) for the next pages it makes, and `mmap` puts a
//! mapping in the lowest free space, so freed space is used again too.
//!
//! Sockets ([`sock`]): IPv4 TCP and UDP, each the network server's (slot
//! 7, its buffer frame in [`sock::BUF`]); a call waiting on one is tried
//! again every tick.
//!
//! Not yet: `vfork`'s kind of `clone` (memory shared without
//! `CLONE_THREAD`), fixed-address (non-PIE) executables.

#![no_std]
#![no_main]

mod fs;
mod remote;
mod signal;
mod sock;
mod tty;

use fs::{FileKind, Fs, Kind, MAX_FILES, MAX_IMAGES, MAX_PIPES, Open, PIPE_BUF, Pipe, ROOT};
use signal::{Action, Next, SA_RESTART, SIGALRM, SIGCHLD, SIGPIPE, SIGSEGV, SYSCALL_LEN, TRAMPOLINE, TRAMPOLINE_CODE};
use superior_objects::abi::{
    Error, FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType, REGS_COUNT, REGS_FOREIGN, REGS_FORK_FROM, REGS_FP_GET,
    REGS_BARRIER, REGS_FP_SET, REGS_FP_WORDS, REGS_GET, REGS_SET, REGS_SET_TLS, REGS_SYSCALL, REGS_SYSCALL_MORE, REGS_TLS, Syscall, TICK_HZ,
};
use superior_objects::elf::{Elf, Machine};
use superior_sys::{USER_BASE, print_line, syscall};

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

const UNTYPED: u64 = 0;
const CONTROL: u64 = 1;
const EP: u64 = 2;
/// More untyped memory: the spare blocks.
const UNTYPED_SPARE: u64 = 5;
/// Each process's block, then the state's and files' (`FS_BLOCK`).
const BLOCKS: u64 = 8;
const BLOCK_BITS: u64 = 20;
/// Blocks lent to processes that outgrow their own, one at a time.
const SPARE_BLOCKS: u64 = 1004;
const SPARES: usize = 4;
/// The notification this server's thread is bound to (so `Recv` also
/// returns when it is signalled), and two badged copies of it: the UART's
/// interrupt (bit 0) and the timer for sleepers (bit 1).
const NTFN: u64 = 1001;
const NTFN_UART: u64 = 1002;
const NTFN_TIMER: u64 = 1003;
/// The bundle's files (`file` in the manifest), their first slots: musl's
/// dynamic linker, BusyBox, pigz, zlib, and fptest, smptest and mmaptest
/// (if there: not on the second boot).
const INTERP_FILE: u64 = 16;
const MMAPTEST_FILE: u64 = 177;
const PIGZ_FILE: u64 = 180;
const SMPTEST_FILE: u64 = 213;
const LIBZ_FILE: u64 = 216;
const FPTEST_FILE: u64 = 250;
const PROGRAM_FILE: u64 = 252;
const STATE_SLOTS: u64 = 512;
const STATE_PAGES: u64 = 32;
const POOL_SLOTS: u64 = STATE_SLOTS + STATE_PAGES;
/// The signal restorer's page ([`signal::TRAMPOLINE`]).
const TRAMPOLINE_SLOT: u64 = 1000;
const PROC_SLOTS: u64 = 1024;
const PROC_SPAN: u64 = 1024;
/// A frame of a process's that `munmap` gave back ([`Proc::frames`]).
const FREE: u16 = u16::MAX;
const MAX_PROCS: usize = 7;
/// Threads, in all processes.
const MAX_TASKS: usize = 16;
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
const PIGZ_VA: u64 = USER_BASE + 0x1_5000_0000;
const LIBZ_VA: u64 = USER_BASE + 0x1_5800_0000;
const FPTEST_VA: u64 = USER_BASE + 0x1_5c00_0000;
const SMPTEST_VA: u64 = USER_BASE + 0x1_5d00_0000;
const MMAPTEST_VA: u64 = USER_BASE + 0x1_5e00_0000;

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
const EIO: u64 = 5;
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
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
const ETIMEDOUT: u64 = 110;
const CLONE_THREAD: u64 = 0x1_0000;
const CLONE_SETTLS: u64 = 0x8_0000;
const CLONE_PARENT_SETTID: u64 = 0x10_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
const CLONE_CHILD_SETTID: u64 = 0x100_0000;

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
    /// `exit` ends a thread; `exit_group` ([`Sys::Exit`]) the process.
    ExitThread,
    Gettid,
    SetTidAddress,
    Futex,
    SchedGetaffinity,
    Membarrier,
    Setitimer,
    /// Sockets ([`sock`]); `accept` is `accept4` with no flags.
    Socket,
    Bind,
    Listen,
    Accept,
    Connect,
    Sendto,
    Recvfrom,
    Shutdown,
    Getsockname,
    Getpeername,
    Setsockopt,
    Getsockopt,
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
        39 => Sys::Getpid,
        186 => Sys::Gettid,
        202 => Sys::Futex,
        204 => Sys::SchedGetaffinity,
        218 => Sys::SetTidAddress,
        324 => Sys::Membarrier,
        38 => Sys::Setitimer,
        41 => Sys::Socket,
        42 => Sys::Connect,
        43 => return (Sys::Accept, [a[0], a[1], a[2], 0, 0, 0]),
        288 => Sys::Accept,
        44 => Sys::Sendto,
        45 => Sys::Recvfrom,
        48 => Sys::Shutdown,
        49 => Sys::Bind,
        50 => Sys::Listen,
        51 => Sys::Getsockname,
        52 => Sys::Getpeername,
        54 => Sys::Setsockopt,
        55 => Sys::Getsockopt,
        40 => Sys::Sendfile,
        56 => Sys::Clone,
        57 | 58 => Sys::Fork,
        59 => Sys::Execve,
        60 => Sys::ExitThread,
        231 => Sys::Exit,
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
        93 => Sys::ExitThread,
        94 => Sys::Exit,
        96 => Sys::SetTidAddress,
        98 => Sys::Futex,
        123 => Sys::SchedGetaffinity,
        283 => Sys::Membarrier,
        103 => Sys::Setitimer,
        198 => Sys::Socket,
        200 => Sys::Bind,
        201 => Sys::Listen,
        202 => return (Sys::Accept, [a[0], a[1], a[2], 0, 0, 0]),
        242 => Sys::Accept,
        203 => Sys::Connect,
        204 => Sys::Getsockname,
        205 => Sys::Getpeername,
        206 => Sys::Sendto,
        207 => Sys::Recvfrom,
        208 => Sys::Setsockopt,
        209 => Sys::Getsockopt,
        210 => Sys::Shutdown,
        172 => Sys::Getpid,
        178 => Sys::Gettid,
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
        220 => return (Sys::Clone, [a[0], a[1], a[2], a[4], a[3], 0]),
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
    /// `futex`: until woken at `addr` or the tick `until`; `seq` orders
    /// the waiters.
    Futex { addr: u64, until: u64, seq: u64 },
    /// Its process stopped as its call was answered: the answer, given
    /// once it continues.
    Stopped { value: u64 },
    /// A socket call (`connect`, `accept`, `sendto`, `recvfrom`), made
    /// again until it can be answered.
    Net { call: Sys, a: [u64; 6] },
}

/// What a process's parent has yet to hear from `wait4`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Report {
    None = 0,
    /// It stopped (`WUNTRACED`).
    Stopped,
    /// It continued (`WCONTINUED`).
    Continued,
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
    /// Signals sent to the process and not yet taken (by any of its
    /// threads); what each signal does.
    pending: u64,
    actions: [Action; 64],
    /// Its wait status once a zombie.
    status: u32,
    /// Stopped (job control), by which signal, and what its parent has
    /// yet to hear.
    stopped: bool,
    stop_sig: u8,
    report: Report,
    /// Slots used of its span.
    cursor: u64,
    cwd: u16,
    /// Open-file description + 1, per descriptor.
    fds: [u8; MAX_FDS],
    cloexec: u32,
    brk_start: u64,
    brk: u64,
    /// Its own pages (mapped in the mirror too).
    present: [u64; CHILD_PAGES / 64],
    /// What each slot of its span holds that is one of its own pages'
    /// frames (the slot after is its copy for the mirror): the page's
    /// number + 1, or [`FREE`] for a frame `munmap` gave back, to be used
    /// again; 0 for any other slot.
    frames: [u16; PROC_SPAN as usize],
    /// Pages of anonymous mappings not yet touched: each becomes one of
    /// its own when first used (a page fault there, or a system call
    /// writing there).
    reserved: [u64; CHILD_PAGES / 64],
    /// The runs of bundle-file pages it maps (code, read-only data; the
    /// restorer page first).
    shared: [Shared; 12],
    nshared: usize,
    /// Libraries loaded by `mmap` ([`mmap_file`]): their span and inode.
    libs: [(u64, u64, u16); 4],
    nlibs: usize,
    /// `setitimer`'s real-time timer: the tick `SIGALRM` is due (0: none),
    /// and the ticks between one and the next (0: once).
    alarm: u64,
    alarm_every: u64,
}

/// A thread: Linux's task. Every process has one or more; they share its
/// address space, descriptors and signal actions.
struct Task {
    used: bool,
    /// Its process.
    proc: u8,
    tid: u32,
    /// Its thread's slot and its fault endpoint's (badged with the task's
    /// index + 1), in its process's span.
    thread: u64,
    fault: u64,
    blocked: Blocked,
    /// Where its waiting call was set aside, and where it resumes.
    place: u64,
    pc: u64,
    /// Signals sent to this thread alone (`tkill`); held back; the mask
    /// to restore after a `sigsuspend` (`suspended`).
    pending: u64,
    mask: u64,
    saved_mask: u64,
    suspended: bool,
    /// Suspended where it ran, its process stopped.
    frozen: bool,
    /// Where to write 0 and wake a futex when it ends
    /// (`CLONE_CHILD_CLEARTID`, `set_tid_address`).
    clear_tid: u64,
}

/// A file from the bundle: its bytes (mapped here) and its first page's
/// slot.
#[derive(Clone, Copy)]
struct Img {
    bytes: &'static [u8],
    slot: u64,
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
    tasks: [Task; MAX_TASKS],
    /// Process and thread ids come from one count, as Linux's do.
    next_pid: u32,
    /// Futex waits so far: the order waiters are woken in.
    futex_seq: u64,
    /// Which process (its index + 1) each spare block is lent to.
    spare_owner: [u8; SPARES],
    /// The restorer page's run, which every process maps.
    trampoline: Shared,
    images: [Img; MAX_IMAGES],
    /// Console output not yet printed: the line being written.
    line: [u8; 160],
    len: usize,
    /// The wait status of the run's first process, once it is gone.
    top_status: Option<u32>,
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
fn block_slot(i: usize) -> u64 {
    BLOCKS + i as u64
}

impl State {
    // ---- memory ------------------------------------------------------

    /// Makes an object of process `i`'s in `slot`: from its block, or a
    /// spare block it has been lent, or one lent now.
    fn retype(&mut self, i: usize, ty: ObjectType, size: u64, slot: u64) -> Result<(), u64> {
        let msg = [ty as u64, size, slot, 0];
        if sys(Syscall::Retype, block_slot(i), msg).is_ok() {
            return Ok(());
        }
        for k in 0..SPARES {
            if self.spare_owner[k] as usize == i + 1 && sys(Syscall::Retype, SPARE_BLOCKS + k as u64, msg).is_ok() {
                return Ok(());
            }
        }
        let k = self.spare_owner.iter().position(|&o| o == 0).ok_or(ENOMEM)?;
        self.spare_owner[k] = i as u8 + 1;
        sys(Syscall::Retype, SPARE_BLOCKS + k as u64, msg).map(drop).map_err(|_| ENOMEM)
    }

    fn is_present(&self, i: usize, va: u64) -> bool {
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].present[k / 64] & (1 << (k % 64)) != 0
    }

    /// Whether `va` is in process `i`'s window, in an anonymous mapping's
    /// page not yet made (see [`Proc::reserved`]).
    fn is_reserved(&self, i: usize, va: u64) -> bool {
        if !(CHILD..CHILD_END).contains(&va) {
            return false;
        }
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].reserved[k / 64] & (1 << (k % 64)) != 0
    }

    fn set_reserved(&mut self, i: usize, va: u64, on: bool) {
        let k = ((va - CHILD) / PAGE) as usize;
        let w = &mut self.procs[i].reserved[k / 64];
        if on { *w |= 1 << (k % 64) } else { *w &= !(1 << (k % 64)) }
    }

    /// Makes the reserved page at `va` (any address in it) one of process
    /// `i`'s own. Whether it was reserved and is now made.
    fn take_reserved(&mut self, i: usize, va: u64) -> bool {
        let page = va & !(PAGE - 1);
        if !self.is_reserved(i, page) || self.map_private(i, page).is_err() {
            return false;
        }
        self.set_reserved(i, page, false);
        true
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
        let p = &self.procs[i];
        p.shared[..p.nshared]
            .iter()
            .find(|s| (s.start..s.end).contains(&va))
            .map(|s| ((s.ptr + va - s.start) as *mut u8, false))
    }

    fn copy_in(&self, i: usize, va: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let at = va + done as u64;
            let n = (PAGE - at % PAGE).min((buf.len() - done) as u64) as usize;
            let Some((p, _)) = self.locate(i, at) else {
                // A page not yet made reads as zeros.
                if !self.is_reserved(i, at) {
                    return false;
                }
                buf[done..done + n].fill(0);
                done += n;
                continue;
            };
            // SAFETY: p..p+n lies in one mapped page.
            unsafe { core::ptr::copy_nonoverlapping(p, buf[done..].as_mut_ptr(), n) };
            done += n;
        }
        true
    }

    fn copy_out(&mut self, i: usize, va: u64, data: &[u8]) -> bool {
        let mut done = 0;
        while done < data.len() {
            let at = va + done as u64;
            if !self.is_present(i, at & !(PAGE - 1)) && CHILD <= at {
                self.take_reserved(i, at);
            }
            let Some((p, true)) = self.locate(i, at) else { return false };
            let n = (PAGE - at % PAGE).min((data.len() - done) as u64) as usize;
            // SAFETY: p..p+n lies in one of the process's own pages, mapped
            // writable here; the process waits on this server meanwhile.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), p, n) };
            done += n;
        }
        true
    }

    fn put(&mut self, i: usize, va: u64, data: &[u8]) -> Result<u64, u64> {
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
    /// (writable), mapped in the mirror too, unless it has one there: a
    /// frame `munmap` gave back if there is one (zeroed), else a new one.
    fn map_private(&mut self, i: usize, va: u64) -> Result<(), u64> {
        if !(CHILD..CHILD_END).contains(&va) {
            return Err(EFAULT);
        }
        if self.is_present(i, va) {
            return Ok(());
        }
        let k = ((va - CHILD) / PAGE) as usize;
        let mirror = va - CHILD + MIRROR + i as u64 * SPAN;
        let p = &mut self.procs[i];
        let n = if let Some(n) = p.frames.iter().position(|&f| f == FREE) {
            let slot = slot_base(i) + n as u64;
            sys(Syscall::FrameMap, slot + 1, [mirror, 1, 0, 0]).map_err(|_| ENOMEM)?;
            // SAFETY: the frame was just mapped here, writable, a whole
            // page at `mirror`; the process has it nowhere (munmap took
            // it away) and waits on this server meanwhile.
            unsafe { core::ptr::write_bytes(mirror as *mut u8, 0, PAGE as usize) };
            n
        } else {
            if p.cursor + 2 > PROC_SPAN {
                return Err(ENOMEM);
            }
            let slot = slot_base(i) + p.cursor;
            self.retype(i, ObjectType::Frame, 0, slot)?;
            let p = &mut self.procs[i];
            sys(Syscall::CapMint, slot, [slot + 1, ALL, 0, 0]).map_err(|_| ENOMEM)?;
            p.cursor += 2;
            sys(Syscall::FrameMap, slot + 1, [mirror, 1, 0, 0]).map_err(|_| ENOMEM)?;
            (slot - slot_base(i)) as usize
        };
        let slot = slot_base(i) + n as u64;
        let p = &mut self.procs[i];
        if sys(Syscall::FrameMapInto, slot, [va, MAP_WRITE, space_slot(i), 0]).is_err() {
            // Kept for another try.
            let _ = syscall(Syscall::FrameUnmap, slot + 1, [0; 4]);
            p.frames[n] = FREE;
            return Err(ENOMEM);
        }
        p.frames[n] = k as u16 + 1;
        p.present[k / 64] |= 1 << (k % 64);
        Ok(())
    }

    /// `munmap` of process `i`'s own page at `va`, if it has one there:
    /// unmapped from it and from the mirror, its frame kept to be used
    /// again ([`State::map_private`]).
    fn unmap_private(&mut self, i: usize, va: u64) {
        if !self.is_present(i, va) {
            return;
        }
        let k = ((va - CHILD) / PAGE) as usize;
        let p = &mut self.procs[i];
        let Some(n) = p.frames.iter().position(|&f| f == k as u16 + 1) else { return };
        let slot = slot_base(i) + n as u64;
        let _ = syscall(Syscall::FrameUnmap, slot, [0; 4]);
        let _ = syscall(Syscall::FrameUnmap, slot + 1, [0; 4]);
        p.frames[n] = FREE;
        p.present[k / 64] &= !(1 << (k % 64));
    }

    /// Whether process `i` has anything at page `va`: a page of its own, a
    /// reserved one, a bundle file's, or a library's span.
    fn taken(&self, i: usize, va: u64) -> bool {
        let p = &self.procs[i];
        self.is_present(i, va)
            || self.is_reserved(i, va)
            || p.shared[..p.nshared].iter().any(|s| (s.start..s.end).contains(&va))
            || p.libs[..p.nlibs].iter().any(|&(s, e, _)| (s..e).contains(&va))
    }

    /// Where `mmap` puts `len` bytes (page-aligned) in process `i`: the
    /// lowest place in the mapping area with nothing there, and a free
    /// page after it (a guard). So space `munmap` gave back is used again.
    fn place(&self, i: usize, len: u64) -> Result<u64, u64> {
        let limit = STACK_TOP - STACK_PAGES * PAGE;
        let mut at = MMAP_BASE;
        let mut va = MMAP_BASE;
        while va < limit {
            if self.taken(i, va) {
                at = va + PAGE;
            } else if va + PAGE - at >= len + PAGE {
                return Ok(at);
            }
            va += PAGE;
        }
        Err(ENOMEM)
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

    /// Maps a shared run in process `i`, but where it has its own page.
    fn map_run(&mut self, i: usize, s: Shared) -> Result<(), u64> {
        for va in (s.start..s.end).step_by(PAGE as usize) {
            if !self.is_present(i, va) {
                self.map_shared(i, va, s.slot + (va - s.start) / PAGE, s.flags)?;
            }
        }
        Ok(())
    }

    /// Maps every shared run of process `i`'s (a `fork`'s new copy).
    fn map_all_shared(&mut self, i: usize) -> Result<(), u64> {
        for k in 0..self.procs[i].nshared {
            let s = self.procs[i].shared[k];
            self.map_run(i, s)?;
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
            let p = &mut self.procs[i];
            if !p.shared[..p.nshared].iter().any(|s| s.start == run.start) {
                if p.nshared == p.shared.len() {
                    return Err("too many segments");
                }
                p.shared[p.nshared] = run;
                p.nshared += 1;
                self.map_run(i, run).map_err(|_| "out of memory")?;
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
        p.stopped = false;
        p.report = Report::None;
        p.cursor = 0;
        p.cwd = ROOT;
        p.fds = [0; MAX_FDS];
        p.cloexec = 0;
        p.present = [0; CHILD_PAGES / 64];
        p.reserved = [0; CHILD_PAGES / 64];
        p.frames = [0; PROC_SPAN as usize];
        (p.alarm, p.alarm_every) = (0, 0);
        (p.pgid, p.sid) = (pid, pid);
        p.pending = 0;
        p.actions = [Action { handler: 0, flags: 0, restorer: 0, mask: 0 }; 64];
        Some(i)
    }

    /// A new task in process `i` (its thread made later), with its
    /// own id, or `tid` if given.
    fn new_task(&mut self, i: usize, tid: Option<u32>) -> Option<usize> {
        let t = self.tasks.iter().position(|t| !t.used)?;
        let tid = tid.unwrap_or_else(|| {
            self.next_pid += 1;
            self.next_pid - 1
        });
        self.tasks[t] = Task {
            used: true,
            proc: i as u8,
            tid,
            thread: 0,
            fault: 0,
            blocked: Blocked::None,
            place: 0,
            pc: 0,
            pending: 0,
            mask: 0,
            saved_mask: 0,
            suspended: false,
            frozen: false,
            clear_tid: 0,
        };
        Some(t)
    }

    /// Makes process `i`'s address space, and task `t`'s thread and fault
    /// endpoint, at the start of the process's span.
    fn make_space(&mut self, i: usize, t: usize) -> Result<(), &'static str> {
        let b = slot_base(i);
        self.retype(i, ObjectType::AddressSpace, 17, b).map_err(|_| "no address space")?;
        self.procs[i].cursor = 1;
        self.make_thread(t).map_err(|_| "no thread")
    }

    /// Makes task `t`'s thread and its fault endpoint, in the next slots
    /// of its process's span.
    fn make_thread(&mut self, t: usize) -> Result<(), u64> {
        let i = self.tasks[t].proc as usize;
        let p = &mut self.procs[i];
        if p.cursor + 2 > PROC_SPAN {
            return Err(ENOMEM);
        }
        let s = slot_base(i) + p.cursor;
        p.cursor += 2;
        self.retype(i, ObjectType::Thread, 0, s).map_err(|_| EAGAIN)?;
        sys(Syscall::CapMint, EP, [s + 1, WRITE_RIGHT, t as u64 + 1, 0]).map_err(|_| EAGAIN)?;
        (self.tasks[t].thread, self.tasks[t].fault) = (s, s + 1);
        Ok(())
    }

    /// Readies task `t`'s thread: at `entry` with stack `top`, or with
    /// another task's registers (`fork`, `clone`). Not yet started.
    fn configure(&mut self, t: usize, entry: u64, top: u64, from: Option<usize>) -> Result<(), &'static str> {
        let (th, i) = (self.tasks[t].thread, self.tasks[t].proc as usize);
        let made = |r: Result<[u64; 4], u64>, what| r.map(drop).map_err(|_| what);
        made(sys(Syscall::ThreadSetVSpace, th, [space_slot(i), 0, 0, 0]), "set address space")?;
        made(sys(Syscall::ThreadConfigure, th, [entry, top, 0, 5]), "configure the thread")?;
        made(sys(Syscall::ThreadSetFaultHandler, th, [self.tasks[t].fault, 0, 0, 0]), "set fault handler")?;
        made(sys(Syscall::ThreadRegisters, th, [REGS_FOREIGN, 1, 0, 0]), "make the thread foreign")?;
        if let Some(f) = from {
            made(sys(Syscall::ThreadRegisters, th, [REGS_FORK_FROM, self.tasks[f].thread, 0, 0]), "copy registers")?;
        }
        Ok(())
    }

    /// Readies and starts task `t`'s thread (see [`State::configure`]).
    fn start(&mut self, t: usize, entry: u64, top: u64, from: Option<usize>) -> Result<(), &'static str> {
        self.configure(t, entry, top, from)?;
        sys(Syscall::ThreadResume, self.tasks[t].thread, [0; 4]).map(drop).map_err(|_| "start the thread")
    }

    /// The tasks of process `i`.
    fn tasks_of(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_TASKS).filter(move |&t| self.tasks[t].used && self.tasks[t].proc as usize == i)
    }

    /// Destroys process `i`'s address space, thread and pages.
    fn unmake_space(&mut self, i: usize) {
        for s in slot_base(i)..slot_base(i) + self.procs[i].cursor {
            let _ = syscall(Syscall::CapDelete, s, [0; 4]);
        }
        let _ = syscall(Syscall::CapRevoke, block_slot(i), [0; 4]);
        for k in 0..SPARES {
            if self.spare_owner[k] as usize == i + 1 {
                let _ = syscall(Syscall::CapRevoke, SPARE_BLOCKS + k as u64, [0; 4]);
                self.spare_owner[k] = 0;
            }
        }
        let p = &mut self.procs[i];
        p.cursor = 0;
        p.present = [0; CHILD_PAGES / 64];
        p.reserved = [0; CHILD_PAGES / 64];
        p.frames = [0; PROC_SPAN as usize];
    }

    /// Runs bundle file `image` (a program) as task `t`'s process, its
    /// address space made afresh, with `argv` and `envp`, and the
    /// interpreter the program names, if it names one.
    fn exec(&mut self, t: usize, image: usize, argv: &Strs, envp: &Strs, execfn: &[u8]) -> Result<(), &'static str> {
        let i = self.tasks[t].proc as usize;
        self.make_space(i, t)?;
        let tramp = self.trampoline;
        let p = &mut self.procs[i];
        (p.shared[0], p.nshared, p.nlibs) = (tramp, 1, 0);
        self.map_run(i, tramp).map_err(|_| "out of memory")?;
        let Img { bytes: program, slot } = self.images[image];
        let (entry, phdr, phnum, end) = self.load(i, program, slot, PROGRAM_BASE)?;
        let (start, interp_base) = match Elf::parse(program).ok().and_then(|e| e.interpreter()) {
            Some(path) => {
                let ino = self.fs.resolve(ROOT, path, true).map_err(|_| "its interpreter is missing")?;
                let k = self.fs.image(ino).ok_or("its interpreter is not a program")?;
                let Img { bytes, slot } = self.images[k];
                (self.load(i, bytes, slot, INTERP_BASE)?.0, INTERP_BASE)
            }
            None => (entry, 0),
        };
        for p in 1..=STACK_PAGES {
            self.set_reserved(i, STACK_TOP - p * PAGE, true);
        }
        let p = &mut self.procs[i];
        p.brk_start = end + PAGE;
        p.brk = p.brk_start;

        // The stack Linux gives a new program: strings at the top, then
        // the auxiliary vector, environment and argument pointers, argc.
        let mut top = STACK_TOP;
        let mut push_str = |st: &mut State, s: &[u8]| -> Result<u64, &'static str> {
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
            (7, interp_base),
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
        self.start(t, start, thread_top, None)
    }

    /// Process `i` ends with wait status `status`: its descriptors are
    /// closed, its address space destroyed, and it waits as a zombie for
    /// its parent (if it has one).
    fn exit(&mut self, i: usize, status: u32) {
        for fd in 0..MAX_FDS {
            self.close(i, fd);
        }
        self.unmake_space(i);
        for t in 0..MAX_TASKS {
            if self.tasks[t].used && self.tasks[t].proc as usize == i {
                self.tasks[t].used = false;
            }
        }
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
        p.stopped = false;
        p.status = status;
        if p.ppid == 0 {
            p.used = false;
            if self.top_status.is_none() && pid == self.first_pid() {
                self.top_status = Some(status);
            }
        }
    }

    /// Task `t` ends (`exit`): its thread is destroyed, and the word
    /// `clear_tid` names is cleared and its futex woken, for `pthread_join`.
    /// The last thread's end is its process's, with wait status `status`.
    fn exit_thread(&mut self, t: usize, status: u32) {
        let i = self.tasks[t].proc as usize;
        if self.tasks_of(i).count() == 1 {
            return self.exit(i, status);
        }
        let task = &mut self.tasks[t];
        task.used = false;
        let (clear, th, fault) = (task.clear_tid, task.thread, task.fault);
        let _ = syscall(Syscall::CapDelete, th, [0; 4]);
        let _ = syscall(Syscall::CapDelete, fault, [0; 4]);
        if clear != 0 && self.copy_out(i, clear, &0u32.to_le_bytes()) {
            futex_wake(self, i, clear, 1, None);
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
                FileKind::Socket => sock::close(o.pipe as usize),
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
        Kind::Image => 0o100755,
        Kind::Null => 0o20666,
        Kind::Tty => 0o20620,
        Kind::Free => 0,
    }
}

/// Does what Linux would for process `i`'s call.
fn answer(st: &mut State, t: usize, call: Sys, a: [u64; 6]) -> Out {
    use Out::Ret;
    let r = |v: Result<u64, u64>| Ret(v.unwrap_or_else(err));
    let i = st.tasks[t].proc as usize;
    match call {
        Sys::Exit => {
            st.exit(i, ((a[0] & 0xff) << 8) as u32);
            Out::Gone
        }
        Sys::ExitThread => {
            st.exit_thread(t, ((a[0] & 0xff) << 8) as u32);
            Out::Gone
        }
        Sys::Gettid => Ret(st.tasks[t].tid as u64),
        Sys::SetTidAddress => {
            st.tasks[t].clear_tid = a[0];
            Ret(st.tasks[t].tid as u64)
        }
        Sys::Futex => futex(st, t, a),
        // The process's other threads may be running on other CPUs: each
        // CPU in its address space passes a barrier (`REGS_BARRIER`), and
        // for the global kind every process's. The global and private
        // expedited kinds (and registering for the latter) are what it
        // offers.
        Sys::Socket
        | Sys::Bind
        | Sys::Listen
        | Sys::Accept
        | Sys::Connect
        | Sys::Sendto
        | Sys::Recvfrom
        | Sys::Shutdown
        | Sys::Getsockname
        | Sys::Getpeername
        | Sys::Setsockopt
        | Sys::Getsockopt => net_call(st, i, call, a),
        Sys::Setitimer => r(setitimer(st, i, a[0], a[1], a[2])),
        Sys::Membarrier => match a[0] {
            0 => Ret(0b1_1001),
            1 => {
                for p in 0..MAX_PROCS {
                    if let Some(u) = st.tasks.iter().position(|u| u.used && u.proc as usize == p) {
                        barrier(st.tasks[u].thread);
                    }
                }
                Ret(0)
            }
            8 => {
                barrier(st.tasks[t].thread);
                Ret(0)
            }
            16 => Ret(0),
            _ => Ret(err(EINVAL)),
        },
        Sys::SchedGetaffinity => {
            // Every CPU online: a process's threads run on any of them.
            if a[1] < 8 {
                return Ret(err(EINVAL));
            }
            let mask = (1u64 << superior_sys::cpus().min(64)).wrapping_sub(1);
            r(st.put(i, a[2], &mask.to_le_bytes()).map(|_| 8))
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
        Sys::Sigprocmask => r(st.sigprocmask(t, a[0], a[1], a[2])),
        Sys::Sigpending => {
            let pending = (st.procs[i].pending | st.tasks[t].pending) & st.tasks[t].mask;
            r(st.put(i, a[0], &pending.to_le_bytes()))
        }
        Sys::Sigsuspend => st.sigsuspend(t, Some(a[0])),
        Sys::Pause => st.sigsuspend(t, None),
        Sys::Sigreturn => match st.sigreturn(t) {
            Some((pc, value)) => Out::Resume { pc, value },
            None => {
                st.exit(i, SIGSEGV);
                Out::Gone
            }
        },
        Sys::Kill => r(st.kill(i, a[0] as i32 as i64, a[1])),
        Sys::Tkill if (a[0] as i32) <= 0 || a[1] > 64 => Ret(err(EINVAL)),
        Sys::Tkill => match st.tasks.iter().position(|k| k.used && k.tid as u64 == a[0]) {
            Some(k) => {
                st.post_task(k, a[1] as u32);
                Ret(0)
            }
            None => Ret(err(ESRCH)),
        },
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
        Sys::Fork => r(fork(st, t)),
        Sys::Clone if a[0] & CLONE_THREAD != 0 && a[0] & CLONE_VM != 0 => r(new_thread(st, t, a)),
        // A process sharing its parent's memory (vfork's kind): not yet.
        Sys::Clone if a[0] & (CLONE_VM | CLONE_THREAD) != 0 => Ret(err(ENOSYS)),
        Sys::Clone => r(fork(st, t)),
        Sys::Execve => match execve(st, t, a[0], a[1], a[2]) {
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
                path_op(st, i, a[1], a[2], |fs, dir, name| fs.symlink(dir, name, &target[..n]).map(|_| 0))
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
        Sys::Munmap => r(munmap(st, i, a[0], a[1])),
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
            let th = st.tasks[t].thread;
            match a[0] {
                ARCH_SET_FS => r(sys(Syscall::ThreadRegisters, th, [REGS_SET_TLS, a[1], 0, 0]).map(|_| 0).map_err(|_| EINVAL)),
                ARCH_GET_FS => {
                    let fs = sys(Syscall::ThreadRegisters, th, [REGS_TLS, 0, 0, 0]).map_or(0, |m| m[0]);
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
    if writing && kind == Kind::Image {
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
        FileKind::Socket => stat_bytes(0o140777, 0, 0),
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
    while let Some(e) = st.fs.entry(o.ino, pos) {
        let (next, ino, name) = (e.next, e.ino, e.name());
        let reclen = (19 + name.len() as u64 + 1).next_multiple_of(8);
        if out + reclen > count {
            if out == 0 {
                return Err(EINVAL);
            }
            break;
        }
        let mut rec = [0u8; 88];
        rec[..8].copy_from_slice(&ino.to_le_bytes());
        rec[8..16].copy_from_slice(&next.to_le_bytes());
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = match e.kind {
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
        // A reader not in the terminal's foreground group: its group is
        // stopped (SIGTTIN), and it reads once continued in the
        // foreground; or, if it ignores or blocks SIGTTIN, EIO.
        FileKind::Tty if st.procs[i].pgid != st.tty.fg => {
            if !st.takes(i, signal::SIGTTIN) {
                return Out::Ret(err(EIO));
            }
            let g = st.procs[i].pgid;
            st.post_group(g, signal::SIGTTIN);
            return Out::Block(Blocked::Read { fd, buf, len });
        }
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
        FileKind::Socket => match sock::recv(o.pipe as usize, &mut tmp[..want], false) {
            Ok((n, _)) => n,
            Err(sock::EAGAIN) if o.flags & O_NONBLOCK == 0 => return Out::Block(Blocked::Read { fd, buf, len }),
            Err(e) => return Out::Ret(err(e)),
        },
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
        FileKind::Console | FileKind::Tty | FileKind::Node | FileKind::Socket => len.min(tmp.len() as u64) as usize,
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
        FileKind::Socket => match sock::send(o.pipe as usize, &tmp[..n], 0) {
            Ok(w) => w as u64,
            Err(sock::EAGAIN) if o.flags & O_NONBLOCK == 0 => return Out::Block(Blocked::Write { fd, buf, len }),
            Err(EPIPE) => {
                st.post(i, SIGPIPE);
                err(EPIPE)
            }
            Err(e) => err(e),
        },
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
    if len == 0 {
        return Err(EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        return mmap_file(st, i, addr, len, flags & MAP_FIXED != 0, a[4], a[5]);
    }
    let at = if flags & MAP_FIXED != 0 { addr } else { st.place(i, len)? };
    if at % PAGE != 0 || at < CHILD || at + len > STACK_TOP - STACK_PAGES * PAGE {
        return Err(ENOMEM);
    }
    // Pages made as they are first used; any already there zeroed.
    for p in (at..at + len).step_by(PAGE as usize) {
        if st.is_present(i, p) {
            st.copy_out(i, p, &[0; PAGE as usize]);
        } else {
            st.set_reserved(i, p, true);
        }
    }
    Ok(at)
}

/// `munmap`: process `i`'s own pages in [`addr`, `addr + len`) are
/// unmapped and their frames kept to be used again, and reserved ones
/// dropped; a later access there is a fault. Pages of bundle files (code,
/// read-only data) stay as they are.
fn munmap(st: &mut State, i: usize, addr: u64, len: u64) -> Result<u64, u64> {
    if addr % PAGE != 0 || len == 0 {
        return Err(EINVAL);
    }
    let end = addr.checked_add(len.next_multiple_of(PAGE)).ok_or(EINVAL)?;
    for va in (addr.max(CHILD)..end.min(CHILD_END)).step_by(PAGE as usize) {
        st.set_reserved(i, va, false);
        st.unmap_private(i, va);
    }
    Ok(0)
}

/// `mmap` of a file (private: what the process writes stays its own).
/// A bundle file that is an ELF image, mapped from its start where the
/// process chooses not, is a library musl's dynamic linker is loading: it
/// is loaded as the program loader loads one (code and read-only data the
/// file's own pages, shared; data a copy), and the linker's mappings of
/// its segments into that span after are already there. Anything else is
/// a copy of the file's bytes in pages of the process's own.
fn mmap_file(st: &mut State, i: usize, addr: u64, len: u64, fixed: bool, fd: u64, off: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    if o.kind != FileKind::Node || st.fs.kind(o.ino) == Kind::Dir {
        return Err(ENODEV);
    }
    if off % PAGE != 0 {
        return Err(EINVAL);
    }
    let p = &st.procs[i];
    if fixed && p.libs[..p.nlibs].iter().any(|&(s, e, ino)| ino == o.ino && s <= addr && addr + len <= e) {
        return Ok(addr);
    }
    let reserve = |st: &mut State| st.place(i, len);
    if let (Some(k), false, 0) = (st.fs.image(o.ino), fixed, off) {
        let Img { bytes, slot } = st.images[k];
        if let Ok(elf) = Elf::parse(bytes) {
            let lowest = elf.segments().flatten().map(|s| s.vaddr & !(PAGE - 1)).min().unwrap_or(0);
            let at = reserve(st)?;
            st.load(i, bytes, slot, at - lowest).map_err(|_| ENOMEM)?;
            let p = &mut st.procs[i];
            if p.nlibs < p.libs.len() {
                p.libs[p.nlibs] = (at, at + len, o.ino);
                p.nlibs += 1;
            }
            return Ok(at);
        }
    }
    let at = if fixed { addr } else { reserve(st)? };
    if at % PAGE != 0 || at < CHILD || at + len > STACK_TOP - STACK_PAGES * PAGE {
        return Err(ENOMEM);
    }
    let mut buf = [0u8; PAGE as usize];
    for page in (at..at + len).step_by(PAGE as usize) {
        st.map_private(i, page)?;
        buf.fill(0);
        st.fs.read(o.ino, off + (page - at), &mut buf);
        st.copy_out(i, page, &buf);
    }
    Ok(at)
}

/// `fork`: a new process with a copy of task `t`'s process's own pages,
/// its descriptors and directory, and one thread, with `t`'s registers (0
/// in the result).
fn fork(st: &mut State, t: usize) -> Result<u64, u64> {
    let i = st.tasks[t].proc as usize;
    let c = st.new_proc(st.procs[i].pid).ok_or(EAGAIN)?;
    let Some(ct) = st.new_task(c, Some(st.procs[c].pid)) else {
        st.procs[c].used = false;
        return Err(EAGAIN);
    };
    let fail = |st: &mut State, e| {
        st.unmake_space(c);
        st.procs[c].used = false;
        st.tasks[ct].used = false;
        Err(e)
    };
    if st.make_space(c, ct).is_err() {
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
    st.procs[c].reserved = st.procs[i].reserved;
    (st.procs[c].shared, st.procs[c].nshared) = (st.procs[i].shared, st.procs[i].nshared);
    (st.procs[c].libs, st.procs[c].nlibs) = (st.procs[i].libs, st.procs[i].nlibs);
    if st.map_all_shared(c).is_err() {
        return fail(st, ENOMEM);
    }
    let (fds, cloexec, cwd) = (st.procs[i].fds, st.procs[i].cloexec, st.procs[i].cwd);
    let (b0, b1) = (st.procs[i].brk_start, st.procs[i].brk);
    for &f in fds.iter().filter(|&&f| f != 0) {
        st.files[f as usize - 1].refs += 1;
    }
    let (pgid, sid, actions) = (st.procs[i].pgid, st.procs[i].sid, st.procs[i].actions);
    let p = &mut st.procs[c];
    (p.fds, p.cloexec, p.cwd, p.brk_start, p.brk) = (fds, cloexec, cwd, b0, b1);
    (p.pgid, p.sid, p.actions) = (pgid, sid, actions);
    st.tasks[ct].mask = st.tasks[t].mask;
    if st.start(ct, CHILD + PAGE, CHILD + 2 * PAGE, Some(t)).is_err() {
        for fd in 0..MAX_FDS {
            st.close(c, fd);
        }
        return fail(st, ENOMEM);
    }
    Ok(st.procs[c].pid as u64)
}

/// `execve`: the program `path` names replaces task `t`'s process's; its
/// other threads end, and `t` goes on as the process's one thread.
fn execve(st: &mut State, t: usize, path: u64, argv: u64, envp: u64) -> Result<(), u64> {
    let i = st.tasks[t].proc as usize;
    let mut name = [0u8; 256];
    let n = st.cstr(i, path, &mut name)?;
    let ino = st.fs.resolve(st.procs[i].cwd, &name[..n], true)?;
    let image = match (st.fs.image(ino), st.fs.kind(ino)) {
        (Some(k), _) => k,
        (None, Kind::Dir) => return Err(EACCES),
        _ => return Err(ENOEXEC),
    };
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
    for k in 0..MAX_TASKS {
        if k != t && st.tasks[k].used && st.tasks[k].proc as usize == i {
            st.tasks[k].used = false;
        }
    }
    st.tasks[t].tid = st.procs[i].pid;
    let cloexec = st.procs[i].cloexec;
    for fd in 0..MAX_FDS {
        if cloexec & 1 << fd != 0 {
            st.close(i, fd);
        }
    }
    st.reset_handlers(i);
    if let Err(why) = st.exec(t, image, &args, &env, &name[..n]) {
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
    // An ended child; or, if asked, one that stopped or continued since
    // its parent last heard (wait status 0x7f with the signal above it,
    // or 0xffff).
    let told = |p: &Proc| {
        p.zombie
            || options & WUNTRACED != 0 && p.stopped && p.report == Report::Stopped
            || options & WCONTINUED != 0 && p.report == Report::Continued
    };
    let Some(c) = st.procs.iter().position(|p| mine(p) && told(p)) else {
        if options & WNOHANG != 0 {
            return Out::Ret(0);
        }
        return Out::Block(Blocked::Wait { pid, status, options });
    };
    let p = &st.procs[c];
    let (cpid, cstatus) = match (p.zombie, p.report) {
        (true, _) => (p.pid, p.status),
        (false, Report::Stopped) => (p.pid, (p.stop_sig as u32) << 8 | 0x7f),
        _ => (p.pid, 0xffff),
    };
    if status != 0 && st.put(i, status, &cstatus.to_le_bytes()).is_err() {
        return Out::Ret(err(EFAULT));
    }
    if st.procs[c].zombie {
        st.procs[c].used = false;
    } else {
        st.procs[c].report = Report::None;
    }
    Out::Ret(cpid as u64)
}

/// Answers task `t`'s call with `value`, resuming at `pc` (the call
/// just received if `place` is `None`, else the one set aside there),
/// unless a signal it must take comes first: then its process ends, or it
/// starts in the handler with that answer saved for after.
fn finish(st: &mut State, t: usize, pc: u64, value: u64, place: Option<u64>) {
    if !st.tasks[t].used {
        return;
    }
    let i = st.tasks[t].proc as usize;
    // Its process stopped (by a signal it takes now, or another thread
    // took): the answer is kept, and given once it continues.
    let hold = |st: &mut State, t: usize| {
        let place = place.unwrap_or_else(|| syscall(Syscall::ReplySave, 0, [0; 4]).msg[0]);
        let task = &mut st.tasks[t];
        (task.place, task.pc, task.blocked) = (place, pc, Blocked::Stopped { value });
    };
    if st.procs[i].stopped {
        return hold(st, t);
    }
    let (pc, value) = match st.next_signal(t) {
        Next::None => (pc, value),
        Next::Stop(sig) => {
            st.stop(i, sig, Some(t));
            return hold(st, t);
        }
        Next::Kill(sig) => {
            st.exit(i, sig);
            return;
        }
        Next::Handle(sig) => match st.enter_handler(t, sig, pc, Some(value)) {
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
/// acts on signals: a thread waiting in a call is interrupted for a
/// handler, and any process a signal ends is ended. Until nothing moves.
fn wake(st: &mut State) {
    // Timers due: SIGALRM.
    let now = superior_sys::ticks();
    for i in 0..MAX_PROCS {
        let p = &mut st.procs[i];
        if p.used && !p.zombie && p.alarm != 0 && now >= p.alarm {
            p.alarm = if p.alarm_every != 0 { now + p.alarm_every } else { 0 };
            st.post(i, SIGALRM);
        }
    }
    loop {
        let mut moved = false;
        for t in 0..MAX_TASKS {
            if !st.tasks[t].used {
                continue;
            }
            let i = st.tasks[t].proc as usize;
            // Stopped: nothing goes on but SIGKILL.
            if st.procs[i].stopped {
                if st.killed_while_stopped(i) {
                    st.exit(i, signal::SIGKILL);
                    moved = true;
                }
                continue;
            }
            let blocked = st.tasks[t].blocked;
            let now = superior_sys::ticks();
            let out = match blocked {
                Blocked::None => {
                    // Running: only a signal that ends or stops it acts
                    // now.
                    match st.next_signal(t) {
                        Next::Kill(sig) => {
                            st.exit(i, sig);
                            moved = true;
                        }
                        Next::Stop(sig) => {
                            st.stop(i, sig, None);
                            moved = true;
                        }
                        _ => {}
                    }
                    continue;
                }
                // Continued: the answer it was held with.
                Blocked::Stopped { value } => Out::Ret(value),
                Blocked::Read { fd, buf, len } => read(st, i, fd, buf, len),
                Blocked::Write { fd, buf, len } => write(st, i, fd, buf, len),
                Blocked::Writev { fd, iov, cnt } => writev(st, i, fd, iov, cnt),
                Blocked::Wait { pid, status, options } => wait4(st, i, pid, status, options),
                Blocked::Sleep { until } if now >= until => Out::Ret(0),
                Blocked::Poll { fds, n, until } => poll(st, i, fds, n, until),
                Blocked::Net { call, a } => net_call(st, i, call, a),
                Blocked::Futex { until, .. } if now >= until => Out::Ret(err(ETIMEDOUT)),
                Blocked::Sleep { .. } | Blocked::Suspend | Blocked::Futex { .. } => Out::Block(blocked),
            };
            if !st.tasks[t].used {
                moved = true;
                continue;
            }
            let (place, pc) = (st.tasks[t].place, st.tasks[t].pc);
            if let Out::Ret(v) = out {
                st.tasks[t].blocked = Blocked::None;
                finish(st, t, pc, v, Some(place));
                moved = true;
                continue;
            }
            match st.next_signal(t) {
                Next::None => {}
                Next::Kill(sig) => {
                    st.exit(i, sig);
                    moved = true;
                }
                // Stopped where it waits; the call goes on once it
                // continues.
                Next::Stop(sig) => {
                    st.stop(i, sig, None);
                    moved = true;
                }
                Next::Handle(sig) => {
                    // Interrupted: EINTR after the handler, or with
                    // SA_RESTART the call made again.
                    let restart = st.procs[i].actions[sig as usize - 1].flags & SA_RESTART != 0
                        && matches!(blocked, Blocked::Read { .. } | Blocked::Write { .. } | Blocked::Writev { .. } | Blocked::Wait { .. });
                    st.tasks[t].blocked = Blocked::None;
                    let entered = if restart {
                        st.enter_handler(t, sig, pc - SYSCALL_LEN, None)
                    } else {
                        st.enter_handler(t, sig, pc, Some(err(EINTR)))
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
        .tasks
        .iter()
        .filter(|t| t.used)
        .filter_map(|t| match t.blocked {
            Blocked::Sleep { until } => Some(until),
            Blocked::Poll { until, .. } | Blocked::Futex { until, .. } if until != u64::MAX => Some(until),
            _ => None,
        })
        .chain(st.procs.iter().filter(|p| p.used && !p.zombie && p.alarm != 0).map(|p| p.alarm))
        .min();
    let ticks = next.map_or(0, |until| until.saturating_sub(superior_sys::ticks()).max(1));
    // A call waiting on a socket: tried again every tick (this server
    // waits on its one notification, not the sockets').
    let on_socket = sock::any_open()
        && st.tasks.iter().any(|t| {
            t.used
                && matches!(
                    t.blocked,
                    Blocked::Read { .. } | Blocked::Write { .. } | Blocked::Writev { .. } | Blocked::Poll { .. } | Blocked::Net { .. }
                )
        });
    let ticks = if on_socket { 1 } else { ticks };
    syscall(Syscall::TimerSignal, NTFN_TIMER, [ticks, 0, 0, 0]);
}

/// A memory barrier on every CPU running in thread `th`'s address space.
fn barrier(th: u64) {
    let _ = sys(Syscall::ThreadRegisters, th, [REGS_BARRIER, 0, 0, 0]);
}

/// `clone` for a thread: a new task in task `t`'s process, starting where
/// `t` returns, with 0 as its result, the stack `a[1]` and, as `a[0]`'s
/// flags say, its thread pointer (`a[4]`), its id written for the parent
/// (`a[2]`) or the child (`a[3]`), and the child's id cleared at `a[3]`
/// (and a futex there woken) when it ends. Its id.
fn new_thread(st: &mut State, t: usize, a: [u64; 6]) -> Result<u64, u64> {
    let [flags, stack, ptid, ctid, tls, _] = a;
    let i = st.tasks[t].proc as usize;
    let c = st.new_task(i, None).ok_or(EAGAIN)?;
    let fail = |st: &mut State, e| {
        st.tasks[c].used = false;
        Err(e)
    };
    if st.make_thread(c).is_err() || st.configure(c, CHILD + PAGE, CHILD + 2 * PAGE, Some(t)).is_err() {
        return fail(st, EAGAIN);
    }
    let th = st.tasks[c].thread;
    // Its stack, and the pc the registers' copy already has.
    let sp = signal::SP as u64;
    let Ok(r) = sys(Syscall::ThreadRegisters, th, [REGS_GET, sp, 0, 0]) else { return fail(st, EAGAIN) };
    if sys(Syscall::ThreadRegisters, th, [REGS_SET, sp, stack, r[1]]).is_err() {
        return fail(st, EINVAL);
    }
    if flags & CLONE_SETTLS != 0 && sys(Syscall::ThreadRegisters, th, [REGS_SET_TLS, tls, 0, 0]).is_err() {
        return fail(st, EINVAL);
    }
    let tid = st.tasks[c].tid;
    if flags & CLONE_PARENT_SETTID != 0 && !st.copy_out(i, ptid, &tid.to_le_bytes()) {
        return fail(st, EFAULT);
    }
    if flags & CLONE_CHILD_SETTID != 0 && !st.copy_out(i, ctid, &tid.to_le_bytes()) {
        return fail(st, EFAULT);
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        st.tasks[c].clear_tid = ctid;
    }
    st.tasks[c].mask = st.tasks[t].mask;
    if sys(Syscall::ThreadResume, th, [0; 4]).is_err() {
        return fail(st, EAGAIN);
    }
    say!("linux: pid {} started thread {tid}", st.procs[i].pid);
    Ok(tid as u64)
}

/// `futex`: wait while the word at `a[0]` holds `a[2]` (`FUTEX_WAIT`,
/// with a relative timeout; `FUTEX_WAIT_BITSET`, absolute), wake up to
/// `a[2]` waiters (`FUTEX_WAKE`, `FUTEX_WAKE_BITSET`), or wake some and
/// move up to `a[3]` more to the word at `a[4]` (`FUTEX_REQUEUE`;
/// `FUTEX_CMP_REQUEUE` first checks the word holds `a[5]`). Waiters are
/// the process's threads, oldest first; the bitsets are not looked at.
fn futex(st: &mut State, t: usize, a: [u64; 6]) -> Out {
    let i = st.tasks[t].proc as usize;
    let (addr, op, val) = (a[0], a[1] & 0x7f, a[2] as u32);
    let word = |st: &State, at: u64| {
        let mut b = [0u8; 4];
        st.copy_in(i, at, &mut b).then(|| u32::from_le_bytes(b))
    };
    match op {
        0 | 9 => {
            match word(st, addr) {
                None => return Out::Ret(err(EFAULT)),
                Some(v) if v != val => return Out::Ret(err(EAGAIN)),
                _ => {}
            }
            let until = if a[3] == 0 {
                u64::MAX
            } else {
                let (Some(sec), Some(ns)) = (st.word(i, a[3]), st.word(i, a[3] + 8)) else { return Out::Ret(err(EFAULT)) };
                let ticks = sec.saturating_mul(TICK_HZ).saturating_add((ns * TICK_HZ).div_ceil(1_000_000_000));
                if op == 0 { superior_sys::ticks().saturating_add(ticks) } else { ticks }
            };
            st.futex_seq += 1;
            Out::Block(Blocked::Futex { addr, until, seq: st.futex_seq })
        }
        1 | 10 => Out::Ret(futex_wake(st, i, addr, val as u64, None)),
        3 | 4 => {
            if op == 4 && word(st, addr) != Some(a[5] as u32) {
                return Out::Ret(err(EAGAIN));
            }
            let woke = futex_wake(st, i, addr, val as u64, None);
            let moved = futex_wake(st, i, addr, a[3] as u32 as u64, Some(a[4]));
            Out::Ret(woke + moved)
        }
        _ => Out::Ret(err(ENOSYS)),
    }
}

/// Wakes up to `n` of process `i`'s threads waiting on the futex at
/// `addr`, oldest first, answering their waits with 0; or, `to` given,
/// moves them to wait on the futex there instead. How many.
fn futex_wake(st: &mut State, i: usize, addr: u64, n: u64, to: Option<u64>) -> u64 {
    let mut done = 0;
    while done < n {
        let next = (0..MAX_TASKS)
            .filter(|&k| st.tasks[k].used && st.tasks[k].proc as usize == i)
            .filter_map(|k| match st.tasks[k].blocked {
                Blocked::Futex { addr: at, seq, .. } if at == addr => Some((seq, k)),
                _ => None,
            })
            .min();
        let Some((_, k)) = next else { break };
        match to {
            Some(new) => {
                if let Blocked::Futex { until, seq, .. } = st.tasks[k].blocked {
                    st.tasks[k].blocked = Blocked::Futex { addr: new, until, seq };
                }
            }
            None => {
                st.tasks[k].blocked = Blocked::None;
                let (pc, place) = (st.tasks[k].pc, st.tasks[k].place);
                finish(st, k, pc, 0, Some(place));
            }
        }
        done += 1;
    }
    done
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
    let Some(t) = st.new_task(i, Some(pid)) else {
        st.procs[i].used = false;
        return Err("no thread slot");
    };
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
    let image = st.fs.resolve(ROOT, execfn.as_slice(), true).ok().and_then(|ino| st.fs.image(ino));
    let started = match image {
        Some(k) => st.exec(t, k, &args, &envs, execfn.as_slice()),
        None => Err("no such program"),
    };
    if let Err(why) = started {
        st.exit(i, 127 << 8);
        return Err(why);
    }
    let program = st.images[image.unwrap_or(0)].bytes;
    let interp = Elf::parse(program).ok().and_then(|e| e.interpreter()).unwrap_or(b"(none)");
    let interp = core::str::from_utf8(interp).unwrap_or("?");
    say!("linux: running {} (pid {pid}, interpreter {interp})", Joined(argv));
    while st.procs.iter().any(|p| p.used && !p.zombie) {
        // Remote inodes nothing needs go when inodes run short.
        if st.fs.free_inodes() < 32 {
            let (fs, files, procs) = (&mut st.fs, &st.files, &st.procs);
            fs.evict(|ino| {
                files.iter().any(|f| f.kind == FileKind::Node && f.ino == ino)
                    || procs.iter().any(|p| p.used && !p.zombie && p.cwd == ino)
            });
        }
        let r = syscall(Syscall::Recv, EP, [0; 4]);
        if r.status == Error::Notified as u64 {
            if r.badge & 1 != 0 {
                uart_input(st);
            }
            wake(st);
            continue;
        }
        let [kind, nr, pc, _] = r.msg;
        let Some(t) = (r.badge as usize).checked_sub(1).filter(|&t| t < MAX_TASKS && st.tasks[t].used) else {
            continue;
        };
        let i = st.tasks[t].proc as usize;
        // A first touch of an anonymous mapping's page: made, and the
        // access tried again; or another thread made it first.
        let page_fault = r.status == 0 && FaultKind::from_u64(kind) == Some(FaultKind::PageFault);
        let made = |st: &State| (CHILD..CHILD_END).contains(&nr) && st.is_present(i, nr & !(PAGE - 1));
        if page_fault && (made(st) || st.take_reserved(i, nr)) {
            syscall(Syscall::Reply, 0, [FaultReply::Retry as u64, 0, 0, 0]);
            continue;
        }
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
        let th = st.tasks[t].thread;
        let x = sys(Syscall::ThreadRegisters, th, [REGS_SYSCALL, 0, 0, 0]).unwrap_or([0; 4]);
        let y = sys(Syscall::ThreadRegisters, th, [REGS_SYSCALL_MORE, 0, 0, 0]).unwrap_or([0; 4]);
        let (call, args) = decode(nr, [x[1], x[2], x[3], y[0], y[1], y[2]]);
        match answer(st, t, call, args) {
            // The task may be gone (its process killed meanwhile).
            Out::Ret(v) => finish(st, t, pc, v, None),
            Out::Resume { pc, value } => finish(st, t, pc, value, None),
            Out::Block(_) if !st.tasks[t].used => {}
            Out::Block(b) => {
                let saved = syscall(Syscall::ReplySave, 0, [0; 4]);
                let task = &mut st.tasks[t];
                task.blocked = b;
                task.place = saved.msg[0];
                task.pc = pc;
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
                    FileKind::Socket => {
                        let k = o.pipe as usize;
                        (if sock::readable(k) { POLLIN } else { 0 })
                            | (if sock::writable(k) { POLLOUT } else { 0 })
                            | if sock::failed(k) { POLLERR } else { 0 }
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

/// Descriptor `fd`'s socket, and its file's flags.
fn sock_of(st: &State, i: usize, fd: u64) -> Result<(usize, u32), u64> {
    let o = st.files[st.file(i, fd).ok_or(EBADF)?];
    if o.kind != FileKind::Socket {
        return Err(sock::NOT_A_SOCKET);
    }
    Ok((o.pipe as usize, o.flags))
}

/// The address word ([`superior_objects::interfaces::net::addr`]) of the
/// `sockaddr_in` at `addr`.
fn sockaddr(st: &State, i: usize, addr: u64, len: u64) -> Result<u64, u64> {
    const EAFNOSUPPORT: u64 = 97;
    let mut b = [0u8; 16];
    if len < 16 {
        return Err(EINVAL);
    }
    if !st.copy_in(i, addr, &mut b) {
        return Err(EFAULT);
    }
    if u16::from_le_bytes([b[0], b[1]]) as u64 != sock::AF_INET {
        return Err(EAFNOSUPPORT);
    }
    let ip = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as u64;
    Ok(ip << 16 | u16::from_be_bytes([b[2], b[3]]) as u64)
}

/// Address word `word` as a `sockaddr_in` at `addr` (if any), cut to the
/// length at `lenp`, which then says 16.
fn put_sockaddr(st: &mut State, i: usize, word: u64, addr: u64, lenp: u64) -> Result<(), u64> {
    if addr == 0 {
        return Ok(());
    }
    let mut l = [0u8; 4];
    if !st.copy_in(i, lenp, &mut l) {
        return Err(EFAULT);
    }
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&(sock::AF_INET as u16).to_le_bytes());
    b[2..4].copy_from_slice(&(word as u16).to_be_bytes());
    b[4..8].copy_from_slice(&((word >> 16) as u32).to_be_bytes());
    let n = (u32::from_le_bytes(l) as usize).min(16);
    st.put(i, addr, &b[..n])?;
    st.put(i, lenp, &16u32.to_le_bytes()).map(|_| ())
}

/// A new socket's descriptor in process `i`.
fn new_socket(st: &mut State, i: usize, k: usize, ty: u64) -> Result<u64, u64> {
    let flags = O_RDWR | ty as u32 & O_NONBLOCK;
    let Some(f) = st.new_file(FileKind::Socket, 0, k as u8, flags) else {
        sock::close(k);
        return Err(ENFILE);
    };
    st.new_fd(i, f, 0, ty as u32 & O_CLOEXEC != 0).inspect_err(|_| {
        st.files[f].kind = FileKind::Closed;
        sock::close(k);
    })
}

/// The socket calls: IPv4 TCP and UDP over the network server
/// ([`sock`]). One that must wait, on a descriptor without `O_NONBLOCK`
/// (or a send or receive without `MSG_DONTWAIT`), waits.
fn net_call(st: &mut State, i: usize, call: Sys, a: [u64; 6]) -> Out {
    const EPROTONOSUPPORT: u64 = 93;
    const EAFNOSUPPORT: u64 = 97;
    const MSG_PEEK: u64 = 2;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_NOSIGNAL: u64 = 0x4000;
    let r = |v: Result<u64, u64>| Out::Ret(v.unwrap_or_else(err));
    if call == Sys::Socket {
        if a[0] != sock::AF_INET {
            return Out::Ret(err(EAFNOSUPPORT));
        }
        let stream = match (a[1] & 0xf, a[2]) {
            (sock::SOCK_STREAM, 0 | 6) => true,
            (sock::SOCK_DGRAM, 0 | 17) => false,
            _ => return Out::Ret(err(EPROTONOSUPPORT)),
        };
        return r(sock::socket(stream).and_then(|k| new_socket(st, i, k, a[1])));
    }
    let (k, flags) = match sock_of(st, i, a[0]) {
        Ok(s) => s,
        Err(e) => return Out::Ret(err(e)),
    };
    let wait = |dontwait: bool, e: u64| e == sock::EAGAIN && flags & O_NONBLOCK == 0 && !dontwait;
    match call {
        Sys::Bind => r(sockaddr(st, i, a[1], a[2]).and_then(|w| sock::bind(k, w as u16)).map(|_| 0)),
        Sys::Listen => r(sock::listen(k).map(|_| 0)),
        Sys::Connect => match sockaddr(st, i, a[1], a[2]).and_then(|w| sock::connect(k, w)) {
            Ok(()) => Out::Ret(0),
            Err(sock::EINPROGRESS) if flags & O_NONBLOCK == 0 => Out::Block(Blocked::Net { call, a }),
            Err(e) => Out::Ret(err(e)),
        },
        Sys::Accept => match sock::accept(k) {
            Ok(c) => {
                let peer = sock::get(c).peer;
                match new_socket(st, i, c, a[3]) {
                    Ok(fd) => match put_sockaddr(st, i, peer, a[1], a[2]) {
                        Ok(()) => Out::Ret(fd),
                        Err(e) => Out::Ret(err(e)),
                    },
                    Err(e) => Out::Ret(err(e)),
                }
            }
            Err(e) if wait(false, e) => Out::Block(Blocked::Net { call, a }),
            Err(e) => Out::Ret(err(e)),
        },
        Sys::Sendto => {
            let mut tmp = [0u8; 4096];
            let n = a[2].min(tmp.len() as u64) as usize;
            if !st.copy_in(i, a[1], &mut tmp[..n]) {
                return Out::Ret(err(EFAULT));
            }
            let to = if a[4] != 0 && !sock::get(k).stream {
                match sockaddr(st, i, a[4], a[5]) {
                    Ok(w) => w,
                    Err(e) => return Out::Ret(err(e)),
                }
            } else {
                0
            };
            match sock::send(k, &tmp[..n], to) {
                Ok(w) => Out::Ret(w as u64),
                Err(e) if wait(a[3] & MSG_DONTWAIT != 0, e) => Out::Block(Blocked::Net { call, a }),
                Err(EPIPE) => {
                    if a[3] & MSG_NOSIGNAL == 0 {
                        st.post(i, SIGPIPE);
                    }
                    Out::Ret(err(EPIPE))
                }
                Err(e) => Out::Ret(err(e)),
            }
        }
        Sys::Recvfrom => {
            let mut tmp = [0u8; 4096];
            let n = a[2].min(tmp.len() as u64) as usize;
            match sock::recv(k, &mut tmp[..n], a[3] & MSG_PEEK != 0) {
                Ok((n, from)) => r(st.put(i, a[1], &tmp[..n]).and_then(|_| put_sockaddr(st, i, from, a[4], a[5])).map(|_| n as u64)),
                Err(e) if wait(a[3] & MSG_DONTWAIT != 0, e) => Out::Block(Blocked::Net { call, a }),
                Err(e) => Out::Ret(err(e)),
            }
        }
        Sys::Shutdown => r(sock::shutdown(k, a[1]).map(|_| 0)),
        Sys::Getsockname => {
            let w = sock::name(k);
            r(put_sockaddr(st, i, w, a[1], a[2]).map(|_| 0))
        }
        Sys::Getpeername => r(sock::peer(k).and_then(|w| put_sockaddr(st, i, w, a[1], a[2])).map(|_| 0)),
        // Options are taken and do nothing.
        Sys::Setsockopt => Out::Ret(0),
        Sys::Getsockopt => {
            const SOL_SOCKET: u64 = 1;
            const SO_TYPE: u64 = 3;
            const SO_ERROR: u64 = 4;
            let v = match (a[1], a[2]) {
                (SOL_SOCKET, SO_ERROR) => sock::take_error(k),
                (SOL_SOCKET, SO_TYPE) => if sock::get(k).stream { sock::SOCK_STREAM } else { sock::SOCK_DGRAM },
                _ => 0,
            };
            r(st.put(i, a[3], &(v as u32).to_le_bytes()).and_then(|_| st.put(i, a[4], &4u32.to_le_bytes())).map(|_| 0))
        }
        _ => Out::Ret(err(ENOSYS)),
    }
}

/// `setitimer` for the real-time timer (`ITIMER_REAL`): `SIGALRM` after
/// the time in `new` (0: none), then every interval; what was left
/// written to `old`. To the tick.
fn setitimer(st: &mut State, i: usize, which: u64, new: u64, old: u64) -> Result<u64, u64> {
    if which != 0 {
        return Err(EINVAL);
    }
    let now = superior_sys::ticks();
    let to_ticks = |sec: u64, usec: u64| sec.saturating_mul(TICK_HZ).saturating_add((usec * TICK_HZ).div_ceil(1_000_000));
    let timeval = |t: u64| [t / TICK_HZ, t % TICK_HZ * (1_000_000 / TICK_HZ)];
    let p = &st.procs[i];
    let left = if p.alarm != 0 { p.alarm.saturating_sub(now).max(1) } else { 0 };
    let was = [timeval(p.alarm_every), timeval(left)];
    if new != 0 {
        let mut w = [0u64; 4];
        for (k, v) in w.iter_mut().enumerate() {
            *v = st.word(i, new + 8 * k as u64).ok_or(EFAULT)?;
        }
        if w[1] >= 1_000_000 || w[3] >= 1_000_000 {
            return Err(EINVAL);
        }
        let (every, first) = (to_ticks(w[0], w[1]), to_ticks(w[2], w[3]));
        let p = &mut st.procs[i];
        p.alarm = if first != 0 { now + first } else { 0 };
        p.alarm_every = every;
    }
    if old != 0 {
        let mut b = [0u8; 32];
        for (k, v) in was.iter().flatten().enumerate() {
            b[8 * k..8 * k + 8].copy_from_slice(&v.to_le_bytes());
        }
        st.put(i, old, &b)?;
    }
    Ok(0)
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
    "kill", "gzip", "md5sum", "nproc", "wget", "nc",
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
    // A handler that changes the floating-point and SIMD registers leaves
    // them as they were for the code it interrupted (they are in the
    // signal frame): a program of our own, no C library.
    (&["sh", "-c", "fptest && echo fptest said $?"], 0),
    // A process's threads on two CPUs at once (smptest, of our own), and
    // as many CPUs as there are online for programs that ask.
    (&["sh", "-c", "smptest && echo smptest said $? && echo cpus $(nproc)"], 0),
    // Memory unmapped is given back and used again: far more mapped,
    // touched and unmapped than a process has (mmaptest, of our own).
    (&["sh", "-c", "mmaptest && echo mmaptest said $?"], 0),
    // A program with a library of its own: pigz, with zlib, which musl's
    // dynamic linker loads. BusyBox's gzip checks what it wrote.
    (&["sh", "-c", "seq 1 10000 > /tmp/n && pigz -p 2 -b 32 -k /tmp/n && ls /tmp && gzip -dc /tmp/n.gz | md5sum && md5sum < /tmp/n"], 0),
    // Files on the filesystem server, for the second boot to find.
    (&["sh", "-c", "mkdir -p /home/docs/old && cd /home/docs && cp /tmp/n.gz . && echo first > note && echo second >> note && ln -s note link && mv old new && ls && pwd && cat link"], 0),
    (&["sh", "-c", "echo boot >> /home/boots; wc -l < /home/boots"], 0),
    (&["sh", "-c", "mkdir -p /etc /data && echo hello from the disk > /etc/motd && echo 42 > /data/answer && ls /"], 0),
    // Sockets, the network server's: a page over HTTP from the host
    // (BusyBox's wget), TCP and UDP echoed by it (nc), and a connection
    // from it, accepted and served.
    (&["sh", "-c", "wget -q -O - http://10.0.3.2:47081/hello"], 0),
    (&["sh", "-c", "echo echoed over TCP | nc 10.0.3.2 47002"], 0),
    (&["sh", "-c", "echo echoed over UDP | nc -u -w 2 10.0.3.2 47001"], 0),
    (&["nc", "-l", "-p", "8080", "-e", "echo", "served from Linux"], 0),
];

/// The second boot's runs (`arg 1`, boot/linux-verify.manifest): what the
/// first left under /home, read back, and then removed.
const VERIFY_RUNS: &[(&[&str], u32)] = &[
    (&["sh", "-c", "echo boot >> /home/boots; wc -l < /home/boots"], 0),
    (&["sh", "-c", "cd /home/docs && ls && cat note && readlink link && gzip -dc n.gz | md5sum && cd / && rm -r /home/docs && ls /home"], 0),
    (&["sh", "-c", "cat /etc/motd /data/answer && ls / && rm -r /data /etc && ls /"], 0),
];

/// Then a shell on the terminal, until it exits (the test types into it).
const SESSION: &[&str] = &["sh"];
const SESSION_ENV: &[&str] = &["PATH=/usr/bin:/bin", "HOME=/home", "PS1=linux$ "];

#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let failures = setup().map_or_else(
        |why| {
            say!("linux: could not start: {why}");
            1
        },
        |st| {
            let mut failures = 0;
            let (batch, session): (_, &[_]) = if arg == 1 { (VERIFY_RUNS, &[]) } else { (RUNS, &[(SESSION, 0, true)]) };
            let runs = batch.iter().map(|&(argv, want)| (argv, want, false)).chain(session.iter().copied());
            for (argv, want, interactive) in runs {
                let line = Joined(argv);
                let env: &[&str] = if interactive { SESSION_ENV } else { &["PATH=/usr/bin:/bin", "HOME=/home"] };
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
    for k in 0..SPARES as u64 {
        sys(Syscall::Retype, UNTYPED_SPARE, [ObjectType::Untyped as u64, BLOCK_BITS, SPARE_BLOCKS + k, 0])
            .map_err(|_| "no spare memory")?;
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
    let interp = map_file(INTERP_FILE, INTERP_VA, MMAPTEST_FILE - INTERP_FILE);
    let mmaptest = map_file(MMAPTEST_FILE, MMAPTEST_VA, PIGZ_FILE - MMAPTEST_FILE);
    let pigz = map_file(PIGZ_FILE, PIGZ_VA, SMPTEST_FILE - PIGZ_FILE);
    let smptest = map_file(SMPTEST_FILE, SMPTEST_VA, LIBZ_FILE - SMPTEST_FILE);
    let libz = map_file(LIBZ_FILE, LIBZ_VA, FPTEST_FILE - LIBZ_FILE);
    let fptest = map_file(FPTEST_FILE, FPTEST_VA, PROGRAM_FILE - FPTEST_FILE);
    let program = map_file(PROGRAM_FILE, PROGRAM_VA, STATE_SLOTS - PROGRAM_FILE);
    st.next_pid = 1;
    // The restorer page, executable in every process.
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, TRAMPOLINE_SLOT, 0]).map_err(|_| "no memory")?;
    sys(Syscall::FrameMap, TRAMPOLINE_SLOT, [TRAMPOLINE_VA, 1, 0, 0]).map_err(|_| "no room")?;
    // SAFETY: the page was just mapped, writable, at TRAMPOLINE_VA.
    unsafe { core::ptr::copy_nonoverlapping(TRAMPOLINE_CODE.as_ptr(), TRAMPOLINE_VA as *mut u8, TRAMPOLINE_CODE.len()) };
    st.trampoline = Shared { start: TRAMPOLINE, end: TRAMPOLINE + PAGE, ptr: TRAMPOLINE_VA, slot: TRAMPOLINE_SLOT, flags: MAP_EXEC };
    let interp_path = Elf::parse(program).ok().and_then(|e| e.interpreter()).ok_or("BusyBox is not dynamically linked")?;
    // Where each file is: BusyBox first (the runs' programs are its).
    let files: [(&[u8], &'static [u8], u64); 7] = [
        (b"/bin/busybox", program, PROGRAM_FILE),
        (interp_path, interp, INTERP_FILE),
        (b"/usr/bin/pigz", pigz, PIGZ_FILE),
        (b"/lib/libz.so.1", libz, LIBZ_FILE),
        (b"/usr/bin/fptest", fptest, FPTEST_FILE),
        (b"/usr/bin/smptest", smptest, SMPTEST_FILE),
        (b"/usr/bin/mmaptest", mmaptest, MMAPTEST_FILE),
    ];
    let mut tree = [(&b""[..], &b""[..]); 7];
    let mut n = 0;
    for (path, bytes, slot) in files {
        if !bytes.is_empty() {
            st.images[n] = Img { bytes, slot };
            tree[n] = (path, bytes);
            n += 1;
        }
    }
    st.fs.init(POOL_VA, &tree[..n], APPLETS);
    // The root on the filesystem server, through a frame lent with each
    // call.
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, remote::BUF, 0]).map_err(|_| "no memory for files")?;
    sys(Syscall::FrameMap, remote::BUF, [remote::BUF_VA, 1, 0, 0]).map_err(|_| "no room for files")?;
    // The network server's, likewise.
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, sock::BUF, 0]).map_err(|_| "no memory for sockets")?;
    sys(Syscall::FrameMap, sock::BUF, [sock::BUF_VA, 1, 0, 0]).map_err(|_| "no room for sockets")?;
    for k in 0..sock::MAX as u64 {
        sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, sock::STASH + k, 0]).map_err(|_| "no memory for sockets")?;
        sys(Syscall::FrameMap, sock::STASH + k, [sock::STASH_VA + k * PAGE, 1, 0, 0]).map_err(|_| "no room for sockets")?;
    }
    if st.fs.mount() {
        say!("linux: the root is on the filesystem server, /bin, /usr, /lib, /dev and /tmp in memory over it");
    } else {
        say!("linux: no filesystem server; every file is in memory");
    }
    Ok(st)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
