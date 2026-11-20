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
//! `/usr/bin` and zlib in `/lib`; glibc's dynamic linker and C library
//! where Debian puts them, and GNU hello, linked against them; `/tmp`,
//! `/dev/null`; pipes; the console. They last as long as this server,
//! but for what is made outside them, which is the filesystem server's
//! (this component's container there: the root, with `/home`), and so on
//! its disk.
//!
//! Slots: 0 the untyped memory everything is made from, cut into eight
//! blocks (slots 8 to 15): seven for processes, revoked when one exits or
//! execs, and one for this server's state and the files' pages (from
//! [`STATE_SLOTS`]). From 920 the rest of RAM, cut into spare blocks (from
//! [`SPARE_BLOCKS`]) lent to a process that outgrows its own. 1 the
//! manager's control endpoint, 2 the endpoint faults arrive on, 6 the
//! filesystem server (its buffer frame in [`remote::BUF`]). The
//! bundle's files' pages from 16: musl's, mmaptest's from 177, pigz's
//! from 180, smptest's
//! from 213, zlib's from 216, fptest's from 250, BusyBox's from 252, and
//! glibc's dynamic linker's from 8192, hello's from 8256, glibc's from
//! 8320, the toolchain's from 8832 (tcc, make, libtcc, the archive of the
//! rest), and binutils' from 9472 (as, ld and their libraries) (`file`
//! in the manifest); the exec buffer and the framebuffer after the shared
//! pages, at the end. Process `i` owns the
//! slots from `PROC_SLOTS + i * PROC_SPAN` (16384 on, 2048 each): its
//! address space, then its threads (each with a badged fault endpoint)
//! and pages as made, two slots a page (its frame and the mirror's copy),
//! so up to 4 MiB of its own.
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
//! Sockets ([`sock`]): TCP, UDP and ping, over IPv4 and IPv6, each the network server's (slot
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
mod unix;
mod wl;

use fs::{FileKind, Fs, Kind, MAX_FILES, MAX_IMAGES, MAX_PIPES, Open, PIPE_BUF, Pipe, ROOT};
use signal::{Action, Next, SA_RESTART, SIGALRM, SIGCHLD, SIGPIPE, SIGSEGV, SYSCALL_LEN, TRAMPOLINE, TRAMPOLINE_CODE};
use superior_objects::abi::{
    CapTransfer, Error, FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType, REGS_COUNT, REGS_FOREIGN, REGS_FORK_FROM, REGS_FP_GET,
    REGS_BARRIER, REGS_FP_SET, REGS_FP_WORDS, REGS_GET, REGS_SET, REGS_SET_TLS, REGS_SYSCALL, REGS_SYSCALL_MORE, REGS_TLS, Syscall, TICK_HZ,
};
use superior_objects::elf::{Elf, Machine, Segment};
use superior_objects::idl::window;
use superior_sys::{USER_BASE, print_line, syscall};

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

const CONTROL: u64 = 1;
const EP: u64 = 2;
/// The rest of RAM (`untyped spare` in the manifest): blocks in slots
/// from here, the first empty one after the last; the spare blocks are
/// cut from them.
const UNTYPED_SPARE: u64 = 920;
const UNTYPED_SPARE_COUNT: u64 = 32;
/// Each process's block, then the state's and files' (`FS_BLOCK`), cut
/// from the rest of RAM (the component's own memory holds its files).
const BLOCKS: u64 = 8;
const BLOCK_BITS: u64 = 20;
/// Blocks lent to processes that outgrow their own, one at a time (1 MiB
/// each).
const SPARE_BLOCKS: u64 = 1024;
const SPARES: usize = 32;
/// The block this server's state is in, from the rest of RAM.
const STATE_BLOCK: u64 = 1100;
const STATE_BLOCK_BITS: u64 = 19;
/// The notification this server's thread is bound to (so `Recv` also
/// returns when it is signalled), and two badged copies of it: the UART's
/// interrupt (bit 0) and the timer for sleepers (bit 1).
const NTFN: u64 = 1001;
const NTFN_UART: u64 = 1002;
const NTFN_TIMER: u64 = 1003;
/// Another, the framebuffer window's events (bit 2), lent to the
/// compositor.
const NTFN_WINDOW: u64 = 1005;
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
/// glibc's dynamic linker, GNU hello and glibc, past the processes' slots.
const GLIBC_LD_FILE: u64 = 8192;
const HELLO_FILE: u64 = 8256;
const LIBC_FILE: u64 = 8320;
const LIBC_PAGES: u64 = 512;
/// The toolchain: tcc, make, tcc's library, and an archive (ustar) of the
/// rest (C headers, start files, runtime libraries, gcc's linker plugin;
/// up to 1.5 MiB), unpacked into the tree here.
const TCC_FILE: u64 = 8832;
const MAKE_FILE: u64 = 8864;
const LIBTCC_FILE: u64 = 8960;
const TOOLS_FILE: u64 = 9088;
const TOOLS_END: u64 = AS_FILE;
/// Where the first page of a program in a file of the tree (not the
/// bundle's) is read, for its headers, as it is loaded: `EXEC_PAGES`
/// pages cut from a block of the rest of RAM. Its segments are read from
/// the file a page at a time. In the slots after the shared pages'.
const EXEC_BLOCK: u64 = SHM_SLOTS + SHM_PAGES;
const EXEC_SLOTS: u64 = EXEC_BLOCK + 1;
const EXEC_PAGES: u64 = 1;
/// GNU binutils' assembler and linker, their libraries (BFD, CTF, SFrame,
/// and the opcodes AArch64's assembler links to) and zstd's, which BFD
/// links to.
const AS_FILE: u64 = 9472;
const LD_FILE: u64 = 9664;
const LIBBFD_FILE: u64 = 10112;
const LIBCTF_FILE: u64 = 10432;
const LIBSFRAME_FILE: u64 = 10496;
const LIBZSTD_FILE: u64 = 10528;
const LIBOPCODES_FILE: u64 = 10752;
/// gcc: its driver, compiler proper (cc1, some 30 MB) and collect2 (which
/// runs ld), its runtime library (libgcc.a; libgcc_s), and the libraries
/// cc1 links to (GMP, MPFR, MPC, isl).
const CC1_FILE: u64 = 11072;
const GCC_FILE: u64 = 19328;
const COLLECT2_FILE: u64 = 19664;
const LIBGCC_A_FILE: u64 = 19840;
const LIBGMP_FILE: u64 = 20608;
const LIBMPFR_FILE: u64 = 20736;
const LIBMPC_FILE: u64 = 20912;
const LIBISL_FILE: u64 = 20960;
const LIBGCC_S_FILE: u64 = 21504;
/// links, a text browser, and what it links to: OpenSSL's libssl and
/// libcrypto, libevent and libbz2.
const LINKS_FILE: u64 = 21552;
const LIBCRYPTO_FILE: u64 = 22128;
const LIBSSL_FILE: u64 = 23216;
const LIBEVENT_FILE: u64 = 23376;
const LIBBZ2_FILE: u64 = 23472;
const LINKS_END: u64 = 23504;
/// libwayland's client library, the libffi it calls through, and
/// libxkbcommon: what a Wayland program links against. After the
/// framebuffer's slots, at the CNode's end.
const LIBWAYLAND_FILE: u64 = 65360;
const LIBFFI_FILE: u64 = 65392;
const LIBXKBCOMMON_FILE: u64 = 65424;
const WAYLAND_END: u64 = 65520;
const _: () = assert!(FB_SLOTS + FB_PAGES <= LIBWAYLAND_FILE && WAYLAND_END <= 1 << 16);
const STATE_SLOTS: u64 = 512;
const STATE_PAGES: u64 = 128;
const POOL_SLOTS: u64 = STATE_SLOTS + STATE_PAGES;
/// The signal restorer's page ([`signal::TRAMPOLINE`]).
const TRAMPOLINE_SLOT: u64 = 1000;
const PROC_SLOTS: u64 = 23552;
const PROC_SPAN: u64 = 5888;
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
const LIBC_VA: u64 = USER_BASE + 0x1_7000_0000;
const GLIBC_LD_VA: u64 = USER_BASE + 0x1_7400_0000;
const HELLO_VA: u64 = USER_BASE + 0x1_7500_0000;
const TCC_VA: u64 = USER_BASE + 0x1_7600_0000;
const MAKE_VA: u64 = USER_BASE + 0x1_7700_0000;
const LIBTCC_VA: u64 = USER_BASE + 0x1_7800_0000;
const TOOLS_VA: u64 = USER_BASE + 0x1_7900_0000;
const EXEC_VA: u64 = USER_BASE + 0x1_7a00_0000;
const AS_VA: u64 = USER_BASE + 0x1_7b00_0000;
const LD_VA: u64 = USER_BASE + 0x1_7c00_0000;
const LIBBFD_VA: u64 = USER_BASE + 0x1_7d00_0000;
const LIBCTF_VA: u64 = USER_BASE + 0x1_7e00_0000;
const LIBSFRAME_VA: u64 = USER_BASE + 0x1_7f00_0000;
const LIBZSTD_VA: u64 = USER_BASE + 0x1_8000_0000;
const LIBOPCODES_VA: u64 = USER_BASE + 0x1_8100_0000;
const GCC_VA: u64 = USER_BASE + 0x1_8200_0000;
const COLLECT2_VA: u64 = USER_BASE + 0x1_8300_0000;
const LIBGCC_A_VA: u64 = USER_BASE + 0x1_8400_0000;
const LIBGMP_VA: u64 = USER_BASE + 0x1_8500_0000;
const LIBMPFR_VA: u64 = USER_BASE + 0x1_8600_0000;
const LIBMPC_VA: u64 = USER_BASE + 0x1_8700_0000;
const LIBISL_VA: u64 = USER_BASE + 0x1_8800_0000;
const LIBGCC_S_VA: u64 = USER_BASE + 0x1_8900_0000;
const CC1_VA: u64 = USER_BASE + 0x1_9000_0000;
const LINKS_VA: u64 = USER_BASE + 0x1_9400_0000;
const LIBCRYPTO_VA: u64 = USER_BASE + 0x1_9600_0000;
const LIBSSL_VA: u64 = USER_BASE + 0x1_9700_0000;
const LIBEVENT_VA: u64 = USER_BASE + 0x1_9800_0000;
const LIBBZ2_VA: u64 = USER_BASE + 0x1_9900_0000;
const LIBWAYLAND_VA: u64 = USER_BASE + 0x1_9d00_0000;
const LIBFFI_VA: u64 = USER_BASE + 0x1_9e00_0000;
const LIBXKBCOMMON_VA: u64 = USER_BASE + 0x1_9f00_0000;
/// The framebuffer (`/dev/fb0`): a window of the compositor's (`uses
/// window` in the manifest), FB_W by FB_H, XRGB8888, its pages cut from
/// a block of the rest of RAM, here at FB_VA and lent to the compositor;
/// a process that maps it shares them. Shown where Linux's would be on a
/// screen already: when a program pans it, writes to it or closes it.
const WINDOWS: u64 = 1004;
const FB_BLOCK: u64 = EXEC_SLOTS + EXEC_PAGES;
const FB_BLOCK_BITS: u64 = 19;
const FB_SLOTS: u64 = FB_BLOCK + 1;
const FB_W: u64 = 320;
const FB_H: u64 = 240;
const FB_PAGES: u64 = (FB_W * FB_H * 4).div_ceil(PAGE);
const FB_AT: (u64, u64) = (240, 180);
const FB_VA: u64 = USER_BASE + 0x1_9a00_0000;
/// While a process has the framebuffer mapped, it is shown as it is drawn,
/// as a screen would show it: every FB_PERIOD ticks (25 times a second).
const FB_PERIOD: u64 = TICK_HZ / 25;
const _: () = assert!(FB_PAGES << 12 <= 1 << FB_BLOCK_BITS && FB_SLOTS + FB_PAGES <= 1 << 16);
/// Shared memory (`memfd_create`): a block of the rest of RAM cut into
/// SHM_PAGES pages, here at SHM_VA, in the slots after the processes'.
/// A memory file holds a run of them, which the processes that map it
/// share ([`Shm`]).
const SHM_BLOCK: u64 = PROC_SLOTS + MAX_PROCS as u64 * PROC_SPAN;
const SHM_BLOCK_BITS: u64 = 21;
const SHM_SLOTS: u64 = SHM_BLOCK + 1;
const SHM_PAGES: u64 = 1 << (SHM_BLOCK_BITS - 12);
const SHM_VA: u64 = USER_BASE + 0x1_9c00_0000;
const MAX_SHM: usize = 16;
const _: () = assert!(SHM_SLOTS + SHM_PAGES <= 1 << 16 && FB_VA + FB_PAGES * PAGE <= SHM_VA);

/// A memory file: `size` bytes in the `pages` shared pages from `first`.
/// Its pages are given back once it is closed and no process maps them
/// ([`State::shm_sweep`]).
#[derive(Clone, Copy)]
struct Shm {
    used: bool,
    open: bool,
    first: u16,
    pages: u16,
    size: u64,
}

/// Where Alpine puts gcc's own files: under its target's name.
const CC1_PATH: &[u8] = if cfg!(target_arch = "x86_64") {
    b"/usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/cc1"
} else {
    b"/usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/cc1"
};
const COLLECT2_PATH: &[u8] = if cfg!(target_arch = "x86_64") {
    b"/usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/collect2"
} else {
    b"/usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/collect2"
};
const LIBGCC_A_PATH: &[u8] = if cfg!(target_arch = "x86_64") {
    b"/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/libgcc.a"
} else {
    b"/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/libgcc.a"
};
/// Where Debian puts glibc.
const LIBC_PATH: &[u8] = if cfg!(target_arch = "x86_64") {
    b"/lib/x86_64-linux-gnu/libc.so.6"
} else {
    b"/lib/aarch64-linux-gnu/libc.so.6"
};

/// A process's address space: everything inside [`CHILD`, `CHILD_END`)
/// (256 MiB), in the kernel's low user window (from 64 KiB), so a
/// fixed-address program, linked at 4 MiB, is loaded where it is linked:
/// where a position-independent one goes ([`PROGRAM_BASE`]). A program
/// has up to 96 MiB (cc1 is 38), then the interpreter, then mappings.
const CHILD: u64 = 0x1_0000;
const SPAN: u64 = 0x1000_0000;
const CHILD_END: u64 = CHILD + SPAN;
const PROGRAM_BASE: u64 = CHILD + 0x40_0000;
const INTERP_BASE: u64 = CHILD + 0x600_0000;
const MMAP_BASE: u64 = CHILD + 0x680_0000;
const STACK_TOP: u64 = CHILD_END - 0x10_0000;
const STACK_PAGES: u64 = 32;
const BRK_MAX: u64 = 0x80_0000;
/// Process `i`'s page at `va` is here at `va - CHILD + MIRROR + i * SPAN`.
const MIRROR: u64 = USER_BASE + 0x48_0000_0000;
const CHILD_PAGES: usize = (SPAN / PAGE) as usize;

const MACHINE: Machine = if cfg!(target_arch = "x86_64") { Machine::X86_64 } else { Machine::Aarch64 };
const PLATFORM: &str = if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" };

// Linux error numbers (and those in `fs`).
use fs::{EBADF, EEXIST, EINVAL, EISDIR, ENFILE, ENOENT, ENOSPC, ENOTDIR, EPIPE};
const EPERM: u64 = 1;
const ESRCH: u64 = 3;
const EINTR: u64 = 4;
const ENOEXEC: u64 = 8;
const ECHILD: u64 = 10;
const EIO: u64 = 5;
const EAGAIN: u64 = 11;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const E2BIG: u64 = 7;
const EFAULT: u64 = 14;
const ENODEV: u64 = 19;
const ENXIO: u64 = 6;
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
const CLONE_VFORK: u64 = 0x4000;
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
    Readv,
    Openat,
    Close,
    Fstat,
    Fstatat,
    Lseek,
    Pread,
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
    Vfork,
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
    Getrusage,
    /// `epoll_create`, `epoll_create1`.
    EpollCreate,
    EpollCtl,
    /// `epoll_wait`, `epoll_pwait` (the mask not applied): a timeout in
    /// milliseconds in a[3]; `epoll_pwait2`: a[5] 1, a timespec's address
    /// in a[4].
    EpollWait,
    Sysinfo,
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
    Sendmsg,
    Recvmsg,
    Shutdown,
    Getsockname,
    Getpeername,
    Setsockopt,
    Getsockopt,
    Socketpair,
    MemfdCreate,
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
        17 => Sys::Pread,
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
        19 => Sys::Readv,
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
        46 => Sys::Sendmsg,
        47 => Sys::Recvmsg,
        48 => Sys::Shutdown,
        49 => Sys::Bind,
        50 => Sys::Listen,
        51 => Sys::Getsockname,
        52 => Sys::Getpeername,
        54 => Sys::Setsockopt,
        55 => Sys::Getsockopt,
        53 => Sys::Socketpair,
        319 => Sys::MemfdCreate,
        40 => Sys::Sendfile,
        56 => Sys::Clone,
        57 => Sys::Fork,
        58 => Sys::Vfork,
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
        98 => Sys::Getrusage,
        99 => Sys::Sysinfo,
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
        213 | 291 => Sys::EpollCreate,
        233 => Sys::EpollCtl,
        232 | 281 => return (Sys::EpollWait, [a[0], a[1], a[2], a[3], 0, 0]),
        441 => return (Sys::EpollWait, [a[0], a[1], a[2], 0, a[3], 1]),
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
        67 => Sys::Pread,
        63 => Sys::Read,
        64 => Sys::Write,
        65 => Sys::Readv,
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
        211 => Sys::Sendmsg,
        212 => Sys::Recvmsg,
        208 => Sys::Setsockopt,
        209 => Sys::Getsockopt,
        199 => Sys::Socketpair,
        279 => Sys::MemfdCreate,
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
        165 => Sys::Getrusage,
        179 => Sys::Sysinfo,
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
        20 => Sys::EpollCreate,
        21 => Sys::EpollCtl,
        22 => return (Sys::EpollWait, [a[0], a[1], a[2], a[3], 0, 0]),
        441 => return (Sys::EpollWait, [a[0], a[1], a[2], 0, a[3], 1]),
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
    /// `epoll_wait`: until a descriptor epoll instance `fd` watches is
    /// ready, or the tick `until`.
    EpollWait { fd: u64, events: u64, max: u64, until: u64 },
    /// `vfork` (or `clone` with `CLONE_VFORK`): until child `pid` has
    /// exec'd or ended.
    Vfork { pid: u32 },
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
    /// A `vfork` child that has yet to exec or end: its parent waits.
    vfork: bool,
    /// The process whose memory (address space, pages, mappings, break)
    /// this one uses: itself, but for a `vfork` child, which borrows its
    /// parent's until it execs or ends ([`State::mem`]).
    mem: u8,
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
    /// Which of its own pages hold code (a program from a file of the
    /// tree, copied): executable, never writable, in its space.
    code: [u64; CHILD_PAGES / 64],
    /// Which pages of its shared runs are mapped in its space so far
    /// ([`State::take_shared`]).
    mapped: [u64; CHILD_PAGES / 64],
    /// The runs of bundle-file pages it maps (code, read-only data; the
    /// restorer page first; links and its six libraries have some 24).
    shared: [Shared; 48],
    nshared: usize,
    /// Libraries loaded by `mmap` ([`mmap_file`]): their span and inode.
    libs: [(u64, u64, u16); 16],
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
    /// The address its last page fault was at, if it was tried again (0
    /// once it makes a system call).
    last_fault: u64,
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
    epolls: [Epoll; MAX_EPOLLS],
    procs: [Proc; MAX_PROCS],
    /// The arguments and environment of the program being started, here
    /// for their size ([`State::exec`]).
    exec_args: Strs,
    exec_env: Strs,
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
    /// Whether the framebuffer's pages are there, and its window's number
    /// plus one (0 until it is made, or once the compositor lost it).
    fb_pages: bool,
    fb_window: u64,
    fb_shown: bool,
    /// When a mapped framebuffer is next shown (ticks).
    fb_next: u64,
    /// The input devices' events not yet read (the keys', the pointer's),
    /// and what the window's events last said: the modifier keys held,
    /// the buttons held, where the pointer is.
    input: [Events; 2],
    input_mods: u8,
    input_buttons: u8,
    input_at: (i32, i32),
    /// Unix domain sockets.
    unix: [unix::Unix; unix::MAX_UNIX],
    /// Memory files, whether their pages are there, and which are taken.
    shm: [Shm; MAX_SHM],
    shm_pages: bool,
    shm_used: [u64; (SHM_PAGES / 64) as usize],
}

/// An input device's events, oldest first: (when, in ticks; type; code;
/// value). The oldest go when it is full, as Linux's do.
struct Events {
    ev: [(u64, u16, u16, i32); 128],
    head: usize,
    len: usize,
}

impl Events {
    fn push(&mut self, at: u64, ty: u16, code: u16, value: i32) {
        let n = self.ev.len();
        if self.len == n {
            self.head = (self.head + 1) % n;
            self.len -= 1;
        }
        self.ev[(self.head + self.len) % n] = (at, ty, code, value);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<(u64, u16, u16, i32)> {
        if self.len == 0 {
            return None;
        }
        let e = self.ev[self.head];
        self.head = (self.head + 1) % self.ev.len();
        self.len -= 1;
        Some(e)
    }
}

/// Linux's event types and codes the input devices use.
const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const REL_HWHEEL: u16 = 6;
const REL_WHEEL: u16 = 8;
const BTN_LEFT: u16 = 0x110;
/// Linux's key code for each USB HID keyboard usage up to 0x67 (0: none),
/// as Linux's HID driver maps them; and for the modifier byte's bits
/// (Control, Shift, Alt, Meta; left, then right).
const HID_KEYS: [u8; 0x68] = [
    0, 0, 0, 0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 28, 1, 14, 15, 57, 12, 13, 26, 27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 87, 88, 99, 70, 119, 110, 102, 104, 111, 107, 109, 106, 105, 108, 103, 69, 98, 55, 74, 78, 96, 79, 80, 81,
    75, 76, 77, 71, 72, 73, 82, 83, 86, 127, 116, 117,
];
const MOD_KEYS: [u16; 8] = [29, 42, 56, 125, 97, 54, 100, 126];

const _: () = assert!(core::mem::size_of::<State>() as u64 <= STATE_PAGES * PAGE);

/// Strings gathered from a process (arguments, environment).
struct Strs {
    buf: [u8; STRS_BYTES],
    len: usize,
    off: [(u16, u16); MAX_STRS],
    n: usize,
}

/// A new program's arguments, or its environment: as many as gcc gives
/// collect2 and ld (some forty, long paths among them).
const STRS_BYTES: usize = 16384;
const MAX_STRS: usize = 256;
/// The longest one.
const MAX_STR: usize = 4096;

impl Strs {
    fn clear(&mut self) {
        (self.len, self.n) = (0, 0);
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

    /// The process whose memory process `i` uses (see [`Proc::mem`]):
    /// what every reach into a process's memory goes through.
    fn mem(&self, i: usize) -> usize {
        self.procs[i].mem as usize
    }

    fn is_present(&self, i: usize, va: u64) -> bool {
        let i = self.mem(i);
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].present[k / 64] & (1 << (k % 64)) != 0
    }

    fn is_code(&self, i: usize, va: u64) -> bool {
        let i = self.mem(i);
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].code[k / 64] & (1 << (k % 64)) != 0
    }

    /// Whether `va` is in process `i`'s window, in an anonymous mapping's
    /// page not yet made (see [`Proc::reserved`]).
    fn is_reserved(&self, i: usize, va: u64) -> bool {
        let i = self.mem(i);
        if !(CHILD..CHILD_END).contains(&va) {
            return false;
        }
        let k = ((va - CHILD) / PAGE) as usize;
        self.procs[i].reserved[k / 64] & (1 << (k % 64)) != 0
    }

    fn set_reserved(&mut self, i: usize, va: u64, on: bool) {
        let i = self.mem(i);
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
        let i = self.mem(i);
        if !(CHILD..CHILD_END).contains(&va) {
            return None;
        }
        if self.is_present(i, va) {
            // Code is not written, by the process or for it.
            return Some(((va - CHILD + MIRROR + i as u64 * SPAN) as *mut u8, !self.is_code(i, va)));
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
        self.map_page(i, va, None)
    }

    /// As [`State::map_private`], but a page of code holding `bytes`
    /// (written here first): executable in the process, not writable.
    fn map_code(&mut self, i: usize, va: u64, bytes: &[u8]) -> Result<(), u64> {
        self.map_page(i, va, Some(bytes))
    }

    fn map_page(&mut self, i: usize, va: u64, code: Option<&[u8]>) -> Result<(), u64> {
        let i = self.mem(i);
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
        if let Some(bytes) = code {
            let len = bytes.len().min(PAGE as usize);
            // SAFETY: the page is mapped here, writable, at `mirror`, and
            // not yet in the process.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mirror as *mut u8, len) };
        }
        let flags = if code.is_some() { MAP_EXEC } else { MAP_WRITE };
        let p = &mut self.procs[i];
        if sys(Syscall::FrameMapInto, slot, [va, flags, space_slot(i), 0]).is_err() {
            // Kept for another try.
            let _ = syscall(Syscall::FrameUnmap, slot + 1, [0; 4]);
            p.frames[n] = FREE;
            return Err(ENOMEM);
        }
        p.frames[n] = k as u16 + 1;
        p.present[k / 64] |= 1 << (k % 64);
        if code.is_some() {
            p.code[k / 64] |= 1 << (k % 64);
        }
        Ok(())
    }

    /// `munmap` of process `i`'s own page at `va`, if it has one there:
    /// unmapped from it and from the mirror, its frame kept to be used
    /// again ([`State::map_private`]).
    fn unmap_private(&mut self, i: usize, va: u64) {
        let i = self.mem(i);
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
        p.code[k / 64] &= !(1 << (k % 64));
    }

    /// Whether process `i` has anything at page `va`: a page of its own, a
    /// reserved one, a bundle file's, or a library's span.
    fn taken(&self, i: usize, va: u64) -> bool {
        let i = self.mem(i);
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
        let i = self.mem(i);
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

    /// Maps the page of a shared run at `va` (any address in it) in
    /// process `i`, on its first touch: a run's pages are mapped only as
    /// they are used, so a slot is spent on each page a program touches,
    /// not on each it has (cc1's code alone is some 7000 pages). Whether
    /// it is now mapped (or was, by another of its threads meanwhile).
    fn take_shared(&mut self, i: usize, va: u64) -> bool {
        let i = self.mem(i);
        let page = va & !(PAGE - 1);
        if !(CHILD..CHILD_END).contains(&page) || self.is_present(i, page) {
            return false;
        }
        let k = ((page - CHILD) / PAGE) as usize;
        let p = &self.procs[i];
        if p.mapped[k / 64] & 1 << (k % 64) != 0 {
            return true;
        }
        let Some(s) = p.shared[..p.nshared].iter().copied().find(|s| (s.start..s.end).contains(&page)) else {
            return false;
        };
        if self.map_shared(i, page, s.slot + (page - s.start) / PAGE, s.flags).is_err() {
            return false;
        }
        self.procs[i].mapped[k / 64] |= 1 << (k % 64);
        true
    }

    /// Loads an image (the file whose pages are in slots from
    /// `file_slot`) in process `i`: a position-independent one at `base`, a
    /// fixed-address program where it is linked (as the program, below the
    /// mapping area, only). (entry, program headers' address, their count,
    /// the image's end). Pages that are written get a copy; the rest are
    /// the file's own, shared; or, for a file of the tree, every page is
    /// read from the file into one of its own, code into pages of code
    /// ([`State::map_code`]).
    fn load(&mut self, i: usize, src: Src, base: u64) -> Result<(u64, u64, u64, u64), &'static str> {
        let i = self.mem(i);
        let elf = src.elf().map_err(|_| "not an ELF executable")?;
        if elf.machine != MACHINE {
            return Err("not for this machine");
        }
        let (base, limit) = match (elf.pie, base) {
            (true, _) => (base, CHILD_END),
            (false, PROGRAM_BASE) => (0, MMAP_BASE),
            (false, _) => return Err("a fixed-address library or interpreter"),
        };
        let (phoff, phnum) = elf.program_headers();
        let mut phdr = base + phoff;
        let mut end = 0;
        for seg in elf.segments() {
            let seg = seg.map_err(|_| "a bad segment")?;
            if seg.mem_size == 0 {
                continue;
            }
            let (lo, hi) = (seg.vaddr & !(PAGE - 1), (seg.vaddr + seg.mem_size).next_multiple_of(PAGE));
            if base + lo < CHILD || hi.checked_add(base).is_none_or(|h| h > limit) {
                return Err("a segment outside the process's space");
            }
            // The program headers' address: where the segment holding
            // them puts them (in a position-independent image, at their
            // offset).
            if (seg.file_offset..seg.file_offset + seg.file_size).contains(&phoff) {
                phdr = base + seg.vaddr + (phoff - seg.file_offset);
            }
            end = end.max(hi);
            let (image, file_slot) = match src {
                Src::Bundle { bytes, slot } => (bytes, slot),
                Src::Tree { ino, .. } => {
                    if seg.executable && seg.writable {
                        return Err("an unsupported segment layout");
                    }
                    self.load_pages(i, ino, &seg, base, lo, hi)?;
                    continue;
                }
            };
            if seg.writable {
                for page in (lo..hi).step_by(PAGE as usize) {
                    self.map_private(i, base + page).map_err(|_| "out of memory")?;
                }
                if !self.copy_out(i, base + seg.vaddr, elf.file_bytes(&seg)) {
                    return Err("out of memory");
                }
                continue;
            }
            if seg.executable && seg.writable {
                return Err("an unsupported segment layout");
            }
            if seg.vaddr % PAGE != seg.file_offset % PAGE {
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
            }
        }
        Ok((base + elf.entry, phdr, phnum as u64, base + end))
    }

    /// Segment `seg`'s pages [`lo`, `hi`) of a program in file `ino` of
    /// the tree, each read from the file (zeros past its bytes) into a
    /// page of process `i`'s own at `base` on.
    fn load_pages(&mut self, i: usize, ino: u16, seg: &Segment, base: u64, lo: u64, hi: u64) -> Result<(), &'static str> {
        let i = self.mem(i);
        for page in (lo..hi).step_by(PAGE as usize) {
            let mut buf = [0u8; PAGE as usize];
            let (from, to) = (page.max(seg.vaddr), (page + PAGE).min(seg.vaddr + seg.file_size));
            let mut at = from;
            while at < to {
                let got = self.fs.read(ino, seg.file_offset + (at - seg.vaddr), &mut buf[(at - page) as usize..(to - page) as usize]);
                if got == 0 {
                    return Err("the file is cut short");
                }
                at += got as u64;
            }
            if self.is_present(i, base + page) {
                // A page an earlier segment has too (a linker that packs
                // them, as tcc does on AArch64): this one's bytes and zeros
                // written into it, the rest kept.
                let end = (page + PAGE).min(seg.vaddr + seg.mem_size);
                let mirror = base + page - CHILD + MIRROR + i as u64 * SPAN;
                let at = (from - page) as usize;
                // SAFETY: the page is mapped here, writable, at `mirror`;
                // [at, end - page) is within it.
                unsafe { core::ptr::copy_nonoverlapping(buf[at..].as_ptr(), (mirror as *mut u8).add(at), (end - from) as usize) };
                continue;
            }
            let made = if seg.executable {
                self.map_code(i, base + page, &buf)
            } else {
                self.map_private(i, base + page).map(|_| {
                    self.copy_out(i, base + page, &buf);
                })
            };
            made.map_err(|_| "out of memory")?;
        }
        Ok(())
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
        p.vfork = false;
        p.mem = i as u8;
        p.cursor = 0;
        p.cwd = ROOT;
        p.fds = [0; MAX_FDS];
        p.cloexec = 0;
        p.present = [0; CHILD_PAGES / 64];
        p.reserved = [0; CHILD_PAGES / 64];
        p.code = [0; CHILD_PAGES / 64];
        p.mapped = [0; CHILD_PAGES / 64];
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
            last_fault: 0,
        };
        Some(t)
    }

    /// Makes process `i`'s address space, and task `t`'s thread and fault
    /// endpoint, at the start of the process's span.
    fn make_space(&mut self, i: usize, t: usize) -> Result<(), &'static str> {
        let b = slot_base(i);
        // Room for the page tables of a 256 MiB space, sparse.
        self.retype(i, ObjectType::AddressSpace, 18, b).map_err(|_| "no address space")?;
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
        let (th, i) = (self.tasks[t].thread, self.mem(self.tasks[t].proc as usize));
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

    /// The tasks of process `i`.
    fn tasks_of(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_TASKS).filter(move |&t| self.tasks[t].used && self.tasks[t].proc as usize == i)
    }

    /// Destroys process `i`'s address space, thread and pages (its own,
    /// not memory it borrows). A `vfork` child still borrowing them is
    /// killed first, as it has nothing left to run in.
    fn unmake_space(&mut self, i: usize) {
        for c in 0..MAX_PROCS {
            if c != i && self.procs[c].used && !self.procs[c].zombie && self.mem(c) == i {
                self.exit(c, signal::SIGKILL);
            }
        }
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
        p.code = [0; CHILD_PAGES / 64];
        p.mapped = [0; CHILD_PAGES / 64];
        p.frames = [0; PROC_SPAN as usize];
    }

    /// Runs bundle file `image` (a program) as task `t`'s process, its
    /// address space made afresh, with `argv` and `envp`, and the
    /// interpreter the program names, if it names one.
    fn exec(&mut self, t: usize, image: Prog, execfn: &[u8]) -> Result<(), &'static str> {
        let i = self.tasks[t].proc as usize;
        self.make_space(i, t)?;
        let tramp = self.trampoline;
        let p = &mut self.procs[i];
        (p.shared[0], p.nshared, p.nlibs) = (tramp, 1, 0);
        let src = match image {
            Prog::Image(k) => Src::Bundle { bytes: self.images[k].bytes, slot: self.images[k].slot },
            // SAFETY: the file's first bytes, read into the buffer at
            // EXEC_VA, which nothing else uses until the next exec.
            Prog::File { ino, len, head } => Src::Tree { head: unsafe { core::slice::from_raw_parts(EXEC_VA as *const u8, head) }, ino, len },
        };
        let (entry, phdr, phnum, end) = self.load(i, src, PROGRAM_BASE)?;
        let (start, interp_base) = match src.elf().ok().and_then(|e| e.interpreter()) {
            Some(path) => {
                let ino = self.fs.resolve(ROOT, path, true).map_err(|_| "its interpreter is missing")?;
                let k = self.fs.image(ino).ok_or("its interpreter is not a program")?;
                let Img { bytes, slot } = self.images[k];
                (self.load(i, Src::Bundle { bytes, slot }, INTERP_BASE)?.0, INTERP_BASE)
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
        let mut argp = [0u64; MAX_STRS];
        let mut envp_at = [0u64; MAX_STRS];
        let mut s = [0u8; MAX_STR];
        let (nargs, nenv) = (self.exec_args.n, self.exec_env.n);
        // The arguments and environment, each copied a piece at a time
        // (one may be longer than a piece: a shell script given with
        // `sh -c`, say).
        for (env, n) in [(false, nargs), (true, nenv)] {
            for k in 0..n {
                let len = if env { self.exec_env.get(k) } else { self.exec_args.get(k) }.len();
                top -= len as u64 + 1;
                for at in (0..len).step_by(MAX_STR) {
                    let m = (len - at).min(MAX_STR);
                    s[..m].copy_from_slice(&if env { self.exec_env.get(k) } else { self.exec_args.get(k) }[at..at + m]);
                    if !self.copy_out(i, top + at as u64, &s[..m]) {
                        return Err("stack");
                    }
                }
                if !self.copy_out(i, top + len as u64, &[0]) {
                    return Err("stack");
                }
                if env { envp_at[k] = top } else { argp[k] = top }
            }
        }
        let mut push_str = |st: &mut State, s: &[u8]| -> Result<u64, &'static str> {
            top -= s.len() as u64 + 1;
            if st.copy_out(i, top, s) && st.copy_out(i, top + s.len() as u64, &[0]) { Ok(top) } else { Err("stack") }
        };
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
        let words = 1 + nargs + 1 + nenv + 1 + 2 * (aux.len() + 1);
        // At argc, on a 16-byte boundary, as Linux starts a program (glibc's
        // dynamic linker relies on it; musl's realigns its stack itself).
        let sp = (top - 8 * words as u64) & !15;
        let mut words = [0u64; 1 + MAX_STRS + 1 + MAX_STRS + 1 + 36];
        let mut n = 0;
        let mut w = |v: u64| {
            words[n] = v;
            n += 1;
        };
        w(nargs as u64);
        argp[..nargs].iter().for_each(|&p| w(p));
        w(0);
        envp_at[..nenv].iter().for_each(|&p| w(p));
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
        self.configure(t, start, sp, None)?;
        if cfg!(target_arch = "x86_64") {
            // An x86-64 thread starts as if called, 8 below its stack's
            // top: put the stack pointer (Linux's register 15) at argc,
            // and the entry (16) back.
            let th = self.tasks[t].thread;
            sys(Syscall::ThreadRegisters, th, [REGS_SET, 15, sp, start]).map_err(|_| "set the stack pointer")?;
        }
        sys(Syscall::ThreadResume, self.tasks[t].thread, [0; 4]).map(drop).map_err(|_| "start the thread")
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

    /// Whether a process maps memory file `k`'s pages.
    fn shm_mapped(&self, k: usize) -> bool {
        let s = self.shm[k];
        let pages = SHM_SLOTS + s.first as u64..SHM_SLOTS + s.first as u64 + s.pages as u64;
        self.procs.iter().any(|p| p.used && !p.zombie && p.shared[..p.nshared].iter().any(|r| pages.contains(&r.slot)))
    }

    /// Gives back the pages of memory files closed and no longer mapped.
    fn shm_sweep(&mut self) {
        for k in 0..MAX_SHM {
            if self.shm[k].used && !self.shm[k].open && !self.shm_mapped(k) {
                let s = self.shm[k];
                self.shm_take(s.first as u64, s.pages as u64, false);
                self.shm[k].used = false;
            }
        }
    }

    /// Marks shared pages [first, first + n) taken or free.
    fn shm_take(&mut self, first: u64, n: u64, taken: bool) {
        for p in first..first + n {
            let (w, b) = ((p / 64) as usize, p % 64);
            self.shm_used[w] = if taken { self.shm_used[w] | 1 << b } else { self.shm_used[w] & !(1 << b) };
        }
    }

    fn shm_free(&self, first: u64, n: u64) -> bool {
        first + n <= SHM_PAGES && (first..first + n).all(|p| self.shm_used[(p / 64) as usize] & 1 << (p % 64) == 0)
    }

    /// Memory file `k`'s bytes from `off`, at most `n`, up to its size.
    fn shm_bytes(&self, k: usize, off: u64, n: usize) -> &[u8] {
        let s = self.shm[k];
        let n = (n as u64).min(s.size.saturating_sub(off)) as usize;
        // SAFETY: the file's pages, mapped here for this server's life;
        // [off, off + n) lies within its size, so within them.
        unsafe { core::slice::from_raw_parts((SHM_VA + s.first as u64 * PAGE + off) as *const u8, n) }
    }

    /// `ftruncate` of memory file `k`: what is cut off reads as zeros
    /// if it grows again. It grows in place, or, while no process maps
    /// it, moves to pages with room.
    fn shm_resize(&mut self, k: usize, size: u64) -> Result<(), u64> {
        const EFBIG: u64 = 27;
        let s = self.shm[k];
        let base = SHM_VA + s.first as u64 * PAGE;
        let zero = |from: u64, to: u64| {
            // SAFETY: shared pages, mapped here for this server's life.
            unsafe { core::ptr::write_bytes((SHM_VA + from) as *mut u8, 0, (to - from) as usize) }
        };
        if size > SHM_PAGES * PAGE {
            return Err(EFBIG);
        }
        let need = size.div_ceil(PAGE);
        let have = s.pages as u64;
        if size < s.size {
            zero(base - SHM_VA + size, base - SHM_VA + s.size);
        }
        if need > have {
            let first = s.first as u64;
            if have > 0 && self.shm_free(first + have, need - have) {
                self.shm_take(first + have, need - have, true);
            } else {
                if have > 0 && self.shm_mapped(k) {
                    return Err(ENOMEM);
                }
                self.shm_sweep();
                let to = (0..SHM_PAGES).find(|&p| self.shm_free(p, need)).ok_or(ENOMEM)?;
                self.shm_take(to, need, true);
                if have > 0 {
                    // SAFETY: two runs of shared pages, apart (the new one
                    // was free), mapped here.
                    unsafe { core::ptr::copy_nonoverlapping(base as *const u8, (SHM_VA + to * PAGE) as *mut u8, s.size as usize) };
                    self.shm_take(first, have, false);
                }
                self.shm[k].first = to as u16;
            }
            let first = self.shm[k].first as u64;
            zero((first + have) * PAGE, (first + need) * PAGE);
            if have == 0 || self.shm[k].first != s.first {
                zero(first * PAGE + s.size, (first + have) * PAGE);
            }
            self.shm[k].pages = need as u16;
        }
        self.shm[k].size = size;
        Ok(())
    }

    /// The framebuffer's window, made (and its pages lent) the first time.
    fn fb(&mut self) -> Result<u64, u64> {
        if !self.fb_pages {
            return Err(ENODEV);
        }
        if self.fb_window != 0 {
            return Ok(self.fb_window - 1);
        }
        let ok = |m: Option<[u64; 4]>| m.filter(|m| m[0] == 0);
        let n = ok(fb_call(window::create(FB_W | FB_H << 16, FB_AT.0 | FB_AT.1 << 16), None)).ok_or(ENODEV)?[1];
        if !(0..FB_PAGES).all(|p| ok(fb_call(window::attach(n, p), Some(FB_SLOTS + p))).is_some()) {
            let _ = fb_call(window::destroy(n), None);
            return Err(ENODEV);
        }
        // Its events (the input devices') signal this server.
        let _ = fb_call(window::listen(n), Some(NTFN_WINDOW));
        self.fb_window = n + 1;
        Ok(n)
    }

    /// Shows the whole framebuffer as it is now; if the compositor
    /// restarted (and lost the window), the window is made again.
    fn fb_show(&mut self) {
        for _ in 0..2 {
            let Ok(n) = self.fb() else { return };
            if fb_call(window::commit(n, FB_W << 32 | FB_H << 48), None).is_some_and(|m| m[0] == 0) {
                if !self.fb_shown {
                    self.fb_shown = true;
                    say!("linux: /dev/fb0 shown: window {n}, {FB_W}x{FB_H} at {},{}", FB_AT.0, FB_AT.1);
                }
                return;
            }
            self.fb_window = 0;
        }
    }

    fn close(&mut self, i: usize, fd: usize) {
        let Some(f) = self.file(i, fd as u64) else { return };
        let fb = self.files[f].kind == FileKind::Node && self.fs.kind(self.files[f].ino) == Kind::Fb;
        self.procs[i].fds[fd] = 0;
        self.procs[i].cloexec &= !(1 << fd);
        self.release(f);
        if fb {
            self.fb_show();
        }
    }

    /// Drops a reference to open file `f` (a descriptor's, or a message's
    /// in flight on a Unix socket), closing it with the last.
    fn release(&mut self, f: usize) {
        let o = &mut self.files[f];
        o.refs -= 1;
        if o.refs == 0 {
            let (kind, k) = (o.kind, o.pipe as usize);
            o.kind = FileKind::Closed;
            match kind {
                FileKind::PipeRead => self.pipes[k].readers -= 1,
                FileKind::PipeWrite => self.pipes[k].writers -= 1,
                FileKind::Socket => sock::close(k),
                FileKind::Epoll => self.epolls[k].used = false,
                FileKind::Unix => self.unix_close(k),
                FileKind::Shm => {
                    self.shm[k].open = false;
                    self.shm_sweep();
                }
                _ => {}
            }
        }
    }

    /// Closes Unix socket `k`: its peer reads to the end of what it has,
    /// then sees the end, and may no longer write; connections it had yet
    /// to accept are closed, and descriptors in flight to it dropped.
    fn unix_close(&mut self, k: usize) {
        let u = &mut self.unix[k];
        let (peer, nback, backlog, nrights) = (u.peer, u.nback as usize, u.backlog, u.nrights);
        let rights = u.rights;
        u.phase = unix::Phase::Free;
        if peer != 0 {
            let p = &mut self.unix[peer as usize - 1];
            (p.peer, p.eof, p.broken) = (0, true, true);
        }
        for &s in &backlog[..nback] {
            self.unix_close(s as usize - 1);
        }
        for r in &rights[..nrights] {
            for &f in &r.files[..r.n as usize] {
                self.release(f as usize);
            }
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

/// The Unix time when the uptime was 0, from the kernel's real-time clock
/// the first time it is asked for (0 where there is none). `now` is the
/// uptime in ticks.
fn epoch(now: u64) -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EPOCH: AtomicU64 = AtomicU64::new(u64::MAX);
    match EPOCH.load(Ordering::Relaxed) {
        u64::MAX => {
            let e = superior_sys::time().map_or(0, |t| t.saturating_sub(now / TICK_HZ));
            EPOCH.store(e, Ordering::Relaxed);
            e
        }
        e => e,
    }
}

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
        Kind::Fb => 0o20660,
        Kind::Input => 0o20640,
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
        | Sys::Sendmsg
        | Sys::Recvmsg
        | Sys::Shutdown
        | Sys::Getsockname
        | Sys::Getpeername
        | Sys::Setsockopt
        | Sys::Getsockopt
        | Sys::Socketpair => net_call(st, i, call, a),
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
        Sys::Readv => readv(st, i, a[0], a[1], a[2]),
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
        Sys::Pread => r(pread(st, i, a[0], a[1], a[2], a[3])),
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
        Sys::EpollCreate => r(epoll_create(st, i, a[0])),
        Sys::EpollCtl => r(epoll_ctl(st, i, a[0], a[1], a[2], a[3])),
        Sys::EpollWait => {
            let until = if a[5] == 0 {
                let ms = a[3] as i32;
                if ms < 0 { u64::MAX } else { superior_sys::ticks() + (ms as u64 * TICK_HZ).div_ceil(1000) }
            } else if a[4] == 0 {
                u64::MAX
            } else {
                match (st.word(i, a[4]), st.word(i, a[4] + 8)) {
                    (Some(sec), Some(ns)) => superior_sys::ticks() + sec * TICK_HZ + (ns * TICK_HZ).div_ceil(1_000_000_000),
                    _ => return Ret(err(EFAULT)),
                }
            };
            epoll_wait(st, i, a[0], a[1], a[2], until)
        }
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
        Sys::MemfdCreate => r(memfd_create(st, i, a[1])),
        Sys::Ftruncate => r(st.file(i, a[0]).ok_or(EBADF).and_then(|f| {
            let o = st.files[f];
            if o.kind == FileKind::Shm {
                return st.shm_resize(o.pipe as usize, a[1]).map(|_| 0);
            }
            if o.kind != FileKind::Node || o.flags & O_ACCMODE == 0 {
                return Err(EINVAL);
            }
            st.fs.truncate(o.ino, a[1]).map(|_| 0)
        })),
        Sys::Fork => r(fork(st, t)),
        Sys::Vfork => vfork(st, t, 0),
        Sys::Clone if a[0] & CLONE_THREAD != 0 && a[0] & CLONE_VM != 0 => r(new_thread(st, t, a)),
        Sys::Clone if a[0] & CLONE_THREAD != 0 => Ret(err(ENOSYS)),
        // vfork's kind, as musl's posix_spawn makes one: see [`vfork`].
        Sys::Clone if a[0] & CLONE_VFORK != 0 => vfork(st, t, a[1]),
        // A process sharing its parent's memory without vfork's wait: a
        // copy, on the stack it was given.
        Sys::Clone if a[0] & CLONE_VM != 0 => r(fork_on(st, t, a[1], false)),
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
            // The time of day (CLOCK_REALTIME and its kin, and
            // gettimeofday) is the uptime from when it was the RTC's
            // reading; the other clocks are the uptime.
            let real = call == Sys::Gettimeofday || matches!(a[0], 0 | 5 | 8 | 11);
            let (sec, frac) = (t / TICK_HZ + if real { epoch(t) } else { 0 }, t % TICK_HZ);
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
        // Resources used (as reports its time): none counted, all zero.
        Sys::Getrusage => r(st.put(i, a[1], &[0u8; 144])),
        // The uptime, the memory a process may have (its window, the most
        // of it free), and the processes: what gcc sizes its collector by.
        Sys::Sysinfo => {
            let mut b = [0u8; 112];
            b[0..8].copy_from_slice(&(superior_sys::ticks() / TICK_HZ).to_le_bytes());
            b[32..40].copy_from_slice(&SPAN.to_le_bytes());
            b[40..48].copy_from_slice(&(SPAN / 2).to_le_bytes());
            let procs = st.procs.iter().filter(|p| p.used && !p.zombie).count() as u16;
            b[80..82].copy_from_slice(&procs.to_le_bytes());
            b[104..108].copy_from_slice(&1u32.to_le_bytes());
            r(st.put(i, a[0], &b))
        }
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
    if kind == Kind::Fb {
        st.fb()?;
    }
    // An input device: the window's events from now on.
    if kind == Kind::Input {
        st.fb()?;
        input_events(st);
        let d = st.fs.size(ino) as usize & 1;
        (st.input[d].head, st.input[d].len) = (0, 0);
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
        FileKind::Socket | FileKind::Unix => stat_bytes(0o140777, 0, 0),
        FileKind::Shm => stat_bytes(0o100600, 0, st.shm[o.pipe as usize].size),
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
    if o.kind != FileKind::Node && o.kind != FileKind::Shm {
        return Err(ESPIPE);
    }
    let size = if o.kind == FileKind::Shm { st.shm[o.pipe as usize].size } else { st.fs.size(o.ino) };
    let base = match whence {
        0 => 0,
        1 => o.off as i64,
        2 => size as i64,
        _ => return Err(EINVAL),
    };
    let to = base.checked_add(off).filter(|&t| t >= 0).ok_or(EINVAL)?;
    st.files[f].off = to as u64;
    Ok(to as u64)
}

/// `pread64`: a file's bytes from `off`, its offset left as it is (up to
/// a page at a time, as `read`).
fn pread(st: &mut State, i: usize, fd: u64, buf: u64, len: u64, off: u64) -> Result<u64, u64> {
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    if o.kind != FileKind::Node {
        return Err(ESPIPE);
    }
    if st.fs.kind(o.ino) == Kind::Dir {
        return Err(EISDIR);
    }
    if o.flags & O_ACCMODE == O_WRONLY {
        return Err(EBADF);
    }
    if (off as i64) < 0 {
        return Err(EINVAL);
    }
    let mut tmp = [0u8; 4096];
    let n = st.fs.read(o.ino, off, &mut tmp[..len.min(4096) as usize]);
    st.put(i, buf, &tmp[..n]).map(|_| n as u64)
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
            Kind::Null | Kind::Fb | Kind::Input => 2,
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
        // F_ADD_SEALS, F_GET_SEALS: a memory file's seals are taken and
        // not kept.
        1033 | 1034 if st.files[f].kind == FileKind::Shm => Ok(0),
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
            // Whole events (struct input_event), waiting for one.
            Kind::Input if want < 24 => return Out::Ret(err(EINVAL)),
            Kind::Input => {
                let d = st.fs.size(o.ino) as usize & 1;
                if st.input[d].len == 0 {
                    if o.flags & O_NONBLOCK != 0 {
                        return Out::Ret(err(EAGAIN));
                    }
                    return Out::Block(Blocked::Read { fd, buf, len });
                }
                let mut n = 0;
                while n + 24 <= want {
                    let Some((at, ty, code, value)) = st.input[d].pop() else { break };
                    let e = &mut tmp[n..n + 24];
                    e[..8].copy_from_slice(&(epoch(at) + at / TICK_HZ).to_le_bytes());
                    e[8..16].copy_from_slice(&(at % TICK_HZ * (1_000_000 / TICK_HZ)).to_le_bytes());
                    e[16..18].copy_from_slice(&ty.to_le_bytes());
                    e[18..20].copy_from_slice(&code.to_le_bytes());
                    e[20..24].copy_from_slice(&value.to_le_bytes());
                    n += 24;
                }
                n
            }
            Kind::Fb => {
                let n = want.min((FB_PAGES * PAGE).saturating_sub(o.off) as usize);
                // SAFETY: the framebuffer's pages, mapped here for this
                // server's life; n bytes from o.off lie within them.
                tmp[..n].copy_from_slice(unsafe { core::slice::from_raw_parts((FB_VA + o.off) as *const u8, n) });
                st.files[f].off += n as u64;
                n
            }
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
        FileKind::Shm => {
            let n = st.shm_bytes(o.pipe as usize, o.off, want).len();
            tmp[..n].copy_from_slice(st.shm_bytes(o.pipe as usize, o.off, want));
            st.files[f].off += n as u64;
            n
        }
        FileKind::Unix => {
            let u = &mut st.unix[o.pipe as usize];
            if u.phase != unix::Phase::Connected {
                return Out::Ret(err(ENOTCONN));
            }
            if u.len == 0 {
                if u.eof {
                    return Out::Ret(0);
                }
                if o.flags & O_NONBLOCK != 0 {
                    return Out::Ret(err(EAGAIN));
                }
                return Out::Block(Blocked::Read { fd, buf, len });
            }
            // Descriptors sent with what is read are closed.
            let (n, rights) = u.take(&mut tmp[..want]);
            if let Some(r) = rights {
                for &f in &r.files[..r.n as usize] {
                    st.release(f as usize);
                }
            }
            n
        }
        FileKind::Socket => match sock::recv(o.pipe as usize, &mut tmp[..want], false) {
            Ok(got) => got.n,
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
        FileKind::Console | FileKind::Tty | FileKind::Node | FileKind::Socket | FileKind::Unix | FileKind::Shm => {
            len.min(tmp.len() as u64) as usize
        }
        _ => return Out::Ret(err(EBADF)),
    };
    if !st.copy_in(i, buf, &mut tmp[..n]) {
        return Out::Ret(err(EFAULT));
    }
    Out::Ret(match o.kind {
        // Past its end, it grows.
        FileKind::Shm => {
            let k = o.pipe as usize;
            let end = o.off + n as u64;
            match if end > st.shm[k].size { st.shm_resize(k, end) } else { Ok(()) } {
                Ok(()) => {
                    let at = SHM_VA + st.shm[k].first as u64 * PAGE + o.off;
                    // SAFETY: the file's pages, mapped here for this
                    // server's life; [off, end) lies within its size.
                    unsafe { core::slice::from_raw_parts_mut(at as *mut u8, n) }.copy_from_slice(&tmp[..n]);
                    st.files[f].off = end;
                    n as u64
                }
                Err(e) => err(e),
            }
        }
        FileKind::Unix => match unix_send(st, i, o.pipe as usize, &tmp[..n], None, false) {
            Ok(w) => w as u64,
            Err(EAGAIN) if o.flags & O_NONBLOCK == 0 => return Out::Block(Blocked::Write { fd, buf, len }),
            Err(e) => err(e),
        },
        FileKind::Console => {
            st.output(&tmp[..n]);
            n as u64
        }
        FileKind::Tty => {
            st.tty.write(&tmp[..n]);
            n as u64
        }
        FileKind::PipeWrite => st.pipes[o.pipe as usize].put(&tmp[..n]) as u64,
        FileKind::Socket => match sock::send(o.pipe as usize, &tmp[..n], None) {
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
            Kind::Input => err(EINVAL),
            // As Linux's: up to the framebuffer's end, then ENOSPC.
            Kind::Fb if o.off >= FB_PAGES * PAGE => err(ENOSPC),
            Kind::Fb => {
                let n = n.min((FB_PAGES * PAGE - o.off) as usize);
                // SAFETY: as for reading it.
                unsafe { core::slice::from_raw_parts_mut((FB_VA + o.off) as *mut u8, n) }.copy_from_slice(&tmp[..n]);
                st.files[f].off += n as u64;
                st.fb_show();
                n as u64
            }
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

/// `readv`: [`read`] into each buffer in turn, until one is not filled.
/// Waiting, it waits as a `read` into the first.
fn readv(st: &mut State, i: usize, fd: u64, iov: u64, cnt: u64) -> Out {
    let mut total = 0;
    for k in 0..cnt.min(64) {
        let (Some(base), Some(len)) = (st.word(i, iov + 16 * k), st.word(i, iov + 16 * k + 8)) else {
            return Out::Ret(err(EFAULT));
        };
        if len == 0 {
            continue;
        }
        match read(st, i, fd, base, len) {
            Out::Ret(v) if (v as i64) < 0 => return Out::Ret(if total > 0 { total } else { v }),
            Out::Ret(v) => {
                total += v;
                if v < len {
                    break;
                }
            }
            Out::Block(_) if total == 0 => return Out::Block(Blocked::Read { fd, buf: base, len }),
            _ => break,
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
    let i = st.mem(i);
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
        return mmap_file(st, i, addr, len, a[2], flags & MAP_FIXED != 0, a[4], a[5]);
    }
    let i = st.mem(i);
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
    let i = st.mem(i);
    for va in (addr.max(CHILD)..end.min(CHILD_END)).step_by(PAGE as usize) {
        st.set_reserved(i, va, false);
        st.unmap_private(i, va);
    }
    Ok(0)
}

/// Maps `len` bytes of pages that are shared (here at `ptr`, in slots from
/// `slot`) in process `i`, at `addr` if `fixed`: where.
#[allow(clippy::too_many_arguments)]
fn map_run(st: &mut State, i: usize, addr: u64, len: u64, fixed: bool, ptr: u64, slot: u64, flags: u64) -> Result<u64, u64> {
    let i = st.mem(i);
    if st.procs[i].nshared == st.procs[i].shared.len() {
        return Err(ENOMEM);
    }
    let at = if fixed { addr } else { st.place(i, len)? };
    if at % PAGE != 0 || at < CHILD || at + len > STACK_TOP - STACK_PAGES * PAGE {
        return Err(ENOMEM);
    }
    for page in (at..at + len).step_by(PAGE as usize) {
        st.set_reserved(i, page, false);
        st.unmap_private(i, page);
    }
    let p = &mut st.procs[i];
    p.shared[p.nshared] = Shared { start: at, end: at + len, ptr, slot, flags };
    p.nshared += 1;
    Ok(at)
}

/// `memfd_create(name, flags)`: an empty memory file (`MFD_CLOEXEC`
/// honoured; seals allowed, and not kept).
fn memfd_create(st: &mut State, i: usize, flags: u64) -> Result<u64, u64> {
    if !st.shm_pages {
        return Err(ENOMEM);
    }
    st.shm_sweep();
    let k = st.shm.iter().position(|s| !s.used).ok_or(ENFILE)?;
    let f = st.new_file(FileKind::Shm, 0, k as u8, O_RDWR).ok_or(ENFILE)?;
    st.shm[k] = Shm { used: true, open: true, first: 0, pages: 0, size: 0 };
    st.new_fd(i, f, 0, flags & 1 != 0).inspect_err(|_| st.release(f))
}

/// `mmap` of a file (private: what the process writes stays its own).
/// Unpacks the toolchain's archive (ustar: files, directories, symbolic
/// links) into the tree.
fn unpack(fs: &mut Fs, mut tar: &[u8]) -> Result<(), &'static str> {
    let octal = |f: &[u8]| f.iter().take_while(|&&b| b.is_ascii_digit()).fold(0usize, |v, &b| v * 8 + (b - b'0') as usize);
    fn name(f: &[u8]) -> &[u8] {
        &f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())]
    }
    while tar.len() >= 512 && tar[0] != 0 {
        let (header, rest) = tar.split_at(512);
        let size = octal(&header[124..136]);
        let data = rest.get(..size).ok_or("the toolchain's archive is cut short")?;
        let path = name(&header[..100]);
        let made = match header[156] {
            b'0' | 0 => fs.add(path, data, false),
            b'2' => fs.add(path, name(&header[157..257]), true),
            _ => Ok(()),
        };
        made.map_err(|_| "no room for the toolchain's files")?;
        tar = &rest[size.next_multiple_of(512).min(rest.len())..];
    }
    Ok(())
}

/// What `exec` runs: a bundle file, or a file of the tree (its inode and
/// length, and how much of it is in the buffer).
#[derive(Clone, Copy)]
enum Prog {
    Image(usize),
    File { ino: u16, len: u64, head: usize },
}

/// What [`State::load`] loads: a bundle file (its bytes, mapped here, and
/// its first page's slot), or a file of the tree, its first bytes (`head`)
/// at hand and the rest read as it is loaded.
#[derive(Clone, Copy)]
enum Src {
    Bundle { bytes: &'static [u8], slot: u64 },
    Tree { head: &'static [u8], ino: u16, len: u64 },
}

impl Src {
    fn elf(self) -> Result<Elf<'static>, superior_objects::elf::ElfError> {
        match self {
            Src::Bundle { bytes, .. } => Elf::parse(bytes),
            Src::Tree { head, len, .. } => Elf::parse_head(head, len),
        }
    }
}

/// A bundle file that is an ELF image, mapped from its start where the
/// process chooses not, is a library musl's dynamic linker is loading: it
/// is loaded as the program loader loads one (code and read-only data the
/// file's own pages, shared; data a copy), and the linker's mappings of
/// its segments into that span after are already there. Any other
/// mapping of a bundle file that cannot be written (code, read-only data)
/// is the file's own pages, shared, as glibc's dynamic linker maps a
/// library's code over the span it reserved for it. Anything else is a
/// copy of the file's bytes in pages of the process's own.
#[allow(clippy::too_many_arguments)]
fn mmap_file(st: &mut State, i: usize, addr: u64, len: u64, prot: u64, fixed: bool, fd: u64, off: u64) -> Result<u64, u64> {
    const PROT_WRITE: u64 = 2;
    const PROT_EXEC: u64 = 4;
    let f = st.file(i, fd).ok_or(EBADF)?;
    let o = st.files[f];
    if off % PAGE != 0 {
        return Err(EINVAL);
    }
    // A memory file: its pages, shared (writable if so mapped), as far
    // as it has them.
    if o.kind == FileKind::Shm {
        let s = st.shm[o.pipe as usize];
        if off.checked_add(len).is_none_or(|e| e > s.pages as u64 * PAGE) {
            return Err(ENXIO);
        }
        let flags = if prot & PROT_WRITE != 0 { MAP_WRITE } else { 0 };
        let first = s.first as u64 + off / PAGE;
        return map_run(st, i, addr, len, fixed, SHM_VA + first * PAGE, SHM_SLOTS + first, flags);
    }
    if o.kind != FileKind::Node || st.fs.kind(o.ino) == Kind::Dir {
        return Err(ENODEV);
    }
    // The framebuffer: its own pages, shared.
    if st.fs.kind(o.ino) == Kind::Fb {
        if off.checked_add(len).is_none_or(|e| e > FB_PAGES * PAGE) {
            return Err(EINVAL);
        }
        return map_run(st, i, addr, len, fixed, FB_VA + off, FB_SLOTS + off / PAGE, MAP_WRITE);
    }
    let i = st.mem(i);
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
            st.load(i, Src::Bundle { bytes, slot }, at - lowest).map_err(|_| ENOMEM)?;
            let p = &mut st.procs[i];
            if p.nlibs < p.libs.len() {
                p.libs[p.nlibs] = (at, at + len, o.ino);
                p.nlibs += 1;
            }
            return Ok(at);
        }
    }
    // So too a library in a file of the tree (gcc's linker plugin, which
    // ld loads): its first page read into the exec buffer for its headers,
    // then loaded as a program in a file is, code into pages of code.
    if let (None, false, 0, Kind::File) = (st.fs.image(o.ino), fixed, off, st.fs.kind(o.ino)) {
        let flen = st.fs.size(o.ino);
        let want = flen.min(EXEC_PAGES * PAGE) as usize;
        // SAFETY: the buffer's EXEC_PAGES pages, mapped writable here for
        // this server's life; used by one exec or mmap at a time.
        let buf = unsafe { core::slice::from_raw_parts_mut(EXEC_VA as *mut u8, want) };
        let mut n = 0;
        while n < want {
            let got = st.fs.read(o.ino, n as u64, &mut buf[n..]);
            if got == 0 {
                break;
            }
            n += got;
        }
        if let Some(elf) = Elf::parse_head(&buf[..n], flen).ok().filter(|e| e.pie && e.machine == MACHINE) {
            let lowest = elf.segments().flatten().map(|s| s.vaddr & !(PAGE - 1)).min().unwrap_or(0);
            let at = reserve(st)?;
            // SAFETY: the n bytes just read into the buffer.
            let head = unsafe { core::slice::from_raw_parts(EXEC_VA as *const u8, n) };
            st.load(i, Src::Tree { head, ino: o.ino, len: flen }, at - lowest).map_err(|_| ENOMEM)?;
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
    // What was there goes (MAP_FIXED): pages of its own, reserved ones.
    for page in (at..at + len).step_by(PAGE as usize) {
        st.set_reserved(i, page, false);
    }
    if let Some(k) = st.fs.image(o.ino).filter(|_| prot & PROT_WRITE == 0) {
        let Img { bytes, slot } = st.images[k];
        // Up to the file's end, as Linux maps it (past it, an access faults).
        let n = len.min((bytes.len() as u64).saturating_sub(off));
        if n > 0 && st.procs[i].nshared < st.procs[i].shared.len() {
            for page in (at..at + len).step_by(PAGE as usize) {
                st.unmap_private(i, page);
            }
            let run = Shared {
                start: at,
                end: at + n,
                ptr: bytes.as_ptr() as u64 + off,
                slot: slot + off / PAGE,
                flags: if prot & PROT_EXEC != 0 { MAP_EXEC } else { 0 },
            };
            let p = &mut st.procs[i];
            p.shared[p.nshared] = run;
            p.nshared += 1;
            return Ok(at);
        }
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
/// `vfork`, or `clone` with `CLONE_VFORK`: a new process (onto stack
/// `sp`, if not 0) with a thread of its own in its parent's memory, which
/// it borrows, as Linux's does: what it writes there before it execs (or
/// ends) its parent sees, and its parent waits until then.
fn vfork(st: &mut State, t: usize, sp: u64) -> Out {
    match fork_on(st, t, sp, true) {
        // The child runs once this server next waits: not yet.
        Ok(pid) => Out::Block(Blocked::Vfork { pid: pid as u32 }),
        Err(e) => Out::Ret(err(e)),
    }
}

fn fork(st: &mut State, t: usize) -> Result<u64, u64> {
    fork_on(st, t, 0, false)
}

/// `fork`, the child's stack pointer `sp` (if not 0); with `borrow`, a
/// `vfork`: the child's thread in the parent's memory, not a copy.
fn fork_on(st: &mut State, t: usize, sp: u64, borrow: bool) -> Result<u64, u64> {
    let i = st.tasks[t].proc as usize;
    // The memory copied, or borrowed: the parent's (itself perhaps a
    // vfork child's, borrowed).
    let m = st.mem(i);
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
    if borrow {
        // Its thread only, in its own span (from 1, as a space's would be).
        st.procs[c].mem = m as u8;
        st.procs[c].vfork = true;
        st.procs[c].cursor = 1;
        if st.make_thread(ct).is_err() {
            return fail(st, ENOMEM);
        }
    } else if st.make_space(c, ct).is_err() {
        return fail(st, ENOMEM);
    }
    for k in 0..CHILD_PAGES {
        if borrow || st.procs[m].present[k / 64] & (1 << (k % 64)) == 0 {
            continue;
        }
        let va = CHILD + k as u64 * PAGE;
        let from = va - CHILD + MIRROR + m as u64 * SPAN;
        if st.is_code(m, va) {
            // SAFETY: a whole page mapped in the mirror.
            let bytes = unsafe { core::slice::from_raw_parts(from as *const u8, PAGE as usize) };
            if st.map_code(c, va, bytes).is_err() {
                return fail(st, ENOMEM);
            }
            continue;
        }
        if st.map_private(c, va).is_err() {
            return fail(st, ENOMEM);
        }
        let to = va - CHILD + MIRROR + c as u64 * SPAN;
        // SAFETY: both are whole pages mapped in the mirrors.
        unsafe { core::ptr::copy_nonoverlapping(from as *const u8, to as *mut u8, PAGE as usize) };
    }
    if !borrow {
        st.procs[c].reserved = st.procs[m].reserved;
        (st.procs[c].shared, st.procs[c].nshared) = (st.procs[m].shared, st.procs[m].nshared);
        (st.procs[c].libs, st.procs[c].nlibs) = (st.procs[m].libs, st.procs[m].nlibs);
    }
    let (fds, cloexec, cwd) = (st.procs[i].fds, st.procs[i].cloexec, st.procs[i].cwd);
    let (b0, b1) = (st.procs[m].brk_start, st.procs[m].brk);
    for &f in fds.iter().filter(|&&f| f != 0) {
        st.files[f as usize - 1].refs += 1;
    }
    let (pgid, sid, actions) = (st.procs[i].pgid, st.procs[i].sid, st.procs[i].actions);
    let p = &mut st.procs[c];
    (p.fds, p.cloexec, p.cwd, p.brk_start, p.brk) = (fds, cloexec, cwd, b0, b1);
    (p.pgid, p.sid, p.actions) = (pgid, sid, actions);
    st.tasks[ct].mask = st.tasks[t].mask;
    let started = st.configure(ct, CHILD + PAGE, CHILD + 2 * PAGE, Some(t)).ok().and_then(|_| {
        let th = st.tasks[ct].thread;
        if sp != 0 {
            // Its stack, and the pc the registers' copy already has.
            let r = sys(Syscall::ThreadRegisters, th, [REGS_GET, signal::SP as u64, 0, 0]).ok()?;
            sys(Syscall::ThreadRegisters, th, [REGS_SET, signal::SP as u64, sp, r[1]]).ok()?;
        }
        sys(Syscall::ThreadResume, th, [0; 4]).ok()
    });
    if started.is_none() {
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
        (Some(k), _) => Prog::Image(k),
        (None, Kind::Dir) => return Err(EACCES),
        // A program in a file of the tree (one a compiler made, say): its
        // first page read into the buffer, for its headers, the rest as it
        // is loaded; else not one to run here (a shell runs a script so
        // refused itself).
        (None, Kind::File) => {
            let len = st.fs.size(ino);
            let want = len.min(EXEC_PAGES * PAGE) as usize;
            // SAFETY: the buffer's EXEC_PAGES pages, mapped writable here
            // for this server's life; only exec uses them.
            let buf = unsafe { core::slice::from_raw_parts_mut(EXEC_VA as *mut u8, want) };
            let mut n = 0;
            while n < want {
                let got = st.fs.read(ino, n as u64, &mut buf[n..]);
                if got == 0 {
                    break;
                }
                n += got;
            }
            // Refused now, while the old program is still there: a file
            // not for this machine, or one cut short of its segments.
            if Elf::parse_head(&buf[..n], len).map_or(true, |e| e.machine != MACHINE || e.segments().any(|s| s.is_err())) {
                return Err(ENOEXEC);
            }
            Prog::File { ino, len, head: n }
        }
        _ => return Err(ENOEXEC),
    };
    st.exec_args.clear();
    st.exec_env.clear();
    for (env, at) in [(false, argv), (true, envp)] {
        if at == 0 {
            continue;
        }
        for k in 0.. {
            let ptr = st.word(i, at + 8 * k).ok_or(EFAULT)?;
            if ptr == 0 {
                break;
            }
            let mut s = [0u8; MAX_STR];
            let len = st.cstr(i, ptr, &mut s).map_err(|_| E2BIG)?;
            let list = if env { &mut st.exec_env } else { &mut st.exec_args };
            if !list.push(&s[..len]) {
                return Err(E2BIG);
            }
        }
    }
    // Past here there is no going back: the old program is gone (and a
    // vfork parent goes on).
    st.procs[i].vfork = false;
    st.procs[i].mem = i as u8;
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
    if let Err(why) = st.exec(t, image, &name[..n]) {
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
    // A mapped framebuffer, shown as it is drawn.
    let fb_mapped = st.procs.iter().any(|p| {
        p.used && !p.zombie && p.shared[..p.nshared].iter().any(|s| (FB_SLOTS..FB_SLOTS + FB_PAGES).contains(&s.slot))
    });
    if fb_mapped && now >= st.fb_next {
        st.fb_show();
        st.fb_next = now + FB_PERIOD;
    }
    for i in 0..MAX_PROCS {
        let p = &mut st.procs[i];
        if p.used && !p.zombie && p.alarm != 0 && now >= p.alarm {
            p.alarm = if p.alarm_every != 0 { now + p.alarm_every } else { 0 };
            st.post(i, SIGALRM);
        }
    }
    loop {
        let mut moved = false;
        // Wayland clients' requests, which may answer what others wait for.
        moved |= wl::service(st);
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
                Blocked::EpollWait { fd, events, max, until } => epoll_wait(st, i, fd, events, max, until),
                Blocked::Net { call, a } => net_call(st, i, call, a),
                Blocked::Vfork { pid } if st.procs.iter().any(|p| p.used && !p.zombie && p.pid == pid && p.vfork) => Out::Block(blocked),
                Blocked::Vfork { pid } => Out::Ret(pid as u64),
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
            // A vfork parent takes signals once its child has exec'd or
            // ended, as Linux's waits (it cannot fail the call: the child
            // is there).
            if let Blocked::Vfork { .. } = blocked {
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
            Blocked::Poll { until, .. } | Blocked::EpollWait { until, .. } | Blocked::Futex { until, .. } if until != u64::MAX => Some(until),
            _ => None,
        })
        .chain(st.procs.iter().filter(|p| p.used && !p.zombie && p.alarm != 0).map(|p| p.alarm))
        .chain(fb_mapped.then_some(st.fb_next))
        .min();
    let ticks = next.map_or(0, |until| until.saturating_sub(superior_sys::ticks()).max(1));
    // A call waiting on a socket: tried again every tick (this server
    // waits on its one notification, not the sockets').
    let on_socket = sock::any_open()
        && st.tasks.iter().any(|t| {
            t.used
                && matches!(
                    t.blocked,
                    Blocked::Read { .. }
                        | Blocked::Write { .. }
                        | Blocked::Writev { .. }
                        | Blocked::Poll { .. }
                        | Blocked::EpollWait { .. }
                        | Blocked::Net { .. }
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
    st.exec_args.clear();
    st.exec_env.clear();
    argv.iter().for_each(|a| _ = st.exec_args.push(a.as_bytes()));
    env.iter().for_each(|e| _ = st.exec_env.push(e.as_bytes()));
    let execfn = [b"/bin/" as &[u8], argv[0].as_bytes()].concat_into::<64>();
    let image = st.fs.resolve(ROOT, execfn.as_slice(), true).ok().and_then(|ino| st.fs.image(ino));
    let started = match image {
        Some(k) => st.exec(t, Prog::Image(k), execfn.as_slice()),
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
            if r.badge & 4 != 0 {
                input_events(st);
                wl::window_events(st);
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
        // Made by another thread meanwhile, unless it faults there again:
        // then it is the access that is refused (say, running code in a
        // page of its own, which is never executable).
        let made = |st: &State| {
            (CHILD..CHILD_END).contains(&nr) && st.is_present(i, nr & !(PAGE - 1)) && st.tasks[t].last_fault != nr
        };
        // Or a shared run's page, mapped on its first touch (a second
        // fault there is the access refused).
        if page_fault && (made(st) || st.take_reserved(i, nr) || st.tasks[t].last_fault != nr && st.take_shared(i, nr)) {
            st.tasks[t].last_fault = nr;
            syscall(Syscall::Reply, 0, [FaultReply::Retry as u64, 0, 0, 0]);
            continue;
        }
        st.tasks[t].last_fault = 0;
        if r.status != 0 || FaultKind::from_u64(kind) != Some(FaultKind::ForeignSyscall) {
            st.flush();
            let (what, signal) = match FaultKind::from_u64(kind) {
                Some(FaultKind::PageFault) => ("page fault", 11),
                Some(FaultKind::InvalidOpcode) => ("invalid instruction", 4),
                Some(FaultKind::DivideError) => ("arithmetic fault", 8),
                _ => ("general protection fault", 11),
            };
            // A handler the program set for it, and not blocked: entered,
            // at the faulting instruction (OpenSSL tries instructions so,
            // catching SIGILL, to learn the CPU's features).
            let handler = st.procs[i].actions[signal as usize - 1].handler;
            if handler > signal::SIG_IGN && st.tasks[t].mask & signal::bit(signal) == 0 {
                if let Some((at, v)) = st.enter_handler(t, signal, pc, None) {
                    syscall(Syscall::Reply, 0, [FaultReply::ResumeAt as u64, at, v, 0]);
                    continue;
                }
            }
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
/// epoll instances, and what each watches.
const MAX_EPOLLS: usize = 16;
const MAX_WATCHED: usize = 64;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLL_CLOEXEC: u64 = 0o2000000;
/// The size of a `struct epoll_event`: packed on x86-64 (events, then
/// the data at 4), not on AArch64 (the data at 8).
const EPOLL_EVENT: u64 = if cfg!(target_arch = "x86_64") { 12 } else { 16 };
const EPOLL_DATA: usize = if cfg!(target_arch = "x86_64") { 4 } else { 8 };

/// An epoll instance: the descriptors it watches, each with the open file
/// it named when added (a descriptor closed, or now naming another file,
/// is dropped), the events wanted and the data given back.
#[derive(Clone, Copy)]
struct Epoll {
    used: bool,
    n: usize,
    watched: [Watched; MAX_WATCHED],
}

#[derive(Clone, Copy)]
struct Watched {
    fd: u32,
    file: u8,
    events: u32,
    data: u64,
}

/// `epoll_create1` (and `epoll_create`, whose size is only checked):
/// a new instance, watching nothing.
fn epoll_create(st: &mut State, i: usize, flags: u64) -> Result<u64, u64> {
    let k = st.epolls.iter().position(|e| !e.used).ok_or(ENFILE)?;
    let f = st.new_file(FileKind::Epoll, 0, k as u8, 0).ok_or(ENFILE)?;
    st.epolls[k].used = true;
    st.epolls[k].n = 0;
    st.new_fd(i, f, 0, flags & EPOLL_CLOEXEC != 0).inspect_err(|_| {
        st.files[f].kind = FileKind::Closed;
        st.epolls[k].used = false;
    })
}

/// The epoll instance descriptor `epfd` names.
fn epoll_of(st: &State, i: usize, epfd: u64) -> Result<usize, u64> {
    let f = st.file(i, epfd).ok_or(EBADF)?;
    match st.files[f] {
        o if o.kind == FileKind::Epoll => Ok(o.pipe as usize),
        _ => Err(EINVAL),
    }
}

/// `epoll_ctl`: `fd` added to (1), removed from (2) or changed in (3)
/// what instance `epfd` watches, with the `struct epoll_event` at `ev`.
fn epoll_ctl(st: &mut State, i: usize, epfd: u64, op: u64, fd: u64, ev: u64) -> Result<u64, u64> {
    const ADD: u64 = 1;
    const DEL: u64 = 2;
    const MOD: u64 = 3;
    let k = epoll_of(st, i, epfd)?;
    let f = st.file(i, fd).ok_or(EBADF)?;
    // A file on the disk is always ready: Linux refuses to watch one.
    if fd == epfd || st.files[f].kind == FileKind::Node {
        return Err(if fd == epfd { EINVAL } else { EPERM });
    }
    let mut e = [0u8; 16];
    if op != DEL && !st.copy_in(i, ev, &mut e[..EPOLL_EVENT as usize]) {
        return Err(EFAULT);
    }
    let events = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
    let data = u64::from_le_bytes(e[EPOLL_DATA..EPOLL_DATA + 8].try_into().unwrap_or([0; 8]));
    let ep = &mut st.epolls[k];
    let at = ep.watched[..ep.n].iter().position(|w| w.fd as u64 == fd && w.file as usize == f);
    match (op, at) {
        (ADD, Some(_)) => Err(EEXIST),
        (ADD, None) if ep.n == MAX_WATCHED => Err(ENOSPC),
        (ADD, None) => {
            ep.watched[ep.n] = Watched { fd: fd as u32, file: f as u8, events, data };
            ep.n += 1;
            Ok(0)
        }
        (MOD, Some(w)) => {
            (ep.watched[w].events, ep.watched[w].data) = (events, data);
            Ok(0)
        }
        (DEL, Some(w)) => {
            ep.watched[w] = ep.watched[ep.n - 1];
            ep.n -= 1;
            Ok(0)
        }
        (MOD | DEL, None) => Err(ENOENT),
        _ => Err(EINVAL),
    }
}

/// `epoll_wait`: up to `max` of what instance `epfd` watches that is
/// ready, written to `events`; or, if none is, a wait until one is or the
/// tick `until`. Level-triggered (`EPOLLET` is taken as level: a program
/// that reads until `EAGAIN`, as one using it must, sees no difference);
/// `EPOLLONESHOT` turns a descriptor off once reported.
fn epoll_wait(st: &mut State, i: usize, epfd: u64, events: u64, max: u64, until: u64) -> Out {
    if max == 0 || max > MAX_WATCHED as u64 * 4 {
        return Out::Ret(err(EINVAL));
    }
    let k = match epoll_of(st, i, epfd) {
        Ok(k) => k,
        Err(e) => return Out::Ret(err(e)),
    };
    // Descriptors closed, or naming another file now, are dropped.
    let mut w = 0;
    while w < st.epolls[k].n {
        let x = st.epolls[k].watched[w];
        if st.file(i, x.fd as u64) != Some(x.file as usize) {
            let ep = &mut st.epolls[k];
            ep.watched[w] = ep.watched[ep.n - 1];
            ep.n -= 1;
            continue;
        }
        w += 1;
    }
    let mut got = 0;
    for w in 0..st.epolls[k].n {
        if got == max {
            break;
        }
        let x = st.epolls[k].watched[w];
        let ready = readiness(st, x.file as usize) as u32 & (x.events | POLLERR as u32 | POLLHUP as u32);
        if ready == 0 {
            continue;
        }
        let mut e = [0u8; 16];
        e[..4].copy_from_slice(&ready.to_le_bytes());
        e[EPOLL_DATA..EPOLL_DATA + 8].copy_from_slice(&x.data.to_le_bytes());
        if !st.copy_out(i, events + got * EPOLL_EVENT, &e[..EPOLL_EVENT as usize]) {
            return Out::Ret(err(EFAULT));
        }
        if x.events & EPOLLONESHOT != 0 {
            st.epolls[k].watched[w].events = 0;
        }
        got += 1;
    }
    if got > 0 || superior_sys::ticks() >= until {
        return Out::Ret(got);
    }
    Out::Block(Blocked::EpollWait { fd: epfd, events, max, until })
}

/// `poll`'s (and epoll's) readiness bits.
const POLLIN: u16 = 1;
const POLLOUT: u16 = 4;
const POLLERR: u16 = 8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;

/// Which of `POLLIN`, `POLLOUT`, `POLLERR` and `POLLHUP` open file `f`
/// is now: what `poll` and `epoll_wait` report (epoll's bits are the
/// same).
fn readiness(st: &State, f: usize) -> u16 {
    let o = st.files[f];
    match o.kind {
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
        // An epoll instance is readable when something it watches is
        // ready (one instance inside another is not followed further).
        FileKind::Epoll => 0,
        FileKind::Unix => {
            let u = &st.unix[o.pipe as usize];
            match u.phase {
                unix::Phase::Listening => if u.nback > 0 { POLLIN } else { 0 },
                unix::Phase::Connected => {
                    let room = u.peer != 0 && st.unix[u.peer as usize - 1].room() > 0;
                    (if u.len > 0 || u.eof { POLLIN } else { 0 })
                        | (if room { POLLOUT } else { 0 })
                        | if u.broken { POLLHUP } else { 0 }
                }
                _ => POLLOUT | POLLHUP,
            }
        }
        FileKind::Node if st.fs.kind(o.ino) == Kind::Input => {
            if st.input[st.fs.size(o.ino) as usize & 1].len > 0 { POLLIN } else { 0 }
        }
        _ => POLLIN | POLLOUT,
    }
}

fn poll(st: &mut State, i: usize, fds: u64, n: u64, until: u64) -> Out {
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
            match st.file(i, fd as u64) {
                None => POLLNVAL,
                Some(f) => readiness(st, f),
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

/// The address in the `sockaddr_in` or `sockaddr_in6` at `addr`.
fn sockaddr(st: &State, i: usize, addr: u64, len: u64) -> Result<sock::Addr, u64> {
    const EAFNOSUPPORT: u64 = 97;
    let mut b = [0u8; 24];
    let n = (len as usize).min(b.len());
    if n < 2 || !st.copy_in(i, addr, &mut b[..n]) {
        return Err(if n < 2 { EINVAL } else { EFAULT });
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    match u16::from_le_bytes([b[0], b[1]]) as u64 {
        sock::AF_INET if n >= 16 => Ok(sock::Addr::v4([b[4], b[5], b[6], b[7]], port)),
        sock::AF_INET6 if n >= 24 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[8..24]);
            Ok(sock::Addr { ip, port })
        }
        sock::AF_INET | sock::AF_INET6 => Err(EINVAL),
        _ => Err(EAFNOSUPPORT),
    }
}

/// `a` as socket `k`'s family's address at `addr` (if any): a
/// `sockaddr_in`, or a `sockaddr_in6` (an IPv4 address mapped), cut to
/// the length at `lenp`, which then says its whole length.
fn put_sockaddr(st: &mut State, i: usize, k: usize, a: sock::Addr, addr: u64, lenp: u64) -> Result<(), u64> {
    if addr == 0 {
        return Ok(());
    }
    let mut l = [0u8; 4];
    if !st.copy_in(i, lenp, &mut l) {
        return Err(EFAULT);
    }
    let mut b = [0u8; 28];
    let len = match a.ipv4() {
        Some(ip) if sock::get(k).family == sock::AF_INET => {
            b[..2].copy_from_slice(&(sock::AF_INET as u16).to_le_bytes());
            b[4..8].copy_from_slice(&ip);
            16
        }
        _ => {
            b[..2].copy_from_slice(&(sock::AF_INET6 as u16).to_le_bytes());
            b[8..24].copy_from_slice(&a.ip);
            28
        }
    };
    b[2..4].copy_from_slice(&a.port.to_be_bytes());
    let n = (u32::from_le_bytes(l) as usize).min(len);
    st.put(i, addr, &b[..n])?;
    st.put(i, lenp, &(len as u32).to_le_bytes()).map(|_| ())
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

/// A `msghdr`'s fields: the name and its length's address, the `iovec`s
/// and their count.
struct Msg {
    name: u64,
    namelen: u64,
    iov: u64,
    iovlen: u64,
}

fn msghdr(st: &State, i: usize, at: u64) -> Result<Msg, u64> {
    let w = |o: u64| st.word(i, at + o).ok_or(EFAULT);
    Ok(Msg { name: w(0)?, namelen: at + 8, iov: w(16)?, iovlen: w(24)?.min(64) })
}

/// The `iovec`s' bytes, gathered into `out` (as many as fit).
fn gather(st: &State, i: usize, iov: u64, cnt: u64, out: &mut [u8]) -> Result<usize, u64> {
    let mut n = 0;
    for k in 0..cnt {
        let (base, len) = (st.word(i, iov + 16 * k).ok_or(EFAULT)?, st.word(i, iov + 16 * k + 8).ok_or(EFAULT)?);
        let take = (len as usize).min(out.len() - n);
        if !st.copy_in(i, base, &mut out[n..n + take]) {
            return Err(EFAULT);
        }
        n += take;
    }
    Ok(n)
}

/// `data` scattered into the `iovec`s.
fn scatter(st: &mut State, i: usize, iov: u64, cnt: u64, mut data: &[u8]) -> Result<(), u64> {
    for k in 0..cnt {
        if data.is_empty() {
            break;
        }
        let (base, len) = (st.word(i, iov + 16 * k).ok_or(EFAULT)?, st.word(i, iov + 16 * k + 8).ok_or(EFAULT)?);
        let n = (len as usize).min(data.len());
        st.put(i, base, &data[..n])?;
        data = &data[n..];
    }
    Ok(())
}

/// The socket calls: TCP, UDP and ping sockets over IPv4 and IPv6, the
/// network server's ([`sock`]). One that must wait, on a descriptor
/// without `O_NONBLOCK` (or a send or receive without `MSG_DONTWAIT`),
/// waits.
fn net_call(st: &mut State, i: usize, call: Sys, a: [u64; 6]) -> Out {
    const EPROTONOSUPPORT: u64 = 93;
    const EAFNOSUPPORT: u64 = 97;
    const SOCK_RAW: u64 = 3;
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_NOSIGNAL: u64 = 0x4000;
    let r = |v: Result<u64, u64>| Out::Ret(v.unwrap_or_else(err));
    if call == Sys::Socket && a[0] == unix::AF_UNIX || call == Sys::Socketpair {
        return unix_socket(st, i, call, a);
    }
    if call != Sys::Socket {
        if let Some(f) = st.file(i, a[0]).filter(|&f| st.files[f].kind == FileKind::Unix) {
            return unix_call(st, i, f, call, a);
        }
    }
    if call == Sys::Socket {
        if a[0] != sock::AF_INET && a[0] != sock::AF_INET6 {
            return Out::Ret(err(EAFNOSUPPORT));
        }
        let icmp = if a[0] == sock::AF_INET { 1 } else { 58 };
        let proto = match (a[1] & 0xf, a[2]) {
            (sock::SOCK_STREAM, 0 | 6) => sock::Proto::Tcp,
            (sock::SOCK_DGRAM, 0 | 17) => sock::Proto::Udp,
            // A ping socket, as Linux gives unprivileged programs.
            (sock::SOCK_DGRAM, p) if p == icmp => sock::Proto::Echo,
            // Raw sockets are for the privileged: ping falls back to the
            // kind above.
            (SOCK_RAW, _) => return Out::Ret(err(EPERM)),
            _ => return Out::Ret(err(EPROTONOSUPPORT)),
        };
        return r(sock::socket(a[0], proto).and_then(|k| new_socket(st, i, k, a[1])));
    }
    let (k, flags) = match sock_of(st, i, a[0]) {
        Ok(s) => s,
        Err(e) => return Out::Ret(err(e)),
    };
    let wait = |dontwait: bool, e: u64| e == sock::EAGAIN && flags & O_NONBLOCK == 0 && !dontwait;
    match call {
        Sys::Bind => r(sockaddr(st, i, a[1], a[2]).and_then(|w| sock::bind(k, w.port)).map(|_| 0)),
        Sys::Listen => r(sock::listen(k).map(|_| 0)),
        Sys::Connect => match sockaddr(st, i, a[1], a[2]).and_then(|w| sock::connect(k, w)) {
            Ok(()) => Out::Ret(0),
            Err(sock::EINPROGRESS) if flags & O_NONBLOCK == 0 => Out::Block(Blocked::Net { call, a }),
            Err(e) => Out::Ret(err(e)),
        },
        Sys::Accept => match sock::accept(k) {
            Ok(c) => {
                let peer = sock::get(c).peer.unwrap_or(sock::Addr::NONE);
                match new_socket(st, i, c, a[3]) {
                    Ok(fd) => r(put_sockaddr(st, i, c, peer, a[1], a[2]).map(|_| fd)),
                    Err(e) => Out::Ret(err(e)),
                }
            }
            Err(e) if wait(false, e) => Out::Block(Blocked::Net { call, a }),
            Err(e) => Out::Ret(err(e)),
        },
        // `sendto(fd, buf, len, flags, addr, addrlen)`, or `sendmsg(fd,
        // msg, flags)`.
        Sys::Sendto | Sys::Sendmsg => {
            let mut tmp = [0u8; 4096];
            let (n, name, namelen, mflags) = if call == Sys::Sendto {
                let n = a[2].min(tmp.len() as u64) as usize;
                if !st.copy_in(i, a[1], &mut tmp[..n]) {
                    return Out::Ret(err(EFAULT));
                }
                (n, a[4], a[5], a[3])
            } else {
                let m = match msghdr(st, i, a[1]) {
                    Ok(m) => m,
                    Err(e) => return Out::Ret(err(e)),
                };
                let n = match gather(st, i, m.iov, m.iovlen, &mut tmp) {
                    Ok(n) => n,
                    Err(e) => return Out::Ret(err(e)),
                };
                let len = st.word(i, m.namelen).unwrap_or(0) as u32 as u64;
                (n, m.name, len, a[2])
            };
            let to = if name != 0 && sock::get(k).proto != sock::Proto::Tcp {
                match sockaddr(st, i, name, namelen) {
                    Ok(w) => Some(w),
                    Err(e) => return Out::Ret(err(e)),
                }
            } else {
                None
            };
            match sock::send(k, &tmp[..n], to) {
                Ok(w) => Out::Ret(w as u64),
                Err(e) if wait(mflags & MSG_DONTWAIT != 0, e) => Out::Block(Blocked::Net { call, a }),
                Err(EPIPE) => {
                    if mflags & MSG_NOSIGNAL == 0 {
                        st.post(i, SIGPIPE);
                    }
                    Out::Ret(err(EPIPE))
                }
                Err(e) => Out::Ret(err(e)),
            }
        }
        // `recvfrom(fd, buf, len, flags, addr, addrlen)`, or
        // `recvmsg(fd, msg, flags)`: no control messages.
        Sys::Recvfrom | Sys::Recvmsg => {
            let mut tmp = [0u8; 4096];
            let (want, mflags, msg) = if call == Sys::Recvfrom {
                (a[2], a[3], None)
            } else {
                let m = match msghdr(st, i, a[1]) {
                    Ok(m) => m,
                    Err(e) => return Out::Ret(err(e)),
                };
                let mut total = 0u64;
                for c in 0..m.iovlen {
                    total = total.saturating_add(st.word(i, m.iov + 16 * c + 8).unwrap_or(0));
                }
                (total, a[2], Some(m))
            };
            let n = want.min(tmp.len() as u64) as usize;
            let got = match sock::recv(k, &mut tmp[..n], mflags & MSG_PEEK != 0) {
                Ok(g) => g,
                Err(e) if wait(mflags & MSG_DONTWAIT != 0, e) => return Out::Block(Blocked::Net { call, a }),
                Err(e) => return Out::Ret(err(e)),
            };
            let data = &tmp[..got.n];
            r(match msg {
                None => st.put(i, a[1], data).and_then(|_| put_sockaddr(st, i, k, got.from, a[4], a[5])),
                Some(m) => scatter(st, i, m.iov, m.iovlen, data)
                    .and_then(|_| put_sockaddr(st, i, k, got.from, m.name, m.namelen))
                    .and_then(|_| st.put(i, a[1] + 40, &0u64.to_le_bytes()))
                    .and_then(|_| {
                        let f = if got.full > got.n { MSG_TRUNC as u32 } else { 0 };
                        st.put(i, a[1] + 48, &f.to_le_bytes())
                    })
                    .map(|_| ()),
            }
            .map(|_| got.n as u64))
        }
        Sys::Shutdown => r(sock::shutdown(k, a[1]).map(|_| 0)),
        Sys::Getsockname => {
            let w = sock::name(k);
            r(put_sockaddr(st, i, k, w, a[1], a[2]).map(|_| 0))
        }
        Sys::Getpeername => r(sock::peer(k).and_then(|w| put_sockaddr(st, i, k, w, a[1], a[2])).map(|_| 0)),
        // Options are taken and do nothing.
        Sys::Setsockopt => Out::Ret(0),
        Sys::Getsockopt => {
            const SOL_SOCKET: u64 = 1;
            const SO_TYPE: u64 = 3;
            const SO_ERROR: u64 = 4;
            let v = match (a[1], a[2]) {
                (SOL_SOCKET, SO_ERROR) => sock::take_error(k),
                (SOL_SOCKET, SO_TYPE) => {
                    if sock::get(k).proto == sock::Proto::Tcp { sock::SOCK_STREAM } else { sock::SOCK_DGRAM }
                }
                _ => 0,
            };
            r(st.put(i, a[3], &(v as u32).to_le_bytes()).and_then(|_| st.put(i, a[4], &4u32.to_le_bytes())).map(|_| 0))
        }
        _ => Out::Ret(err(ENOSYS)),
    }
}

/// Unix socket errors.
const ENOTCONN: u64 = 107;
const EISCONN: u64 = 106;
const ECONNREFUSED: u64 = 111;
const EADDRINUSE: u64 = 98;
const EOPNOTSUPP: u64 = 95;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;

/// A `sockaddr_un`'s name: its path (to its first NUL), or, its first
/// byte 0, an abstract name (the rest of the given length).
fn sun_name(st: &State, i: usize, addr: u64, len: u64) -> Result<([u8; unix::NAME_MAX], usize), u64> {
    let mut b = [0u8; 2 + unix::NAME_MAX];
    let n = (len as usize).min(b.len());
    if n < 3 {
        return Err(EINVAL);
    }
    if !st.copy_in(i, addr, &mut b[..n]) {
        return Err(EFAULT);
    }
    if u16::from_le_bytes([b[0], b[1]]) as u64 != unix::AF_UNIX {
        return Err(EINVAL);
    }
    let path = &b[2..n];
    let l = if path[0] == 0 { path.len() } else { path.iter().position(|&c| c == 0).unwrap_or(path.len()) };
    let mut name = [0u8; unix::NAME_MAX];
    name[..l].copy_from_slice(&path[..l]);
    Ok((name, l))
}

/// Unix socket `k`'s name as a `sockaddr_un` at `addr` (if any), cut to
/// the length at `lenp`, which then says its whole length.
fn put_sun(st: &mut State, i: usize, k: Option<usize>, addr: u64, lenp: u64) -> Result<(), u64> {
    if addr == 0 {
        return Ok(());
    }
    let mut l = [0u8; 4];
    if !st.copy_in(i, lenp, &mut l) {
        return Err(EFAULT);
    }
    let mut b = [0u8; 3 + unix::NAME_MAX];
    b[..2].copy_from_slice(&(unix::AF_UNIX as u16).to_le_bytes());
    let mut len = 2;
    if let Some(k) = k {
        let name = st.unix[k].name();
        b[2..2 + name.len()].copy_from_slice(name);
        // A path's NUL counts; an abstract name has none.
        len += name.len() + (name.first().is_some_and(|&c| c != 0)) as usize;
    }
    let n = (u32::from_le_bytes(l) as usize).min(len);
    st.put(i, addr, &b[..n])?;
    st.put(i, lenp, &(len as u32).to_le_bytes()).map(|_| ())
}

/// A free Unix socket, made by process `pid`.
fn unix_new(st: &mut State, pid: u32) -> Result<usize, u64> {
    let k = st.unix.iter().position(|u| u.phase == unix::Phase::Free).ok_or(ENFILE)?;
    st.unix[k].reset(pid);
    Ok(k)
}

/// A descriptor in process `i` for Unix socket `k`, with `ty`'s
/// `SOCK_NONBLOCK` and `SOCK_CLOEXEC`; the socket closed if there is none.
fn unix_fd(st: &mut State, i: usize, k: usize, ty: u64) -> Result<u64, u64> {
    let Some(f) = st.new_file(FileKind::Unix, 0, k as u8, O_RDWR | ty as u32 & O_NONBLOCK) else {
        st.unix_close(k);
        return Err(ENFILE);
    };
    st.new_fd(i, f, 0, ty as u32 & O_CLOEXEC != 0).inspect_err(|_| st.release(f))
}

/// `socket(AF_UNIX, SOCK_STREAM, 0)` and `socketpair`.
fn unix_socket(st: &mut State, i: usize, call: Sys, a: [u64; 6]) -> Out {
    const EAFNOSUPPORT: u64 = 97;
    const ESOCKTNOSUPPORT: u64 = 94;
    if a[0] != unix::AF_UNIX {
        return Out::Ret(err(EAFNOSUPPORT));
    }
    if a[1] & 0xf != sock::SOCK_STREAM {
        return Out::Ret(err(ESOCKTNOSUPPORT));
    }
    let pid = st.procs[i].pid;
    let one = |st: &mut State| unix_new(st, pid).and_then(|k| unix_fd(st, i, k, a[1]).map(|fd| (k, fd)));
    if call == Sys::Socket {
        return Out::Ret(one(st).map_or_else(err, |(_, fd)| fd));
    }
    let (k, fd) = match one(st) {
        Ok(s) => s,
        Err(e) => return Out::Ret(err(e)),
    };
    let (j, fd2) = match one(st) {
        Ok(s) => s,
        Err(e) => {
            st.close(i, fd as usize);
            return Out::Ret(err(e));
        }
    };
    for (x, y) in [(k, j), (j, k)] {
        st.unix[x].phase = unix::Phase::Connected;
        st.unix[x].peer = y as u8 + 1;
        st.unix[x].peer_pid = st.unix[y].pid;
    }
    let mut sv = [0u8; 8];
    sv[..4].copy_from_slice(&(fd as u32).to_le_bytes());
    sv[4..].copy_from_slice(&(fd2 as u32).to_le_bytes());
    Out::Ret(st.put(i, a[3], &sv).map_or_else(err, |_| 0))
}

/// Puts `data` (and the open files `rights`, each then holding a
/// reference) in Unix socket `k`'s peer's buffer: how many bytes, or
/// `EAGAIN` if it is full. Writing to a peer gone is `EPIPE`, and
/// `SIGPIPE` unless `nosignal`.
fn unix_send(st: &mut State, i: usize, k: usize, data: &[u8], rights: Option<(u8, [u8; unix::RIGHTS_FDS])>, nosignal: bool) -> Result<usize, u64> {
    let u = &st.unix[k];
    if u.phase != unix::Phase::Connected {
        return Err(ENOTCONN);
    }
    if u.peer == 0 || u.broken {
        if !nosignal {
            st.post(i, SIGPIPE);
        }
        return Err(EPIPE);
    }
    if data.is_empty() {
        return Ok(0);
    }
    let p = u.peer as usize - 1;
    if st.unix[p].room() == 0 {
        return Err(EAGAIN);
    }
    let n = st.unix[p].put(data, rights).ok_or(EAGAIN)?;
    if let Some((c, files)) = rights {
        for &f in &files[..c as usize] {
            st.files[f as usize].refs += 1;
        }
    }
    Ok(n)
}

/// The open files a `msghdr`'s control messages (`SCM_RIGHTS`) send.
fn rights_of(st: &State, i: usize, msg: u64) -> Result<Option<(u8, [u8; unix::RIGHTS_FDS])>, u64> {
    let (control, len) = (st.word(i, msg + 32).ok_or(EFAULT)?, st.word(i, msg + 40).ok_or(EFAULT)?);
    let mut out = [0u8; unix::RIGHTS_FDS];
    let mut n = 0;
    let mut at = 0;
    while at + 16 <= len {
        let clen = st.word(i, control + at).ok_or(EFAULT)?;
        let kind = st.word(i, control + at + 8).ok_or(EFAULT)?;
        if clen < 16 || at + clen > len {
            return Err(EINVAL);
        }
        // SOL_SOCKET, SCM_RIGHTS.
        if kind == 1 | 1 << 32 {
            for c in 0..(clen - 16) / 4 {
                let mut b = [0u8; 4];
                if !st.copy_in(i, control + at + 16 + 4 * c, &mut b) {
                    return Err(EFAULT);
                }
                let f = st.file(i, u32::from_le_bytes(b) as u64).ok_or(EBADF)?;
                if n == unix::RIGHTS_FDS {
                    return Err(EINVAL);
                }
                out[n] = f as u8;
                n += 1;
            }
        }
        at += (clen + 7) & !7;
    }
    Ok((n > 0).then_some((n as u8, out)))
}

/// Gives the open files that came with a message to process `i` as new
/// descriptors, written as an `SCM_RIGHTS` control message to the
/// `msghdr` at `msg`; those that do not fit are closed (`MSG_CTRUNC`).
/// Its flags.
fn give_rights(st: &mut State, i: usize, msg: u64, r: Option<unix::Rights>, cloexec: bool) -> Result<u32, u64> {
    const MSG_CTRUNC: u32 = 8;
    let (control, len) = (st.word(i, msg + 32).ok_or(EFAULT)?, st.word(i, msg + 40).ok_or(EFAULT)?);
    let Some(r) = r else {
        st.put(i, msg + 40, &0u64.to_le_bytes())?;
        return Ok(0);
    };
    let files = &r.files[..r.n as usize];
    let room = (len.saturating_sub(16) / 4) as usize;
    let mut b = [0u8; 16 + 4 * unix::RIGHTS_FDS];
    let mut n = 0;
    for (c, &f) in files.iter().enumerate() {
        let fd = if c < room { st.new_fd(i, f as usize, 0, cloexec).ok() } else { None };
        match fd {
            Some(fd) => {
                b[16 + 4 * n..20 + 4 * n].copy_from_slice(&(fd as u32).to_le_bytes());
                n += 1;
            }
            None => st.release(f as usize),
        }
    }
    let flags = if n < files.len() { MSG_CTRUNC } else { 0 };
    if n == 0 {
        st.put(i, msg + 40, &0u64.to_le_bytes())?;
        return Ok(flags);
    }
    let clen = 16 + 4 * n as u64;
    b[..8].copy_from_slice(&clen.to_le_bytes());
    b[8..16].copy_from_slice(&(1u64 | 1 << 32).to_le_bytes());
    st.put(i, control, &b[..clen as usize])?;
    st.put(i, msg + 40, &((clen + 7) & !7).to_le_bytes())?;
    Ok(flags)
}

/// The socket calls on Unix socket file `f`.
fn unix_call(st: &mut State, i: usize, f: usize, call: Sys, a: [u64; 6]) -> Out {
    use unix::Phase;
    const MSG_PEEK: u64 = 2;
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    let r = |v: Result<u64, u64>| Out::Ret(v.unwrap_or_else(err));
    let (k, flags) = (st.files[f].pipe as usize, st.files[f].flags);
    let wait = |dontwait: bool| flags & O_NONBLOCK == 0 && !dontwait;
    let phase = st.unix[k].phase;
    match call {
        Sys::Bind => {
            let (name, len) = match sun_name(st, i, a[1], a[2]) {
                Ok(n) => n,
                Err(e) => return Out::Ret(err(e)),
            };
            if phase != Phase::New || st.unix[k].name_len != 0 || len == 0 {
                return Out::Ret(err(EINVAL));
            }
            if st.unix.iter().any(|u| u.phase != Phase::Free && u.name() == &name[..len]) {
                return Out::Ret(err(EADDRINUSE));
            }
            let u = &mut st.unix[k];
            u.name = name;
            u.name_len = len as u8;
            Out::Ret(0)
        }
        Sys::Listen => match phase {
            Phase::New if st.unix[k].name_len != 0 => {
                st.unix[k].phase = Phase::Listening;
                Out::Ret(0)
            }
            Phase::Listening => Out::Ret(0),
            _ => Out::Ret(err(EINVAL)),
        },
        Sys::Connect => {
            match phase {
                Phase::Connected => return Out::Ret(err(EISCONN)),
                Phase::Listening => return Out::Ret(err(EINVAL)),
                _ => {}
            }
            let (name, len) = match sun_name(st, i, a[1], a[2]) {
                Ok(n) => n,
                Err(e) => return Out::Ret(err(e)),
            };
            let Some(l) = st.unix.iter().position(|u| u.phase == Phase::Listening && u.name() == &name[..len]) else {
                return Out::Ret(err(ECONNREFUSED));
            };
            if st.unix[l].nback as usize == unix::BACKLOG {
                return if wait(false) { Out::Block(Blocked::Net { call, a }) } else { Out::Ret(err(EAGAIN)) };
            }
            let s = match unix_new(st, st.unix[l].pid) {
                Ok(s) => s,
                Err(e) => return Out::Ret(err(e)),
            };
            let (lname, lname_len) = (st.unix[l].name, st.unix[l].name_len);
            for (x, y) in [(k, s), (s, k)] {
                st.unix[x].phase = Phase::Connected;
                st.unix[x].peer = y as u8 + 1;
                st.unix[x].peer_pid = st.unix[y].pid;
            }
            st.unix[s].name = lname;
            st.unix[s].name_len = lname_len;
            let ln = &mut st.unix[l];
            ln.backlog[ln.nback as usize] = s as u8 + 1;
            ln.nback += 1;
            Out::Ret(0)
        }
        Sys::Accept => {
            if phase != Phase::Listening {
                return Out::Ret(err(EINVAL));
            }
            let u = &mut st.unix[k];
            if u.nback == 0 {
                return if wait(false) { Out::Block(Blocked::Net { call, a }) } else { Out::Ret(err(EAGAIN)) };
            }
            let s = u.backlog[0] as usize - 1;
            u.backlog.copy_within(1.., 0);
            u.nback -= 1;
            // Its peer, which connected, has most likely no name.
            let peer = st.unix[s].peer;
            let fd = match unix_fd(st, i, s, a[3]) {
                Ok(fd) => fd,
                Err(e) => return Out::Ret(err(e)),
            };
            let named = (peer != 0 && st.unix[peer as usize - 1].name_len != 0).then(|| peer as usize - 1);
            r(put_sun(st, i, named, a[1], a[2]).map(|_| fd))
        }
        Sys::Sendto | Sys::Sendmsg => {
            let mut tmp = [0u8; 4096];
            let (n, rights, mflags) = if call == Sys::Sendto {
                let n = a[2].min(tmp.len() as u64) as usize;
                if !st.copy_in(i, a[1], &mut tmp[..n]) {
                    return Out::Ret(err(EFAULT));
                }
                (n, None, a[3])
            } else {
                let m = match msghdr(st, i, a[1]) {
                    Ok(m) => m,
                    Err(e) => return Out::Ret(err(e)),
                };
                match gather(st, i, m.iov, m.iovlen, &mut tmp).and_then(|n| Ok((n, rights_of(st, i, a[1])?))) {
                    Ok((n, rights)) => (n, rights, a[2]),
                    Err(e) => return Out::Ret(err(e)),
                }
            };
            match unix_send(st, i, k, &tmp[..n], rights, mflags & MSG_NOSIGNAL != 0) {
                Ok(w) => Out::Ret(w as u64),
                Err(EAGAIN) if wait(mflags & MSG_DONTWAIT != 0) => Out::Block(Blocked::Net { call, a }),
                Err(e) => Out::Ret(err(e)),
            }
        }
        Sys::Recvfrom | Sys::Recvmsg => {
            if phase != Phase::Connected {
                return Out::Ret(err(if phase == Phase::Listening { EINVAL } else { ENOTCONN }));
            }
            let mut tmp = [0u8; 4096];
            let (want, mflags, msg) = if call == Sys::Recvfrom {
                (a[2], a[3], None)
            } else {
                let m = match msghdr(st, i, a[1]) {
                    Ok(m) => m,
                    Err(e) => return Out::Ret(err(e)),
                };
                let mut total = 0u64;
                for c in 0..m.iovlen {
                    total = total.saturating_add(st.word(i, m.iov + 16 * c + 8).unwrap_or(0));
                }
                (total, a[2], Some(m))
            };
            let u = &mut st.unix[k];
            if u.len == 0 && !u.eof {
                return if wait(mflags & MSG_DONTWAIT != 0) { Out::Block(Blocked::Net { call, a }) } else { Out::Ret(err(EAGAIN)) };
            }
            let want = want.min(tmp.len() as u64) as usize;
            let (n, rights) = if mflags & MSG_PEEK != 0 { (u.peek(&mut tmp[..want]), None) } else { u.take(&mut tmp[..want]) };
            let data = &tmp[..n];
            r(match msg {
                None => {
                    if let Some(rr) = rights {
                        for &f in &rr.files[..rr.n as usize] {
                            st.release(f as usize);
                        }
                    }
                    st.put(i, a[1], data).and_then(|_| if a[4] != 0 { st.put(i, a[5], &0u32.to_le_bytes()) } else { Ok(0) })
                }
                Some(m) => scatter(st, i, m.iov, m.iovlen, data)
                    .and_then(|_| if m.name != 0 { st.put(i, m.namelen, &0u32.to_le_bytes()) } else { Ok(0) })
                    .and_then(|_| give_rights(st, i, a[1], rights, mflags & MSG_CMSG_CLOEXEC != 0))
                    .and_then(|fl| st.put(i, a[1] + 48, &fl.to_le_bytes())),
            }
            .map(|_| n as u64))
        }
        Sys::Shutdown => {
            if phase != Phase::Connected {
                return Out::Ret(err(ENOTCONN));
            }
            let peer = st.unix[k].peer;
            // SHUT_RD, SHUT_WR, SHUT_RDWR.
            if a[1] != 1 {
                st.unix[k].eof = true;
            }
            if a[1] != 0 && peer != 0 {
                st.unix[peer as usize - 1].eof = true;
            }
            Out::Ret(0)
        }
        Sys::Getsockname => r(put_sun(st, i, Some(k).filter(|&k| st.unix[k].name_len != 0), a[1], a[2]).map(|_| 0)),
        Sys::Getpeername => match st.unix[k].peer {
            0 => Out::Ret(err(ENOTCONN)),
            p => {
                let p = p as usize - 1;
                r(put_sun(st, i, Some(p).filter(|&p| st.unix[p].name_len != 0), a[1], a[2]).map(|_| 0))
            }
        },
        Sys::Setsockopt => Out::Ret(0),
        Sys::Getsockopt => {
            const SOL_SOCKET: u64 = 1;
            const SO_TYPE: u64 = 3;
            const SO_PEERCRED: u64 = 17;
            const SO_ACCEPTCONN: u64 = 30;
            let mut b = [0u8; 12];
            let len = match (a[1], a[2]) {
                (SOL_SOCKET, SO_PEERCRED) => {
                    b[..4].copy_from_slice(&st.unix[k].peer_pid.to_le_bytes());
                    12
                }
                (SOL_SOCKET, SO_TYPE) => {
                    b[0] = sock::SOCK_STREAM as u8;
                    4
                }
                (SOL_SOCKET, SO_ACCEPTCONN) => {
                    b[0] = (phase == Phase::Listening) as u8;
                    4
                }
                _ => 4,
            };
            let mut l = [0u8; 4];
            if !st.copy_in(i, a[4], &mut l) {
                return Out::Ret(err(EFAULT));
            }
            let n = (u32::from_le_bytes(l) as usize).min(len);
            r(st.put(i, a[3], &b[..n]).and_then(|_| st.put(i, a[4], &(len as u32).to_le_bytes())).map(|_| 0))
        }
        _ => Out::Ret(err(EOPNOTSUPP)),
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
/// Takes the framebuffer window's events from the compositor, as Linux's
/// input devices give them: a key (the modifier keys first, as their
/// byte changed) to the keys' device; the pointer's place (absolute, in
/// the window), its buttons and the wheel to the pointer's; each change a
/// report (`SYN_REPORT` after it).
fn input_events(st: &mut State) {
    let Some(n) = st.fb_window.checked_sub(1) else { return };
    let now = superior_sys::ticks();
    while let Some(m) = fb_call(window::next(n), None).filter(|m| m[0] == 0) {
        let (a, b) = (m[2], m[3]);
        match m[1] {
            window::KEY => {
                let k = &mut st.input[0];
                let mods = (b >> 8) as u8;
                let changed = mods ^ st.input_mods;
                for bit in 0..8 {
                    if changed & 1 << bit != 0 {
                        k.push(now, EV_KEY, MOD_KEYS[bit], (mods >> bit & 1) as i32);
                    }
                }
                st.input_mods = mods;
                if let Some(&code) = HID_KEYS.get(a as usize).filter(|&&c| c != 0) {
                    k.push(now, EV_KEY, code as u16, match b & 3 { 1 => 1, 3 => 2, _ => 0 });
                }
                k.push(now, EV_SYN, 0, 0);
            }
            window::POINTER => {
                let p = &mut st.input[1];
                let at = (a as u16 as i16 as i32, (a >> 16) as u16 as i16 as i32);
                if at.0 != st.input_at.0 {
                    p.push(now, EV_ABS, 0, at.0);
                }
                if at.1 != st.input_at.1 {
                    p.push(now, EV_ABS, 1, at.1);
                }
                let changed = b as u8 ^ st.input_buttons;
                for bit in 0..3 {
                    if changed & 1 << bit != 0 {
                        p.push(now, EV_KEY, BTN_LEFT + bit, (b >> bit & 1) as i32);
                    }
                }
                (st.input_at, st.input_buttons) = (at, b as u8);
                p.push(now, EV_SYN, 0, 0);
            }
            window::WHEEL => {
                let p = &mut st.input[1];
                let (up, right) = (b as u32 as i32, (b >> 32) as u32 as i32);
                if up != 0 {
                    p.push(now, EV_REL, REL_WHEEL, up);
                }
                if right != 0 {
                    p.push(now, EV_REL, REL_HWHEEL, right);
                }
                p.push(now, EV_SYN, 0, 0);
            }
            _ => {}
        }
    }
}

/// The input devices' ioctls (evdev's), as Linux answers them: the
/// driver's version, the device's id and name, which event types and
/// codes it gives (bit masks), the pointer's axes, and grabbing it (it is
/// this window's alone already). Device 0 is the keys, 1 the pointer.
fn input_ioctl(st: &mut State, i: usize, d: usize, cmd: u64, arg: u64) -> Result<u64, u64> {
    let (size, ty, nr) = ((cmd >> 16 & 0x3fff) as usize, cmd >> 8 & 0xff, cmd & 0xff);
    if ty != b'E' as u64 {
        return Err(ENOTTY);
    }
    let mut out = [0u8; 96];
    let set = |b: &mut [u8; 96], bit: usize| b[bit / 8] |= 1 << (bit % 8);
    let n = match nr {
        // EVIOCGVERSION, EVIOCGID (a virtual bus).
        0x01 => return st.put(i, arg, &0x0001_0001u32.to_le_bytes()),
        0x02 => return st.put(i, arg, &[6, 0, 0, 0, d as u8 + 1, 0, 1, 0]),
        // EVIOCGNAME: as much of it as fits, with its NUL.
        0x06 => {
            let name: &[u8] = if d == 0 { b"Superior keyboard\0" } else { b"Superior pointer\0" };
            let n = name.len().min(size);
            out[..n].copy_from_slice(&name[..n]);
            n
        }
        // EVIOCGBIT for the event types, then for keys, relative and
        // absolute axes.
        0x20 => {
            for t in if d == 0 { &[EV_SYN, EV_KEY][..] } else { &[EV_SYN, EV_KEY, EV_REL, EV_ABS][..] } {
                set(&mut out, *t as usize);
            }
            size.min(4)
        }
        0x21 => {
            if d == 0 {
                HID_KEYS.iter().map(|&k| k as u16).chain(MOD_KEYS).for_each(|k| set(&mut out, k as usize));
            } else {
                (0..3).for_each(|b| set(&mut out, BTN_LEFT as usize + b));
            }
            out[0] &= !1;
            size.min(96)
        }
        0x22 if d == 1 => {
            set(&mut out, REL_WHEEL as usize);
            set(&mut out, REL_HWHEEL as usize);
            size.min(2)
        }
        0x23 if d == 1 => {
            set(&mut out, 0);
            set(&mut out, 1);
            size.min(8)
        }
        // Other types (and these on the keys): none of them. The keys,
        // lights, sounds and switches held, and the properties: none.
        0x09 | 0x18..=0x1b | 0x20..=0x3f => size.min(96),
        // EVIOCGABS for x and y: where the pointer is, in the window.
        0x40 | 0x41 if d == 1 => {
            let (value, max) = if nr == 0x40 { (st.input_at.0, FB_W - 1) } else { (st.input_at.1, FB_H - 1) };
            let mut a = [0u8; 24];
            a[..4].copy_from_slice(&value.to_le_bytes());
            a[8..12].copy_from_slice(&(max as i32).to_le_bytes());
            return st.put(i, arg, &a);
        }
        // EVIOCGRAB: it is.
        0x90 => return Ok(0),
        _ => return Err(EINVAL),
    };
    st.put(i, arg, &out[..n]).map(|_| n as u64)
}

/// A call to the compositor, lending the page in slot `grant`: its answer,
/// or `None` if the call failed (no compositor, or it restarted).
fn fb_call(m: [u64; 4], grant: Option<u64>) -> Option<[u64; 4]> {
    let x = CapTransfer { grant: grant.map(|s| s as u16), accept: None };
    let r = superior_sys::syscall_x(Syscall::Call, WINDOWS, m, x);
    (r.status == 0).then_some(r.msg)
}

/// The framebuffer's ioctls, as Linux's fbdev answers them: its mode
/// (`FBIOGET_VSCREENINFO`; setting one is answered with the one it has),
/// its layout (`FBIOGET_FSCREENINFO`), panning (which shows it) and
/// blanking (nothing to do).
fn fb_ioctl(st: &mut State, i: usize, cmd: u64, arg: u64) -> Result<u64, u64> {
    const FBIOGET_VSCREENINFO: u64 = 0x4600;
    const FBIOPUT_VSCREENINFO: u64 = 0x4601;
    const FBIOGET_FSCREENINFO: u64 = 0x4602;
    const FBIOPAN_DISPLAY: u64 = 0x4606;
    const FBIOBLANK: u64 = 0x4611;
    let word = |b: &mut [u8], at: usize, v: u64| b[at..at + 4].copy_from_slice(&(v as u32).to_le_bytes());
    match cmd {
        FBIOGET_VSCREENINFO | FBIOPUT_VSCREENINFO => {
            // struct fb_var_screeninfo: the visible and virtual sizes, 32
            // bits a pixel, red, green and blue (offset, length) at 16, 8
            // and 0, and the screen's size in millimetres unknown.
            let mut v = [0u8; 160];
            for (at, x) in [(0, FB_W), (4, FB_H), (8, FB_W), (12, FB_H), (24, 32), (32, 16), (36, 8), (44, 8), (48, 8), (60, 8)] {
                word(&mut v, at, x);
            }
            word(&mut v, 88, u32::MAX as u64);
            word(&mut v, 92, u32::MAX as u64);
            st.put(i, arg, &v)
        }
        FBIOGET_FSCREENINFO => {
            // struct fb_fix_screeninfo: its name, length, packed pixels in
            // true colour, and the bytes from one row to the next.
            let mut f = [0u8; 80];
            f[..8].copy_from_slice(b"superior");
            word(&mut f, 24, FB_PAGES * PAGE);
            word(&mut f, 36, 2);
            word(&mut f, 48, FB_W * 4);
            st.put(i, arg, &f)
        }
        FBIOPAN_DISPLAY => {
            st.fb_show();
            Ok(0)
        }
        FBIOBLANK => Ok(0),
        _ => Err(ENOTTY),
    }
}

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
    if st.files[f].kind == FileKind::Node && st.fs.kind(st.files[f].ino) == Kind::Fb {
        return fb_ioctl(st, i, cmd, arg);
    }
    if st.files[f].kind == FileKind::Node && st.fs.kind(st.files[f].ino) == Kind::Input {
        let d = st.fs.size(st.files[f].ino) as usize & 1;
        return input_ioctl(st, i, d, cmd, arg);
    }
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
    "kill", "gzip", "md5sum", "nproc", "wget", "nc", "ping", "ping6",
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
    // A program linked against glibc (Debian's GNU hello): glibc's
    // dynamic linker loads its C library.
    (&["sh", "-c", "hello && echo hello said $?"], 0),
    // A toolchain: make has tcc compile, assemble and link a C program
    // against musl, and the program it made, a file of the tree, runs.
    (
        &[
            "sh",
            "-c",
            r#"mkdir -p /tmp/cc && cd /tmp/cc && printf '#include <stdio.h>\nint main(void) { printf("built by tcc: %%d\\n", 6 * 7); return 0; }\n' > hi.c && printf 'hi: hi.c\n\ttcc -o hi hi.c\n' > Makefile && make && ./hi"#,
        ],
        0,
    ),
    // GNU binutils: as assembles a string (data alone, the same on both
    // ISAs), tcc compiles the C that prints it, and ld links the two
    // against musl, the start files and the dynamic linker given.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf '.section .rodata\n.globl greeting\ngreeting: .asciz "assembled by as, linked by ld"\n' > msg.s && as -o msg.o msg.s && printf '#include <stdio.h>\nextern const char greeting[];\nint main(void) { puts(greeting); return 0; }\n' > main.c && tcc -c -o main.o main.c && ld -o linked -dynamic-linker /lib/ld-musl-$(uname -m).so.1 /usr/lib/crt1.o /usr/lib/crti.o main.o msg.o -L/usr/lib -lc /usr/lib/crtn.o && ./linked"#,
        ],
        0,
    ),
    // gcc: its driver runs cc1 (some 30 MB, fixed-address), as, and
    // collect2, which runs ld, and the program it made runs.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf '#include <stdio.h>\nint main(void) { printf("compiled by gcc: %%d\\n", 6 * 7); return 0; }\n' > g.c && gcc -o g g.c && ./g"#,
        ],
        0,
    ),
    // vfork: the child borrows its parent's memory, so what it writes
    // before it ends (here, on the stack they share) its parent sees.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int printf(const char *, ...); int vfork(void); void _exit(int);\nint main(void) { volatile int x = 1; if (vfork() == 0) { x = 42; _exit(0); } printf("vfork shared: %%d\\n", x); return 0; }\n' > vf.c && tcc -o vf vf.c && ./vf"#,
        ],
        0,
    ),
    // epoll: a pipe watched, nothing ready at first, then a wait that
    // blocks until a child writes to it, with the data given back.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int printf(const char *, ...); int pipe(int *); int fork(void); int usleep(unsigned); void _exit(int); long write(int, const void *, unsigned long); int epoll_create1(int); int epoll_ctl(int, int, int, void *); int epoll_wait(int, void *, int, int);\n#ifdef __x86_64__\n#define OFF 4\n#else\n#define OFF 8\n#endif\nint main(void) { int p[2]; unsigned char ev[16] = {1}, out[64]; pipe(p); int e = epoll_create1(0); ev[OFF] = 7; epoll_ctl(e, 1, p[0], ev); int n0 = epoll_wait(e, out, 4, 0); if (fork() == 0) { usleep(200000); write(p[1], "x", 1); _exit(0); } int n1 = epoll_wait(e, out, 4, 5000); printf("epoll: %%d ready, then %%d, data %%d\\n", n0, n1, out[OFF]); return 0; }\n' > ep.c && tcc -o ep ep.c && ./ep"#,
        ],
        0,
    ),
    // The framebuffer: a program reads its mode and layout, maps it, draws
    // a gradient (red across, green down) and pans it, which shows it.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int open(const char *, int, ...); int ioctl(int, unsigned long, ...); void *mmap(void *, unsigned long, int, int, int, long); int printf(const char *, ...);\nint main(void) { unsigned v[40], f[20]; int fd = open("/dev/fb0", 2); if (fd < 0 || ioctl(fd, 0x4600, v) || ioctl(fd, 0x4602, f)) return 1; unsigned w = v[0], h = v[1], line = f[12]; unsigned *p = mmap(0, f[6], 3, 1, fd, 0); if (p == (void *)-1) return 2; for (unsigned y = 0; y < h; y++) for (unsigned x = 0; x < w; x++) p[y * (line / 4) + x] = x * 255 / (w - 1) << 16 | y * 255 / (h - 1) << 8 | 0x80; ioctl(fd, 0x4606, v); printf("fb0: %%ux%%u, %%u bits, line %%u\\n", w, h, v[6], line); return 0; }\n' > fb.c && tcc -o fb fb.c && ./fb"#,
        ],
        0,
    ),
    // Shown as it is drawn: another picture (red falling across, blue
    // rising down), never panned, the program asleep while the screen is
    // looked at, the framebuffer still mapped.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int open(const char *, int, ...); int ioctl(int, unsigned long, ...); void *mmap(void *, unsigned long, int, int, int, long); long write(int, const void *, unsigned long); unsigned sleep(unsigned);\nint main(void) { unsigned v[40], f[20]; int fd = open("/dev/fb0", 2); if (fd < 0 || ioctl(fd, 0x4600, v) || ioctl(fd, 0x4602, f)) return 1; unsigned w = v[0], h = v[1], line = f[12]; unsigned *p = mmap(0, f[6], 3, 1, fd, 0); if (p == (void *)-1) return 2; for (unsigned y = 0; y < h; y++) for (unsigned x = 0; x < w; x++) p[y * (line / 4) + x] = (w - 1 - x) * 255 / (w - 1) << 16 | 0x40 << 8 | y * 255 / (h - 1); write(1, "fb0: drawn, not panned\\n", 23); sleep(3); return 0; }\n' > live.c && tcc -o live live.c && ./live"#,
        ],
        0,
    ),
    // Input: the pointer's device named, then a click on the window and
    // two keys typed (the host does both once it is ready), read from the
    // pointer's and the keys' devices as Linux's evdev gives them.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int open(const char *, int, ...); int ioctl(int, unsigned long, ...); long read(int, void *, unsigned long); long write(int, const void *, unsigned long); int printf(const char *, ...);\nstruct ev { long s, us; unsigned short type, code; int value; };\nint main(void) { char name[32]; struct ev e; int k = open("/dev/input/event0", 0), p = open("/dev/input/event1", 0), x = -1, y = -1, down = 0, up = 0, keys[4], n = 0; if (k < 0 || p < 0 || ioctl(p, 0x80204506, name) < 0) return 1; write(1, "input: ready\\n", 13); while (!up) { if (read(p, &e, sizeof e) != sizeof e) return 2; if (e.type == 3 && e.code == 0) x = e.value; if (e.type == 3 && e.code == 1) y = e.value; if (e.type == 1 && e.code == 0x110) { if (e.value) down = 1; else if (down) up = 1; } } while (n < 4) { if (read(k, &e, sizeof e) != sizeof e) return 3; if (e.type == 1) keys[n++] = e.code << 1 | e.value; } printf("input: %%s at %%d,%%d, left pressed and let go; keys %%d %%d, %%d %%d, %%d %%d, %%d %%d\\n", name, x, y, keys[0] >> 1, keys[0] & 1, keys[1] >> 1, keys[1] & 1, keys[2] >> 1, keys[2] & 1, keys[3] >> 1, keys[3] & 1); return 0; }\n' > in.c && tcc -o in in.c && ./in"#,
        ],
        0,
    ),
    // Unix domain sockets: a pipe's descriptor passed over a socket pair
    // (SCM_RIGHTS); a named socket, listened on and polled, a child's
    // connection accepted, its sender known (SO_PEERCRED), and the end
    // seen once the child has gone.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int socket(int, int, int); int socketpair(int, int, int, int *); int bind(int, const void *, unsigned); int listen(int, int); int accept(int, void *, unsigned *); int connect(int, const void *, unsigned); long sendmsg(int, const void *, int); long recvmsg(int, void *, int); int pipe(int *); long read(int, void *, unsigned long); long write(int, const void *, unsigned long); int close(int); int fork(void); int poll(void *, unsigned long, int); int getsockopt(int, int, int, void *, unsigned *); int waitpid(int, int *, int); void _exit(int); int printf(const char *, ...);\nstruct iov { void *b; unsigned long n; }; struct msg { void *name; unsigned namelen; struct iov *iov; unsigned long iovlen; void *ctl; unsigned long ctllen; int flags; }; struct ctl { unsigned long len; int level, type, fd, pad; }; struct sun { unsigned short fam; char path[108]; }; struct pfd { int fd; short ev, rev; };\nint main(void) { int sv[2], p[2], s, c, pid, cred[3], st; char b[32]; unsigned l = 12; long n; struct iov v = { b, 1 }; struct ctl k = { 20, 1, 1, 0, 0 }; struct msg m = { 0, 0, &v, 1, &k, 24, 0 }; struct sun a = { 1, "/tmp/sock" }; struct pfd q = { 0, 1, 0 }; if (socketpair(1, 1, 0, sv) || pipe(p)) return 1; write(p[1], "through a pipe", 14); close(p[1]); k.fd = p[0]; b[0] = 120; if (sendmsg(sv[0], &m, 0) != 1) return 2; close(p[0]); k.fd = -1; k.len = 0; if (recvmsg(sv[1], &m, 0) != 1 || k.len != 20 || k.level != 1 || k.type != 1 || m.ctllen != 24) return 3; n = read(k.fd, b, 31); b[n] = 0; printf("unix: a pipe passed over a socket pair, read: %%s\\n", b); s = socket(1, 1, 0); if (bind(s, &a, sizeof a) || listen(s, 4)) return 4; pid = fork(); if (!pid) { c = socket(1, 1, 0); if (connect(c, &a, sizeof a)) _exit(1); write(c, "hello from the child", 20); _exit(0); } q.fd = s; if (poll(&q, 1, 5000) != 1 || !(q.rev & 1)) return 5; c = accept(s, 0, 0); if (c < 0) return 6; if (getsockopt(c, 1, 17, cred, &l) || l != 12 || cred[0] != pid) return 7; n = read(c, b, 31); b[n] = 0; waitpid(pid, &st, 0); printf("unix: %%s, accepted at /tmp/sock, its credentials right; then %%ld\\n", b, read(c, b + 20, 11)); return 0; }\n' > un.c && tcc -o un un.c && ./un; s=$?; rm -f un un.c; exit $s"#,
        ],
        0,
    ),
    // Shared memory, as a Wayland client gives its compositor a buffer: a
    // child makes a memory file, sizes and maps it, draws in it, and
    // passes it over a socket; the parent maps it, reads it, and writes
    // back what the child then sees.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int socketpair(int, int, int, int *); long sendmsg(int, const void *, int); long recvmsg(int, void *, int); int memfd_create(const char *, unsigned); int ftruncate(int, long); void *mmap(void *, unsigned long, int, int, int, long); long lseek(int, long, int); long read(int, void *, unsigned long); long write(int, const void *, unsigned long); int close(int); int fork(void); int waitpid(int, int *, int); void _exit(int); int printf(const char *, ...); char *strcpy(char *, const char *); int fflush(void *);\nstruct iov { void *b; unsigned long n; }; struct msg { void *name; unsigned namelen; struct iov *iov; unsigned long iovlen; void *ctl; unsigned long ctllen; int flags; }; struct ctl { unsigned long len; int level, type, fd, pad; };\nint main(void) { int sv[2], fd, pid, st; char b[4]; char *p; struct iov v = { b, 1 }; struct ctl k = { 20, 1, 1, 0, 0 }; struct msg m = { 0, 0, &v, 1, &k, 24, 0 }; if (socketpair(1, 1, 0, sv)) return 1; pid = fork(); if (!pid) { fd = memfd_create("buffer", 1); if (fd < 0 || ftruncate(fd, 3 * 4096)) _exit(2); p = mmap(0, 3 * 4096, 3, 1, fd, 0); if (p == (char *)-1) _exit(3); strcpy(p + 8192, "drawn by the child"); k.fd = fd; if (sendmsg(sv[0], &m, 0) != 1 || read(sv[0], b, 1) != 1) _exit(4); printf("memfd: the child sees: %%s\\n", p); fflush(0); _exit(0); } k.fd = -1; if (recvmsg(sv[1], &m, 0) != 1 || k.fd < 0) return 5; p = mmap(0, 3 * 4096, 3, 1, k.fd, 0); if (p == (char *)-1) return 6; printf("memfd: %%s, %%ld bytes\\n", p + 8192, lseek(k.fd, 0, 2)); strcpy(p, "written back"); write(sv[1], b, 1); waitpid(pid, &st, 0); return st; }\n' > shm.c && tcc -o shm shm.c 2>&1 && ./shm; s=$?; rm -f shm shm.c; exit $s"#,
        ],
        0,
    ),
    // A Wayland client, speaking the wire protocol itself: it binds the
    // compositor, shm and xdg_wm_base, makes a toplevel, draws into a
    // memory file's pool, and commits a buffer once configured; the
    // personality's server shows it in a window of the compositor's,
    // which the host's screenshot checks while the client sleeps.
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'int socket(int, int, int); int connect(int, const void *, unsigned); long sendmsg(int, const void *, int); long recvmsg(int, void *, int); long write(int, const void *, unsigned long); int memfd_create(const char *, unsigned); int ftruncate(int, long); void *mmap(void *, unsigned long, int, int, int, long); int printf(const char *, ...); int fflush(void *); unsigned sleep(unsigned); int strcmp(const char *, const char *); unsigned long strlen(const char *); void *memcpy(void *, const void *, unsigned long);\nstruct iov { void *b; unsigned long n; }; struct msg { void *name; unsigned namelen; struct iov *iov; unsigned long iovlen; void *ctl; unsigned long ctllen; int flags; }; struct ctl { unsigned long len; int level, type, fd, pad; }; struct sun { unsigned short fam; char path[108]; };\nunsigned q[128]; int n, s, nfd; char ib[4096]; int ih, it;\nvoid begin(unsigned id, unsigned op) { q[0] = id; q[1] = op; n = 2; } void u(unsigned v) { q[n++] = v; } void str(const char *t) { int l = strlen(t) + 1; q[n++] = l; q[n + (l + 3) / 4 - 1] = 0; memcpy(&q[n], t, l); n += (l + 3) / 4; }\nlong end(int fd) { struct iov v; struct ctl k; struct msg h = { 0 }; q[1] |= n * 4 << 16; if (fd < 0) return write(s, q, n * 4); v.b = q; v.n = n * 4; k.len = 20; k.level = 1; k.type = 1; k.fd = fd; k.pad = 0; h.iov = &v; h.iovlen = 1; h.ctl = &k; h.ctllen = 24; return sendmsg(s, &h, 0); }\nunsigned *ev(void) { unsigned *m; long r; struct iov v; struct msg h; struct ctl k; for (;;) { if (it - ih >= 8) { m = (unsigned *)(ib + ih); if (it - ih >= (int)(m[1] >> 16)) { ih += m[1] >> 16; return m; } } if (ih == it) ih = it = 0; v.b = ib + it; v.n = sizeof ib - it; h.name = 0; h.namelen = 0; h.iov = &v; h.iovlen = 1; h.ctl = &k; h.ctllen = sizeof k; h.flags = 0; r = recvmsg(s, &h, 0); if (r <= 0) return 0; if (h.ctllen) nfd += (k.len - 16) / 4; it += r; } }\nint main(void) { struct sun a = { 1, "/tmp/wayland-0" }; unsigned *m, comp = 0, shm = 0, wm = 0, seat = 0, serial = 0, *px, op, caps = 0, k[4]; int fd, x, y, W = 160, H = 100, done = 0, released = 0, cfg = 0, fmts = 0, px0 = -1, py0 = -1, bx = -1, by = -1, down = 0, up = 0, kin = 0, kfmt = -1, keys = 0; s = socket(1, 1, 0); if (connect(s, &a, sizeof a)) return 1; begin(1, 1); u(2); end(-1); begin(1, 0); u(3); end(-1); while ((m = ev()) && m[0] != 3) if (m[0] == 2 && (m[1] & 0xffff) == 0) { if (!strcmp((char *)&m[4], "wl_compositor")) comp = m[2]; if (!strcmp((char *)&m[4], "wl_shm")) shm = m[2]; if (!strcmp((char *)&m[4], "xdg_wm_base")) wm = m[2]; if (!strcmp((char *)&m[4], "wl_seat")) seat = m[2]; } if (!m || !comp || !shm || !wm || !seat) return 2; begin(2, 0); u(comp); str("wl_compositor"); u(4); u(4); end(-1); begin(2, 0); u(shm); str("wl_shm"); u(1); u(5); end(-1); begin(2, 0); u(wm); str("xdg_wm_base"); u(1); u(6); end(-1); begin(4, 0); u(7); end(-1); fd = memfd_create("wl", 1); if (fd < 0 || ftruncate(fd, W * H * 4)) return 3; px = mmap(0, W * H * 4, 3, 1, fd, 0); if (px == (unsigned *)-1) return 4; for (y = 0; y < H; y++) for (x = 0; x < W; x++) px[y * W + x] = (x * 255 / (W - 1)) << 16 | 0x20 << 8 | y * 255 / (H - 1); begin(5, 0); u(8); u(W * H * 4); if (end(fd) <= 0) return 5; begin(8, 0); u(9); u(0); u(W); u(H); u(W * 4); u(1); end(-1); begin(6, 2); u(10); u(7); end(-1); begin(10, 1); u(11); end(-1); begin(11, 2); str("wayland test"); end(-1); begin(7, 6); end(-1); while ((m = ev())) { if (m[0] == 5) fmts++; if (m[0] == 11 && (m[1] & 0xffff) == 0) cfg = 1; if (m[0] == 10 && (m[1] & 0xffff) == 0) { serial = m[2]; break; } } if (!m) return 6; begin(10, 4); u(serial); end(-1); begin(7, 1); u(9); u(0); u(0); end(-1); begin(7, 2); u(0); u(0); u(W); u(H); end(-1); begin(7, 3); u(12); end(-1); begin(7, 6); end(-1); while (!(done && released) && (m = ev())) { if (m[0] == 12) done = 1; if (m[0] == 9) released = 1; } if (!m) return 7; printf("wayland: %%d formats, configured %%d, a %%dx%%d buffer shown, its frame done and the buffer released\\n", fmts, cfg, W, H); fflush(0); begin(2, 0); u(seat); str("wl_seat"); u(5); u(13); end(-1); begin(13, 0); u(14); end(-1); begin(13, 1); u(15); end(-1); sleep(2); printf("wayland: input ready\\n"); fflush(0); while (keys < 4 || !up) { if (!(m = ev())) return 8; op = m[1] & 0xffff; if (m[0] == 13 && op == 0) caps = m[2]; if (m[0] == 14 && op == 0) { px0 = m[4] >> 8; py0 = m[5] >> 8; } if (m[0] == 14 && op == 2) { px0 = m[3] >> 8; py0 = m[4] >> 8; } if (m[0] == 14 && op == 3 && m[4] == 0x110) { if (m[5]) { down = 1; bx = px0; by = py0; } else if (down) up = 1; } if (m[0] == 15 && op == 0) kfmt = m[2]; if (m[0] == 15 && op == 1) kin = 1; if (m[0] == 15 && op == 3 && keys < 4) k[keys++] = m[4] << 1 | m[5]; } printf("wayland: seat %%d, pointer at %%d,%%d, left pressed and let go; keyboard entered %%d, keymap %%d with %%d fd, keys %%d %%d, %%d %%d, %%d %%d, %%d %%d\\n", caps, bx, by, kin, kfmt, nfd, k[0] >> 1, k[0] & 1, k[1] >> 1, k[1] & 1, k[2] >> 1, k[2] & 1, k[3] >> 1, k[3] & 1); return 0; }\n' > wl.c && tcc -o wl wl.c 2>&1 && ./wl; s=$?; rm -f wl wl.c; exit $s"#,
        ],
        0,
    ),
    // A Wayland client built on libwayland, linked by tcc against it and
    // libxkbcommon: it shows a toplevel, compiles the server's keymap,
    // and makes text of the keys the host types (Shift held for two).
    (
        &[
            "sh",
            "-c",
            r#"cd /tmp/cc && printf 'typedef struct { const char *name, *sig; const void **types; } M;\ntypedef struct { const char *name; int version, nm; const M *m; int ne; const M *e; } I;\nvoid *wl_display_connect(const char *); int wl_display_roundtrip(void *); int wl_display_dispatch(void *);\nvoid *wl_proxy_marshal_flags(void *, unsigned, const I *, unsigned, unsigned, ...); int wl_proxy_add_listener(void *, void *, void *);\nvoid *xkb_context_new(int); void *xkb_keymap_new_from_string(void *, const char *, int, int); void *xkb_state_new(void *);\nint xkb_state_update_mask(void *, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned); int xkb_state_key_get_utf8(void *, unsigned, char *, unsigned long); const char *xkb_keymap_layout_get_name(void *, unsigned);\nint memfd_create(const char *, unsigned); int ftruncate(int, long); void *mmap(void *, unsigned long, int, int, int, long); int close(int); unsigned sleep(unsigned);\nint printf(const char *, ...); int fflush(void *); int strcmp(const char *, const char *);\nconst void *nul[8];\nM reg_m[] = { { "bind", "usun", nul } }, reg_e[] = { { "global", "usu", nul }, { "global_remove", "u", nul } };\nI reg_i = { "wl_registry", 1, 1, reg_m, 2, reg_e };\nM comp_m[] = { { "create_surface", "n", nul }, { "create_region", "n", nul } };\nI comp_i = { "wl_compositor", 4, 2, comp_m, 0, 0 };\nM shm_m[] = { { "create_pool", "nhi", nul } }, shm_e[] = { { "format", "u", nul } };\nI shm_i = { "wl_shm", 1, 1, shm_m, 1, shm_e };\nM pool_m[] = { { "create_buffer", "niiiiu", nul }, { "destroy", "", nul }, { "resize", "i", nul } };\nI pool_i = { "wl_shm_pool", 1, 3, pool_m, 0, 0 };\nM buf_m[] = { { "destroy", "", nul } }, buf_e[] = { { "release", "", nul } };\nI buf_i = { "wl_buffer", 1, 1, buf_m, 1, buf_e };\nM surf_m[] = { { "destroy", "", nul }, { "attach", "?oii", nul }, { "damage", "iiii", nul }, { "frame", "n", nul }, { "set_opaque_region", "?o", nul }, { "set_input_region", "?o", nul }, { "commit", "", nul } }, surf_e[] = { { "enter", "o", nul }, { "leave", "o", nul } };\nI surf_i = { "wl_surface", 4, 7, surf_m, 2, surf_e };\nM wm_m[] = { { "destroy", "", nul }, { "create_positioner", "n", nul }, { "get_xdg_surface", "no", nul }, { "pong", "u", nul } }, wm_e[] = { { "ping", "u", nul } };\nI wm_i = { "xdg_wm_base", 1, 4, wm_m, 1, wm_e };\nM xs_m[] = { { "destroy", "", nul }, { "get_toplevel", "n", nul }, { "get_popup", "n?oo", nul }, { "set_window_geometry", "iiii", nul }, { "ack_configure", "u", nul } }, xs_e[] = { { "configure", "u", nul } };\nI xs_i = { "xdg_surface", 1, 5, xs_m, 1, xs_e };\nM tl_m[] = { { "destroy", "", nul }, { "set_parent", "?o", nul }, { "set_title", "s", nul } }, tl_e[] = { { "configure", "iia", nul }, { "close", "", nul } };\nI tl_i = { "xdg_toplevel", 1, 3, tl_m, 2, tl_e };\nM seat_m[] = { { "get_pointer", "n", nul }, { "get_keyboard", "n", nul } }, seat_e[] = { { "capabilities", "u", nul }, { "name", "2s", nul } };\nI seat_i = { "wl_seat", 5, 2, seat_m, 2, seat_e };\nM kb_m[] = { { "release", "3", nul } }, kb_e[] = { { "keymap", "uhu", nul }, { "enter", "uoa", nul }, { "leave", "uo", nul }, { "key", "uuuu", nul }, { "modifiers", "uuuuu", nul }, { "repeat_info", "4ii", nul } };\nI kb_i = { "wl_keyboard", 5, 1, kb_m, 6, kb_e };\nvoid *comp, *shm, *wm, *seat, *km, *xst; int configured, kfmt = -1, ksize, n; char text[64];\nvoid global(void *d, void *r, unsigned name, const char *ifc, unsigned v) {\n  if (!strcmp(ifc, "wl_compositor")) comp = wl_proxy_marshal_flags(r, 0, &comp_i, 4, 0, name, ifc, 4, 0);\n  if (!strcmp(ifc, "wl_shm")) shm = wl_proxy_marshal_flags(r, 0, &shm_i, 1, 0, name, ifc, 1, 0);\n  if (!strcmp(ifc, "xdg_wm_base")) wm = wl_proxy_marshal_flags(r, 0, &wm_i, 1, 0, name, ifc, 1, 0);\n  if (!strcmp(ifc, "wl_seat")) seat = wl_proxy_marshal_flags(r, 0, &seat_i, 5, 0, name, ifc, 5, 0);\n}\nvoid none(void) {}\nvoid ping(void *d, void *w, unsigned s) { wl_proxy_marshal_flags(w, 3, 0, 1, 0, s); }\nvoid xconf(void *d, void *x, unsigned s) { wl_proxy_marshal_flags(x, 4, 0, 1, 0, s); configured = 1; }\nvoid kmap(void *d, void *k, unsigned f, int fd, unsigned size) {\n  char *m = mmap(0, size, 1, 2, fd, 0);\n  kfmt = f; ksize = size;\n  void *ctx = xkb_context_new(1);\n  if (ctx && m != (char *)-1) km = xkb_keymap_new_from_string(ctx, m, 1, 0);\n  if (km) xst = xkb_state_new(km);\n  close(fd);\n}\nvoid key(void *d, void *k, unsigned s, unsigned t, unsigned code, unsigned st) { if (st == 1 && xst && n < 60) n += xkb_state_key_get_utf8(xst, code + 8, text + n, 64 - n); }\nvoid mods(void *d, void *k, unsigned s, unsigned dep, unsigned lat, unsigned lock, unsigned grp) { if (xst) xkb_state_update_mask(xst, dep, lat, lock, 0, 0, grp); }\nvoid *reg_l[] = { global, none }, *shm_l[] = { none }, *buf_l[] = { none }, *surf_l[] = { none, none }, *wm_l[] = { ping }, *xs_l[] = { xconf }, *tl_l[] = { none, none }, *seat_l[] = { none, none }, *kb_l[] = { kmap, none, none, key, mods, none };\nint main(void) {\n  void *d = wl_display_connect("/tmp/wayland-0"), *r, *pool, *buf, *surf, *xs, *tl, *kb; unsigned *px; int fd, i, W = 160, H = 100;\n  if (!d) return 1;\n  r = wl_proxy_marshal_flags(d, 1, &reg_i, 1, 0, 0);\n  wl_proxy_add_listener(r, reg_l, 0);\n  wl_display_roundtrip(d);\n  if (!comp || !shm || !wm || !seat) return 2;\n  wl_proxy_add_listener(shm, shm_l, 0); wl_proxy_add_listener(wm, wm_l, 0); wl_proxy_add_listener(seat, seat_l, 0);\n  fd = memfd_create("xkb", 1);\n  if (fd < 0 || ftruncate(fd, W * H * 4)) return 3;\n  px = mmap(0, W * H * 4, 3, 1, fd, 0);\n  if (px == (unsigned *)-1) return 4;\n  for (i = 0; i < W * H; i++) px[i] = 0x305070;\n  pool = wl_proxy_marshal_flags(shm, 0, &pool_i, 1, 0, 0, fd, W * H * 4);\n  buf = wl_proxy_marshal_flags(pool, 0, &buf_i, 1, 0, 0, 0, W, H, W * 4, 1);\n  wl_proxy_add_listener(buf, buf_l, 0);\n  surf = wl_proxy_marshal_flags(comp, 0, &surf_i, 4, 0, 0);\n  wl_proxy_add_listener(surf, surf_l, 0);\n  xs = wl_proxy_marshal_flags(wm, 2, &xs_i, 1, 0, 0, surf);\n  wl_proxy_add_listener(xs, xs_l, 0);\n  tl = wl_proxy_marshal_flags(xs, 1, &tl_i, 1, 0, 0);\n  wl_proxy_add_listener(tl, tl_l, 0);\n  wl_proxy_marshal_flags(tl, 2, 0, 1, 0, "xkb test");\n  wl_proxy_marshal_flags(surf, 6, 0, 4, 0);\n  while (!configured) if (wl_display_dispatch(d) < 0) return 5;\n  wl_proxy_marshal_flags(surf, 1, 0, 4, 0, buf, 0, 0);\n  wl_proxy_marshal_flags(surf, 2, 0, 4, 0, 0, 0, W, H);\n  wl_proxy_marshal_flags(surf, 6, 0, 4, 0);\n  kb = wl_proxy_marshal_flags(seat, 1, &kb_i, 5, 0, 0);\n  wl_proxy_add_listener(kb, kb_l, 0);\n  wl_display_roundtrip(d);\n  if (!xst) return 6;\n  sleep(2);\n  printf("xkb: ready\\n"); fflush(0);\n  while (n < 3) if (wl_display_dispatch(d) < 0) return 7;\n  printf("xkb: keymap %%d of %%d bytes, layout %%s; typed %%s\\n", kfmt, ksize, xkb_keymap_layout_get_name(km, 0), text);\n  return 0;\n}\n' > xkb.c && tcc -o xkb xkb.c -lwayland-client -lxkbcommon 2>&1 && ./xkb; s=$?; rm -f xkb xkb.c; exit $s"#,
        ],
        0,
    ),
    // A program larger than a page many times over, read from its file
    // as it is loaded.
    (
        &[
            "sh",
            "-c",
            r#"mkdir -p /home/big && cd /home/big && printf 'char big[200000] = {1};\nint main(void) { return big[0] == 1 && big[199999] == 0 ? 0 : 1; }\n' > big.c && tcc -o big big.c && [ $(wc -c < big) -gt 200000 ] && ./big && cd / && rm -r /home/big && echo ran a program of more than 200000 bytes"#,
        ],
        0,
    ),
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
    // Ping sockets (ICMP echo), and IPv6: the host (QEMU's gateway at
    // fd00:3::2) pinged, a page fetched and TCP and UDP echoed over it.
    (&["ping", "-c", "1", "10.0.3.2"], 0),
    (&["ping6", "-c", "1", "fd00:3::2"], 0),
    (&["sh", "-c", "wget -q -O - http://[fd00:3::2]:47081/hello6"], 0),
    // A browser: links fetches a page from the host and renders it.
    (&["sh", "-c", "links -dump http://10.0.3.2:47081/page.html"], 0),
    // The same page over HTTPS: OpenSSL checks the server's certificate
    // against the test's CA (links refuses it otherwise).
    (&["sh", "-c", "SSL_CERT_FILE=/usr/share/ca/superior-test.pem links -ssl.certificates 2 -dump https://10.0.3.2:47443/page.html"], 0),
    // Without the CA, the certificate is refused and no page shown.
    (&["sh", "-c", "links -ssl.certificates 2 -dump https://10.0.3.2:47443/page.html; echo links said $?"], 0),
    (&["sh", "-c", "echo echoed over TCP and IPv6 | nc fd00:3::2 47002"], 0),
    (&["sh", "-c", "echo echoed over UDP and IPv6 | nc -u -w 2 fd00:3::2 47001"], 0),
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
    // From the first blocks of the rest of RAM with room for them: the
    // processes' and the files' blocks,
    let mut from = UNTYPED_SPARE;
    for b in 0..8 {
        while sys(Syscall::Retype, from, [ObjectType::Untyped as u64, BLOCK_BITS, BLOCKS + b, 0]).is_err() {
            from += 1;
            if from == UNTYPED_SPARE + UNTYPED_SPARE_COUNT {
                return Err("no memory");
            }
        }
    }
    // This server's state.
    while sys(Syscall::Retype, from, [ObjectType::Untyped as u64, STATE_BLOCK_BITS, STATE_BLOCK, 0]).is_err() {
        from += 1;
        if from == UNTYPED_SPARE + UNTYPED_SPARE_COUNT {
            return Err("no spare memory");
        }
    }
    // The buffer programs in the tree's files are read into.
    let exec_bits = (EXEC_PAGES * PAGE).trailing_zeros() as u64;
    while sys(Syscall::Retype, from, [ObjectType::Untyped as u64, exec_bits, EXEC_BLOCK, 0]).is_err() {
        from += 1;
        if from == UNTYPED_SPARE + UNTYPED_SPARE_COUNT {
            return Err("no spare memory");
        }
    }
    for p in 0..EXEC_PAGES {
        sys(Syscall::Retype, EXEC_BLOCK, [ObjectType::Frame as u64, 0, EXEC_SLOTS + p, 0]).map_err(|_| "no memory")?;
        sys(Syscall::FrameMap, EXEC_SLOTS + p, [EXEC_VA + p * PAGE, 1, 0, 0]).map_err(|_| "no room")?;
    }
    // The framebuffer's pages, where there is a compositor to show them
    // (none on the second boot).
    let fb_pages = superior_sys::syscall(Syscall::Call, WINDOWS, window::info()).status == 0 && {
        while from < UNTYPED_SPARE + UNTYPED_SPARE_COUNT
            && sys(Syscall::Retype, from, [ObjectType::Untyped as u64, FB_BLOCK_BITS, FB_BLOCK, 0]).is_err()
        {
            from += 1;
        }
        (0..FB_PAGES).all(|p| {
            sys(Syscall::Retype, FB_BLOCK, [ObjectType::Frame as u64, 0, FB_SLOTS + p, 0]).is_ok()
                && sys(Syscall::FrameMap, FB_SLOTS + p, [FB_VA + p * PAGE, 1, 0, 0]).is_ok()
        })
    };
    // The pages memory files share.
    let shm_pages = {
        while from < UNTYPED_SPARE + UNTYPED_SPARE_COUNT
            && sys(Syscall::Retype, from, [ObjectType::Untyped as u64, SHM_BLOCK_BITS, SHM_BLOCK, 0]).is_err()
        {
            from += 1;
        }
        (0..SHM_PAGES).all(|p| {
            sys(Syscall::Retype, SHM_BLOCK, [ObjectType::Frame as u64, 0, SHM_SLOTS + p, 0]).is_ok()
                && sys(Syscall::FrameMap, SHM_SLOTS + p, [SHM_VA + p * PAGE, 1, 0, 0]).is_ok()
        })
    };
    // Then as many spare blocks as the rest has room for (the more, the
    // larger a process can grow), at least one.
    let mut spares = 0;
    while spares < SPARES && from < UNTYPED_SPARE + UNTYPED_SPARE_COUNT {
        if sys(Syscall::Retype, from, [ObjectType::Untyped as u64, BLOCK_BITS, SPARE_BLOCKS + spares as u64, 0]).is_ok() {
            spares += 1;
        } else {
            from += 1;
        }
    }
    if spares == 0 {
        return Err("no spare memory");
    }
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Endpoint as u64, 0, EP, 0]).map_err(|_| "no endpoint")?;
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Notification as u64, 0, NTFN, 0]).map_err(|_| "no notification")?;
    sys(Syscall::CapMint, NTFN, [NTFN_UART, ALL, 1, 0]).map_err(|_| "no notification")?;
    sys(Syscall::CapMint, NTFN, [NTFN_TIMER, ALL, 2, 0]).map_err(|_| "no notification")?;
    sys(Syscall::CapMint, NTFN, [NTFN_WINDOW, ALL, 4, 0]).map_err(|_| "no notification")?;
    sys(Syscall::NotificationBind, NTFN, [0; 4]).map_err(|_| "could not bind the notification")?;
    if tty::uart::init() != 0 {
        return Err("could not map the UART");
    }
    sys(Syscall::IrqSetNotification, tty::UART_IRQ, [NTFN_UART, 0, 0, 0]).map_err(|_| "no UART interrupt")?;
    for p in 0..STATE_PAGES + fs::POOL_PAGES as u64 {
        let slot = STATE_SLOTS + p;
        let (va, block) = if p < STATE_PAGES { (STATE_VA + p * PAGE, STATE_BLOCK) } else { (POOL_VA + (slot - POOL_SLOTS) * PAGE, FS_BLOCK) };
        sys(Syscall::Retype, block, [ObjectType::Frame as u64, 0, slot, 0]).map_err(|_| "no memory for files")?;
        sys(Syscall::FrameMap, slot, [va, 1, 0, 0]).map_err(|_| "no room for files")?;
    }
    // SAFETY: STATE_PAGES zeroed pages are mapped at STATE_VA, for this
    // server's life; all zero is a valid empty State (every enum's zero
    // is its empty variant), and this is its only reference.
    let st = unsafe { &mut *(STATE_VA as *mut State) };
    // Spare blocks there was no room for: never lent.
    st.spare_owner[spares..].fill(u8::MAX);
    st.fb_pages = fb_pages;
    st.shm_pages = shm_pages;
    wl::start(st);
    let interp = map_file(INTERP_FILE, INTERP_VA, MMAPTEST_FILE - INTERP_FILE);
    let mmaptest = map_file(MMAPTEST_FILE, MMAPTEST_VA, PIGZ_FILE - MMAPTEST_FILE);
    let pigz = map_file(PIGZ_FILE, PIGZ_VA, SMPTEST_FILE - PIGZ_FILE);
    let smptest = map_file(SMPTEST_FILE, SMPTEST_VA, LIBZ_FILE - SMPTEST_FILE);
    let libz = map_file(LIBZ_FILE, LIBZ_VA, FPTEST_FILE - LIBZ_FILE);
    let fptest = map_file(FPTEST_FILE, FPTEST_VA, PROGRAM_FILE - FPTEST_FILE);
    let program = map_file(PROGRAM_FILE, PROGRAM_VA, STATE_SLOTS - PROGRAM_FILE);
    let glibc_ld = map_file(GLIBC_LD_FILE, GLIBC_LD_VA, HELLO_FILE - GLIBC_LD_FILE);
    let hello = map_file(HELLO_FILE, HELLO_VA, LIBC_FILE - HELLO_FILE);
    let libc = map_file(LIBC_FILE, LIBC_VA, LIBC_PAGES);
    let tcc = map_file(TCC_FILE, TCC_VA, MAKE_FILE - TCC_FILE);
    let make = map_file(MAKE_FILE, MAKE_VA, LIBTCC_FILE - MAKE_FILE);
    let libtcc = map_file(LIBTCC_FILE, LIBTCC_VA, TOOLS_FILE - LIBTCC_FILE);
    let tools = map_file(TOOLS_FILE, TOOLS_VA, TOOLS_END - TOOLS_FILE);
    let as_ = map_file(AS_FILE, AS_VA, LD_FILE - AS_FILE);
    let ld = map_file(LD_FILE, LD_VA, LIBBFD_FILE - LD_FILE);
    let libbfd = map_file(LIBBFD_FILE, LIBBFD_VA, LIBCTF_FILE - LIBBFD_FILE);
    let libctf = map_file(LIBCTF_FILE, LIBCTF_VA, LIBSFRAME_FILE - LIBCTF_FILE);
    let libsframe = map_file(LIBSFRAME_FILE, LIBSFRAME_VA, LIBZSTD_FILE - LIBSFRAME_FILE);
    let libzstd = map_file(LIBZSTD_FILE, LIBZSTD_VA, LIBOPCODES_FILE - LIBZSTD_FILE);
    let libopcodes = map_file(LIBOPCODES_FILE, LIBOPCODES_VA, CC1_FILE - LIBOPCODES_FILE);
    let cc1 = map_file(CC1_FILE, CC1_VA, GCC_FILE - CC1_FILE);
    let gcc = map_file(GCC_FILE, GCC_VA, COLLECT2_FILE - GCC_FILE);
    let collect2 = map_file(COLLECT2_FILE, COLLECT2_VA, LIBGCC_A_FILE - COLLECT2_FILE);
    let libgcc_a = map_file(LIBGCC_A_FILE, LIBGCC_A_VA, LIBGMP_FILE - LIBGCC_A_FILE);
    let libgmp = map_file(LIBGMP_FILE, LIBGMP_VA, LIBMPFR_FILE - LIBGMP_FILE);
    let libmpfr = map_file(LIBMPFR_FILE, LIBMPFR_VA, LIBMPC_FILE - LIBMPFR_FILE);
    let libmpc = map_file(LIBMPC_FILE, LIBMPC_VA, LIBISL_FILE - LIBMPC_FILE);
    let libisl = map_file(LIBISL_FILE, LIBISL_VA, LIBGCC_S_FILE - LIBISL_FILE);
    let libgcc_s = map_file(LIBGCC_S_FILE, LIBGCC_S_VA, LINKS_FILE - LIBGCC_S_FILE);
    let links = map_file(LINKS_FILE, LINKS_VA, LIBCRYPTO_FILE - LINKS_FILE);
    let libcrypto = map_file(LIBCRYPTO_FILE, LIBCRYPTO_VA, LIBSSL_FILE - LIBCRYPTO_FILE);
    let libssl = map_file(LIBSSL_FILE, LIBSSL_VA, LIBEVENT_FILE - LIBSSL_FILE);
    let libevent = map_file(LIBEVENT_FILE, LIBEVENT_VA, LIBBZ2_FILE - LIBEVENT_FILE);
    let libbz2 = map_file(LIBBZ2_FILE, LIBBZ2_VA, LINKS_END - LIBBZ2_FILE);
    let libwayland = map_file(LIBWAYLAND_FILE, LIBWAYLAND_VA, LIBFFI_FILE - LIBWAYLAND_FILE);
    let libffi = map_file(LIBFFI_FILE, LIBFFI_VA, LIBXKBCOMMON_FILE - LIBFFI_FILE);
    let libxkbcommon = map_file(LIBXKBCOMMON_FILE, LIBXKBCOMMON_VA, WAYLAND_END - LIBXKBCOMMON_FILE);
    // glibc's dynamic linker is where hello says it is.
    let glibc_ld_path = Elf::parse(hello).ok().and_then(|e| e.interpreter()).unwrap_or(b"");
    st.next_pid = 1;
    // The restorer page, executable in every process.
    sys(Syscall::Retype, FS_BLOCK, [ObjectType::Frame as u64, 0, TRAMPOLINE_SLOT, 0]).map_err(|_| "no memory")?;
    sys(Syscall::FrameMap, TRAMPOLINE_SLOT, [TRAMPOLINE_VA, 1, 0, 0]).map_err(|_| "no room")?;
    // SAFETY: the page was just mapped, writable, at TRAMPOLINE_VA.
    unsafe { core::ptr::copy_nonoverlapping(TRAMPOLINE_CODE.as_ptr(), TRAMPOLINE_VA as *mut u8, TRAMPOLINE_CODE.len()) };
    st.trampoline = Shared { start: TRAMPOLINE, end: TRAMPOLINE + PAGE, ptr: TRAMPOLINE_VA, slot: TRAMPOLINE_SLOT, flags: MAP_EXEC };
    let interp_path = Elf::parse(program).ok().and_then(|e| e.interpreter()).ok_or("BusyBox is not dynamically linked")?;
    // Where each file is: BusyBox first (the runs' programs are its).
    let files: [(&[u8], &'static [u8], u64); MAX_IMAGES] = [
        (b"/bin/busybox", program, PROGRAM_FILE),
        (interp_path, interp, INTERP_FILE),
        (b"/usr/bin/pigz", pigz, PIGZ_FILE),
        (b"/lib/libz.so.1", libz, LIBZ_FILE),
        (b"/usr/bin/fptest", fptest, FPTEST_FILE),
        (b"/usr/bin/smptest", smptest, SMPTEST_FILE),
        (b"/usr/bin/mmaptest", mmaptest, MMAPTEST_FILE),
        (glibc_ld_path, glibc_ld, GLIBC_LD_FILE),
        (LIBC_PATH, libc, LIBC_FILE),
        (b"/usr/bin/hello", hello, HELLO_FILE),
        (b"/usr/bin/tcc", tcc, TCC_FILE),
        (b"/usr/bin/make", make, MAKE_FILE),
        (b"/usr/lib/libtcc.so", libtcc, LIBTCC_FILE),
        (b"/usr/bin/as", as_, AS_FILE),
        (b"/usr/bin/ld", ld, LD_FILE),
        (b"/usr/lib/libbfd-2.40.so", libbfd, LIBBFD_FILE),
        (b"/usr/lib/libctf.so.0", libctf, LIBCTF_FILE),
        (b"/usr/lib/libsframe.so.0", libsframe, LIBSFRAME_FILE),
        (b"/usr/lib/libzstd.so.1", libzstd, LIBZSTD_FILE),
        (b"/usr/lib/libopcodes-2.40.so", libopcodes, LIBOPCODES_FILE),
        (b"/usr/bin/gcc", gcc, GCC_FILE),
        (CC1_PATH, cc1, CC1_FILE),
        (COLLECT2_PATH, collect2, COLLECT2_FILE),
        (LIBGCC_A_PATH, libgcc_a, LIBGCC_A_FILE),
        (b"/usr/lib/libgmp.so.10", libgmp, LIBGMP_FILE),
        (b"/usr/lib/libmpfr.so.6", libmpfr, LIBMPFR_FILE),
        (b"/usr/lib/libmpc.so.3", libmpc, LIBMPC_FILE),
        (b"/usr/lib/libisl.so.23", libisl, LIBISL_FILE),
        (b"/usr/lib/libgcc_s.so.1", libgcc_s, LIBGCC_S_FILE),
        (b"/usr/bin/links", links, LINKS_FILE),
        (b"/lib/libcrypto.so.3", libcrypto, LIBCRYPTO_FILE),
        (b"/lib/libssl.so.3", libssl, LIBSSL_FILE),
        (b"/usr/lib/libevent-2.1.so.7", libevent, LIBEVENT_FILE),
        (b"/usr/lib/libbz2.so.1", libbz2, LIBBZ2_FILE),
        (b"/usr/lib/libwayland-client.so.0", libwayland, LIBWAYLAND_FILE),
        (b"/usr/lib/libffi.so.8", libffi, LIBFFI_FILE),
        (b"/usr/lib/libxkbcommon.so.0", libxkbcommon, LIBXKBCOMMON_FILE),
    ];
    let mut tree = [(&b""[..], &b""[..]); MAX_IMAGES];
    let mut n = 0;
    for (path, bytes, slot) in files {
        if !bytes.is_empty() {
            st.images[n] = Img { bytes, slot };
            tree[n] = (path, bytes);
            n += 1;
        }
    }
    st.fs.init(POOL_VA, &tree[..n], APPLETS);
    unpack(&mut st.fs, tools)?;
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
