//! The Linux personality (Phase 3): runs unmodified Linux programs.
//!
//! A Linux program runs in an address space of its own, on a thread the
//! kernel marks foreign (`ThreadRegisters`, `REGS_FOREIGN`): its `syscall`
//! (x86-64) or `svc` (AArch64) does not reach the kernel's system calls but
//! comes here as a [`FaultKind::ForeignSyscall`] fault. This server reads
//! the arguments, does what Linux would, and resumes the thread after the
//! instruction with the result in `rax` or `x0`, every other register as it
//! was. Its thread pointer (`arch_prctl(ARCH_SET_FS)` on x86-64; on AArch64
//! the program sets `TPIDR_EL0` itself) the kernel keeps per thread.
//!
//! Loading is Linux's: the program (a position-independent executable)
//! and the interpreter it names (`PT_INTERP`, musl's dynamic linker, which
//! is also its C library) are mapped, a stack built with the arguments,
//! environment and auxiliary vector (`AT_PHDR`, `AT_BASE`, `AT_ENTRY`,
//! `AT_RANDOM`, ...), and the thread started at the interpreter's entry.
//! The interpreter relocates itself and the program and calls its `main`.
//!
//! Every page of the program's address space is also mapped here, at the
//! same offset in a mirror window, so its memory is read and written in
//! place (a `write`'s buffer, a `uname`'s structure).
//!
//! Slots: 0 the untyped memory programs are made from, 1 the manager's
//! control endpoint; the interpreter's pages from 16, the program's from
//! 200 (`file` in the manifest). Made here: 2 the endpoint the program's
//! faults arrive on, 3 its badged copy (the program's fault handler), 4 the
//! address space, 5 the thread, and from [`PAGES`] two slots for each page
//! (the program's mapping, and this server's mirror of it).
//!
//! Not yet: processes (`fork`, `clone`, `execve`), files, signals,
//! fixed-address (non-PIE) executables, which Linux links at 4 MiB where
//! Superior's kernel lives on AArch64.

#![no_std]
#![no_main]

use superior_objects::abi::{
    FaultKind, FaultReply, MAP_EXEC, MAP_WRITE, ObjectType, REGS_FOREIGN, REGS_SET_TLS, REGS_SYSCALL,
    REGS_SYSCALL_MORE, REGS_TLS, Syscall, TICK_HZ,
};
use superior_objects::elf::{Elf, Machine};
use superior_sys::{USER_BASE, print_line, syscall};

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!($($t)*)) };
}

const UNTYPED: u64 = 0;
const CONTROL: u64 = 1;
const EP: u64 = 2;
const EP_FAULT: u64 = 3;
const SPACE: u64 = 4;
const THREAD: u64 = 5;
const INTERP_FILE: u64 = 16;
const PROGRAM_FILE: u64 = 200;
const PAGES: u64 = 1024;
const MAX_PAGES: u64 = 1500;
const OP_SHUTDOWN: u64 = 2;
const ALL: u64 = 0x1f;
const WRITE_RIGHT: u64 = 1 << 1;
const PAGE: u64 = 4096;

/// Where the files are mapped here.
const INTERP_VA: u64 = USER_BASE + 0x1_0000_0000;
const PROGRAM_VA: u64 = USER_BASE + 0x1_1000_0000;

/// A program's address space: everything inside [`CHILD`, `CHILD_END`).
const CHILD: u64 = USER_BASE + 0x40_0000_0000;
const CHILD_END: u64 = CHILD + 0x1000_0000;
const PROGRAM_BASE: u64 = CHILD + 0x40_0000;
const INTERP_BASE: u64 = CHILD + 0x400_0000;
const MMAP_BASE: u64 = CHILD + 0x800_0000;
const STACK_TOP: u64 = CHILD_END - 0x10_0000;
const STACK_PAGES: u64 = 32;
/// How far `brk` may grow.
const BRK_MAX: u64 = 0x80_0000;
/// The mirror: a program's page at `va` is here at `va - CHILD + MIRROR`.
const MIRROR: u64 = USER_BASE + 0x48_0000_0000;
const CHILD_PAGES: usize = ((CHILD_END - CHILD) / PAGE) as usize;

const MACHINE: Machine = if cfg!(target_arch = "x86_64") { Machine::X86_64 } else { Machine::Aarch64 };
const PLATFORM: &str = if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" };

// Linux error numbers.
const ENOENT: u64 = 2;
const EBADF: u64 = 9;
const ENOMEM: u64 = 12;
const EFAULT: u64 = 14;
const EINVAL: u64 = 22;
const ENOTTY: u64 = 25;
const ESPIPE: u64 = 29;
const ENOSYS: u64 = 38;
const ENODEV: u64 = 19;

const fn err(e: u64) -> u64 {
    e.wrapping_neg()
}

/// The system calls answered, by name; [`Sys::from`] maps each ISA's
/// numbers (x86-64's own table, AArch64's the generic one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sys {
    Read,
    Write,
    Writev,
    Open,
    Close,
    Stat,
    Fstat,
    Lseek,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    Sigaction,
    Sigprocmask,
    Sigaltstack,
    Ioctl,
    Madvise,
    Getpid,
    Gettid,
    Getppid,
    Getuid,
    Exit,
    ExitGroup,
    Uname,
    Getcwd,
    Readlink,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    ArchPrctl,
    SetTidAddress,
    SetRobustList,
    ClockGettime,
    Getrandom,
    Other(u64),
}

impl Sys {
    #[cfg(target_arch = "x86_64")]
    fn from(nr: u64) -> Sys {
        match nr {
            0 => Sys::Read,
            1 => Sys::Write,
            2 | 257 => Sys::Open,
            3 => Sys::Close,
            4 | 6 | 21 | 262 | 269 | 332 => Sys::Stat,
            5 => Sys::Fstat,
            8 => Sys::Lseek,
            9 => Sys::Mmap,
            10 => Sys::Mprotect,
            11 => Sys::Munmap,
            12 => Sys::Brk,
            13 => Sys::Sigaction,
            14 => Sys::Sigprocmask,
            16 => Sys::Ioctl,
            20 => Sys::Writev,
            28 => Sys::Madvise,
            39 => Sys::Getpid,
            60 => Sys::Exit,
            63 => Sys::Uname,
            79 => Sys::Getcwd,
            89 | 267 => Sys::Readlink,
            102 | 104 | 107 | 108 => Sys::Getuid,
            110 => Sys::Getppid,
            131 => Sys::Sigaltstack,
            158 => Sys::ArchPrctl,
            186 => Sys::Gettid,
            218 => Sys::SetTidAddress,
            228 => Sys::ClockGettime,
            231 => Sys::ExitGroup,
            273 => Sys::SetRobustList,
            318 => Sys::Getrandom,
            n => Sys::Other(n),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn from(nr: u64) -> Sys {
        match nr {
            17 => Sys::Getcwd,
            29 => Sys::Ioctl,
            48 | 79 | 291 => Sys::Stat,
            56 => Sys::Open,
            57 => Sys::Close,
            62 => Sys::Lseek,
            63 => Sys::Read,
            64 => Sys::Write,
            66 => Sys::Writev,
            78 => Sys::Readlink,
            80 => Sys::Fstat,
            93 => Sys::Exit,
            94 => Sys::ExitGroup,
            96 => Sys::SetTidAddress,
            99 => Sys::SetRobustList,
            113 => Sys::ClockGettime,
            132 => Sys::Sigaltstack,
            134 => Sys::Sigaction,
            135 => Sys::Sigprocmask,
            160 => Sys::Uname,
            172 => Sys::Getpid,
            173 => Sys::Getppid,
            174..=177 => Sys::Getuid,
            178 => Sys::Gettid,
            214 => Sys::Brk,
            215 => Sys::Munmap,
            222 => Sys::Mmap,
            226 => Sys::Mprotect,
            233 => Sys::Madvise,
            278 => Sys::Getrandom,
            n => Sys::Other(n),
        }
    }
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

/// One program's address space and what this server knows of it.
struct Child {
    /// Pages made so far.
    pages: u64,
    /// Which pages of [`CHILD`, `CHILD_END`) are mapped.
    present: [u64; CHILD_PAGES / 64],
    brk_start: u64,
    brk: u64,
    mmap_next: u64,
    /// Output not yet printed: the line being written.
    line: [u8; 160],
    len: usize,
}

impl Child {
    fn is_present(&self, va: u64) -> bool {
        let i = ((va - CHILD) / PAGE) as usize;
        self.present[i / 64] & (1 << (i % 64)) != 0
    }

    /// Maps a fresh zeroed page at page-aligned `va` in the program (with
    /// `flags`) and in the mirror, unless it is mapped already.
    fn map(&mut self, va: u64, flags: u64) -> Result<(), u64> {
        if !(CHILD..CHILD_END).contains(&va) {
            return Err(EFAULT);
        }
        if self.is_present(va) {
            return Ok(());
        }
        if self.pages == MAX_PAGES {
            return Err(ENOMEM);
        }
        let slot = PAGES + 2 * self.pages;
        sys(Syscall::Retype, UNTYPED, [ObjectType::Frame as u64, 0, slot, 0]).map_err(|_| ENOMEM)?;
        self.pages += 1;
        sys(Syscall::CapMint, slot, [slot + 1, ALL, 0, 0])?;
        sys(Syscall::FrameMap, slot + 1, [va - CHILD + MIRROR, 1, 0, 0])?;
        sys(Syscall::FrameMapInto, slot, [va, flags, SPACE, 0])?;
        let i = ((va - CHILD) / PAGE) as usize;
        self.present[i / 64] |= 1 << (i % 64);
        Ok(())
    }

    /// The program's memory at `va`, `len` bytes, if every page is mapped.
    fn mem(&self, va: u64, len: u64) -> Option<&'static mut [u8]> {
        let end = va.checked_add(len)?;
        if va < CHILD || end > CHILD_END {
            return None;
        }
        let mut p = va & !(PAGE - 1);
        while p < end {
            if !self.is_present(p) {
                return None;
            }
            p += PAGE;
        }
        // SAFETY: every page of the range is mapped in the mirror, which
        // only this (single-threaded) server touches while the program
        // waits on it.
        Some(unsafe { core::slice::from_raw_parts_mut((va - CHILD + MIRROR) as *mut u8, len as usize) })
    }

    fn put(&self, va: u64, bytes: &[u8]) -> Result<(), u64> {
        self.mem(va, bytes.len() as u64).ok_or(EFAULT)?.copy_from_slice(bytes);
        Ok(())
    }

    fn word(&self, va: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.mem(va, 8)?.try_into().ok()?))
    }

    /// Output on standard output or error, printed a line at a time.
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

    /// Loads a position-independent ELF image at `base`: (entry, program
    /// headers' address, their count, the end of the image).
    fn load(&mut self, image: &[u8], base: u64) -> Result<(u64, u64, u64, u64), &'static str> {
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
            for page in (lo..hi).step_by(PAGE as usize) {
                // A page's permissions: every segment on it.
                let (mut write, mut exec) = (false, false);
                for s in elf.segments().flatten() {
                    if s.mem_size > 0 && s.vaddr < page + PAGE && s.vaddr + s.mem_size > page {
                        write |= s.writable;
                        exec |= s.executable;
                    }
                }
                let flags = match (write, exec) {
                    (true, true) => return Err("a page both writable and executable"),
                    (true, false) => MAP_WRITE,
                    (false, true) => MAP_EXEC,
                    (false, false) => 0,
                };
                self.map(base + page, flags).map_err(|_| "out of memory")?;
            }
            let bytes = elf.file_bytes(&seg);
            self.put(base + seg.vaddr, bytes).map_err(|_| "out of memory")?;
        }
        let (phoff, phnum) = elf.program_headers();
        Ok((base + elf.entry, base + phoff, phnum as u64, base + end))
    }
}

/// Runs `program` with arguments `argv` to its exit, `interp` being the
/// interpreter it names. Returns its exit status, or why it could not run.
fn run(
    program: &[u8],
    interp: &[u8],
    argv: &[&str],
    env: &[&str],
    child: &mut Child,
) -> Result<u64, &'static str> {
    let elf = Elf::parse(program).map_err(|_| "not an ELF executable")?;
    let wants = elf.interpreter().and_then(|s| core::str::from_utf8(s).ok()).ok_or("not dynamically linked")?;
    let made = |r: Result<[u64; 4], u64>, what| r.map(drop).map_err(|_| what);
    made(sys(Syscall::Retype, UNTYPED, [ObjectType::Endpoint as u64, 0, EP, 0]), "no endpoint")?;
    made(sys(Syscall::CapMint, EP, [EP_FAULT, WRITE_RIGHT, 1, 0]), "no endpoint")?;
    made(sys(Syscall::Retype, UNTYPED, [ObjectType::AddressSpace as u64, 17, SPACE, 0]), "no address space")?;
    made(sys(Syscall::Retype, UNTYPED, [ObjectType::Thread as u64, 0, THREAD, 0]), "no thread")?;

    let (entry, phdr, phnum, end) = child.load(program, PROGRAM_BASE)?;
    let (interp_entry, ..) = child.load(interp, INTERP_BASE)?;
    child.brk_start = end + PAGE;
    child.brk = child.brk_start;
    child.mmap_next = MMAP_BASE;
    for p in 1..=STACK_PAGES {
        child.map(STACK_TOP - p * PAGE, MAP_WRITE).map_err(|_| "out of memory")?;
    }
    say!(
        "linux: running {} ({} bytes, position-independent; interpreter {wants})",
        argv.join_display(),
        program.len()
    );

    // The stack Linux gives a new program: strings at the top, then the
    // auxiliary vector, environment and argument pointers, and argc.
    let mut top = STACK_TOP;
    let mut push_str = |s: &[u8], child: &Child| -> Result<u64, &'static str> {
        top -= s.len() as u64 + 1;
        child.put(top, s).and_then(|_| child.put(top + s.len() as u64, &[0])).map_err(|_| "stack")?;
        Ok(top)
    };
    let mut argp = [0u64; 8];
    let mut envp = [0u64; 8];
    for (i, a) in argv.iter().enumerate() {
        argp[i] = push_str(a.as_bytes(), child)?;
    }
    for (i, e) in env.iter().enumerate() {
        envp[i] = push_str(e.as_bytes(), child)?;
    }
    let platform = push_str(PLATFORM.as_bytes(), child)?;
    let random = push_str(&superior_sys::random().unwrap_or([0x5a; 32])[..16], child)?;
    let execfn = argp[0];
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
    let words = 1 + argv.len() + 1 + env.len() + 1 + 2 * (aux.len() + 1);
    let mut sp = (top - 8 * words as u64) & !15;
    // x86-64 threads start as if called (8 below a 16-byte boundary); the
    // interpreter realigns its stack itself.
    let thread_top = if cfg!(target_arch = "x86_64") {
        sp -= 8;
        sp + 8
    } else {
        sp
    };
    let mut at = sp;
    let mut push = |w: u64| -> Result<(), &'static str> {
        child.put(at, &w.to_le_bytes()).map_err(|_| "stack")?;
        at += 8;
        Ok(())
    };
    push(argv.len() as u64)?;
    argp[..argv.len()].iter().try_for_each(|&p| push(p))?;
    push(0)?;
    envp[..env.len()].iter().try_for_each(|&p| push(p))?;
    push(0)?;
    for (k, v) in aux {
        push(k)?;
        push(v)?;
    }
    push(0)?;
    push(0)?;

    made(sys(Syscall::ThreadSetVSpace, THREAD, [SPACE, 0, 0, 0]), "set address space")?;
    made(sys(Syscall::ThreadConfigure, THREAD, [interp_entry, thread_top, 0, 5]), "configure the thread")?;
    made(sys(Syscall::ThreadSetFaultHandler, THREAD, [EP_FAULT, 0, 0, 0]), "set fault handler")?;
    made(sys(Syscall::ThreadRegisters, THREAD, [REGS_FOREIGN, 1, 0, 0]), "make the thread foreign")?;
    made(sys(Syscall::ThreadResume, THREAD, [0; 4]), "start the thread")?;

    let mut r = syscall(Syscall::Recv, EP, [0; 4]);
    loop {
        let [kind, nr, pc, _] = r.msg;
        if r.status != 0 || FaultKind::from_u64(kind) != Some(FaultKind::ForeignSyscall) {
            child.flush();
            let what = match FaultKind::from_u64(kind) {
                Some(FaultKind::PageFault) => "page fault",
                Some(FaultKind::GeneralProtection) => "general protection fault",
                Some(FaultKind::InvalidOpcode) => "invalid instruction",
                Some(FaultKind::DivideError) => "divide error",
                _ => "unknown fault",
            };
            say!("linux: {} stopped: {what} at pc {pc:#x}, address {nr:#x}", argv[0]);
            return Err("the program faulted");
        }
        let a = sys(Syscall::ThreadRegisters, THREAD, [REGS_SYSCALL, 0, 0, 0]).unwrap_or([0; 4]);
        let b = sys(Syscall::ThreadRegisters, THREAD, [REGS_SYSCALL_MORE, 0, 0, 0]).unwrap_or([0; 4]);
        let args = [a[1], a[2], a[3], b[0], b[1], b[2]];
        let ret = match answer(Sys::from(nr), args, child) {
            Answer::Return(v) => v,
            Answer::Exit(status) => {
                child.flush();
                return Ok(status);
            }
        };
        r = syscall(Syscall::ReplyRecv, EP, [FaultReply::ResumeAt as u64, pc, ret, 0]);
    }
}

enum Answer {
    Return(u64),
    Exit(u64),
}

/// Does what Linux would for one system call.
fn answer(call: Sys, a: [u64; 6], child: &mut Child) -> Answer {
    use Answer::Return;
    Return(match call {
        Sys::Exit | Sys::ExitGroup => return Answer::Exit(a[0] & 0xff),
        Sys::Write => match child.mem(a[1], a[2]) {
            Some(b) if a[0] == 1 || a[0] == 2 => {
                child.output(b);
                a[2]
            }
            Some(_) => err(EBADF),
            None => err(EFAULT),
        },
        Sys::Writev => {
            if a[0] != 1 && a[0] != 2 {
                return Return(err(EBADF));
            }
            let mut total = 0;
            for i in 0..a[2].min(64) {
                let (Some(base), Some(len)) = (child.word(a[1] + 16 * i), child.word(a[1] + 16 * i + 8)) else {
                    return Return(err(EFAULT));
                };
                let Some(b) = child.mem(base, len) else { return Return(err(EFAULT)) };
                child.output(b);
                total += len;
            }
            total
        }
        // No standard input yet: at its end at once.
        Sys::Read if a[0] == 0 => 0,
        Sys::Read => err(EBADF),
        // No files yet.
        Sys::Open | Sys::Stat | Sys::Readlink => err(ENOENT),
        Sys::Fstat => err(ENOSYS),
        Sys::Lseek => err(ESPIPE),
        // Not a terminal: so output is buffered until exit.
        Sys::Ioctl => err(ENOTTY),
        Sys::Close | Sys::Mprotect | Sys::Munmap | Sys::Madvise => 0,
        Sys::Sigaction | Sys::Sigprocmask | Sys::Sigaltstack | Sys::SetRobustList => 0,
        Sys::Getpid | Sys::Gettid | Sys::SetTidAddress => 1,
        Sys::Getppid | Sys::Getuid => 0,
        Sys::Brk => {
            let want = a[0];
            if want <= child.brk_start || want > child.brk_start + BRK_MAX {
                return Return(child.brk);
            }
            let mut p = child.brk.next_multiple_of(PAGE);
            while p < want {
                if child.map(p, MAP_WRITE).is_err() {
                    return Return(child.brk);
                }
                p += PAGE;
            }
            child.brk = want;
            want
        }
        Sys::Mmap => {
            const MAP_FIXED: u64 = 0x10;
            const MAP_ANONYMOUS: u64 = 0x20;
            let (addr, len, flags) = (a[0], a[1].next_multiple_of(PAGE), a[3]);
            if flags & MAP_ANONYMOUS == 0 {
                return Return(err(ENODEV));
            }
            if len == 0 {
                return Return(err(EINVAL));
            }
            let at = if flags & MAP_FIXED != 0 {
                addr
            } else {
                let at = child.mmap_next;
                child.mmap_next += len + PAGE;
                at
            };
            if at % PAGE != 0 || at < CHILD || at + len > STACK_TOP - STACK_PAGES * PAGE {
                return Return(err(ENOMEM));
            }
            for p in (at..at + len).step_by(PAGE as usize) {
                let was = child.is_present(p);
                if child.map(p, MAP_WRITE).is_err() {
                    return Return(err(ENOMEM));
                }
                if was {
                    if let Some(m) = child.mem(p, PAGE) {
                        m.fill(0);
                    }
                }
            }
            at
        }
        Sys::Uname => {
            let mut u = [0u8; 6 * 65];
            for (i, f) in ["Linux", "superior", "6.1.0-superior", "#1 Superior", PLATFORM, ""].iter().enumerate() {
                u[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
            }
            child.put(a[0], &u).map_or(err(EFAULT), |_| 0)
        }
        Sys::Getcwd => {
            if a[1] < 2 {
                return Return(err(EINVAL));
            }
            child.put(a[0], b"/\0").map_or(err(EFAULT), |_| 2)
        }
        Sys::ArchPrctl => {
            const ARCH_SET_FS: u64 = 0x1002;
            const ARCH_GET_FS: u64 = 0x1003;
            match a[0] {
                ARCH_SET_FS => sys(Syscall::ThreadRegisters, THREAD, [REGS_SET_TLS, a[1], 0, 0]).map_or(err(EINVAL), |_| 0),
                ARCH_GET_FS => {
                    let fs = sys(Syscall::ThreadRegisters, THREAD, [REGS_TLS, 0, 0, 0]).map_or(0, |m| m[0]);
                    child.put(a[1], &fs.to_le_bytes()).map_or(err(EFAULT), |_| 0)
                }
                _ => err(EINVAL),
            }
        }
        Sys::ClockGettime => {
            let t = superior_sys::ticks();
            let mut ts = [0u8; 16];
            ts[..8].copy_from_slice(&(t / TICK_HZ).to_le_bytes());
            ts[8..].copy_from_slice(&((t % TICK_HZ) * (1_000_000_000 / TICK_HZ)).to_le_bytes());
            child.put(a[1], &ts).map_or(err(EFAULT), |_| 0)
        }
        Sys::Getrandom => {
            let Some(m) = child.mem(a[0], a[1].min(256)) else { return Return(err(EFAULT)) };
            for chunk in m.chunks_mut(32) {
                let r = superior_sys::random().unwrap_or([0x5a; 32]);
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            a[1].min(256)
        }
        Sys::Other(n) => {
            say!("linux: system call {n} not implemented");
            err(ENOSYS)
        }
    })
}

/// Destroys the program: its thread, address space, pages and the
/// endpoint, everything made from the untyped memory.
fn tear_down(child: &mut Child) {
    let _ = syscall(Syscall::CapRevoke, UNTYPED, [0; 4]);
    child.pages = 0;
    child.present = [0; CHILD_PAGES / 64];
    child.len = 0;
}

/// Joins words with spaces, for messages.
trait JoinDisplay {
    fn join_display(&self) -> Joined<'_>;
}

struct Joined<'a>(&'a [&'a str]);

impl JoinDisplay for [&str] {
    fn join_display(&self) -> Joined<'_> {
        Joined(self)
    }
}

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

/// What the test runs, and the exit status each must end with.
const RUNS: &[(&[&str], u64)] = &[
    (&["busybox", "echo", "hello from Linux"], 0),
    (&["busybox", "uname", "-sm"], 0),
    (&["busybox", "sh", "-c", "echo $((6 * 7)) from the shell; exit 3"], 3),
    // Floating point: the FPU's registers are the thread's own.
    (&["busybox", "awk", "BEGIN { printf \"pi is %.6f\\n\", atan2(0, -1) }"], 0),
];

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut child = Child {
        pages: 0,
        present: [0; CHILD_PAGES / 64],
        brk_start: 0,
        brk: 0,
        mmap_next: 0,
        line: [0; 160],
        len: 0,
    };
    let interp = map_file(INTERP_FILE, INTERP_VA, PROGRAM_FILE - INTERP_FILE);
    let program = map_file(PROGRAM_FILE, PROGRAM_VA, PAGES - PROGRAM_FILE);
    let mut failures = 0;
    for &(argv, want) in RUNS {
        let r = run(program, interp, argv, &["PATH=/bin", "HOME=/"], &mut child);
        tear_down(&mut child);
        match r {
            Ok(status) => {
                say!("linux: {} exited with status {status}", argv.join_display());
                failures += (status != want) as u64;
            }
            Err(why) => {
                say!("linux: {} could not run: {why}", argv.join_display());
                failures += 1;
            }
        }
    }
    syscall(Syscall::Call, CONTROL, [OP_SHUTDOWN, failures, 0, 0]);
    superior_sys::park()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
