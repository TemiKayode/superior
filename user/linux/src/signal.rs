//! Signals: actions, masks, sending and delivery.
//!
//! A signal sent to a process is pending until the process can take it.
//! One whose action is to end the process ends it at once, wherever it is.
//! One with a handler is taken when the process next comes back from a
//! system call: if it is waiting in one (a pipe, `wait4`, `nanosleep`,
//! `sigsuspend`), that call is interrupted (`EINTR`, or restarted with
//! `SA_RESTART`); if it is running, at its next call. (A process that
//! spins without making one is not interrupted for a handler; for that the
//! thread would be stopped where it runs.) Taking it is Linux's: the
//! registers the process would have resumed with, and its signal mask, go
//! in a frame on its stack (`rt_sigframe`, with the registers in
//! `sigcontext`'s order, the order the kernel's `REGS_GET` and `REGS_SET`
//! number them), and the thread starts in the handler with the signal,
//! `siginfo` and `ucontext` as its arguments, returning to the restorer
//! musl gives (`SA_RESTORER`) or to this server's own (a page at
//! [`TRAMPOLINE`] in every process), which calls `rt_sigreturn` to take
//! the frame back. Not yet in the frame: the FPU and SIMD registers (a
//! handler that uses them leaves them changed for the code it
//! interrupted), and an alternate signal stack.
//!
//! Job control: a stop signal whose action is the default (`SIGSTOP`,
//! and `SIGTSTP`, `SIGTTIN`, `SIGTTOU` unless caught) stops the whole
//! process. Its threads running in user space are suspended where they
//! are; one coming back from a call is held there, its answer kept; one
//! waiting in a call goes on waiting, and is not answered while stopped.
//! The parent hears of it (`SIGCHLD`, unless `SA_NOCLDSTOP`; `wait4` with
//! `WUNTRACED`). `SIGCONT` continues it, whatever its action, and drops
//! any stop pending (as a stop drops a pending `SIGCONT`); `wait4` with
//! `WCONTINUED` reports that. Only `SIGKILL` acts on a stopped process;
//! other signals wait until it continues.

use super::*;

pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTTIN: u32 = 21;
const NSIG: u32 = 64;

/// The stop signals: `SIGSTOP`, `SIGTSTP`, `SIGTTIN` and `SIGTTOU`.
const STOPS: u64 = bit(19) | bit(20) | bit(21) | bit(22);

const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
const SA_NOCLDSTOP: u64 = 1;
const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;

pub const fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

/// What masks never hold back.
const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// Linux's (kernel) `struct sigaction`, as musl passes it.
#[derive(Clone, Copy)]
pub struct Action {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// Signals whose default is to do nothing: `SIGCHLD`, `SIGCONT` (whose
/// continuing is done when it is sent), `SIGURG`, `SIGWINCH`.
fn ignored_by_default(sig: u32) -> bool {
    matches!(sig, 17 | 18 | 23 | 28)
}

/// Signals whose default is to stop the process.
fn stops_by_default(sig: u32) -> bool {
    STOPS & bit(sig) != 0
}

/// What a process must do about its signals now.
pub enum Next {
    None,
    /// End, killed by this signal.
    Kill(u32),
    /// Run this signal's handler.
    Handle(u32),
    /// Stop, for this signal (taken: no longer pending).
    Stop(u32),
}

/// Where the restorer page is in every process: `rt_sigreturn`, for
/// handlers set without `SA_RESTORER`.
pub const TRAMPOLINE: u64 = CHILD + PAGE;
/// Its code: `mov $15, %eax; syscall` / `mov x8, #139; svc #0`.
pub const TRAMPOLINE_CODE: &[u8] = if cfg!(target_arch = "x86_64") {
    &[0xb8, 0x0f, 0, 0, 0, 0x0f, 0x05]
} else {
    &[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4]
};

/// The registers, in `REGS_GET`'s order: how many, and which are the
/// result, stack pointer and program counter.
const COUNT: usize = REGS_COUNT as usize;
const RESULT: usize = if cfg!(target_arch = "x86_64") { 13 } else { 0 };
pub const SP: usize = if cfg!(target_arch = "x86_64") { 15 } else { 31 };
const PC: usize = if cfg!(target_arch = "x86_64") { 16 } else { 32 };
/// The `ucontext` the handler gets: its size, and where its registers
/// (`uc_mcontext`'s general registers) and signal mask are in it.
const UC_LEN: u64 = if cfg!(target_arch = "x86_64") { 304 } else { 528 };
const UC_REGS: u64 = if cfg!(target_arch = "x86_64") { 40 } else { 184 };
const UC_MASK: u64 = if cfg!(target_arch = "x86_64") { 296 } else { 40 };
const INFO_LEN: u64 = 128;
/// The instruction that made a system call, to make it again.
pub const SYSCALL_LEN: u64 = if cfg!(target_arch = "x86_64") { 2 } else { 4 };

fn regs(th: u64) -> Option<[u64; COUNT]> {
    let mut r = [0; COUNT];
    for k in (0..COUNT).step_by(4) {
        let m = sys(Syscall::ThreadRegisters, th, [REGS_GET, k as u64, 0, 0]).ok()?;
        let n = (COUNT - k).min(4);
        r[k..k + n].copy_from_slice(&m[..n]);
    }
    Some(r)
}

fn set_regs(th: u64, r: &[u64; COUNT]) -> Option<()> {
    for k in (0..COUNT).step_by(2) {
        sys(Syscall::ThreadRegisters, th, [REGS_SET, k as u64, r[k], r[k + 1]]).ok()?;
    }
    Some(())
}

impl State {
    /// Whether process `i` drops `sig` when sent: its action ignores it,
    /// and no thread masks it (the action may change before it is
    /// unmasked).
    fn dropped(&self, i: usize, sig: u32) -> bool {
        let a = self.procs[i].actions[sig as usize - 1];
        let ignored = sig != SIGKILL && (a.handler == SIG_IGN || a.handler == SIG_DFL && ignored_by_default(sig));
        ignored && self.tasks_of(i).all(|t| self.tasks[t].mask & bit(sig) == 0)
    }

    /// Sends `sig` to process `i`, for whichever of its threads takes it.
    pub fn post(&mut self, i: usize, sig: u32) {
        let p = &self.procs[i];
        if !p.used || p.zombie || sig == 0 || sig > NSIG {
            return;
        }
        self.job_control(i, sig);
        if self.dropped(i, sig) {
            return;
        }
        self.procs[i].pending |= bit(sig);
    }

    /// Sends `sig` to task `t` alone (`tkill`).
    pub fn post_task(&mut self, t: usize, sig: u32) {
        let i = self.tasks[t].proc as usize;
        if sig == 0 || sig > NSIG || self.procs[i].zombie {
            return;
        }
        self.job_control(i, sig);
        if self.dropped(i, sig) {
            return;
        }
        self.tasks[t].pending |= bit(sig);
    }

    /// What sending `sig` to process `i` does at once: `SIGCONT`
    /// continues it and drops pending stops; a stop drops a pending
    /// `SIGCONT`.
    fn job_control(&mut self, i: usize, sig: u32) {
        let drop = if sig == SIGCONT {
            STOPS
        } else if STOPS & bit(sig) != 0 {
            bit(SIGCONT)
        } else {
            return;
        };
        self.procs[i].pending &= !drop;
        for t in 0..MAX_TASKS {
            if self.tasks[t].used && self.tasks[t].proc as usize == i {
                self.tasks[t].pending &= !drop;
            }
        }
        if sig == SIGCONT {
            self.cont(i);
        }
    }

    /// Process `i`'s parent, if it is still there.
    fn parent(&self, i: usize) -> Option<usize> {
        let ppid = self.procs[i].ppid;
        self.procs.iter().position(|q| q.used && !q.zombie && q.pid == ppid)
    }

    /// Tells process `i`'s parent it stopped or continued: `SIGCHLD`,
    /// unless its action says `SA_NOCLDSTOP`.
    fn tell_parent(&mut self, i: usize) {
        if let Some(parent) = self.parent(i) {
            if self.procs[parent].actions[SIGCHLD as usize - 1].flags & SA_NOCLDSTOP == 0 {
                self.post(parent, SIGCHLD);
            }
        }
    }

    /// Stops process `i` for `sig`: its threads running in user space are
    /// suspended where they are (all but `current`, whose call is being
    /// answered: the caller holds it), and its parent told.
    pub fn stop(&mut self, i: usize, sig: u32, current: Option<usize>) {
        if self.procs[i].stopped {
            return;
        }
        for t in 0..MAX_TASKS {
            let task = &mut self.tasks[t];
            if !task.used || task.proc as usize != i || Some(t) == current || task.frozen {
                continue;
            }
            if matches!(task.blocked, Blocked::None) && sys(Syscall::ThreadSuspend, task.thread, [0; 4]).is_ok() {
                task.frozen = true;
            }
        }
        let p = &mut self.procs[i];
        p.stopped = true;
        p.stop_sig = sig as u8;
        p.report = Report::Stopped;
        self.tell_parent(i);
    }

    /// Continues process `i`, if stopped: its suspended threads go on
    /// where they were; calls held or set aside are answered as they can
    /// be ([`wake`]).
    fn cont(&mut self, i: usize) {
        if !self.procs[i].stopped {
            return;
        }
        for t in 0..MAX_TASKS {
            let task = &mut self.tasks[t];
            if task.used && task.proc as usize == i && core::mem::take(&mut task.frozen) {
                let _ = sys(Syscall::ThreadResume, task.thread, [0; 4]);
            }
        }
        let p = &mut self.procs[i];
        p.stopped = false;
        p.report = Report::Continued;
        self.tell_parent(i);
    }

    /// Whether process `i` is stopped with a `SIGKILL` waiting for it,
    /// which ends it even so.
    pub fn killed_while_stopped(&self, i: usize) -> bool {
        self.procs[i].stopped
            && ((self.procs[i].pending | self.tasks_of(i).fold(0, |m, t| m | self.tasks[t].pending)) & bit(SIGKILL)) != 0
    }

    /// Whether process `i` neither ignores nor blocks `sig` (in any of its
    /// threads): for `SIGTTIN`, which stops a background reader of the
    /// terminal only then (else the read fails).
    pub fn takes(&self, i: usize, sig: u32) -> bool {
        self.procs[i].actions[sig as usize - 1].handler != SIG_IGN && self.tasks_of(i).all(|t| self.tasks[t].mask & bit(sig) == 0)
    }

    /// Sends `sig` to every process in group `pgid`; whether there was one.
    pub fn post_group(&mut self, pgid: u32, sig: u32) -> bool {
        let mut any = false;
        for i in 0..MAX_PROCS {
            if self.procs[i].used && !self.procs[i].zombie && self.procs[i].pgid == pgid {
                self.post(i, sig);
                any = true;
            }
        }
        any
    }

    /// What task `t` must do about the signals pending for it or its
    /// process, dropping those now ignored.
    pub fn next_signal(&mut self, t: usize) -> Next {
        let i = self.tasks[t].proc as usize;
        let task = &mut self.tasks[t];
        let p = &mut self.procs[i];
        loop {
            let live = (p.pending | task.pending) & (!task.mask | UNBLOCKABLE);
            if live == 0 {
                return Next::None;
            }
            let sig = live.trailing_zeros() + 1;
            let a = p.actions[sig as usize - 1];
            if sig == SIGSTOP || a.handler == SIG_DFL && stops_by_default(sig) {
                p.pending &= !bit(sig);
                task.pending &= !bit(sig);
                return Next::Stop(sig);
            }
            if sig == SIGKILL || a.handler == SIG_DFL && !ignored_by_default(sig) {
                return Next::Kill(sig);
            }
            if a.handler == SIG_IGN || a.handler == SIG_DFL {
                p.pending &= !bit(sig);
                task.pending &= !bit(sig);
                continue;
            }
            return Next::Handle(sig);
        }
    }

    /// Task `t` (stopped in a system call) takes `sig`'s handler: the
    /// registers it would resume with (at `pc`, with `result` in the
    /// result register unless `None`: a restarted call keeps its
    /// arguments) and its mask are saved on its stack. Returns where it
    /// resumes and the result register's value there.
    pub fn enter_handler(&mut self, t: usize, sig: u32, pc: u64, result: Option<u64>) -> Option<(u64, u64)> {
        let (i, th) = (self.tasks[t].proc as usize, self.tasks[t].thread);
        let mut r = regs(th)?;
        r[PC] = pc;
        if let Some(v) = result {
            r[RESULT] = v;
        }
        let task = &mut self.tasks[t];
        let p = &mut self.procs[i];
        let a = p.actions[sig as usize - 1];
        let old_mask = if core::mem::take(&mut task.suspended) { task.saved_mask } else { task.mask };
        // The thread's own first, as Linux takes them.
        if task.pending & bit(sig) != 0 {
            task.pending &= !bit(sig);
        } else {
            p.pending &= !bit(sig);
        }
        task.mask |= a.mask | if a.flags & SA_NODEFER != 0 { 0 } else { bit(sig) };
        task.mask &= !UNBLOCKABLE;
        if a.flags & SA_RESETHAND != 0 {
            p.actions[sig as usize - 1].handler = SIG_DFL;
        }
        let restorer = if a.flags & SA_RESTORER != 0 && a.restorer != 0 { a.restorer } else { TRAMPOLINE };

        let mut uc = [0u8; UC_LEN as usize];
        for (k, v) in r.iter().enumerate() {
            let at = UC_REGS as usize + 8 * k;
            uc[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        uc[UC_MASK as usize..UC_MASK as usize + 8].copy_from_slice(&old_mask.to_le_bytes());
        let mut info = [0u8; INFO_LEN as usize];
        info[..4].copy_from_slice(&sig.to_le_bytes());

        if cfg!(target_arch = "x86_64") {
            // Below the red zone: the return address (the restorer), the
            // ucontext and the siginfo, the return address 8 below a
            // 16-byte boundary, as after a call.
            let frame = ((r[SP] - 128 - (8 + UC_LEN + INFO_LEN)) & !15) - 8;
            let (ucp, infop) = (frame + 8, frame + 8 + UC_LEN);
            let ok = self.copy_out(i, frame, &restorer.to_le_bytes())
                && self.copy_out(i, ucp, &uc)
                && self.copy_out(i, infop, &info);
            if !ok {
                return None;
            }
            (r[8], r[9], r[12], r[SP], r[PC]) = (sig as u64, infop, ucp, frame, a.handler);
            r[17] &= !0x400; // the direction flag
            set_regs(th, &r)?;
            Some((a.handler, 0))
        } else {
            // The siginfo, the ucontext and a frame record (the
            // interrupted frame pointer and pc).
            let frame = (r[SP] - (INFO_LEN + UC_LEN + 16)) & !15;
            let (infop, ucp, record) = (frame, frame + INFO_LEN, frame + INFO_LEN + UC_LEN);
            let mut rec = [0u8; 16];
            rec[..8].copy_from_slice(&r[29].to_le_bytes());
            rec[8..].copy_from_slice(&r[PC].to_le_bytes());
            let ok = self.copy_out(i, infop, &info) && self.copy_out(i, ucp, &uc) && self.copy_out(i, record, &rec);
            if !ok {
                return None;
            }
            (r[0], r[1], r[2], r[29], r[30], r[SP], r[PC]) = (sig as u64, infop, ucp, record, restorer, frame, a.handler);
            set_regs(th, &r)?;
            Some((a.handler, sig as u64))
        }
    }

    /// `rt_sigreturn`: the registers and mask saved by
    /// [`State::enter_handler`] back. Where the process resumes, and its
    /// result register there.
    pub fn sigreturn(&mut self, t: usize) -> Option<(u64, u64)> {
        let (i, th) = (self.tasks[t].proc as usize, self.tasks[t].thread);
        let sp = regs(th)?[SP];
        // x86-64: the handler's return took the return address; AArch64:
        // the stack is as the handler was given it.
        let ucp = if cfg!(target_arch = "x86_64") { sp } else { sp + INFO_LEN };
        let mut uc = [0u8; UC_LEN as usize];
        if !self.copy_in(i, ucp, &mut uc) {
            return None;
        }
        let word = |at: u64| u64::from_le_bytes(uc[at as usize..at as usize + 8].try_into().unwrap());
        let mut r = [0; COUNT];
        for (k, v) in r.iter_mut().enumerate() {
            *v = word(UC_REGS + 8 * k as u64);
        }
        set_regs(th, &r)?;
        self.tasks[t].mask = word(UC_MASK) & !UNBLOCKABLE;
        Some((r[PC], r[RESULT]))
    }

    /// `rt_sigaction`.
    pub fn sigaction(&mut self, i: usize, sig: u64, act: u64, old: u64) -> Result<u64, u64> {
        if sig == 0 || sig > NSIG as u64 {
            return Err(EINVAL);
        }
        let k = sig as usize - 1;
        let a = self.procs[i].actions[k];
        if old != 0 {
            let mut b = [0u8; 32];
            for (n, v) in [a.handler, a.flags, a.restorer, a.mask].iter().enumerate() {
                b[n * 8..n * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            self.put(i, old, &b)?;
        }
        if act != 0 {
            if sig as u32 == SIGKILL || sig as u32 == SIGSTOP {
                return Err(EINVAL);
            }
            let w = |n: u64| self.word(i, act + 8 * n).ok_or(EFAULT);
            let new = Action { handler: w(0)?, flags: w(1)?, restorer: w(2)?, mask: w(3)? };
            self.procs[i].actions[k] = new;
            if new.handler == SIG_IGN || new.handler == SIG_DFL && ignored_by_default(sig as u32) {
                self.procs[i].pending &= !bit(sig as u32);
                for t in 0..MAX_TASKS {
                    if self.tasks[t].used && self.tasks[t].proc as usize == i {
                        self.tasks[t].pending &= !bit(sig as u32);
                    }
                }
            }
        }
        Ok(0)
    }

    /// `rt_sigprocmask`: task `t`'s mask.
    pub fn sigprocmask(&mut self, t: usize, how: u64, set: u64, old: u64) -> Result<u64, u64> {
        let (i, cur) = (self.tasks[t].proc as usize, self.tasks[t].mask);
        if old != 0 {
            self.put(i, old, &cur.to_le_bytes())?;
        }
        if set != 0 {
            let s = self.word(i, set).ok_or(EFAULT)?;
            let new = match how {
                0 => cur | s,
                1 => cur & !s,
                2 => s,
                _ => return Err(EINVAL),
            };
            self.tasks[t].mask = new & !UNBLOCKABLE;
        }
        Ok(0)
    }

    /// `kill`: to a process, its own group (0), every other process (-1)
    /// or a group (below -1).
    pub fn kill(&mut self, i: usize, pid: i64, sig: u64) -> Result<u64, u64> {
        if sig > NSIG as u64 {
            return Err(EINVAL);
        }
        let sig = sig as u32;
        let found = match pid {
            0 => {
                let g = self.procs[i].pgid;
                self.post_group(g, sig)
            }
            -1 => {
                let mut any = false;
                for k in 0..MAX_PROCS {
                    if k != i && self.procs[k].used && !self.procs[k].zombie {
                        self.post(k, sig);
                        any = true;
                    }
                }
                any
            }
            p if p < -1 => self.post_group((-p) as u32, sig),
            p => match self.procs.iter().position(|q| q.used && q.pid as i64 == p) {
                Some(k) => {
                    self.post(k, sig);
                    true
                }
                None => false,
            },
        };
        if found { Ok(0) } else { Err(ESRCH) }
    }

    /// `rt_sigsuspend` (or `pause`, `mask` `None`): waits for a signal
    /// with `mask` in place, the old one back once the handler returns.
    pub fn sigsuspend(&mut self, t: usize, mask: Option<u64>) -> Out {
        let i = self.tasks[t].proc as usize;
        let new = match mask {
            Some(at) => match self.word(i, at) {
                Some(m) => m,
                None => return Out::Ret(err(EFAULT)),
            },
            None => self.tasks[t].mask,
        };
        let task = &mut self.tasks[t];
        task.saved_mask = task.mask;
        task.suspended = true;
        task.mask = new & !UNBLOCKABLE;
        Out::Block(Blocked::Suspend)
    }

    /// After `execve`: handlers are gone (their code is), ignored signals
    /// stay ignored.
    pub fn reset_handlers(&mut self, i: usize) {
        for a in self.procs[i].actions.iter_mut() {
            if a.handler != SIG_IGN {
                *a = Action { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
            }
        }
    }
}
