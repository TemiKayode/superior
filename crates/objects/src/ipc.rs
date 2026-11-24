//! IPC and scheduling state machine.
//!
//! This is the logic behind the kernel's `Send`, `Call`, `Recv`, `Reply`,
//! `ReplyRecv`, `Signal`, `Wait` and `Yield` system calls, with no
//! hardware in it. The kernel resolves capabilities to object indices,
//! calls one operation here for the current thread, then resumes whichever
//! thread [`Ipc::current`] names, loading that thread's delivered message
//! into its registers.
//!
//! Design points (spec section 3):
//! - Every wait queue is an intrusive list through the TCBs, so nothing
//!   here allocates and every operation is O(1) apart from the ready-queue
//!   bitmap scan, which is one instruction.
//! - `Call` to a waiting server and `ReplyRecv` back to a waiting caller
//!   switch threads directly, without going through the ready queues
//!   (the IPC fast path), unless a higher-priority thread is ready.
//! - Strict fixed priorities (64 levels), FIFO within a level, and
//!   round-robin time slices within a level driven by [`Ipc::tick`].
//! - Scheduling contexts (MCS, spec section 3): objects of their own. A
//!   thread runs on the context it is bound to ([`Ipc::bind_sc`]), and
//!   several threads may share one (a component's threads draw on one
//!   budget). A context is unlimited, empty (no budget: its threads cannot
//!   run) or configured with a budget per period. A thread bound to none
//!   cannot run; destroying a context unbinds its threads
//!   ([`Ipc::destroy_sc`]). Thread `i` starts bound to context `i`. Budgets are
//!   charged per timer tick and replenished as sporadic servers: a tick
//!   charged at time `c` comes back at `c + period`, so no window of one
//!   period is charged more than the budget (see [`SchedContext`]); a
//!   thread whose context runs dry is throttled until a refill is due.
//! - A passive server has given up its own context and runs only on its
//!   caller's, lent on `Call` and returned on reply, so time spent serving
//!   a client is charged to that client. A passive thread with no lent
//!   context cannot run: woken any other way (a `Send`, a signal), it is
//!   parked in [`State::NoSchedContext`].
//! - Timeout faults: a thread that empties a context lent to it (a server
//!   whose caller's budget ran out mid-request) and has a timeout handler
//!   ([`Ipc::set_timeout_handler`]) is not throttled holding up its other
//!   callers: it calls the handler with [`FaultKind::Timeout`] instead,
//!   as the kernel makes any fault a call. Without a handler it is
//!   throttled until the caller's next refill.
//!
//! Message delivery always fills `msg`, `badge` and `status` of the thread
//! being woken; the kernel copies them into that thread's registers.
//!
//! Bound notifications (as in seL4): a thread may bind one notification
//! to itself. Its `Recv` and `ReplyRecv` then also return when that
//! notification is signalled, with status [`Error::Notified`] and the
//! accumulated bits as the badge, so one server loop waits for calls on
//! its endpoint and for doorbells of its shared-memory rings at once.
//! Pending bits are taken before queued senders.
//!
//! Capability transfer: before each operation the kernel records the
//! current thread's [`CapTransfer`] (slot to grant, slot to accept into).
//! When a message moves from a sender that grants to a receiver that
//! accepts, delivery records a [`Transfer`]; the kernel drains them after
//! the operation with [`Ipc::take_transfers`], copies the capability
//! between CSpaces, and reports the outcome with [`Ipc::set_cap_received`].
//! CSpaces themselves are not this module's business.

use crate::abi::{CapTransfer, Error, FaultKind, MSG_WORDS};

pub type Tid = u16;
/// CPUs the engine schedules for.
pub const MAX_CPUS: usize = 8;
pub const PRIORITIES: usize = 64;
/// Timer ticks a thread runs before yielding to a ready peer of the same
/// (or higher) priority.
pub const TIMESLICE_TICKS: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Inactive,
    /// Runnable and in a ready queue.
    Ready,
    /// The current thread.
    Running,
    BlockedSend {
        ep: u16,
        call: bool,
    },
    BlockedRecv {
        ep: u16,
    },
    /// Called a server and waits for its reply.
    BlockedReply,
    BlockedWait {
        ntfn: u16,
    },
    /// Runnable, but its scheduling context `sc` has no budget left until
    /// the next refill.
    Throttled {
        sc: Tid,
    },
    /// Passive with no lent scheduling context: cannot run.
    NoSchedContext,
}

/// Refills a scheduling context keeps at once. When a charge would need
/// one more, it is merged into the last, which only delays budget.
pub const MAX_REFILLS: usize = 8;

/// `amount` ticks of budget usable from tick `release` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refill {
    pub release: u64,
    pub amount: u32,
}

const NO_REFILL: Refill = Refill {
    release: 0,
    amount: 0,
};

/// CPU time a thread may consume. Scheduling context `i` belongs to
/// thread `i`; a passive server borrows its caller's.
///
/// A limited context is a sporadic server: its `budget` is split into
/// refills, each usable from its release tick. A tick charged at time `c`
/// is taken from a released refill and comes back as a refill released
/// at `c + period`, so every tick of budget is used at most once in any
/// `period` ticks and no window of `period` ticks is charged more than
/// `budget` (a periodic refill allows twice that across a boundary).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SchedContext {
    /// Ticks per period; `None` is unlimited.
    pub budget: Option<u32>,
    pub period: u32,
    /// Ordered by release, strictly increasing; amounts sum to `budget`.
    refills: [Refill; MAX_REFILLS],
    len: u8,
    /// Ticks ever charged to this context.
    pub consumed: u64,
}

const UNLIMITED: SchedContext = SchedContext {
    budget: None,
    period: 0,
    refills: [NO_REFILL; MAX_REFILLS],
    len: 0,
    consumed: 0,
};

/// No budget at all, until configured: what a new context object holds.
const EMPTY: SchedContext = SchedContext {
    budget: Some(0),
    period: 0,
    refills: [NO_REFILL; MAX_REFILLS],
    len: 0,
    consumed: 0,
};

impl core::fmt::Debug for SchedContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.budget {
            None => write!(f, "unlimited"),
            Some(0) => write!(f, "empty"),
            Some(b) => write!(
                f,
                "{b}/{} refills {:?} used {}",
                self.period,
                self.refills(),
                self.consumed
            ),
        }
    }
}

impl SchedContext {
    /// A full `budget` usable from `now`.
    fn limited(budget: u32, period: u32, now: u64) -> SchedContext {
        let mut refills = [NO_REFILL; MAX_REFILLS];
        refills[0] = Refill {
            release: now,
            amount: budget,
        };
        SchedContext {
            budget: Some(budget),
            period,
            refills,
            len: 1,
            consumed: 0,
        }
    }

    /// The pending refills, earliest first.
    pub fn refills(&self) -> &[Refill] {
        &self.refills[..self.len as usize]
    }

    /// Ticks of budget usable at `now` (0 for an unlimited context).
    pub fn available(&self, now: u64) -> u32 {
        self.refills()
            .iter()
            .take_while(|r| r.release <= now)
            .map(|r| r.amount)
            .sum()
    }

    fn exhausted(&self, now: u64) -> bool {
        self.budget.is_some() && self.available(now) == 0
    }

    fn remove(&mut self, i: usize) {
        let n = self.len as usize;
        self.refills.copy_within(i + 1..n, i);
        self.refills[n - 1] = NO_REFILL;
        self.len -= 1;
    }

    /// Charges the tick that began at `now` (the clock before the tick
    /// advanced it). Returns whether the context is then exhausted.
    fn charge(&mut self, now: u64) -> bool {
        self.consumed += 1;
        let Some(_) = self.budget else { return false };
        // Released refills are one pool: fold them into the first.
        while self.len >= 2 && self.refills[1].release <= now {
            self.refills[0].amount += self.refills[1].amount;
            self.remove(1);
        }
        if self.len == 0 || self.refills[0].release > now {
            // Nothing released (cannot happen to a running thread).
            return true;
        }
        self.refills[0].amount -= 1;
        if self.refills[0].amount == 0 {
            self.remove(0);
        }
        // The tick comes back one period after it began. Every pending
        // release is at most `now + period`, so appending keeps the order;
        // merging into a full ring's last refill only delays that refill.
        let release = now + self.period as u64;
        let n = self.len as usize;
        if n > 0 && (self.refills[n - 1].release == release || n == MAX_REFILLS) {
            self.refills[n - 1].release = release;
            self.refills[n - 1].amount += 1;
        } else {
            self.refills[n] = Refill { release, amount: 1 };
            self.len += 1;
        }
        self.exhausted(now)
    }

    /// The refill ring is well formed at `now`.
    #[cfg(test)]
    fn check(&self, now: u64) -> Result<(), std::string::String> {
        use std::format;
        let Some(budget) = self.budget else {
            return if self.len == 0 {
                Ok(())
            } else {
                Err(format!("unlimited context with refills {:?}", self.refills()))
            };
        };
        let r = self.refills();
        if budget == 0 {
            return if r.is_empty() {
                Ok(())
            } else {
                Err(format!("empty context with refills {r:?}"))
            };
        }
        if r.is_empty() {
            return Err(format!("{budget}-tick budget with no refills"));
        }
        if r.iter().map(|x| x.amount as u64).sum::<u64>() != budget as u64 {
            return Err(format!("refills {r:?} do not sum to the {budget}-tick budget"));
        }
        if r.iter().any(|x| x.amount == 0) {
            return Err(format!("empty refill in {r:?}"));
        }
        if r.windows(2).any(|w| w[0].release >= w[1].release) {
            return Err(format!("refills out of order: {r:?}"));
        }
        if r[r.len() - 1].release > now + self.period as u64 {
            return Err(format!("refill past one period from {now}: {r:?}"));
        }
        Ok(())
    }
}

/// Scheduler counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedStats {
    /// Times a thread was stopped because its budget ran out.
    pub throttles: u64,
    /// Ticks charged to a context lent by a caller (a passive server ran).
    pub donated_ticks: u64,
    /// Timeout faults raised (a lent budget ran out under a handler).
    pub timeouts: u64,
    /// Threads a CPU took from another CPU's ready queue.
    pub migrations: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Tcb {
    pub state: State,
    pub prio: u8,
    /// The CPU whose ready queue it joins: the one it last ran on, or
    /// the one it is pinned to.
    home: u8,
    /// Pinned to `home` ([`Ipc::set_affinity`]): no other CPU runs it.
    pinned: bool,
    /// When it was queued to run (lower is longer ago; 0 for a thread
    /// preempted mid-slice, which goes first).
    queued: u64,
    pub msg: [u64; MSG_WORDS],
    pub badge: u64,
    /// Result of this thread's last completed operation (0 = ok).
    pub status: u64,
    /// For a server: the caller it owes a reply to.
    caller: Option<Tid>,
    /// For a server: callers it set aside to answer later
    /// ([`Ipc::save_caller`], [`Ipc::reply_saved`]).
    saved: [Option<Tid>; SAVED_CALLERS],
    /// Link in whichever queue this thread is on.
    next: Option<Tid>,
    /// Ticks left in this thread's time slice.
    slice: u32,
    /// Capability transfer named by this thread's latest operation.
    xfer: CapTransfer,
    /// Slot the last delivered message's capability landed in, if any.
    pub cap_received: Option<u16>,
    /// Runs only on a lent scheduling context.
    pub passive: bool,
    /// Becomes passive the next time it blocks.
    passive_pending: bool,
    /// The scheduling context a caller lent this (passive) thread.
    lent: Option<Tid>,
    /// The scheduling context this thread is bound to (runs on when not
    /// passive).
    sc: Option<Tid>,
    /// The notification bound to this thread.
    bound: Option<u16>,
    /// Endpoint and badge a timeout fault calls.
    timeout: Option<(u16, u64)>,
}

/// A capability to copy from `from`'s slot `grant` into `to`'s slot `accept`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub from: Tid,
    pub grant: u16,
    pub to: Tid,
    pub accept: u16,
}

/// The most deliveries one operation makes: `ReplyRecv` replies, then
/// may receive from a queued sender.
pub const MAX_TRANSFERS: usize = 2;

/// Callers one server thread may set aside at once.
pub const SAVED_CALLERS: usize = 16;

const IDLE_TCB: Tcb = Tcb {
    state: State::Inactive,
    prio: 0,
    msg: [0; MSG_WORDS],
    badge: 0,
    status: 0,
    caller: None,
    saved: [None; SAVED_CALLERS],
    next: None,
    slice: TIMESLICE_TICKS,
    xfer: CapTransfer::NONE,
    cap_received: None,
    passive: false,
    passive_pending: false,
    lent: None,
    bound: None,
    timeout: None,
    sc: None,
    home: 0,
    pinned: false,
    queued: 0,
};

#[derive(Clone, Copy, Default, Debug)]
struct Queue {
    head: Option<Tid>,
    tail: Option<Tid>,
}

impl Queue {
    const EMPTY: Queue = Queue {
        head: None,
        tail: None,
    };

    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    fn push_back(&mut self, threads: &mut [Tcb], t: Tid) {
        threads[t as usize].next = None;
        match self.tail {
            Some(tail) => threads[tail as usize].next = Some(t),
            None => self.head = Some(t),
        }
        self.tail = Some(t);
    }

    fn push_front(&mut self, threads: &mut [Tcb], t: Tid) {
        threads[t as usize].next = self.head;
        if self.head.is_none() {
            self.tail = Some(t);
        }
        self.head = Some(t);
    }

    fn pop(&mut self, threads: &mut [Tcb]) -> Option<Tid> {
        let t = self.head?;
        self.head = threads[t as usize].next.take();
        if self.head.is_none() {
            self.tail = None;
        }
        Some(t)
    }

    /// Unlinks `t` from anywhere in the queue. Returns whether it was there.
    fn remove(&mut self, threads: &mut [Tcb], t: Tid) -> bool {
        let mut prev: Option<Tid> = None;
        let mut at = self.head;
        while let Some(x) = at {
            if x == t {
                let next = threads[x as usize].next.take();
                match prev {
                    Some(p) => threads[p as usize].next = next,
                    None => self.head = next,
                }
                if self.tail == Some(t) {
                    self.tail = prev;
                }
                return true;
            }
            prev = Some(x);
            at = threads[x as usize].next;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpState {
    Idle,
    /// The queue holds blocked senders.
    Sending,
    /// The queue holds blocked receivers.
    Receiving,
}

#[derive(Clone, Copy)]
struct Endpoint {
    state: EpState,
    queue: Queue,
}

#[derive(Clone, Copy)]
struct Notification {
    word: u64,
    waiters: Queue,
    /// The thread this notification is bound to.
    bound: Option<Tid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    /// No thread is running (nothing to act on behalf of).
    NoCurrent,
    BadThread,
    BadObject,
    BadPriority,
    BadSchedParams,
    ThreadActive,
    WouldBlock,
    /// The thread or notification is already bound.
    AlreadyBound,
    /// Not a failure: the receive was answered by the thread's bound
    /// notification (the badge holds its bits).
    Notified,
    /// `save_caller` with no caller waiting for a reply.
    NoCaller,
    /// `save_caller` with every saved place taken, or by a passive thread
    /// (which runs on its caller's context: it must answer it first).
    CannotSave,
    /// `reply_saved` to a place out of range.
    BadIndex,
}

impl IpcError {
    /// The status code reported to user space.
    pub const fn status(self) -> u64 {
        match self {
            IpcError::WouldBlock => Error::WouldBlock.code(),
            IpcError::Notified => Error::Notified.code(),
            IpcError::BadObject => Error::InvalidCapability.code(),
            IpcError::NoCaller | IpcError::BadIndex => Error::InvalidArgument.code(),
            IpcError::CannotSave => Error::ObjectTableFull.code(),
            _ => Error::IllegalOperation.code(),
        }
    }
}

/// `T` threads, `E` endpoints, `N` notifications.
pub struct Ipc<const T: usize, const E: usize, const N: usize> {
    threads: [Tcb; T],
    eps: [Endpoint; E],
    ntfns: [Notification; N],
    /// Each CPU's ready queues, one per priority. A thread queues on its
    /// home CPU's (the one it last ran on), and a CPU runs the highest
    /// priority ready anywhere, its own queue first among equals: the
    /// highest-priority threads always run, and a thread stays on its CPU
    /// (and its cache) unless another CPU would otherwise run something
    /// lower, or nothing. A slice's end or a yield hands the turn to the
    /// equal that has waited longest anywhere ([`Ipc::longest_waiting`]).
    ready: [[Queue; PRIORITIES]; MAX_CPUS],
    /// Bit p of entry x set ⇔ ready[x][p] non-empty.
    ready_bits: [u64; MAX_CPUS],
    /// Threads pinned to a CPU (while there are none, every ready thread
    /// may run anywhere and the scheduler takes its fast path).
    pinned_count: usize,
    /// Counts queuings, to tell which ready thread has waited longest.
    queue_seq: u64,
    /// The thread each CPU runs. A thread stopped by another CPU stays
    /// here, no longer `Running`, until its own CPU next enters the kernel
    /// and [`Ipc::settle`]s: its registers are still on that CPU.
    currents: [Option<Tid>; MAX_CPUS],
    /// The CPU operations act for (see [`Ipc::set_cpu`]).
    cpu: usize,
    transfers: [Option<Transfer>; MAX_TRANSFERS],
    scs: [SchedContext; T],
    /// Timer ticks since boot.
    now: u64,
    pub stats: SchedStats,
    /// The thread the last tick made raise a timeout fault, for the kernel
    /// to mark as in a fault ([`Ipc::take_timeout`]).
    timeout_raised: Option<Tid>,
}

impl<const T: usize, const E: usize, const N: usize> Default for Ipc<T, E, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const T: usize, const E: usize, const N: usize> Ipc<T, E, N> {
    pub const fn new() -> Self {
        let mut threads = [IDLE_TCB; T];
        let mut i = 0;
        while i < T {
            threads[i].sc = Some(i as Tid);
            i += 1;
        }
        Ipc {
            threads,
            eps: [Endpoint {
                state: EpState::Idle,
                queue: Queue::EMPTY,
            }; E],
            ntfns: [Notification {
                word: 0,
                waiters: Queue::EMPTY,
                bound: None,
            }; N],
            ready: [[Queue::EMPTY; PRIORITIES]; MAX_CPUS],
            ready_bits: [0; MAX_CPUS],
            pinned_count: 0,
            queue_seq: 0,
            currents: [None; MAX_CPUS],
            cpu: 0,
            transfers: [None; MAX_TRANSFERS],
            scs: [UNLIMITED; T],
            now: 0,
            stats: SchedStats {
                throttles: 0,
                donated_ticks: 0,
                timeouts: 0,
                migrations: 0,
            },
            timeout_raised: None,
        }
    }

    /// The thread the CPU operations act for runs (see [`Ipc::set_cpu`]).
    pub fn current(&self) -> Option<Tid> {
        self.currents[self.cpu]
    }

    /// The thread CPU `cpu` runs, or keeps until it settles.
    pub fn current_on(&self, cpu: usize) -> Option<Tid> {
        self.currents[cpu]
    }

    /// Operations from here on act for CPU `cpu`: its current thread
    /// makes system calls, it is charged ticks, it schedules.
    pub fn set_cpu(&mut self, cpu: usize) {
        assert!(cpu < MAX_CPUS);
        self.cpu = cpu;
    }

    /// Drops this CPU's thread if another CPU stopped it meanwhile (it is
    /// no longer `Running`): the kernel calls this on entry, once it has
    /// saved the thread's registers. Returns the thread dropped.
    ///
    /// Every operation that acts on this CPU's thread without a system call
    /// from it (a tick, an interrupt's signal, a reschedule) settles first:
    /// an interrupt in the idle loop can make a thread this CPU's (not yet
    /// loaded) and another CPU can stop it before the CPU loads it.
    pub fn settle(&mut self) -> Option<Tid> {
        let t = self.currents[self.cpu]?;
        if self.threads[t as usize].state == State::Running {
            return None;
        }
        self.currents[self.cpu] = None;
        Some(t)
    }

    /// For a CPU kicked by another: runs whatever now outranks its thread,
    /// or anything, if it has none.
    pub fn reschedule(&mut self) {
        self.settle();
        self.preempt_if_outranked();
        self.schedule();
    }

    /// Whether CPU `x` should enter the kernel to reschedule: another CPU
    /// stopped its thread, or something ready outranks it (or it idles
    /// with something ready it could run).
    pub fn needs_kick(&self, x: usize) -> bool {
        let ready = self.highest_ready_on(x);
        match self.currents[x] {
            Some(t) if self.threads[t as usize].state != State::Running => true,
            Some(t) => ready.is_some_and(|p| p > self.threads[t as usize].prio),
            None => ready.is_some(),
        }
    }

    /// Whether thread `t` is kept by a CPU other than `cpu` (stopped there
    /// but not yet settled), so `cpu` may not run it yet.
    fn pinned_off(&self, t: Tid, cpu: usize) -> bool {
        self.currents
            .iter()
            .enumerate()
            .any(|(x, &c)| x != cpu && c == Some(t))
    }

    /// Whether any CPU keeps a thread it no longer runs.
    fn any_pinned(&self) -> bool {
        self.currents
            .iter()
            .flatten()
            .any(|&t| self.threads[t as usize].state != State::Running)
    }

    pub fn thread(&self, t: Tid) -> &Tcb {
        &self.threads[t as usize]
    }

    /// Records the capability transfer the current thread's next operation
    /// offers and accepts. The kernel calls this before every IPC operation.
    pub fn set_transfer(&mut self, xfer: CapTransfer) {
        if let Some(c) = self.currents[self.cpu] {
            self.threads[c as usize].xfer = xfer;
        }
    }

    /// The transfers recorded by deliveries since the last call.
    pub fn take_transfers(&mut self) -> [Option<Transfer>; MAX_TRANSFERS] {
        core::mem::take(&mut self.transfers)
    }

    /// Records where a transferred capability landed for `t`.
    pub fn set_cap_received(&mut self, t: Tid, slot: Option<u16>) {
        self.threads[t as usize].cap_received = slot;
    }

    /// The caller `t` owes a reply to, if any.
    pub fn caller_of(&self, t: Tid) -> Option<Tid> {
        self.threads[t as usize].caller
    }

    /// Whether some server has set caller `t` aside ([`Ipc::save_caller`]).
    pub fn is_saved(&self, t: Tid) -> bool {
        self.threads.iter().any(|s| s.saved.contains(&Some(t)))
    }

    /// Stops the current thread (it becomes inactive), e.g. after a fault
    /// nobody handles.
    pub fn suspend_current(&mut self) {
        if let Some(c) = self.currents[self.cpu] {
            let _ = self.suspend(c);
        }
    }

    /// Stops the current thread because it crashed (a fault nobody handles,
    /// or its handler said stop). As [`Ipc::destroy`]: a caller it owed a
    /// reply gets [`Error::PeerRestarted`], whether or not a supervisor
    /// goes on to destroy it, so the caller sees the same whichever comes
    /// first (on several CPUs, either may).
    pub fn crash_current(&mut self) {
        if let Some(c) = self.currents[self.cpu] {
            let _ = self.destroy(c);
        }
    }

    /// Stops thread `t` wherever it is: running, queued to run, or blocked.
    /// A blocked thread's system call is cancelled with
    /// [`Error::Interrupted`] (seen when it is resumed with
    /// [`Ipc::spawn`]); a caller it owed a reply gets `ReplyAbandoned`.
    pub fn suspend(&mut self, t: Tid) -> Result<(), IpcError> {
        if t as usize >= T {
            return Err(IpcError::BadThread);
        }
        let blocked = match self.threads[t as usize].state {
            State::Inactive => return Ok(()),
            State::Running => {
                // Another CPU's thread stays kept there until it settles.
                if self.currents[self.cpu] == Some(t) {
                    self.currents[self.cpu] = None;
                }
                false
            }
            State::Ready => {
                self.dequeue(t);
                false
            }
            State::BlockedSend { ep, .. } | State::BlockedRecv { ep } => {
                let e = ep as usize;
                self.eps[e].queue.remove(&mut self.threads, t);
                if self.eps[e].queue.is_empty() {
                    self.eps[e].state = EpState::Idle;
                }
                true
            }
            State::BlockedWait { ntfn } => {
                self.ntfns[ntfn as usize]
                    .waiters
                    .remove(&mut self.threads, t);
                true
            }
            State::BlockedReply => {
                // The server must forget it: if this thread is resumed and
                // calls again, that server's reply must not land in the
                // new call.
                for s in self.threads.iter_mut() {
                    if s.caller == Some(t) {
                        s.caller = None;
                    }
                    for k in s.saved.iter_mut() {
                        if *k == Some(t) {
                            *k = None;
                        }
                    }
                }
                true
            }
            State::Throttled { .. } | State::NoSchedContext => false,
        };
        let tcb = &mut self.threads[t as usize];
        tcb.state = State::Inactive;
        tcb.lent = None;
        if blocked {
            tcb.status = Error::Interrupted.code();
        }
        let saved = core::mem::replace(&mut tcb.saved, [None; SAVED_CALLERS]);
        if let Some(caller) = tcb.caller.take() {
            self.abandon(caller);
        }
        for caller in saved.into_iter().flatten() {
            self.abandon(caller);
        }
        self.schedule();
        Ok(())
    }

    /// Pins thread `t` to CPU `cpu`, so only that CPU runs it, or (`None`)
    /// lets any CPU run it again. A ready thread moves to that CPU's
    /// queue; a thread running elsewhere stops and queues there (one this
    /// CPU runs is switched away from at once; another CPU's stays kept
    /// there until that CPU settles). Pinning outlasts suspension.
    pub fn set_affinity(&mut self, t: Tid, cpu: Option<usize>) -> Result<(), IpcError> {
        if t as usize >= T || cpu.is_some_and(|c| c >= MAX_CPUS) {
            return Err(IpcError::BadThread);
        }
        let tcb = self.threads[t as usize];
        let ready = tcb.state == State::Ready;
        if ready {
            self.dequeue(t);
        }
        match (tcb.pinned, cpu.is_some()) {
            (false, true) => self.pinned_count += 1,
            (true, false) => self.pinned_count -= 1,
            _ => {}
        }
        let tcb = &mut self.threads[t as usize];
        tcb.pinned = cpu.is_some();
        if let Some(c) = cpu {
            tcb.home = c as u8;
        }
        if ready {
            self.enqueue(t, false);
        } else if tcb.state == State::Running && !self.may_run(t, self.running_on(t)) {
            let here = self.currents[self.cpu] == Some(t);
            self.threads[t as usize].state = State::Ready;
            self.enqueue(t, true);
            if here {
                self.currents[self.cpu] = None;
            }
        }
        self.schedule();
        Ok(())
    }

    /// The CPU running thread `t` (which must be running).
    fn running_on(&self, t: Tid) -> usize {
        self.currents.iter().position(|&c| c == Some(t)).unwrap_or(self.cpu)
    }

    /// Clears an inactive thread's state so the table entry can be reused
    /// for a new thread. It is bound to context `t` again; contexts are
    /// objects of their own and outlive it.
    pub fn reset_thread(&mut self, t: Tid) -> Result<(), IpcError> {
        let tcb = self
            .threads
            .get_mut(t as usize)
            .ok_or(IpcError::BadThread)?;
        if tcb.state != State::Inactive {
            return Err(IpcError::ThreadActive);
        }
        if let Some(n) = tcb.bound {
            self.ntfns[n as usize].bound = None;
        }
        if tcb.pinned {
            self.pinned_count -= 1;
        }
        let tcb = &mut self.threads[t as usize];
        *tcb = IDLE_TCB;
        tcb.sc = Some(t);
        Ok(())
    }

    /// Wakes `caller` with `ReplyAbandoned` if it still waits for a reply.
    fn abandon(&mut self, caller: Tid) {
        self.fail_caller(caller, Error::ReplyAbandoned);
    }

    /// Wakes `caller` with `err` if it still waits for a reply.
    fn fail_caller(&mut self, caller: Tid, err: Error) {
        if self.threads[caller as usize].state == State::BlockedReply {
            self.threads[caller as usize].status = err.code();
            self.wake(caller);
        }
    }

    /// Stops thread `t` because it is being destroyed. As [`Ipc::suspend`],
    /// except that a caller it owed a reply gets [`Error::PeerRestarted`]:
    /// the call was received and may or may not have been acted on, and
    /// the server is gone (a supervisor may be starting a new instance on
    /// the same endpoint).
    pub fn destroy(&mut self, t: Tid) -> Result<(), IpcError> {
        let tcb = self.threads.get_mut(t as usize).ok_or(IpcError::BadThread)?;
        let caller = tcb.caller.take();
        let saved = core::mem::replace(&mut tcb.saved, [None; SAVED_CALLERS]);
        // Callers it set aside too: none of their calls was answered.
        for c in caller.into_iter().chain(saved.into_iter().flatten()) {
            self.fail_caller(c, Error::PeerRestarted);
        }
        self.suspend(t)
    }

    fn awaits_reply(&self, t: Tid) -> bool {
        self.threads[t as usize].state == State::BlockedReply
    }

    /// Sets the message words thread `t` will see when it next returns to
    /// user mode (results of a system call that is not IPC).
    pub fn set_msg_of(&mut self, t: Tid, msg: [u64; MSG_WORDS]) {
        self.threads[t as usize].msg = msg;
    }

    /// Sets the status thread `t` will see when it next returns to user
    /// mode: the result of the operation it just made.
    pub fn set_status_of(&mut self, t: Tid, status: u64) {
        self.threads[t as usize].status = status;
    }

    /// Destroys endpoint `ep`: every thread queued on it (senders or
    /// receivers) wakes with [`Error::ObjectDestroyed`]. The kernel calls
    /// this when the last capability to the endpoint goes.
    pub fn destroy_endpoint(&mut self, ep: u16) -> Result<(), IpcError> {
        let e = self.ep_index(ep)?;
        while let Some(t) = self.eps[e].queue.pop(&mut self.threads) {
            self.threads[t as usize].status = Error::ObjectDestroyed.code();
            self.wake(t);
        }
        // A handler gone is no handler: its index may name a new endpoint.
        for tcb in self.threads.iter_mut() {
            if tcb.timeout.is_some_and(|(x, _)| x == ep) {
                tcb.timeout = None;
            }
        }
        self.eps[e].state = EpState::Idle;
        self.schedule();
        Ok(())
    }

    /// Destroys notification `ntfn`: waiters wake with
    /// [`Error::ObjectDestroyed`] and pending bits are discarded.
    pub fn destroy_notification(&mut self, ntfn: u16) -> Result<(), IpcError> {
        let n = self.ntfn_index(ntfn)?;
        while let Some(t) = self.ntfns[n].waiters.pop(&mut self.threads) {
            self.threads[t as usize].status = Error::ObjectDestroyed.code();
            self.wake(t);
        }
        self.ntfns[n].word = 0;
        if let Some(t) = self.ntfns[n].bound.take() {
            self.threads[t as usize].bound = None;
        }
        self.schedule();
        Ok(())
    }

    /// Binds notification `ntfn` to thread `t`; see the module comment.
    pub fn bind_notification(&mut self, t: Tid, ntfn: u16) -> Result<(), IpcError> {
        let n = self.ntfn_index(ntfn)?;
        if t as usize >= T {
            return Err(IpcError::BadThread);
        }
        if self.threads[t as usize].bound.is_some() || self.ntfns[n].bound.is_some() {
            return Err(IpcError::AlreadyBound);
        }
        self.threads[t as usize].bound = Some(ntfn);
        self.ntfns[n].bound = Some(t);
        Ok(())
    }

    /// Takes the current thread's bound notification's pending bits, if
    /// there are any, as its badge.
    fn take_bound(&mut self, cur: Tid) -> bool {
        let Some(n) = self.threads[cur as usize].bound else {
            return false;
        };
        let word = core::mem::take(&mut self.ntfns[n as usize].word);
        if word == 0 {
            return false;
        }
        let tcb = &mut self.threads[cur as usize];
        tcb.badge = word;
        tcb.cap_received = None;
        true
    }

    /// Sets the status the current thread will see on return.
    pub fn set_status(&mut self, status: u64) {
        if let Some(c) = self.currents[self.cpu] {
            self.threads[c as usize].status = status;
        }
    }

    /// Makes an inactive thread runnable (starting or resuming it).
    pub fn spawn(&mut self, t: Tid, prio: u8) -> Result<(), IpcError> {
        let tcb = self
            .threads
            .get_mut(t as usize)
            .ok_or(IpcError::BadThread)?;
        if tcb.state != State::Inactive {
            return Err(IpcError::ThreadActive);
        }
        if prio as usize >= PRIORITIES {
            return Err(IpcError::BadPriority);
        }
        tcb.prio = prio;
        if !tcb.pinned {
            tcb.home = self.cpu as u8;
        }
        tcb.slice = TIMESLICE_TICKS;
        // Like any wakeup: a thread that outranks the running one takes over.
        self.wake(t);
        Ok(())
    }

    /// Gives scheduling context `sc` `budget` ticks every `period` ticks,
    /// starting with a full budget now.
    pub fn configure_sc(&mut self, sc: Tid, budget: u32, period: u32) -> Result<(), IpcError> {
        if sc as usize >= T {
            return Err(IpcError::BadThread);
        }
        if budget == 0 || budget > period {
            return Err(IpcError::BadSchedParams);
        }
        self.set_sc(sc, SchedContext::limited(budget, period, self.now));
        Ok(())
    }

    /// Makes context `sc` unlimited.
    pub fn unlimit_sc(&mut self, sc: Tid) -> Result<(), IpcError> {
        if sc as usize >= T {
            return Err(IpcError::BadThread);
        }
        self.set_sc(sc, UNLIMITED);
        Ok(())
    }

    /// Takes all budget from context `sc` (a new context object): threads
    /// on it cannot run until it is configured.
    pub fn empty_sc(&mut self, sc: Tid) -> Result<(), IpcError> {
        if sc as usize >= T {
            return Err(IpcError::BadThread);
        }
        self.set_sc(sc, EMPTY);
        Ok(())
    }

    /// Replaces context `sc` and moves every thread on it to match: ready
    /// threads may now be throttled, throttled ones may run.
    fn set_sc(&mut self, sc: Tid, ctx: SchedContext) {
        let consumed = self.scs[sc as usize].consumed;
        self.scs[sc as usize] = SchedContext { consumed, ..ctx };
        for w in 0..T as Tid {
            if self.active_sc(w) == Some(sc) {
                self.recheck(w);
            }
        }
        self.schedule();
    }

    /// Binds thread `t` to context `sc` (or to none: it cannot run). A
    /// passive thread keeps running on what callers lend it; the binding
    /// counts once it is no longer passive.
    pub fn bind_sc(&mut self, t: Tid, sc: Option<Tid>) -> Result<(), IpcError> {
        if t as usize >= T {
            return Err(IpcError::BadThread);
        }
        if sc.is_some_and(|x| x as usize >= T) {
            return Err(IpcError::BadThread);
        }
        self.threads[t as usize].sc = sc;
        self.recheck(t);
        self.schedule();
        self.preempt_if_outranked();
        Ok(())
    }

    /// The context thread `t` is bound to.
    pub fn bound_sc(&self, t: Tid) -> Option<Tid> {
        self.threads[t as usize].sc
    }

    /// Destroys context `sc`: threads bound to it, and passive threads
    /// running on it as a loan, are left with none and cannot run.
    pub fn destroy_sc(&mut self, sc: Tid) -> Result<(), IpcError> {
        if sc as usize >= T {
            return Err(IpcError::BadThread);
        }
        for w in 0..T {
            let tcb = &mut self.threads[w];
            let mut changed = false;
            if tcb.sc == Some(sc) {
                tcb.sc = None;
                changed = true;
            }
            if tcb.lent == Some(sc) {
                tcb.lent = None;
                changed = true;
            }
            if changed {
                self.recheck(w as Tid);
            }
        }
        self.scs[sc as usize] = UNLIMITED;
        self.schedule();
        Ok(())
    }

    /// Thread `t`'s context changed (bound, lent, emptied, refilled): puts
    /// it where it now belongs. A thread running on another CPU is only
    /// marked, and that CPU lets it go when it next enters the kernel.
    fn recheck(&mut self, t: Tid) {
        let usable = match self.active_sc(t) {
            None => Err(State::NoSchedContext),
            Some(sc) if self.scs[sc as usize].exhausted(self.now) => Err(State::Throttled { sc }),
            Some(_) => Ok(()),
        };
        let state = self.threads[t as usize].state;
        match (state, usable) {
            (State::Running, Err(parked)) => {
                self.threads[t as usize].state = parked;
                if self.currents[self.cpu] == Some(t) {
                    self.currents[self.cpu] = None;
                }
            }
            (State::Ready, Err(parked)) => {
                self.dequeue(t);
                self.threads[t as usize].state = parked;
            }
            (State::Throttled { .. } | State::NoSchedContext, Err(parked)) => {
                self.threads[t as usize].state = parked;
            }
            (State::Throttled { .. } | State::NoSchedContext, Ok(())) => self.wake(t),
            _ => {}
        }
    }

    pub fn sched_context(&self, sc: Tid) -> &SchedContext {
        &self.scs[sc as usize]
    }

    /// Ticks of budget context `sc` may use now.
    pub fn budget_left(&self, sc: Tid) -> u32 {
        self.scs[sc as usize].available(self.now)
    }

    /// Timer ticks since boot (advanced by the global tick).
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Makes `handler` (endpoint, badge) the one thread `t` calls with a
    /// timeout fault when a context lent to it runs dry; `None` for none.
    pub fn set_timeout_handler(&mut self, t: Tid, handler: Option<(u16, u64)>) -> Result<(), IpcError> {
        if t as usize >= T {
            return Err(IpcError::BadThread);
        }
        if let Some((ep, _)) = handler {
            self.ep_index(ep)?;
        }
        self.threads[t as usize].timeout = handler;
        Ok(())
    }

    pub fn timeout_handler(&self, t: Tid) -> Option<(u16, u64)> {
        self.threads[t as usize].timeout
    }

    /// The thread that the last tick made call its timeout handler, once.
    /// The kernel treats it as in a fault: the handler's reply says
    /// whether it goes on ([`crate::abi::FaultReply`]).
    pub fn take_timeout(&mut self) -> Option<Tid> {
        self.timeout_raised.take()
    }

    /// The caller server `t` set aside as `i` ([`Ipc::save_caller`]).
    pub fn saved_caller(&self, t: Tid, i: usize) -> Option<Tid> {
        self.threads.get(t as usize)?.saved.get(i).copied().flatten()
    }

    /// The current thread gives up its own scheduling context the next
    /// time it blocks or receives, and from then on runs only on contexts
    /// its callers lend it.
    pub fn make_passive(&mut self) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let tcb = &mut self.threads[cur as usize];
        tcb.passive_pending = true;
        tcb.status = 0;
        Ok(())
    }

    /// The scheduling context `t` runs on, if any.
    pub fn active_sc(&self, t: Tid) -> Option<Tid> {
        let tcb = &self.threads[t as usize];
        if tcb.passive { tcb.lent } else { tcb.sc }
    }

    /// One timer tick: charges the tick to the current thread's scheduling
    /// context (throttling it if that empties the budget), refills contexts
    /// whose period has ended (waking threads throttled on them), then
    /// applies round-robin time slicing. Returns true if the current
    /// thread changed.
    pub fn tick(&mut self) -> bool {
        self.tick_cpu(true)
    }

    /// One tick of this CPU's timer. Only the `global` one (one CPU's)
    /// advances time and refills budgets; every CPU charges its own thread
    /// and slices its own time.
    pub fn tick_cpu(&mut self, global: bool) -> bool {
        self.settle();
        // The tick being charged began at the clock's current value.
        let began = self.now;
        if global {
            self.now += 1;
        }
        let before = self.currents[self.cpu];
        if let Some(c) = before {
            self.charge(c, began);
        }
        if global {
            self.refill();
        }
        if self.currents[self.cpu].is_some() && self.currents[self.cpu] == before {
            self.rotate();
        }
        self.schedule();
        self.currents[self.cpu] != before
    }

    fn charge(&mut self, c: Tid, began: u64) {
        let Some(sc) = self.active_sc(c) else {
            // Passive with nothing lent: may not run unaccounted.
            self.threads[c as usize].state = State::NoSchedContext;
            self.currents[self.cpu] = None;
            return;
        };
        let lent = self.threads[c as usize].passive;
        if lent {
            self.stats.donated_ticks += 1;
        }
        if self.scs[sc as usize].charge(began) {
            // Every other thread on the context stops too, wherever it runs.
            for x in 0..MAX_CPUS {
                if let Some(o) = self.currents[x]
                    && x != self.cpu
                    && self.threads[o as usize].state == State::Running
                    && self.active_sc(o) == Some(sc)
                {
                    self.threads[o as usize].state = State::Throttled { sc };
                    self.stats.throttles += 1;
                }
            }
            if lent && self.raise_timeout(c, sc) {
                return;
            }
            self.threads[c as usize].state = State::Throttled { sc };
            self.currents[self.cpu] = None;
            self.stats.throttles += 1;
        }
    }

    /// The current thread `c` emptied context `sc`, lent to it: if it has
    /// a timeout handler, it calls it (`msg` = [`FaultKind::Timeout`], the
    /// context's budget and period) and keeps the lent context, as a
    /// server keeps it through any call it makes. Returns false if there
    /// is no handler or the call fails, for the caller to throttle it.
    fn raise_timeout(&mut self, c: Tid, sc: Tid) -> bool {
        let Some((ep, badge)) = self.threads[c as usize].timeout else {
            return false;
        };
        let ctx = self.scs[sc as usize];
        let msg = [
            FaultKind::Timeout as u64,
            ctx.budget.unwrap_or(0) as u64,
            ctx.period as u64,
            0,
        ];
        // A fault message carries no capability, whatever the thread's
        // last system call named.
        let xfer = core::mem::replace(&mut self.threads[c as usize].xfer, CapTransfer::NONE);
        let raised = self.call(ep, badge, msg).is_ok();
        self.threads[c as usize].xfer = xfer;
        if raised {
            self.stats.timeouts += 1;
            self.timeout_raised = Some(c);
        }
        raised
    }

    /// Wakes threads throttled on a context that a refill released.
    fn refill(&mut self) {
        for t in 0..T {
            if let State::Throttled { sc } = self.threads[t].state
                && !self.scs[sc as usize].exhausted(self.now)
            {
                self.wake(t as Tid);
            }
        }
    }

    /// Round robin: when the current thread's slice is used up it goes
    /// behind any ready thread of equal or higher priority.
    fn rotate(&mut self) {
        let Some(c) = self.currents[self.cpu] else { return };
        let tcb = &mut self.threads[c as usize];
        if tcb.slice > 1 {
            tcb.slice -= 1;
            return;
        }
        tcb.slice = TIMESLICE_TICKS;
        let prio = tcb.prio;
        if let Some(p) = self.highest_ready()
            && p >= prio
        {
            // Among equals, the one that has waited longest anywhere.
            let peer = (p == prio)
                .then(|| self.longest_waiting(p as usize, self.cpu))
                .flatten();
            self.currents[self.cpu] = None;
            self.make_ready(c);
            if let Some(t) = peer {
                self.run_queued(t);
            }
        }
    }

    /// Picks a thread if none is running. After every operation `current`
    /// is the thread to resume, or `None` if nothing is runnable.
    pub fn schedule(&mut self) {
        if self.currents[self.cpu].is_some() {
            return;
        }
        // Levels whose every thread another CPU still keeps.
        let mut kept = 0u64;
        while self.all_ready_bits() & !kept != 0 {
            let bits = self.all_ready_bits() & !kept;
            let p = 63 - bits.leading_zeros() as usize;
            let Some(t) = self.first_runnable(p, self.cpu) else {
                kept |= 1 << p;
                continue;
            };
            if self.run_queued(t) {
                return;
            }
        }
    }

    /// Takes queued thread `t` off its queue and runs it on this CPU, or,
    /// if its context has run dry since it was queued (another thread on
    /// the same context used it up), parks it until a refill, as it would
    /// have been on waking. Returns whether it runs.
    fn run_queued(&mut self, t: Tid) -> bool {
        self.dequeue(t);
        match self.active_sc(t) {
            None => self.threads[t as usize].state = State::NoSchedContext,
            Some(sc) if self.scs[sc as usize].exhausted(self.now) => {
                self.threads[t as usize].state = State::Throttled { sc };
            }
            Some(_) => {
                self.switch_to(t);
                return true;
            }
        }
        false
    }

    // ---- system calls, always on behalf of `current` --------------------

    pub fn send(
        &mut self,
        ep: u16,
        badge: u64,
        msg: [u64; MSG_WORDS],
        blocking: bool,
    ) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let e = self.ep_index(ep)?;
        self.threads[cur as usize].status = 0;
        if self.eps[e].state == EpState::Receiving {
            let r = self.dequeue_ep(e);
            self.deliver(cur, r, msg, badge);
            self.wake(r);
        } else if blocking {
            let tcb = &mut self.threads[cur as usize];
            tcb.msg = msg;
            tcb.badge = badge;
            self.block_on_ep(
                cur,
                e,
                State::BlockedSend { ep, call: false },
                EpState::Sending,
            );
            self.schedule();
        }
        // A non-blocking send with no receiver is silently dropped (seL4 semantics).
        Ok(())
    }

    pub fn call(&mut self, ep: u16, badge: u64, msg: [u64; MSG_WORDS]) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let e = self.ep_index(ep)?;
        if self.eps[e].state == EpState::Receiving {
            let server = self.dequeue_ep(e);
            self.deliver(cur, server, msg, badge);
            self.take_caller(server, cur);
            self.lend(cur, server);
            self.threads[cur as usize].state = State::BlockedReply;
            self.currents[self.cpu] = None;
            self.switch_or_schedule(server);
        } else {
            let tcb = &mut self.threads[cur as usize];
            tcb.msg = msg;
            tcb.badge = badge;
            self.block_on_ep(
                cur,
                e,
                State::BlockedSend { ep, call: true },
                EpState::Sending,
            );
            self.schedule();
        }
        Ok(())
    }

    pub fn recv(&mut self, ep: u16, blocking: bool) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let e = self.ep_index(ep)?;
        if self.take_bound(cur) {
            return Err(IpcError::Notified);
        }
        if self.eps[e].state == EpState::Sending {
            // A pending switch to passive takes effect on any receive, not
            // just one that blocks: a server whose first caller is already
            // queued must run on that caller's context, not its own.
            self.settle_passive(cur);
            self.take_from_sender(cur, e);
            // A passive receiver runs on what the caller lent it, which
            // may be nothing (the caller went passive as it blocked).
            self.park_if_no_sc(cur);
            self.schedule();
            self.preempt_if_outranked();
            Ok(())
        } else if blocking {
            self.block_on_ep(cur, e, State::BlockedRecv { ep }, EpState::Receiving);
            self.schedule();
            Ok(())
        } else {
            Err(IpcError::WouldBlock)
        }
    }

    /// Replies to the caller this thread owes, if any. Replying with no
    /// caller is a no-op.
    pub fn reply(&mut self, msg: [u64; MSG_WORDS]) -> Result<(), IpcError> {
        let cur = self.cur()?;
        self.threads[cur as usize].status = 0;
        if let Some(c) = self.threads[cur as usize].caller.take() {
            // The caller may have been suspended meanwhile: then the reply
            // has nobody to go to.
            let waiting = self.awaits_reply(c);
            if waiting {
                self.deliver(cur, c, msg, 0);
            }
            self.threads[cur as usize].lent = None;
            self.park_if_no_sc(cur);
            if waiting {
                self.wake(c);
            }
            self.schedule();
        }
        Ok(())
    }

    /// Sets aside the caller the current thread owes a reply, so it may
    /// receive more calls before answering it ([`Ipc::reply_saved`]):
    /// returns the place it went in. A passive thread may not (it runs
    /// on that caller's context), nor one with every place taken.
    pub fn save_caller(&mut self) -> Result<usize, IpcError> {
        let cur = self.cur()?;
        let tcb = &mut self.threads[cur as usize];
        let Some(c) = tcb.caller else {
            return Err(IpcError::NoCaller);
        };
        if tcb.passive {
            return Err(IpcError::CannotSave);
        }
        let Some(i) = tcb.saved.iter().position(|s| s.is_none()) else {
            return Err(IpcError::CannotSave);
        };
        tcb.saved[i] = Some(c);
        tcb.caller = None;
        Ok(i)
    }

    /// Answers the caller the current thread set aside in place `i` (as
    /// [`Ipc::reply`]; no capability goes with it). A place with nobody
    /// in it (answered already, or its caller was stopped) is a no-op.
    pub fn reply_saved(&mut self, i: usize, msg: [u64; MSG_WORDS]) -> Result<(), IpcError> {
        let cur = self.cur()?;
        if i >= SAVED_CALLERS {
            return Err(IpcError::BadIndex);
        }
        self.threads[cur as usize].status = 0;
        if let Some(c) = self.threads[cur as usize].saved[i].take()
            && self.awaits_reply(c)
        {
            let xfer = core::mem::replace(&mut self.threads[cur as usize].xfer, CapTransfer::NONE);
            self.deliver(cur, c, msg, 0);
            self.threads[cur as usize].xfer = xfer;
            self.wake(c);
            self.schedule();
        }
        Ok(())
    }

    /// Reply then receive, the server's steady-state loop. When nothing is
    /// queued, the server blocks and control passes straight to the caller.
    pub fn reply_recv(&mut self, ep: u16, msg: [u64; MSG_WORDS]) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let e = self.ep_index(ep)?;
        let owed = self.threads[cur as usize].caller.take();
        if owed.is_some() {
            self.threads[cur as usize].lent = None;
        }
        let caller = owed.filter(|&c| self.awaits_reply(c));
        if let Some(c) = caller {
            self.deliver(cur, c, msg, 0);
        }
        if self.take_bound(cur) {
            self.park_if_no_sc(cur);
            if let Some(c) = caller {
                self.wake(c);
            }
            self.schedule();
            self.preempt_if_outranked();
            return Err(IpcError::Notified);
        }
        if self.eps[e].state == EpState::Sending {
            self.take_from_sender(cur, e);
            self.park_if_no_sc(cur);
            if let Some(c) = caller {
                self.wake(c);
            }
            self.schedule();
            self.preempt_if_outranked();
        } else {
            self.block_on_ep(cur, e, State::BlockedRecv { ep }, EpState::Receiving);
            match caller {
                Some(c) => self.switch_or_schedule(c),
                None => self.schedule(),
            }
        }
        Ok(())
    }

    /// ORs `bits` into a notification, waking one waiter if there is one.
    pub fn signal(&mut self, ntfn: u16, bits: u64) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let n = self.ntfn_index(ntfn)?;
        self.threads[cur as usize].status = 0;
        self.deliver_bits(n, bits);
        Ok(())
    }

    /// Signals a notification from an interrupt: like [`Ipc::signal`], but
    /// with no calling thread, so it also works while the CPU is idle. A
    /// woken thread of higher priority than the current one preempts it;
    /// with nothing running, the woken thread becomes current.
    pub fn signal_irq(&mut self, ntfn: u16, bits: u64) -> Result<(), IpcError> {
        self.settle();
        let n = self.ntfn_index(ntfn)?;
        self.deliver_bits(n, bits);
        self.schedule();
        Ok(())
    }

    fn deliver_bits(&mut self, n: usize, bits: u64) {
        match self.ntfns[n].waiters.pop(&mut self.threads) {
            Some(w) => {
                let word = self.ntfns[n].word | bits;
                self.ntfns[n].word = 0;
                let tcb = &mut self.threads[w as usize];
                tcb.badge = word;
                tcb.status = 0;
                self.wake(w);
            }
            None => {
                self.ntfns[n].word |= bits;
                // A bound thread waiting for calls takes the bits now.
                if let Some(t) = self.ntfns[n].bound
                    && let State::BlockedRecv { ep } = self.threads[t as usize].state
                {
                    let e = ep as usize;
                    self.eps[e].queue.remove(&mut self.threads, t);
                    if self.eps[e].queue.is_empty() {
                        self.eps[e].state = EpState::Idle;
                    }
                    let tcb = &mut self.threads[t as usize];
                    tcb.badge = core::mem::take(&mut self.ntfns[n].word);
                    tcb.status = Error::Notified.code();
                    tcb.cap_received = None;
                    self.wake(t);
                }
            }
        }
    }

    /// Forgets the notification's accumulated bits.
    pub fn clear_notification(&mut self, ntfn: u16) -> Result<(), IpcError> {
        let n = self.ntfn_index(ntfn)?;
        self.ntfns[n].word = 0;
        Ok(())
    }

    /// Takes the notification's accumulated bits (returned as the badge),
    /// blocking until there are some.
    pub fn wait(&mut self, ntfn: u16) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let n = self.ntfn_index(ntfn)?;
        let word = self.ntfns[n].word;
        if word != 0 {
            self.ntfns[n].word = 0;
            let tcb = &mut self.threads[cur as usize];
            tcb.badge = word;
            tcb.status = 0;
        } else {
            self.settle_passive(cur);
            self.threads[cur as usize].state = State::BlockedWait { ntfn };
            self.currents[self.cpu] = None;
            self.ntfns[n].waiters.push_back(&mut self.threads, cur);
            self.schedule();
        }
        Ok(())
    }

    pub fn yield_now(&mut self) -> Result<(), IpcError> {
        let cur = self.cur()?;
        self.threads[cur as usize].status = 0;
        self.currents[self.cpu] = None;
        // The peer of equal priority that has waited longest gets the
        // turn, wherever it is queued: queued behind it on this CPU, the
        // yielder would otherwise come straight back while a peer on a
        // busy CPU's queue waits out that CPU's time slice.
        let p = self.threads[cur as usize].prio;
        let peer = if self.highest_ready() == Some(p) {
            self.longest_waiting(p as usize, self.cpu)
        } else {
            None
        };
        self.make_ready(cur);
        if let Some(t) = peer
            && self.run_queued(t)
        {
            return Ok(());
        }
        self.schedule();
        Ok(())
    }

    // ---- internals ------------------------------------------------------

    fn cur(&self) -> Result<Tid, IpcError> {
        self.currents[self.cpu].ok_or(IpcError::NoCurrent)
    }

    fn ep_index(&self, ep: u16) -> Result<usize, IpcError> {
        ((ep as usize) < E)
            .then_some(ep as usize)
            .ok_or(IpcError::BadObject)
    }

    fn ntfn_index(&self, n: u16) -> Result<usize, IpcError> {
        ((n as usize) < N)
            .then_some(n as usize)
            .ok_or(IpcError::BadObject)
    }

    /// Moves a message from `from` to `to`, recording a capability
    /// transfer if `from` grants one and `to` accepts one.
    fn deliver(&mut self, from: Tid, to: Tid, msg: [u64; MSG_WORDS], badge: u64) {
        let grant = self.threads[from as usize].xfer.grant;
        let tcb = &mut self.threads[to as usize];
        tcb.msg = msg;
        tcb.badge = badge;
        tcb.status = 0;
        tcb.cap_received = None;
        if let (Some(grant), Some(accept)) = (grant, tcb.xfer.accept) {
            let t = Transfer {
                from,
                grant,
                to,
                accept,
            };
            let free = self.transfers.iter_mut().find(|x| x.is_none());
            *free.expect("more deliveries in one operation than MAX_TRANSFERS") = Some(t);
        }
    }

    /// Records that `server` owes `caller` a reply. If the server already
    /// owed someone, that earlier caller is woken with `ReplyAbandoned`
    /// rather than left blocked forever.
    fn take_caller(&mut self, server: Tid, caller: Tid) {
        if let Some(old) = self.threads[server as usize].caller.replace(caller)
            && self.awaits_reply(old)
        {
            self.threads[old as usize].status = Error::ReplyAbandoned.code();
            self.make_ready(old);
        }
    }

    /// `cur` receives from the first queued sender on endpoint `e`.
    fn take_from_sender(&mut self, cur: Tid, e: usize) {
        let s = self.dequeue_ep(e);
        let sender = self.threads[s as usize];
        self.deliver(s, cur, sender.msg, sender.badge);
        if let State::BlockedSend { call: true, .. } = sender.state {
            self.take_caller(cur, s);
            self.lend(s, cur);
            self.threads[s as usize].state = State::BlockedReply;
        } else {
            self.threads[s as usize].status = 0;
            self.wake(s);
        }
    }

    fn block_on_ep(&mut self, t: Tid, e: usize, state: State, ep_state: EpState) {
        self.settle_passive(t);
        self.threads[t as usize].state = state;
        if self.currents[self.cpu] == Some(t) {
            self.currents[self.cpu] = None;
        }
        self.eps[e].queue.push_back(&mut self.threads, t);
        self.eps[e].state = ep_state;
    }

    fn dequeue_ep(&mut self, e: usize) -> Tid {
        let t = self.eps[e].queue.pop(&mut self.threads).unwrap();
        if self.eps[e].queue.is_empty() {
            self.eps[e].state = EpState::Idle;
        }
        t
    }

    /// A pending switch to passive takes effect as the thread blocks.
    fn settle_passive(&mut self, t: Tid) {
        let tcb = &mut self.threads[t as usize];
        if core::mem::take(&mut tcb.passive_pending) {
            tcb.passive = true;
        }
    }

    /// `caller` calls passive `server`: lend it the context `caller` runs on.
    fn lend(&mut self, caller: Tid, server: Tid) {
        if self.threads[server as usize].passive {
            self.threads[server as usize].lent = self.active_sc(caller);
        }
    }

    /// Stops the current thread `t` if it has no context to run on, or
    /// one with no budget: a passive server that took a call lent a
    /// context emptied while its caller waited in the queue.
    fn park_if_no_sc(&mut self, t: Tid) {
        if self.currents[self.cpu] != Some(t) {
            return;
        }
        let parked = match self.active_sc(t) {
            None => State::NoSchedContext,
            Some(sc) if self.scs[sc as usize].exhausted(self.now) => State::Throttled { sc },
            Some(_) => return,
        };
        self.threads[t as usize].state = parked;
        self.currents[self.cpu] = None;
    }

    /// Queues `t` to run, or, if it has no context with budget, parks it
    /// as throttled (until refill) or without a context. Returns whether
    /// it was queued.
    fn make_ready(&mut self, t: Tid) -> bool {
        match self.active_sc(t) {
            None => {
                self.threads[t as usize].state = State::NoSchedContext;
                return false;
            }
            Some(sc) if self.scs[sc as usize].exhausted(self.now) => {
                self.threads[t as usize].state = State::Throttled { sc };
                return false;
            }
            Some(_) => {}
        }
        self.threads[t as usize].state = State::Ready;
        self.enqueue(t, false);
        true
    }

    /// Queues ready thread `t` on its home CPU, at the back of its level
    /// or (preempted, so it resumes before peers that have not run) the
    /// front.
    fn enqueue(&mut self, t: Tid, front: bool) {
        let (h, p) = (self.threads[t as usize].home as usize, self.threads[t as usize].prio as usize);
        if front {
            self.threads[t as usize].queued = 0;
            self.ready[h][p].push_front(&mut self.threads, t);
        } else {
            self.queue_seq += 1;
            self.threads[t as usize].queued = self.queue_seq;
            self.ready[h][p].push_back(&mut self.threads, t);
        }
        self.ready_bits[h] |= 1 << p;
    }

    /// Takes ready thread `t` off its queue.
    fn dequeue(&mut self, t: Tid) {
        let (h, p) = (self.threads[t as usize].home as usize, self.threads[t as usize].prio as usize);
        self.ready[h][p].remove(&mut self.threads, t);
        if self.ready[h][p].is_empty() {
            self.ready_bits[h] &= !(1 << p);
        }
    }

    /// Levels with a thread ready on any CPU.
    fn all_ready_bits(&self) -> u64 {
        self.ready_bits.iter().fold(0, |a, b| a | b)
    }

    /// The first thread at level `p` CPU `cpu` may run: from its own queue
    /// if it has one there, else from the next CPU's round, skipping any
    /// another CPU still keeps.
    fn first_runnable(&self, p: usize, cpu: usize) -> Option<Tid> {
        (0..MAX_CPUS).map(|i| (cpu + i) % MAX_CPUS).find_map(|x| {
            let mut at = self.ready[x][p].head;
            while let Some(t) = at {
                if self.may_run(t, cpu) && !self.pinned_off(t, cpu) {
                    return Some(t);
                }
                at = self.threads[t as usize].next;
            }
            None
        })
    }

    /// The thread at level `p` that has waited longest of those CPU `cpu`
    /// may run, on any CPU's queue (its own first among equals): who takes
    /// the turn when a thread's slice ends or it yields, so that threads
    /// of equal priority share every CPU in turn, not just their own.
    fn longest_waiting(&self, p: usize, cpu: usize) -> Option<Tid> {
        let mut best: Option<Tid> = None;
        for x in (0..MAX_CPUS).map(|i| (cpu + i) % MAX_CPUS) {
            let mut at = self.ready[x][p].head;
            while let Some(t) = at {
                if self.may_run(t, cpu) && !self.pinned_off(t, cpu) {
                    if best.is_none_or(|b| self.threads[t as usize].queued < self.threads[b as usize].queued) {
                        best = Some(t);
                    }
                    break;
                }
                at = self.threads[t as usize].next;
            }
        }
        best
    }

    /// The CPU whose queue ready thread `t` is on, if it is ready.
    pub fn queued_on(&self, t: Tid) -> Option<usize> {
        let tcb = &self.threads[t as usize];
        (tcb.state == State::Ready).then_some(tcb.home as usize)
    }

    /// Whether CPU `cpu` may run thread `t`: any CPU, unless it is pinned.
    fn may_run(&self, t: Tid, cpu: usize) -> bool {
        let tcb = &self.threads[t as usize];
        !tcb.pinned || tcb.home as usize == cpu
    }

    /// The highest priority with a thread ready that this CPU may run.
    fn highest_ready(&self) -> Option<u8> {
        self.highest_ready_on(self.cpu)
    }

    /// The highest priority with a thread ready that CPU `cpu` may run
    /// (one no other CPU keeps).
    fn highest_ready_on(&self, cpu: usize) -> Option<u8> {
        let bits = self.all_ready_bits();
        if self.pinned_count == 0 && !self.any_pinned() {
            return (bits != 0).then(|| 63 - bits.leading_zeros() as u8);
        }
        (0..PRIORITIES)
            .rev()
            .filter(|&p| bits >> p & 1 == 1)
            .find(|&p| self.first_runnable(p, cpu).is_some())
            .map(|p| p as u8)
    }

    /// Makes `t` runnable; preempts the current thread if `t` outranks it.
    fn wake(&mut self, t: Tid) {
        if !self.make_ready(t) {
            return;
        }
        if let Some(c) = self.currents[self.cpu]
            && self.threads[t as usize].prio > self.threads[c as usize].prio
            && self.may_run(t, self.cpu)
        {
            // The preempted thread goes to the front of its level so it
            // resumes before peers that have not run.
            self.threads[c as usize].state = State::Ready;
            self.enqueue(c, true);
            self.currents[self.cpu] = None;
            self.schedule();
        }
    }

    /// Taking a new caller can wake an abandoned earlier one without
    /// preempting (the operation was still in progress): if anything ready
    /// now outranks the current thread, switch to it.
    fn preempt_if_outranked(&mut self) {
        if let (Some(c), Some(p)) = (self.currents[self.cpu], self.highest_ready())
            && p > self.threads[c as usize].prio
        {
            self.currents[self.cpu] = None;
            let runnable = self
                .active_sc(c)
                .is_some_and(|sc| !self.scs[sc as usize].exhausted(self.now));
            if runnable {
                self.threads[c as usize].state = State::Ready;
                self.enqueue(c, true);
            } else {
                self.make_ready(c); // parks it
            }
            self.schedule();
        }
    }

    /// Direct switch to `t` (fast path) unless a higher-priority thread is
    /// waiting, in which case `t` queues like anyone else.
    fn switch_or_schedule(&mut self, t: Tid) {
        debug_assert!(self.currents[self.cpu].is_none());
        let runnable = self
            .active_sc(t)
            .is_some_and(|sc| !self.scs[sc as usize].exhausted(self.now));
        match self.highest_ready() {
            _ if !runnable || !self.may_run(t, self.cpu) => {
                self.make_ready(t); // parks it
                self.schedule();
            }
            Some(p) if p > self.threads[t as usize].prio => {
                self.make_ready(t);
                self.schedule();
            }
            _ => self.switch_to(t),
        }
    }

    fn switch_to(&mut self, t: Tid) {
        debug_assert!(self.may_run(t, self.cpu));
        let tcb = &mut self.threads[t as usize];
        if tcb.home as usize != self.cpu {
            tcb.home = self.cpu as u8;
            self.stats.migrations += 1;
        }
        tcb.state = State::Running;
        self.currents[self.cpu] = Some(t);
    }
}

#[cfg(test)]
impl<const T: usize, const E: usize, const N: usize> Ipc<T, E, N> {
    /// Checks every structural invariant of the engine, for the
    /// simulation harness. Call after the kernel would (after `schedule`).
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn check_invariants(&self) -> Result<(), std::string::String> {
        use std::format;
        use std::vec::Vec;
        let th = &self.threads;
        // Walk a queue, refusing cycles; returns its members in order.
        let walk = |q: &Queue, what: &str| -> Result<Vec<Tid>, std::string::String> {
            let mut out = Vec::new();
            let mut at = q.head;
            while let Some(t) = at {
                if out.len() > T {
                    return Err(format!("{what}: cycle"));
                }
                out.push(t);
                at = th[t as usize].next;
            }
            if q.tail != out.last().copied() {
                return Err(format!(
                    "{what}: tail {:?} but last is {:?}",
                    q.tail,
                    out.last()
                ));
            }
            Ok(out)
        };
        let mut seen = [0u32; T];
        let mut mark = |members: &[Tid], what: &str| -> Result<(), std::string::String> {
            for &t in members {
                seen[t as usize] += 1;
                if seen[t as usize] > 1 {
                    return Err(format!("thread {t} on two queues (second: {what})"));
                }
            }
            Ok(())
        };
        // Ready queues: each thread on its home CPU's.
        for x in 0..MAX_CPUS {
            for p in 0..PRIORITIES {
                let q = walk(&self.ready[x][p], "ready")?;
                if (self.ready_bits[x] >> p & 1 == 1) != !q.is_empty() {
                    return Err(format!("CPU {x}'s ready bit {p} disagrees with its queue"));
                }
                for &t in &q {
                    let tcb = &th[t as usize];
                    if tcb.state != State::Ready || tcb.prio as usize != p || tcb.home as usize != x {
                        return Err(format!(
                            "thread {t} in CPU {x}'s ready[{p}] is {:?} prio {} home {}",
                            tcb.state, tcb.prio, tcb.home
                        ));
                    }
                }
                mark(&q, "ready")?;
            }
        }
        // Pinning: counted right, and no CPU runs a thread pinned elsewhere.
        let pinned = th.iter().filter(|t| t.pinned).count();
        if pinned != self.pinned_count {
            return Err(format!("{pinned} threads pinned but the count is {}", self.pinned_count));
        }
        for (x, c) in self.currents.iter().enumerate() {
            if let Some(t) = *c
                && th[t as usize].state == State::Running
                && !self.may_run(t, x)
            {
                return Err(format!("CPU {x} runs thread {t}, pinned to CPU {}", th[t as usize].home));
            }
        }
        // Endpoints.
        for e in 0..E {
            let q = walk(&self.eps[e].queue, "endpoint")?;
            let ok = match self.eps[e].state {
                EpState::Idle => q.is_empty(),
                EpState::Sending => {
                    !q.is_empty()
                        && q.iter().all(|&t| {
                            matches!(th[t as usize].state,
                            State::BlockedSend { ep, .. } if ep as usize == e)
                        })
                }
                EpState::Receiving => {
                    !q.is_empty()
                        && q.iter().all(|&t| {
                            matches!(th[t as usize].state,
                            State::BlockedRecv { ep } if ep as usize == e)
                        })
                }
            };
            if !ok {
                return Err(format!(
                    "endpoint {e} is {:?} with queue {q:?}",
                    self.eps[e].state
                ));
            }
            mark(&q, "endpoint")?;
        }
        // Notifications.
        for n in 0..N {
            let q = walk(&self.ntfns[n].waiters, "notification")?;
            if q.iter()
                .any(|&t| th[t as usize].state != State::BlockedWait { ntfn: n as u16 })
            {
                return Err(format!("notification {n} has a waiter not waiting on it"));
            }
            if !q.is_empty() && self.ntfns[n].word != 0 {
                return Err(format!("notification {n} has waiters and pending bits"));
            }
            mark(&q, "notification")?;
        }
        // Every queued state is on exactly the queue it names, and only
        // queued states are on queues.
        let mut running = 0;
        for (t, tcb) in th.iter().enumerate() {
            let queued = matches!(
                tcb.state,
                State::Ready
                    | State::BlockedSend { .. }
                    | State::BlockedRecv { .. }
                    | State::BlockedWait { .. }
            );
            if queued != (seen[t] == 1) {
                return Err(format!(
                    "thread {t} is {:?} but on {} queues",
                    tcb.state, seen[t]
                ));
            }
            if tcb.state == State::Running {
                running += 1;
                let on = self.currents.iter().filter(|&&c| c == Some(t as Tid)).count();
                if on != 1 {
                    return Err(format!("thread {t} Running but current on {on} CPUs"));
                }
            }
            // A thread waiting for a reply is owed one by exactly one server.
            if tcb.state == State::BlockedReply {
                let me = Some(t as Tid);
                let owers = th
                    .iter()
                    .map(|s| (s.caller == me) as usize + s.saved.iter().filter(|&&x| x == me).count())
                    .sum::<usize>();
                if owers != 1 {
                    return Err(format!("thread {t} awaits a reply owed by {owers} threads"));
                }
            }
            if let State::Throttled { sc } = tcb.state
                && !self.scs[sc as usize].exhausted(self.now)
            {
                return Err(format!("thread {t} throttled on a context with budget"));
            }
            if tcb.lent.is_some() && !tcb.passive {
                return Err(format!(
                    "thread {t} holds a lent context but is not passive"
                ));
            }
        }
        let current = self.currents[self.cpu];
        let held = self.currents.iter().flatten().count();
        let kept = self
            .currents
            .iter()
            .flatten()
            .filter(|&&c| self.threads[c as usize].state != State::Running)
            .count();
        if running != held - kept {
            return Err(format!("{running} Running threads, CPUs hold {:?}", self.currents));
        }
        if current.is_some_and(|c| self.threads[c as usize].state != State::Running) {
            return Err(format!("this CPU keeps {current:?}, not Running"));
        }
        // Strict priorities: nothing ready outranks the running thread, and
        // the CPU is never idle with a thread ready.
        match (current, self.highest_ready()) {
            (None, Some(p)) => return Err(format!("idle with priority {p} ready")),
            (Some(c), Some(p)) if p > th[c as usize].prio => {
                return Err(format!("thread {c} runs below ready priority {p}"));
            }
            _ => {}
        }
        if let Some(c) = current {
            match self.active_sc(c) {
                None => return Err(format!("current thread {c} has no scheduling context")),
                Some(sc) if self.scs[sc as usize].exhausted(self.now) => {
                    return Err(format!("current thread {c} runs on an empty budget"));
                }
                _ => {}
            }
        }
        for (i, sc) in self.scs.iter().enumerate() {
            sc.check(self.now).map_err(|e| format!("context {i}: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    type K = Ipc<8, 4, 4>;
    const SERVER: Tid = 0;
    const CLIENT: Tid = 1;
    const OTHER: Tid = 2;
    const EP: u16 = 0;

    /// Server (prio 10) blocks in Recv on EP; client (prio 5) is running.
    fn server_waiting() -> K {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        k.recv(EP, true).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        k
    }

    #[test]
    fn highest_priority_runs_first() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
    }

    #[test]
    fn call_and_reply_recv_ping_pong_switch_directly() {
        let mut k = server_waiting();
        for i in 0..3u64 {
            k.call(EP, 0xC1, [i, 0, 0, 0]).unwrap();
            // Fast path: straight to the server, with the message and badge.
            assert_eq!(k.current(), Some(SERVER));
            assert_eq!(k.thread(SERVER).msg[0], i);
            assert_eq!(k.thread(SERVER).badge, 0xC1);
            assert_eq!(k.thread(CLIENT).state, State::BlockedReply);

            k.reply_recv(EP, [i + 1, 0, 0, 0]).unwrap();
            // And straight back to the client with the reply.
            assert_eq!(k.current(), Some(CLIENT));
            assert_eq!(k.thread(CLIENT).msg[0], i + 1);
            assert_eq!(k.thread(CLIENT).status, 0);
            assert_eq!(k.thread(SERVER).state, State::BlockedRecv { ep: EP });
        }
        assert_eq!(k.ready_bits, [0; MAX_CPUS], "fast path never touched the ready queues");
    }

    #[test]
    fn senders_queue_in_fifo_order() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.spawn(SERVER, 1).unwrap();
        k.schedule();
        k.send(EP, 1, [100, 0, 0, 0], true).unwrap(); // CLIENT blocks
        assert_eq!(k.current(), Some(OTHER));
        k.send(EP, 2, [200, 0, 0, 0], true).unwrap(); // OTHER blocks
        assert_eq!(k.current(), Some(SERVER));

        k.recv(EP, true).unwrap();
        assert_eq!((k.thread(SERVER).msg[0], k.thread(SERVER).badge), (100, 1));
        // CLIENT woke and outranks SERVER, so it preempted.
        assert_eq!(k.current(), Some(CLIENT));
        k.yield_now().unwrap(); // CLIENT -> back of prio 5, after nobody
        assert_eq!(k.current(), Some(CLIENT));
    }

    #[test]
    fn send_to_waiting_receiver_wakes_it_by_priority() {
        let mut k = server_waiting();
        k.send(EP, 7, [9, 0, 0, 0], true).unwrap();
        // Server outranks the client, so it preempts.
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!((k.thread(SERVER).msg[0], k.thread(SERVER).badge), (9, 7));
        assert_eq!(k.thread(CLIENT).state, State::Ready);
    }

    #[test]
    fn non_blocking_ops() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        assert_eq!(k.recv(EP, false), Err(IpcError::WouldBlock));
        k.send(EP, 0, [1, 0, 0, 0], false).unwrap(); // dropped, no receiver
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.recv(EP, false), Err(IpcError::WouldBlock));
    }

    #[test]
    fn recv_from_queued_caller_owes_reply() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(SERVER, 1).unwrap();
        k.schedule();
        k.call(EP, 3, [41, 0, 0, 0]).unwrap(); // no server waiting: queue
        assert_eq!(k.current(), Some(SERVER));
        k.recv(EP, true).unwrap();
        assert_eq!(k.thread(SERVER).msg[0], 41);
        assert_eq!(k.thread(CLIENT).state, State::BlockedReply);
        k.reply([42, 0, 0, 0]).unwrap();
        assert_eq!(k.current(), Some(CLIENT)); // higher prio, preempts
        assert_eq!(k.thread(CLIENT).msg[0], 42);
    }

    #[test]
    fn saved_callers_are_answered_later_in_any_order() {
        let mut k = K::new();
        k.spawn(CLIENT, 1).unwrap();
        k.spawn(OTHER, 1).unwrap();
        k.spawn(SERVER, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap(); // the server waits
        assert_eq!(k.current(), Some(CLIENT));
        k.call(EP, 1, [10, 0, 0, 0]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.save_caller(), Ok(0));
        k.recv(EP, true).unwrap(); // no abandoning: CLIENT is set aside
        assert_eq!(k.current(), Some(OTHER));
        k.call(EP, 2, [20, 0, 0, 0]).unwrap();
        assert_eq!(k.thread(CLIENT).state, State::BlockedReply);
        assert_eq!(k.thread(CLIENT).status, 0);
        assert_eq!(k.save_caller(), Ok(1));
        assert_eq!(k.save_caller(), Err(IpcError::NoCaller));
        // Answered in the other order; an empty place is a no-op.
        k.reply_saved(1, [21, 0, 0, 0]).unwrap();
        assert_eq!(k.thread(OTHER).msg[0], 21);
        assert_eq!(k.thread(OTHER).state, State::Ready);
        k.reply_saved(1, [99, 0, 0, 0]).unwrap();
        assert_eq!(k.thread(OTHER).msg[0], 21);
        k.reply_saved(0, [11, 0, 0, 0]).unwrap();
        assert_eq!(k.thread(CLIENT).msg[0], 11);
        assert_eq!(k.reply_saved(SAVED_CALLERS, [0; 4]), Err(IpcError::BadIndex));
        k.check_invariants().unwrap();
    }

    #[test]
    fn saved_callers_learn_their_server_is_gone() {
        let mut k = K::new();
        k.spawn(CLIENT, 1).unwrap();
        k.spawn(OTHER, 1).unwrap();
        k.spawn(SERVER, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap();
        k.call(EP, 1, [0; 4]).unwrap();
        k.save_caller().unwrap();
        k.recv(EP, true).unwrap();
        k.call(EP, 2, [0; 4]).unwrap();
        k.save_caller().unwrap();
        // A saved caller stopped meanwhile is forgotten: no reply reaches
        // it when it is started again and calls once more.
        k.suspend(OTHER).unwrap();
        k.check_invariants().unwrap();
        k.destroy(SERVER).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::PeerRestarted.code());
        assert_ne!(k.thread(CLIENT).state, State::BlockedReply);
        assert_eq!(k.thread(OTHER).state, State::Inactive);
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_suspended_server_abandons_its_saved_callers() {
        let mut k = K::new();
        k.spawn(CLIENT, 1).unwrap();
        k.spawn(SERVER, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap();
        k.call(EP, 1, [0; 4]).unwrap();
        k.save_caller().unwrap();
        k.suspend(SERVER).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
        k.check_invariants().unwrap();
    }

    #[test]
    fn second_call_before_reply_abandons_the_first() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.spawn(SERVER, 1).unwrap();
        k.schedule();
        k.call(EP, 1, [0; 4]).unwrap();
        k.call(EP, 2, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.recv(EP, true).unwrap(); // owes CLIENT
        k.recv(EP, true).unwrap(); // takes OTHER without replying to CLIENT
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
        // The abandoned caller outranks the server, so it runs at once.
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(SERVER).state, State::Ready);
        assert_eq!(k.thread(OTHER).state, State::BlockedReply);
    }

    #[test]
    fn reply_without_caller_is_noop() {
        let mut k = K::new();
        k.spawn(SERVER, 1).unwrap();
        k.schedule();
        k.reply([1; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
    }

    #[test]
    fn spawn_of_a_higher_priority_thread_preempts() {
        let mut k = server_waiting(); // server 10 waiting, client 5 running
        k.spawn(OTHER, 20).unwrap();
        assert_eq!(k.current(), Some(OTHER), "starting a thread is a wakeup");
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        // The preempted client resumes first among its level once OTHER blocks.
        k.wait(1).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
    }

    #[test]
    fn notifications_accumulate_and_wake() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(SERVER, 1).unwrap();
        k.schedule();
        k.signal(0, 0b001).unwrap();
        k.signal(0, 0b100).unwrap();
        k.wait(0).unwrap(); // bits pending: returns at once
        assert_eq!(k.thread(CLIENT).badge, 0b101);
        k.wait(0).unwrap(); // nothing pending: blocks
        assert_eq!(k.current(), Some(SERVER));
        k.signal(0, 0b010).unwrap();
        assert_eq!(k.current(), Some(CLIENT)); // woken, preempts
        assert_eq!(k.thread(CLIENT).badge, 0b010);
    }

    #[test]
    fn bound_notification_wakes_a_receiving_server() {
        let mut k = server_waiting();
        k.bind_notification(SERVER, 1).unwrap();
        // Blocked in Recv: a signal takes it off the endpoint and wakes it.
        k.signal(1, 0b10).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.thread(SERVER).badge, 0b10);
        assert_eq!(k.thread(SERVER).status, Error::Notified.code());
        // The endpoint no longer holds it: a call queues, and the next Recv
        // takes it as an ordinary message.
        k.recv(EP, true).unwrap();
        k.call(EP, 7, [1, 2, 3, 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.thread(SERVER).msg, [1, 2, 3, 4]);
        assert_eq!(k.thread(SERVER).badge, 7);
    }

    #[test]
    fn pending_bound_bits_come_before_queued_callers() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.bind_notification(SERVER, 1).unwrap();
        k.signal(1, 0b1).unwrap();
        k.signal(1, 0b100).unwrap();
        // Bits pending: Recv returns at once, coalesced.
        assert_eq!(k.recv(EP, true), Err(IpcError::Notified));
        assert_eq!(k.thread(SERVER).badge, 0b101);
        // Then it blocks; the client calls; ReplyRecv with bits pending
        // replies and returns at once again.
        k.recv(EP, true).unwrap();
        k.call(EP, 3, [9, 0, 0, 0]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.signal(1, 0b1000).unwrap();
        assert_eq!(k.reply_recv(EP, [5, 0, 0, 0]), Err(IpcError::Notified));
        assert_eq!(k.thread(SERVER).badge, 0b1000);
        assert_eq!(k.thread(CLIENT).msg[0], 5);
        assert_eq!(k.thread(CLIENT).state, State::Ready);
    }

    #[test]
    fn binding_is_one_to_one_and_ends_with_either_side() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        k.bind_notification(SERVER, 1).unwrap();
        assert_eq!(k.bind_notification(SERVER, 2), Err(IpcError::AlreadyBound));
        assert_eq!(k.bind_notification(CLIENT, 1), Err(IpcError::AlreadyBound));
        k.destroy_notification(1).unwrap();
        k.bind_notification(CLIENT, 1).unwrap();
        k.suspend(CLIENT).unwrap();
        k.reset_thread(CLIENT).unwrap();
        k.bind_notification(SERVER, 1).unwrap();
        // Unbound now: a plain Wait on it still works for others.
        k.signal(2, 1).unwrap();
        assert_eq!(k.thread(SERVER).state, State::Running);
    }

    #[test]
    fn deadlock_leaves_no_current() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap();
        assert_eq!(k.current(), None);
        assert_eq!(k.call(EP, 0, [0; 4]), Err(IpcError::NoCurrent));
    }

    #[test]
    fn bad_arguments() {
        let mut k = K::new();
        assert_eq!(k.spawn(99, 1), Err(IpcError::BadThread));
        assert_eq!(k.spawn(0, 64), Err(IpcError::BadPriority));
        k.spawn(0, 1).unwrap();
        assert_eq!(k.spawn(0, 1), Err(IpcError::ThreadActive));
        k.schedule();
        assert_eq!(k.send(99, 0, [0; 4], true), Err(IpcError::BadObject));
        assert_eq!(k.wait(99), Err(IpcError::BadObject));
    }
    #[test]
    fn tick_rotates_equal_priority_threads_after_slice() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(CLIENT));
        for _ in 1..TIMESLICE_TICKS {
            assert!(!k.tick(), "slice not used up yet");
            assert_eq!(k.current(), Some(CLIENT));
        }
        assert!(k.tick());
        assert_eq!(k.current(), Some(OTHER));
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        for _ in 0..TIMESLICE_TICKS {
            k.tick();
        }
        assert_eq!(k.current(), Some(CLIENT), "round robin comes back");
    }

    #[test]
    fn tick_never_hands_cpu_to_lower_priority() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        for _ in 0..10 * TIMESLICE_TICKS {
            assert!(!k.tick());
            assert_eq!(k.current(), Some(SERVER));
        }
    }

    #[test]
    fn tick_with_nothing_running_is_harmless() {
        let mut k = K::new();
        assert!(!k.tick());
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        for _ in 0..5 {
            assert!(!k.tick(), "alone: keeps running");
        }
        assert_eq!(k.current(), Some(CLIENT));
    }
    #[test]
    fn signal_irq_wakes_waiter_when_idle() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.wait(0).unwrap();
        assert_eq!(k.current(), None, "everyone blocked: idle");
        k.signal_irq(0, 0b1).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).badge, 0b1);
        assert_eq!(k.thread(CLIENT).status, 0);
    }

    #[test]
    fn signal_irq_preempts_lower_priority_only() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.wait(0).unwrap(); // server waits; client runs
        assert_eq!(k.current(), Some(CLIENT));
        k.signal_irq(0, 1).unwrap();
        assert_eq!(k.current(), Some(SERVER), "higher priority preempts");
        assert_eq!(k.thread(CLIENT).state, State::Ready);
    }

    #[test]
    fn signal_irq_does_not_preempt_for_lower_priority() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.wait(0).unwrap(); // client waits; idle
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        k.signal_irq(0, 1).unwrap();
        assert_eq!(k.current(), Some(SERVER), "lower-priority waiter queues");
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        assert_eq!(k.thread(CLIENT).badge, 1);
    }

    #[test]
    fn signal_irq_without_waiter_accumulates_bits() {
        let mut k = K::new();
        k.signal_irq(0, 0b01).unwrap();
        k.signal_irq(0, 0b10).unwrap();
        assert_eq!(k.current(), None);
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.wait(0).unwrap();
        assert_eq!(k.current(), Some(CLIENT), "bits pending: no block");
        assert_eq!(k.thread(CLIENT).badge, 0b11);
    }
    fn xfer(grant: Option<u16>, accept: Option<u16>) -> CapTransfer {
        CapTransfer { grant, accept }
    }

    fn tr(from: Tid, grant: u16, to: Tid, accept: u16) -> Option<Transfer> {
        Some(Transfer {
            from,
            grant,
            to,
            accept,
        })
    }

    #[test]
    fn call_and_reply_record_transfers() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.set_transfer(xfer(None, Some(4)));
        k.recv(0, true).unwrap();
        k.set_transfer(xfer(Some(2), Some(9)));
        k.call(0, 0, [1, 0, 0, 0]).unwrap();
        assert_eq!(k.take_transfers(), [tr(CLIENT, 2, SERVER, 4), None]);
        assert_eq!(k.take_transfers(), [None, None], "drained");

        // The reply grants into the slot the caller named at call time.
        k.set_transfer(xfer(Some(7), None));
        k.reply([0; 4]).unwrap();
        assert_eq!(k.take_transfers(), [tr(SERVER, 7, CLIENT, 9), None]);
    }

    #[test]
    fn queued_sender_grant_is_delivered_at_receive() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.set_transfer(xfer(Some(3), None));
        k.send(0, 0, [0; 4], true).unwrap(); // no receiver: blocks
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        k.set_transfer(xfer(None, Some(5)));
        k.recv(0, true).unwrap();
        assert_eq!(k.take_transfers(), [tr(CLIENT, 3, SERVER, 5), None]);
    }

    #[test]
    fn no_transfer_unless_both_sides_agree() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.set_transfer(CapTransfer::NONE); // server accepts nothing
        k.recv(0, true).unwrap();
        k.set_transfer(xfer(Some(2), None)); // client accepts nothing back
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.take_transfers(), [None, None]);
        k.set_transfer(xfer(Some(5), None));
        k.reply([0; 4]).unwrap();
        assert_eq!(k.take_transfers(), [None, None]);
    }

    #[test]
    fn reply_recv_records_reply_and_receive_transfers() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.schedule();
        // Both call before the server exists, so both queue on the endpoint.
        k.set_transfer(xfer(Some(1), Some(8)));
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(OTHER));
        k.set_transfer(xfer(Some(2), Some(3)));
        k.call(0, 0, [0; 4]).unwrap();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        k.set_transfer(xfer(None, Some(4)));
        k.recv(0, true).unwrap();
        assert_eq!(k.take_transfers(), [tr(CLIENT, 1, SERVER, 4), None]);
        // Reply to CLIENT (into its slot 8), then take OTHER's call.
        k.set_transfer(xfer(Some(6), Some(5)));
        k.reply_recv(0, [0; 4]).unwrap();
        assert_eq!(
            k.take_transfers(),
            [tr(SERVER, 6, CLIENT, 8), tr(OTHER, 2, SERVER, 5)]
        );
    }

    #[test]
    fn delivery_clears_previous_cap_received() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(0, true).unwrap();
        k.set_cap_received(SERVER, Some(3));
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.thread(SERVER).cap_received, None);
    }
    #[test]
    fn budget_throttles_then_refills_and_preempts() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(SERVER, 2, 5).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        assert!(!k.tick()); // 1 of 2 used
        assert!(k.tick(), "budget gone: throttled");
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: SERVER });
        assert_eq!(k.stats.throttles, 1);
        // The ticks that began at 0 and 1 come back at 5 and 6.
        assert_eq!(
            k.sched_context(SERVER).refills(),
            [Refill { release: 5, amount: 1 }, Refill { release: 6, amount: 1 }]
        );
        for _ in 3..=4 {
            assert!(!k.tick());
        }
        assert!(k.tick(), "tick 5: one tick back, higher priority preempts");
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.budget_left(SERVER), 1);
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        assert!(!k.tick(), "tick 6: the second tick is back as the first is used");
        assert!(k.tick(), "tick 7: both used again, throttled until 10");
        assert_eq!(k.current(), Some(CLIENT));
    }

    /// Runs `k` for `ticks` ticks and returns at which ticks `t` was charged.
    fn charged_at(k: &mut K, t: Tid, ticks: u64) -> Vec<u64> {
        let mut at = Vec::new();
        for _ in 0..ticks {
            let before = k.sched_context(t).consumed;
            k.tick();
            k.check_invariants().unwrap();
            if k.sched_context(t).consumed != before {
                at.push(k.now());
            }
        }
        at
    }

    /// No `period` ticks hold more than `budget` charges.
    fn assert_window(at: &[u64], budget: usize, period: u64) {
        for (i, &c) in at.iter().enumerate() {
            let n = at[i..].iter().take_while(|&&x| x < c + period).count();
            assert!(n <= budget, "{n} charges in the {period} ticks from {c}: {at:?}");
        }
    }

    #[test]
    fn a_hog_gets_exactly_its_bandwidth_in_every_window() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(SERVER, 3, 10).unwrap();
        k.schedule();
        let at = charged_at(&mut k, SERVER, 100);
        assert_window(&at, 3, 10);
        assert_eq!(at.len(), 30, "the full budget every period: {at:?}");
    }

    #[test]
    fn no_double_budget_across_a_period_boundary() {
        // Periodic refills let a thread that wakes late in a period use its
        // budget, then the next period's at once: 4 ticks in a row here.
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(SERVER, 2, 10).unwrap();
        k.schedule();
        k.wait(0).unwrap(); // the server sleeps
        for _ in 0..7 {
            k.tick();
        }
        k.signal(0, 1).unwrap(); // and wakes at tick 7, near the boundary
        assert_eq!(k.current(), Some(SERVER));
        let at = charged_at(&mut k, SERVER, 30);
        assert_eq!(&at[..4], [8, 9, 18, 19], "two ticks, then a period off");
        assert_window(&at, 2, 10);
    }

    #[test]
    fn a_full_refill_ring_only_delays_budget() {
        // Short runs spread over time give every charged tick its own
        // release, more than the ring holds.
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(SERVER, 20, 100).unwrap();
        k.schedule();
        let mut at = Vec::new();
        for _ in 0..300 {
            let running = k.current() == Some(SERVER);
            let before = k.sched_context(SERVER).consumed;
            k.tick();
            if k.sched_context(SERVER).consumed != before {
                at.push(k.now());
            }
            if running && k.current() == Some(SERVER) {
                k.wait(0).unwrap(); // one tick, then sleep
            } else if !running && k.now() % 3 == 0 {
                k.signal(0, 1).unwrap();
            }
            k.check_invariants().unwrap();
            assert!(k.sched_context(SERVER).refills().len() <= MAX_REFILLS);
        }
        assert_window(&at, 20, 100);
        assert!(at.len() >= 40, "still runs: {}", at.len());
    }

    /// A passive server (0, prio 10) on EP 0 with a timeout handler (2,
    /// prio 12, waiting on EP 1); the client (1) has a 1-tick budget in 10
    /// and has just called the server, which now runs on that budget.
    fn server_with_timeout_handler() -> K {
        let mut k = K::new();
        k.spawn(OTHER, 12).unwrap();
        k.schedule();
        k.recv(1, true).unwrap(); // the handler waits
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(CLIENT, 1, 10).unwrap();
        k.schedule();
        k.make_passive().unwrap();
        k.set_timeout_handler(SERVER, Some((1, 0x7E))).unwrap();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.active_sc(SERVER), Some(CLIENT));
        k
    }

    #[test]
    fn a_lent_budget_running_dry_calls_the_timeout_handler() {
        let mut k = server_with_timeout_handler();
        k.tick();
        k.check_invariants().unwrap();
        assert_eq!(k.take_timeout(), Some(SERVER));
        assert_eq!(k.take_timeout(), None, "reported once");
        assert_eq!(k.stats.timeouts, 1);
        assert_eq!(k.stats.throttles, 0, "not throttled");
        assert_eq!(k.current(), Some(OTHER), "the handler runs");
        let h = k.thread(OTHER);
        assert_eq!(h.msg, [FaultKind::Timeout as u64, 1, 10, 0]);
        assert_eq!(h.badge, 0x7E);
        assert_eq!(k.thread(SERVER).state, State::BlockedReply);
        assert_eq!(k.thread(CLIENT).state, State::BlockedReply, "still served");
        // Retry: the server keeps the client's budget and waits for it.
        k.reply_recv(1, [0; 4]).unwrap();
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: CLIENT });
        while k.now() < 9 {
            k.tick();
        }
        assert_eq!(k.current(), None);
        k.tick();
        assert_eq!(k.current(), Some(SERVER), "back at the client's refill");
        k.check_invariants().unwrap();
    }

    #[test]
    fn stopping_a_timed_out_server_fails_its_caller() {
        let mut k = server_with_timeout_handler();
        k.tick();
        assert_eq!(k.take_timeout(), Some(SERVER));
        // The kernel stops the server when the handler answers Stop.
        k.destroy(SERVER).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::PeerRestarted.code());
        k.check_invariants().unwrap();
    }

    #[test]
    fn running_out_of_its_own_budget_is_no_timeout() {
        let mut k = K::new();
        k.spawn(OTHER, 12).unwrap();
        k.schedule();
        k.recv(1, true).unwrap();
        k.spawn(SERVER, 10).unwrap();
        k.configure_sc(SERVER, 1, 10).unwrap();
        k.set_timeout_handler(SERVER, Some((1, 0x7E))).unwrap();
        k.schedule();
        k.tick();
        assert_eq!(k.take_timeout(), None);
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: SERVER });
    }

    #[test]
    fn a_destroyed_handler_endpoint_is_no_handler() {
        let mut k = server_with_timeout_handler();
        assert_eq!(k.set_timeout_handler(SERVER, Some((9, 0))), Err(IpcError::BadObject));
        k.destroy_endpoint(1).unwrap();
        assert_eq!(k.timeout_handler(SERVER), None);
        k.schedule();
        // The handler woke with an error and outranks the server; let it
        // block, then the server runs dry with nobody to call.
        k.wait(0).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.tick();
        assert_eq!(k.take_timeout(), None);
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: CLIENT });
    }

    #[test]
    fn configure_sc_rejects_bad_parameters() {
        let mut k = K::new();
        assert_eq!(k.configure_sc(CLIENT, 0, 5), Err(IpcError::BadSchedParams));
        assert_eq!(k.configure_sc(CLIENT, 6, 5), Err(IpcError::BadSchedParams));
        assert_eq!(k.configure_sc(100, 1, 5), Err(IpcError::BadThread));
        assert!(k.configure_sc(CLIENT, 5, 5).is_ok());
    }

    /// Server goes passive on its first receive; returns a kernel with the
    /// server blocked and the client current.
    fn passive_server(client_budget: u32, period: u32) -> K {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(CLIENT, client_budget, period).unwrap();
        k.schedule();
        k.make_passive().unwrap();
        k.recv(0, true).unwrap();
        assert!(k.thread(SERVER).passive);
        assert_eq!(k.active_sc(SERVER), None);
        assert_eq!(k.current(), Some(CLIENT));
        k
    }

    #[test]
    fn passive_server_runs_on_callers_budget() {
        let mut k = passive_server(3, 100);
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.active_sc(SERVER), Some(CLIENT), "lent by the caller");
        k.tick();
        assert_eq!(k.budget_left(CLIENT), 2, "charged to the client");
        assert_eq!(k.stats.donated_ticks, 1);
        k.reply_recv(0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.active_sc(SERVER), None, "returned on reply");
    }

    #[test]
    fn passive_server_is_throttled_with_the_lent_budget() {
        let mut k = passive_server(1, 4);
        k.call(0, 0, [0; 4]).unwrap();
        assert!(k.tick());
        assert_eq!(k.current(), None, "server out of the client's budget");
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: CLIENT });
        k.tick(); // 2
        k.tick(); // 3
        assert_eq!(k.current(), None);
        k.tick(); // 4: the tick that began at 0 is back
        assert_eq!(k.current(), Some(SERVER));
    }

    #[test]
    fn passive_server_parks_after_plain_reply() {
        let mut k = passive_server(10, 10);
        k.call(0, 0, [0; 4]).unwrap();
        k.reply([0; 4]).unwrap();
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.current(), Some(CLIENT));
    }

    #[test]
    fn send_to_passive_server_parks_it() {
        let mut k = passive_server(10, 10);
        k.send(0, 0, [7, 0, 0, 0], true).unwrap();
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.current(), Some(CLIENT));
    }

    #[test]
    fn make_passive_takes_effect_at_next_block() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        k.make_passive().unwrap();
        // Not blocked yet: still runs on its own context.
        assert!(!k.tick());
        assert_eq!(k.current(), Some(SERVER));
    }
    #[test]
    fn a_server_going_passive_runs_on_a_caller_already_queued() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(CLIENT, 2, 10).unwrap();
        // CLIENT calls before SERVER first receives (on another CPU, say).
        k.set_cpu(1);
        k.schedule();
        assert_eq!(k.current_on(1), Some(CLIENT));
        k.call(0, 1, [0; MSG_WORDS]).unwrap();
        k.set_cpu(0);
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        k.make_passive().unwrap();
        k.recv(0, true).unwrap();
        // It took the call without blocking, and runs on CLIENT's budget.
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.active_sc(SERVER), Some(CLIENT));
        k.tick();
        k.tick();
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: CLIENT });
        k.check_invariants().unwrap();
    }

    #[test]
    fn destroying_an_endpoint_wakes_its_queue_with_an_error() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 1).unwrap();
        k.schedule();
        k.recv(0, true).unwrap(); // server waits
        k.recv(1, true).unwrap(); // client waits on another endpoint
        assert_eq!(k.current(), Some(OTHER));
        k.destroy_endpoint(0).unwrap();
        assert_eq!(k.current(), Some(SERVER), "woken and preempts");
        assert_eq!(k.thread(SERVER).status, Error::ObjectDestroyed.code());
        assert_eq!(k.thread(CLIENT).state, State::BlockedRecv { ep: 1 });
        // The endpoint is usable afresh.
        k.recv(0, true).unwrap();
        assert_eq!(k.thread(SERVER).state, State::BlockedRecv { ep: 0 });
    }

    #[test]
    fn destroying_a_notification_wakes_waiters_and_drops_bits() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.wait(1).unwrap();
        assert_eq!(k.current(), None);
        k.destroy_notification(1).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).status, Error::ObjectDestroyed.code());
        k.signal(2, 0b1).unwrap();
        k.destroy_notification(2).unwrap();
        k.wait(2).unwrap();
        assert_eq!(k.current(), None, "pending bits were discarded");
    }
    #[test]
    fn suspend_current_stops_it_and_releases_its_caller() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.suspend_current();
        assert_eq!(k.thread(SERVER).state, State::Inactive);
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
        assert!(!k.tick() || k.current() == Some(CLIENT));
    }
    #[test]
    fn suspend_blocked_receiver_cancels_its_call() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(0, true).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        k.suspend(SERVER).unwrap();
        assert_eq!(k.thread(SERVER).state, State::Inactive);
        // The endpoint no longer has a receiver: a send is dropped.
        k.send(0, 0, [1, 0, 0, 0], false).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        // Resumed, the server returns from its receive with Interrupted.
        k.spawn(SERVER, 10).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.thread(SERVER).status, Error::Interrupted.code());
    }

    #[test]
    fn suspend_removes_from_the_middle_of_queues() {
        let mut k = K::new();
        k.spawn(SERVER, 5).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.schedule(); // SERVER runs; CLIENT, OTHER queued
        k.suspend(CLIENT).unwrap();
        k.yield_now().unwrap();
        assert_eq!(k.current(), Some(OTHER), "CLIENT skipped");
        k.yield_now().unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.yield_now().unwrap();
        assert_eq!(k.current(), Some(OTHER), "queue intact after removal");
    }

    #[test]
    fn suspend_running_and_ready_threads() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.suspend(SERVER).unwrap(); // the current thread
        assert_eq!(k.current(), Some(CLIENT));
        k.suspend(CLIENT).unwrap();
        assert_eq!(k.current(), None);
        assert_eq!(k.thread(CLIENT).status, 0, "not blocked: result kept");
        assert_eq!(k.suspend(CLIENT), Ok(()), "already inactive");
    }

    #[test]
    fn reply_to_a_suspended_caller_is_dropped() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.spawn(OTHER, 1).unwrap();
        k.schedule();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap(); // client waits for the reply
        k.suspend(CLIENT).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::Interrupted.code());
        k.reply_recv(0, [9, 0, 0, 0]).unwrap();
        assert_eq!(k.thread(CLIENT).state, State::Inactive, "not woken");
        assert_eq!(k.current(), Some(OTHER));
    }

    #[test]
    fn suspending_a_server_abandons_its_caller() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.suspend(SERVER).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
    }

    #[test]
    fn destroying_a_server_fails_its_caller_with_peer_restarted() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap(); // the server waits
        k.call(EP, 7, [1, 2, 3, 4]).unwrap(); // the client calls; the server has it
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.caller_of(SERVER), Some(CLIENT));
        k.destroy(SERVER).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::PeerRestarted.code());
        assert_eq!(k.current(), Some(CLIENT));
        // A suspended (not destroyed) server still means ReplyAbandoned.
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap();
        k.call(EP, 7, [0; 4]).unwrap();
        k.suspend(SERVER).unwrap();
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
    }

    #[test]
    fn a_crashed_server_fails_its_caller_with_peer_restarted() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.recv(EP, true).unwrap();
        k.call(EP, 7, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.crash_current();
        assert_eq!(k.thread(SERVER).state, State::Inactive);
        assert_eq!(k.thread(CLIENT).status, Error::PeerRestarted.code());
        assert_eq!(k.current(), Some(CLIENT));
    }

    #[test]
    fn reset_thread_needs_inactive_and_leaves_contexts_alone() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(CLIENT, 1, 4).unwrap();
        k.bind_sc(CLIENT, Some(OTHER)).unwrap();
        assert_eq!(k.reset_thread(CLIENT), Err(IpcError::ThreadActive));
        k.schedule();
        k.suspend(CLIENT).unwrap();
        k.reset_thread(CLIENT).unwrap();
        assert_eq!(k.sched_context(CLIENT).budget, Some(1), "contexts outlive threads");
        assert_eq!(k.bound_sc(CLIENT), Some(CLIENT), "bound to its own index again");
        assert_eq!(k.thread(CLIENT).state, State::Inactive);
    }

    #[test]
    fn threads_sharing_a_context_share_its_budget() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(OTHER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(SERVER, 2, 10).unwrap();
        k.bind_sc(OTHER, Some(SERVER)).unwrap();
        k.schedule();
        let mut ran = 0;
        for _ in 0..100 {
            let c = k.current();
            k.tick();
            k.check_invariants().unwrap();
            if c == Some(SERVER) || c == Some(OTHER) {
                ran += 1;
            }
        }
        assert_eq!(ran, 20, "2 ticks in 10 between them, not each");
        assert_eq!(k.sched_context(SERVER).consumed, 20);
    }

    #[test]
    fn a_thread_bound_to_no_context_or_an_empty_one_cannot_run() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        assert_eq!(k.current(), Some(SERVER));
        k.bind_sc(SERVER, None).unwrap();
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.current(), Some(CLIENT));
        k.empty_sc(OTHER).unwrap();
        k.bind_sc(SERVER, Some(OTHER)).unwrap();
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: OTHER });
        k.tick();
        assert_eq!(k.current(), Some(CLIENT), "an empty context never refills");
        k.configure_sc(OTHER, 3, 6).unwrap();
        assert_eq!(k.current(), Some(SERVER), "configured: it runs and preempts");
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_passive_server_lent_an_emptied_context_stops() {
        // SERVER (passive) waits; OTHER calls it on CPU 0 and it runs.
        let mut k = passive_server(5, 10);
        k.spawn(OTHER, 7).unwrap();
        assert_eq!(k.current(), Some(OTHER));
        k.call(0, 1, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        // Meanwhile CLIENT calls on CPU 1 and waits in the queue, and its
        // context is emptied while it waits.
        k.set_cpu(1);
        k.schedule();
        assert_eq!(k.current(), Some(CLIENT));
        k.call(0, 2, [0; 4]).unwrap();
        assert!(matches!(k.thread(CLIENT).state, State::BlockedSend { .. }));
        k.empty_sc(CLIENT).unwrap();
        // SERVER answers OTHER and takes CLIENT's call on an empty loan:
        // it may not run on it.
        k.set_cpu(0);
        k.reply_recv(0, [0; 4]).unwrap();
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: CLIENT });
        assert_eq!(k.current(), Some(OTHER));
        k.check_invariants().unwrap();
        // Given budget again, it runs on it.
        k.configure_sc(CLIENT, 2, 10).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.check_invariants().unwrap();
    }

    #[test]
    fn destroying_a_context_unbinds_its_threads() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(OTHER, 8).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.bind_sc(OTHER, Some(SERVER)).unwrap();
        k.schedule();
        k.destroy_sc(SERVER).unwrap();
        assert_eq!(k.bound_sc(SERVER), None);
        assert_eq!(k.bound_sc(OTHER), None);
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.thread(OTHER).state, State::NoSchedContext);
        assert_eq!(k.current(), Some(CLIENT));
        k.bind_sc(OTHER, Some(CLIENT)).unwrap();
        assert_eq!(k.current(), Some(OTHER), "rebound, it runs again");
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_context_running_dry_stops_its_threads_on_every_cpu() {
        let mut k = two_cpus();
        // CPU 0 runs SERVER, CPU 1 runs CLIENT; both now share one tick.
        k.configure_sc(SERVER, 1, 10).unwrap();
        k.bind_sc(CLIENT, Some(SERVER)).unwrap();
        k.set_cpu(0);
        k.tick_cpu(true);
        assert_eq!(k.thread(SERVER).state, State::Throttled { sc: SERVER });
        assert_eq!(k.thread(CLIENT).state, State::Throttled { sc: SERVER });
        assert_eq!(k.current_on(1), Some(CLIENT), "kept by CPU 1 until it enters the kernel");
        assert!(k.needs_kick(1));
        k.set_cpu(1);
        k.reschedule();
        assert_eq!(k.current_on(1), None);
        k.check_invariants().unwrap();
    }
    // Regressions found by the simulation harness (crate::sim).

    #[test]
    fn a_reply_never_reaches_a_later_call_of_a_restarted_caller() {
        let mut k = K::new();
        k.spawn(SERVER, 3).unwrap();
        k.spawn(OTHER, 2).unwrap();
        k.spawn(CLIENT, 1).unwrap();
        k.schedule();
        k.recv(0, true).unwrap(); // SERVER waits on endpoint 0
        k.recv(1, true).unwrap(); // OTHER waits on endpoint 1
        k.call(0, 0, [1, 0, 0, 0]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.suspend(CLIENT).unwrap();
        k.spawn(CLIENT, 4).unwrap();
        assert_eq!(k.current(), Some(CLIENT));
        k.call(1, 0, [2, 0, 0, 0]).unwrap(); // now awaits OTHER's reply
        assert_eq!(k.current(), Some(SERVER));
        k.reply([99, 0, 0, 0]).unwrap(); // owed to nobody any more
        assert_eq!(k.thread(CLIENT).state, State::BlockedReply);
        assert_ne!(k.thread(CLIENT).msg[0], 99);
    }

    #[test]
    fn a_passive_server_taking_a_call_that_lends_nothing_stops() {
        let mut k = K::new();
        k.spawn(SERVER, 5).unwrap();
        k.spawn(CLIENT, 4).unwrap();
        k.spawn(OTHER, 3).unwrap();
        k.schedule();
        k.make_passive().unwrap();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap(); // SERVER runs on CLIENT's context
        assert_eq!(k.current(), Some(SERVER));
        k.wait(0).unwrap(); // SERVER blocks elsewhere, still owing CLIENT
        assert_eq!(k.current(), Some(OTHER));
        k.make_passive().unwrap();
        k.call(0, 0, [0; 4]).unwrap(); // OTHER goes passive as it blocks
        k.signal_irq(0, 1).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.recv(0, false).unwrap(); // takes OTHER's call, which lends nothing
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.current(), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).status, Error::ReplyAbandoned.code());
    }

    #[test]
    fn a_destroyed_callers_context_is_taken_back_from_its_server() {
        let mut k = K::new();
        k.spawn(SERVER, 5).unwrap();
        k.spawn(CLIENT, 4).unwrap();
        k.schedule();
        k.make_passive().unwrap();
        k.recv(0, true).unwrap();
        k.call(0, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(SERVER));
        k.destroy_sc(CLIENT).unwrap();
        assert_eq!(k.thread(SERVER).state, State::NoSchedContext);
        assert_eq!(k.current(), None);
    }

    // ---- several CPUs -----------------------------------------------------

    /// CPU 0 runs SERVER (prio 10), CPU 1 runs CLIENT (prio 5).
    #[test]
    fn a_preempted_thread_queues_on_the_cpu_it_ran_on() {
        let mut k = two_cpus();
        // CPU 1 runs CLIENT; OTHER (prio 8) made on CPU 1 preempts it.
        k.spawn(OTHER, 8).unwrap();
        assert_eq!(k.current_on(1), Some(OTHER));
        assert_eq!(k.queued_on(CLIENT), Some(1), "back on CPU 1's queue");
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_cpu_runs_its_own_thread_before_an_equal_one_queued_elsewhere() {
        let mut k = K::new();
        // Two prio-5 threads, made on CPU 0 and on CPU 1, both queued
        // behind SERVER on CPU 0 and CLIENT on CPU 1.
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        k.spawn(OTHER, 5).unwrap();
        k.set_cpu(1);
        k.spawn(CLIENT, 10).unwrap();
        k.schedule();
        k.spawn(3, 5).unwrap();
        assert_eq!(k.queued_on(OTHER), Some(0));
        assert_eq!(k.queued_on(3), Some(1));
        // CLIENT blocks: CPU 1 takes its own 3, though OTHER queued first.
        k.recv(EP, true).unwrap();
        assert_eq!(k.current_on(1), Some(3));
        assert_eq!(k.queued_on(OTHER), Some(0));
        assert_eq!(k.stats.migrations, 0);
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_cpu_takes_a_higher_thread_from_another_cpus_queue() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        k.spawn(OTHER, 7).unwrap();
        k.set_cpu(1);
        k.spawn(CLIENT, 10).unwrap();
        k.schedule();
        k.spawn(3, 5).unwrap();
        // CPU 1's own 3 is prio 5; CPU 0's OTHER, 7, goes first.
        k.recv(EP, true).unwrap();
        assert_eq!(k.current_on(1), Some(OTHER), "the highest ready runs");
        assert_eq!(k.stats.migrations, 1);
        k.check_invariants().unwrap();
        // It now lives on CPU 1: preempted there, it queues there.
        k.spawn(4, 9).unwrap();
        assert_eq!(k.queued_on(OTHER), Some(1));
        k.check_invariants().unwrap();
    }

    #[test]
    fn eight_cpus_run_the_eight_highest_threads() {
        let mut k = Ipc::<16, 4, 4>::new();
        for t in 0..12u16 {
            k.set_cpu(t as usize % 2);
            k.spawn(t, 1 + t as u8).unwrap();
        }
        for cpu in 0..MAX_CPUS {
            k.set_cpu(cpu);
            k.schedule();
            k.check_invariants().unwrap();
        }
        let mut running: Vec<Tid> = (0..MAX_CPUS).filter_map(|x| k.current_on(x)).collect();
        running.sort();
        assert_eq!(running, (4..12).collect::<Vec<Tid>>());
        for t in 0..4 {
            assert!(k.queued_on(t).is_some(), "the four lowest wait");
        }
    }

    #[test]
    fn a_thread_pinned_elsewhere_waits_for_its_cpu() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        // OTHER, pinned to CPU 1, outranks nothing CPU 0 could leave it to.
        k.spawn(OTHER, 12).unwrap();
        assert_eq!(k.current(), Some(OTHER));
        k.set_affinity(OTHER, Some(1)).unwrap();
        assert_eq!(k.current(), Some(SERVER), "CPU 0 lets it go");
        assert_eq!(k.queued_on(OTHER), Some(1));
        assert!(k.needs_kick(1));
        assert!(!k.needs_kick(0));
        k.check_invariants().unwrap();
        k.set_cpu(1);
        k.schedule();
        assert_eq!(k.current_on(1), Some(OTHER));
        // Blocked and woken on CPU 0, it still queues for CPU 1 alone.
        k.recv(EP, true).unwrap();
        k.set_cpu(0);
        k.send(EP, 0, [0; MSG_WORDS], true).unwrap();
        assert_eq!(k.current_on(0), Some(SERVER));
        assert_eq!(k.queued_on(OTHER), Some(1));
        k.check_invariants().unwrap();
        // Unpinned, CPU 0 takes it (it outranks SERVER).
        k.set_affinity(OTHER, None).unwrap();
        k.reschedule();
        assert_eq!(k.current_on(0), Some(OTHER));
        k.check_invariants().unwrap();
    }

    #[test]
    fn pinning_a_thread_running_elsewhere_stops_it_there() {
        let mut k = two_cpus();
        // From CPU 0, pin CPU 1's CLIENT to CPU 0: CPU 1 keeps it until
        // it settles, and CPU 0 may not run it before then.
        k.set_cpu(0);
        k.set_affinity(CLIENT, Some(0)).unwrap();
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        assert!(k.needs_kick(1));
        k.check_invariants().unwrap();
        k.set_cpu(1);
        k.reschedule();
        assert_eq!(k.current_on(1), None, "nothing else CPU 1 may run");
        k.set_cpu(0);
        k.suspend(SERVER).unwrap();
        assert_eq!(k.current_on(0), Some(CLIENT));
        k.check_invariants().unwrap();
        // A pin survives suspension: resumed on CPU 1, it queues for 0.
        k.suspend(CLIENT).unwrap();
        k.set_cpu(1);
        k.spawn(CLIENT, 5).unwrap();
        assert_eq!(k.current_on(1), None);
        assert_eq!(k.queued_on(CLIENT), Some(0));
        k.reset_thread(SERVER).unwrap();
        k.suspend(CLIENT).unwrap();
        k.reset_thread(CLIENT).unwrap();
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_yield_hands_the_turn_to_a_peer_queued_on_another_cpu() {
        let mut k = two_cpus();
        // CPU 0's SERVER blocks and a prio-5 thread, 3, runs there; OTHER,
        // CLIENT's peer (prio 5), queues behind it on CPU 1.
        k.set_cpu(0);
        k.recv(EP, true).unwrap();
        k.spawn(3, 5).unwrap();
        k.schedule();
        assert_eq!(k.current_on(0), Some(3));
        k.set_cpu(1);
        k.spawn(OTHER, 5).unwrap();
        assert_eq!(k.queued_on(OTHER), Some(1));
        // 3 yields: OTHER runs on CPU 0.
        k.set_cpu(0);
        k.yield_now().unwrap();
        assert_eq!(k.current_on(0), Some(OTHER), "the peer takes the turn");
        assert_eq!(k.queued_on(3), Some(0));
        k.check_invariants().unwrap();
        // Alone at its level, a yielder goes on.
        k.yield_now().unwrap();
        assert_eq!(k.current_on(0), Some(3));
        k.yield_now().unwrap();
        assert_eq!(k.current_on(0), Some(OTHER));
        k.check_invariants().unwrap();
    }

    #[test]
    fn equal_threads_take_turns_on_every_cpu() {
        let mut k = two_cpus();
        // SERVER drops to CLIENT's prio 5 by blocking; OTHER (prio 5)
        // runs on CPU 0, and 3 (prio 5) queues behind CLIENT on CPU 1.
        k.set_cpu(0);
        k.recv(EP, true).unwrap();
        k.spawn(OTHER, 5).unwrap();
        k.schedule();
        k.set_cpu(1);
        k.spawn(3, 5).unwrap();
        assert_eq!(k.queued_on(3), Some(1));
        // CPU 0's slice ends: 3, waiting on CPU 1's queue, takes the turn.
        k.set_cpu(0);
        for _ in 0..TIMESLICE_TICKS {
            k.tick();
        }
        k.schedule();
        assert_eq!(k.current_on(0), Some(3));
        assert_eq!(k.queued_on(OTHER), Some(0));
        k.check_invariants().unwrap();
        // CPU 1's slice ends: OTHER, now waiting longest, runs there.
        k.set_cpu(1);
        for _ in 0..TIMESLICE_TICKS {
            k.tick();
        }
        k.schedule();
        assert_eq!(k.current_on(1), Some(OTHER));
        assert_eq!(k.queued_on(CLIENT), Some(1));
        k.check_invariants().unwrap();
    }

    fn two_cpus() -> K {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.spawn(CLIENT, 5).unwrap();
        k.schedule();
        k.set_cpu(1);
        k.schedule();
        assert_eq!(k.current_on(0), Some(SERVER));
        assert_eq!(k.current_on(1), Some(CLIENT));
        k.check_invariants().unwrap();
        k
    }

    #[test]
    fn each_cpu_runs_its_own_thread() {
        let mut k = two_cpus();
        // CPU 1's thread blocks; CPU 0's goes on.
        k.wait(1).unwrap();
        assert_eq!(k.current_on(1), None);
        assert_eq!(k.current_on(0), Some(SERVER));
        assert!(!k.needs_kick(0));
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_wakeup_outranking_another_cpus_thread_kicks_it() {
        let mut k = two_cpus();
        k.set_cpu(0);
        k.spawn(OTHER, 7).unwrap();
        // Below CPU 0's thread: queued, and CPU 1 (prio 5) should take it.
        assert_eq!(k.current_on(0), Some(SERVER));
        assert_eq!(k.thread(OTHER).state, State::Ready);
        assert!(k.needs_kick(1));
        k.set_cpu(1);
        k.reschedule();
        assert_eq!(k.current_on(1), Some(OTHER));
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        assert!(!k.needs_kick(1));
        k.check_invariants().unwrap();
    }

    #[test]
    fn an_idle_cpu_is_kicked_for_ready_work() {
        let mut k = K::new();
        k.spawn(SERVER, 10).unwrap();
        k.schedule();
        assert!(!k.needs_kick(1));
        k.spawn(CLIENT, 5).unwrap();
        assert!(k.needs_kick(1), "CPU 1 idles with CLIENT ready");
        k.set_cpu(1);
        k.reschedule();
        assert_eq!(k.current_on(1), Some(CLIENT));
    }

    #[test]
    fn a_thread_stopped_on_another_cpu_is_kept_there_until_it_settles() {
        let mut k = two_cpus();
        // CPU 0 suspends CPU 1's thread, then resumes it at once.
        k.set_cpu(0);
        k.suspend(CLIENT).unwrap();
        assert_eq!(k.current_on(1), Some(CLIENT), "its registers are still on CPU 1");
        assert_eq!(k.thread(CLIENT).state, State::Inactive);
        assert!(k.needs_kick(1));
        k.spawn(CLIENT, 5).unwrap();
        assert_eq!(k.thread(CLIENT).state, State::Ready);
        // Nobody else may run it before CPU 1 has let it go.
        k.set_cpu(2);
        k.schedule();
        assert_eq!(k.current_on(2), None);
        k.check_invariants().unwrap();
        // CPU 1 enters the kernel: drops it, and may then run it again.
        k.set_cpu(1);
        assert_eq!(k.settle(), Some(CLIENT));
        k.reschedule();
        assert_eq!(k.current_on(1), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).state, State::Running);
        k.check_invariants().unwrap();
    }

    #[test]
    fn a_thread_made_current_while_the_cpu_idled_is_let_go_if_stopped() {
        let mut k = two_cpus();
        // CPU 2 idles; an interrupt there wakes a waiter, which becomes its
        // thread before the CPU has loaded it.
        k.set_cpu(2);
        k.spawn(OTHER, 3).unwrap();
        k.schedule();
        assert_eq!(k.current_on(2), Some(OTHER));
        k.wait(1).unwrap();
        assert_eq!(k.current_on(2), None);
        k.signal_irq(1, 1).unwrap();
        assert_eq!(k.current_on(2), Some(OTHER));
        // CPU 0 stops it (its component is killed) before CPU 2 runs it.
        k.set_cpu(0);
        k.suspend(OTHER).unwrap();
        k.reset_thread(OTHER).unwrap();
        // CPU 2's next tick, signal or reschedule drops it: it must not be
        // queued to run again, nor charged.
        k.set_cpu(2);
        k.tick_cpu(false);
        assert_eq!(k.current_on(2), None);
        assert_eq!(k.thread(OTHER).state, State::Inactive);
        k.reschedule();
        assert_eq!(k.thread(OTHER).state, State::Inactive);
        k.check_invariants().unwrap();
    }

    #[test]
    fn only_the_global_tick_advances_time() {
        let mut k = two_cpus();
        k.set_cpu(1);
        k.configure_sc(CLIENT, 1, 4).unwrap();
        k.tick_cpu(false);
        assert_eq!(k.thread(CLIENT).state, State::Throttled { sc: CLIENT });
        assert_eq!(k.current_on(1), None);
        for _ in 0..3 {
            k.tick_cpu(false);
        }
        assert_eq!(k.now, 0);
        assert_eq!(k.thread(CLIENT).state, State::Throttled { sc: CLIENT });
        k.set_cpu(0);
        for _ in 0..4 {
            k.tick_cpu(true);
        }
        assert_eq!(k.thread(CLIENT).state, State::Ready, "refilled by CPU 0's ticks");
        assert!(k.needs_kick(1));
    }

    #[test]
    fn a_call_from_one_cpu_runs_the_server_there() {
        let mut k = two_cpus();
        // SERVER (CPU 0) waits for calls; CLIENT (CPU 1) calls it.
        k.set_cpu(0);
        k.recv(EP, true).unwrap();
        assert_eq!(k.current_on(0), None);
        k.set_cpu(1);
        k.call(EP, 7, [1, 2, 3, 4]).unwrap();
        assert_eq!(k.current_on(1), Some(SERVER));
        assert_eq!(k.thread(SERVER).msg, [1, 2, 3, 4]);
        k.reply_recv(EP, [9, 0, 0, 0]).unwrap();
        assert_eq!(k.current_on(1), Some(CLIENT));
        assert_eq!(k.thread(CLIENT).msg[0], 9);
        k.check_invariants().unwrap();
    }
}
