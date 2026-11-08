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
//! - Scheduling contexts (MCS, spec section 3): every thread owns one,
//!   unlimited unless configured with a budget per period. Budgets are
//!   charged per timer tick and refilled in full at each period boundary
//!   (periodic, not yet sporadic); a thread whose context runs dry is
//!   throttled until the refill.
//! - A passive server has given up its own context and runs only on its
//!   caller's, lent on `Call` and returned on reply, so time spent serving
//!   a client is charged to that client. A passive thread with no lent
//!   context cannot run: woken any other way (a `Send`, a signal), it is
//!   parked in [`State::NoSchedContext`].
//!
//! Message delivery always fills `msg`, `badge` and `status` of the thread
//! being woken; the kernel copies them into that thread's registers.
//!
//! Capability transfer: before each operation the kernel records the
//! current thread's [`CapTransfer`] (slot to grant, slot to accept into).
//! When a message moves from a sender that grants to a receiver that
//! accepts, delivery records a [`Transfer`]; the kernel drains them after
//! the operation with [`Ipc::take_transfers`], copies the capability
//! between CSpaces, and reports the outcome with [`Ipc::set_cap_received`].
//! CSpaces themselves are not this module's business.

use crate::abi::{CapTransfer, Error, MSG_WORDS};

pub type Tid = u16;
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

/// CPU time a thread may consume. Scheduling context `i` belongs to
/// thread `i`; a passive server borrows its caller's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedContext {
    /// Ticks per period; `None` is unlimited.
    pub budget: Option<u32>,
    pub period: u32,
    /// Ticks left in the current period.
    pub remaining: u32,
    /// Tick at which the budget is next refilled.
    pub next_refill: u64,
}

const UNLIMITED: SchedContext = SchedContext {
    budget: None,
    period: 0,
    remaining: 0,
    next_refill: 0,
};

impl SchedContext {
    fn exhausted(&self) -> bool {
        self.budget.is_some() && self.remaining == 0
    }
}

/// Scheduler counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedStats {
    /// Times a thread was stopped because its budget ran out.
    pub throttles: u64,
    /// Ticks charged to a context lent by a caller (a passive server ran).
    pub donated_ticks: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Tcb {
    pub state: State,
    pub prio: u8,
    pub msg: [u64; MSG_WORDS],
    pub badge: u64,
    /// Result of this thread's last completed operation (0 = ok).
    pub status: u64,
    /// For a server: the caller it owes a reply to.
    caller: Option<Tid>,
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

const IDLE_TCB: Tcb = Tcb {
    state: State::Inactive,
    prio: 0,
    msg: [0; MSG_WORDS],
    badge: 0,
    status: 0,
    caller: None,
    next: None,
    slice: TIMESLICE_TICKS,
    xfer: CapTransfer::NONE,
    cap_received: None,
    passive: false,
    passive_pending: false,
    lent: None,
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
}

impl IpcError {
    /// The status code reported to user space.
    pub const fn status(self) -> u64 {
        match self {
            IpcError::WouldBlock => Error::WouldBlock.code(),
            IpcError::BadObject => Error::InvalidCapability.code(),
            _ => Error::IllegalOperation.code(),
        }
    }
}

/// `T` threads, `E` endpoints, `N` notifications.
pub struct Ipc<const T: usize, const E: usize, const N: usize> {
    threads: [Tcb; T],
    eps: [Endpoint; E],
    ntfns: [Notification; N],
    ready: [Queue; PRIORITIES],
    /// Bit p set ⇔ ready[p] non-empty.
    ready_bits: u64,
    current: Option<Tid>,
    transfers: [Option<Transfer>; MAX_TRANSFERS],
    scs: [SchedContext; T],
    /// Timer ticks since boot.
    now: u64,
    pub stats: SchedStats,
}

impl<const T: usize, const E: usize, const N: usize> Default for Ipc<T, E, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const T: usize, const E: usize, const N: usize> Ipc<T, E, N> {
    pub const fn new() -> Self {
        Ipc {
            threads: [IDLE_TCB; T],
            eps: [Endpoint {
                state: EpState::Idle,
                queue: Queue::EMPTY,
            }; E],
            ntfns: [Notification {
                word: 0,
                waiters: Queue::EMPTY,
            }; N],
            ready: [Queue::EMPTY; PRIORITIES],
            ready_bits: 0,
            current: None,
            transfers: [None; MAX_TRANSFERS],
            scs: [UNLIMITED; T],
            now: 0,
            stats: SchedStats {
                throttles: 0,
                donated_ticks: 0,
            },
        }
    }

    pub fn current(&self) -> Option<Tid> {
        self.current
    }

    pub fn thread(&self, t: Tid) -> &Tcb {
        &self.threads[t as usize]
    }

    /// Records the capability transfer the current thread's next operation
    /// offers and accepts. The kernel calls this before every IPC operation.
    pub fn set_transfer(&mut self, xfer: CapTransfer) {
        if let Some(c) = self.current {
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

    /// Stops the current thread (it becomes inactive), e.g. after a fault
    /// nobody handles.
    pub fn suspend_current(&mut self) {
        if let Some(c) = self.current {
            let _ = self.suspend(c);
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
                self.current = None;
                false
            }
            State::Ready => {
                let p = self.threads[t as usize].prio as usize;
                self.ready[p].remove(&mut self.threads, t);
                if self.ready[p].is_empty() {
                    self.ready_bits &= !(1 << p);
                }
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
            State::BlockedReply => true,
            State::Throttled { .. } | State::NoSchedContext => false,
        };
        let tcb = &mut self.threads[t as usize];
        tcb.state = State::Inactive;
        tcb.lent = None;
        if blocked {
            tcb.status = Error::Interrupted.code();
        }
        if let Some(caller) = tcb.caller.take() {
            self.abandon(caller);
        }
        self.schedule();
        Ok(())
    }

    /// Clears an inactive thread's state (and scheduling context) so the
    /// table entry can be reused for a new thread.
    pub fn reset_thread(&mut self, t: Tid) -> Result<(), IpcError> {
        let tcb = self
            .threads
            .get_mut(t as usize)
            .ok_or(IpcError::BadThread)?;
        if tcb.state != State::Inactive {
            return Err(IpcError::ThreadActive);
        }
        *tcb = IDLE_TCB;
        self.scs[t as usize] = UNLIMITED;
        Ok(())
    }

    /// Wakes `caller` with `ReplyAbandoned` if it still waits for a reply.
    fn abandon(&mut self, caller: Tid) {
        if self.threads[caller as usize].state == State::BlockedReply {
            self.threads[caller as usize].status = Error::ReplyAbandoned.code();
            self.wake(caller);
        }
    }

    fn awaits_reply(&self, t: Tid) -> bool {
        self.threads[t as usize].state == State::BlockedReply
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
        self.schedule();
        Ok(())
    }

    /// Sets the status the current thread will see on return.
    pub fn set_status(&mut self, status: u64) {
        if let Some(c) = self.current {
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
        tcb.slice = TIMESLICE_TICKS;
        // Like any wakeup: a thread that outranks the running one takes over.
        self.wake(t);
        Ok(())
    }

    /// Gives thread `t`'s scheduling context `budget` ticks every `period`
    /// ticks, starting with a full budget now.
    pub fn configure_sc(&mut self, t: Tid, budget: u32, period: u32) -> Result<(), IpcError> {
        if t as usize >= T {
            return Err(IpcError::BadThread);
        }
        if budget == 0 || budget > period {
            return Err(IpcError::BadSchedParams);
        }
        self.scs[t as usize] = SchedContext {
            budget: Some(budget),
            period,
            remaining: budget,
            next_refill: self.now + period as u64,
        };
        Ok(())
    }

    pub fn sched_context(&self, sc: Tid) -> &SchedContext {
        &self.scs[sc as usize]
    }

    /// The current thread gives up its own scheduling context the next
    /// time it blocks, and from then on runs only on contexts its callers
    /// lend it.
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
        if tcb.passive { tcb.lent } else { Some(t) }
    }

    /// One timer tick: charges the tick to the current thread's scheduling
    /// context (throttling it if that empties the budget), refills contexts
    /// whose period has ended (waking threads throttled on them), then
    /// applies round-robin time slicing. Returns true if the current
    /// thread changed.
    pub fn tick(&mut self) -> bool {
        self.now += 1;
        let before = self.current;
        if let Some(c) = before {
            self.charge(c);
        }
        self.refill();
        if self.current.is_some() && self.current == before {
            self.rotate();
        }
        self.schedule();
        self.current != before
    }

    fn charge(&mut self, c: Tid) {
        let Some(sc) = self.active_sc(c) else {
            // Passive with nothing lent: may not run unaccounted.
            self.threads[c as usize].state = State::NoSchedContext;
            self.current = None;
            return;
        };
        if sc != c {
            self.stats.donated_ticks += 1;
        }
        let ctx = &mut self.scs[sc as usize];
        if ctx.budget.is_some() {
            ctx.remaining = ctx.remaining.saturating_sub(1);
            if ctx.remaining == 0 {
                self.threads[c as usize].state = State::Throttled { sc };
                self.current = None;
                self.stats.throttles += 1;
            }
        }
    }

    fn refill(&mut self) {
        let now = self.now;
        for ctx in self.scs.iter_mut() {
            if let Some(b) = ctx.budget
                && now >= ctx.next_refill
            {
                ctx.remaining = b;
                while ctx.next_refill <= now {
                    ctx.next_refill += ctx.period as u64;
                }
            }
        }
        for t in 0..T {
            if let State::Throttled { sc } = self.threads[t].state
                && !self.scs[sc as usize].exhausted()
            {
                self.wake(t as Tid);
            }
        }
    }

    /// Round robin: when the current thread's slice is used up it goes
    /// behind any ready thread of equal or higher priority.
    fn rotate(&mut self) {
        let Some(c) = self.current else { return };
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
            self.current = None;
            self.make_ready(c);
        }
    }

    /// Picks a thread if none is running. After every operation `current`
    /// is the thread to resume, or `None` if nothing is runnable.
    pub fn schedule(&mut self) {
        if self.current.is_some() {
            return;
        }
        if self.ready_bits == 0 {
            return;
        }
        let p = 63 - self.ready_bits.leading_zeros() as usize;
        let t = self.ready[p].pop(&mut self.threads).unwrap();
        if self.ready[p].is_empty() {
            self.ready_bits &= !(1 << p);
        }
        self.switch_to(t);
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
            self.current = None;
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
        if self.eps[e].state == EpState::Sending {
            self.take_from_sender(cur, e);
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
        if self.eps[e].state == EpState::Sending {
            self.take_from_sender(cur, e);
            self.park_if_no_sc(cur);
            if let Some(c) = caller {
                self.wake(c);
            }
            self.schedule();
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
            None => self.ntfns[n].word |= bits,
        }
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
            self.current = None;
            self.ntfns[n].waiters.push_back(&mut self.threads, cur);
            self.schedule();
        }
        Ok(())
    }

    pub fn yield_now(&mut self) -> Result<(), IpcError> {
        let cur = self.cur()?;
        self.threads[cur as usize].status = 0;
        self.current = None;
        self.make_ready(cur);
        self.schedule();
        Ok(())
    }

    // ---- internals ------------------------------------------------------

    fn cur(&self) -> Result<Tid, IpcError> {
        self.current.ok_or(IpcError::NoCurrent)
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
        if self.current == Some(t) {
            self.current = None;
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

    /// Stops the current thread `t` if it has no context to run on.
    fn park_if_no_sc(&mut self, t: Tid) {
        if self.current == Some(t) && self.active_sc(t).is_none() {
            self.threads[t as usize].state = State::NoSchedContext;
            self.current = None;
        }
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
            Some(sc) if self.scs[sc as usize].exhausted() => {
                self.threads[t as usize].state = State::Throttled { sc };
                return false;
            }
            Some(_) => {}
        }
        let p = self.threads[t as usize].prio as usize;
        self.threads[t as usize].state = State::Ready;
        self.ready[p].push_back(&mut self.threads, t);
        self.ready_bits |= 1 << p;
        true
    }

    fn highest_ready(&self) -> Option<u8> {
        (self.ready_bits != 0).then(|| 63 - self.ready_bits.leading_zeros() as u8)
    }

    /// Makes `t` runnable; preempts the current thread if `t` outranks it.
    fn wake(&mut self, t: Tid) {
        if !self.make_ready(t) {
            return;
        }
        if let Some(c) = self.current
            && self.threads[t as usize].prio > self.threads[c as usize].prio
        {
            // The preempted thread goes to the front of its level so it
            // resumes before peers that have not run.
            let p = self.threads[c as usize].prio as usize;
            self.threads[c as usize].state = State::Ready;
            self.ready[p].push_front(&mut self.threads, c);
            self.ready_bits |= 1 << p;
            self.current = None;
            self.schedule();
        }
    }

    /// Direct switch to `t` (fast path) unless a higher-priority thread is
    /// waiting, in which case `t` queues like anyone else.
    fn switch_or_schedule(&mut self, t: Tid) {
        debug_assert!(self.current.is_none());
        let runnable = self
            .active_sc(t)
            .is_some_and(|sc| !self.scs[sc as usize].exhausted());
        match self.highest_ready() {
            _ if !runnable => {
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
        self.threads[t as usize].state = State::Running;
        self.current = Some(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(k.ready_bits, 0, "fast path never touched the ready queues");
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
        assert_eq!(k.thread(CLIENT).state, State::Ready);
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
        assert!(!k.tick()); // tick 3
        assert!(!k.tick()); // tick 4
        assert!(k.tick(), "tick 5: refilled, higher priority preempts");
        assert_eq!(k.current(), Some(SERVER));
        assert_eq!(k.sched_context(SERVER).remaining, 2);
        assert_eq!(k.thread(CLIENT).state, State::Ready);
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
        assert_eq!(
            k.sched_context(CLIENT).remaining,
            2,
            "charged to the client"
        );
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
        k.tick(); // 4: refill
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
    fn reset_thread_needs_inactive_and_clears_budget() {
        let mut k = K::new();
        k.spawn(CLIENT, 5).unwrap();
        k.configure_sc(CLIENT, 1, 4).unwrap();
        assert_eq!(k.reset_thread(CLIENT), Err(IpcError::ThreadActive));
        k.schedule();
        k.suspend(CLIENT).unwrap();
        k.reset_thread(CLIENT).unwrap();
        assert_eq!(k.sched_context(CLIENT).budget, None);
        assert_eq!(k.thread(CLIENT).state, State::Inactive);
    }
}
