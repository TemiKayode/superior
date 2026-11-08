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
//!   Scheduling contexts with budgets (MCS) come later and slot in at
//!   `switch_to`.
//!
//! Message delivery always fills `msg`, `badge` and `status` of the thread
//! being woken; the kernel copies them into that thread's registers.

use crate::abi::{Error, MSG_WORDS};

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
}

const IDLE_TCB: Tcb = Tcb {
    state: State::Inactive,
    prio: 0,
    msg: [0; MSG_WORDS],
    badge: 0,
    status: 0,
    caller: None,
    next: None,
    slice: TIMESLICE_TICKS,
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
        }
    }

    pub fn current(&self) -> Option<Tid> {
        self.current
    }

    pub fn thread(&self, t: Tid) -> &Tcb {
        &self.threads[t as usize]
    }

    /// Sets the status the current thread will see on return.
    pub fn set_status(&mut self, status: u64) {
        if let Some(c) = self.current {
            self.threads[c as usize].status = status;
        }
    }

    /// Makes an inactive thread runnable.
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
        self.make_ready(t);
        Ok(())
    }

    /// One timer tick. Charges the current thread; when its slice is used
    /// up, it is refilled and the thread rotates behind any ready thread
    /// of equal or higher priority. Returns true if the current thread changed.
    pub fn tick(&mut self) -> bool {
        let Some(c) = self.current else {
            return false;
        };
        let tcb = &mut self.threads[c as usize];
        if tcb.slice > 1 {
            tcb.slice -= 1;
            return false;
        }
        tcb.slice = TIMESLICE_TICKS;
        let prio = tcb.prio;
        match self.highest_ready() {
            Some(p) if p >= prio => {
                self.current = None;
                self.make_ready(c);
                self.schedule();
                self.current != Some(c)
            }
            _ => false,
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
            self.deliver(r, msg, badge);
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
            self.deliver(server, msg, badge);
            self.take_caller(server, cur);
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
            self.deliver(c, msg, 0);
            self.wake(c);
        }
        Ok(())
    }

    /// Reply then receive, the server's steady-state loop. When nothing is
    /// queued, the server blocks and control passes straight to the caller.
    pub fn reply_recv(&mut self, ep: u16, msg: [u64; MSG_WORDS]) -> Result<(), IpcError> {
        let cur = self.cur()?;
        let e = self.ep_index(ep)?;
        let caller = self.threads[cur as usize].caller.take();
        if let Some(c) = caller {
            self.deliver(c, msg, 0);
        }
        if self.eps[e].state == EpState::Sending {
            self.take_from_sender(cur, e);
            if let Some(c) = caller {
                self.wake(c);
            }
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

    fn deliver(&mut self, t: Tid, msg: [u64; MSG_WORDS], badge: u64) {
        let tcb = &mut self.threads[t as usize];
        tcb.msg = msg;
        tcb.badge = badge;
        tcb.status = 0;
    }

    /// Records that `server` owes `caller` a reply. If the server already
    /// owed someone, that earlier caller is woken with `ReplyAbandoned`
    /// rather than left blocked forever.
    fn take_caller(&mut self, server: Tid, caller: Tid) {
        if let Some(old) = self.threads[server as usize].caller.replace(caller) {
            self.threads[old as usize].status = Error::ReplyAbandoned.code();
            self.make_ready(old);
        }
    }

    /// `cur` receives from the first queued sender on endpoint `e`.
    fn take_from_sender(&mut self, cur: Tid, e: usize) {
        let s = self.dequeue_ep(e);
        let sender = self.threads[s as usize];
        self.deliver(cur, sender.msg, sender.badge);
        if let State::BlockedSend { call: true, .. } = sender.state {
            self.take_caller(cur, s);
            self.threads[s as usize].state = State::BlockedReply;
        } else {
            self.threads[s as usize].status = 0;
            self.wake(s);
        }
    }

    fn block_on_ep(&mut self, t: Tid, e: usize, state: State, ep_state: EpState) {
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

    fn make_ready(&mut self, t: Tid) {
        let p = self.threads[t as usize].prio as usize;
        self.threads[t as usize].state = State::Ready;
        self.ready[p].push_back(&mut self.threads, t);
        self.ready_bits |= 1 << p;
    }

    fn highest_ready(&self) -> Option<u8> {
        (self.ready_bits != 0).then(|| 63 - self.ready_bits.leading_zeros() as u8)
    }

    /// Makes `t` runnable; preempts the current thread if `t` outranks it.
    fn wake(&mut self, t: Tid) {
        self.make_ready(t);
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
        match self.highest_ready() {
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
    fn fast_path_yields_to_higher_priority_ready_thread() {
        let mut k = server_waiting(); // server 10 waiting, client 5 running
        k.spawn(OTHER, 20).unwrap(); // ready, but client keeps running (no preemption on spawn)
        k.call(EP, 0, [0; 4]).unwrap();
        assert_eq!(k.current(), Some(OTHER), "prio 20 beats the direct switch");
        assert_eq!(k.thread(SERVER).state, State::Ready);
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
}
