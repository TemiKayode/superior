//! A small executor for drivers: `async` tasks on the driver's one
//! thread, woken by events.
//!
//! A driver's work is several things going on at once on one thread: an
//! interrupt to answer, calls to serve, a request in flight waiting for
//! the device. Written as one loop, each of those is a piece of state
//! the loop must remember; written as tasks, each is straight-line code
//! that waits where it has to.
//!
//! Everything a task waits for is an event: a bit in [`Events`], posted
//! by whatever the driver blocks in when nothing can run (a `Recv` that
//! returns a call or the notification an interrupt signals). [`run`]
//! polls the tasks while any can go on and calls `idle` when none can;
//! `idle` blocks, and returns the events that woke it.
//!
//! There is no allocation and no waker: tasks are futures on `run`'s
//! caller's stack, and all of them are polled again whenever events
//! arrive, which is cheap for the handful a driver has.

use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// Events posted and not yet taken, and the ones tasks wait for.
pub struct Events {
    pending: Cell<u64>,
    wanted: Cell<u64>,
    /// How many waits found nothing: `run` tells a task that waits from
    /// one that only yielded by whether this moved.
    waits: Cell<u64>,
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl Events {
    pub const fn new() -> Events {
        Events {
            pending: Cell::new(0),
            wanted: Cell::new(0),
            waits: Cell::new(0),
        }
    }

    /// Posts events: tasks waiting for any of `bits` can go on.
    pub fn post(&self, bits: u64) {
        self.pending.set(self.pending.get() | bits);
    }

    /// Waits for any event in `mask`: the ones that arrived, which are
    /// taken (another task waiting for the same bit does not see them).
    pub fn wait(&self, mask: u64) -> Wait<'_> {
        Wait { events: self, mask }
    }

    /// Events in `mask` already posted, taken without waiting.
    pub fn take(&self, mask: u64) -> u64 {
        let got = self.pending.get() & mask;
        self.pending.set(self.pending.get() & !got);
        got
    }
}

/// The future of [`Events::wait`].
pub struct Wait<'a> {
    events: &'a Events,
    mask: u64,
}

impl Future for Wait<'_> {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u64> {
        match self.events.take(self.mask) {
            0 => {
                self.events.wanted.set(self.events.wanted.get() | self.mask);
                self.events.waits.set(self.events.waits.get() + 1);
                Poll::Pending
            }
            got => Poll::Ready(got),
        }
    }
}

/// Lets the other tasks run once before going on.
pub fn yield_now() -> Yield {
    Yield(false)
}

pub struct Yield(bool);

impl Future for Yield {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

fn no_waker() -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
    const RAW: RawWaker = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: the vtable's functions do nothing and touch no data.
    unsafe { Waker::from_raw(RAW) }
}

/// Runs `tasks` until all have finished. While any can go on they are
/// polled in turn; when every one waits for an event that has not been
/// posted, `idle` is called to block until something happens and say
/// what (the events to post).
pub fn run<const N: usize>(
    events: &Events,
    mut tasks: [Pin<&mut dyn Future<Output = ()>>; N],
    mut idle: impl FnMut() -> u64,
) {
    let waker = no_waker();
    let mut cx = Context::from_waker(&waker);
    let mut done = [false; N];
    loop {
        events.wanted.set(0);
        // A task that yields, rather than waits for an event, is ready
        // again at once.
        let mut yielded = false;
        for (task, done) in tasks.iter_mut().zip(done.iter_mut()) {
            if *done {
                continue;
            }
            let before = events.waits.get();
            match task.as_mut().poll(&mut cx) {
                Poll::Ready(()) => *done = true,
                Poll::Pending => yielded |= events.waits.get() == before,
            }
        }
        if done.iter().all(|&d| d) {
            return;
        }
        // An event a task waits for may have been posted by a later one.
        if !yielded && events.pending.get() & events.wanted.get() == 0 {
            events.post(idle());
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::pin::pin;
    use std::cell::RefCell;
    use std::vec::Vec;

    const A: u64 = 1;
    const B: u64 = 2;
    const C: u64 = 4;

    #[test]
    fn a_task_that_waits_for_nothing_runs_to_the_end_without_idling() {
        let events = Events::new();
        let ran = Cell::new(false);
        let task = pin!(async { ran.set(true) });
        run(&events, [task], || panic!("nothing to wait for"));
        assert!(ran.get());
    }

    #[test]
    fn idle_is_called_only_when_no_task_can_go_on() {
        let events = Events::new();
        let log = RefCell::new(Vec::new());
        let idles = Cell::new(0);
        let first = pin!(async {
            log.borrow_mut().push("first waits");
            events.wait(A).await;
            log.borrow_mut().push("first woke");
        });
        let second = pin!(async {
            log.borrow_mut().push("second runs");
        });
        run(&events, [first, second], || {
            idles.set(idles.get() + 1);
            log.borrow_mut().push("idle");
            A
        });
        assert_eq!(*log.borrow(), ["first waits", "second runs", "idle", "first woke"]);
        assert_eq!(idles.get(), 1);
    }

    #[test]
    fn tasks_wake_each_other_without_idling() {
        let events = Events::new();
        let log = RefCell::new(Vec::new());
        let ping = pin!(async {
            for i in 0..3 {
                events.wait(A).await;
                log.borrow_mut().push(("ping", i));
                events.post(B);
            }
        });
        let pong = pin!(async {
            for i in 0..3 {
                events.post(A);
                events.wait(B).await;
                log.borrow_mut().push(("pong", i));
            }
        });
        run(&events, [ping, pong], || panic!("each wakes the other"));
        assert_eq!(
            *log.borrow(),
            [("ping", 0), ("pong", 0), ("ping", 1), ("pong", 1), ("ping", 2), ("pong", 2)]
        );
    }

    #[test]
    fn an_event_goes_to_one_waiter_and_only_for_its_mask() {
        let events = Events::new();
        let got = RefCell::new(Vec::new());
        let a = pin!(async { {
            let bits = events.wait(A | B).await;
            got.borrow_mut().push(("a", bits))
        } });
        let c = pin!(async { {
            let bits = events.wait(C).await;
            got.borrow_mut().push(("c", bits))
        } });
        let mut script = [B, A | C].into_iter();
        let late = pin!(async { {
            let bits = events.wait(A).await;
            got.borrow_mut().push(("late", bits))
        } });
        run(&events, [a, c, late], || script.next().expect("two idles"));
        // B woke `a` alone; then A went to `late` and C to `c`.
        assert_eq!(*got.borrow(), [("a", B), ("c", C), ("late", A)]);
    }

    #[test]
    fn events_posted_early_are_kept() {
        let events = Events::new();
        events.post(A | C);
        assert_eq!(events.take(B), 0);
        let got = Cell::new(0);
        let task = pin!(async { got.set(events.wait(A | B).await) });
        run(&events, [task], || panic!("already posted"));
        assert_eq!(got.get(), A);
        assert_eq!(events.take(!0), C);
    }

    #[test]
    fn yielding_lets_the_others_run_without_idling() {
        let events = Events::new();
        let log = RefCell::new(Vec::new());
        let spinner = pin!(async {
            for i in 0..3 {
                log.borrow_mut().push(("spin", i));
                yield_now().await;
            }
        });
        let other = pin!(async {
            for i in 0..2 {
                log.borrow_mut().push(("other", i));
                yield_now().await;
            }
        });
        run(&events, [spinner, other], || panic!("yielding is not waiting"));
        assert_eq!(
            *log.borrow(),
            [("spin", 0), ("other", 0), ("spin", 1), ("other", 1), ("spin", 2)]
        );
    }

    #[test]
    fn a_driver_shaped_run() {
        // An interrupt task and a service task; `idle` plays the kernel:
        // two calls, an interrupt between them, then shutdown.
        const IRQ: u64 = 1;
        const CALL: u64 = 2;
        const STOP: u64 = 4;
        let events = Events::new();
        let interrupts = Cell::new(0);
        let served = Cell::new(0);
        let irq = pin!(async {
            loop {
                if events.wait(IRQ | STOP).await & STOP != 0 {
                    // Passed on, so the other task stops too.
                    events.post(STOP);
                    return;
                }
                interrupts.set(interrupts.get() + 1);
            }
        });
        let service = pin!(async {
            loop {
                if events.wait(CALL | STOP).await & STOP != 0 {
                    return;
                }
                served.set(served.get() + 1);
            }
        });
        let mut script = [CALL, IRQ, CALL | IRQ, STOP].into_iter();
        run(&events, [irq, service], || script.next().expect("four waits"));
        assert_eq!((interrupts.get(), served.get()), (2, 2));
    }
}
