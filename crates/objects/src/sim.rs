//! Deterministic simulation of the IPC and scheduling engine.
//!
//! Each run starts from a seed. A pseudo-random generator (SplitMix64, so
//! no dependency and the same sequence on every machine) picks, step by
//! step, either a system call by the current thread (send, call, receive,
//! reply, reply-and-receive, signal, wait, yield, going passive, each with
//! random objects, badges and capability transfers) or an outside event (a
//! timer tick, an interrupt signal, a thread suspended or started, a
//! budget changed, a thread bound to another scheduling context or to
//! none, a context emptied, made unlimited or destroyed, an object
//! destroyed). After every step the harness:
//!
//! - runs `schedule` as the kernel does, then checks every structural
//!   invariant of the engine ([`Ipc::check_invariants`]): queues
//!   well-formed and consistent with thread states, one running thread at
//!   the highest ready priority, budgets respected, no caller left waiting
//!   on a reply nobody owes;
//! - checks timeout faults: a thread given a timeout handler (badge
//!   `0x100 | thread`) that empties a lent budget calls it; every such
//!   fault is received at most once, only after it was raised, and never
//!   after its sender was stopped;
//! - checks bandwidth: the harness notes when every tick charged to each
//!   scheduling context began (the clock before the step) and requires that no `period` ticks hold
//!   more charges than the context's `budget` (the sporadic-server
//!   guarantee), independently of how the engine keeps its refills;
//! - checks message integrity: every message a thread receives was sent to
//!   that endpoint, with the sender's badge, and is received at most once;
//!   a message whose sender was suspended before delivery is never
//!   received.
//!
//! Runs on several CPUs ([`run_on`]) pick a CPU for each step, settle it
//! as the kernel does on entry (a thread another CPU stopped leaves it),
//! make the step that CPU's, and reschedule it after.
//!
//! The trace of every step (operation, result, who runs next) is hashed,
//! and every seed is run twice: the two hashes must match, so a failing
//! seed always replays exactly. A failure reports the seed, the step and
//! the last operations; `SIM_SEED=<n> SIM_STEPS=<m> cargo test sim::`
//! replays one seed.

use crate::abi::{CapTransfer, Error, FaultKind};
use crate::ipc::{Ipc, IpcError, State, Tid};
use std::collections::{HashMap, HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec::Vec;

const THREADS: usize = 5;
const ENDPOINTS: usize = 2;
const NOTIFICATIONS: usize = 2;
type Engine = Ipc<THREADS, ENDPOINTS, NOTIFICATIONS>;

/// SplitMix64: tiny, fast, and fully determined by its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Send {
        ep: u16,
        badge: u64,
        blocking: bool,
    },
    Call {
        ep: u16,
        badge: u64,
    },
    Recv {
        ep: u16,
        blocking: bool,
    },
    Reply,
    /// Set the caller aside, or answer one set aside.
    SaveCaller,
    ReplySaved(usize),
    ReplyRecv {
        ep: u16,
    },
    Signal {
        ntfn: u16,
        bits: u64,
    },
    Wait {
        ntfn: u16,
    },
    Yield,
    Passive,
    Tick,
    Irq {
        ntfn: u16,
        bits: u64,
    },
    Suspend(Tid),
    /// Destroy and re-make a thread, as the kernel does when a thread
    /// object's last capability goes and its entry is retyped again.
    Recreate {
        t: Tid,
        prio: u8,
    },
    Spawn {
        t: Tid,
        prio: u8,
    },
    /// Destroy a thread and leave its entry empty, as when its component
    /// is killed (a new thread may be made in it later).
    Destroy(Tid),
    Budget {
        t: Tid,
        budget: u32,
        period: u32,
    },
    Bind {
        t: Tid,
        sc: Option<Tid>,
    },
    EmptySc(Tid),
    UnlimitSc(Tid),
    DestroySc(Tid),
    TimeoutHandler {
        t: Tid,
        ep: Option<u16>,
    },
    DestroyEp(u16),
    DestroyNtfn(u16),
}

/// Message words carry a tag so receipts can be traced to their send.
const SENT_TAG: u64 = 1 << 40;
const REPLY_TAG: u64 = 2 << 40;
/// Badge of a timeout handler's endpoint, ORed with the thread it serves.
const TIMEOUT_BADGE: u64 = 0x100;

struct Sim {
    k: Engine,
    /// CPUs the steps are spread over.
    cpus: usize,
    rng: Rng,
    step: u64,
    /// Messages sent (or queued) and not yet received: id -> (endpoint, badge).
    in_flight: HashMap<u64, (u16, u64)>,
    received: HashSet<u64>,
    /// Messages whose sender was suspended before they were delivered.
    cancelled: HashSet<u64>,
    /// Which message each blocked sender carries.
    carrying: [Option<u64>; THREADS],
    hash: u64,
    recent: VecDeque<String>,
    /// Per scheduling context: `consumed` as last seen, and when each tick
    /// charged since it was last configured began.
    consumed: [u64; THREADS],
    charges: [VecDeque<u64>; THREADS],
    /// Threads whose timeout fault is raised and not yet received.
    faults: HashSet<Tid>,
}

impl Sim {
    fn new(seed: u64, cpus: usize) -> Sim {
        let mut sim = Sim {
            k: Engine::new(),
            cpus,
            rng: Rng(seed),
            step: 0,
            in_flight: HashMap::new(),
            received: HashSet::new(),
            cancelled: HashSet::new(),
            carrying: [None; THREADS],
            hash: 0xcbf2_9ce4_8422_2325,
            recent: VecDeque::new(),
            consumed: [0; THREADS],
            charges: core::array::from_fn(|_| VecDeque::new()),
            faults: HashSet::new(),
        };
        // Threads 0..4 start at a few priorities (so there are ties); the
        // last is left inactive for Spawn to start later.
        for t in 0..THREADS as Tid - 1 {
            let prio = 1 + sim.rng.below(3) as u8;
            sim.k.spawn(t, prio).unwrap();
            // Some start limited and some with a timeout handler, so lent
            // budgets run dry under handlers from the start.
            if sim.rng.chance(50) {
                let period = 2 + sim.rng.below(10) as u32;
                let budget = 1 + sim.rng.below(period as u64) as u32;
                sim.k.configure_sc(t, budget, period).unwrap();
            }
            if sim.rng.chance(50) {
                let ep = sim.rng.below(ENDPOINTS as u64) as u16;
                sim.k
                    .set_timeout_handler(t, Some((ep, TIMEOUT_BADGE | t as u64)))
                    .unwrap();
            }
        }
        sim.k.schedule();
        sim
    }

    fn pick(&mut self) -> Op {
        // A server working on a caller's budget does work between system
        // calls, so its budget can run dry mid-request.
        let serving = self
            .k
            .current()
            .is_some_and(|c| self.k.active_sc(c).is_some_and(|sc| sc != c));
        if serving && self.rng.chance(80) {
            return Op::Tick;
        }
        let r = &mut self.rng;
        let ep = r.below(ENDPOINTS as u64) as u16;
        let ntfn = r.below(NOTIFICATIONS as u64) as u16;
        let badge = r.below(4);
        let t = r.below(THREADS as u64) as Tid;
        // Weights: mostly system calls, some outside events.
        match r.below(100) {
            0..=11 => Op::Send {
                ep,
                badge,
                blocking: r.chance(70),
            },
            12..=23 => Op::Call { ep, badge },
            24..=35 => Op::Recv {
                ep,
                blocking: r.chance(80),
            },
            36..=37 => Op::Reply,
            38..=39 => Op::SaveCaller,
            40 => Op::ReplySaved(r.below(4) as usize),
            41..=50 => Op::ReplyRecv { ep },
            51..=56 => Op::Signal {
                ntfn,
                bits: 1 << r.below(4),
            },
            57..=62 => Op::Wait { ntfn },
            63..=67 => Op::Yield,
            68 => Op::Passive,
            69..=80 => Op::Tick,
            81..=84 => Op::Irq {
                ntfn,
                bits: 1 << r.below(4),
            },
            85..=86 => Op::Suspend(t),
            87..=88 => Op::Recreate {
                t,
                prio: 1 + r.below(3) as u8,
            },
            89 if r.chance(50) => Op::Destroy(t),
            89..=92 => Op::Spawn {
                t,
                prio: 1 + r.below(3) as u8,
            },
            93 => Op::TimeoutHandler {
                t,
                ep: r.chance(80).then_some(ep),
            },
            94 => {
                let sc = r.below(THREADS as u64) as Tid;
                match r.below(6) {
                    0..=2 => Op::Bind {
                        t,
                        sc: r.chance(85).then_some(sc),
                    },
                    3 => Op::EmptySc(sc),
                    4 => Op::UnlimitSc(sc),
                    _ => Op::DestroySc(sc),
                }
            }
            95..=96 => {
                // Mostly short periods, so threads are often throttled;
                // some long enough to fill a context's refill ring.
                let period = if r.chance(70) {
                    2 + r.below(6) as u32
                } else {
                    8 + r.below(33) as u32
                };
                Op::Budget {
                    t,
                    budget: 1 + r.below(period as u64) as u32,
                    period,
                }
            }
            97 => Op::DestroyEp(ep),
            _ => Op::DestroyNtfn(ntfn),
        }
    }

    fn fail(&self, seed: u64, why: String) -> String {
        let mut s = format!("seed {seed}, step {}: {why}\n  last operations:", self.step);
        for r in &self.recent {
            s.push_str("\n    ");
            s.push_str(r);
        }
        s.push_str("\n  threads:");
        for t in 0..THREADS as Tid {
            let tcb = self.k.thread(t);
            s.push_str(&format!(
                "\n    {t}: {:?} prio {} passive {} sc {:?}",
                tcb.state,
                tcb.prio,
                tcb.passive,
                self.k.sched_context(t)
            ));
        }
        s
    }

    fn mix(&mut self, x: u64) {
        // FNV-1a over the trace.
        for b in x.to_le_bytes() {
            self.hash ^= b as u64;
            self.hash = self.hash.wrapping_mul(0x100_0000_01b3);
        }
    }

    /// One step. Returns an error describing the first violation.
    fn step(&mut self, seed: u64) -> Result<(), String> {
        self.step += 1;
        // The CPU making this step enters the kernel: if another CPU
        // stopped its thread, it lets it go.
        let cpu = if self.cpus > 1 {
            self.rng.below(self.cpus as u64) as usize
        } else {
            0
        };
        let op = self.pick();
        // An interrupt can also reach a CPU in the kernel's idle loop,
        // whose handler acts on the engine as it stands, settling nothing.
        let idle = self.cpus > 1
            && matches!(op, Op::Tick | Op::Irq { .. })
            && self.rng.chance(50);
        if self.cpus > 1 {
            self.k.set_cpu(cpu);
            if !idle {
                self.k.settle();
                self.k.reschedule();
            }
        }
        let before: [State; THREADS] = core::array::from_fn(|t| self.k.thread(t as Tid).state);
        // A tick charged in this step began at the clock as it is now.
        let began = self.k.now();
        let cur = self.k.current();
        let id = self.step;
        let xfer = CapTransfer {
            grant: self.rng.chance(20).then(|| self.rng.below(4) as u16),
            accept: self.rng.chance(30).then(|| self.rng.below(4) as u16),
        };
        self.k.set_transfer(xfer);
        let msg = |tag: u64| [tag | id, 0, 0, 0];
        // A blocked sender stopped by this step: its message is cancelled.
        let stopped = match op {
            Op::Suspend(t) | Op::Recreate { t, .. } | Op::Destroy(t) => Some(t),
            _ => None,
        };
        if let Some(t) = stopped
            && matches!(before[t as usize], State::BlockedSend { .. })
            && let Some(m) = self.carrying[t as usize].take()
        {
            self.cancelled.insert(m);
        }
        let result: Result<(), IpcError> = match op {
            Op::Send {
                ep,
                badge,
                blocking,
            } => {
                let r = self.k.send(ep, badge, msg(SENT_TAG), blocking);
                if r.is_ok() && cur.is_some() {
                    self.in_flight.insert(SENT_TAG | id, (ep, badge));
                }
                r
            }
            Op::Call { ep, badge } => {
                let r = self.k.call(ep, badge, msg(SENT_TAG));
                if r.is_ok() {
                    self.in_flight.insert(SENT_TAG | id, (ep, badge));
                }
                r
            }
            Op::Recv { ep, blocking } => self.k.recv(ep, blocking),
            Op::Reply => self.k.reply(msg(REPLY_TAG)),
            Op::SaveCaller => self.k.save_caller().map(|_| ()),
            Op::ReplySaved(i) => self.k.reply_saved(i, msg(REPLY_TAG)),
            Op::ReplyRecv { ep } => self.k.reply_recv(ep, msg(REPLY_TAG)),
            Op::Signal { ntfn, bits } => self.k.signal(ntfn, bits),
            Op::Wait { ntfn } => self.k.wait(ntfn),
            Op::Yield => self.k.yield_now(),
            Op::Passive => self.k.make_passive(),
            Op::Tick => {
                self.k.tick_cpu(cpu == 0);
                Ok(())
            }
            Op::Irq { ntfn, bits } => self.k.signal_irq(ntfn, bits),
            Op::Suspend(t) => self.k.suspend(t),
            Op::Recreate { t, prio } => {
                // As the kernel destroys a thread object.
                let _ = self.k.destroy(t);
                self.k.reset_thread(t).unwrap();
                self.k.spawn(t, prio)
            }
            Op::Spawn { t, prio } => self.k.spawn(t, prio),
            Op::Destroy(t) => {
                let _ = self.k.destroy(t);
                self.k.reset_thread(t).unwrap();
                Ok(())
            }
            Op::Budget { t, budget, period } => self.k.configure_sc(t, budget, period),
            Op::Bind { t, sc } => self.k.bind_sc(t, sc),
            Op::EmptySc(sc) => self.k.empty_sc(sc),
            Op::UnlimitSc(sc) => self.k.unlimit_sc(sc),
            Op::DestroySc(sc) => self.k.destroy_sc(sc),
            Op::TimeoutHandler { t, ep } => self
                .k
                .set_timeout_handler(t, ep.map(|e| (e, TIMEOUT_BADGE | t as u64))),
            Op::DestroyEp(ep) => self.k.destroy_endpoint(ep),
            Op::DestroyNtfn(n) => self.k.destroy_notification(n),
        };
        let _ = self.k.take_transfers();
        if let Some(f) = self.k.take_timeout() {
            if !matches!(op, Op::Tick) {
                return Err(self.fail(seed, format!("timeout fault by {f} outside a tick")));
            }
            self.faults.insert(f);
        }
        if idle {
            // Back to the idle loop, which reschedules.
            self.k.reschedule();
        } else if self.cpus > 1 {
            self.k.reschedule();
        } else {
            self.k.schedule();
        }

        let now = self.k.current();
        let line = format!("CPU {cpu}: {op:?} by {cur:?} -> {result:?}, then {now:?} runs");
        self.recent.push_back(line);
        if self.recent.len() > 12 {
            self.recent.pop_front();
        }
        self.mix(self.step);
        self.mix(match result {
            Ok(()) => 0,
            Err(e) => e.status() + 1,
        });
        self.mix(now.map_or(u64::MAX, |t| t as u64));
        for t in 0..THREADS as Tid {
            let tcb = self.k.thread(t);
            self.mix(tcb.status ^ tcb.msg[0] ^ tcb.badge);
        }

        self.k.check_invariants().map_err(|e| self.fail(seed, e))?;
        // A context given new parameters starts a new budget now.
        let restarted = match (op, result) {
            (
                Op::Budget { t: sc, .. } | Op::EmptySc(sc) | Op::UnlimitSc(sc) | Op::DestroySc(sc),
                Ok(()),
            ) => Some(sc),
            _ => None,
        };
        self.check_bandwidth(began, restarted)
            .map_err(|e| self.fail(seed, e))?;
        self.check_messages(op, cur, stopped, &before, result)
            .map_err(|e| self.fail(seed, e))
    }

    /// No context is charged more than its budget in any `period` ticks.
    fn check_bandwidth(&mut self, began: u64, restarted: Option<Tid>) -> Result<(), String> {
        for t in 0..THREADS {
            let sc = *self.k.sched_context(t as Tid);
            if restarted == Some(t as Tid) || sc.consumed < self.consumed[t] {
                // Configured again (or destroyed): a new budget starts now,
                // and nothing charged before it counts against it. Charges
                // from this very step (none: no tick) would be lost.
                self.charges[t].clear();
                self.consumed[t] = sc.consumed;
                continue;
            }
            for _ in self.consumed[t]..sc.consumed {
                self.charges[t].push_back(began);
            }
            self.consumed[t] = sc.consumed;
            let Some(budget) = sc.budget else {
                self.charges[t].clear();
                continue;
            };
            let h = &mut self.charges[t];
            while h.front().is_some_and(|&c| c + sc.period as u64 <= began) {
                h.pop_front();
            }
            if h.len() > budget as usize {
                return Err(format!(
                    "context {t}: {} ticks charged in the {} ticks to {began}, budget {budget}: {h:?}",
                    h.len(),
                    sc.period
                ));
            }
        }
        Ok(())
    }

    fn check_messages(
        &mut self,
        op: Op,
        cur: Option<Tid>,
        stopped: Option<Tid>,
        before: &[State; THREADS],
        result: Result<(), IpcError>,
    ) -> Result<(), String> {
        // Track which message each blocked sender holds.
        if let (Some(c), Op::Send { .. } | Op::Call { .. }) = (cur, op)
            && result.is_ok()
        {
            self.carrying[c as usize] = Some(SENT_TAG | self.step);
        }
        for t in 0..THREADS {
            let st = self.k.thread(t as Tid).state;
            let was_sending = matches!(before[t], State::BlockedSend { .. });
            // A blocked sender suspended before delivery: its message is
            // cancelled and must never arrive.
            if was_sending
                && st == State::Inactive
                && let Some(m) = self.carrying[t].take()
            {
                self.cancelled.insert(m);
            }
        }
        // Who completed a receive in this step?
        let mut receivers = Vec::new();
        for t in 0..THREADS as Tid {
            let tcb = self.k.thread(t);
            let woken = matches!(before[t as usize], State::BlockedRecv { .. })
                && !matches!(tcb.state, State::BlockedRecv { .. } | State::Inactive)
                && tcb.status == 0;
            let immediate = cur == Some(t)
                && result.is_ok()
                && matches!(op, Op::Recv { .. } | Op::ReplyRecv { .. })
                && !matches!(tcb.state, State::BlockedRecv { .. } | State::Inactive);
            if (woken || immediate) && stopped != Some(t) {
                receivers.push(t);
            }
        }
        for t in receivers {
            let tcb = *self.k.thread(t);
            let m = tcb.msg[0];
            if m == FaultKind::Timeout as u64 && tcb.badge & TIMEOUT_BADGE != 0 {
                let from = (tcb.badge & 0xff) as Tid;
                if !self.faults.remove(&from) {
                    return Err(format!(
                        "thread {t} received a timeout fault from {from}, which raised none"
                    ));
                }
                if tcb.msg[1] == 0 || tcb.msg[1] > tcb.msg[2] {
                    return Err(format!("timeout fault with budget/period {:?}", tcb.msg));
                }
                continue;
            }
            if m & SENT_TAG == 0 {
                return Err(format!("thread {t} received {m:#x}, which nobody sent"));
            }
            if self.cancelled.contains(&m) {
                return Err(format!(
                    "thread {t} received {m:#x}, cancelled by suspending its sender"
                ));
            }
            if !self.received.insert(m) {
                return Err(format!("thread {t} received {m:#x} a second time"));
            }
            let Some((_, badge)) = self.in_flight.remove(&m) else {
                return Err(format!("thread {t} received {m:#x}, never sent"));
            };
            if tcb.badge != badge {
                return Err(format!(
                    "thread {t} got badge {} for a message sent with {badge}",
                    tcb.badge
                ));
            }
            // The sender no longer carries it.
            for c in self.carrying.iter_mut() {
                if *c == Some(m) {
                    *c = None;
                }
            }
        }
        // A fault not received is only ever waiting to be: its sender is
        // queued to send it, or it was cancelled (stopped, endpoint gone).
        let k = &self.k;
        self.faults
            .retain(|&f| matches!(k.thread(f).state, State::BlockedSend { call: true, .. }));
        if result.is_err()
            && !matches!(
                result,
                Err(IpcError::NoCurrent
                    | IpcError::NoCaller
                    | IpcError::CannotSave
                    | IpcError::WouldBlock
                    | IpcError::ThreadActive
                    | IpcError::BadSchedParams
                    | IpcError::BadPriority)
            )
        {
            return Err(format!("unexpected error {result:?}"));
        }
        Ok(())
    }
}

/// Runs `steps` steps from `seed`; returns the trace hash.
pub fn run(seed: u64, steps: u64) -> Result<u64, String> {
    run_on(1, seed, steps)
}

/// Runs `steps` steps from `seed` spread over `cpus` CPUs; returns the
/// trace hash.
pub fn run_on(cpus: usize, seed: u64, steps: u64) -> Result<u64, String> {
    let mut sim = Sim::new(seed, cpus);
    for _ in 0..steps {
        sim.step(seed)?;
    }
    Ok(sim.hash)
}

/// Statistics over many seeds, to show the runs exercise the engine.
pub fn coverage(seeds: u64, steps: u64) -> HashMap<&'static str, u64> {
    let mut c = HashMap::new();
    for seed in 0..seeds {
        let mut sim = Sim::new(seed, 1);
        for _ in 0..steps {
            sim.step(seed).unwrap();
            let k = &sim.k;
            for t in 0..THREADS as Tid {
                let key = match k.thread(t).state {
                    State::BlockedSend { call: true, .. } => "blocked calling",
                    State::BlockedSend { .. } => "blocked sending",
                    State::BlockedRecv { .. } => "blocked receiving",
                    State::BlockedReply if k.is_saved(t) => "awaiting a saved reply",
                    State::BlockedReply => "awaiting reply",
                    State::BlockedWait { .. } => "waiting on notification",
                    State::Throttled { .. } => "throttled",
                    State::NoSchedContext => "passive, no context",
                    _ => continue,
                };
                *c.entry(key).or_insert(0) += 1;
            }
            if k.thread(0).status == Error::ReplyAbandoned.code() {
                *c.entry("reply abandoned").or_insert(0) += 1;
            }
            if (0..4).any(|t| k.thread(t).status == Error::PeerRestarted.code()) {
                *c.entry("peer restarted").or_insert(0) += 1;
            }
        }
        *c.entry("messages received").or_insert(0) += sim.received.len() as u64;
        *c.entry("timeout faults").or_insert(0) += sim.k.stats.timeouts;
        *c.entry("donated ticks").or_insert(0) += sim.k.stats.donated_ticks;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    const SEEDS: u64 = 400;
    const STEPS: u64 = 2_000;

    #[test]
    fn simulated_runs_keep_every_invariant_and_replay_exactly() {
        let seeds: Vec<u64> = match std::env::var("SIM_SEED") {
            Ok(s) => std::vec![s.parse().expect("SIM_SEED must be a number")],
            Err(_) => (0..SEEDS).collect(),
        };
        let steps = std::env::var("SIM_STEPS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(STEPS);
        for seed in seeds {
            let a = run(seed, steps).unwrap_or_else(|e| panic!("{e}"));
            let b = run(seed, steps).unwrap();
            assert_eq!(a, b, "seed {seed} did not replay identically");
        }
    }

    /// Many more seeds and longer runs: run by `cargo xtask test` in
    /// release mode.
    #[test]
    #[ignore]
    fn long_simulated_runs_keep_every_invariant() {
        const LONG_SEEDS: u64 = 10_000;
        const LONG_STEPS: u64 = 5_000;
        for seed in SEEDS..SEEDS + LONG_SEEDS {
            run(seed, LONG_STEPS).unwrap_or_else(|e| panic!("{e}"));
        }
        let c = coverage(200, LONG_STEPS);
        std::println!(
            "simulation: {LONG_SEEDS} seeds x {LONG_STEPS} steps, no violation; coverage {c:?}"
        );
    }

    #[test]
    fn simulated_runs_reach_every_kind_of_state() {
        let c = coverage(40, STEPS);
        std::println!("simulation coverage: {c:?}");
        for key in [
            "blocked calling",
            "blocked sending",
            "blocked receiving",
            "awaiting reply",
            "awaiting a saved reply",
            "waiting on notification",
            "throttled",
            "passive, no context",
            "timeout faults",
            "messages received",
        ] {
            assert!(c.get(key).copied().unwrap_or(0) > 0, "never reached: {key}");
        }
    }

    #[test]
    fn simulated_runs_on_several_cpus_keep_every_invariant() {
        for cpus in 2..=crate::ipc::MAX_CPUS {
            for seed in 0..SEEDS {
                let a = run_on(cpus, seed, STEPS).unwrap_or_else(|e| panic!("{cpus} CPUs: {e}"));
                let b = run_on(cpus, seed, STEPS).unwrap();
                assert_eq!(a, b, "{cpus} CPUs, seed {seed} did not replay identically");
            }
        }
    }

    #[test]
    fn different_seeds_take_different_paths() {
        assert_ne!(run(1, 500).unwrap(), run(2, 500).unwrap());
    }
}
