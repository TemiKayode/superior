//! Deterministic simulation of the IPC and scheduling engine.
//!
//! Each run starts from a seed. A pseudo-random generator (SplitMix64, so
//! no dependency and the same sequence on every machine) picks, step by
//! step, either a system call by the current thread (send, call, receive,
//! reply, reply-and-receive, signal, wait, yield, going passive, each with
//! random objects, badges and capability transfers) or an outside event (a
//! timer tick, an interrupt signal, a thread suspended or started, a
//! budget changed, an object destroyed). After every step the harness:
//!
//! - runs `schedule` as the kernel does, then checks every structural
//!   invariant of the engine ([`Ipc::check_invariants`]): queues
//!   well-formed and consistent with thread states, one running thread at
//!   the highest ready priority, budgets respected, no caller left waiting
//!   on a reply nobody owes;
//! - checks message integrity: every message a thread receives was sent to
//!   that endpoint, with the sender's badge, and is received at most once;
//!   a message whose sender was suspended before delivery is never
//!   received.
//!
//! The trace of every step (operation, result, who runs next) is hashed,
//! and every seed is run twice: the two hashes must match, so a failing
//! seed always replays exactly. A failure reports the seed, the step and
//! the last operations; `SIM_SEED=<n> SIM_STEPS=<m> cargo test sim::`
//! replays one seed.

use crate::abi::{CapTransfer, Error};
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
    Budget {
        t: Tid,
        budget: u32,
        period: u32,
    },
    DestroyEp(u16),
    DestroyNtfn(u16),
}

/// Message words carry a tag so receipts can be traced to their send.
const SENT_TAG: u64 = 1 << 40;
const REPLY_TAG: u64 = 2 << 40;

struct Sim {
    k: Engine,
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
}

impl Sim {
    fn new(seed: u64) -> Sim {
        let mut sim = Sim {
            k: Engine::new(),
            rng: Rng(seed),
            step: 0,
            in_flight: HashMap::new(),
            received: HashSet::new(),
            cancelled: HashSet::new(),
            carrying: [None; THREADS],
            hash: 0xcbf2_9ce4_8422_2325,
            recent: VecDeque::new(),
        };
        // Threads 0..4 start at a few priorities (so there are ties); the
        // last is left inactive for Spawn to start later.
        for t in 0..THREADS as Tid - 1 {
            let prio = 1 + sim.rng.below(3) as u8;
            sim.k.spawn(t, prio).unwrap();
        }
        sim.k.schedule();
        sim
    }

    fn pick(&mut self) -> Op {
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
            36..=40 => Op::Reply,
            41..=50 => Op::ReplyRecv { ep },
            51..=56 => Op::Signal {
                ntfn,
                bits: 1 << r.below(4),
            },
            57..=62 => Op::Wait { ntfn },
            63..=67 => Op::Yield,
            68 if r.chance(25) => Op::Passive,
            68 => Op::Tick,
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
            89..=92 => Op::Spawn {
                t,
                prio: 1 + r.below(3) as u8,
            },
            93..=95 => {
                let period = 2 + r.below(6) as u32;
                Op::Budget {
                    t,
                    budget: 1 + r.below(period as u64) as u32,
                    period,
                }
            }
            96..=97 => Op::DestroyEp(ep),
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
        let op = self.pick();
        let before: [State; THREADS] = core::array::from_fn(|t| self.k.thread(t as Tid).state);
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
            Op::Suspend(t) | Op::Recreate { t, .. } => Some(t),
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
            Op::ReplyRecv { ep } => self.k.reply_recv(ep, msg(REPLY_TAG)),
            Op::Signal { ntfn, bits } => self.k.signal(ntfn, bits),
            Op::Wait { ntfn } => self.k.wait(ntfn),
            Op::Yield => self.k.yield_now(),
            Op::Passive => self.k.make_passive(),
            Op::Tick => {
                self.k.tick();
                Ok(())
            }
            Op::Irq { ntfn, bits } => self.k.signal_irq(ntfn, bits),
            Op::Suspend(t) => self.k.suspend(t),
            Op::Recreate { t, prio } => {
                let _ = self.k.suspend(t);
                self.k.reset_thread(t).unwrap();
                self.k.spawn(t, prio)
            }
            Op::Spawn { t, prio } => self.k.spawn(t, prio),
            Op::Budget { t, budget, period } => self.k.configure_sc(t, budget, period),
            Op::DestroyEp(ep) => self.k.destroy_endpoint(ep),
            Op::DestroyNtfn(n) => self.k.destroy_notification(n),
        };
        let _ = self.k.take_transfers();
        self.k.schedule();

        let now = self.k.current();
        let line = format!("{op:?} by {cur:?} -> {result:?}, then {now:?} runs");
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
        self.check_messages(op, cur, stopped, &before, result)
            .map_err(|e| self.fail(seed, e))
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
        if result.is_err()
            && !matches!(
                result,
                Err(IpcError::NoCurrent
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
    let mut sim = Sim::new(seed);
    for _ in 0..steps {
        sim.step(seed)?;
    }
    Ok(sim.hash)
}

/// Statistics over many seeds, to show the runs exercise the engine.
pub fn coverage(seeds: u64, steps: u64) -> HashMap<&'static str, u64> {
    let mut c = HashMap::new();
    for seed in 0..seeds {
        let mut sim = Sim::new(seed);
        for _ in 0..steps {
            sim.step(seed).unwrap();
            let k = &sim.k;
            for t in 0..THREADS as Tid {
                let key = match k.thread(t).state {
                    State::BlockedSend { call: true, .. } => "blocked calling",
                    State::BlockedSend { .. } => "blocked sending",
                    State::BlockedRecv { .. } => "blocked receiving",
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
        }
        *c.entry("messages received").or_insert(0) += sim.received.len() as u64;
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
            "waiting on notification",
            "throttled",
            "passive, no context",
            "messages received",
        ] {
            assert!(c.get(key).copied().unwrap_or(0) > 0, "never reached: {key}");
        }
    }

    #[test]
    fn different_seeds_take_different_paths() {
        assert_ne!(run(1, 500).unwrap(), run(2, 500).unwrap());
    }
}
