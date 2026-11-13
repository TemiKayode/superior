//! The kernel's random numbers, for [`Syscall::Random`]: what keys and
//! nonces are drawn from (the Wi-Fi station's handshake nonces first).
//!
//! The pool is seeded at boot from the CPU's own random source where it
//! has one (RDSEED or RDRAND on x86-64, RNDR on AArch64) and from the
//! jitter of the cycle counter, and keeps taking in the counter's value
//! at every interrupt. Drawing hashes all of that (SHA-256) into a new
//! key, then the output from the key: the key moves on with every draw,
//! so output already given cannot be worked back from a later state.
//!
//! [`Syscall::Random`]: superior_objects::abi::Syscall::Random

use crate::arch;
use spin::Mutex;
use superior_objects::crypto::sha2::Sha256;

struct Pool {
    key: [u8; 32],
    /// Interrupt timings since the last draw, folded in cheaply.
    pending: [u64; 8],
    events: u64,
    draws: u64,
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    key: [0; 32],
    pending: [0; 8],
    events: 0,
    draws: 0,
});

/// Seeds the pool: the hardware source's words, if any, and the jitter of
/// the cycle counter over some busy work. Returns the hardware source.
pub fn init() -> Option<&'static str> {
    let mut h = Sha256::new();
    h.update(b"superior entropy seed");
    let source = arch::random_source();
    if source.is_some() {
        for _ in 0..16 {
            if let Some(w) = arch::random_word() {
                h.update(&w.to_le_bytes());
            }
        }
    }
    // The counter's low bits between rounds of hashing wander with caches,
    // the host's scheduling (under emulation) and interrupts meanwhile.
    let mut j = Sha256::new();
    for i in 0..256u32 {
        let t = arch::cycles();
        j.update(&t.to_le_bytes());
        j.update(&i.to_le_bytes());
        h.update(&arch::cycles().wrapping_sub(t).to_le_bytes());
    }
    h.update(&j.finish());
    let mut p = POOL.lock();
    h.update(&p.key);
    p.key = h.finish();
    source
}

/// Takes in an interrupt's timing: called on every interrupt, so it only
/// folds the counter into the pending words.
pub fn interrupt(line: u8) {
    if let Some(mut p) = POOL.try_lock() {
        let i = (p.events % 8) as usize;
        let t = arch::cycles() ^ ((line as u64) << 56);
        p.pending[i] = p.pending[i].rotate_left(13) ^ t;
        p.events = p.events.wrapping_add(1);
    }
}

/// 32 fresh random bytes.
pub fn draw() -> [u8; 32] {
    let mut p = POOL.lock();
    let mut h = Sha256::new();
    h.update(&p.key);
    for w in p.pending {
        h.update(&w.to_le_bytes());
    }
    h.update(&p.events.to_le_bytes());
    h.update(&p.draws.to_le_bytes());
    h.update(&arch::cycles().to_le_bytes());
    if let Some(w) = arch::random_word() {
        h.update(&w.to_le_bytes());
    }
    let seed = h.finish();
    let derive = |label: &[u8]| {
        let mut d = Sha256::new();
        d.update(label);
        d.update(&seed);
        d.finish()
    };
    // The output and the next key both come from `seed`, which is not
    // kept: the state left behind does not give the output away.
    p.key = derive(b"superior entropy key");
    p.pending = [0; 8];
    p.draws = p.draws.wrapping_add(1);
    derive(b"superior entropy out")
}
