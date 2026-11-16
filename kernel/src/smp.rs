//! Several CPUs: what they share outside the kernel lock.
//!
//! The kernel takes one lock for all its work (`task::lock_kernel`), so
//! most of SMP is the IPC engine keeping a current thread per CPU. Two
//! things cannot wait for the lock, and live here:
//!
//! - Kicks: when one CPU's work leaves another with something better to
//!   run (or its thread stopped), it interrupts that CPU, which enters
//!   the kernel and reschedules ([`kick`]).
//! - Address-space shootdowns: a mapping removed, or a whole address space
//!   destroyed, must be gone from every CPU's TLB (and a destroyed space's
//!   tables off every CPU) before its memory can be used again. The CPU
//!   doing it, holding the lock, asks each CPU that has the space loaded
//!   and waits for each to answer ([`shootdown`]). A CPU answers from an
//!   interrupt handler that takes no lock (in user mode, or idle), or from
//!   the loop in which it waits for the lock: so waiting cannot deadlock.

use crate::arch;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub use superior_objects::ipc::MAX_CPUS;

/// CPUs running the kernel: CPU 0 boots, the rest start in order.
pub static ONLINE: AtomicUsize = AtomicUsize::new(1);

/// The top-level table each CPU has loaded (0: the kernel's own, or not
/// known to be a user address space's).
static LOADED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Shootdown requests to each CPU: the latest one's number and what it
/// asks, and the number of the last one it carried out.
static REQUESTED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static DONE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static ROOT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static UNLOAD: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// A kick sent and not yet taken.
static KICKED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// CPUs online now.
pub fn online() -> usize {
    ONLINE.load(Ordering::Acquire)
}

/// This CPU has loaded the address space with top-level table `root`.
pub fn note_loaded(root: u64) {
    LOADED[arch::cpu_id()].store(root, Ordering::Release);
}

/// Carries out this CPU's outstanding shootdown request, if any. Safe in
/// any context with interrupts masked.
pub fn service() {
    let me = arch::cpu_id();
    let req = REQUESTED[me].load(Ordering::Acquire);
    if DONE[me].load(Ordering::Relaxed) == req {
        return;
    }
    let root = ROOT[me].load(Ordering::Relaxed);
    if arch::vm::current_root() == root {
        if UNLOAD[me].load(Ordering::Relaxed) {
            arch::vm::load_kernel_root();
            LOADED[me].store(0, Ordering::Release);
        } else {
            arch::vm::flush_local();
        }
    }
    DONE[me].store(req, Ordering::Release);
}

/// Makes every CPU forget mappings of the address space whose top-level
/// table is `root`: flush them from its TLB or, with `unload`, switch it
/// to the kernel's own tables. Returns once every CPU has. Called with
/// the kernel lock held.
pub fn shootdown(root: u64, unload: bool) {
    let me = arch::cpu_id();
    let mut waiting = [None; MAX_CPUS];
    for (x, w) in waiting.iter_mut().enumerate().take(online()) {
        if x == me || LOADED[x].load(Ordering::Acquire) != root {
            continue;
        }
        ROOT[x].store(root, Ordering::Relaxed);
        UNLOAD[x].store(unload, Ordering::Relaxed);
        let n = REQUESTED[x].fetch_add(1, Ordering::AcqRel) + 1;
        arch::send_ipi(x, arch::Ipi::Shootdown);
        *w = Some(n);
    }
    for (x, w) in waiting.iter().enumerate() {
        if let Some(n) = *w {
            while DONE[x].load(Ordering::Acquire) < n {
                core::hint::spin_loop();
            }
        }
    }
    if arch::vm::current_root() == root {
        if unload {
            arch::vm::load_kernel_root();
            LOADED[me].store(0, Ordering::Release);
        } else {
            arch::vm::flush_local();
        }
    }
}

/// Interrupts CPU `x` so it enters the kernel and reschedules, unless a
/// kick is already on its way.
pub fn kick(x: usize) {
    if !KICKED[x].swap(true, Ordering::AcqRel) {
        arch::send_ipi(x, arch::Ipi::Kick);
    }
}

/// CPU `x` is being started again after S3, with nothing loaded and no
/// request outstanding (none was made while it was off: the CPU that
/// slept held the kernel lock throughout).
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub fn restarted(x: usize) {
    LOADED[x].store(0, Ordering::Release);
    DONE[x].store(REQUESTED[x].load(Ordering::Acquire), Ordering::Release);
    KICKED[x].store(false, Ordering::Release);
}

/// This CPU is in the kernel and will reschedule: a kick may be sent again.
pub fn kicked() {
    KICKED[arch::cpu_id()].store(false, Ordering::Release);
}
