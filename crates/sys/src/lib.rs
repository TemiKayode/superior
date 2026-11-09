//! User-side system call wrappers for Superior.
//!
//! One ABI on both instruction sets, by position:
//!
//! | Role | x86-64 | AArch64 |
//! | --- | --- | --- |
//! | number in, status out | `rax` | `x8` |
//! | capability in, badge out | `rdi` | `x0` |
//! | message words 0-3, both ways | `rsi`, `rdx`, `r8`, `r9` | `x1`-`x4` |
//! | transfer word in, received slot + 1 out | `r10` | `x5` |
//! | trap instruction | `syscall` (clobbers `rcx`, `r11`) | `svc #0` |
//!
//! The kernel preserves every other register.

#![no_std]

use superior_objects::abi::{CapTransfer, MSG_WORDS, Syscall};

/// What a system call returns.
#[derive(Clone, Copy, Debug)]
pub struct Ret {
    pub status: u64,
    pub badge: u64,
    pub msg: [u64; MSG_WORDS],
    /// Slot a capability arrived in, if any.
    pub cap: Option<u16>,
}

/// A system call with no capability transfer.
#[inline(always)]
pub fn syscall(nr: Syscall, a0: u64, m: [u64; MSG_WORDS]) -> Ret {
    syscall_x(nr, a0, m, CapTransfer::NONE)
}

/// A system call that may grant and accept a capability.
#[inline(always)]
pub fn syscall_x(nr: Syscall, a0: u64, m: [u64; MSG_WORDS], x: CapTransfer) -> Ret {
    let (status, badge, m0, m1, m2, m3, cap): (u64, u64, u64, u64, u64, u64, u64);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the kernel preserves every register except rax, rdi, rsi,
    // rdx, r8, r9, r10 (outputs) and rcx, r11 (clobbered by `syscall`).
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as u64 => status,
            inlateout("rdi") a0 => badge,
            inlateout("rsi") m[0] => m0,
            inlateout("rdx") m[1] => m1,
            inlateout("r8") m[2] => m2,
            inlateout("r9") m[3] => m3,
            inlateout("r10") x.encode() => cap,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the kernel preserves every register except x0-x5 and x8
    // (outputs).
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x8") nr as u64 => status,
            inlateout("x0") a0 => badge,
            inlateout("x1") m[0] => m0,
            inlateout("x2") m[1] => m1,
            inlateout("x3") m[2] => m2,
            inlateout("x4") m[3] => m3,
            inlateout("x5") x.encode() => cap,
            options(nostack),
        );
    }
    Ret {
        status,
        badge,
        msg: [m0, m1, m2, m3],
        cap: if cap == 0 { None } else { Some(cap as u16 - 1) },
    }
}

/// A cycle-ish counter for timing: the time-stamp counter on x86-64, the
/// virtual counter (`CNTVCT_EL0`, which the kernel lets user mode read) on
/// AArch64. Neither counts core cycles exactly; under emulation neither
/// means anything.
#[inline(always)]
pub fn cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rdtsc has no preconditions.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let v: u64;
        // SAFETY: reading the virtual counter; the kernel enables EL0
        // access (CNTKCTL_EL1.EL0VCTEN). `isb` keeps the read in order.
        unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nostack)) };
        v
    }
}

/// The instruction set, for messages.
pub const ARCH: &str = if cfg!(target_arch = "aarch64") {
    "AArch64"
} else {
    "x86-64"
};
