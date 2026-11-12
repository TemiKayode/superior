//! The architected generic timer: the EL1 virtual timer, a private
//! interrupt (PPI 11, ID 27), re-armed every tick.

pub const TICK_HZ: u32 = 100;
pub const INTID: u32 = 27;

static mut INTERVAL: u64 = 0;

/// Starts the tick and lets user mode read the virtual counter. Returns
/// the counter's frequency in Hz.
pub fn init() -> u64 {
    let freq: u64;
    // SAFETY: reading the counter frequency has no side effect.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack, nomem)) };
    let interval = (freq / TICK_HZ as u64).max(1);
    // SAFETY: written once at boot, before the timer is enabled.
    unsafe { (&raw mut INTERVAL).write(interval) };
    // SAFETY: CNTKCTL_EL1.EL0VCTEN (bit 1) lets user mode read
    // CNTVCT_EL0; the timer is enabled (bit 0) with its interrupt unmasked.
    unsafe {
        core::arch::asm!(
            "mrs {t}, cntkctl_el1",
            "orr {t}, {t}, #2",
            "msr cntkctl_el1, {t}",
            "msr cntv_tval_el0, {iv}",
            "mov {t}, #1",
            "msr cntv_ctl_el0, {t}",
            "isb",
            t = out(reg) _,
            iv = in(reg) interval,
            options(nostack)
        )
    };
    freq
}

/// Starts this CPU's tick (another CPU's: [`init`] ran first).
pub fn init_cpu() {
    // SAFETY: INTERVAL is only written in init, before any CPU starts.
    let interval = unsafe { (&raw const INTERVAL).read() };
    // SAFETY: as in `init`.
    unsafe {
        core::arch::asm!(
            "mrs {t}, cntkctl_el1",
            "orr {t}, {t}, #2",
            "msr cntkctl_el1, {t}",
            "msr cntv_tval_el0, {iv}",
            "mov {t}, #1",
            "msr cntv_ctl_el0, {t}",
            "isb",
            t = out(reg) _,
            iv = in(reg) interval,
            options(nostack)
        )
    };
}

/// The virtual counter.
pub fn counter() -> u64 {
    let v: u64;
    // SAFETY: reading the counter has no side effect.
    unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nostack)) };
    v
}

/// The counter's frequency, in Hz.
pub fn frequency() -> u64 {
    let f: u64;
    // SAFETY: reading the frequency has no side effect.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nostack, nomem)) };
    f
}

/// Schedules the next tick, which also clears this one.
pub fn rearm() {
    // SAFETY: INTERVAL is only written in init.
    let interval = unsafe { (&raw const INTERVAL).read() };
    // SAFETY: reloading the timer's countdown.
    unsafe { core::arch::asm!("msr cntv_tval_el0, {}", "isb", in(reg) interval, options(nostack)) };
}

/// When the alarm [`alarm`] set is due, on the virtual counter.
static mut ALARM_AT: u64 = 0;

/// Stops this CPU's tick.
pub fn tick_stop() {
    // SAFETY: disabling the timer only stops its interrupt.
    unsafe { core::arch::asm!("msr cntv_ctl_el0, xzr", "isb", options(nostack)) };
}

/// Starts this CPU's tick again after [`tick_stop`].
pub fn tick_start() {
    init_cpu();
}

/// Has the timer interrupt this CPU once, `ticks` ticks from now, instead
/// of every tick. Its handler's [`rearm`] then starts the tick again.
/// Returns the ticks it will wait (the countdown is 32 bits).
pub fn alarm(ticks: u64) -> u64 {
    // SAFETY: INTERVAL is only written in init.
    let interval = unsafe { (&raw const INTERVAL).read() };
    let ticks = ticks.clamp(1, u32::MAX as u64 / interval);
    let count = ticks * interval;
    // SAFETY: written only by the CPU that keeps the system's time.
    unsafe { (&raw mut ALARM_AT).write(counter() + count) };
    // SAFETY: loading the countdown and enabling the timer.
    unsafe {
        core::arch::asm!(
            "msr cntv_tval_el0, {c}",
            "mov {t}, #1",
            "msr cntv_ctl_el0, {t}",
            "isb",
            c = in(reg) count,
            t = out(reg) _,
            options(nostack)
        )
    };
    ticks
}

/// Has the alarm [`alarm`] set come due (rather than a tick from before)?
pub fn alarm_fired() -> bool {
    // SAFETY: as in `alarm`.
    counter() >= unsafe { (&raw const ALARM_AT).read() }
}

/// Sets the countdown back to the alarm, after a tick from before it
/// arrived and its handler's [`rearm`] replaced the alarm with a tick.
pub fn alarm_keep() {
    // SAFETY: as in `alarm`.
    let left = unsafe { (&raw const ALARM_AT).read() }.saturating_sub(counter()).max(1);
    // SAFETY: reloading the countdown.
    unsafe { core::arch::asm!("msr cntv_tval_el0, {}", "isb", in(reg) left, options(nostack)) };
}
