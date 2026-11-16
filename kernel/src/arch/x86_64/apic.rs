//! The local APIC: each CPU's timer, and interrupts between CPUs.
//!
//! The timer runs in periodic mode at [`TICK_HZ`] on vector
//! [`TIMER_VECTOR`]. Its input clock (bus or crystal) differs between
//! machines, so it is calibrated once at boot against the legacy PIT,
//! whose 1.193182 MHz rate is fixed; the other CPUs reuse the result.
//!
//! CPUs interrupt each other through the interrupt command register: a
//! kick ([`KICK_VECTOR`]), a shootdown request ([`SHOOTDOWN_VECTOR`]), and
//! INIT and start-up messages to start a CPU. A CPU's number is its APIC
//! ID.

use super::vm;
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;

pub const TIMER_VECTOR: u8 = 0x30;
pub const KICK_VECTOR: u8 = 0x50;
pub const SHOOTDOWN_VECTOR: u8 = 0x51;
/// The IOMMU's fault event interrupt.
pub const IOMMU_VECTOR: u8 = 0x52;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const TICK_HZ: u32 = 100;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

// Register offsets.
const ID: usize = 0x20;
const EOI: usize = 0xb0;
const ICR_LOW: usize = 0x300;
const ICR_HIGH: usize = 0x310;
const ICR_PENDING: u32 = 1 << 12;
const ICR_INIT: u32 = 0b101 << 8 | 1 << 14;
const ICR_STARTUP: u32 = 0b110 << 8 | 1 << 14;
const SPURIOUS: usize = 0xf0;
const LVT_TIMER: usize = 0x320;
const INITIAL_COUNT: usize = 0x380;
const CURRENT_COUNT: usize = 0x390;
const DIVIDE: usize = 0x3e0;

const SOFTWARE_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
const DIVIDE_BY_16: u32 = 0b0011;

const PIT_HZ: u32 = 1_193_182;
const CALIBRATION_MS: u32 = 10;

static mut BASE: usize = 0;
/// Timer counts per tick, from the calibration.
static mut PER_TICK: u32 = 0;

fn read(reg: usize) -> u32 {
    // SAFETY: BASE maps the local APIC's register page (set in init).
    unsafe { core::ptr::read_volatile(((&raw const BASE).read() + reg) as *const u32) }
}

fn write(reg: usize, value: u32) {
    // SAFETY: as in `read`.
    unsafe { core::ptr::write_volatile(((&raw const BASE).read() + reg) as *mut u32, value) }
}

/// Maps and enables the local APIC, calibrates its timer, and starts it.
/// Returns the timer's input frequency in Hz (after the divider).
///
/// Must run before any address space is created: the mapping goes into
/// kernel page tables that every address space shares.
pub fn init() -> u64 {
    let mut msr = Msr::new(IA32_APIC_BASE);
    // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU.
    let base = unsafe { msr.read() };
    if base & APIC_GLOBAL_ENABLE == 0 {
        // SAFETY: setting the global enable bit only turns the APIC on.
        unsafe { msr.write(base | APIC_GLOBAL_ENABLE) };
    }
    let va = vm::map_mmio(PhysAddr::new(base & 0xf_ffff_f000)).expect("mapping the local APIC");
    // SAFETY: written once at boot before any register access.
    unsafe { (&raw mut BASE).write(va.as_u64() as usize) };

    write(SPURIOUS, SOFTWARE_ENABLE | SPURIOUS_VECTOR as u32);
    write(DIVIDE, DIVIDE_BY_16);
    write(LVT_TIMER, LVT_MASKED | TIMER_VECTOR as u32);

    let per_calibration = calibrate();
    let hz = per_calibration as u64 * 1000 / CALIBRATION_MS as u64;
    let per_tick = (hz / TICK_HZ as u64).max(1) as u32;

    // SAFETY: written once at boot, before any other CPU starts.
    unsafe { (&raw mut PER_TICK).write(per_tick) };
    write(LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, per_tick);
    hz
}

/// Enables another CPU's APIC and starts its timer, at CPU 0's rate.
pub fn init_ap() {
    let mut msr = Msr::new(IA32_APIC_BASE);
    // SAFETY: as in `init`.
    let base = unsafe { msr.read() };
    if base & APIC_GLOBAL_ENABLE == 0 {
        // SAFETY: as in `init`.
        unsafe { msr.write(base | APIC_GLOBAL_ENABLE) };
    }
    write(SPURIOUS, SOFTWARE_ENABLE | SPURIOUS_VECTOR as u32);
    write(DIVIDE, DIVIDE_BY_16);
    // SAFETY: written before any other CPU started.
    let per_tick = unsafe { (&raw const PER_TICK).read() };
    write(LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, per_tick);
}

/// After S3, which resets it: enables CPU 0's APIC again, with its tick
/// stopped (the suspend's end starts it).
pub fn resume() {
    init_ap();
    tick_stop();
}

/// Stops this CPU's tick.
pub fn tick_stop() {
    write(LVT_TIMER, LVT_MASKED | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, 0);
}

/// Starts this CPU's tick again after [`tick_stop`] or an [`alarm`].
pub fn tick_start() {
    // SAFETY: written once at boot.
    let per_tick = unsafe { (&raw const PER_TICK).read() };
    write(LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, per_tick);
}

/// Has the timer interrupt this CPU once, `ticks` ticks from now, instead
/// of every tick, until [`tick_start`]. Returns the ticks it will wait
/// (the count is 32 bits).
pub fn alarm(ticks: u64) -> u64 {
    // SAFETY: written once at boot.
    let per_tick = unsafe { (&raw const PER_TICK).read() } as u64;
    let ticks = ticks.clamp(1, u32::MAX as u64 / per_tick);
    write(LVT_TIMER, TIMER_VECTOR as u32);
    write(INITIAL_COUNT, (ticks * per_tick) as u32);
    ticks
}

/// Keeps the alarm after a tick from before it arrived: the alarm is
/// untouched here, as a one-shot count is not reloaded by its interrupt.
pub fn alarm_keep() {}

/// Has the alarm [`alarm`] set come due (rather than a tick from before)?
/// A one-shot count stays at zero once it has run out.
pub fn alarm_fired() -> bool {
    read(LVT_TIMER) & LVT_PERIODIC == 0 && read(CURRENT_COUNT) == 0
}

/// This CPU's APIC ID (0 before the APIC is mapped: only CPU 0 runs then).
pub fn id() -> usize {
    // SAFETY: BASE is written once at boot.
    if unsafe { (&raw const BASE).read() } == 0 {
        return 0;
    }
    (read(ID) >> 24) as usize
}

fn command(apic: usize, low: u32) {
    while read(ICR_LOW) & ICR_PENDING != 0 {
        core::hint::spin_loop();
    }
    write(ICR_HIGH, (apic as u32) << 24);
    write(ICR_LOW, low);
}

/// Sends `vector` to the CPU with APIC ID `apic` (fixed, physical, edge).
pub fn send_ipi(apic: usize, vector: u8) {
    command(apic, vector as u32);
}

/// Starts the CPU with APIC ID `apic` at physical page `page` (below
/// 1 MiB), in real mode: INIT, then start-up twice, as Intel prescribes.
pub fn start_cpu(apic: usize, page: u64) {
    command(apic, ICR_INIT);
    delay_us(10_000);
    for _ in 0..2 {
        command(apic, ICR_STARTUP | (page >> 12) as u32);
        delay_us(200);
    }
}

/// Waits `us` microseconds by the PIT (channel 2, polled).
pub fn delay_us(us: u64) {
    let mut gate = Port::<u8>::new(0x61);
    let mut command = Port::<u8>::new(0x43);
    let mut channel2 = Port::<u8>::new(0x42);
    let mut left = us * PIT_HZ as u64 / 1_000_000;
    while left > 0 {
        let count = left.min(0xffff) as u16;
        left -= count as u64;
        // SAFETY: as in `calibrate`.
        unsafe {
            let g = gate.read();
            gate.write((g & !0x02) | 0x01);
            command.write(0b1011_0000);
            channel2.write(count as u8);
            channel2.write((count >> 8) as u8);
            let g = gate.read();
            gate.write(g & !0x01);
            gate.write(g | 0x01);
            while gate.read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
        }
    }
}

/// Counts APIC timer decrements during [`CALIBRATION_MS`] of PIT time,
/// using PIT channel 2 in one-shot mode (its output is readable on port
/// 0x61 bit 5, so no PIT interrupt is needed).
fn calibrate() -> u32 {
    let mut gate = Port::<u8>::new(0x61);
    let mut command = Port::<u8>::new(0x43);
    let mut channel2 = Port::<u8>::new(0x42);
    let count = PIT_HZ / (1000 / CALIBRATION_MS);
    // SAFETY: standard PIT channel 2 programming on its fixed ports.
    unsafe {
        // Gate on, speaker off.
        let g = gate.read();
        gate.write((g & !0x02) | 0x01);
        // Channel 2, lobyte/hibyte, mode 0 (interrupt on terminal count), binary.
        command.write(0b1011_0000);
        channel2.write(count as u8);
        channel2.write((count >> 8) as u8);
        // Restart the count: gate low, then high.
        let g = gate.read();
        gate.write(g & !0x01);
        gate.write(g | 0x01);
    }
    write(INITIAL_COUNT, u32::MAX);
    // SAFETY: reading the PIT status bit.
    while unsafe { gate.read() } & 0x20 == 0 {
        core::hint::spin_loop();
    }
    let elapsed = u32::MAX - read(CURRENT_COUNT);
    write(INITIAL_COUNT, 0); // stop
    elapsed
}

/// Signals end of interrupt for the in-service interrupt.
pub fn end_of_interrupt() {
    write(EOI, 0);
}
