//! The local APIC timer: the kernel's only interrupt source.
//!
//! The timer runs in periodic mode at [`TICK_HZ`] on vector
//! [`TIMER_VECTOR`]. Its input clock (bus or crystal) differs between
//! machines, so it is calibrated once at boot against the legacy PIT,
//! whose 1.193182 MHz rate is fixed.
//!
//! Device interrupts are not routed here: in Superior they reach user-space
//! drivers as notifications, which needs the IOAPIC and comes later.

use crate::vm;
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;

pub const TIMER_VECTOR: u8 = 0x30;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const TICK_HZ: u32 = 100;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

// Register offsets.
const EOI: usize = 0xb0;
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

    write(LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, per_tick);
    hz
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
