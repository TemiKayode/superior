//! The PL011 UART the firmware names: the kernel's debug console. The
//! shell drives the same UART from user space for its own console.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// The registers; 0 until found, and until then output goes nowhere.
static BASE: AtomicU64 = AtomicU64::new(0);
const DR: u64 = 0x00;
const FR: u64 = 0x18;
const FR_TXFF: u32 = 1 << 5;

struct Pl011;

impl Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let base = BASE.load(Ordering::Relaxed);
        if base == 0 {
            return Ok(());
        }
        for b in s.bytes() {
            // SAFETY: PL011 registers, mapped as device memory.
            unsafe {
                while core::ptr::read_volatile(super::vm::phys_ptr(base + FR) as *const u32) & FR_TXFF != 0 {
                    core::hint::spin_loop();
                }
                core::ptr::write_volatile(super::vm::phys_ptr(base + DR) as *mut u32, b as u32);
            }
        }
        Ok(())
    }
}

static CONSOLE: Mutex<Pl011> = Mutex::new(Pl011);

/// The console's registers, mapped (the firmware has set it up).
pub fn init(base: u64) {
    BASE.store(base, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // The kernel runs with interrupts masked, so a handler that logs can
    // never interrupt code holding the lock.
    let _ = CONSOLE.lock().write_fmt(args);
    crate::dbc::print(args);
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::serial::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => { $crate::kprint!("{}\n", format_args!($($arg)*)) };
}
