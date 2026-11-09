//! The PL011 UART on QEMU's `virt` machine: the kernel's debug console.
//! The shell drives the same UART from user space for its own console.

use core::fmt::{self, Write};
use spin::Mutex;

const BASE: u64 = 0x0900_0000;
const DR: u64 = 0x00;
const FR: u64 = 0x18;
const FR_TXFF: u32 = 1 << 5;

struct Pl011;

impl Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            // SAFETY: PL011 registers, identity-mapped as device memory.
            unsafe {
                while core::ptr::read_volatile((BASE + FR) as *const u32) & FR_TXFF != 0 {
                    core::hint::spin_loop();
                }
                core::ptr::write_volatile((BASE + DR) as *mut u32, b as u32);
            }
        }
        Ok(())
    }
}

static CONSOLE: Mutex<Pl011> = Mutex::new(Pl011);

/// QEMU's PL011 needs no set-up.
pub fn init() {}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // The kernel runs with interrupts masked, so a handler that logs can
    // never interrupt code holding the lock.
    let _ = CONSOLE.lock().write_fmt(args);
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
