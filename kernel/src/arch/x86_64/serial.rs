//! COM1 serial console, and until user space starts the boot framebuffer
//! too (`super::fbcon`), and USB's debug capability (`crate::dbc`). Everything here is debug output; user-facing
//! consoles are user-space services.

use core::fmt::{self, Write};
use spin::{Lazy, Mutex};
use uart_16550::SerialPort;

static COM1: Lazy<Mutex<SerialPort>> = Lazy::new(|| {
    // SAFETY: 0x3F8 is the standard COM1 base; nothing else in the kernel
    // touches these ports.
    let mut port = unsafe { SerialPort::new(0x3F8) };
    port.init();
    Mutex::new(port)
});

pub fn init() {
    Lazy::force(&COM1);
}

/// Programs COM1 again (after S3, which resets it).
pub fn reinit() {
    COM1.lock().init();
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Interrupts off while holding the lock, so a handler that logs cannot
    // deadlock against the code it interrupted.
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _ = COM1.lock().write_fmt(args);
        super::fbcon::print(args);
        crate::dbc::print(args);
    });
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
