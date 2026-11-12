//! Linux's bochs display driver, unmodified, as a component:
//! `drivers/gpu/drm/tiny/bochs.c` from Linux 6.6, for QEMU's
//! `bochs-display` (and its standard VGA), compiled against the Linux
//! Driver Environment's headers, its DRM ones too, and linked here with
//! its host (`superior_lde`), which finds the device from the driver's
//! own ID table and serves the `display` interface with it.
//!
//! Slots, as the environment wants them (in a CSpace of 2^11): 0 the bus
//! server, 1 the `display` endpoint (receive), 2 a notification, 3
//! untyped memory (1 MiB).

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    superior_lde::run_display("bochs")
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    superior_sys::print_line(format_args!("lde bochs: panic: {info}"));
    superior_sys::park()
}
