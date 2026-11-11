//! Linux's e100 driver (Intel 8255x PRO/100), unmodified, as a
//! component: `drivers/net/ethernet/intel/e100.c` from Linux 6.6,
//! compiled against the Linux Driver Environment's headers and linked
//! here with its host (`superior_lde`), which finds the device from the
//! driver's own ID table and serves the `nic` interface with it.
//!
//! Slots, as the environment wants them (in a CSpace of 2^8): 0 the bus server, 1 the `nic`
//! endpoint (receive), 2 a notification, 3 untyped memory (1 MiB).

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    superior_lde::run("e100")
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    superior_sys::print_line(format_args!("lde e100: panic: {info}"));
    superior_sys::park()
}
