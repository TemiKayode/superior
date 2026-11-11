//! Linux's 8139cp driver (RealTek RTL-8139C+), unmodified, as a
//! component: `drivers/net/ethernet/realtek/8139cp.c` from Linux 6.6,
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
    superior_lde::run("8139cp")
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    superior_sys::print_line(format_args!("lde 8139cp: panic: {info}"));
    superior_sys::park()
}
