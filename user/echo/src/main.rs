//! A test service for the Component Manager. It answers each call with
//! the value it was sent plus one, the badge it arrived with (which client
//! called), and how many calls this instance has served.
//!
//! Slot 0: the receive side of its service endpoint.

#![no_std]
#![no_main]

use superior_objects::abi::Syscall;
use superior_sys::syscall;

const SERVICE: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    superior_sys::print_line(format_args!("echo: running in its own address space"));
    let mut served = 0u64;
    let mut r = syscall(Syscall::Recv, SERVICE, [0; 4]);
    loop {
        served += 1;
        let reply = [r.msg[0].wrapping_add(1), r.badge, served, 0];
        r = syscall(Syscall::ReplyRecv, SERVICE, reply);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
