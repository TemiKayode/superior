//! A test service for the Component Manager. It answers each call with
//! the value it was sent plus one, the badge it arrived with (which client
//! called), and how many calls this instance has served.
//!
//! Its argument: the slot holding the receive side of its service endpoint
//! (0 unless the manifest says otherwise).

#![no_std]
#![no_main]

use superior_objects::abi::Syscall;
use superior_sys::syscall;

#[unsafe(no_mangle)]
pub extern "C" fn _start(service: u64) -> ! {
    superior_sys::print_line(format_args!("echo: running in its own address space"));
    if service != 0 {
        superior_sys::print_line(format_args!("echo: serving through slot {service}"));
    }
    let mut served = 0u64;
    let mut r = syscall(Syscall::Recv, service, [0; 4]);
    loop {
        served += 1;
        let reply = [r.msg[0].wrapping_add(1), r.badge, served, 0];
        r = syscall(Syscall::ReplyRecv, service, reply);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    superior_sys::park()
}
