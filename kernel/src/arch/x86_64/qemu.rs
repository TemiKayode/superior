//! QEMU's isa-debug-exit device, used by self-tests to report a result as
//! the emulator's exit status: QEMU exits with `(code << 1) | 1`.

#![cfg_attr(not(feature = "selftest"), allow(dead_code))]

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10, // QEMU status 33
    Failure = 0x11, // QEMU status 35
}

pub fn exit(code: ExitCode) -> ! {
    use x86_64::instructions::port::Port;
    // SAFETY: port 0xf4 is the isa-debug-exit device xtask attaches.
    unsafe { Port::new(0xf4).write(code as u32) };
    // Not under QEMU (or no device): stop here.
    loop {
        x86_64::instructions::hlt();
    }
}
