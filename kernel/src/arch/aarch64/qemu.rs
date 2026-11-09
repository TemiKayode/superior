//! Ending a QEMU run with an exit status, through Arm semihosting
//! (`SYS_EXIT` with `ADP_Stopped_ApplicationExit`). QEMU must be started
//! with `-semihosting-config enable=on,target=native`; without it the
//! `hlt` traps as an undefined instruction.

const SYS_EXIT: u64 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;

pub fn exit_status(status: u32) -> ! {
    let block = [ADP_STOPPED_APPLICATION_EXIT, status as u64];
    // SAFETY: the semihosting call reads the two-word block and ends QEMU.
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") SYS_EXIT,
            in("x1") block.as_ptr(),
            options(nostack)
        )
    };
    super::halt_forever()
}
