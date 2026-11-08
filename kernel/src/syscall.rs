//! `syscall` / `sysret` entry and exit.
//!
//! Entry saves the full user register state into a [`UserFrame`] on the
//! kernel stack and calls [`crate::task::handle_syscall`], which copies it
//! into the current thread's TCB, runs the operation, and overwrites the
//! frame with the registers of whichever thread should run next. Exit pops
//! that frame and `sysret`s, so a thread switch is just a different frame.
//!
//! Interrupts stay disabled for the whole kernel entry (SFMASK clears IF);
//! the kernel is single-core and non-preemptible for now.

use crate::gdt;
use core::arch::naked_asm;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

/// User registers as pushed by [`syscall_entry`], lowest address first.
/// `rcx` and `r11` are not saved: `syscall` overwrites them with the
/// user `rip` and `rflags`, which are saved instead.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UserFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl UserFrame {
    /// A fresh thread: interrupts enabled, `rdi` = its start argument.
    /// `rsp` is 8 below a 16-byte boundary, as if `entry` had been called.
    pub fn new_thread(entry: u64, stack_top: u64, arg: u64) -> Self {
        UserFrame {
            rip: entry,
            rsp: stack_top - 8,
            rflags: (RFlags::INTERRUPT_FLAG | RFlags::from_bits_retain(1 << 1)).bits(),
            rdi: arg,
            ..Default::default()
        }
    }
}

static mut USER_RSP_SCRATCH: u64 = 0;
static mut KERNEL_STACK_TOP: u64 = 0;
/// Frame used for the very first entry to user mode.
static mut FIRST_FRAME: UserFrame = UserFrame {
    r15: 0,
    r14: 0,
    r13: 0,
    r12: 0,
    r10: 0,
    r9: 0,
    r8: 0,
    rbp: 0,
    rdi: 0,
    rsi: 0,
    rdx: 0,
    rbx: 0,
    rax: 0,
    rip: 0,
    rflags: 0,
    rsp: 0,
};

pub fn init() {
    // SAFETY: single-threaded boot; written once before any syscall.
    unsafe { (&raw mut KERNEL_STACK_TOP).write(gdt::kernel_stack_top()) };
    let s = gdt::selectors();
    Star::write(s.user_code, s.user_data, s.kernel_code, s.kernel_data)
        .expect("GDT layout incompatible with sysret");
    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));
    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::ALIGNMENT_CHECK,
    );
    // SAFETY: enabling syscall/sysret and the NX bit changes no existing mapping.
    unsafe {
        Efer::update(|f| *f |= EferFlags::SYSTEM_CALL_EXTENSIONS | EferFlags::NO_EXECUTE_ENABLE)
    };
}

/// Enters user mode for the first time with `frame`'s registers.
pub fn enter_user(frame: UserFrame) -> ! {
    // SAFETY: FIRST_FRAME is only touched here, with interrupts disabled,
    // and is fully consumed by restore_user before anything else runs.
    unsafe {
        (&raw mut FIRST_FRAME).write(frame);
        enter_user_asm(&raw const FIRST_FRAME)
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_user_asm(_frame: *const UserFrame) -> ! {
    naked_asm!("mov rsp, rdi", "jmp {restore}", restore = sym restore_user)
}

/// The LSTAR target. On entry: rcx = user rip, r11 = user rflags,
/// rsp = user stack, interrupts off.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "mov [rip + {scratch}], rsp",
        "mov rsp, [rip + {kstack}]",
        "push qword ptr [rip + {scratch}]", // rsp
        "push r11",                         // rflags
        "push rcx",                         // rip
        "push rax",
        "push rbx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "call {dispatch}",
        "jmp {restore}",
        scratch = sym USER_RSP_SCRATCH,
        kstack = sym KERNEL_STACK_TOP,
        dispatch = sym syscall_dispatch,
        restore = sym restore_user,
    )
}

/// Pops a [`UserFrame`] at rsp and returns to user mode.
///
/// `sysret` with a non-canonical rip faults in ring 0 on Intel CPUs. The
/// rip here always comes from a `syscall` instruction or from an ELF entry
/// point checked to lie in the user window, so it is canonical.
#[unsafe(naked)]
unsafe extern "C" fn restore_user() -> ! {
    naked_asm!(
        "pop r15", "pop r14", "pop r13", "pop r12", "pop r10", "pop r9", "pop r8", "pop rbp",
        "pop rdi", "pop rsi", "pop rdx", "pop rbx", "pop rax", "pop rcx", // rip
        "pop r11", // rflags
        "pop rsp", "sysretq",
    )
}

extern "C" fn syscall_dispatch(frame: &mut UserFrame) {
    crate::task::handle_syscall(frame);
}
