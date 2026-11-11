//! Kernel entry and exit: `syscall`, hardware interrupts, `sysret`, `iretq`.
//!
//! Both entry paths build the same [`UserFrame`] on the kernel stack. Its
//! top five words are exactly what the CPU pushes on an interrupt from ring
//! 3 (`ss`, `rsp`, `rflags`, `cs`, `rip`); the `syscall` entry pushes the
//! same five by hand. The Rust handler copies the frame into the current
//! thread's TCB, does its work, overwrites the frame with the registers of
//! the thread to run next, and returns how to leave:
//!
//! - [`Exit::Sysret`] (fast): for threads that last left user mode through
//!   `syscall`, whose `rcx`/`r11` are dead by the ABI, or that never ran.
//! - [`Exit::Iret`] (complete): for threads that were interrupted, whose
//!   every register must come back exactly.
//!
//! Interrupts stay disabled for the whole kernel entry; the kernel is
//! non-preemptible, and only user mode (and the idle halt) is
//! interruptible.
//!
//! Each CPU has its own kernel stack. Interrupts find it through the CPU's
//! TSS; `syscall`, which switches no stack, through the CPU's [`PerCpu`]
//! block, whose address is in `IA32_KERNEL_GS_BASE`: the entry swaps it in
//! with `swapgs` just long enough to switch stacks.

use super::gdt;
use crate::smp::MAX_CPUS;
use core::arch::naked_asm;
use superior_objects::abi::FaultKind;
use x86_64::registers::model_specific::{Efer, EferFlags, KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

/// User segment selectors (GDT index 3 and 4, RPL 3), checked in [`init`].
pub const USER_SS: u64 = 0x1b;
pub const USER_CS: u64 = 0x23;

/// Saved user registers, lowest address first.
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
    pub rcx: u64,
    pub r11: u64,
    // The interrupt-return frame.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl UserFrame {
    pub const ZERO: UserFrame = UserFrame {
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
        rcx: 0,
        r11: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
        rsp: 0,
        ss: 0,
    };

    /// A fresh thread: interrupts enabled, `rdi` = its start argument.
    /// `rsp` is 8 below a 16-byte boundary, as if `entry` had been called.
    pub fn new_thread(entry: u64, stack_top: u64, arg: u64) -> Self {
        UserFrame {
            rip: entry,
            cs: USER_CS,
            rsp: stack_top - 8,
            ss: USER_SS,
            rflags: (RFlags::INTERRUPT_FLAG | RFlags::from_bits_retain(1 << 1)).bits(),
            rdi: arg,
            ..UserFrame::ZERO
        }
    }

    pub fn is_user_mode(&self) -> bool {
        self.cs & 3 == 3
    }

    /// The system call number and its six argument registers.
    pub fn args(&self) -> Args {
        Args {
            nr: self.rax,
            a0: self.rdi,
            a1: self.rsi,
            a2: self.rdx,
            a3: self.r8,
            a4: self.r9,
            a5: self.r10,
        }
    }

    /// Delivers a system call's results: status, badge, message and the
    /// received-capability word, in the registers the ABI names.
    pub fn set_results(&mut self, status: u64, badge: u64, msg: [u64; 4], cap: u64) {
        self.rax = status;
        self.rdi = badge;
        [self.rsi, self.rdx, self.r8, self.r9] = msg;
        self.r10 = cap;
    }

    /// The user instruction pointer.
    pub fn pc(&self) -> u64 {
        self.rip
    }

    /// Points back at the `syscall` that entered the kernel (two bytes),
    /// so the system call is made again. Its `rcx` and `r11` were already
    /// lost to the ABI.
    pub fn rewind_syscall(&mut self) {
        self.rip -= 2;
    }

    /// Resumes at `pc` with `value` in the first result register (`rax`).
    pub fn resume_at(&mut self, pc: u64, value: u64) {
        self.rip = pc;
        self.rax = value;
    }
}

/// A system call's number and arguments, independent of register names:
/// `a0` names the capability, `a1`..`a4` are the message words and `a5`
/// the capability-transfer word.
#[derive(Clone, Copy, Debug)]
pub struct Args {
    pub nr: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}

/// How to return to user mode; the handler's return value in `rax`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Sysret = 0,
    Iret = 1,
}

/// What the `syscall` entry needs of its CPU: somewhere to keep the user
/// stack pointer, and the CPU's kernel stack.
#[repr(C)]
pub struct PerCpu {
    scratch: u64,
    kernel_stack: u64,
}

static mut PER_CPU: [PerCpu; MAX_CPUS] = [const {
    PerCpu {
        scratch: 0,
        kernel_stack: 0,
    }
}; MAX_CPUS];

/// Sets up `syscall` on CPU `cpu` (its GDT is loaded).
pub fn init(cpu: usize) {
    // SAFETY: each CPU writes its own block, once, before its first
    // system call.
    let block = unsafe {
        let b = &raw mut PER_CPU[cpu];
        (&raw mut (*b).kernel_stack).write(gdt::kernel_stack_top(cpu));
        b
    };
    KernelGsBase::write(VirtAddr::from_ptr(block));
    let s = gdt::selectors();
    assert_eq!(
        s.user_data.0 as u64, USER_SS,
        "GDT user data selector moved"
    );
    assert_eq!(
        s.user_code.0 as u64, USER_CS,
        "GDT user code selector moved"
    );
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

/// Enters user mode for the first time on this CPU with `frame`'s
/// registers, from the top of its kernel stack (where every later entry
/// from user mode starts).
pub fn enter_user(frame: UserFrame) -> ! {
    let at = (gdt::kernel_stack_top(super::cpu_id()) - core::mem::size_of::<UserFrame>() as u64)
        as *mut UserFrame;
    // SAFETY: the top of this CPU's stack is free (boot ran below it), and
    // the frame is consumed by return_to_user before anything else runs.
    unsafe {
        at.write(frame);
        enter_user_asm(at)
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_user_asm(_frame: *const UserFrame) -> ! {
    naked_asm!(
        "mov rsp, rdi",
        "mov eax, {iret}",
        "jmp {ret}",
        iret = const Exit::Iret as u64,
        ret = sym return_to_user,
    )
}

/// The LSTAR target. On entry: rcx = user rip, r11 = user rflags,
/// rsp = user stack, interrupts off.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // This CPU's block, briefly: the user stack pointer kept in it,
        // the kernel stack from it.
        "swapgs",
        "mov gs:[0], rsp",
        "mov rsp, gs:[8]",
        // The interrupt-return frame, built by hand.
        "push {ss}",
        "push qword ptr gs:[0]",
        "swapgs",
        "push r11", // rflags
        "push {cs}",
        "push rcx", // rip
        // General registers, same order as the interrupt entry.
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "call {handler}",
        "jmp {ret}",
        ss = const USER_SS,
        cs = const USER_CS,
        handler = sym syscall_handler,
        ret = sym return_to_user,
    )
}

/// Entry for the timer interrupt. The CPU has switched to the kernel stack
/// (TSS rsp0) and pushed the interrupt-return frame.
#[unsafe(naked)]
pub unsafe extern "C" fn timer_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "call {handler}",
        "jmp {ret}",
        handler = sym timer_handler,
        ret = sym return_to_user,
    )
}

/// Entry for a kick from another CPU: reschedule.
#[unsafe(naked)]
pub unsafe extern "C" fn kick_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "call {handler}",
        "jmp {ret}",
        handler = sym kick_handler,
        ret = sym return_to_user,
    )
}

/// Entry for the IOMMU's fault event: drain its fault records.
#[unsafe(naked)]
pub unsafe extern "C" fn iommu_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "call {handler}",
        "jmp {ret}",
        handler = sym iommu_handler,
        ret = sym return_to_user,
    )
}

extern "C" fn iommu_handler(frame: &mut UserFrame) -> Exit {
    super::apic::end_of_interrupt();
    crate::task::handle_io_fault_irq(frame)
}

/// Entry for COM1's interrupt (legacy PIC line 4), delivered to the
/// serial driver as a notification.
#[unsafe(naked)]
pub unsafe extern "C" fn com1_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "call {handler}",
        "jmp {ret}",
        handler = sym com1_handler,
        ret = sym return_to_user,
    )
}

// CPU exception entries. Each builds the same UserFrame as the timer entry
// and passes the fault kind and error code. For exceptions that push an
// error code, the code sits where the saved r11 belongs: swap them.

#[unsafe(naked)]
pub unsafe extern "C" fn page_fault_entry() {
    naked_asm!(
        "xchg [rsp], r11", // error code out, saved r11 in its slot
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "mov esi, {kind}",
        "mov rdx, r11",
        "call {handler}",
        "jmp {ret}",
        kind = const FaultKind::PageFault as u64,
        handler = sym fault_handler,
        ret = sym return_to_user,
    )
}

#[unsafe(naked)]
pub unsafe extern "C" fn general_protection_entry() {
    naked_asm!(
        "xchg [rsp], r11", // error code out, saved r11 in its slot
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "mov esi, {kind}",
        "mov rdx, r11",
        "call {handler}",
        "jmp {ret}",
        kind = const FaultKind::GeneralProtection as u64,
        handler = sym fault_handler,
        ret = sym return_to_user,
    )
}

#[unsafe(naked)]
pub unsafe extern "C" fn invalid_opcode_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "mov esi, {kind}",
        "xor edx, edx",
        "call {handler}",
        "jmp {ret}",
        kind = const FaultKind::InvalidOpcode as u64,
        handler = sym fault_handler,
        ret = sym return_to_user,
    )
}

#[unsafe(naked)]
pub unsafe extern "C" fn divide_error_entry() {
    naked_asm!(
        "push r11",
        "push rcx",
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
        "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
        "mov esi, {kind}",
        "xor edx, edx",
        "call {handler}",
        "jmp {ret}",
        kind = const FaultKind::DivideError as u64,
        handler = sym fault_handler,
        ret = sym return_to_user,
    )
}

/// Leaves the kernel with the [`UserFrame`] at rsp. `rax` selects the exit:
/// [`Exit::Sysret`] or [`Exit::Iret`].
///
/// `sysret` with a non-canonical rip faults in ring 0 on Intel CPUs. A rip
/// on the sysret path always comes from a `syscall` instruction or from an
/// ELF entry point checked to lie in the user window, so it is canonical.
#[unsafe(naked)]
unsafe extern "C" fn return_to_user() -> ! {
    naked_asm!(
        "test rax, rax",
        "jnz 2f",
        // sysret: rcx/r11 carry rip/rflags; their saved values are dead.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rbx",
        "pop rax",
        "add rsp, 16", // saved rcx, r11
        "pop rcx",     // rip
        "add rsp, 8",  // cs
        "pop r11",     // rflags
        "pop rsp",
        "sysretq",
        "2:",
        // iretq: restore every register exactly.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rbx",
        "pop rax",
        "pop rcx",
        "pop r11",
        "iretq",
    )
}

extern "C" fn syscall_handler(frame: &mut UserFrame) -> Exit {
    crate::task::handle_syscall(frame)
}

extern "C" fn fault_handler(frame: &mut UserFrame, kind: u64, code: u64) -> Exit {
    let kind = FaultKind::from_u64(kind).unwrap();
    let addr = match kind {
        FaultKind::PageFault => x86_64::registers::control::Cr2::read_raw(),
        _ => 0,
    };
    crate::task::handle_fault(frame, kind, code, addr)
}

extern "C" fn com1_handler(frame: &mut UserFrame) -> Exit {
    // Masked until the driver acknowledges, so a level that stays raised
    // cannot storm the kernel.
    super::interrupts::pic_mask(super::interrupts::COM1_IRQ);
    super::interrupts::pic_eoi(super::interrupts::COM1_IRQ);
    crate::task::handle_irq(frame, super::interrupts::COM1_IRQ)
}

/// Entries for the PCI interrupt lines (`interrupts::INTX_LINES`), like
/// COM1's: masked until the driver acknowledges, since the device holds
/// its line down until the driver has dealt with it.
macro_rules! intx_entries {
    ($($entry:ident $handler:ident $n:literal),* $(,)?) => {
        $(
            #[unsafe(naked)]
            pub unsafe extern "C" fn $entry() {
                naked_asm!(
                    "push r11",
                    "push rcx",
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
                    "cld", // the ABI wants DF clear; user code may have set it
                    "mov rdi, rsp",
                    "call {handler}",
                    "jmp {ret}",
                    handler = sym $handler,
                    ret = sym return_to_user,
                )
            }

            extern "C" fn $handler(frame: &mut UserFrame) -> Exit {
                let line = super::interrupts::INTX_LINES[$n];
                super::interrupts::pic_mask(line);
                super::interrupts::pic_eoi(line);
                crate::task::handle_irq(frame, line)
            }
        )*

        /// The entry for each PCI interrupt line, in order.
        pub const INTX_ENTRIES: [unsafe extern "C" fn(); 4] = [$($entry),*];
    };
}

intx_entries!(
    intx0_entry intx0_handler 0,
    intx1_entry intx1_handler 1,
    intx2_entry intx2_handler 2,
    intx3_entry intx3_handler 3,
);

/// Entries for the MSI vectors, one per vector: each saves the user
/// registers as the timer's does and passes its vector's index on.
macro_rules! msi_entries {
    ($($entry:ident $handler:ident $n:literal),* $(,)?) => {
        $(
            #[unsafe(naked)]
            pub unsafe extern "C" fn $entry() {
                naked_asm!(
                    "push r11",
                    "push rcx",
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
                    "cld", // the ABI wants DF clear; user code may have set it
        "mov rdi, rsp",
                    "call {handler}",
                    "jmp {ret}",
                    handler = sym $handler,
                    ret = sym return_to_user,
                )
            }

            extern "C" fn $handler(frame: &mut UserFrame) -> Exit {
                msi_handler(frame, $n)
            }
        )*

        /// The entry for each MSI vector, in order.
        pub const MSI_ENTRIES: [unsafe extern "C" fn(); super::interrupts::MSI_COUNT as usize] =
            [$($entry),*];
    };
}

msi_entries!(
    msi0_entry msi0_handler 0,
    msi1_entry msi1_handler 1,
    msi2_entry msi2_handler 2,
    msi3_entry msi3_handler 3,
    msi4_entry msi4_handler 4,
    msi5_entry msi5_handler 5,
    msi6_entry msi6_handler 6,
    msi7_entry msi7_handler 7,
);

/// An MSI is edge-triggered and raised by the device writing a message:
/// nothing to mask, just end it at the local APIC and signal the line.
fn msi_handler(frame: &mut UserFrame, n: u8) -> Exit {
    super::apic::end_of_interrupt();
    crate::task::handle_irq(frame, super::interrupts::MSI_LINE_BASE + n)
}

extern "C" fn kick_handler(frame: &mut UserFrame) -> Exit {
    super::apic::end_of_interrupt();
    crate::task::handle_kick(frame)
}

extern "C" fn timer_handler(frame: &mut UserFrame) -> Exit {
    super::apic::end_of_interrupt();
    crate::task::handle_timer(frame)
}
