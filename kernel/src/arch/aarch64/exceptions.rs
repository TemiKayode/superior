//! Exception entry and exit at EL1: system calls (`svc`), faults from user
//! mode, interrupts, and the kernel's own breakpoints.
//!
//! Every entry saves the same [`UserFrame`] (x0-x30, `SP_EL0`, `ELR_EL1`,
//! `SPSR_EL1`) on the kernel stack and passes it to a Rust handler, which
//! may overwrite it with another thread's registers; the common exit
//! restores the frame and `eret`s. An entry from user mode always finds
//! the stack empty, because every return to user mode pops its frame from
//! the top of the stack. The only entry from EL1 is an interrupt taken
//! while the kernel idles, which nests below the idle loop's frame.
//!
//! Interrupts are masked throughout the kernel, as on x86-64.

use crate::kprintln;
use superior_objects::abi::FaultKind;

/// Saved user registers, lowest address first.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UserFrame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
}

const FRAME_SIZE: usize = core::mem::size_of::<UserFrame>();
const _: () = assert!(FRAME_SIZE == 272);

/// How to return to user mode. AArch64 always restores the whole frame;
/// the distinction matters only on x86-64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Sysret,
    Iret,
}

/// A system call's number and arguments; see the x86-64 `Args`.
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

impl UserFrame {
    pub const ZERO: UserFrame = UserFrame {
        x: [0; 31],
        sp: 0,
        elr: 0,
        spsr: 0,
    };

    /// A fresh thread at EL0 with interrupts unmasked, `x0` = its start
    /// argument.
    pub fn new_thread(entry: u64, stack_top: u64, arg: u64) -> Self {
        let mut f = UserFrame {
            elr: entry,
            sp: stack_top,
            spsr: 0, // EL0t, DAIF clear
            ..UserFrame::ZERO
        };
        f.x[0] = arg;
        f
    }

    pub fn is_user_mode(&self) -> bool {
        self.spsr & 0b1111 == 0
    }

    /// `x8` is the number; `x0`-`x5` the arguments.
    pub fn args(&self) -> Args {
        let x = &self.x;
        Args {
            nr: x[8],
            a0: x[0],
            a1: x[1],
            a2: x[2],
            a3: x[3],
            a4: x[4],
            a5: x[5],
        }
    }

    /// Status in `x8`, badge in `x0`, message in `x1`-`x4`, the
    /// received-capability word in `x5`.
    pub fn set_results(&mut self, status: u64, badge: u64, msg: [u64; 4], cap: u64) {
        self.x[8] = status;
        self.x[0] = badge;
        self.x[1..5].copy_from_slice(&msg);
        self.x[5] = cap;
    }

    pub fn pc(&self) -> u64 {
        self.elr
    }

    /// Points back at the `svc` that entered the kernel, so the system
    /// call is made again.
    pub fn rewind_syscall(&mut self) {
        self.elr -= 4;
    }

    /// Resumes at `pc` with `value` in `x0`.
    pub fn resume_at(&mut self, pc: u64, value: u64) {
        self.elr = pc;
        self.x[0] = value;
    }
}

extern "C" {
    static exception_vectors: u8;
    fn exception_return() -> !;
}

pub fn init() {
    // SAFETY: the table is 2 KiB-aligned and every entry saves a full
    // frame before calling Rust.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "isb",
            in(reg) core::ptr::addr_of!(exception_vectors),
            options(nostack)
        )
    };
}

/// Enters user mode for the first time with `frame`'s registers, from the
/// top of the kernel stack.
pub fn enter_user(frame: UserFrame) -> ! {
    let at = super::stack_top(super::cpu_id()) - FRAME_SIZE as u64;
    // SAFETY: nothing on the kernel stack is needed any more; the frame is
    // written at its top and popped by the common exit.
    unsafe {
        (at as *mut UserFrame).write(frame);
        core::arch::asm!(
            "mov sp, {at}",
            "b {ret}",
            at = in(reg) at,
            ret = sym exception_return,
            options(noreturn)
        )
    }
}

core::arch::global_asm!(
    ".macro SAVE_FRAME",
    "    sub sp, sp, #272",
    "    stp x0, x1, [sp, #0]",
    "    stp x2, x3, [sp, #16]",
    "    stp x4, x5, [sp, #32]",
    "    stp x6, x7, [sp, #48]",
    "    stp x8, x9, [sp, #64]",
    "    stp x10, x11, [sp, #80]",
    "    stp x12, x13, [sp, #96]",
    "    stp x14, x15, [sp, #112]",
    "    stp x16, x17, [sp, #128]",
    "    stp x18, x19, [sp, #144]",
    "    stp x20, x21, [sp, #160]",
    "    stp x22, x23, [sp, #176]",
    "    stp x24, x25, [sp, #192]",
    "    stp x26, x27, [sp, #208]",
    "    stp x28, x29, [sp, #224]",
    "    mrs x21, sp_el0",
    "    stp x30, x21, [sp, #240]",
    "    mrs x22, elr_el1",
    "    mrs x23, spsr_el1",
    "    stp x22, x23, [sp, #256]",
    ".endm",
    ".macro VENTRY handler, kind",
    "    .balign 0x80",
    "    SAVE_FRAME",
    "    mov x0, sp",
    "    mov x1, #\\kind",
    "    bl \\handler",
    "    b exception_return",
    ".endm",
    ".section .text",
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP_EL0: never used.
    "    VENTRY {unexpected}, 0",
    "    VENTRY {unexpected}, 1",
    "    VENTRY {unexpected}, 2",
    "    VENTRY {unexpected}, 3",
    // Current EL with SP_EL1: the kernel itself.
    "    VENTRY {el1_sync}, 4",
    "    VENTRY {irq}, 5",
    "    VENTRY {unexpected}, 6",
    "    VENTRY {unexpected}, 7",
    // Lower EL, AArch64: user threads.
    "    VENTRY {el0_sync}, 8",
    "    VENTRY {irq}, 9",
    "    VENTRY {unexpected}, 10",
    "    VENTRY {unexpected}, 11",
    // Lower EL, AArch32: not supported.
    "    VENTRY {unexpected}, 12",
    "    VENTRY {unexpected}, 13",
    "    VENTRY {unexpected}, 14",
    "    VENTRY {unexpected}, 15",
    ".global exception_return",
    "exception_return:",
    "    ldp x22, x23, [sp, #256]",
    "    msr elr_el1, x22",
    "    msr spsr_el1, x23",
    "    ldp x30, x21, [sp, #240]",
    "    msr sp_el0, x21",
    "    ldp x0, x1, [sp, #0]",
    "    ldp x2, x3, [sp, #16]",
    "    ldp x4, x5, [sp, #32]",
    "    ldp x6, x7, [sp, #48]",
    "    ldp x8, x9, [sp, #64]",
    "    ldp x10, x11, [sp, #80]",
    "    ldp x12, x13, [sp, #96]",
    "    ldp x14, x15, [sp, #112]",
    "    ldp x16, x17, [sp, #128]",
    "    ldp x18, x19, [sp, #144]",
    "    ldp x20, x21, [sp, #160]",
    "    ldp x22, x23, [sp, #176]",
    "    ldp x24, x25, [sp, #192]",
    "    ldp x26, x27, [sp, #208]",
    "    ldp x28, x29, [sp, #224]",
    "    add sp, sp, #272",
    "    eret",
    unexpected = sym unexpected,
    el1_sync = sym el1_sync,
    el0_sync = sym el0_sync,
    irq = sym irq,
);

fn esr() -> u64 {
    let v: u64;
    // SAFETY: reading the syndrome register has no side effect.
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) v, options(nostack, nomem)) };
    v
}

fn far() -> u64 {
    let v: u64;
    // SAFETY: reading the fault address register has no side effect.
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) v, options(nostack, nomem)) };
    v
}

// Exception classes (ESR_EL1.EC).
const EC_UNKNOWN: u64 = 0x00;
const EC_WFX: u64 = 0x01;
const EC_SVC64: u64 = 0x15;
const EC_SYSREG: u64 = 0x18;
const EC_IABT_LOWER: u64 = 0x20;
const EC_DABT_LOWER: u64 = 0x24;
const EC_BRK: u64 = 0x3c;

/// A synchronous exception from user mode: a system call or a fault.
///
/// Faults are reported in x86-64 terms so fault handlers are portable: a
/// data or instruction abort is a page fault whose code has bit 0 set for
/// a permission (rather than translation) fault, bit 1 for a write, bit 2
/// for user mode and bit 4 for an instruction fetch. An undefined
/// instruction is an invalid opcode; a trapped `wfi`, system-register
/// access or alignment fault is a general-protection fault.
extern "C" fn el0_sync(frame: &mut UserFrame, _kind: u64) {
    let esr = esr();
    let ec = esr >> 26;
    if ec == EC_SVC64 {
        crate::task::handle_syscall(frame);
        return;
    }
    let (kind, code, addr) = match ec {
        EC_DABT_LOWER | EC_IABT_LOWER => {
            let fsc = esr & 0x3f;
            if (0x21..=0x22).contains(&fsc) {
                (FaultKind::GeneralProtection, esr, far())
            } else {
                let mut code = 1 << 2;
                // Permission (0b0011xx) and access-flag (0b0010xx) faults
                // hit a present mapping.
                if matches!(fsc & 0x3c, 0x08 | 0x0c) {
                    code |= 1;
                }
                if ec == EC_DABT_LOWER && esr & (1 << 6) != 0 {
                    code |= 1 << 1;
                }
                if ec == EC_IABT_LOWER {
                    code |= 1 << 4;
                }
                (FaultKind::PageFault, code, far())
            }
        }
        EC_UNKNOWN => (FaultKind::InvalidOpcode, 0, 0),
        EC_WFX | EC_SYSREG => (FaultKind::GeneralProtection, 0, 0),
        _ => (FaultKind::GeneralProtection, esr, 0),
    };
    crate::task::handle_fault(frame, kind, code, addr);
}

/// A synchronous exception in the kernel: a breakpoint from the self-test
/// returns; anything else is a kernel bug.
extern "C" fn el1_sync(frame: &mut UserFrame, _kind: u64) {
    let esr = esr();
    if esr >> 26 == EC_BRK {
        kprintln!("[trap] breakpoint at {:#x}", frame.elr);
        frame.elr += 4;
        return;
    }
    panic!(
        "kernel exception: ESR {esr:#x}, FAR {:#x}, ELR {:#x}",
        far(),
        frame.elr
    );
}

extern "C" fn irq(frame: &mut UserFrame, _kind: u64) {
    let Some(id) = super::gic::acknowledge() else {
        return; // spurious
    };
    if id == super::timer::intid() {
        super::timer::rearm();
        super::gic::end_of_interrupt(id);
        crate::task::handle_timer(frame);
    } else if id == super::gic::KICK_SGI {
        super::gic::end_of_interrupt(id);
        crate::task::handle_kick(frame);
    } else if id == super::gic::SHOOTDOWN_SGI {
        crate::smp::service();
        super::gic::end_of_interrupt(id);
    } else if Some(id) == super::iommu::fault_irq() {
        super::gic::end_of_interrupt(id);
        crate::task::handle_io_fault_irq(frame);
    } else {
        // Masked until the driver acknowledges, so a level that stays
        // raised cannot storm the kernel (MSIs, being messages, are not).
        let line = super::gic::line_of(id);
        super::gic::mask(line);
        super::gic::end_of_interrupt(id);
        crate::task::handle_irq(frame, line as u8);
    }
}

extern "C" fn unexpected(frame: &mut UserFrame, kind: u64) {
    panic!(
        "unexpected exception {kind}: ESR {:#x}, FAR {:#x}, ELR {:#x}",
        esr(),
        far(),
        frame.elr
    );
}
