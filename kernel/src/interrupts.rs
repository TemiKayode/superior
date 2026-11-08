//! Interrupt descriptor table: CPU exception handlers.
//!
//! In the finished kernel, a fault taken in user mode becomes a fault
//! message to the faulting thread's handler (its supervisor). A fault in
//! kernel mode is always a kernel bug, so for now every handler logs and
//! halts.

use crate::{gdt, kprintln};
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint);
    idt.general_protection_fault
        .set_handler_fn(general_protection);
    idt.page_fault.set_handler_fn(page_fault);
    // SAFETY: the IST index refers to a stack set up in gdt::TSS and used
    // by no other handler.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt
});

pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint(frame: InterruptStackFrame) {
    kprintln!(
        "[trap] breakpoint at {:#x}",
        frame.instruction_pointer.as_u64()
    );
}

extern "x86-interrupt" fn general_protection(frame: InterruptStackFrame, code: u64) {
    panic!("general protection fault (code {code:#x})\n{frame:#?}");
}

extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let addr = Cr2::read_raw();
    panic!("kernel page fault at {addr:#x} ({code:?})\n{frame:#?}");
}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    panic!("double fault\n{frame:#?}");
}
