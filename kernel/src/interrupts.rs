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
    disable_legacy_pic();
    IDT.load();
}

/// The 8259 PIC powers up delivering IRQ 0-7 on vectors 8-15, which
/// collide with CPU exceptions (IRQ 0, the timer, would arrive as a
/// "double fault"). Remap it to vectors 0x20-0x2f and mask every line:
/// device interrupts will go through the APIC to user-space drivers.
fn disable_legacy_pic() {
    use x86_64::instructions::port::Port;
    let mut cmd1 = Port::<u8>::new(0x20);
    let mut data1 = Port::<u8>::new(0x21);
    let mut cmd2 = Port::<u8>::new(0xa0);
    let mut data2 = Port::<u8>::new(0xa1);
    // SAFETY: standard 8259 initialisation sequence on the PIC's fixed ports.
    unsafe {
        cmd1.write(0x11); // ICW1: init, expect ICW4
        cmd2.write(0x11);
        data1.write(0x20); // ICW2: vector base
        data2.write(0x28);
        data1.write(4); // ICW3: slave on IRQ 2
        data2.write(2);
        data1.write(1); // ICW4: 8086 mode
        data2.write(1);
        data1.write(0xff); // mask all lines
        data2.write(0xff);
    }
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
