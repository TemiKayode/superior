//! Interrupt descriptor table: CPU exception handlers.
//!
//! A fault taken in user mode becomes a fault message to the faulting
//! thread's handler (see `task::handle_fault`). A fault in kernel mode is
//! always a kernel bug and panics.

use super::{apic, gdt, syscall};
use crate::kprintln;
use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint);
    // SAFETY: each entry is a naked stub that saves a full UserFrame and
    // leaves through return_to_user.
    unsafe {
        let addr = |f: unsafe extern "C" fn()| VirtAddr::new(f as *const () as u64);
        idt.page_fault
            .set_handler_addr(addr(syscall::page_fault_entry));
        idt.general_protection_fault
            .set_handler_addr(addr(syscall::general_protection_entry));
        idt.invalid_opcode
            .set_handler_addr(addr(syscall::invalid_opcode_entry));
        idt.divide_error
            .set_handler_addr(addr(syscall::divide_error_entry));
    }
    // SAFETY: the IST index refers to a stack set up in gdt::TSS and used
    // by no other handler.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    // SAFETY: timer_entry is a naked interrupt entry that saves a full
    // UserFrame and leaves through return_to_user (iretq or sysret).
    unsafe {
        idt[apic::TIMER_VECTOR]
            .set_handler_addr(VirtAddr::new(syscall::timer_entry as *const () as u64));
    }
    // SAFETY: com1_entry is a naked interrupt entry like timer_entry.
    unsafe {
        idt[PIC_BASE + COM1_IRQ]
            .set_handler_addr(VirtAddr::new(syscall::com1_entry as *const () as u64));
    }
    for (n, entry) in syscall::MSI_ENTRIES.iter().enumerate() {
        // SAFETY: each entry saves the user frame like the timer's.
        unsafe {
            idt[MSI_VECTOR_BASE + n as u8]
                .set_handler_addr(VirtAddr::new(*entry as *const () as u64));
        }
    }
    idt[apic::SPURIOUS_VECTOR].set_handler_fn(spurious);
    // The PIC's spurious IRQ 7 and 15.
    idt[PIC_BASE + 7].set_handler_fn(spurious);
    idt[PIC_BASE + 15].set_handler_fn(spurious);
    idt
});

/// Legacy PIC lines arrive on vectors `PIC_BASE + line`.
pub const PIC_BASE: u8 = 0x20;
/// COM1's interrupt line, handed to the serial driver.
pub const COM1_IRQ: u8 = 4;
/// Lines user space may own: only COM1 for now.
/// MSI vectors: interrupt lines `MSI_LINE_BASE ..` arrive on vectors
/// `MSI_VECTOR_BASE ..` at the local APIC.
pub const MSI_VECTOR_BASE: u8 = 0x40;
pub const MSI_LINE_BASE: u8 = 32;
pub const MSI_COUNT: u8 = 8;

/// Whether `line` is an MSI vector's.
pub fn is_msi(line: u8) -> bool {
    (MSI_LINE_BASE..MSI_LINE_BASE + MSI_COUNT).contains(&line)
}

/// The message that raises MSI line `line` on this CPU. With interrupt
/// remapping, the line's remapping entry is pointed at its vector for
/// requester `source` alone (or for nobody) and the message names that
/// entry. Without, it is the vector itself: address 0xfee0_0000 (the
/// local APIC, destination ID 0, physical mode), data = the vector (fixed
/// delivery, edge).
pub fn msi_message(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    if !is_msi(line) {
        return None;
    }
    let vector = MSI_VECTOR_BASE + line - MSI_LINE_BASE;
    Some(if super::iommu::remapping() {
        super::iommu::route((line - MSI_LINE_BASE) as u16, vector, source)
    } else {
        (0xfee0_0000, vector as u64)
    })
}

pub fn irq_routable(line: u8) -> bool {
    line == COM1_IRQ || is_msi(line)
}

/// Masks a line on the master PIC (lines 0-7).
pub fn pic_mask(line: u8) {
    use x86_64::instructions::port::Port;
    let mut data = Port::<u8>::new(0x21);
    // SAFETY: read-modify-write of the master PIC's mask register.
    unsafe {
        let m = data.read();
        data.write(m | 1 << line);
    }
}

/// Unmasks a line on the master PIC.
pub fn pic_unmask(line: u8) {
    if line >= 16 {
        return; // not a PIC line (an MSI vector: never masked)
    }
    use x86_64::instructions::port::Port;
    let mut data = Port::<u8>::new(0x21);
    // SAFETY: as in `pic_mask`.
    unsafe {
        let m = data.read();
        data.write(m & !(1 << line));
    }
}

/// End of interrupt on the master PIC.
pub fn pic_eoi(_line: u8) {
    use x86_64::instructions::port::Port;
    // SAFETY: non-specific EOI to the master PIC's command port.
    unsafe { Port::<u8>::new(0x20).write(0x20) };
}

pub fn init() {
    disable_legacy_pic();
    IDT.load();
}

/// The 8259 PIC powers up delivering IRQ 0-7 on vectors 8-15, which
/// collide with CPU exceptions (IRQ 0, the timer, would arrive as a
/// "double fault"). Remap it to vectors 0x20-0x2f and mask every line; a
/// line is unmasked only when a user-space driver binds it to a
/// notification (`IrqSetNotification`).
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
        data1.write(!(1u8 << 2)); // mask all lines but the cascade
        data2.write(0xff);
    }
}

extern "x86-interrupt" fn breakpoint(frame: InterruptStackFrame) {
    kprintln!(
        "[trap] breakpoint at {:#x}",
        frame.instruction_pointer.as_u64()
    );
}

/// A spurious APIC interrupt needs no EOI and no action.
extern "x86-interrupt" fn spurious(_frame: InterruptStackFrame) {}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    panic!("double fault\n{frame:#?}");
}
