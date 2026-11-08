//! Global descriptor table and task-state segment.
//!
//! Long mode barely uses segmentation, but we still need a TSS to give the
//! double-fault handler its own known-good stack (IST slot 0), so a kernel
//! stack overflow produces a diagnostic instead of a triple-fault reset.

use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const DOUBLE_FAULT_STACK_SIZE: usize = 5 * 4096;

static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0; DOUBLE_FAULT_STACK_SIZE];

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    let base = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
    // Stacks grow down: the IST entry points at the top.
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        base + DOUBLE_FAULT_STACK_SIZE as u64;
    tss
});

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (gdt, Selectors { code, data, tss })
});

pub fn init() {
    let (gdt, sel) = &*GDT;
    gdt.load();
    // SAFETY: the selectors index descriptors in the GDT just loaded.
    unsafe {
        CS::set_reg(sel.code);
        DS::set_reg(sel.data);
        ES::set_reg(sel.data);
        SS::set_reg(sel.data);
        load_tss(sel.tss);
    }
}
