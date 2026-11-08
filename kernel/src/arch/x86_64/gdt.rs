//! Global descriptor table, task-state segment and the kernel stack.
//!
//! Long mode barely uses segmentation, but we need:
//! - user code/data segments laid out the way `sysret` expects,
//! - a TSS whose `rsp0` is the kernel stack (for traps from ring 3), and
//! - an IST stack for double faults, so a kernel stack overflow produces a
//!   diagnostic instead of a triple-fault reset.
//!
//! The kernel runs on one stack for every thread (the seL4 model): a
//! system call saves the user registers into the thread's TCB, so nothing
//! of a blocked thread is left on the kernel stack.

use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const DOUBLE_FAULT_STACK_SIZE: usize = 5 * 4096;
const KERNEL_STACK_SIZE: usize = 64 * 1024;

#[repr(align(16))]
struct Stack<const N: usize>([u8; N]);

static mut DOUBLE_FAULT_STACK: Stack<DOUBLE_FAULT_STACK_SIZE> = Stack([0; DOUBLE_FAULT_STACK_SIZE]);
static mut KERNEL_STACK: Stack<KERNEL_STACK_SIZE> = Stack([0; KERNEL_STACK_SIZE]);

/// Top of the kernel stack used for system calls and traps from user mode.
pub fn kernel_stack_top() -> u64 {
    VirtAddr::from_ptr(&raw const KERNEL_STACK).as_u64() + KERNEL_STACK_SIZE as u64
}

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    let df = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
    // Stacks grow down: point at the top.
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        df + DOUBLE_FAULT_STACK_SIZE as u64;
    tss.privilege_stack_table[0] = VirtAddr::new(kernel_stack_top());
    tss
});

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    tss: SegmentSelector,
}

// Order matters: `sysret` loads SS = user_data and CS = user_code from
// consecutive slots, and `syscall` loads SS = kernel_code + 8.
static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (
        gdt,
        Selectors {
            kernel_code,
            kernel_data,
            user_data,
            user_code,
            tss,
        },
    )
});

pub fn selectors() -> &'static Selectors {
    &GDT.1
}

pub fn init() {
    let (gdt, sel) = &*GDT;
    gdt.load();
    // SAFETY: the selectors index descriptors in the GDT just loaded.
    unsafe {
        CS::set_reg(sel.kernel_code);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        SS::set_reg(sel.kernel_data);
        load_tss(sel.tss);
    }
}
