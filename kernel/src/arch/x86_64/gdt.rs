//! Global descriptor tables, task-state segments and kernel stacks, one
//! of each per CPU.
//!
//! Long mode barely uses segmentation, but we need:
//! - user code/data segments laid out the way `sysret` expects,
//! - a TSS whose `rsp0` is the CPU's kernel stack (for traps from ring 3),
//! - an IST stack for double faults, so a kernel stack overflow produces a
//!   diagnostic instead of a triple-fault reset.
//!
//! Each CPU runs on one stack for every thread (the seL4 model): a system
//! call saves the user registers into the thread's TCB, so nothing of a
//! blocked thread is left on the kernel stack. Every CPU's GDT has the same
//! layout, so the selectors are the same everywhere.

use crate::smp::MAX_CPUS;
use spin::Once;
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

static mut DOUBLE_FAULT_STACKS: [Stack<DOUBLE_FAULT_STACK_SIZE>; MAX_CPUS] =
    [const { Stack([0; DOUBLE_FAULT_STACK_SIZE]) }; MAX_CPUS];
static mut KERNEL_STACKS: [Stack<KERNEL_STACK_SIZE>; MAX_CPUS] =
    [const { Stack([0; KERNEL_STACK_SIZE]) }; MAX_CPUS];

/// Top of CPU `cpu`'s kernel stack, used for system calls and traps from
/// user mode.
pub fn kernel_stack_top(cpu: usize) -> u64 {
    VirtAddr::from_ptr(&raw const KERNEL_STACKS).as_u64() + ((cpu + 1) * KERNEL_STACK_SIZE) as u64
}

static TSS: [Once<TaskStateSegment>; MAX_CPUS] = [const { Once::new() }; MAX_CPUS];

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: [Once<(GlobalDescriptorTable, Selectors)>; MAX_CPUS] =
    [const { Once::new() }; MAX_CPUS];

/// The selectors (the same on every CPU).
pub fn selectors() -> &'static Selectors {
    &GDT[0].get().expect("GDT not loaded").1
}

/// Loads CPU `cpu`'s GDT and TSS.
pub fn init(cpu: usize) {
    let tss = TSS[cpu].call_once(|| {
        let mut tss = TaskStateSegment::new();
        let df = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACKS)
            + ((cpu + 1) * DOUBLE_FAULT_STACK_SIZE) as u64;
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = df;
        tss.privilege_stack_table[0] = VirtAddr::new(kernel_stack_top(cpu));
        tss
    });
    // Order matters: `sysret` loads SS = user_data and CS = user_code from
    // consecutive slots, and `syscall` loads SS = kernel_code + 8.
    let (gdt, sel) = GDT[cpu].call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss = gdt.append(Descriptor::tss_segment(tss));
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
    gdt.load();
    // A TSS descriptor is marked busy once loaded, and loading a busy one
    // faults: after S3 this CPU loads it again (its GDT kept in RAM), so
    // mark it available first.
    let table = x86_64::instructions::tables::sgdt();
    let at = table.base.as_u64() + sel.tss.index() as u64 * 8 + 5;
    // SAFETY: byte 5 (access) of the TSS descriptor in this CPU's own GDT,
    // a static only this CPU loads; clearing bit 1 makes type 0xB
    // (busy) 0x9 (available).
    unsafe { (at as *mut u8).write_volatile((at as *const u8).read_volatile() & !2) };
    // SAFETY: the selectors index descriptors in the GDT just loaded.
    unsafe {
        CS::set_reg(sel.kernel_code);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        SS::set_reg(sel.kernel_data);
        load_tss(sel.tss);
    }
}
