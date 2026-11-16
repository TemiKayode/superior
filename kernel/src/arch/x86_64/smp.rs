//! Starting the other CPUs.
//!
//! A CPU starts in real mode at a page below 1 MiB (the start-up message
//! names it). The trampoline below is copied there; it loads a small GDT
//! of its own, turns on protected mode, then long mode with paging on the
//! kernel's own tables (in which the page is identity-mapped for the
//! switch), and jumps to [`ap_main`] on the CPU's own kernel stack. CPU 0
//! fills in the trampoline's data (tables, stack, number, entry) before
//! each start and waits for the CPU to come up before the next.
//!
//! Waking from S3 ([`super::sleep`]) goes through the same trampoline: the
//! firmware starts CPU 0 in real mode at the page the FACS names, and it
//! lands in [`super::sleep`]'s wake entry instead; then the other CPUs,
//! which lost everything, are started again ([`restart_secondaries`]).

use super::{apic, gdt, interrupts, syscall, vm};
use crate::smp::{self, MAX_CPUS};
use core::sync::atomic::{AtomicU64, Ordering};

/// The start-up page, if the memory map had one.
pub static STARTUP_PAGE: AtomicU64 = AtomicU64::new(0);
/// CPU 0's CR0 and CR4 (and XCR0 if it uses XSAVE), which every CPU
/// copies.
static CR0: AtomicU64 = AtomicU64::new(0);
static CR4: AtomicU64 = AtomicU64::new(0);
static XCR0: AtomicU64 = AtomicU64::new(0);
const CR4_PAE: u64 = 1 << 5;
const CR4_OSXSAVE: u64 = 1 << 18;

core::arch::global_asm!(
    ".pushsection .rodata.ap_trampoline, \"a\"",
    ".balign 16",
    ".global sup_ap_start",
    "sup_ap_start:",
    ".code16",
    "    cli",
    "    cld",
    "    mov %cs, %ax",
    "    mov %ax, %ds",
    // %esi: the page's address, kept through every mode.
    "    movzwl %ax, %esi",
    "    shll $4, %esi",
    "    lgdtl sup_ap_gdtr - sup_ap_start",
    "    movl %cr0, %eax",
    "    orl $1, %eax",
    "    movl %eax, %cr0",
    "    ljmpl *(sup_ap_far32 - sup_ap_start)",
    ".code32",
    "sup_ap_pm32:",
    "    movw $0x10, %ax",
    "    movw %ax, %ds",
    "    movw %ax, %es",
    "    movw %ax, %ss",
    "    movl $0x20, %eax",
    "    movl %eax, %cr4",
    "    movl (sup_ap_cr3 - sup_ap_start)(%esi), %eax",
    "    movl %eax, %cr3",
    // EFER: syscall, long mode, no-execute.
    "    movl $0xc0000080, %ecx",
    "    rdmsr",
    "    orl $0x901, %eax",
    "    wrmsr",
    "    movl (sup_ap_cr0 - sup_ap_start)(%esi), %eax",
    "    movl %eax, %cr0",
    "    ljmpl *(sup_ap_far64 - sup_ap_start)(%esi)",
    ".code64",
    "sup_ap_lm64:",
    "    movl %esi, %esi",
    "    movq (sup_ap_stack - sup_ap_start)(%rsi), %rsp",
    "    movq (sup_ap_cpu - sup_ap_start)(%rsi), %rdi",
    "    movq (sup_ap_entry - sup_ap_start)(%rsi), %rax",
    "    jmpq *%rax",
    ".balign 8",
    "sup_ap_gdt:",
    "    .quad 0",
    "    .quad 0x00cf9a000000ffff", // 0x08: 32-bit code
    "    .quad 0x00cf92000000ffff", // 0x10: data
    "    .quad 0x00af9a000000ffff", // 0x18: 64-bit code
    ".global sup_ap_gdtr",
    "sup_ap_gdtr:",
    "    .word 31",
    "    .long 0",
    ".balign 8",
    ".global sup_ap_far32",
    "sup_ap_far32:",
    "    .long 0",
    "    .word 0x08",
    ".balign 8",
    ".global sup_ap_far64",
    "sup_ap_far64:",
    "    .long 0",
    "    .word 0x18",
    ".balign 8",
    ".global sup_ap_cr3",
    "sup_ap_cr3: .quad 0",
    ".global sup_ap_cr0",
    "sup_ap_cr0: .quad 0",
    ".global sup_ap_stack",
    "sup_ap_stack: .quad 0",
    ".global sup_ap_cpu",
    "sup_ap_cpu: .quad 0",
    ".global sup_ap_entry",
    "sup_ap_entry: .quad 0",
    ".global sup_ap_pm32_at",
    "sup_ap_pm32_at: .quad sup_ap_pm32 - sup_ap_start",
    ".global sup_ap_lm64_at",
    "sup_ap_lm64_at: .quad sup_ap_lm64 - sup_ap_start",
    ".global sup_ap_gdt_at",
    "sup_ap_gdt_at: .quad sup_ap_gdt - sup_ap_start",
    ".global sup_ap_end",
    "sup_ap_end:",
    ".popsection",
    options(att_syntax)
);

extern "C" {
    static sup_ap_start: u8;
    static sup_ap_end: u8;
    static sup_ap_gdtr: u8;
    static sup_ap_far32: u8;
    static sup_ap_far64: u8;
    static sup_ap_cr3: u8;
    static sup_ap_cr0: u8;
    static sup_ap_stack: u8;
    static sup_ap_cpu: u8;
    static sup_ap_entry: u8;
    static sup_ap_pm32_at: u64;
    static sup_ap_lm64_at: u64;
    static sup_ap_gdt_at: u64;
}

/// Where `sym` lands in the copy at `page`.
fn at(page: u64, sym: *const u8) -> *mut u8 {
    let off = sym as u64 - (&raw const sup_ap_start) as u64;
    vm::phys_ptr(page + off)
}

/// Notes CPU 0's control registers, for the others to copy.
pub fn note_boot_cpu() {
    use x86_64::registers::control::{Cr0, Cr4};
    CR0.store(Cr0::read_raw(), Ordering::Relaxed);
    let cr4 = Cr4::read_raw();
    CR4.store(cr4, Ordering::Relaxed);
    if cr4 & CR4_OSXSAVE != 0 {
        let xcr0 = x86_64::registers::xcontrol::XCr0::read_raw();
        XCR0.store(xcr0, Ordering::Relaxed);
    }
}

/// Each CPU's local APIC ID, by CPU number (`u32::MAX` for none yet):
/// CPU 0 is the boot CPU, the rest in the order they were started.
static APIC_OF: [core::sync::atomic::AtomicU32; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(u32::MAX) }; MAX_CPUS];

/// CPU `cpu`'s local APIC ID.
pub fn apic_of(cpu: usize) -> u32 {
    APIC_OF[cpu].load(Ordering::Relaxed)
}

/// The number of the CPU with local APIC ID `apic` (0 if none has it).
pub fn cpu_of(apic: u32) -> usize {
    (0..MAX_CPUS).find(|&c| APIC_OF[c].load(Ordering::Relaxed) == apic).unwrap_or(0)
}

/// Records the boot CPU's APIC ID as CPU 0's, once its local APIC is on.
pub fn note_boot_apic() {
    APIC_OF[0].store(apic::id() as u32, Ordering::Relaxed);
}

/// The other CPUs to start, by APIC ID: those the ACPI MADT lists
/// enabled, but the boot CPU; without a MADT, IDs 1, 2, ... (until one
/// does not come up).
fn others() -> [Option<u32>; MAX_CPUS] {
    let mut out = [None; MAX_CPUS];
    let boot = apic_of(0);
    match super::acpi::cpus() {
        Some(ids) => {
            for (slot, id) in out.iter_mut().skip(1).zip(ids.filter(|&id| id != boot)) {
                *slot = Some(id);
            }
        }
        None => {
            for (cpu, slot) in out.iter_mut().enumerate().skip(1) {
                *slot = Some(cpu as u32);
            }
        }
    }
    out
}

/// Copies the trampoline to the start-up page and fills in what every
/// start shares (its GDT, jumps, tables, CR0, and `entry`), with the page
/// identity-mapped for the switch to long mode (until [`uninstall`]).
/// Returns the page, if there is one the trampoline can use.
fn install(entry: u64) -> Option<u64> {
    let page = STARTUP_PAGE.load(Ordering::Relaxed);
    let root = vm::kernel_root();
    if page == 0 || root >= 1 << 32 || vm::identity_map(page, true).is_err() {
        return None;
    }
    // SAFETY: the trampoline's bytes, and the start-up page, which nothing
    // else uses; the patched fields are inside the copy.
    unsafe {
        let len = (&raw const sup_ap_end) as usize - (&raw const sup_ap_start) as usize;
        core::ptr::copy_nonoverlapping(&raw const sup_ap_start, vm::phys_ptr(page), len);
        let gdt = page + (&raw const sup_ap_gdt_at).read();
        (at(page, &raw const sup_ap_gdtr).add(2) as *mut u32).write_unaligned(gdt as u32);
        let pm32 = page + (&raw const sup_ap_pm32_at).read();
        (at(page, &raw const sup_ap_far32) as *mut u32).write_unaligned(pm32 as u32);
        let lm64 = page + (&raw const sup_ap_lm64_at).read();
        (at(page, &raw const sup_ap_far64) as *mut u32).write_unaligned(lm64 as u32);
        (at(page, &raw const sup_ap_cr3) as *mut u64).write_unaligned(root);
        // Paging, protection, and CPU 0's other bits, but caching on.
        let cr0 = CR0.load(Ordering::Relaxed) | 1 << 31 | 1;
        (at(page, &raw const sup_ap_cr0) as *mut u64).write_unaligned(cr0);
        (at(page, &raw const sup_ap_entry) as *mut u64).write_unaligned(entry);
    }
    Some(page)
}

/// Takes the start-up page's identity mapping away again.
fn uninstall(page: u64) {
    let _ = vm::identity_map(page, false);
}

/// Sets the stack and CPU number the next CPU through the trampoline at
/// `page` starts with.
fn set_start(page: u64, stack: u64, cpu: usize) {
    // SAFETY: fields inside the trampoline's copy; no CPU is in it (the
    // last one started came up, or none was).
    unsafe {
        (at(page, &raw const sup_ap_stack) as *mut u64).write_unaligned(stack);
        (at(page, &raw const sup_ap_cpu) as *mut u64).write_unaligned(cpu as u64);
    }
}

/// Readies the trampoline for CPU 0 to wake from S3 into `entry` (with
/// `stack`, which `entry` replaces): the page to give the firmware, with
/// it identity-mapped until [`wake_done`].
pub fn prepare_wake(entry: u64, stack: u64) -> Option<u64> {
    let page = install(entry)?;
    set_start(page, stack, 0);
    Some(page)
}

/// CPU 0 is awake (or did not sleep): the start-up page is not needed.
pub fn wake_done(page: u64) {
    uninstall(page);
}

/// Starts the other CPUs ([`others`]), up to [`MAX_CPUS`] in all, each
/// numbered in turn; stops at one that does not come up. Returns how many
/// CPUs are online.
pub fn start_secondaries() -> usize {
    let Some(page) = install(ap_main as *const () as u64) else {
        return smp::online();
    };
    for (cpu, apic) in others().into_iter().enumerate().skip(1) {
        let Some(apic) = apic else { break };
        APIC_OF[cpu].store(apic, Ordering::Relaxed);
        if !start_one(page, cpu, apic) {
            APIC_OF[cpu].store(u32::MAX, Ordering::Relaxed);
            break;
        }
    }
    uninstall(page);
    smp::online()
}

/// After S3: starts the CPUs that were online before it again, as they
/// were numbered (they lost all their state, and run the scheduler
/// afresh). Returns how many CPUs are online.
pub fn restart_secondaries(before: usize) -> usize {
    smp::ONLINE.store(1, Ordering::Release);
    let Some(page) = install(ap_main as *const () as u64) else {
        return smp::online();
    };
    for cpu in 1..before {
        let apic = apic_of(cpu);
        crate::smp::restarted(cpu);
        if apic == u32::MAX || !start_one(page, cpu, apic) {
            break;
        }
    }
    uninstall(page);
    smp::online()
}

/// Starts CPU `cpu` (local APIC ID `apic`) through the trampoline at
/// `page`; returns whether it came up.
fn start_one(page: u64, cpu: usize, apic: u32) -> bool {
    {
        // Below a page kept free for the first entry to user mode.
        let stack = gdt::kernel_stack_top(cpu) - 4096;
        set_start(page, stack, cpu);
        apic::start_cpu(apic as usize, page);
        // Up to 200 ms to come up; QEMU starts nothing for an ID it does
        // not have.
        let mut waited = 0;
        while smp::online() <= cpu && waited < 200 {
            apic::delay_us(1000);
            waited += 1;
        }
        smp::online() > cpu
    }
}

/// Loads CPU 0's CR4 (and XCR0) on this CPU: after the trampoline, which
/// sets only what long mode needs.
pub fn restore_control_registers() {
    // SAFETY: the same settings CPU 0 runs with.
    unsafe {
        let cr4 = CR4.load(Ordering::Relaxed) | CR4_PAE;
        x86_64::registers::control::Cr4::write_raw(cr4);
        if cr4 & CR4_OSXSAVE != 0 {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0,
                in("eax") XCR0.load(Ordering::Relaxed) as u32,
                in("edx") (XCR0.load(Ordering::Relaxed) >> 32) as u32,
                options(nostack)
            );
        }
    }
}

/// A started CPU in long mode on its own stack: CPU 0's control
/// registers, its own GDT, TSS and `syscall` set-up, the IDT, its APIC and
/// timer; then it schedules.
extern "C" fn ap_main(cpu: u64) -> ! {
    let cpu = cpu as usize;
    restore_control_registers();
    gdt::init(cpu);
    interrupts::load();
    syscall::init(cpu);
    apic::init_ap();
    debug_assert_eq!(apic::id() as u32, apic_of(cpu));
    smp::ONLINE.fetch_add(1, Ordering::AcqRel);
    crate::task::start()
}
