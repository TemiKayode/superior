//! AArch64 on QEMU's `virt` machine: entered at EL1 with the MMU off, at
//! the link address, with the device tree at the start of RAM. The kernel
//! runs at EL1 and user threads at EL0. Devices: a PL011 UART, a GICv2
//! interrupt controller and the architected generic timer.
//!
//! One translation table base (`TTBR0_EL1`) serves both: every address
//! space shares the kernel's first top-level entry, an identity map of
//! devices and RAM that only EL1 can touch, and owns its user window at
//! the same address as on x86-64.

pub mod exceptions;
mod fdt;
mod gic;
#[path = "smmu.rs"]
pub mod iommu;
pub mod qemu;
pub mod serial;
mod timer;
pub mod vm;

pub use exceptions::{enter_user, Args, Exit, UserFrame};
#[cfg_attr(not(feature = "selftest"), allow(unused_imports))]
pub use timer::TICK_HZ;

use crate::kprintln;
use crate::memory::{add_region, Summary};
use superior_objects::cap::{Capability, Object, Rights};

pub const NAME: &str = "aarch64";

/// The PL011's register page and its interrupt (SPI 1).
const UART_BASE: u64 = 0x0900_0000;
const UART_IRQ: u8 = 33;
/// Where QEMU puts the device tree for a bare-metal image.
const DTB_DEFAULT: u64 = 0x4000_0000;
const BOOT_STACK_SIZE: usize = 128 * 1024;
/// The device tree in use, for drivers that look themselves up later.
static DTB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Finds and turns on the IOMMU, if the machine has one.
pub fn iommu_init() -> Option<&'static str> {
    iommu::init(DTB.load(core::sync::atomic::Ordering::Relaxed))
}

#[repr(C, align(16))]
struct Stack([u8; BOOT_STACK_SIZE]);

/// The kernel's only stack: boot, system calls, faults and interrupts.
#[no_mangle]
static mut BOOT_STACK: Stack = Stack([0; BOOT_STACK_SIZE]);

fn stack_top() -> u64 {
    core::ptr::addr_of!(BOOT_STACK) as u64 + BOOT_STACK_SIZE as u64
}

extern "C" {
    static __kernel_end: u8;
}

// Boot: park secondary CPUs, set up the stack, zero .bss, build the
// kernel's identity map (devices below 1 GiB, RAM in the second GiB, both
// EL1-only) and turn on the MMU and caches before any Rust code runs. With
// the MMU off every access is Device memory, where unaligned accesses fault.
//
// MAIR: attribute 0 = Device-nGnRE, 1 = Normal write-back.
// TCR: 48-bit VAs through TTBR0 with 4 KiB pages, inner-shareable
// write-back walks, TTBR1 walks disabled, 40-bit physical addresses.
// SCTLR: MMU, caches, stack alignment checks; user mode may read the
// cache type and use `dc zva`, and `wfi` from user mode traps.
core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    "_start:",
    "    mrs x1, mpidr_el1",
    "    and x1, x1, #0xff",
    "    cbz x1, 2f",
    "1:  wfe",
    "    b 1b",
    "2:  mov x19, x0",
    "    adrp x1, {stack}",
    "    add x1, x1, :lo12:{stack}",
    "    mov x2, #{stack_size}",
    "    add sp, x1, x2",
    "    adrp x1, __bss_start",
    "    add x1, x1, :lo12:__bss_start",
    "    adrp x2, __bss_end",
    "    add x2, x2, :lo12:__bss_end",
    "3:  cmp x1, x2",
    "    b.hs 4f",
    "    str xzr, [x1], #8",
    "    b 3b",
    "4:  adrp x1, {l0}",
    "    add x1, x1, :lo12:{l0}",
    "    adrp x2, {l1}",
    "    add x2, x2, :lo12:{l1}",
    "    orr x3, x2, #3",
    "    str x3, [x1]",
    "    ldr x3, ={device_block}",
    "    str x3, [x2]",
    "    ldr x3, ={ram_block}",
    "    str x3, [x2, #8]",
    "    dsb ish",
    "    ldr x3, ={mair}",
    "    msr mair_el1, x3",
    "    ldr x3, ={tcr}",
    "    msr tcr_el1, x3",
    "    msr ttbr0_el1, x1",
    "    isb",
    "    tlbi vmalle1",
    "    dsb ish",
    "    isb",
    "    ldr x3, ={sctlr}",
    "    msr sctlr_el1, x3",
    "    isb",
    "    mov x0, x19",
    "    bl {main}",
    "    b 1b",
    stack = sym BOOT_STACK,
    stack_size = const BOOT_STACK_SIZE,
    l0 = sym vm::KERNEL_L0,
    l1 = sym vm::KERNEL_L1,
    device_block = const vm::KERNEL_DEVICE_BLOCK,
    ram_block = const vm::KERNEL_RAM_BLOCK,
    mair = const vm::MAIR,
    tcr = const vm::TCR,
    sctlr = const vm::SCTLR,
    main = sym kernel_main,
);

#[no_mangle]
extern "C" fn kernel_main(dtb: u64) -> ! {
    serial::init();
    crate::banner();
    exceptions::init();
    kprintln!("[ok] MMU on; exception vectors installed");

    let dtb = if fdt::valid(dtb) { dtb } else { DTB_DEFAULT };
    DTB.store(dtb, core::sync::atomic::Ordering::Relaxed);
    let mut ram = [(0u64, 0u64); fdt::MAX_RANGES];
    let n = fdt::memory(dtb, &mut ram).expect("no usable device tree");
    let kernel_end = core::ptr::addr_of!(__kernel_end) as u64;
    let dtb_end = dtb + fdt::size(dtb);
    let mut mem = Summary::default();
    for &(base, size) in &ram[..n] {
        // The kernel maps only the second GiB, where QEMU's RAM starts.
        let (base, end) = (
            base.max(vm::KERNEL_RAM.start),
            (base + size).min(vm::KERNEL_RAM.end),
        );
        if base >= end {
            continue;
        }
        vm::note_ram(base, end);
        // Everything below the end of the kernel image holds the device
        // tree and the kernel; a device tree placed above it is skipped.
        let start = base.max(kernel_end);
        if (start..end).contains(&dtb) {
            add_region(&mut mem, start, dtb & !0xfff);
            add_region(&mut mem, (dtb_end + 0xfff) & !0xfff, end);
        } else {
            add_region(&mut mem, start, end);
        }
    }
    crate::report_memory(&mem);
    gic::init();
    let hz = timer::init();
    gic::unmask(timer::INTID);
    kprintln!(
        "[ok] GICv2, generic timer: {} kHz counter, {} Hz tick",
        hz / 1000,
        TICK_HZ
    );
    crate::kernel_start(mem.untyped_caps)
}

/// The shell's console: the PL011's register page, as a device frame it
/// maps itself, and its interrupt line.
pub fn console_caps() -> (Capability, Capability) {
    (
        Capability::new(
            Object::Frame {
                paddr: UART_BASE,
                size_bits: 12,
            },
            Rights::READ | Rights::WRITE | Rights::MAP,
        ),
        Capability::new(Object::Irq { line: UART_IRQ }, Rights::READ | Rights::WRITE),
    )
}

/// `brk` must trap into the kernel's handler and return.
#[cfg_attr(not(feature = "selftest"), allow(dead_code))]
pub fn breakpoint_selftest() {
    // SAFETY: the EL1 synchronous handler logs a `brk` and skips it.
    unsafe { core::arch::asm!("brk #0", options(nostack)) };
}

/// Waits for an interrupt and lets it be taken. `wfi` wakes on a pending
/// interrupt even while interrupts are masked, so one that arrives before
/// it is not missed; unmasking afterwards takes it.
pub fn idle_wait() {
    // SAFETY: the interrupt handler saves and restores everything.
    unsafe {
        core::arch::asm!(
            "wfi",
            "msr daifclr, #2",
            "isb",
            "msr daifset, #2",
            options(nostack)
        )
    };
}

/// MSI lines: the first [`MSI_COUNT`] interrupt IDs of the GICv2m frame.
const MSI_COUNT: u32 = 8;

fn msi_lines() -> core::ops::Range<u8> {
    let (first, count) = gic::msi_spis();
    let count = count.min(MSI_COUNT);
    first as u8..(first + count) as u8
}

pub fn irq_routable(line: u8) -> bool {
    line == UART_IRQ || msi_lines().contains(&line)
}

/// The message a device writes to raise MSI line `line`, if it is one:
/// the line's interrupt ID, written to the GICv2m doorbell.
pub fn msi_message(line: u8) -> Option<(u64, u64)> {
    msi_lines()
        .contains(&line)
        .then_some((gic::MSI_DOORBELL, line as u64))
}

/// For the root task's PCI bus server: the ECAM configuration window
/// (buses 0-15), a device-memory window to assign BARs from, and the MSI
/// lines. These are QEMU `virt`'s addresses with `highmem=off`, which keeps
/// ECAM below 4 GiB: ECAM at 0x3f00_0000, PCI memory from 0x1000_0000.
pub fn pci_caps() -> (Capability, Capability, core::ops::Range<u8>) {
    (
        Capability::new(
            Object::DeviceUntyped {
                base: 0x3f00_0000,
                size_bits: 24,
            },
            Rights::ALL,
        ),
        Capability::new(
            Object::DeviceUntyped {
                base: 0x1000_0000,
                size_bits: 28,
            },
            Rights::ALL,
        ),
        msi_lines(),
    )
}

pub fn irq_unmask(line: u8) {
    gic::unmask(line as u32)
}

/// There are no I/O ports on AArch64.
pub fn io_in(_port: u16, _width: u64) -> u64 {
    0
}

/// There are no I/O ports on AArch64; a write to port 0xf4, QEMU's exit
/// device on x86-64, is emulated through semihosting with the same exit
/// status, so `shutdown` works on both.
pub fn io_out(port: u16, _width: u64, value: u64) {
    if port == 0xf4 {
        qemu::exit_status(((value as u32) << 1) | 1);
    }
}

#[cfg_attr(not(feature = "selftest"), allow(dead_code))]
pub fn qemu_exit(pass: bool) -> ! {
    qemu::exit_status(if pass { 33 } else { 35 })
}

pub fn disable_interrupts() {
    // SAFETY: masking interrupts is always safe.
    unsafe { core::arch::asm!("msr daifset, #3", options(nostack)) };
}

pub fn halt_forever() -> ! {
    loop {
        // SAFETY: waiting for an event has no other effect.
        unsafe { core::arch::asm!("wfe", options(nostack)) };
    }
}
