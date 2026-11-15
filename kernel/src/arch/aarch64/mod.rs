//! AArch64 on QEMU's `virt` machine: entered at EL1 or EL2 with the MMU
//! off, at the link address, with a device tree's address in x0 (entered
//! at EL2, each CPU sets EL1 up and steps down to it first): QEMU's own at the
//! start of RAM (`-kernel`), or the UEFI loader's, which lists the RAM the
//! firmware's memory map leaves free and points under `/chosen` to the
//! firmware's device tree or to its ACPI tables ([`acpi`]). The kernel
//! runs at EL1 and user threads at EL0. Devices: a PL011 UART, a GICv3
//! interrupt controller with an ITS, and the architected generic timer.
//! The other CPUs are started through PSCI (`CPU_ON`, by `hvc`, or by `smc`
//! where EL2 is there to catch `hvc`, as the device tree or ACPI's FADT
//! says; QEMU answers either itself) at [`ap_start`], each with its own stack, redistributor
//! and timer; CPU `n` is the one whose MPIDR affinity 0 is `n`.
//!
//! One translation table base (`TTBR0_EL1`) serves both: every address
//! space shares the kernel's first top-level entry, an identity map of
//! devices and RAM that only EL1 can touch, and owns its user window at
//! the same address as on x86-64.

mod acpi;
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
pub use timer::{alarm, alarm_fired, alarm_keep, tick_start, tick_stop, TICK_HZ};

use crate::kprintln;
use crate::memory::{add_region, Summary};
use crate::smp::{self, MAX_CPUS};
use superior_objects::cap::{Capability, Object, Rights};

pub const NAME: &str = "aarch64";

/// The PL011's register page and its interrupt (SPI 1).
const UART_BASE: u64 = 0x0900_0000;
const UART_IRQ: u8 = 33;
/// Where QEMU puts the device tree for a bare-metal image.
const DTB_DEFAULT: u64 = 0x4000_0000;
const BOOT_STACK_SIZE: usize = 128 * 1024;
/// PSCI 0.2's `CPU_ON`, 64-bit.
const PSCI_CPU_ON: u64 = 0xc400_0003;
/// The firmware's device tree, for drivers that look themselves up later
/// (none when the machine is described by ACPI).
static DTB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The machine is described by ACPI: the SMMU, if any (registers, and its
/// event interrupt ID or 0), as its IORT gives it.
static ACPI: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static ACPI_SMMU: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static ACPI_SMMU_IRQ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// PSCI is called by `smc`, not `hvc`.
static PSCI_SMC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// CPUs to bring up at most: ACPI's MADT says how many there are.
static CPU_LIMIT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(MAX_CPUS);
/// QEMU `virt`'s ECAM with `highmem=off`: the kernel hands it out as it is.
const ECAM_BASE: u64 = 0x3f00_0000;

/// User space is about to start. Nothing to hand over: QEMU's `virt`
/// machine boots with no framebuffer, so the log is on the PL011 alone.
pub fn console_hand_over() {}

/// Finds and turns on the IOMMU, if the machine has one.
pub fn iommu_init() -> Option<&'static str> {
    use core::sync::atomic::Ordering::Relaxed;
    if ACPI.load(Relaxed) {
        let base = ACPI_SMMU.load(Relaxed);
        let irq = ACPI_SMMU_IRQ.load(Relaxed);
        if base == 0 {
            return None;
        }
        return iommu::init(base, (irq != 0).then_some(irq));
    }
    let (base, irq) = fdt::find_device(DTB.load(Relaxed), b"arm,smmu-v3")?;
    iommu::init(base, irq)
}

#[repr(C, align(16))]
struct Stack([u8; BOOT_STACK_SIZE]);

/// Each CPU's only stack: boot, system calls, faults and interrupts.
#[no_mangle]
static mut BOOT_STACKS: [Stack; MAX_CPUS] = [const { Stack([0; BOOT_STACK_SIZE]) }; MAX_CPUS];

fn stack_top(cpu: usize) -> u64 {
    core::ptr::addr_of!(BOOT_STACKS) as u64 + ((cpu + 1) * BOOT_STACK_SIZE) as u64
}

/// This CPU's number: its MPIDR affinity 0.
pub fn cpu_id() -> usize {
    let mpidr: u64;
    // SAFETY: reading MPIDR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack, nomem)) };
    (mpidr & 0xff) as usize
}

/// Interrupts between CPUs.
#[derive(Clone, Copy)]
pub enum Ipi {
    /// Enter the kernel and reschedule.
    Kick,
    /// Carry out a shootdown request (`crate::smp`).
    Shootdown,
}

pub fn send_ipi(cpu: usize, ipi: Ipi) {
    gic::send_sgi(
        cpu,
        match ipi {
            Ipi::Kick => gic::KICK_SGI,
            Ipi::Shootdown => gic::SHOOTDOWN_SGI,
        },
    )
}

/// Starts the other CPUs, one at a time, until PSCI says there are no
/// more (or [`MAX_CPUS`]). Returns how many CPUs are online.
pub fn start_secondaries() -> usize {
    let limit = CPU_LIMIT.load(core::sync::atomic::Ordering::Relaxed).min(MAX_CPUS);
    for cpu in 1..limit {
        let r = psci(PSCI_CPU_ON, cpu as u64, ap_start as *const () as u64, cpu as u64);
        if r != 0 {
            break;
        }
        // A second at most to come up.
        let deadline = timer::counter() + timer::frequency();
        while smp::online() <= cpu {
            if timer::counter() > deadline {
                panic!("CPU {cpu} did not come up");
            }
            core::hint::spin_loop();
        }
    }
    smp::online()
}

/// A PSCI call, by the conduit the firmware's description names.
fn psci(function: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let r: i64;
    if PSCI_SMC.load(core::sync::atomic::Ordering::Relaxed) {
        // SAFETY: a PSCI call, which the caller makes for its own ends;
        // the firmware may clobber x0 to x17.
        unsafe {
            core::arch::asm!(
                "smc #0",
                inout("x0") function => r,
                inout("x1") a1 => _,
                inout("x2") a2 => _,
                inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack)
            )
        };
    } else {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(
                "hvc #0",
                inout("x0") function => r,
                inout("x1") a1 => _,
                inout("x2") a2 => _,
                inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack)
            )
        };
    }
    r
}

extern "C" {
    fn ap_start();
}

/// A started CPU, on its own stack with the MMU on: its exception vectors,
/// redistributor and CPU interface, and timer; then it schedules.
#[no_mangle]
extern "C" fn ap_main(cpu: u64) -> ! {
    exceptions::init();
    gic::init_cpu(cpu as usize);
    timer::init_cpu();
    gic::unmask(timer::INTID);
    smp::ONLINE.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    crate::task::start()
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
    "    bl el2_to_el1",
    "    mov x20, x9",
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
    "    mov x1, x20",
    "    bl {main}",
    "    b 1b",
    // A CPU started by PSCI, with its number in x0: its own stack (below
    // a page kept free for the first entry to user mode), the kernel's
    // tables (already built), the MMU on.
    ".global ap_start",
    "ap_start:",
    "    mov x19, x0",
    "    bl el2_to_el1",
    "    mov x0, x19",
    "    adrp x1, {stack}",
    "    add x1, x1, :lo12:{stack}",
    "    mov x2, #{stack_size}",
    "    add x3, x0, #1",
    "    mul x3, x3, x2",
    "    add x1, x1, x3",
    "    sub sp, x1, #4096",
    "    ldr x3, ={mair}",
    "    msr mair_el1, x3",
    "    ldr x3, ={tcr}",
    "    msr tcr_el1, x3",
    "    adrp x1, {l0}",
    "    add x1, x1, :lo12:{l0}",
    "    msr ttbr0_el1, x1",
    "    isb",
    "    tlbi vmalle1",
    "    dsb ish",
    "    isb",
    "    ldr x3, ={sctlr}",
    "    msr sctlr_el1, x3",
    "    isb",
    "    bl {ap_main}",
    "    b 1b",
    // Entered at EL2: EL1 gets the machine as if there were no EL2 (EL1
    // in AArch64, nothing trapped, the counter and timers, the GIC's
    // system registers, FP and SIMD, the PMU's counters, its own MIDR
    // and MPIDR, no stage 2), and this returns there, at EL1 with the
    // MMU off and interrupts masked. Entered at EL1, it just returns.
    // x9 is then 1 if it stepped down, 0 if not; x0 to x8 are kept.
    "el2_to_el1:",
    "    mrs x9, CurrentEL",
    "    cmp x9, #8",
    "    b.eq 7f",
    "    mov x9, #0",
    "    ret",
    "7:  mov x9, #0x80000000", // HCR_EL2.RW: EL1 is AArch64
    "    msr hcr_el2, x9",
    "    isb",
    "    mov x9, #3", // CNTHCTL_EL2: EL1PCTEN, EL1PCEN
    "    msr cnthctl_el2, x9",
    "    msr cntvoff_el2, xzr",
    "    mrs x9, id_aa64pfr0_el1",
    "    ubfx x9, x9, #24, #4", // GIC system register interface
    "    cbz x9, 8f",
    "    mrs x9, icc_sre_el2",
    "    orr x9, x9, #0xf", // SRE, DFB, DIB, and EL1 may use SRE
    "    msr icc_sre_el2, x9",
    "    isb",
    "    msr ich_hcr_el2, xzr",
    "8:  mov x9, #0x33ff", // CPTR_EL2: its RES1 bits; FP not trapped
    "    msr cptr_el2, x9",
    "    msr hstr_el2, xzr",
    "    msr vttbr_el2, xzr",
    "    mrs x9, id_aa64dfr0_el1",
    "    ubfx x9, x9, #8, #4", // PMUVer
    "    mov x10, #0",
    "    cbz x9, 9f",
    "    cmp x9, #0xf",
    "    b.eq 9f",
    "    mrs x10, pmcr_el0",
    "    ubfx x10, x10, #11, #5", // PMCR_EL0.N: every counter to EL1
    "9:  msr mdcr_el2, x10",
    "    mrs x9, midr_el1",
    "    msr vpidr_el2, x9",
    "    mrs x9, mpidr_el1",
    "    msr vmpidr_el2, x9",
    "    ldr x9, =0x30d00800", // SCTLR_EL1: its RES1 bits; MMU, caches off
    "    msr sctlr_el1, x9",
    "    mov x9, #0x3c5", // SPSR_EL2: EL1h, D, A, I and F masked
    "    msr spsr_el2, x9",
    "    msr elr_el2, x30",
    "    mov x9, #1",
    "    isb",
    "    eret",
    stack = sym BOOT_STACKS,
    stack_size = const BOOT_STACK_SIZE,
    l0 = sym vm::KERNEL_L0,
    l1 = sym vm::KERNEL_L1,
    device_block = const vm::KERNEL_DEVICE_BLOCK,
    ram_block = const vm::KERNEL_RAM_BLOCK,
    mair = const vm::MAIR,
    tcr = const vm::TCR,
    sctlr = const vm::SCTLR,
    main = sym kernel_main,
    ap_main = sym ap_main,
);

#[no_mangle]
extern "C" fn kernel_main(dtb: u64, from_el2: u64) -> ! {
    serial::init();
    crate::banner();
    exceptions::init();
    if from_el2 != 0 {
        kprintln!("[ok] entered at EL2: set EL1 up, with nothing trapped, and stepped down to it");
    }
    kprintln!("[ok] MMU on; exception vectors installed");

    let boot = if fdt::valid(dtb) { dtb } else { DTB_DEFAULT };
    // From the UEFI loader: where the firmware's description is.
    let rsdp = fdt::chosen_u64(boot, b"superior,acpi-rsdp");
    let devices = match fdt::chosen_u64(boot, b"superior,device-tree") {
        Some(d) if fdt::valid(d) => d,
        Some(d) => panic!("no device tree at {d:#x}, where the loader says"),
        None if rsdp.is_some() => 0,
        None => boot,
    };
    DTB.store(devices, core::sync::atomic::Ordering::Relaxed);
    // The device tree's PSCI node says how PSCI is called (ACPI's FADT
    // does, below).
    if fdt::device_prop_is(devices, b"arm,psci-0.2", b"method", b"smc") {
        PSCI_SMC.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    let mut ram = [(0u64, 0u64); fdt::MAX_RANGES];
    let n = fdt::memory(boot, &mut ram).expect("no usable device tree");
    let kernel_end = core::ptr::addr_of!(__kernel_end) as u64;
    // The device trees stay where they are: kept out of the RAM handed
    // out, in address order.
    let mut holes = [(boot, boot + fdt::size(boot)), (0, 0)];
    if devices != 0 && devices != boot {
        holes[1] = (devices, devices + fdt::size(devices));
    }
    holes.sort_unstable();
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
        // Everything below the end of the kernel image holds QEMU's device
        // tree and the kernel; device trees placed above it are skipped.
        let mut start = base.max(kernel_end);
        for &(h, h_end) in &holes {
            let (h, h_end) = (h & !0xfff, (h_end + 0xfff) & !0xfff);
            if h_end <= start || h >= end || h == h_end {
                continue;
            }
            add_region(&mut mem, start, h.max(start));
            start = h_end;
        }
        if start < end {
            add_region(&mut mem, start, end);
        }
    }
    crate::report_memory(&mem);
    if let Some(rsdp) = rsdp {
        use_acpi(&acpi::read(rsdp).unwrap_or_else(|e| panic!("ACPI: {e}")));
    }
    gic::init();
    let hz = timer::init();
    gic::unmask(timer::INTID);
    kprintln!(
        "[ok] GICv3{}, generic timer: {} kHz counter, {} Hz tick",
        if gic::its_present() { " with ITS" } else { "" },
        hz / 1000,
        TICK_HZ
    );
    crate::kernel_start(mem.untyped_caps)
}

/// Takes what ACPI says of the machine: the CPUs to start, PSCI and the
/// SMMU; and checks the rest is where the kernel drives it (QEMU `virt`'s
/// layout, which the kernel has fixed: the GIC, the timer, the PL011 and
/// ECAM), refusing to go on if not.
fn use_acpi(m: &acpi::Machine) {
    use core::sync::atomic::Ordering::Relaxed;
    if !matches!(m.gic_version, 0 | 3) {
        panic!("ACPI: a GICv{}, not the GICv3 the kernel drives", m.gic_version);
    }
    if m.gicd != gic::GICD || m.gicr != Some(gic::GICR) || m.its.is_some_and(|its| its != gic::GITS) {
        panic!(
            "ACPI: the GIC's distributor at {:#x}, redistributors at {:#x?}, ITS at {:#x?}; the kernel drives them at {:#x}, {:#x}, {:#x} only",
            m.gicd, m.gicr, m.its, gic::GICD, gic::GICR, gic::GITS
        );
    }
    if m.timer != Some(timer::INTID) {
        panic!("ACPI: the virtual timer's interrupt is {:?} (GTDT), not {}", m.timer, timer::INTID);
    }
    let Some((kind, uart, uart_irq)) = m.uart else {
        panic!("ACPI: no serial console (SPCR)");
    };
    // SPCR interface types 3 (PL011) and 0x0e (SBSA generic UART, a
    // PL011 subset).
    if !matches!(kind, 3 | 0x0e) || uart != UART_BASE || uart_irq != UART_IRQ as u32 {
        panic!(
            "ACPI: the serial console is type {kind:#x} at {uart:#x}, interrupt {uart_irq}; the kernel drives a PL011 at {UART_BASE:#x}, interrupt {UART_IRQ}"
        );
    }
    let Some((ecam, first_bus, last_bus)) = m.ecam else {
        panic!("ACPI: no PCI Express configuration space (MCFG)");
    };
    if ecam != ECAM_BASE || first_bus != 0 || last_bus < 15 {
        panic!("ACPI: ECAM at {ecam:#x}, buses {first_bus} to {last_bus}; the kernel drives buses 0 to 15 at {ECAM_BASE:#x}");
    }
    ACPI.store(true, Relaxed);
    if let Some((base, irq)) = m.smmu {
        ACPI_SMMU.store(base, Relaxed);
        ACPI_SMMU_IRQ.store(irq.unwrap_or(0), Relaxed);
    }
    PSCI_SMC.store(m.psci == Some(false), Relaxed);
    CPU_LIMIT.store(if m.psci.is_some() { m.cpus } else { 1 }, Relaxed);
    kprintln!(
        "[ok] ACPI (RSDP at {:#x}): {} CPUs (MADT){}; GICv3 at {:#x}{}; timer interrupt {} (GTDT); PL011 at {:#x} (SPCR); ECAM at {:#x}, buses {}-{} (MCFG)",
        m.rsdp,
        m.cpus,
        match m.psci {
            Some(true) => ", PSCI by hvc (FADT)",
            Some(false) => ", PSCI by smc (FADT)",
            None => ", no PSCI (FADT): only this one started",
        },
        m.gicd,
        if m.its.is_some() { ", ITS" } else { ", no ITS" },
        timer::INTID,
        uart,
        ecam,
        first_bus,
        last_bus
    );
    match m.smmu {
        Some((base, Some(irq))) => kprintln!("[ok] ACPI: SMMUv3 at {base:#x}, event interrupt {irq}; stream IDs are requester IDs (IORT)"),
        Some((base, None)) => kprintln!("[ok] ACPI: SMMUv3 at {base:#x}, no event interrupt; stream IDs are requester IDs (IORT)"),
        None => kprintln!("[ok] ACPI: no SMMU (IORT)"),
    }
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

/// The virtual counter, for the entropy pool's timings.
pub fn cycles() -> u64 {
    timer::counter()
}

/// The PL031 real-time clock's count: seconds since 1970 (UTC), if the
/// device tree has one.
pub fn rtc_seconds() -> Option<u64> {
    let (base, _) = fdt::find_device(DTB.load(core::sync::atomic::Ordering::Relaxed), b"arm,pl031")?;
    // Devices below 1 GiB are identity-mapped as device memory.
    if base >= 0x4000_0000 {
        return None;
    }
    // SAFETY: the PL031's data register (offset 0), read-only, at the
    // address the device tree gives.
    Some(unsafe { core::ptr::read_volatile(base as *const u32) } as u64)
}

/// RNDR, if the CPU has it (FEAT_RNG: ID_AA64ISAR0_EL1 bits 63:60).
pub fn random_source() -> Option<&'static str> {
    let isar0: u64;
    // SAFETY: reading an ID register has no side effect.
    unsafe { core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack)) };
    (isar0 >> 60 != 0).then_some("RNDR")
}

/// A word from RNDR, retried a few times (it fails, setting Z, when it
/// cannot give one at once); `None` without it.
pub fn random_word() -> Option<u64> {
    random_source()?;
    for _ in 0..32 {
        let (v, nzcv): (u64, u64);
        // SAFETY: RNDR is there (the ID register said so); it only sets
        // the register and the flags. s3_3_c2_c4_0 is RNDR.
        unsafe {
            core::arch::asm!("mrs {}, s3_3_c2_c4_0", "mrs {}, nzcv", out(reg) v, out(reg) nzcv, options(nomem, nostack))
        };
        if nzcv & 1 << 30 == 0 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

/// MSI lines: one LPI each, through the ITS (none without one).
fn msi_lines() -> core::ops::Range<u8> {
    let count = if gic::its_present() { gic::MSI_COUNT } else { 0 };
    gic::MSI_LINE_BASE..gic::MSI_LINE_BASE + count
}

pub fn irq_routable(line: u8) -> bool {
    line == UART_IRQ || msi_lines().contains(&line) || INTX_LINES.contains(&line)
}

/// QEMU `virt`'s four PCI interrupt wires: shared interrupts 3 to 6
/// (interrupt IDs 35 to 38), level-triggered as every shared interrupt
/// is until told otherwise. A function on bus 0 drives wire
/// `(device + pin - 1) % 4`.
const INTX_LINES: [u8; 4] = [35, 36, 37, 38];

/// I/O ports for PCI BARs: QEMU `virt`'s window of device memory that
/// stands for ports 0 to 0xffff, just below the ECAM window.
pub fn pci_io_cap() -> Capability {
    Capability::new(
        Object::DeviceUntyped {
            base: 0x3eff_0000,
            size_bits: 16,
        },
        Rights::ALL,
    )
}

/// The legacy PCI interrupt lines.
pub fn intx_lines() -> &'static [u8] {
    &INTX_LINES
}

/// Which of [`intx_lines`] pin `pin` (1 to 4) of root-bus device `device`
/// reaches: on QEMU `virt`, wire `(device + pin - 1) % 4`, as its device
/// tree's `interrupt-map` says.
pub fn intx_line(device: u8, pin: u8) -> Option<usize> {
    (device < 32 && (1..=4).contains(&pin)).then(|| (device as usize + pin as usize - 1) % 4)
}

/// The message a device writes to raise MSI line `line`, if it is one:
/// an event ID written to the ITS, which the ITS maps to the line for
/// device `source` alone (or for no device).
pub fn msi_message(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    gic::route(line, source)
}

/// For the root task's PCI bus server: the ECAM configuration window
/// (buses 0-15), a device-memory window to assign BARs from, and the MSI
/// lines. These are QEMU `virt`'s addresses with `highmem=off`, which keeps
/// ECAM below 4 GiB: ECAM at 0x3f00_0000, PCI memory from 0x1000_0000.
pub fn pci_caps() -> (Capability, Capability, core::ops::Range<u8>) {
    (
        Capability::new(
            Object::DeviceUntyped {
                base: ECAM_BASE,
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
