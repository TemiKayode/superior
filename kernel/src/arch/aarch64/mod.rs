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
mod platform;
pub mod qemu;
pub mod serial;
mod timer;
pub mod vm;

pub use exceptions::{enter_user, Args, Exit, UserFrame};
#[cfg_attr(not(feature = "selftest"), allow(unused_imports))]
pub use timer::{alarm, alarm_fired, alarm_keep, tick_start, tick_stop, TICK_HZ};

use crate::{kprint, kprintln};
use crate::memory::{add_region, Summary};
use crate::smp::{self, MAX_CPUS};
use superior_objects::cap::{Capability, Object, Rights};

pub const NAME: &str = "aarch64";

/// Where QEMU puts the device tree for a bare-metal image.
const DTB_DEFAULT: u64 = 0x4000_0000;
const BOOT_STACK_SIZE: usize = 128 * 1024;
/// PSCI 0.2's `CPU_ON`, 64-bit.
const PSCI_CPU_ON: u64 = 0xc400_0003;
/// The firmware's device tree, for drivers that look themselves up later
/// (none when the machine is described by ACPI).
static DTB: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The machine, as the firmware describes it: set at boot, before the
/// console is up.
static PLATFORM: spin::Once<platform::Platform> = spin::Once::new();

pub(super) fn platform() -> &'static platform::Platform {
    PLATFORM.get().expect("the machine is read at boot")
}

/// User space is about to start. Nothing to hand over: QEMU's `virt`
/// machine boots with no framebuffer, so the log is on the PL011 alone.
pub fn console_hand_over() {}

/// The user thread pointer (`TPIDR_EL0`) as the thread left it: user code
/// may set it itself.
pub fn user_tls() -> Option<u64> {
    let v: u64;
    // SAFETY: reading TPIDR_EL0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) v, options(nostack, nomem)) };
    Some(v)
}

/// A thread's floating-point and SIMD registers (only foreign threads
/// have any: Superior's own code is built without them).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FpState {
    q: [u128; 32],
    fpsr: u64,
    fpcr: u64,
}

impl FpState {
    /// Linux's initial state: all zero (round to nearest, no traps).
    pub const INITIAL: FpState = FpState { q: [0; 32], fpsr: 0, fpcr: 0 };
}

/// Whether each CPU lets user code use the FP/SIMD registers.
static FP_ON: [core::sync::atomic::AtomicBool; superior_objects::ipc::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; superior_objects::ipc::MAX_CPUS];

/// FP/SIMD for the kernel's own saves (CPACR_EL1.FPEN = 0b01), trapped at
/// EL0 until a foreign thread runs.
pub fn fp_cpu_init() {
    // SAFETY: FPEN only decides which levels trap FP/SIMD instructions.
    unsafe { core::arch::asm!("msr cpacr_el1, {}", "isb", in(reg) 1u64 << 20, options(nostack)) };
    FP_ON[cpu_id()].store(false, core::sync::atomic::Ordering::Relaxed);
}

/// Lets user code use the FP/SIMD registers (`on`, for a foreign thread),
/// or makes them trap.
pub fn fp_enable(on: bool) {
    use core::sync::atomic::Ordering::Relaxed;
    if FP_ON[cpu_id()].swap(on, Relaxed) != on {
        let fpen: u64 = if on { 3 << 20 } else { 1 << 20 };
        // SAFETY: as in `fp_cpu_init`.
        unsafe { core::arch::asm!("msr cpacr_el1, {}", "isb", in(reg) fpen, options(nostack)) };
    }
}

/// Saves the FP/SIMD registers into `s`.
pub fn fp_save(s: &mut FpState) {
    // SAFETY: `s` is 528 writable bytes, 16-byte aligned; EL1 may use
    // FP/SIMD (FPEN is never below 0b01).
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            ".arch_extension simd",
            "stp q0, q1, [{s}, #0]",
            "stp q2, q3, [{s}, #32]",
            "stp q4, q5, [{s}, #64]",
            "stp q6, q7, [{s}, #96]",
            "stp q8, q9, [{s}, #128]",
            "stp q10, q11, [{s}, #160]",
            "stp q12, q13, [{s}, #192]",
            "stp q14, q15, [{s}, #224]",
            "stp q16, q17, [{s}, #256]",
            "stp q18, q19, [{s}, #288]",
            "stp q20, q21, [{s}, #320]",
            "stp q22, q23, [{s}, #352]",
            "stp q24, q25, [{s}, #384]",
            "stp q26, q27, [{s}, #416]",
            "stp q28, q29, [{s}, #448]",
            "stp q30, q31, [{s}, #480]",
            "mrs {a}, fpsr",
            "mrs {b}, fpcr",
            "add {s}, {s}, #512",
            "stp {a}, {b}, [{s}]",
            s = inout(reg) s as *mut FpState => _,
            a = out(reg) _,
            b = out(reg) _,
            options(nostack)
        )
    };
}

/// Loads the FP/SIMD registers from `s`.
pub fn fp_restore(s: &FpState) {
    // SAFETY: as in `fp_save`, reading.
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            ".arch_extension simd",
            "ldp q0, q1, [{s}, #0]",
            "ldp q2, q3, [{s}, #32]",
            "ldp q4, q5, [{s}, #64]",
            "ldp q6, q7, [{s}, #96]",
            "ldp q8, q9, [{s}, #128]",
            "ldp q10, q11, [{s}, #160]",
            "ldp q12, q13, [{s}, #192]",
            "ldp q14, q15, [{s}, #224]",
            "ldp q16, q17, [{s}, #256]",
            "ldp q18, q19, [{s}, #288]",
            "ldp q20, q21, [{s}, #320]",
            "ldp q22, q23, [{s}, #352]",
            "ldp q24, q25, [{s}, #384]",
            "ldp q26, q27, [{s}, #416]",
            "ldp q28, q29, [{s}, #448]",
            "ldp q30, q31, [{s}, #480]",
            "add {s}, {s}, #512",
            "ldp {a}, {b}, [{s}]",
            "msr fpsr, {a}",
            "msr fpcr, {b}",
            s = inout(reg) s as *const FpState => _,
            a = out(reg) _,
            b = out(reg) _,
            options(nostack)
        )
    };
}

/// Loads a user thread pointer into `TPIDR_EL0`.
pub fn set_user_tls(v: u64) {
    // SAFETY: TPIDR_EL0 is a scratch register the kernel does not use.
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) v, options(nostack, nomem)) };
}

/// Finds and turns on the IOMMU, if the machine has one.
pub fn iommu_init() -> Option<&'static str> {
    let (base, irq) = platform().smmu?;
    if !vm::map_device(base) {
        kprintln!("[warn] IOMMU: the SMMUv3 at {base:#x} is where the kernel cannot map it");
        return None;
    }
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
    let limit = platform().cpus.unwrap_or(MAX_CPUS).min(MAX_CPUS);
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
    if platform().psci_smc {
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
    gic::unmask(timer::intid());
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
    // The machine first, so the console is known: from the device tree,
    // or the ACPI tables the UEFI loader points to. Nothing is printed
    // before the console is up.
    let boot = if fdt::valid(dtb) { dtb } else { DTB_DEFAULT };
    let rsdp = fdt::chosen_u64(boot, b"superior,acpi-rsdp");
    let named = fdt::chosen_u64(boot, b"superior,device-tree");
    let devices = match named {
        Some(d) if fdt::valid(d) => d,
        Some(_) => 0,
        None if rsdp.is_some() => 0,
        None => boot,
    };
    DTB.store(devices, core::sync::atomic::Ordering::Relaxed);
    let tables = rsdp.map(acpi::read);
    let p = *PLATFORM.call_once(|| match &tables {
        Some(Ok(m)) => platform::Platform::from_acpi(m),
        Some(Err(_)) => platform::Platform { source: "ACPI", ..Default::default() },
        None => platform::Platform::from_device_tree(devices),
    });
    if let Some((base, _)) = p.uart {
        if vm::map_device(base) {
            serial::init(base);
        }
    }
    crate::banner();
    exceptions::init();
    if from_el2 != 0 {
        kprintln!("[ok] entered at EL2: set EL1 up, with nothing trapped, and stepped down to it");
    }
    kprintln!("[ok] MMU on; exception vectors installed");
    if let Some(d) = named.filter(|_| devices == 0) {
        panic!("no device tree at {d:#x}, where the loader says");
    }
    if let Some(Err(e)) = &tables {
        panic!("ACPI: {e}");
    }
    if let Some(what) = p.missing() {
        panic!("the machine ({}): {what}", p.source);
    }
    if let Some(Ok(m)) = &tables {
        kprintln!(
            "[ok] ACPI (RSDP at {:#x}): {} CPUs (MADT), {}",
            m.rsdp,
            m.cpus,
            match m.psci {
                Some(true) => "PSCI by hvc (FADT)",
                Some(false) => "PSCI by smc (FADT)",
                None => "no PSCI (FADT): only this one started",
            }
        );
    }
    report_machine(&p);
    report_intx(&p);

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
    report_reserved(&p);
    dbc_init(&p);
    let (gicd, gicr) = (p.gicd.unwrap_or(0), p.gicr.unwrap_or(0));
    for base in [gicd, gicr].into_iter().chain(p.its) {
        if !vm::map_device(base) {
            panic!("the GIC's registers at {base:#x} are where the kernel cannot map them");
        }
    }
    gic::set_bases(gicd, gicr, p.its);
    timer::set_intid(p.timer.unwrap_or(27));
    gic::init();
    let hz = timer::init();
    gic::unmask(timer::intid());
    kprintln!(
        "[ok] GICv3{}, generic timer: {} kHz counter, {} Hz tick",
        if gic::its_present() { " with ITS" } else { "" },
        hz / 1000,
        TICK_HZ
    );
    crate::kernel_start(mem.untyped_caps)
}

/// The log over USB, if an xHCI has a Debug Capability: found through
/// ECAM (its first 16 buses), its registers mapped as device memory, its
/// rings in pages of RAM (identity-mapped).
fn dbc_init(p: &platform::Platform) {
    let Some(ecam) = p.ecam.filter(|&e| vm::map_device(e)) else { return };
    let at = move |bus: u8, devfn: u8, off: u16| (ecam + ((bus as u64) << 20 | (devfn as u64) << 12 | (off as u64 & 0xffc))) as *mut u32;
    // SAFETY: ECAM, mapped as device memory.
    let read = |bus, devfn, off| unsafe { core::ptr::read_volatile(at(bus, devfn, off)) };
    // SAFETY: as above.
    let write = |bus, devfn, off, v| unsafe { core::ptr::write_volatile(at(bus, devfn, off), v) };
    let map = |pa: u64| vm::map_device(pa).then_some(pa);
    let page = || crate::memory::user_page().map(|pa| (pa, pa as *mut u8));
    crate::dbc::init(&crate::dbc::Pci { read: &read, write: &write, buses: 16, map: &map, page: &page }, "the PL011");
}

/// The IORT's reserved memory ranges: one line on how many, and one for
/// each kept, with the functions it is for (stream IDs are requester
/// IDs). Once RAM is known: pages of it the kernel has as RAM are not
/// mapped for the function, and that is said.
fn report_reserved(p: &platform::Platform) {
    if p.source != "ACPI" {
        return;
    }
    kprintln!(
        "[ok] ACPI: {} reserved memory range{} (IORT){}",
        p.reserved_found,
        if p.reserved_found == 1 { "" } else { "s" },
        if p.reserved_count < p.reserved_found { ", some not used (not whole pages, for another SMMU, or too many)" } else { "" }
    );
    let bdf = |sid: u32| (sid >> 8 & 0xff, sid >> 3 & 31, sid & 7);
    for r in &p.reserved[..p.reserved_count] {
        let (b, d, f) = bdf(r.sid);
        kprint!("[ok] ACPI: reserved memory {:#x} to {:#x}, for {b:02x}:{d:02x}.{f}", r.start, r.end - 1);
        if r.sids > 1 {
            let (b, d, f) = bdf(r.sid + r.sids - 1);
            kprint!(" to {b:02x}:{d:02x}.{f}");
        }
        kprintln!();
        let usable = (r.start..r.end).step_by(4096).filter(|&pa| crate::memory::is_ram(pa)).count();
        if usable > 0 {
            kprintln!("[warn] ACPI: {usable} of its pages are usable RAM too: they are not mapped for it");
        }
    }
}

/// One line on where everything is, as the firmware said.
fn report_machine(p: &platform::Platform) {
    let (uart, uart_irq) = p.uart.unwrap_or_default();
    let (mem, mem_bits) = p.pci_mem.unwrap_or_default();
    kprintln!(
        "[ok] machine ({}): GICv3 at {:#x}, redistributors at {:#x}, {}; timer interrupt {}; PL011 at {:#x}, interrupt {}; PCI: ECAM at {:#x}, memory at {:#x} ({} MiB), {}",
        p.source,
        p.gicd.unwrap_or(0),
        p.gicr.unwrap_or(0),
        match p.its {
            Some(its) => labelled_hex("ITS at ", its),
            None => labelled_hex("no ITS", u64::MAX),
        },
        p.timer.unwrap_or(0),
        uart,
        uart_irq,
        p.ecam.unwrap_or(0),
        mem,
        (1u64 << mem_bits) >> 20,
        match p.pci_io {
            Some((io, _)) => labelled_hex("I/O ports at ", io),
            None => labelled_hex("no I/O ports", u64::MAX),
        }
    );
    match p.smmu {
        Some((base, Some(irq))) => kprintln!("[ok] machine ({}): SMMUv3 at {base:#x}, event interrupt {irq}", p.source),
        Some((base, None)) => kprintln!("[ok] machine ({}): SMMUv3 at {base:#x}, no event interrupt", p.source),
        None => kprintln!("[ok] machine ({}): no SMMU", p.source),
    }
}

/// `label` and `v` in hex (`label` alone if `v` is `u64::MAX`), for a log
/// line, without the heap.
fn labelled_hex(label: &'static str, v: u64) -> Hex {
    Hex(label, v)
}

struct Hex(&'static str, u64);

impl core::fmt::Display for Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.1 == u64::MAX {
            f.write_str(self.0)
        } else {
            write!(f, "{}{:#x}", self.0, self.1)
        }
    }
}

/// The shell's console: the PL011's register page, as a device frame it
/// maps itself, and its interrupt line.
pub fn console_caps() -> (Capability, Capability) {
    (
        Capability::new(
            Object::Frame {
                paddr: platform().uart.unwrap_or_default().0,
                size_bits: 12,
            },
            Rights::READ | Rights::WRITE | Rights::MAP,
        ),
        Capability::new(Object::Irq { line: uart_irq() }, Rights::READ | Rights::WRITE),
    )
}

/// No PS/2 controller on Arm machines.
pub fn ps2_caps() -> Option<[Capability; 2]> {
    None
}

/// No boot framebuffer is handed out on AArch64 (yet).
pub fn framebuffer_cap() -> Option<Capability> {
    None
}

pub fn framebuffer_geometry(_base: u64) -> Option<[u64; 2]> {
    None
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
/// No suspend to RAM on QEMU's `virt` (it has no sleep states): the
/// kernel suspends to idle instead.
pub fn ram_sleep_available() -> bool {
    false
}

pub fn ram_sleep(_seconds: u64) -> Result<&'static str, &'static str> {
    Err("no suspend to RAM on this machine")
}

pub fn ram_sleep_restart_cpus(_before: usize) -> usize {
    crate::smp::online()
}

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
    if !vm::map_device(base) {
        return None;
    }
    // SAFETY: the PL031's data register (offset 0), read-only, at the
    // address the device tree gives.
    Some(unsafe { core::ptr::read_volatile(base as *const u32) } as u64)
}

/// The TPM's TIS registers, if the device tree has one (QEMU's
/// `tpm-tis-device`, on its platform bus: the node's address is then an
/// offset into the bus's window).
pub fn tpm_base() -> Option<u64> {
    let dtb = DTB.load(core::sync::atomic::Ordering::Relaxed);
    let (mut base, _) = fdt::find_device(dtb, b"tcg,tpm-tis-mmio")?;
    // The bus's `ranges`: (its address, the parent's, size), one cell,
    // then the parent's address cells, then its own size cells.
    if let Some(r) = fdt::prop(dtb, b"qemu,platform", b"ranges") {
        let (child, size) = r.own_cells;
        let parent = r.parent_cells.0;
        let window = r.cells(child as u64 + parent as u64, size).unwrap_or(0);
        if let Some(bus) = r.cells(child as u64, parent).filter(|_| base < window) {
            base += bus;
        }
    }
    vm::map_device(base).then_some(base)
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

/// The console's interrupt line (its ID, below 256: checked at boot).
fn uart_irq() -> u8 {
    platform().uart.unwrap_or_default().1 as u8
}

pub fn irq_routable(line: u8) -> bool {
    line == uart_irq() || msi_lines().contains(&line) || intx_lines().contains(&line)
}

/// I/O ports for PCI BARs: the window of device memory that stands for
/// ports from 0, as the firmware says (QEMU `virt`'s is just below its
/// low ECAM window); none without one.
pub fn pci_io_cap() -> Option<Capability> {
    let (base, size_bits) = platform().pci_io?;
    Some(Capability::new(Object::DeviceUntyped { base, size_bits }, Rights::ALL))
}

/// The legacy PCI interrupt lines: the GIC's shared interrupts PCI's pins
/// reach, as the firmware says (none if it does not).
pub fn intx_lines() -> &'static [u8] {
    platform().intx.as_ref().map_or(&[], |x| &x.lines[..x.used])
}

/// Which of [`intx_lines`] pin `pin` (1 to 4) of root-bus device `device`
/// reaches, as the device tree's `interrupt-map` or ACPI's `_PRT` says.
pub fn intx_line(device: u8, pin: u8) -> Option<usize> {
    platform().intx.as_ref()?.line(device, pin)
}

/// One line on PCI's interrupt pins, as x86-64 reports them.
fn report_intx(p: &platform::Platform) {
    let Some(x) = &p.intx else {
        kprintln!("[ok] PCI interrupt pins: routing unknown (no interrupt-map or _PRT), only MSI");
        return;
    };
    kprint!(
        "[ok] PCI interrupt pins through the GIC, as {} says: {} pins on {} lines, at interrupts",
        x.from,
        x.pins,
        x.used
    );
    for (i, line) in x.lines[..x.used].iter().enumerate() {
        kprint!("{} {line}", if i == 0 { "" } else { "," });
    }
    if x.left > 0 {
        kprintln!(" (level, active high); {} pins left without (not level-high, or past {} lines)", x.left, platform::MAX_INTX);
    } else {
        kprintln!(" (level, active high)");
    }
}

/// The message a device writes to raise MSI line `line`, if it is one:
/// an event ID written to the ITS, which the ITS maps to the line for
/// device `source` alone (or for no device).
pub fn msi_message(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    gic::route(line, source)
}

/// For the root task's PCI bus server: the ECAM configuration window
/// (buses 0-15), a device-memory window to assign BARs from, and the MSI
/// lines, where the firmware says they are (checked at boot).
pub fn pci_caps() -> (Capability, Capability, core::ops::Range<u8>) {
    let p = platform();
    let (mem, mem_bits) = p.pci_mem.unwrap_or_default();
    (
        Capability::new(
            Object::DeviceUntyped {
                base: p.ecam.unwrap_or(0),
                size_bits: 24,
            },
            Rights::ALL,
        ),
        Capability::new(
            Object::DeviceUntyped {
                base: mem,
                size_bits: mem_bits,
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
