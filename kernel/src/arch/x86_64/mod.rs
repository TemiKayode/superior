//! x86-64: boots through the `bootloader` crate (from a BIOS or UEFI), with
//! the serial console on COM1, the GDT/TSS, an IDT, `syscall`/`sysret`, the local APIC
//! timer, and the legacy PIC for COM1's interrupt.

pub mod apic;
mod boot_memory;
pub mod gdt;
pub mod interrupts;
pub mod iommu;
pub mod qemu;
pub mod serial;
mod smp;
mod sleep;
pub mod syscall;
pub mod vm;

#[cfg_attr(not(feature = "selftest"), allow(unused_imports))]
pub use apic::{alarm, alarm_fired, alarm_keep, tick_start, tick_stop, TICK_HZ};
pub use syscall::{enter_user, Args, Exit, UserFrame};

use crate::kprintln;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use superior_objects::cap::{Capability, Object, Rights};

pub const NAME: &str = "x86_64";

mod acpi;
use crate::aml;
mod ioapic;
mod fbcon;

/// Finds and turns on the IOMMU, if the machine has one.
pub fn iommu_init() -> Option<&'static str> {
    iommu::init()
}

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 128 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    fbcon::init(boot_info.framebuffer.as_mut());
    crate::banner();
    if let Some((w, h)) = fbcon::size() {
        kprintln!("[ok] this log on the boot framebuffer too, {w}x{h}, until user space starts");
    }

    gdt::init(0);
    kprintln!("[ok] gdt + tss loaded");
    interrupts::init();
    kprintln!("[ok] idt loaded");
    syscall::init(0);
    kprintln!("[ok] syscall/sysret enabled");
    smp::note_boot_cpu();

    if let Some(page) = boot_memory::startup_page(&boot_info.memory_regions) {
        smp::STARTUP_PAGE.store(page, core::sync::atomic::Ordering::Relaxed);
    }
    let mem = boot_memory::init(&boot_info.memory_regions);
    crate::report_memory(&mem);
    let offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("bootloader did not map physical memory");
    vm::init(offset);
    kprintln!("[ok] physical memory mapped at {offset:#x}");
    fbcon::locate();
    acpi::init(boot_info.rsdp_addr.into_option());
    dbc_init();
    interrupts::init_routing();
    let timer_hz = apic::init();
    smp::note_boot_apic();
    kprintln!(
        "[ok] local APIC timer: {} kHz input, {} Hz tick",
        timer_hz / 1000,
        apic::TICK_HZ
    );
    crate::kernel_start(mem.untyped_caps)
}

/// The log over USB, if an xHCI has a Debug Capability: found through
/// configuration ports 0xcf8 and 0xcfc (nothing else uses them yet), its
/// registers mapped as device memory, its rings in pages of RAM.
fn dbc_init() {
    use x86_64::instructions::port::Port;
    let address = |bus: u8, devfn: u8, off: u16| 1u32 << 31 | (bus as u32) << 16 | (devfn as u32) << 8 | (off as u32 & 0xfc);
    let read = |bus, devfn, off| {
        // SAFETY: the PCI configuration ports, the kernel's alone at boot.
        unsafe {
            Port::<u32>::new(0xcf8).write(address(bus, devfn, off));
            Port::<u32>::new(0xcfc).read()
        }
    };
    let write = |bus, devfn, off, v| {
        // SAFETY: as above.
        unsafe {
            Port::<u32>::new(0xcf8).write(address(bus, devfn, off));
            Port::<u32>::new(0xcfc).write(v);
        }
    };
    let map = |pa: u64| vm::map_mmio(x86_64::PhysAddr::new(pa & !0xfff)).ok().map(|va| va.as_u64() + (pa & 0xfff));
    let page = || crate::memory::user_page().map(|pa| (pa, vm::phys_ptr(pa)));
    crate::dbc::init(&crate::dbc::Pci { read: &read, write: &write, buses: 256, map: &map, page: &page }, "COM1");
}

/// User space is about to start: the kernel stops drawing on the boot
/// framebuffer, which the PCI bus server and a display driver may take.
pub fn console_hand_over() {
    if fbcon::size().is_some() {
        kprintln!("[ok] the screen is user space's from here; the log goes on on COM1");
        fbcon::hand_over();
    }
}

/// This CPU's number (0 the boot CPU), from its local APIC ID.
pub fn cpu_id() -> usize {
    smp::cpu_of(apic::id() as u32)
}

/// The boot CPU's local APIC ID, where device interrupts are sent.
pub fn boot_apic() -> u32 {
    smp::apic_of(0)
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
    apic::send_ipi(
        smp::apic_of(cpu) as usize,
        match ipi {
            Ipi::Kick => apic::KICK_VECTOR,
            Ipi::Shootdown => apic::SHOOTDOWN_VECTOR,
        },
    )
}

/// Starts the other CPUs; returns how many are online.
pub fn start_secondaries() -> usize {
    smp::start_secondaries()
}

/// The shell's console: COM1's eight I/O ports and its interrupt line.
pub fn console_caps() -> (Capability, Capability) {
    let rw = Rights::READ | Rights::WRITE;
    (
        Capability::new(
            Object::IoPort {
                base: 0x3f8,
                count: 8,
            },
            rw,
        ),
        Capability::new(
            Object::Irq {
                line: interrupts::COM1_IRQ,
            },
            rw,
        ),
    )
}

/// The PS/2 controller (i8042): its data port (0x60) and its status and
/// command port (0x64), one capability each, so a holder reaches neither
/// the ports between them (0x61 gates the PC speaker and the PIT's
/// channel 2) nor anything else. A driver reads the keyboard through them;
/// where there is no controller, the ports read as all ones.
pub fn ps2_caps() -> Option<[Capability; 2]> {
    let rw = Rights::READ | Rights::WRITE;
    let port = |base| Capability::new(Object::IoPort { base, count: 1 }, rw);
    Some([port(0x60), port(0x64)])
}

/// The boot framebuffer as device memory, from its first byte over the
/// power of two of bytes that covers its rows ([`fbcon::screen`]), if the
/// bootloader or firmware set one up.
pub fn framebuffer_cap() -> Option<Capability> {
    let (base, size_bits, _) = fbcon::screen()?;
    Some(Capability::new(Object::DeviceUntyped { base, size_bits }, Rights::ALL))
}

/// The framebuffer's geometry, packed for `UntypedInfo`, if `base` is the
/// framebuffer's device memory.
pub fn framebuffer_geometry(base: u64) -> Option<[u64; 2]> {
    let (pa, _, g) = fbcon::screen()?;
    (pa == base).then(|| g.pack())
}

#[cfg_attr(not(feature = "selftest"), allow(dead_code))]
/// `int3` must trap into the kernel's handler and return.
pub fn breakpoint_selftest() {
    x86_64::instructions::interrupts::int3();
}

/// Halts until an interrupt has been handled. `sti; hlt` is atomic, so an
/// interrupt cannot arrive between enabling and halting and be missed.
pub fn idle_wait() {
    x86_64::instructions::interrupts::enable_and_hlt();
    x86_64::instructions::interrupts::disable();
}

/// Whether the machine can suspend to RAM (ACPI S3).
pub fn ram_sleep_available() -> bool {
    sleep::available()
}

/// Suspends to RAM for `seconds` (CPU 0, interrupts off, the other CPUs
/// parked). Returns what woke it, or why it did not sleep.
pub fn ram_sleep(seconds: u64) -> Result<&'static str, &'static str> {
    sleep::suspend(seconds).map(|w| match w {
        sleep::Wake::Alarm => "the RTC alarm",
        sleep::Wake::Button => "the power button (or a key)",
        sleep::Wake::Other => "a wake event PM1 does not name",
    })
}

/// After [`ram_sleep`]: starts the `before` CPUs that were online again.
pub fn ram_sleep_restart_cpus(before: usize) -> usize {
    for f in &FS_LOADED {
        f.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    }
    sleep::restart_cpus(before)
}

/// The FS base each CPU last loaded; `u64::MAX` when unknown (at boot and
/// after sleep).
static FS_LOADED: [core::sync::atomic::AtomicU64; superior_objects::ipc::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; superior_objects::ipc::MAX_CPUS];

/// A thread's x87, MMX, SSE and AVX registers in `xsave` form (only
/// foreign threads have any: Superior's own code is built without them):
/// the `fxsave` area, the `xsave` header and the upper halves of
/// `ymm0`-`ymm15`. Without AVX (see [`fp_cpu_init`]) only the `fxsave`
/// area is used, and the rest stays 0.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FpState([u8; XSAVE_LEN]);

/// The `xsave` area's size with x87, SSE and AVX state (standard form).
const XSAVE_LEN: usize = 832;
/// XCR0, where Superior turns XSAVE on: x87, SSE and AVX state.
const XFEATURES: u64 = 0b111;
/// The header's first word, `XSTATE_BV`, and how many words the header
/// has (all but the first must be 0 for `xrstor`).
const XSTATE_BV: usize = 64;
const HEADER_WORDS: usize = 8;

/// Whether threads' state is saved with `xsave` (AVX on): the same on
/// every CPU.
static XSAVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

impl FpState {
    /// Linux's initial state: x87 control word 0x37f and MXCSR 0x1f80,
    /// every exception masked.
    pub const INITIAL: FpState = {
        let mut b = [0; XSAVE_LEN];
        b[0] = 0x7f;
        b[1] = 0x03;
        b[24] = 0x80;
        b[25] = 0x1f;
        FpState(b)
    };

    /// Word `i` of the `xsave` area.
    pub fn word(&self, i: u64) -> Option<u64> {
        let at = usize::try_from(i).ok().filter(|&i| i < XSAVE_LEN / 8)? * 8;
        Some(u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap()))
    }

    /// Sets word `i`, keeping what `xrstor` (or `fxrstor`) would fault on
    /// out: MXCSR (word 3's low half) keeps only the bits the CPU has (its
    /// mask, the high half, which stays); `XSTATE_BV` only the state turned
    /// on, and the rest of the header stays 0. An index past the last is
    /// ignored.
    pub fn set_word(&mut self, i: u64, v: u64) {
        let Some(i) = usize::try_from(i).ok().filter(|&i| i < XSAVE_LEN / 8) else { return };
        let v = match i {
            3 => {
                let mask = match u32::from_le_bytes(self.0[28..32].try_into().unwrap()) {
                    0 => 0xffbf,
                    m => m,
                };
                (v as u32 & mask) as u64 | (mask as u64) << 32
            }
            XSTATE_BV if XSAVE.load(core::sync::atomic::Ordering::Relaxed) => v & XFEATURES,
            _ if (XSTATE_BV..XSTATE_BV + HEADER_WORDS).contains(&i) => 0,
            _ => v,
        };
        self.0[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
}

/// Whether the CPU has AVX, saved by `xsave` where Linux puts it (the
/// upper halves at 576, 256 bytes).
fn has_avx() -> bool {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    #[allow(unused_unsafe)]
    // SAFETY: CPUID is always there on x86-64; leaf 0xd is there with
    // XSAVE.
    unsafe {
        let leaf1 = __cpuid(1);
        if leaf1.ecx & 1 << 26 == 0 || leaf1.ecx & 1 << 28 == 0 {
            return false;
        }
        let avx = __cpuid_count(0xd, 2);
        avx.eax == 256 && avx.ebx == 576
    }
}

/// Whether each CPU lets user code use the FPU (CR0.TS clear).
static FP_ON: [core::sync::atomic::AtomicBool; superior_objects::ipc::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; superior_objects::ipc::MAX_CPUS];

/// SSE on (CR4.OSFXSR, unmasked SIMD exceptions as #XM), and AVX where
/// the CPU has it (CR4.OSXSAVE, XCR0 [`XFEATURES`]: threads' state is then
/// saved with `xsave`), but CR0.TS set: any FPU instruction traps (#NM)
/// until a foreign thread runs.
pub fn fp_cpu_init(cpu: usize) {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    let avx = has_avx();
    // SAFETY: these bits only decide whether FPU, SSE and AVX instructions
    // work or trap, and which state `xsave` saves; the kernel uses none.
    unsafe {
        Cr4::update(|f| f.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE));
        if avx {
            Cr4::update(|f| f.insert(Cr4Flags::OSXSAVE));
            core::arch::asm!("xsetbv", in("ecx") 0, in("eax") XFEATURES as u32, in("edx") 0, options(nostack));
        }
        Cr0::update(|f| {
            f.remove(Cr0Flags::EMULATE_COPROCESSOR);
            f.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR | Cr0Flags::TASK_SWITCHED);
        });
    }
    FP_ON[cpu].store(false, core::sync::atomic::Ordering::Relaxed);
    XSAVE.store(avx, core::sync::atomic::Ordering::Relaxed);
}

/// Lets user code use the FPU (`on`, for a foreign thread), or makes it
/// trap.
pub fn fp_enable(on: bool) {
    use core::sync::atomic::Ordering::Relaxed;
    if FP_ON[cpu_id()].swap(on, Relaxed) != on {
        // SAFETY: as in `fp_cpu_init`.
        unsafe {
            if on {
                core::arch::asm!("clts", options(nostack, nomem));
            } else {
                x86_64::registers::control::Cr0::update(|f| {
                    f.insert(x86_64::registers::control::Cr0Flags::TASK_SWITCHED)
                });
            }
        }
    }
}

/// Saves the FPU, SSE and AVX registers into `s` (the FPU on:
/// `fp_enable`).
pub fn fp_save(s: &mut FpState) {
    let p = s as *mut FpState;
    // SAFETY: `s` is `XSAVE_LEN` writable bytes, 64-byte aligned; `xsave`
    // only with XSAVE on.
    unsafe {
        if XSAVE.load(core::sync::atomic::Ordering::Relaxed) {
            core::arch::asm!("xsave64 [{}]", in(reg) p, in("eax") XFEATURES as u32, in("edx") 0, options(nostack));
        } else {
            core::arch::asm!("fxsave64 [{}]", in(reg) p, options(nostack));
        }
    }
}

/// Loads the FPU, SSE and AVX registers from `s` (the FPU on).
pub fn fp_restore(s: &FpState) {
    let p = s as *const FpState;
    // SAFETY: as in `fp_save`, reading; a state from `fp_save`, `INITIAL`
    // or `set_word` has no reserved MXCSR bit set and a header `xrstor`
    // takes.
    unsafe {
        if XSAVE.load(core::sync::atomic::Ordering::Relaxed) {
            core::arch::asm!("xrstor64 [{}]", in(reg) p, in("eax") XFEATURES as u32, in("edx") 0, options(nostack));
        } else {
            core::arch::asm!("fxrstor64 [{}]", in(reg) p, options(nostack));
        }
    }
}

/// The user thread pointer as the thread left it, if user code can change
/// it: on x86-64 it cannot (`wrfsbase` is off), so only the kernel sets it.
pub fn user_tls() -> Option<u64> {
    None
}

/// Loads a user thread pointer (a canonical address, checked by the
/// caller) as the FS base, unless this CPU has it already.
pub fn set_user_tls(v: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let loaded = &FS_LOADED[cpu_id()];
    if loaded.load(Relaxed) != v {
        x86_64::registers::model_specific::FsBase::write(x86_64::VirtAddr::new_truncate(v));
        loaded.store(v, Relaxed);
    }
}

/// The CMOS real-time clock's date and time: (year, month, day, hour,
/// minute, second), read between updates; `None` if it reads as nonsense.
pub fn rtc() -> Option<(u64, u64, u64, u64, u64, u64)> {
    use x86_64::instructions::port::Port;
    let read = |reg: u8| -> u8 {
        let (mut index, mut data) = (Port::<u8>::new(0x70), Port::<u8>::new(0x71));
        // SAFETY: the CMOS index and data ports; reading a clock register
        // changes nothing.
        unsafe {
            index.write(reg);
            data.read()
        }
    };
    let regs = || {
        // Not while it updates (register A, bit 7).
        let mut spins = 0;
        while read(0x0a) & 0x80 != 0 && spins < 1_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        [read(0x00), read(0x02), read(0x04), read(0x07), read(0x08), read(0x09)]
    };
    // Read until two reads agree (an update may fall between registers).
    let mut r = regs();
    for _ in 0..8 {
        let again = regs();
        if again == r {
            break;
        }
        r = again;
    }
    let b = read(0x0b);
    let bcd = |v: u8| if b & 0x04 == 0 { (v & 0x0f) + (v >> 4) * 10 } else { v };
    let pm = r[2] & 0x80 != 0;
    let mut hour = bcd(r[2] & 0x7f);
    if b & 0x02 == 0 {
        // 12-hour: 12 is midnight or noon.
        hour = hour % 12 + if pm { 12 } else { 0 };
    }
    let (s, m, d, mo, y) = (bcd(r[0]), bcd(r[1]), bcd(r[3]), bcd(r[4]), bcd(r[5]));
    let ok = s < 60 && m < 60 && hour < 24 && (1..=31).contains(&d) && (1..=12).contains(&mo) && y < 100;
    ok.then_some((2000 + y as u64, mo as u64, d as u64, hour as u64, m as u64, s as u64))
}

/// The time-stamp counter, for the entropy pool's timings.
pub fn cycles() -> u64 {
    // SAFETY: rdtsc reads the counter, nothing else.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Which random instruction the CPU has: RDSEED (straight from its noise
/// source) is preferred to RDRAND (a generator it reseeds).
pub fn random_source() -> Option<&'static str> {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    #[allow(unused_unsafe)]
    // SAFETY: CPUID is always there on x86-64.
    let (leaf1, leaf7) = unsafe { (__cpuid(1), __cpuid_count(7, 0)) };
    if leaf7.ebx & 1 << 18 != 0 {
        Some("RDSEED")
    } else if leaf1.ecx & 1 << 30 != 0 {
        Some("RDRAND")
    } else {
        None
    }
}

/// A word from the CPU's random instruction, retried a few times (it can
/// run dry for a moment); `None` without one.
pub fn random_word() -> Option<u64> {
    let seed = match random_source()? {
        "RDSEED" => true,
        _ => false,
    };
    for _ in 0..32 {
        let (v, ok): (u64, u8);
        // SAFETY: the instruction is there (CPUID said so); it only sets
        // the register and the carry flag.
        unsafe {
            if seed {
                core::arch::asm!("rdseed {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack));
            } else {
                core::arch::asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack));
            }
        }
        if ok == 1 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

pub fn irq_routable(line: u8) -> bool {
    interrupts::irq_routable(line)
}

/// The message a device writes to raise MSI line `line`, if it is one,
/// with the line raisable by requester `source` alone (or by no device)
/// where interrupts are remapped.
pub fn msi_message(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    interrupts::msi_message(line, source)
}

/// The device-memory window the PCI bus server assigns BARs from: 128 MiB
/// in QEMU's PCI hole, clear of RAM (below 0xe000_0000 with up to 3.5 GiB)
/// and of the firmware's own BARs (SeaBIOS assigns from the top of the
/// hole down, OVMF from 0x8000_0000 up), and of PCI Express configuration
/// space where ACPI's MCFG puts it (OVMF: at 0xe000_0000, so the window
/// moves to 0xf000_0000).
fn bar_window() -> u64 {
    const SIZE: u64 = 1 << 27;
    let clear = |base: u64| acpi::ecam().is_none_or(|e| base + SIZE <= e.start || base >= e.end);
    [0xe000_0000, 0xf000_0000].into_iter().find(|&b| clear(b)).unwrap_or(0xe000_0000)
}

/// For the root task's PCI bus server: configuration space (the legacy
/// 0xcf8/0xcfc address and data ports), a device-memory window to assign
/// BARs from ([`bar_window`]), and the MSI lines.
pub fn pci_caps() -> (Capability, Capability, core::ops::Range<u8>) {
    let rw = Rights::READ | Rights::WRITE;
    (
        Capability::new(
            Object::IoPort {
                base: 0xcf8,
                count: 8,
            },
            rw,
        ),
        Capability::new(
            Object::DeviceUntyped {
                base: bar_window(),
                size_bits: 27,
            },
            Rights::ALL,
        ),
        interrupts::MSI_LINE_BASE..interrupts::MSI_LINE_BASE + interrupts::MSI_COUNT,
    )
}

pub fn irq_unmask(line: u8) {
    interrupts::unmask(line)
}

/// I/O ports for PCI BARs: on QEMU's q35 nothing else is at 0xd000 and
/// up (configuration space's own ports, 0xcf8 to 0xcff, are below).
pub fn pci_io_cap() -> Option<Capability> {
    Some(Capability::new(
        Object::IoPort {
            base: 0xd000,
            count: 0x3000,
        },
        Rights::READ | Rights::WRITE,
    ))
}

/// The legacy PCI interrupt lines, where their routing is known.
pub fn intx_lines() -> &'static [u8] {
    interrupts::intx_lines()
}

/// Which of [`intx_lines`] pin `pin` (1 to 4) of root-bus device `device`
/// reaches, as ACPI's `_PRT` says.
pub fn intx_line(device: u8, pin: u8) -> Option<usize> {
    interrupts::intx_line(device, pin)
}

/// Reads an I/O port the caller's capability grants.
pub fn io_in(port: u16, width: u64) -> u64 {
    use x86_64::instructions::port::Port;
    // SAFETY: the capability grants this port range; port reads have no
    // memory-safety effect on the kernel.
    unsafe {
        match width {
            1 => Port::<u8>::new(port).read() as u64,
            2 => Port::<u16>::new(port).read() as u64,
            _ => Port::<u32>::new(port).read() as u64,
        }
    }
}

/// Writes an I/O port the caller's capability grants.
pub fn io_out(port: u16, width: u64, value: u64) {
    use x86_64::instructions::port::Port;
    // SAFETY: as in `io_in`; the ports a capability can name are chosen at
    // boot to be device ports, never ones the kernel relies on.
    unsafe {
        match width {
            1 => Port::<u8>::new(port).write(value as u8),
            2 => Port::<u16>::new(port).write(value as u16),
            _ => Port::<u32>::new(port).write(value as u32),
        }
    }
}

#[cfg_attr(not(feature = "selftest"), allow(dead_code))]
/// Ends a self-test run with QEMU's exit status.
/// The TPM's TIS registers (the PC Client profile puts them at
/// 0xFED40000, locality 0), mapped: whether a TPM answers there is for
/// `tpm` to find out.
pub fn tpm_base() -> Option<u64> {
    vm::map_mmio(x86_64::PhysAddr::new(0xfed4_0000)).ok().map(|va| va.as_u64())
}

pub fn qemu_exit(pass: bool) -> ! {
    qemu::exit(if pass {
        qemu::ExitCode::Success
    } else {
        qemu::ExitCode::Failure
    })
}

pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

pub fn halt_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
