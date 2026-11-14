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
mod aml;
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
    acpi::init(boot_info.rsdp_addr.into_option());
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
pub fn pci_io_cap() -> Capability {
    Capability::new(
        Object::IoPort {
            base: 0xd000,
            count: 0x3000,
        },
        Rights::READ | Rights::WRITE,
    )
}

/// The legacy PCI interrupt lines, where their routing is known.
pub fn intx_lines() -> &'static [u8] {
    interrupts::intx_lines()
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
