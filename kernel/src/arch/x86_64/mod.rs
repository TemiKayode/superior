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
    interrupts::pic_unmask(line)
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
