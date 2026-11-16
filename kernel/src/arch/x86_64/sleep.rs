//! Suspending to RAM: ACPI's S3.
//!
//! Memory keeps its contents while everything else loses power: every
//! CPU, the interrupt controllers, the IOMMU, every device (QEMU resets
//! the whole machine but its RAM). The firmware's tables say how
//! ([`acpi::sleep`]): `\_S3_`'s SLP_TYP, written with SLP_EN to the PM1
//! control registers, puts the machine to sleep; on a wake event the
//! firmware runs again, sees it is a resume, and jumps in real mode to
//! the address the OS left in the FACS.
//!
//! That address is the start-up page, holding the trampoline the other
//! CPUs start through ([`smp`]): it takes CPU 0 to long mode on the
//! kernel's tables and into `sup_s3_wake`, which picks up the stack and
//! registers `sup_s3_sleep` left, so the sleep returns as if from a call.
//! Then the kernel puts back what was lost: CPU 0's control registers,
//! GDT and TSS, IDT, `syscall` registers, its local APIC, the PIC's
//! masks, every I/O APIC entry, the IOMMU's units, COM1; and starts the
//! other CPUs again. Devices are their drivers' business: the Component
//! Manager quiesced them first and resumes them after.
//!
//! Wake events: the RTC's alarm, set for when the suspend should end
//! (enabled with PM1's RTC_EN), and whatever else the platform wakes on
//! unasked (the power button; on QEMU, a key pressed on the PS/2
//! keyboard), which PM1's status tells apart.

use super::{acpi, apic, gdt, interrupts, ioapic, iommu, serial, smp, syscall};
use crate::kprintln;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::port::Port;

/// PM1 status and enable bits: the RTC alarm, the power
/// button. Control: SLP_TYP (3 bits from bit 10) and SLP_EN.
const RTC: u16 = 1 << 10;
const PWRBTN: u16 = 1 << 8;
const SLP_TYP_SHIFT: u16 = 10;
const SLP_EN: u16 = 1 << 13;

/// How long `sup_s3_sleep` waits for the machine to go to sleep before
/// deciding it will not (spins of `pause`: a second or more).
const SLEEP_SPINS: u64 = 1 << 28;

/// The stack pointer `sup_s3_sleep` left, for `sup_s3_wake`.
static SAVED_RSP: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    ".global sup_s3_sleep",
    // rdi: PM1a control port; rsi: its value; rdx: PM1b control port (0
    // for none); rcx: its value; r8: spins to wait. Returns 0 if the
    // machine did not sleep; through `sup_s3_wake`, 1 once it woke.
    "sup_s3_sleep:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    pushfq",
    "    mov [rip + {saved}], rsp",
    "    mov r9, rdx",
    "    mov r10, rcx",
    "    wbinvd",
    "    mov edx, edi",
    "    mov eax, esi",
    "    out dx, ax",
    "    test r9, r9",
    "    jz 2f",
    "    mov edx, r9d",
    "    mov eax, r10d",
    "    out dx, ax",
    "2:  pause",
    "    dec r8",
    "    jnz 2b",
    "    popfq",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    xor eax, eax",
    "    ret",
    ".global sup_s3_wake",
    // From the trampoline, in long mode on the kernel's tables, interrupts
    // off: back onto the stack `sup_s3_sleep` left.
    "sup_s3_wake:",
    "    mov rsp, [rip + {saved}]",
    "    popfq",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    mov eax, 1",
    "    ret",
    saved = sym SAVED_RSP,
);

extern "C" {
    fn sup_s3_sleep(pm1a: u64, a: u64, pm1b: u64, b: u64, spins: u64) -> u64;
    fn sup_s3_wake();
}

/// What woke the machine.
#[derive(Clone, Copy, Debug)]
pub enum Wake {
    /// The RTC's alarm: the suspend's time was up.
    Alarm,
    /// The power button, or whatever else the platform reports as it (on
    /// QEMU, a key pressed).
    Button,
    /// Something PM1's status does not name.
    Other,
}

fn inw(port: u16) -> u16 {
    // SAFETY: a PM1 register the firmware's FADT names.
    unsafe { Port::<u16>::new(port).read() }
}

fn outw(port: u16, v: u16) {
    // SAFETY: as in `inw`.
    unsafe { Port::<u16>::new(port).write(v) }
}

fn cmos(reg: u8) -> u8 {
    // SAFETY: the CMOS index and data ports.
    unsafe {
        Port::<u8>::new(0x70).write(reg);
        Port::<u8>::new(0x71).read()
    }
}

fn set_cmos(reg: u8, v: u8) {
    // SAFETY: as in `cmos`; the alarm and register B are the kernel's.
    unsafe {
        Port::<u8>::new(0x70).write(reg);
        Port::<u8>::new(0x71).write(v);
    }
}

/// Sets the RTC's alarm `seconds` from now (under a day) and enables its
/// interrupt, which is what wakes the machine.
fn set_alarm(seconds: u64) -> Result<(), &'static str> {
    let (_, _, _, h, m, s) = super::rtc().ok_or("the RTC reads as nonsense")?;
    let at = (h * 3600 + m * 60 + s + seconds) % 86400;
    let (h, m, s) = (at / 3600, at / 60 % 60, at % 60);
    let b = cmos(0x0b);
    let enc = |v: u64| if b & 0x04 == 0 { ((v / 10) << 4 | v % 10) as u8 } else { v as u8 };
    let hour = if b & 0x02 == 0 {
        // 12-hour: 12 for midnight and noon, bit 7 for the afternoon.
        let twelve = if h % 12 == 0 { 12 } else { h % 12 };
        enc(twelve) | if h >= 12 { 0x80 } else { 0 }
    } else {
        enc(h)
    };
    set_cmos(0x01, enc(s));
    set_cmos(0x03, enc(m));
    set_cmos(0x05, hour);
    cmos(0x0c); // clears any flag already raised
    set_cmos(0x0b, b | 0x20);
    Ok(())
}

/// PCI configuration through mechanism #1 (ports 0xcf8/0xcfc), bus 0.
fn config(dev: u8, func: u8, off: u8) -> u32 {
    // SAFETY: the configuration ports; every driver is quiesced while the
    // machine suspends, so nothing else uses them.
    unsafe {
        Port::<u32>::new(0xcf8).write(1 << 31 | (dev as u32) << 11 | (func as u32) << 8 | off as u32);
        Port::<u32>::new(0xcfc).read()
    }
}

fn set_config(dev: u8, func: u8, off: u8, v: u32) {
    // SAFETY: as in `config`.
    unsafe {
        Port::<u32>::new(0xcf8).write(1 << 31 | (dev as u32) << 11 | (func as u32) << 8 | off as u32);
        Port::<u32>::new(0xcfc).write(v);
    }
}

/// The chipset registers that place the ACPI registers (PM1's among them)
/// in I/O space, by the function holding them: the device, function,
/// vendor and device ID, and the registers in the order to write them
/// back. Reset with everything else on a wake; firmware would normally
/// set them again before jumping to the OS, but SeaBIOS does not, so PM1
/// would read as all ones (and the next sleep command go nowhere).
const CHIPSET: [(u8, u8, u32, &[u8]); 2] = [
    // ICH9's LPC bridge (QEMU's q35): PMBASE, then ACPI_CNTL's decode
    // enable; the PIRQ routing; RCBA.
    (0x1f, 0, 0x2918_8086, &[0x40, 0x44, 0x60, 0x68, 0xf0]),
    // PIIX4's power management function (QEMU's pc): PMBA, then its
    // decode enable in PMREGMISC.
    (1, 3, 0x7113_8086, &[0x40, 0x80]),
];

/// The values of [`CHIPSET`]'s registers, taken before sleeping.
fn save_chipset() -> [[u32; 5]; 2] {
    let mut saved = [[0; 5]; 2];
    for (k, &(dev, func, id, regs)) in CHIPSET.iter().enumerate() {
        if config(dev, func, 0) == id {
            for (i, &r) in regs.iter().enumerate() {
                saved[k][i] = config(dev, func, r);
            }
        }
    }
    saved
}

fn restore_chipset(saved: &[[u32; 5]; 2]) {
    for (k, &(dev, func, id, regs)) in CHIPSET.iter().enumerate() {
        if config(dev, func, 0) == id {
            for (i, &r) in regs.iter().enumerate() {
                set_config(dev, func, r, saved[k][i]);
            }
        }
    }
}

/// Turns the alarm's interrupt off again.
fn clear_alarm() {
    let b = cmos(0x0b);
    set_cmos(0x0b, b & !0x20);
    cmos(0x0c);
}

/// Whether this machine can suspend to RAM: the firmware's tables say how,
/// and there is a start-up page below 4 GiB to resume through.
pub fn available() -> bool {
    acpi::sleep().is_some() && smp::STARTUP_PAGE.load(Ordering::Relaxed) != 0
}

/// Suspends the machine to RAM for `seconds` (at least 2), unless another
/// wake event comes first. Called on CPU 0 with interrupts off and every
/// other CPU parked (they are started again after). Returns what woke it,
/// or why it did not sleep.
pub fn suspend(seconds: u64) -> Result<Wake, &'static str> {
    let s = acpi::sleep().ok_or("no S3 in the firmware's tables")?;
    let stack = gdt::kernel_stack_top(0) - 4096;
    let page = smp::prepare_wake(sup_s3_wake as *const () as u64, stack).ok_or("no start-up page to resume through")?;
    // The alarm goes off as a second begins, and this one may be nearly
    // over: one second more, so the sleep is never short.
    if let Err(e) = set_alarm(seconds.clamp(2, 86398) + 1) {
        smp::wake_done(page);
        return Err(e);
    }
    let masks = interrupts::pic_masks();
    let chipset = save_chipset();
    ioapic::save();
    // Where the firmware resumes: the start-up page, as a real-mode
    // address (it jumps to page/16:0); the 64-bit vector unused.
    let facs = super::vm::phys_ptr(s.facs);
    // SAFETY: the FACS, in memory the firmware set aside for it (checked
    // in `acpi::fadt`: signature and at least 32 bytes long).
    unsafe {
        (facs.add(12) as *mut u32).write_volatile(page as u32);
        (facs.add(24) as *mut u64).write_volatile(0);
    }
    // Status cleared (each bit by writing it), the RTC enabled to wake.
    let half = s.pm1_event_len / 2;
    for evt in [s.pm1a_event, s.pm1b_event].into_iter().filter(|&p| p != 0) {
        outw(evt, 0xffff);
        outw(evt + half, inw(evt + half) | RTC);
    }
    let control = |port: u16, typ: u8| {
        let keep = inw(port) & !(7 << SLP_TYP_SHIFT | SLP_EN);
        (keep | (typ as u16 & 7) << SLP_TYP_SHIFT | SLP_EN) as u64
    };
    let a = control(s.pm1a_control, s.s3.0);
    let b = if s.pm1b_control != 0 { control(s.pm1b_control, s.s3.1) } else { 0 };
    // SAFETY: saves the callee-saved registers and stack, and writes the
    // sleep command; the machine wakes into `sup_s3_wake`, which returns
    // here with them.
    let woke = unsafe { sup_s3_sleep(s.pm1a_control as u64, a, s.pm1b_control as u64, b, SLEEP_SPINS) };
    if woke == 0 {
        smp::wake_done(page);
        clear_alarm();
        return Err("the machine did not go to sleep");
    }
    // Awake, on the trampoline's GDT, with interrupts off: put back what
    // the CPU and the chipset lost (the ACPI registers' place first: the
    // wake status is read from them).
    restore_chipset(&chipset);
    smp::restore_control_registers();
    gdt::init(0);
    interrupts::load();
    syscall::init(0);
    serial::reinit();
    apic::resume();
    interrupts::resume(masks);
    ioapic::restore();
    iommu::resume();
    smp::wake_done(page);
    let status = inw(s.pm1a_event) | if s.pm1b_event != 0 { inw(s.pm1b_event) } else { 0 };
    for evt in [s.pm1a_event, s.pm1b_event].into_iter().filter(|&p| p != 0) {
        outw(evt + half, inw(evt + half) & !RTC);
        outw(evt, 0xffff);
    }
    clear_alarm();
    Ok(if status & RTC != 0 {
        Wake::Alarm
    } else if status & PWRBTN != 0 {
        Wake::Button
    } else {
        Wake::Other
    })
}

/// Starts the CPUs that were online before the suspend (`before`) again.
pub fn restart_cpus(before: usize) -> usize {
    let n = smp::restart_secondaries(before);
    if n != before {
        kprintln!("[warn] after S3 only {n} of {before} CPUs came back");
    }
    n
}
