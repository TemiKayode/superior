//! Interrupt descriptor table: CPU exception handlers.
//!
//! A fault taken in user mode becomes a fault message to the faulting
//! thread's handler (see `task::handle_fault`). A fault in kernel mode is
//! always a kernel bug and panics.

use super::aml::Route;
use super::{acpi, apic, gdt, ioapic, syscall};
use crate::{kprint, kprintln};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint);
    // SAFETY: each entry is a naked stub that saves a full UserFrame and
    // leaves through return_to_user.
    unsafe {
        let addr = |f: unsafe extern "C" fn()| VirtAddr::new(f as *const () as u64);
        idt.page_fault
            .set_handler_addr(addr(syscall::page_fault_entry));
        idt.general_protection_fault
            .set_handler_addr(addr(syscall::general_protection_entry));
        idt.invalid_opcode
            .set_handler_addr(addr(syscall::invalid_opcode_entry));
        idt.divide_error
            .set_handler_addr(addr(syscall::divide_error_entry));
        // FPU use while it is off (CR0.TS: a thread that is not foreign)
        // is an invalid instruction; a floating-point exception user code
        // unmasked is an arithmetic one, like dividing by zero.
        idt.device_not_available
            .set_handler_addr(addr(syscall::invalid_opcode_entry));
        idt.x87_floating_point
            .set_handler_addr(addr(syscall::divide_error_entry));
        idt.simd_floating_point
            .set_handler_addr(addr(syscall::divide_error_entry));
    }
    // SAFETY: the IST index refers to a stack set up in gdt::TSS and used
    // by no other handler.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    // SAFETY: timer_entry is a naked interrupt entry that saves a full
    // UserFrame and leaves through return_to_user (iretq or sysret).
    unsafe {
        idt[apic::TIMER_VECTOR]
            .set_handler_addr(VirtAddr::new(syscall::timer_entry as *const () as u64));
    }
    // SAFETY: kick_entry is a naked interrupt entry like timer_entry.
    unsafe {
        idt[apic::KICK_VECTOR]
            .set_handler_addr(VirtAddr::new(syscall::kick_entry as *const () as u64));
    }
    idt[apic::SHOOTDOWN_VECTOR].set_handler_fn(shootdown);
    // SAFETY: iommu_entry is a naked interrupt entry like timer_entry.
    unsafe {
        idt[apic::IOMMU_VECTOR]
            .set_handler_addr(VirtAddr::new(syscall::iommu_entry as *const () as u64));
    }
    // SAFETY: com1_entry is a naked interrupt entry like timer_entry.
    unsafe {
        idt[PIC_BASE + COM1_IRQ]
            .set_handler_addr(VirtAddr::new(syscall::com1_entry as *const () as u64));
    }
    for (&line, entry) in INTX_LINES.iter().zip(syscall::INTX_ENTRIES) {
        // SAFETY: each entry saves the user frame like the timer's.
        unsafe {
            idt[vector(line)].set_handler_addr(VirtAddr::new(entry as *const () as u64));
        }
    }
    for (n, entry) in syscall::MSI_ENTRIES.iter().enumerate() {
        // SAFETY: each entry saves the user frame like the timer's.
        unsafe {
            idt[MSI_VECTOR_BASE + n as u8]
                .set_handler_addr(VirtAddr::new(*entry as *const () as u64));
        }
    }
    idt[apic::SPURIOUS_VECTOR].set_handler_fn(spurious);
    // The PIC's spurious IRQ 7 and 15.
    idt[PIC_BASE + 7].set_handler_fn(spurious);
    idt[PIC_BASE + 15].set_handler_fn(spurious);
    idt
});

/// COM1's line arrives on vector `PIC_BASE + COM1_IRQ`, whichever chip
/// carries it.
pub const PIC_BASE: u8 = 0x20;
/// COM1's interrupt line (its ISA IRQ), handed to the serial driver.
pub const COM1_IRQ: u8 = 4;
/// The lines PCI's interrupt pins can reach, one for each GSI the root
/// bridge's `_PRT` routes pins to (up to 8), on vectors
/// `INTX_VECTOR_BASE ..` (up to MSI's).
pub const INTX_LINES: [u8; 8] = [16, 17, 18, 19, 20, 21, 22, 23];
const INTX_VECTOR_BASE: u8 = 0x38;
/// How many of `INTX_LINES` are routed (0 where the routing is unknown).
static INTX_USED: AtomicUsize = AtomicUsize::new(0);
/// For each root-bus device's four pins, the line it reaches: its index
/// in `INTX_LINES`, plus 1 (0: none).
static PIN_LINE: [[AtomicU8; 4]; 32] = [const { [const { AtomicU8::new(0) }; 4] }; 32];
/// Whether the I/O APIC carries the legacy lines (else the 8259 PIC
/// carries COM1, and PCI's pins have none).
static IOAPIC_ON: AtomicBool = AtomicBool::new(false);
/// Where COM1 and the PCI lines arrive at the I/O APIC: bit 31 set, bit
/// 30 level-triggered, bit 29 active low, the GSI.
static ROUTE: [AtomicU32; 1 + INTX_LINES.len()] = [const { AtomicU32::new(0) }; 1 + INTX_LINES.len()];

/// A legacy line's place in `ROUTE`.
fn slot(line: u8) -> Option<usize> {
    if line == COM1_IRQ {
        Some(0)
    } else {
        INTX_LINES.iter().position(|&l| l == line).map(|w| w + 1)
    }
}

/// The vector a legacy line arrives on.
fn vector(line: u8) -> u8 {
    match slot(line) {
        Some(w @ 1..) => INTX_VECTOR_BASE + w as u8 - 1,
        _ => PIC_BASE + line,
    }
}

fn route_of(line: u8) -> Option<Route> {
    let v = ROUTE[slot(line)?].load(Ordering::Relaxed);
    (v >> 31 == 1).then(|| Route { gsi: v & 0xff_ffff, level: v >> 30 & 1 == 1, active_low: v >> 29 & 1 == 1 })
}

fn set_route(line: u8, r: Route) {
    if let Some(s) = slot(line) {
        ROUTE[s].store(1 << 31 | (r.level as u32) << 30 | (r.active_low as u32) << 29 | r.gsi, Ordering::Relaxed);
    }
}

/// The legacy PCI interrupt lines this machine's routing reaches (none
/// where it is unknown).
pub fn intx_lines() -> &'static [u8] {
    &INTX_LINES[..INTX_USED.load(Ordering::Relaxed)]
}

/// The line pin `pin` (1 to 4, INTA# to INTD#) of root-bus device
/// `device` reaches, as `_PRT` says: its index among [`intx_lines`].
pub fn intx_line(device: u8, pin: u8) -> Option<usize> {
    let p = PIN_LINE.get(device as usize)?.get((pin as usize).checked_sub(1)?)?;
    (p.load(Ordering::Relaxed) as usize).checked_sub(1)
}

/// Routes the legacy lines through the I/O APIC, once ACPI's tables are
/// read: COM1 to the GSI the MADT says ISA IRQ 4 arrives on, and PCI's
/// pins as the root bridge's `_PRT` routes each device's: a line for each
/// GSI it names (in the order first named, up to 8), which every pin
/// routed there reaches. The PCI bus server asks which line a function's
/// pin reaches (`IntxLine`), so any wiring works: QEMU's q35 rotates four
/// wires and gives the chipset's slots four more, laptops route each
/// integrated device its own way. Without an I/O APIC, the PIC carries
/// COM1 alone.
pub fn init_routing() {
    if !ioapic::init() {
        kprintln!("[ok] legacy interrupts: no I/O APIC, the 8259 PIC carries COM1; PCI's pins unrouted");
        return;
    }
    let com1 = acpi::isa_irq(COM1_IRQ);
    if !ioapic::has(com1.gsi) {
        kprintln!("[ok] legacy interrupts: COM1's GSI {} is on no I/O APIC; the 8259 PIC carries it", com1.gsi);
        return;
    }
    set_route(COM1_IRQ, com1);
    // Every line of the PIC masked from here on: the I/O APIC has them.
    use x86_64::instructions::port::Port;
    // SAFETY: the PICs' mask registers.
    unsafe {
        Port::<u8>::new(0x21).write(0xff);
        Port::<u8>::new(0xa1).write(0xff);
    }
    IOAPIC_ON.store(true, Ordering::Relaxed);
    let edge = |r: Route| match (r.level, r.active_low) {
        (true, true) => "level, active low",
        (true, false) => "level, active high",
        (false, true) => "edge, active low",
        (false, false) => "edge, active high",
    };
    kprintln!("[ok] legacy interrupts through the I/O APIC: COM1 at GSI {} ({})", com1.gsi, edge(com1));
    let Some(routes) = acpi::pci_routes() else {
        kprintln!("[ok] PCI interrupt pins: routing unknown (no _PRT), only MSI");
        return;
    };
    let (mut used, mut pins, mut left) = (0, 0, 0);
    for (dev, slot) in routes.iter().enumerate() {
        for (pin, r) in slot.iter().enumerate() {
            let Some(r) = *r else { continue };
            // The line for its GSI, or a new one; none if the GSI is on no
            // I/O APIC, or every line is taken.
            let w = (0..used).find(|&w| route_of(INTX_LINES[w]).is_some_and(|l| l.gsi == r.gsi));
            let w = match w {
                Some(w) => w,
                None if used < INTX_LINES.len() && ioapic::has(r.gsi) => {
                    set_route(INTX_LINES[used], r);
                    used += 1;
                    used - 1
                }
                None => {
                    left += 1;
                    continue;
                }
            };
            PIN_LINE[dev][pin].store(w as u8 + 1, Ordering::Relaxed);
            pins += 1;
        }
    }
    INTX_USED.store(used, Ordering::Relaxed);
    if used == 0 {
        kprintln!("[ok] PCI interrupt pins: _PRT routes none to this I/O APIC; only MSI");
        return;
    }
    kprint!("[ok] PCI interrupt pins through the I/O APIC, as _PRT says: {pins} pins on {used} lines, at GSIs");
    for (i, &line) in INTX_LINES[..used].iter().enumerate() {
        if let Some(r) = route_of(line) {
            kprint!("{} {}", if i == 0 { "" } else { "," }, r.gsi);
        }
    }
    let first = route_of(INTX_LINES[0]).map_or("", edge);
    if left > 0 {
        kprintln!(" ({first}); {left} pins left without (past 8 GSIs, or on no I/O APIC)");
    } else {
        kprintln!(" ({first})");
    }
}

/// MSI vectors: interrupt lines `MSI_LINE_BASE ..` arrive on vectors
/// `MSI_VECTOR_BASE ..` at the local APIC.
pub const MSI_VECTOR_BASE: u8 = 0x40;
pub const MSI_LINE_BASE: u8 = 32;
pub const MSI_COUNT: u8 = 8;

/// Whether `line` is an MSI vector's.
pub fn is_msi(line: u8) -> bool {
    (MSI_LINE_BASE..MSI_LINE_BASE + MSI_COUNT).contains(&line)
}

/// The message that raises MSI line `line` on this CPU. With interrupt
/// remapping, the line's remapping entry is pointed at its vector for
/// requester `source` alone (or for nobody) and the message names that
/// entry. Without, it is the vector itself: address 0xfee0_0000 with the
/// boot CPU's APIC ID as destination (physical mode), data = the vector
/// (fixed delivery, edge).
pub fn msi_message(line: u8, source: Option<u16>) -> Option<(u64, u64)> {
    if !is_msi(line) {
        return None;
    }
    let vector = MSI_VECTOR_BASE + line - MSI_LINE_BASE;
    Some(if super::iommu::remapping() {
        super::iommu::route((line - MSI_LINE_BASE) as u16, vector, source)
    } else {
        (0xfee0_0000 | (super::boot_apic() as u64 & 0xff) << 12, vector as u64)
    })
}

pub fn irq_routable(line: u8) -> bool {
    line == COM1_IRQ || is_msi(line) || intx_lines().contains(&line)
}

/// The mask register of the PIC that has `line` (the master: lines 0-7,
/// the slave: 8-15), and the line's bit in it.
fn pic_of(line: u8) -> (x86_64::instructions::port::Port<u8>, u8) {
    use x86_64::instructions::port::Port;
    if line < 8 {
        (Port::new(0x21), 1 << line)
    } else {
        (Port::new(0xa1), 1 << (line - 8))
    }
}

/// Masks a legacy line.
pub fn mask(line: u8) {
    if IOAPIC_ON.load(Ordering::Relaxed) {
        if let Some(r) = route_of(line) {
            ioapic::mask(r.gsi);
        }
        return;
    }
    if line >= 16 {
        return;
    }
    let (mut data, bit) = pic_of(line);
    // SAFETY: read-modify-write of a PIC's mask register.
    unsafe {
        let m = data.read();
        data.write(m | bit);
    }
}

/// Unmasks a legacy line (an MSI line is never masked).
pub fn unmask(line: u8) {
    if IOAPIC_ON.load(Ordering::Relaxed) {
        if let (Some(r), Some(s)) = (route_of(line), slot(line)) {
            // Remapping table entries 64 and up: past the MSI lines'.
            ioapic::unmask(r.gsi, vector(line), r.level, r.active_low, 64 + s as u16);
        }
        return;
    }
    if line >= 16 {
        return;
    }
    let (mut data, bit) = pic_of(line);
    // SAFETY: as in `mask`.
    unsafe {
        let m = data.read();
        data.write(m & !bit);
    }
}

/// A legacy line's interrupt has arrived. A level-triggered line (and any
/// line on the PIC) stays masked until the driver acknowledges, since the
/// device holds it raised until the driver has dealt with it; an edge on
/// the I/O APIC leaves nothing raised, and is left unmasked so that the
/// next edge is not lost. Then the end of interrupt.
pub fn taken(line: u8) {
    if !IOAPIC_ON.load(Ordering::Relaxed) {
        mask(line);
        use x86_64::instructions::port::Port;
        // SAFETY: non-specific EOI to the PICs' command ports.
        unsafe {
            if line >= 8 {
                Port::<u8>::new(0xa0).write(0x20);
            }
            Port::<u8>::new(0x20).write(0x20);
        }
        return;
    }
    if route_of(line).is_some_and(|r| r.level) {
        mask(line);
    }
    apic::end_of_interrupt();
}

pub fn init() {
    disable_legacy_pic();
    IDT.load();
}

/// The PICs' masks, for [`resume`] to put back after S3.
pub fn pic_masks() -> (u8, u8) {
    use x86_64::instructions::port::Port;
    // SAFETY: reading the PICs' mask registers.
    unsafe { (Port::<u8>::new(0x21).read(), Port::<u8>::new(0xa1).read()) }
}

/// After S3, where the firmware set the PIC up its own way: remapped as
/// [`init`] has it, with the masks it had (all of them where the I/O APIC
/// carries the lines).
pub fn resume(masks: (u8, u8)) {
    use x86_64::instructions::port::Port;
    disable_legacy_pic();
    // SAFETY: the PICs' mask registers.
    unsafe {
        Port::<u8>::new(0x21).write(masks.0);
        Port::<u8>::new(0xa1).write(masks.1);
    }
}

/// Loads the IDT on another CPU.
pub fn load() {
    IDT.load();
}

/// The 8259 PIC powers up delivering IRQ 0-7 on vectors 8-15, which
/// collide with CPU exceptions (IRQ 0, the timer, would arrive as a
/// "double fault"). Remap it to vectors 0x20-0x2f and mask every line; a
/// line is unmasked only when a user-space driver binds it to a
/// notification (`IrqSetNotification`), and none at all once the I/O APIC
/// carries them ([`init_routing`]).
fn disable_legacy_pic() {
    use x86_64::instructions::port::Port;
    let mut cmd1 = Port::<u8>::new(0x20);
    let mut data1 = Port::<u8>::new(0x21);
    let mut cmd2 = Port::<u8>::new(0xa0);
    let mut data2 = Port::<u8>::new(0xa1);
    // SAFETY: standard 8259 initialisation sequence on the PIC's fixed ports.
    unsafe {
        cmd1.write(0x11); // ICW1: init, expect ICW4
        cmd2.write(0x11);
        data1.write(0x20); // ICW2: vector base
        data2.write(0x28);
        data1.write(4); // ICW3: slave on IRQ 2
        data2.write(2);
        data1.write(1); // ICW4: 8086 mode
        data2.write(1);
        data1.write(!(1u8 << 2)); // mask all lines but the cascade
        data2.write(0xff);
    }
}

extern "x86-interrupt" fn breakpoint(frame: InterruptStackFrame) {
    kprintln!(
        "[trap] breakpoint at {:#x}",
        frame.instruction_pointer.as_u64()
    );
}

/// Another CPU asks this one to flush or unload an address space; it
/// takes no lock, so it can arrive in user mode or while idle.
extern "x86-interrupt" fn shootdown(_frame: InterruptStackFrame) {
    crate::smp::service();
    apic::end_of_interrupt();
}

/// A spurious APIC interrupt needs no EOI and no action.
extern "x86-interrupt" fn spurious(_frame: InterruptStackFrame) {}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    panic!("double fault\n{frame:#?}");
}
