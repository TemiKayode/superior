//! Linux's ES1370 sound driver, unmodified, as a component:
//! `sound/pci/ens1370.c` and the AK4531 codec it drives,
//! `sound/pci/ak4531_codec.c`, from Linux 6.6, for QEMU's ENSONIQ
//! AudioPCI, compiled against the Linux Driver Environment's headers, its
//! sound ones too, and linked here with its host (`superior_lde`), which
//! finds the card from the driver's own ID table and serves the `audio`
//! interface with it. The card's registers are I/O ports, which the PCI
//! bus server reads and writes for it.
//!
//! Slots, as the environment wants them (in a CSpace of 2^11): 0 the bus
//! server, 1 the `audio` endpoint (receive), 2 a notification, 3 untyped
//! memory (1 MiB).

#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    superior_lde::run_sound("es1370")
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    superior_sys::print_line(format_args!("lde es1370: panic: {info}"));
    superior_sys::park()
}
