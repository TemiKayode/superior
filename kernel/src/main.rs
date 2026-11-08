//! The Superior microkernel.
//!
//! Phase 0 scope: boot on x86-64 through the `bootloader` crate, bring up
//! the serial console, GDT/TSS and exception handlers, and hand all usable
//! physical memory to the root task as untyped capabilities. No heap, ever.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod gdt;
mod interrupts;
mod memory;
mod qemu;
mod serial;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 128 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial::init();
    kprintln!();
    kprintln!(
        "Superior microkernel {} (x86_64)",
        env!("CARGO_PKG_VERSION")
    );

    gdt::init();
    kprintln!("[ok] gdt + tss loaded");
    interrupts::init();
    kprintln!("[ok] idt loaded");

    let mem = memory::init(&boot_info.memory_regions);
    kprintln!(
        "[ok] {} MiB usable in {} regions -> {} untyped caps (largest 2^{} bytes)",
        mem.usable_bytes >> 20,
        mem.regions,
        mem.untyped_caps,
        mem.largest_block_bits
    );
    if mem.dropped_bytes > 0 {
        kprintln!(
            "[warn] {} KiB not placed: root CNode full",
            mem.dropped_bytes >> 10
        );
    }
    if let Some(offset) = boot_info.physical_memory_offset.into_option() {
        kprintln!("[ok] physical memory mapped at {offset:#x}");
    }

    #[cfg(feature = "selftest")]
    {
        selftest(mem.untyped_caps);
        kprintln!("[pass] all self-tests passed");
        qemu::exit(qemu::ExitCode::Success);
    }

    #[allow(unreachable_code)]
    {
        kprintln!("boot complete; idle");
        halt_forever()
    }
}

#[cfg(feature = "selftest")]
fn selftest(untyped_caps: usize) {
    use superior_objects::cap::Rights;

    // Exceptions: int3 must trap into our handler and return.
    x86_64::instructions::interrupts::int3();
    kprintln!("[pass] breakpoint trap returns");

    // Capabilities on the live root CNode: derive a read-only child of the
    // first untyped cap, then revoke it.
    assert!(
        untyped_caps > 0,
        "no untyped memory handed to the root task"
    );
    let mut cnode = memory::ROOT_CNODE.lock();
    let spare = cnode.capacity() - 1;
    cnode.derive(0, spare, Rights::READ, None).expect("derive");
    assert_eq!(cnode.get(spare).unwrap().rights, Rights::READ);
    assert_eq!(cnode.revoke(0), Ok(1));
    assert!(cnode.get(spare).is_none());
    kprintln!("[pass] capability derive + revoke on root CNode");
}

fn halt_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    kprintln!("[panic] {info}");
    #[cfg(feature = "selftest")]
    qemu::exit(qemu::ExitCode::Failure);
    #[allow(unreachable_code)]
    halt_forever()
}
