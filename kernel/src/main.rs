//! The Superior microkernel.
//!
//! Boots on x86-64 through the `bootloader` crate, brings up the serial
//! console, GDT/TSS, exception handlers and the `syscall` path, hands all
//! usable physical memory to the root task as untyped capabilities (no
//! kernel heap, ever), then starts the boot user programs in their own
//! address spaces. From then on the kernel runs only on system calls and
//! timer interrupts.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod apic;
mod gdt;
mod interrupts;
mod memory;
mod qemu;
mod serial;
mod syscall;
mod task;
mod vm;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use superior_objects::cap::{Capability, Object, Rights};

/// The boot user program, built by `cargo xtask` (empty if none).
static USER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/user.elf"));

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
    syscall::init();
    kprintln!("[ok] syscall/sysret enabled");

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
    let offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("bootloader did not map physical memory");
    vm::init(offset);
    kprintln!("[ok] physical memory mapped at {offset:#x}");
    let timer_hz = apic::init();
    kprintln!(
        "[ok] local APIC timer: {} kHz input, {} Hz tick",
        timer_hz / 1000,
        apic::TICK_HZ
    );

    #[cfg(feature = "selftest")]
    selftest(mem.untyped_caps);

    if USER_IMAGE.is_empty() {
        kprintln!("no boot user program embedded; idle");
        halt_forever();
    }
    if let Err(e) = start_pingpong() {
        panic!("starting user programs: {e}");
    }
    task::start()
}

/// Three processes, each in its own address space. The server and client
/// share one endpoint: the server holds it with Read+Write, the client a
/// badged copy with Write only, so it can call but not receive.
///
/// The spinner has the client's priority, is ahead of it in the ready
/// queue, and makes no system call while it spins. The client gets the
/// CPU only if the timer preempts the spinner, so the test passing proves
/// preemption.
///
/// Afterwards the spinner signals the client and parks; the client then
/// sleeps on the timer notification with every other thread blocked, so
/// the CPU must idle and the timer must wake it.
fn start_pingpong() -> Result<(), &'static str> {
    // Until cross-CNode capability copy exists, the kernel mints these
    // two endpoint capabilities directly at boot.
    let endpoint = Object::Endpoint { id: 0 };
    let server_cap = Capability::new(endpoint, Rights::READ | Rights::WRITE);
    let client_cap = Capability {
        badge: 0xC1,
        ..Capability::new(endpoint, Rights::WRITE | Rights::GRANT_REPLY)
    };
    task::spawn_process(0, USER_IMAGE, 10, 0, &[(0, server_cap)])?;
    let timer = Capability::new(
        Object::Notification {
            id: task::TIMER_NTFN as u32,
        },
        Rights::READ,
    );
    let spinner_done = Object::Notification { id: 1 };
    let park = Object::Notification { id: 2 };
    task::spawn_process(
        1,
        USER_IMAGE,
        5,
        2,
        &[
            (0, Capability::new(spinner_done, Rights::WRITE)),
            (1, Capability::new(park, Rights::READ)),
        ],
    )?;
    task::spawn_process(
        2,
        USER_IMAGE,
        5,
        1,
        &[
            (0, client_cap),
            (1, timer),
            (2, Capability::new(spinner_done, Rights::READ)),
        ],
    )?;
    kprintln!(
        "[ok] server (prio 10), spinner and client (prio 5) loaded in separate address spaces"
    );
    Ok(())
}

#[cfg(feature = "selftest")]
fn selftest(untyped_caps: usize) {
    // Exceptions: int3 must trap into our handler and return.
    x86_64::instructions::interrupts::int3();
    kprintln!("[pass] breakpoint trap returns");

    // Capabilities on the live root CNode: derive a read-only child of the
    // first untyped cap, then revoke it (leaving the cap retypable).
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

pub fn halt_forever() -> ! {
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
