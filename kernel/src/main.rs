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

/// The boot self-test program, built by `cargo xtask` (empty if none).
static USER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/user.elf"));
/// The shell, built by `cargo xtask` (empty if none).
static SHELL_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));

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

    // Self-test builds run the self-test programs; others boot the shell.
    let started = if cfg!(feature = "selftest") || SHELL_IMAGE.is_empty() {
        if USER_IMAGE.is_empty() {
            kprintln!("no boot user program embedded; idle");
            halt_forever();
        }
        start_pingpong()
    } else {
        start_shell()
    };
    if let Err(e) = started {
        panic!("starting user programs: {e}");
    }
    task::start()
}

/// The shell: one process that is also the serial driver. It gets COM1's
/// ports and interrupt line, a notification for that interrupt, the timer
/// notification, memory to make objects from, and the QEMU exit port for
/// `shutdown`. Nothing else: it has no other device and no other process.
fn start_shell() -> Result<(), &'static str> {
    let rw = Rights::READ | Rights::WRITE;
    let base = memory::carve(16).ok_or("no memory for the shell's untyped block")?;
    let caps = [
        (
            0,
            Capability::new(
                Object::IoPort {
                    base: 0x3f8,
                    count: 8,
                },
                rw,
            ),
        ),
        (
            1,
            Capability::new(
                Object::Irq {
                    line: interrupts::COM1_IRQ,
                },
                rw,
            ),
        ),
        (2, Capability::new(Object::Notification { id: 2 }, rw)),
        (
            3,
            Capability::new(
                Object::Notification {
                    id: task::TIMER_NTFN as u32,
                },
                Rights::READ,
            ),
        ),
        (
            4,
            Capability::new(
                Object::Untyped {
                    base,
                    size_bits: 16,
                },
                Rights::ALL,
            ),
        ),
        (
            5,
            Capability::new(
                Object::IoPort {
                    base: 0xf4,
                    count: 4,
                },
                Rights::WRITE,
            ),
        ),
    ];
    task::spawn_process(0, SHELL_IMAGE, 10, 0, &caps)?;
    kprintln!("[ok] shell loaded (serial driver in user space)");
    Ok(())
}

/// Three processes, each in its own address space. The server and client
/// share one endpoint: the server holds the original, the client a badged
/// copy derived from it with Write and GrantReply only, so it can call (and
/// accept capabilities in replies) but not receive or grant. The server
/// also holds a notification it hands to the client through a reply. It
/// goes passive before its first receive, so it serves each call on the
/// caller's scheduling context.
///
/// The spinner has the client's priority, is ahead of it in the ready
/// queue, and makes no system call while it spins. The client gets the
/// CPU only if the timer preempts the spinner, so the test passing proves
/// preemption.
///
/// Afterwards the spinner signals the client and stops itself with a fault
/// it has no handler for; the client then
/// sleeps on the timer notification with every other thread blocked, so
/// the CPU must idle and the timer must wake it.
fn start_pingpong() -> Result<(), &'static str> {
    let endpoint = Capability::new(
        Object::Endpoint { id: 0 },
        Rights::READ | Rights::WRITE | Rights::GRANT | Rights::GRANT_REPLY,
    );
    let gift = Capability {
        badge: 0x5,
        ..Capability::new(Object::Notification { id: 3 }, Rights::READ | Rights::WRITE)
    };
    task::spawn_process(0, USER_IMAGE, 10, 0, &[(0, endpoint), (1, gift)])?;
    let timer = Capability::new(
        Object::Notification {
            id: task::TIMER_NTFN as u32,
        },
        Rights::READ,
    );
    let spinner_done = Object::Notification { id: 1 };
    task::spawn_process(
        1,
        USER_IMAGE,
        5,
        2,
        &[(0, Capability::new(spinner_done, Rights::WRITE))],
    )?;
    task::spawn_process(
        2,
        USER_IMAGE,
        5,
        1,
        &[(1, timer), (2, Capability::new(spinner_done, Rights::READ))],
    )?;
    task::derive_cap(0, 0, 2, 0, Rights::WRITE | Rights::GRANT_REPLY, Some(0xC1))?;
    // The server is also the client's fault handler, told apart by badge.
    task::derive_cap(0, 0, 2, 11, Rights::WRITE, Some(0xFA))?;
    // 64 KiB of untyped memory for the client to make its own objects from.
    let base = memory::carve(16).ok_or("no memory for the client's untyped block")?;
    task::grant_root(
        2,
        4,
        Capability::new(
            Object::Untyped {
                base,
                size_bits: 16,
            },
            Rights::ALL,
        ),
    )?;
    // A hog above everyone, spinning forever, held to 2 ticks in every 10
    // by its scheduling context. Without the budget nothing else would run.
    task::spawn_process(3, USER_IMAGE, 20, 3, &[])?;
    task::configure_sched(3, 2, 10)?;
    kprintln!(
        "[ok] hog (prio 20, 2/10 ticks), passive server (prio 10), spinner and client (prio 5) loaded"
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
