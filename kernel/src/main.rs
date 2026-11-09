//! The Superior microkernel.
//!
//! The architecture code (`arch`) boots the machine: console, exception
//! and interrupt handling, the system call path, the timer, and the
//! physical memory map. It hands all usable physical memory to the root
//! CNode as untyped capabilities (no kernel heap, ever) and calls
//! [`kernel_start`], which starts the boot user programs in their own
//! address spaces. From then on the kernel runs only on system calls,
//! faults and interrupts.
//!
//! Everything else, capabilities, threads, IPC, scheduling and the system
//! calls, is shared between architectures (`task`, and the host-tested
//! `superior_objects` crate).

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/mod.rs"]
mod arch;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;

mod memory;
mod task;

pub use arch::serial;

use core::panic::PanicInfo;
use superior_objects::cap::{Capability, Object, Rights};

/// The boot self-test program, built by `cargo xtask` (empty if none).
static USER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/user.elf"));
/// The shell, built by `cargo xtask` (empty if none).
static SHELL_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));
/// The Component Manager, the root task (empty if none).
static CM_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cm.elf"));
/// The boot bundle: the component manifest and every component's image.
static BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bundle.bin"));

fn banner() {
    kprintln!();
    kprintln!(
        "Superior microkernel {} ({})",
        env!("CARGO_PKG_VERSION"),
        arch::NAME
    );
}

fn report_memory(mem: &memory::Summary) {
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
}

/// Called by the architecture code once the machine is up.
fn kernel_start(untyped_caps: usize) -> ! {
    #[cfg(feature = "selftest")]
    selftest(untyped_caps);
    #[cfg(not(feature = "selftest"))]
    let _ = untyped_caps;

    // Self-test builds run the self-test programs; others start the
    // Component Manager, which starts everything else (or, built without
    // one, the shell directly).
    let started = if !cfg!(feature = "selftest") && !CM_IMAGE.is_empty() {
        start_component_manager()
    } else if cfg!(feature = "selftest") || SHELL_IMAGE.is_empty() {
        if USER_IMAGE.is_empty() {
            kprintln!("no boot user program embedded; idle");
            arch::halt_forever();
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

/// The Component Manager: the root task, and the only process the kernel
/// starts. It gets every capability the system has to give (memory, the
/// timer, the console UART and its interrupt, QEMU's exit device) and the
/// boot bundle mapped read-only, and builds every other process from them
/// according to the manifest in the bundle.
fn start_component_manager() -> Result<(), &'static str> {
    use superior_objects::abi::root;
    let base = memory::carve(root::UNTYPED_BITS).ok_or("no memory for the Component Manager")?;
    let (uart, irq) = arch::console_caps();
    let caps = [
        (
            root::UNTYPED as usize,
            Capability::new(
                Object::Untyped {
                    base,
                    size_bits: root::UNTYPED_BITS,
                },
                Rights::ALL,
            ),
        ),
        (
            root::TIMER as usize,
            Capability::new(
                Object::Notification {
                    id: task::TIMER_NTFN as u32,
                },
                Rights::READ,
            ),
        ),
        (
            root::EXIT_PORT as usize,
            Capability::new(
                Object::IoPort {
                    base: 0xf4,
                    count: 4,
                },
                Rights::WRITE,
            ),
        ),
        (root::UART as usize, uart),
        (root::UART_IRQ as usize, irq),
    ];
    task::give_cnode(0, root::CNODE_BITS, root::SELF_CNODE as usize)?;
    let bundle_va = arch::vm::USER_BASE + root::BUNDLE_OFFSET;
    task::spawn_process_with(
        0,
        CM_IMAGE,
        root::PRIORITY,
        BUNDLE.len() as u64,
        &caps,
        &[(bundle_va, BUNDLE)],
    )?;
    kprintln!(
        "[ok] Component Manager loaded; boot bundle of {} KiB",
        BUNDLE.len() >> 10
    );
    Ok(())
}

/// The shell: one process that is also the serial driver. It gets the
/// UART (I/O ports on x86-64, its register page on AArch64) and its
/// interrupt line, a notification for that interrupt, the timer
/// notification, memory to make objects from, and QEMU's exit device for
/// `shutdown`. Nothing else: it has no other device and no other process.
fn start_shell() -> Result<(), &'static str> {
    let rw = Rights::READ | Rights::WRITE;
    let base = memory::carve(16).ok_or("no memory for the shell's untyped block")?;
    let (uart, irq) = arch::console_caps();
    let caps = [
        (0, uart),
        (1, irq),
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
    // Exceptions: a breakpoint must trap into our handler and return.
    arch::breakpoint_selftest();
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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::disable_interrupts();
    kprintln!("[panic] {info}");
    #[cfg(feature = "selftest")]
    arch::qemu_exit(false);
    #[allow(unreachable_code)]
    arch::halt_forever()
}
