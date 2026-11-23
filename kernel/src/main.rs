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

mod aml;
mod dbc;
mod entropy;
mod rtc;
mod iommu;
mod memory;
mod smp;
mod task;
mod tpm;

pub use arch::serial;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use superior_objects::cap::{Capability, Object, Rights};

/// The boot self-test program, built by `cargo xtask` (empty if none).
static USER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/user.elf"));
/// The shell, built by `cargo xtask` (empty if none).
static SHELL_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shell.elf"));
/// The Component Manager, the root task (empty if none).
static CM_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cm.elf"));
/// The boot bundle: the component manifest and every component's image,
/// signed (`superior_objects::bundle::Signed`).
static BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bundle.bin"));
/// The Ed25519 public key the boot bundle must be signed with.
static TRUST_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trust.key"));

/// The oldest bundle version this kernel boots: an older one, however
/// well signed, is a rollback.
fn min_version() -> u64 {
    match u64::from_str_radix(env!("SUPERIOR_MIN_VERSION"), 10) {
        Ok(v) => v,
        Err(_) => u64::MAX,
    }
}

/// Verified boot: checks the boot bundle's signature against the key built
/// into the kernel and its version against the oldest allowed, and
/// measures it (SHA-256 of all of it). Returns the bundle itself; nothing
/// from it runs otherwise.
fn verified_bundle() -> Result<&'static [u8], &'static str> {
    use superior_objects::bundle::Signed;
    let key: &[u8; 32] = TRUST_KEY.try_into().map_err(|_| "no trust key built in")?;
    let s = Signed::split(BUNDLE).ok_or("it is not signed")?;
    if !s.verify(key) {
        return Err("its signature does not verify against the built-in key");
    }
    if s.version < min_version() {
        kprintln!("[boot] bundle version {} is older than {}", s.version, min_version());
        return Err("it is older than this kernel accepts (a rollback)");
    }
    // The TPM's rollback counter: the oldest version this machine boots
    // again, whatever kernel it runs.
    let tpm = tpm::get();
    if let Some(t) = tpm {
        match t.counter(tpm::COUNTER_INDEX) {
            Ok(Some(floor)) if s.version < floor => {
                kprintln!("[tpm] bundle version {} is older than the TPM's rollback counter ({floor})", s.version);
                return Err("it is older than the TPM's rollback counter (a rollback)");
            }
            Ok(_) => {}
            Err(e) => {
                kprintln!("[tpm] reading the rollback counter: {e}");
                return Err("the TPM's rollback counter cannot be read");
            }
        }
    }
    let m = s.measure();
    let hex = |m: &[u8; 32]| {
        let mut hex = [0u8; 64];
        for (i, b) in m.iter().enumerate() {
            hex[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
            hex[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
        }
        hex
    };
    let mhex = hex(&m);
    kprintln!(
        "[boot] bundle verified: version {}, signed by key {:02x}{:02x}{:02x}{:02x}..., measurement sha256:{}",
        s.version,
        key[0],
        key[1],
        key[2],
        key[3],
        core::str::from_utf8(&mhex).unwrap_or("?")
    );
    if let Some(t) = tpm {
        // Measured boot: the bundle's measurement into its PCR, and the
        // counter up to this version (it never comes down).
        let pcr = t.extend(tpm::BUNDLE_PCR, &m).and_then(|_| t.read_pcr(tpm::BUNDLE_PCR));
        let pcr = match pcr {
            Ok(v) => v,
            Err(e) => {
                kprintln!("[tpm] measuring the bundle: {e}");
                return Err("the TPM would not take the bundle's measurement");
            }
        };
        let phex = hex(&pcr);
        kprintln!(
            "[tpm] PCR {} extended with the bundle's measurement: now sha256:{}",
            tpm::BUNDLE_PCR,
            core::str::from_utf8(&phex).unwrap_or("?")
        );
        match t.raise(tpm::COUNTER_INDEX, s.version) {
            Ok(v) => kprintln!("[tpm] rollback counter: {v} (nothing older boots)"),
            Err(e) => {
                kprintln!("[tpm] raising the rollback counter: {e}");
                return Err("the TPM's rollback counter cannot be raised");
            }
        }
    }
    Ok(s.payload)
}

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
    match task::init_tables(memory::ram_bytes()) {
        Ok((slots, bytes)) => {
            kprintln!("[ok] capability table: {slots} slots ({} KiB)", bytes >> 10)
        }
        Err(e) => panic!("{e}"),
    }
    // The IOMMU would block the DbC's DMA, and user space takes the
    // controller: the log over USB ends here.
    dbc::close("the IOMMU comes on next, then user space takes the controller");
    match arch::iommu_init() {
        Some(name) => kprintln!("[ok] IOMMU: {name}, all DMA blocked until bound"),
        None => kprintln!("[ok] no IOMMU"),
    }
    match entropy::init() {
        Some(source) => kprintln!("[ok] entropy: seeded from {source} and the cycle counter's jitter"),
        None => kprintln!("[ok] entropy: no random instruction; seeded from the cycle counter's jitter and interrupt timings"),
    }
    #[cfg(feature = "selftest")]
    selftest(untyped_caps);
    #[cfg(not(feature = "selftest"))]
    let _ = untyped_caps;

    // Self-test builds run the self-test programs; others start the
    // Component Manager, which starts everything else (or, built without
    // one, the shell directly).
    let started = if !cfg!(feature = "selftest") && !CM_IMAGE.is_empty() {
        start_component_manager().inspect(|_| task::set_root_builder(start_component_manager))
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
    // The other CPUs, once the boot threads exist: each idles until there
    // is work for it.
    let cpus = arch::start_secondaries();
    kprintln!("[ok] {cpus} CPU{} online", if cpus == 1 { "" } else { "s" });
    arch::console_hand_over();
    task::start()
}

/// RAM the kernel keeps for itself when it hands the rest to the Component
/// Manager.
const KERNEL_KEEPS: u64 = 16 << 20;

/// The Component Manager: the root task, and the only process the kernel
/// starts. It gets every capability the system has to give (memory, the
/// timer, the console UART and its interrupt, QEMU's exit device, PCI
/// configuration space, device memory for BARs and the MSI vectors) and the
/// boot bundle mapped read-only, and builds every other process from them
/// according to the manifest in the bundle.
///
/// After a fast reboot (`task::fast_reboot`) this runs again: the same
/// untyped block (everything made from it is gone), the same state store
/// with its contents, and the root task's own pages from the start of its
/// arena again. Nothing leaks, however many times it runs.
fn start_component_manager() -> Result<(), &'static str> {
    use superior_objects::abi::root;
    let bundle = match verified_bundle() {
        Ok(b) => b,
        Err(why) => {
            // Nothing from it may run: stop the machine.
            kprintln!("[boot] boot bundle REFUSED: {why}");
            arch::qemu_exit(false);
        }
    };
    // Made once, at the first start.
    static UNTYPED: AtomicU64 = AtomicU64::new(0);
    static UNTYPED_BITS: AtomicU8 = AtomicU8::new(0);
    static STATE_STORE: AtomicU64 = AtomicU64::new(0);
    if UNTYPED.load(Ordering::SeqCst) == 0 {
        // The components' memory holds copies of the bundle's files: room
        // for twice the bundle, and never less than the least.
        let bits = ((2 * bundle.len() as u64).next_power_of_two().ilog2() as u8).max(root::UNTYPED_BITS);
        UNTYPED_BITS.store(bits, Ordering::SeqCst);
        let base = memory::carve(bits).ok_or("no memory for the Component Manager")?;
        let store = memory::carve(12 + root::STATE_PAGES.ilog2() as u8)
            .ok_or("no memory for the state store")?;
        // SAFETY: just carved, so no one else has it; RAM the kernel maps.
        unsafe {
            core::ptr::write_bytes(
                arch::vm::phys_ptr(store),
                0,
                (root::STATE_PAGES * 4096) as usize,
            )
        };
        UNTYPED.store(base, Ordering::SeqCst);
        STATE_STORE.store(store, Ordering::SeqCst);
    }
    // Then the rest of RAM, but for what the kernel keeps for itself (the
    // page tables of address spaces it builds, IOMMU and interrupt
    // tables made as devices appear).
    static SPARE: spin::Mutex<([(u64, u8); root::SPARE_COUNT as usize], usize)> =
        spin::Mutex::new(([(0, 0); root::SPARE_COUNT as usize], 0));
    {
        let mut spare = SPARE.lock();
        if spare.1 == 0 {
            // The Component Manager's arena first, while RAM is whole.
            if !memory::reserve_arena(bundle.len() as u64) {
                return Err("no memory for the Component Manager's arena");
            }
            let given = memory::take_spare(KERNEL_KEEPS, |base, bits| {
                let n = spare.1;
                if n == spare.0.len() {
                    return false;
                }
                spare.0[n] = (base, bits);
                spare.1 = n + 1;
                true
            });
            kprintln!(
                "[ok] {} MiB of spare RAM in {} blocks for the Component Manager",
                given >> 20,
                spare.1
            );
        }
    }
    let base = UNTYPED.load(Ordering::SeqCst);
    let store = STATE_STORE.load(Ordering::SeqCst);
    let (uart, irq) = arch::console_caps();
    let caps = [
        (
            root::UNTYPED as usize,
            Capability::new(
                Object::Untyped {
                    base,
                    size_bits: UNTYPED_BITS.load(Ordering::SeqCst),
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
    let (pci_config, pci_mmio, msi) = arch::pci_caps();
    let rw = Rights::READ | Rights::WRITE;
    let pci = [
        (root::PCI_CONFIG as usize, pci_config),
        (root::PCI_MMIO as usize, pci_mmio),
    ]
    .into_iter()
    .chain(
        msi.take(root::MSI_COUNT as usize)
            .enumerate()
            .map(|(n, line)| {
                (
                    root::MSI as usize + n,
                    Capability::new(Object::Irq { line }, rw),
                )
            }),
    );
    let iommu = arch::iommu::present().then(|| {
        (
            root::IOMMU as usize,
            Capability::new(Object::IommuControl, Rights::ALL),
        )
    });
    let state = (0..root::STATE_PAGES).map(|p| {
        let frame = Object::Frame {
            paddr: store + p * 4096,
            size_bits: 12,
        };
        (
            (root::STATE_STORE + p) as usize,
            Capability::new(frame, Rights::ALL),
        )
    });
    let intx = arch::intx_lines().iter().enumerate().map(|(n, &line)| {
        (
            root::INTX as usize + n,
            Capability::new(Object::Irq { line }, rw),
        )
    });
    let intx = intx.chain(arch::pci_io_cap().map(|c| (root::PCI_IO as usize, c)));
    let ps2 = arch::ps2_caps()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(k, c)| (root::PS2 as usize + k, c));
    let screen = arch::framebuffer_cap().map(|c| (root::FRAMEBUFFER as usize, c));
    if let Some((_, c)) = screen {
        if let Object::DeviceUntyped { base, size_bits } = c.object {
            kprintln!("[ok] the boot framebuffer for user space: {:#x}, 2^{} bytes", base, size_bits);
        }
    }
    let spare = *SPARE.lock();
    let spare = spare.0[..spare.1].iter().enumerate().map(|(k, &(base, size_bits))| {
        (
            root::SPARE as usize + k,
            Capability::new(Object::Untyped { base, size_bits }, Rights::ALL),
        )
    });
    let mut all = [(0, caps[0].1); 56 + root::SPARE_COUNT as usize];
    let mut n = 0;
    for c in caps.into_iter().chain(pci).chain(iommu).chain(state).chain(intx).chain(ps2).chain(screen).chain(spare) {
        all[n] = c;
        n += 1;
    }
    let caps = &all[..n];
    task::give_cnode(task::ROOT_TID, root::CNODE_BITS, root::SELF_CNODE as usize)?;
    let bundle_va = arch::vm::USER_BASE + root::BUNDLE_OFFSET;
    if !memory::arena_on() {
        return Err("no memory for the Component Manager's arena");
    }
    let arg = bundle.len() as u64 | task::reboots() << root::REBOOTS_SHIFT;
    let r = task::spawn_process_with(
        task::ROOT_TID,
        CM_IMAGE,
        root::PRIORITY,
        arg,
        caps,
        &[(bundle_va, bundle)],
    );
    memory::arena_off();
    r?;
    kprintln!(
        "[ok] Component Manager loaded; boot bundle of {} KiB",
        bundle.len() >> 10
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
    start_timeout_test(spinner_done)
}

/// Timeout faults. A passive slow server (thread 4) spins on every call; a
/// caller (5) with a budget of 1 tick in 10 calls it, so the server runs
/// that budget dry mid-request. Its timeout handler (6) gets the fault and
/// says stop, the caller's call fails with `PeerRestarted`, and each of
/// the handler and the caller reports to the client on the spinner's done
/// notification: bit 0x10 (handler) and 0x20 (caller) for success, 0x40
/// for anything else.
fn start_timeout_test(done: Object) -> Result<(), &'static str> {
    let rw = Rights::READ | Rights::WRITE;
    let report = |badge| Capability {
        badge,
        ..Capability::new(done, Rights::WRITE)
    };
    task::spawn_process(
        4,
        USER_IMAGE,
        8,
        4,
        &[(0, Capability::new(Object::Endpoint { id: 4 }, rw))],
    )?;
    task::spawn_process(5, USER_IMAGE, 6, 5, &[(1, report(0x20)), (2, report(0x40))])?;
    task::derive_cap(4, 0, 5, 0, Rights::WRITE, Some(0x5C))?;
    task::configure_sched(5, 1, 10)?;
    task::spawn_process(
        6,
        USER_IMAGE,
        9,
        6,
        &[
            (0, Capability::new(Object::Endpoint { id: 5 }, rw)),
            (1, report(0x10)),
            (2, report(0x40)),
        ],
    )?;
    task::set_timeout_handler(4, 5, 0x7E)?;
    kprintln!("[ok] slow server (prio 8), its 1/10-tick caller (prio 6) and timeout handler (prio 9) loaded");
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
    dbc::flush();
    #[cfg(feature = "selftest")]
    arch::qemu_exit(false);
    #[allow(unreachable_code)]
    arch::halt_forever()
}
