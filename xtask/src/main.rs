//! Superior build driver. Each command takes an optional architecture,
//! `x86_64` (the default) or `aarch64`:
//!
//!   cargo xtask image [arch]       build the kernel and a bootable image
//!   cargo xtask run [arch]         boot it in QEMU, into the shell (serial on
//!                                  this terminal)
//!   cargo xtask console-image      an image whose shell is also a console on
//!                                  the screen and the PS/2 keyboard
//!                                  (boot/console.manifest), for PCs with no
//!                                  serial port
//!   cargo xtask console-run        boot that image in QEMU
//!   cargo xtask console-shell-test type on QEMU's PS/2 keyboard and check the
//!                                  screen, pixel by pixel
//!   cargo xtask test               host unit tests, the exhaustive model check
//!                                  and long simulation, then on each
//!                                  architecture the boot self-tests in QEMU and
//!                                  a scripted session with the shell
//!   cargo xtask boot-test [arch]   just the boot self-tests
//!   cargo xtask shell-test [arch]  just the shell session
//!   cargo xtask el2-test           AArch64 entered at EL2 (-kernel and UEFI)
//!   cargo xtask layout-test        AArch64 with ECAM moved (highmem=on): the
//!                                  driver test from the device tree and ACPI
//!   cargo xtask cm-test [arch]     the Component Manager's boot test: boot
//!                                  `boot/test.manifest` and check the log
//!   cargo xtask supervise-test [arch]  supervision: boot
//!                                  `boot/supervise.manifest` (restarts, state,
//!                                  retries, giving up) and check the log
//!   cargo xtask drivers-test [arch]    the driver framework: boot
//!                                  `boot/drivers.manifest` with a virtio
//!                                  disk (PCI bus server, virtio-blk driver,
//!                                  a client) and check the log
//!   cargo xtask memory-test [arch]     the Memory Server: boot
//!                                  `boot/memory.manifest` (quotas, demand-zero
//!                                  heaps, pages back on restart) and check
//!                                  the log
//!   cargo xtask reboot-test [arch]     the fast reboot: boot
//!                                  `boot/reboot.manifest`, fail the Memory
//!                                  Server and then the Component Manager, and
//!                                  check the state store survives both
//!   cargo xtask fs-test [arch]     the filesystem server: boot
//!                                  `boot/fs.manifest` on a fresh disk (writes
//!                                  under fault injection, then a power cut),
//!                                  then `boot/fs-verify.manifest` on the same
//!                                  disk, and check the logs
//!   cargo xtask bench              time IPC under hardware virtualization
//!                                  (WHPX or KVM, x86-64) and check it against
//!                                  seL4's published figures
//!   cargo xtask sel4-test          the same shell session with the shell
//!                                  running on seL4 (AArch64) instead; `test`
//!                                  ends with it. seL4 and its loader are built
//!                                  once, in Docker (sel4/Dockerfile)
//!
//! A normal image boots the Component Manager with a bundle built from
//! `boot/shell.manifest`, so the shell runs as a component. Self-test
//! images run the kernel's own self-test programs instead.
//!
//! x86-64 boots from a BIOS disk image; AArch64 boots QEMU's `virt` machine
//! straight from the kernel ELF, with semihosting for the exit status.
//! QEMU is found through $QEMU (x86-64) or $QEMU_AARCH64, then the default
//! Windows install path, then PATH.

mod wifi_ap;

use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Both architectures report the kernel's pass code 0x10 as QEMU status
/// (0x10 << 1) | 1: isa-debug-exit on x86-64, semihosting on AArch64.
const QEMU_PASS: i32 = 33;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    fn parse(s: Option<&str>) -> Result<Arch, String> {
        match s {
            None | Some("x86_64") | Some("x86-64") => Ok(Arch::X86_64),
            Some("aarch64") | Some("arm64") => Ok(Arch::Aarch64),
            Some(other) => Err(format!("unknown architecture {other:?}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    /// The kernel and user programs share a target; floating point is off
    /// on both, so threads never need FP state saved.
    fn target(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64-unknown-none",
            Arch::Aarch64 => "aarch64-unknown-none-softfloat",
        }
    }
}

/// A bootable kernel for one architecture.
#[derive(Clone)]
struct Image {
    path: PathBuf,
    arch: Arch,
    /// seL4 with the shell as its root task, rather than Superior.
    sel4: bool,
    /// A disk image to attach as a virtio block device (PCI).
    disk: Option<PathBuf>,
    /// The disk may be written (the filesystem tests).
    writable: bool,
    /// The disk's driver, and so how the disk is attached: `virtio-blk`,
    /// `nvme` or `ahci`.
    driver: &'static str,
    /// A virtio network device on QEMU's user-mode network (the network
    /// test).
    net: bool,
    /// The network device is this one instead, for a Linux driver (the
    /// Linux Driver Environment tests).
    linux_nic: Option<&'static str>,
    /// A virtio network device standing in for a Wi-Fi radio: its frames
    /// go over UDP to the test's access point (the Wi-Fi test).
    radio: bool,
    /// x86-64: a CPU with AVX (QEMU's "max"), whose state the Linux
    /// personality's signal frames carry (the Linux tests).
    avx: bool,
    /// A USB keyboard on an xHCI controller, typed on through QEMU's
    /// monitor (the keyboard test).
    keyboard: bool,
    /// An xHCI controller alone, at [`XHCI_SLOT`], for the kernel to look
    /// for a USB Debug Capability on (QEMU's has none).
    xhci: bool,
    /// A USB mouse and a USB tablet on the same controller (the input
    /// test).
    mouse: bool,
    /// An empty PCI Express root port, and QEMU's monitor to plug cards
    /// into it (the hot-plug test).
    hotplug: bool,
    /// QEMU's monitor alone (the suspend test presses a key through it to
    /// wake the machine).
    monitor: bool,
    /// QEMU's bochs-display as the only display, and its monitor to take
    /// screenshots through (the display test).
    display: bool,
    /// With `display`: a virtio GPU in its place (virtio-vga on x86, for
    /// the bootloader's BIOS), which has a cursor plane (the cursor test).
    gpu: bool,
    /// QEMU's ENSONIQ AudioPCI, recording what it plays to this WAV file
    /// (the audio test).
    audio: Option<PathBuf>,
    /// Booted by UEFI firmware (QEMU's OVMF, or edk2 for `virt`) rather
    /// than a BIOS or QEMU's `-kernel`.
    uefi: bool,
    /// AArch64 UEFI: the firmware describes the machine by ACPI tables,
    /// not a device tree.
    acpi: bool,
    /// AArch64: the CPUs have EL2 (`virtualization=on`), where QEMU's
    /// `-kernel`, edk2 and PSCI start them.
    el2: bool,
    /// AArch64: `highmem=on`, which moves PCI's ECAM above 256 GiB.
    highmem: bool,
    /// QEMU's `-smp` in place of the usual CPU count (a CPU topology).
    smp: Option<&'static str>,
    /// UEFI: the firmware's variable store (a writable copy), for Secure
    /// Boot's enrolled keys.
    vars: Option<PathBuf>,
    /// AArch64 UEFI: firmware in place of QEMU's edk2 (one built with
    /// Secure Boot).
    firmware: Option<PathBuf>,
}

/// The disk drivers, each with the PCI function its test disk appears as
/// and the test client's role for it (which device it must be refused).
const DISK_DRIVERS: [(&str, &str, u64); 3] = [
    ("virtio-blk", "1af4:1042 class 010000", 4),
    ("nvme", "pci: 0a:00.0 1b36:0010 class 010802", 11),
    ("ahci", "8086:2922 class 010601", 12),
];

fn disk_driver(name: &str) -> (&'static str, &'static str, u64) {
    *DISK_DRIVERS
        .iter()
        .find(|d| d.0 == name)
        .expect("a disk driver")
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let arch = Arch::parse(args.get(1).map(String::as_str));
    let result = arch.and_then(|arch| match args.first().map(String::as_str) {
        Some("idl") => idl(false),
        Some("image") => image(false, arch).map(|i| println!("image: {}", i.path.display())),
        // The shell as a console on the machine's own screen and PS/2
        // keyboard (boot/console.manifest), for PCs with no serial port.
        Some("console-image") => {
            image_with(false, arch, "console").map(|i| println!("image: {}", i.path.display()))
        }
        Some("console-run") => image_with(false, arch, "console").and_then(|img| boot(&img, false)),
        Some("console-shell-test") => console_shell_test(),
        Some("run") => image(false, arch).and_then(|img| boot(&img, false)),
        Some("test") => host_tests()
            .and_then(|_| {
                [Arch::X86_64, Arch::Aarch64].into_iter().try_for_each(|a| {
                    image(true, a)
                        .and_then(|img| boot(&img, true))
                        .and_then(|_| image_with(false, a, "test"))
                        .and_then(|img| cm_test(&img))
                        .and_then(|_| image_with(false, a, "supervise"))
                        .and_then(|img| supervise_test(&img))
                        .and_then(|_| image_with(false, a, "drivers"))
                        .and_then(|img| drivers_test(&img))
                        .and_then(|_| image_with(false, a, "memory"))
                        .and_then(|img| memory_test(&img))
                        .and_then(|_| image_with(false, a, "reboot"))
                        .and_then(|img| reboot_test(&img))
                        .and_then(|_| fs_test(a, "virtio-blk"))
                        .and_then(|_| disk_test(a, "nvme"))
                        .and_then(|_| disk_test(a, "ahci"))
                        .and_then(|_| net_test(a, "net"))
                        .and_then(|_| net_test(a, "lde"))
                        .and_then(|_| net_test(a, "lde-e100"))
                        .and_then(|_| wifi_test(a))
                        .and_then(|_| display_test(a))
                        .and_then(|_| desktop_test(a))
                        .and_then(|_| windows_test(a))
                        .and_then(|_| cursor_test(a))
                        .and_then(|_| toolkit_test(a))
                        .and_then(|_| panel_test(a))
                        .and_then(|_| resize_test(a))
                        .and_then(|_| widgets_test(a))
                        .and_then(|_| notes_test(a))
                        .and_then(|_| input_test(a))
                        .and_then(|_| audio_test(a))
                        .and_then(|_| tcp_test(a))
                        .and_then(|_| keyboard_test(a))
                        .and_then(|_| hotplug_test(a))
                        .and_then(|_| suspend_test(a))
                        .and_then(|_| verified_boot_test(a))
                        .and_then(|_| tpm_test(a))
                        .and_then(|_| secure_boot_test(a))
                        .and_then(|_| ab_test(a))
                        .and_then(|_| update_test(a))
                        .and_then(|_| packages_test(a))
                        .and_then(|_| image_with(false, a, "linux"))
                        .and_then(|img| linux_test(&img))
                        .and_then(|_| image(false, a))
                        .and_then(|img| shell_session(&img))
                })
            })
            .and_then(|_| uefi_test(Arch::X86_64))
            .and_then(|_| uefi_test(Arch::Aarch64))
            .and_then(|_| el2_test())
            .and_then(|_| layout_test())
            .and_then(|_| console_test())
            .and_then(|_| console_shell_test())
            .and_then(|_| sel4_image())
            .and_then(|img| shell_session(&img)),
        Some("sel4-test") => sel4_image().and_then(|img| shell_session(&img)),
        Some("boot-test") => image(true, arch).and_then(|img| boot(&img, true)),
        Some("shell-test") => image(false, arch).and_then(|img| shell_session(&img)),
        Some("el2-test") => el2_test(),
        Some("layout-test") => layout_test(),
        Some("uefi-test") => uefi_test(arch),
        Some("console-test") => console_test(),
        Some("cm-test") => image_with(false, arch, "test").and_then(|img| cm_test(&img)),
        Some("drivers-test") => {
            image_with(false, arch, "drivers").and_then(|img| drivers_test(&img))
        }
        Some("supervise-test") => {
            image_with(false, arch, "supervise").and_then(|img| supervise_test(&img))
        }
        Some("fs-test") => fs_test(arch, "virtio-blk"),
        Some("nvme-test") => disk_test(arch, "nvme"),
        Some("ahci-test") => disk_test(arch, "ahci"),
        Some("net-test") => net_test(arch, "net"),
        Some("lde-test") => net_test(arch, "lde"),
        Some("lde-e100-test") => net_test(arch, "lde-e100"),
        Some("wifi-test") => wifi_test(arch),
        Some("display-test") => display_test(arch),
        Some("desktop-test") => desktop_test(arch),
        Some("windows-test") => windows_test(arch),
        Some("cursor-test") => cursor_test(arch),
        Some("toolkit-test") => toolkit_test(arch),
        Some("panel-test") => panel_test(arch),
        Some("resize-test") => resize_test(arch),
        Some("widgets-test") => widgets_test(arch),
        Some("notes-test") => notes_test(arch),
        Some("input-test") => input_test(arch),
        Some("audio-test") => audio_test(arch),
        Some("tcp-test") => tcp_test(arch),
        Some("keyboard-test") => keyboard_test(arch),
        Some("hotplug-test") => hotplug_test(arch),
        Some("suspend-test") => suspend_test(arch),
        Some("verified-boot-test") => verified_boot_test(arch),
        Some("tpm-test") => tpm_test(arch),
        Some("secure-boot-test") => secure_boot_test(arch),
        Some("ab-test") => ab_test(arch),
        Some("update-test") => update_test(arch),
        Some("packages-test") => packages_test(arch),
        Some("memory-test") => {
            image_with(false, arch, "memory").and_then(|img| memory_test(&img))
        }
        Some("linux-test") => image_with(false, arch, "linux").and_then(|img| linux_test(&img)),
        Some("reboot-test") => {
            image_with(false, arch, "reboot").and_then(|img| reboot_test(&img))
        }
        Some("bench") => image(false, Arch::X86_64).and_then(|img| bench(&img)),
        _ => Err(
            "usage: cargo xtask <idl | image | run | test | boot-test | shell-test | cm-test | supervise-test | drivers-test | memory-test | reboot-test | fs-test | nvme-test | ahci-test | net-test | lde-test | lde-e100-test | wifi-test | display-test | desktop-test | windows-test | cursor-test | toolkit-test | panel-test | resize-test | widgets-test | notes-test | uefi-test | console-test | input-test | audio-test | tcp-test | keyboard-test | hotplug-test | suspend-test | verified-boot-test | tpm-test | secure-boot-test | ab-test | update-test | packages-test | linux-test | bench | sel4-test> [x86_64 | aarch64]"
                .into(),
        ),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo() -> Command {
    let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("could not start {cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed with {status}"))
    }
}

/// Compiles every interface description in `interfaces/` to Rust in
/// `crates/objects/src/idl/` (`cargo xtask idl`). With `check`, writes
/// nothing: the generated files must already be what the descriptions
/// give, so a description changed without generating again fails the
/// tests.
fn idl(check: bool) -> Result<(), String> {
    let dir = root().join("interfaces");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().strip_suffix(".idl").map(String::from))
        .collect();
    names.sort();
    for name in names {
        let source = format!("interfaces/{name}.idl");
        let text = std::fs::read_to_string(root().join(&source)).map_err(|e| format!("{source}: {e}"))?;
        let rust = superior_idl::compile(&text.replace("\r\n", "\n"), &source)
            .map_err(|e| format!("{source}: {e}"))?;
        let out = root().join("crates/objects/src/idl").join(format!("{name}.rs"));
        if check {
            let have = std::fs::read_to_string(&out).unwrap_or_default().replace("\r\n", "\n");
            if have != rust {
                return Err(format!(
                    "{} is not what {source} gives: run `cargo xtask idl`",
                    out.display()
                ));
            }
        } else {
            std::fs::write(&out, rust).map_err(|e| format!("writing {}: {e}", out.display()))?;
            println!("{source} -> {}", out.display());
        }
    }
    Ok(())
}

fn host_tests() -> Result<(), String> {
    println!("== interface descriptions against their generated Rust");
    idl(true)?;
    println!("== host unit tests");
    run(cargo().args([
        "test",
        "--quiet",
        "-p",
        "superior-objects",
        "-p",
        "superior-inet",
        "-p",
        "superior-driver",
        "-p",
        "superior-idl",
        "-p",
        "superior-toolkit",
        "-p",
        "superior-console",
        "-p",
        "superior-wifi",
    ]))?;
    println!("== model check and long simulation (release)");
    run(cargo().args([
        "test",
        "--quiet",
        "--release",
        "-p",
        "superior-objects",
        "--",
        "--ignored",
        "--nocapture",
    ]))
}

/// Linux's source files the Linux Driver Environment hosts: name, path in
/// Linux's tree, and SHA-256. They are fetched from kernel.org's stable
/// tree at `LINUX_TAG` when first needed and kept under `target/`: Linux
/// is GPL-2.0, and none of it is in this repository.
const LINUX_TAG: &str = "v6.6";
const LINUX_SOURCES: [(&str, &str, &str); 5] = [
    (
        "8139cp",
        "drivers/net/ethernet/realtek/8139cp.c",
        "11cca9ded616d4442f980af4b03fc54f8bfe992be14bfc8e9b003d7f8b4a0ee6",
    ),
    (
        "e100",
        "drivers/net/ethernet/intel/e100.c",
        "65f562bf302e3b28ea47ee44e77fe61c37e6ec569efdb2d020a4a84662828acd",
    ),
    (
        "bochs",
        "drivers/gpu/drm/tiny/bochs.c",
        "93b0b9a15cd1268b206ac1bbf71aec8338232ed0d47bc5969cd6c4453c86c3c4",
    ),
    (
        "ens1370",
        "sound/pci/ens1370.c",
        "44ca3cd3b0f6b83644545572436a72a095c7f50a4c6bdcc55b58cefca6ff2853",
    ),
    (
        "ak4531_codec",
        "sound/pci/ak4531_codec.c",
        "06336bb38b00cfe39c26196232e0e24049a7f4bc1af6cc21571fb204b9d7def5",
    ),
];

/// The Linux driver a manifest hosts in the Linux Driver Environment:
/// a network test's, the display tests', or the audio test's.
fn linux_driver(manifest: &str) -> Option<&'static str> {
    match manifest {
        "display" | "desktop" | "input" | "windows" | "toolkit" | "panel" | "resize" | "widgets" | "notes" => Some("bochs"),
        "audio" => Some("es1370"),
        _ => linux_nic(manifest).map(|l| l.0),
    }
}

/// The Linux source files (names in `LINUX_SOURCES`) of a driver, by the
/// name its component has (`lde-<driver>`): its own first, then the
/// library code it links (the ES1370's codec, which Linux builds as a
/// module of its own).
fn linux_files(driver: &str) -> Vec<&'static str> {
    match driver {
        "es1370" => vec!["ens1370", "ak4531_codec"],
        d => LINUX_SOURCES.iter().filter(|s| s.0 == d).map(|s| s.0).collect(),
    }
}

/// The Linux driver a manifest name stands for: `lde` is the Linux Driver
/// Environment test with 8139cp, `lde-<driver>` the same with another.
/// With it, the QEMU device it drives.
fn linux_nic(manifest: &str) -> Option<(&'static str, &'static str)> {
    match manifest {
        "lde" => Some(("8139cp", "rtl8139,netdev=n0")),
        // The 82557: QEMU's models of the later 8255x chips read a second
        // buffer descriptor inside a transmit command block whatever the
        // count says, which Linux leaves as the block last held it, and
        // so append stale bytes to some frames.
        "lde-e100" => Some(("e100", "i82557b,netdev=n0")),
        _ => None,
    }
}

/// Where the Linux personality's programs come from: Alpine Linux 3.18 (no
/// longer updated, so its packages stay as they are).
const ALPINE: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.18/main";

/// The packages, for each ISA: (Alpine's name for the ISA, package, its
/// SHA-256, the file taken from it, its name in the bundle).
const ALPINE_PACKAGES: [(&str, &str, &str, &str, &str); 8] = [
    ("x86_64", "busybox-1.36.1-r7", "d2cdd10ad7dce8e8ed48e100679b182646344dab8e07c1ea972d9eb6f9d809d7", "bin/busybox", "busybox"),
    ("x86_64", "musl-1.2.4-r3", "466e1e985756113655b65f49a4c5fb0013fd4da682fbef3dac91ec44ae986f0a", "lib/ld-musl-x86_64.so.1", "ld-musl"),
    ("x86_64", "pigz-2.7-r3", "d7cdca4f05916018a242a7bfaffb13318bcc079d92a6076f50083250052f3731", "usr/bin/pigz", "pigz"),
    ("x86_64", "zlib-1.2.13-r1", "5a25eef56ef21fca1749a3a298062821d5b4e465aa7815192a076adc54f8e778", "lib/libz.so.1.2.13", "libz"),
    ("aarch64", "busybox-1.36.1-r7", "9ecc170cae8289a86597a057670bbdc8cc4b3db327b4006f04000890711edf1d", "bin/busybox", "busybox"),
    ("aarch64", "musl-1.2.4-r3", "d9674ebd60a55330fcca142a02e7e3e5a9ee889d65dc929311f53f735c5c8ac5", "lib/ld-musl-aarch64.so.1", "ld-musl"),
    ("aarch64", "pigz-2.7-r3", "3baf210c43ab8c8e38af17557ea0016bcf8e71527728217fbcab3aa58167b531", "usr/bin/pigz", "pigz"),
    ("aarch64", "zlib-1.2.13-r1", "4e8cbd2d87633f9b1d469b8f8f0edb3a0371b99f7cae7adeb86cecea52fe3466", "lib/libz.so.1.2.13", "libz"),
];

/// BusyBox, musl's dynamic linker (which is also its C library), pigz and
/// zlib, as Alpine builds them for `arch`, unmodified, with their names
/// in the bundle: each package downloaded once and checked against its
/// pinned hash every time.
fn alpine_files(arch: Arch) -> Result<Vec<(String, Vec<u8>)>, String> {
    let isa = if arch == Arch::X86_64 { "x86_64" } else { "aarch64" };
    let dir = root().join("target/linux/alpine");
    let mut out = Vec::new();
    for &(_, package, sha256, file, name) in ALPINE_PACKAGES.iter().filter(|p| p.0 == isa) {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let apk = dir.join(format!("{package}-{isa}.apk"));
        if !apk.exists() {
            println!("== fetching Alpine's {package} ({isa})");
            let url = format!("{ALPINE}/{isa}/{package}.apk");
            run(Command::new("curl").args(["-sSfL", "-o"]).arg(&apk).arg(&url))?;
        }
        let bytes = std::fs::read(&apk).map_err(|e| format!("reading {}: {e}", apk.display()))?;
        let hash: String = superior_objects::crypto::sha2::sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if hash != sha256 {
            return Err(format!("{} is not Alpine's {package}: delete it to fetch it again", apk.display()));
        }
        // An apk is gzipped tar segments one after another.
        let to = dir.join(isa);
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        run(Command::new("tar").arg("-xzf").arg(&apk).arg("-C").arg(&to).arg(file))?;
        let path = to.join(file);
        out.push((name.to_string(), std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?));
    }
    Ok(out)
}

/// The toolchain the Linux personality runs: tcc (Alpine 3.22's, the first
/// with it, in community), which compiles, assembles and links C, and
/// make, with musl's headers and start files, and GNU binutils' as and ld
/// with their libraries and zstd's (Alpine 3.18's, as its musl).
/// (Alpine's repository, package, its SHA-256, and the files taken: to a
/// bundle file of the name given, or, for a name starting with `/`, into
/// the toolchain's archive at that path.)
type ToolPackage = (&'static str, &'static str, &'static str, &'static [(&'static str, &'static str)]);
const TOOLCHAIN_X86_64: [ToolPackage; 14] = [
    ("v3.22/community", "tcc-0.9.27_git20250106-r0", "db4720f2f9c6c5cf46812d52af151cbeaa95c0e4676aa956b3e57b2c3ad9802a", &[("usr/bin/tcc", "tcc")]),
    ("v3.22/community", "tcc-libs-0.9.27_git20250106-r0", "f0d06346af0ffd0d4bca073d56b51e6baaa2825b82996a58ddf6a31dba5df2d0", &[("usr/lib/libtcc.so", "libtcc")]),
    ("v3.22/community", "tcc-libs-static-0.9.27_git20250106-r0", "2aab7f70b8f8918ebe431f9b77193a6f43b72c9206b0e5c7b35fe3975e64f3a9", TCC_RUNTIME),
    ("v3.22/community", "tcc-dev-0.9.27_git20250106-r0", "5bd123d6b22a9e39c5e26a79759573c47243dd1d04bcdc26ce8275ca35fd91f7", TCC_HEADERS),
    ("v3.18/main", "make-4.4.1-r1", "139e1d308ed231bd6c3b35db9c8bee88f732609817524663dfeb7ecc3d7445c8", &[("usr/bin/make", "make")]),
    ("v3.18/main", "musl-dev-1.2.4-r3", "d288f1cae4a503826df1ecff8d4c3818b8c765d3e4c63d397fddd3b52de3c17b", MUSL_DEV),
    ("v3.18/main", "binutils-2.40-r8", "d8260a11280e85306f51a2642c996feeb13356a2226e74e3b76218212a512415", BINUTILS_X86_64),
    ("v3.18/main", "zstd-libs-1.5.5-r4", "79c0aa9461b1cdd238f17e24cc00916c282df2b6ba060f339993b277b4258016", ZSTD),
    ("v3.18/main", "gcc-12.2.1_git20220924-r10", "ff9dc5bf2b8d80cc560c49ce3156d31e88eed94517781ee5e1b30c5ee7db7ea2", GCC_X86_64),
    ("v3.18/main", "libgcc-12.2.1_git20220924-r10", "51c4130bac12e199ad216f0395d09f8ee3086ec143daf2efb142f63bd23c5158", LIBGCC),
    ("v3.18/main", "gmp-6.2.1-r3", "b81925ecab46d1737c3ee8cbe18b8a89f4ec075f82dcd761ec572cd0e9609b5c", GMP),
    ("v3.18/main", "mpfr4-4.2.0_p12-r0", "f06c43c2352b35510625b4b624b85eccd8e07bb1c6d93d37681c3b1fc821f061", MPFR),
    ("v3.18/main", "mpc1-1.3.1-r1", "34d68badb2d45d16221c5e5029133d100a9a66b3899e334a11e19e50d3925685", MPC),
    ("v3.18/main", "isl26-0.26-r1", "25847e5374469cc46dc419904c10ccd87e4f59fa879fb50ddba37651c201bfcc", ISL),
];
const TOOLCHAIN_AARCH64: [ToolPackage; 14] = [
    ("v3.22/community", "tcc-0.9.27_git20250106-r0", "556e5a32cb2b7270c0007039143a905160b7dbadd3deca7e3710c760623a50dc", &[("usr/bin/tcc", "tcc")]),
    ("v3.22/community", "tcc-libs-0.9.27_git20250106-r0", "93e9707704d398f88c2292d115db22f5a10a98d87e0fbf466940e06ca4a386fb", &[("usr/lib/libtcc.so", "libtcc")]),
    ("v3.22/community", "tcc-libs-static-0.9.27_git20250106-r0", "5dc97008751c0770cad9ad94c29cc5bf2a19e555fd37313b3eb256aabe973245", TCC_RUNTIME),
    ("v3.22/community", "tcc-dev-0.9.27_git20250106-r0", "b51ebbadc4f91f1c102f183bad9b60aac3d26bf22f22e66ce2b3e68f72c516de", TCC_HEADERS),
    ("v3.18/main", "make-4.4.1-r1", "e38ee3a4189d098a3b35b937670fb2e5a2e0e1712c5c74924cc474aaeaf44977", &[("usr/bin/make", "make")]),
    ("v3.18/main", "musl-dev-1.2.4-r3", "2965901b73567405ce95f396884b8e01558dc0ab4232b6d68e5a87f2c84e046c", MUSL_DEV),
    ("v3.18/main", "binutils-2.40-r8", "0e2be25ca7b7595b08ca1804ec63dcbb7173994974203fb2c68cb6a540f371d8", BINUTILS_AARCH64),
    ("v3.18/main", "zstd-libs-1.5.5-r4", "e803a78407cb28168b681741753ddf2496cbd0b6d91e0c9aeb143aa48a5a46ff", ZSTD),
    ("v3.18/main", "gcc-12.2.1_git20220924-r10", "b97ab04fde94dae04a9f6801148d3649ad497f4ee12a94af341e06dd41942d06", GCC_AARCH64),
    ("v3.18/main", "libgcc-12.2.1_git20220924-r10", "45907c59e25a6698019f9f39d3f4d61b7a5e11a7c41fcd3a7fa5a3a430e2a692", LIBGCC),
    ("v3.18/main", "gmp-6.2.1-r3", "13f042e07fe32b5487111d6dec4289f6e745cc950a6d64232be679f2435b715d", GMP),
    ("v3.18/main", "mpfr4-4.2.0_p12-r0", "2dd2a525c899871cfca477b982d35d33d09833a06c893a67719d133e62a872eb", MPFR),
    ("v3.18/main", "mpc1-1.3.1-r1", "5569656bc1cde66a32a437e488bb4f56faeaa2151ef2bf354858fa347f6d9c16", MPC),
    ("v3.18/main", "isl26-0.26-r1", "d0832299b2008052681471e7c907e357556fb752c365252a727cfd879c791076", ISL),
];
/// gcc: the driver (its own name on AArch64, `gcc` a link to it), cc1,
/// collect2 and libgcc.a as bundle files; its start files, headers and
/// libgcc_s's link script into the archive.
const GCC_X86_64: &[(&str, &str)] = &[
    ("usr/bin/gcc", "gcc"),
    ("usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/cc1", "cc1"),
    ("usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/collect2", "collect2"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/libgcc.a", "libgcc-a"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/crtbeginS.o", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/crtbeginS.o"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/crtendS.o", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/crtendS.o"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stddef.h", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stddef.h"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stdarg.h", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stdarg.h"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stdbool.h", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/stdbool.h"),
    ("usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/float.h", "/usr/lib/gcc/x86_64-alpine-linux-musl/12.2.1/include/float.h"),
    ("usr/lib/libgcc_s.so", "/usr/lib/libgcc_s.so"),
    // The linker plugin the driver asks ld to load (for LTO objects).
    ("usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/liblto_plugin.so", "/usr/libexec/gcc/x86_64-alpine-linux-musl/12.2.1/liblto_plugin.so"),
];
const GCC_AARCH64: &[(&str, &str)] = &[
    ("usr/bin/aarch64-alpine-linux-musl-gcc", "gcc"),
    ("usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/cc1", "cc1"),
    ("usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/collect2", "collect2"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/libgcc.a", "libgcc-a"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/crtbeginS.o", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/crtbeginS.o"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/crtendS.o", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/crtendS.o"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stddef.h", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stddef.h"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stdarg.h", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stdarg.h"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stdbool.h", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/stdbool.h"),
    ("usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/float.h", "/usr/lib/gcc/aarch64-alpine-linux-musl/12.2.1/include/float.h"),
    ("usr/lib/libgcc_s.so", "/usr/lib/libgcc_s.so"),
    // The linker plugin the driver asks ld to load (for LTO objects).
    ("usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/liblto_plugin.so", "/usr/libexec/gcc/aarch64-alpine-linux-musl/12.2.1/liblto_plugin.so"),
];
const LIBGCC: &[(&str, &str)] = &[("usr/lib/libgcc_s.so.1", "libgcc-s")];
const GMP: &[(&str, &str)] = &[("usr/lib/libgmp.so.10.4.1", "libgmp")];
const MPFR: &[(&str, &str)] = &[("usr/lib/libmpfr.so.6.2.0", "libmpfr")];
const MPC: &[(&str, &str)] = &[("usr/lib/libmpc.so.3.3.1", "libmpc")];
const ISL: &[(&str, &str)] = &[("usr/lib/libisl.so.23.3.0", "libisl")];
/// as and ld and the libraries they load. Each package has as and ld
/// once, the other names hard links to them: in `/usr/bin` on x86-64, in
/// the target's own directory on AArch64.
const BINUTILS_X86_64: &[(&str, &str)] = &[
    ("usr/bin/as", "as"),
    ("usr/bin/ld", "ld"),
    ("usr/lib/libbfd-2.40.so", "libbfd"),
    ("usr/lib/libopcodes-2.40.so", "libopcodes"),
    ("usr/lib/libctf.so.0.0.0", "libctf"),
    ("usr/lib/libsframe.so.0.0.0", "libsframe"),
];
const BINUTILS_AARCH64: &[(&str, &str)] = &[
    ("usr/aarch64-alpine-linux-musl/bin/as", "as"),
    ("usr/aarch64-alpine-linux-musl/bin/ld", "ld"),
    ("usr/lib/libbfd-2.40.so", "libbfd"),
    ("usr/lib/libopcodes-2.40.so", "libopcodes"),
    ("usr/lib/libctf.so.0.0.0", "libctf"),
    ("usr/lib/libsframe.so.0.0.0", "libsframe"),
];
const ZSTD: &[(&str, &str)] = &[("usr/lib/libzstd.so.1.5.5", "libzstd")];
const TCC_RUNTIME: &[(&str, &str)] = &[("usr/lib/tcc/libtcc1.a", "/usr/lib/tcc/libtcc1.a")];
const TCC_HEADERS: &[(&str, &str)] = &[
    ("usr/lib/tcc/include/stdarg.h", "/usr/lib/tcc/include/stdarg.h"),
    ("usr/lib/tcc/include/stddef.h", "/usr/lib/tcc/include/stddef.h"),
    ("usr/lib/tcc/include/stdbool.h", "/usr/lib/tcc/include/stdbool.h"),
    ("usr/lib/tcc/include/float.h", "/usr/lib/tcc/include/float.h"),
    ("usr/lib/tcc/include/tccdefs.h", "/usr/lib/tcc/include/tccdefs.h"),
];
/// Enough of musl's headers for `stdio.h`, and its start files.
const MUSL_DEV: &[(&str, &str)] = &[
    ("usr/include/stdio.h", "/usr/include/stdio.h"),
    ("usr/include/features.h", "/usr/include/features.h"),
    ("usr/include/bits/alltypes.h", "/usr/include/bits/alltypes.h"),
    ("usr/lib/crt1.o", "/usr/lib/crt1.o"),
    ("usr/lib/Scrt1.o", "/usr/lib/Scrt1.o"),
    ("usr/lib/libssp_nonshared.a", "/usr/lib/libssp_nonshared.a"),
    ("usr/lib/crti.o", "/usr/lib/crti.o"),
    ("usr/lib/crtn.o", "/usr/lib/crtn.o"),
];

/// The toolchain's bundle files: tcc, its library, make, and `tools`, an
/// archive (ustar) of the rest, with `/usr/lib/libc.so` linked to musl's
/// dynamic linker (its C library) as Alpine has it. Each package
/// downloaded once and checked against its pinned hash every time.
fn toolchain_files(arch: Arch) -> Result<Vec<(String, Vec<u8>)>, String> {
    let (isa, packages) = match arch {
        Arch::X86_64 => ("x86_64", &TOOLCHAIN_X86_64),
        Arch::Aarch64 => ("aarch64", &TOOLCHAIN_AARCH64),
    };
    let dir = root().join("target/linux/alpine");
    let mut out = Vec::new();
    let mut archive = Vec::new();
    for &(repo, package, sha256, files) in packages {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let apk = dir.join(format!("{package}-{isa}.apk"));
        if !apk.exists() {
            println!("== fetching Alpine's {package} ({isa})");
            let url = format!("https://dl-cdn.alpinelinux.org/alpine/{repo}/{isa}/{package}.apk");
            run(Command::new("curl").args(["-sSfL", "-o"]).arg(&apk).arg(&url))?;
        }
        let bytes = std::fs::read(&apk).map_err(|e| format!("reading {}: {e}", apk.display()))?;
        let hash: String = superior_objects::crypto::sha2::sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if hash != sha256 {
            return Err(format!("{} is not Alpine's {package}: delete it to fetch it again", apk.display()));
        }
        let to = dir.join(isa).join(package);
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        let mut tar = Command::new("tar");
        tar.arg("-xzf").arg(&apk).arg("-C").arg(&to);
        files.iter().for_each(|(file, _)| _ = tar.arg(file));
        run(&mut tar)?;
        for (file, name) in files {
            let path = to.join(file);
            let data = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            match name.strip_prefix('/') {
                Some(at) => ustar_entry(&mut archive, at, &data, None)?,
                None => out.push((name.to_string(), data)),
            }
        }
    }
    ustar_entry(&mut archive, "usr/lib/libc.so", &[], Some(&format!("/lib/ld-musl-{isa}.so.1")))?;
    archive.extend([0u8; 1024]);
    out.push(("tools".to_string(), archive));
    Ok(out)
}

/// Appends a ustar entry to `archive`: a file holding `data`, or a
/// symbolic link to `link`.
fn ustar_entry(archive: &mut Vec<u8>, name: &str, data: &[u8], link: Option<&str>) -> Result<(), String> {
    let mut h = [0u8; 512];
    let mut put = |at: usize, s: &[u8]| h[at..at + s.len()].copy_from_slice(s);
    if name.len() >= 100 || link.is_some_and(|l| l.len() >= 100) {
        return Err(format!("{name}: too long a name for the toolchain's archive"));
    }
    put(0, name.as_bytes());
    put(100, b"0000755\0");
    put(108, b"0000000\0");
    put(116, b"0000000\0");
    put(124, format!("{:011o}\0", data.len()).as_bytes());
    put(136, b"00000000000\0");
    put(148, b"        ");
    put(156, if link.is_some() { b"2" } else { b"0" });
    put(157, link.unwrap_or("").as_bytes());
    put(257, b"ustar\x0000");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    archive.extend(h);
    archive.extend(data);
    archive.resize(archive.len().next_multiple_of(512), 0);
    Ok(())
}

/// Where the Linux personality's glibc programs come from: Debian 12
/// (bookworm), from the snapshot archive, so the URLs stay.
const DEBIAN: &str = "https://snapshot.debian.org/archive/debian/20261115T000000Z/pool/main";

/// Debian's packages, for each ISA: (Debian's name for the ISA, package's
/// path in the pool, its SHA-256, and the files taken from it with their
/// names in the bundle). glibc 2.36's dynamic linker and C library, and
/// GNU hello, linked against them alone.
type DebianPackage = (&'static str, &'static str, &'static str, &'static [(&'static str, &'static str)]);
const DEBIAN_PACKAGES: [DebianPackage; 4] = [
    (
        "amd64",
        "g/glibc/libc6_2.36-9+deb12u14",
        "ba4f88f73dbc3ae9055f3c20f4523bfdbaf1ad13ff95e258924f77d20b4fbedf",
        &[("./lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "ld-glibc"), ("./lib/x86_64-linux-gnu/libc.so.6", "libc")],
    ),
    ("amd64", "h/hello/hello_2.10-3", "2e6e2f1a0007dc43bc91c273fd36e91e40a4f1c2765a03eca68b70a42103878a", &[("./usr/bin/hello", "hello")]),
    (
        "arm64",
        "g/glibc/libc6_2.36-9+deb12u14",
        "01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4",
        &[("./lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", "ld-glibc"), ("./lib/aarch64-linux-gnu/libc.so.6", "libc")],
    ),
    ("arm64", "h/hello/hello_2.10-3", "f7b20d304db0f3a18da28eb2000de2b0205eaa340c1d0fecec3b7c50acc932dc", &[("./usr/bin/hello", "hello")]),
];

/// glibc's dynamic linker and C library and GNU hello, as Debian builds
/// them for `arch`, unmodified, with their names in the bundle: each
/// package downloaded once and checked against its pinned hash every time.
fn debian_files(arch: Arch) -> Result<Vec<(String, Vec<u8>)>, String> {
    let isa = if arch == Arch::X86_64 { "amd64" } else { "arm64" };
    let dir = root().join("target/linux/debian");
    let mut out = Vec::new();
    for &(_, path, sha256, files) in DEBIAN_PACKAGES.iter().filter(|p| p.0 == isa) {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let package = path.rsplit('/').next().unwrap();
        let deb = dir.join(format!("{package}_{isa}.deb"));
        if !deb.exists() {
            println!("== fetching Debian's {package} ({isa})");
            let url = format!("{DEBIAN}/{path}_{isa}.deb");
            run(Command::new("curl").args(["-sSfL", "-o"]).arg(&deb).arg(&url))?;
        }
        let bytes = std::fs::read(&deb).map_err(|e| format!("reading {}: {e}", deb.display()))?;
        let hash: String = superior_objects::crypto::sha2::sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if hash != sha256 {
            return Err(format!("{} is not Debian's {package}: delete it to fetch it again", deb.display()));
        }
        // A .deb is an ar archive; the files are in its data.tar.xz.
        let data = ar_member(&bytes, "data.tar.xz").ok_or_else(|| format!("{} has no data.tar.xz", deb.display()))?;
        let to = dir.join(isa).join(package);
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        let tar = to.join("data.tar.xz");
        std::fs::write(&tar, data).map_err(|e| format!("writing {}: {e}", tar.display()))?;
        let mut cmd = Command::new("tar");
        cmd.arg("-xJf").arg(&tar).arg("-C").arg(&to);
        for (file, _) in files {
            cmd.arg(file);
        }
        run(&mut cmd)?;
        for (file, name) in files {
            let path = to.join(file);
            out.push((name.to_string(), std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?));
        }
    }
    Ok(out)
}

/// The member of a Unix ar archive named `name`.
fn ar_member<'a>(ar: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let mut at = ar.strip_prefix(b"!<arch>\n".as_slice()).map(|_| 8)?;
    while at + 60 <= ar.len() {
        let header = &ar[at..at + 60];
        let size: usize = std::str::from_utf8(&header[48..58]).ok()?.trim().parse().ok()?;
        let member = std::str::from_utf8(&header[..16]).ok()?.trim_end().trim_end_matches('/');
        let body = ar.get(at + 60..at + 60 + size)?;
        if member == name {
            return Some(body);
        }
        at += 60 + size + size % 2;
    }
    None
}

/// What the Linux test types into the shell on the terminal, after the
/// batch runs: each step's bytes, what must then appear, and whether the
/// prompt must come back after it.
const LINUX_SESSION: &[(&str, &str, bool)] = &[
    ("", "", true),
    ("echo $((6 * 7))\n", "\n42", true),
    ("[ -t 0 ] && echo stdin is a terminal\n", "\nstdin is a terminal", true),
    ("stty size\n", "\n24 80", true),
    ("trap 'echo caught USR1' USR1; kill -USR1 $$\n", "\ncaught USR1", true),
    // A foreground job interrupted from the keyboard: ^C sends SIGINT to
    // its process group, and the shell reports 128 + 2.
    ("sh -c 'echo started; sleep 100'\n", "\nstarted", false),
    ("\x03", "", true),
    ("echo status $?\n", "\nstatus 130", true),
    // Job control. ^Z stops the foreground job (SIGTSTP to its group:
    // the shell and the sleep it waits for); fg continues it.
    ("sh -c 'echo one; sleep 2; echo two'\n", "\none", false),
    ("\x1a", "Stopped", true),
    ("jobs\n", "Stopped", true),
    ("fg\n", "\ntwo", true),
    // bg continues it in the background, and wait waits for it.
    ("sh -c 'echo started; sleep 2; echo in the background'\n", "\nstarted", false),
    ("\x1a", "Stopped", true),
    ("bg; wait; echo waited\n", "\nwaited", true),
    // A background job reading the terminal is stopped (SIGTTIN), and
    // reads once brought to the foreground. (A moment first: the job may
    // still be starting on the other CPU.)
    ("sh -c 'read x; echo read $x' &\n", "", true),
    ("sleep 1; jobs\n", "Stopped", true),
    ("fg\n", "read x;", false),
    ("hello\n", "\nread hello", true),
    // A job stopped while running in user space (suspended where it
    // was), then ended by SIGKILL while stopped: the shell reports the
    // job so ended.
    ("sh -c 'echo spinning; while :; do :; done'\n", "\nspinning", false),
    ("\x1a", "Stopped", true),
    ("kill -9 %1\n", "", true),
    ("jobs\n", "Killed", true),
    ("exit\n", "", false),
];
const LINUX_PROMPT: &str = "linux$ ";

/// Boots `img` and types `script` into the Linux personality's terminal
/// (see [`LINUX_SESSION`]); all the output once QEMU exits with the pass
/// code.
fn drive_linux(img: &Image, script: &[(&str, &str, bool)]) -> Result<String, String> {
    let mut child = qemu_command(img)
        .args(["-display", "none"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu(img.arch).display()))?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = std::io::stdout().write_all(&buf[..n]);
            let _ = std::io::stdout().flush();
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    // The batch runs come first: the first prompt may take a while.
    let expect = |want: &str, from: usize| -> Result<usize, String> {
        let deadline = Instant::now() + scaled(Duration::from_secs(120));
        loop {
            {
                let out = seen.lock().unwrap();
                let text = String::from_utf8_lossy(&out[from.min(out.len())..]).into_owned();
                if let Some(i) = text.find(want) {
                    return Ok(from + text[..i].len() + want.len());
                }
            }
            if Instant::now() > deadline {
                return Err(format!("Linux session: timed out waiting for {want:?}"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let mut at = 0;
    let mut result = Ok(());
    for (typed, want, prompt) in script {
        // A byte at a time, as from a keyboard.
        for b in typed.bytes() {
            stdin.write_all(&[b]).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(5));
        }
        let step = expect(want, at).and_then(|p| if *prompt { expect(LINUX_PROMPT, p) } else { Ok(p) });
        match step {
            Ok(p) => at = p,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    let deadline = Instant::now() + scaled(Duration::from_secs(60));
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if Instant::now() > deadline || result.is_err() {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    println!();
    result?;
    let out = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    match status.and_then(|s| s.code()) {
        Some(QEMU_PASS) => Ok(out),
        code => Err(format!("QEMU did not exit with the pass code (exit {code:?})")),
    }
}

/// Boots `boot/linux.manifest`: the Linux personality runs Alpine's
/// programs, unmodified and dynamically linked against musl. BusyBox
/// first, a run at a time: commands, shell scripts with processes, pipes
/// and files, signals; pigz, compressing with threads; files under `/`
/// and `/home`, on the filesystem server; then the shell on the terminal,
/// typed into ([`LINUX_SESSION`]). Then `boot/linux-verify.manifest` on
/// the same disk reads back what the first boot left under `/home`.
fn linux_test(img: &Image) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    println!("== Linux personality test on {}", img.path.display());
    let disk = linux_disk();
    std::fs::write(&disk, vec![0u8; 16 << 20]).map_err(|e| format!("writing {}: {e}", disk.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let (servers, served) = linux_net_servers(stop.clone())?;
    let out = drive_linux(img, LINUX_SESSION);
    stop.store(true, Ordering::Relaxed);
    servers.into_iter().for_each(|s| _ = s.join());
    let out = out?;
    if !served.lock().unwrap().contains("served from Linux") {
        return Err("Linux personality test: the connection to the guest's nc was not served".into());
    }
    let isa = if img.arch == Arch::X86_64 { "x86_64" } else { "aarch64" };
    let interp = format!("interpreter /lib/ld-musl-{isa}.so.1)");
    let machine = format!("linux: > Linux {isa}");
    let steps = [
        "linux: the root is on the filesystem server, /bin, /usr, /lib, /dev and /tmp in memory over it",
        "linux: running busybox echo hello from Linux (",
        &interp,
        "linux: > hello from Linux",
        "linux: busybox echo hello from Linux exited with status 0",
        "linux: running busybox uname -sm (",
        &machine,
        "linux: busybox uname -sm exited with status 0",
        "linux: > 42 from the shell",
        "linux: busybox sh -c echo $((6 * 7)) from the shell; exit 3 exited with status 3",
        "linux: > pi is 3.141593",
        "linux: busybox awk BEGIN { printf \"pi is %.6f\\n\", atan2(0, -1) } exited with status 0",
        // Processes: fork, execve, wait4 and the status passed on.
        "linux: > false said 1",
        "linux: > true said 0",
        // Pipelines: children joined by pipes.
        "linux: > 1000",
        "linux: sh -c seq 1 1000 | wc -l exited with status 0",
        "linux: > 5 4 3 2 1",
        // Files: redirections, directories, copies, renames, removal.
        "linux: > first line",
        "linux: > second line",
        "linux: sh -c mkdir -p /tmp/notes && echo first line > /tmp/notes/a && echo second line >> /tmp/notes/a && cat /tmp/notes/a exited with status 0",
        "linux: > a",
        "linux: > c",
        "linux: > 23",
        "linux: > c",
        "linux: sh -c cd /tmp/notes && cp a b && mv b c && ls && wc -c < c && rm a && ls exited with status 0",
        // A later run sees what the earlier ones left.
        "linux: running cat /tmp/notes/c (pid ",
        "linux: > first line",
        "linux: > second line",
        "linux: cat /tmp/notes/c exited with status 0",
        "linux: > cat said 1",
        // Signals.
        "linux: > trapped USR1",
        "linux: > after the trap",
        "linux: > status after kill 143",
        "linux: sh -c yes | head -n 3 | wc -l exited with status 0",
        "linux: > slept",
        "linux: > fp registers kept across a handler",
        "linux: > fptest said 0",
        "linux: > two threads ran at once",
        "linux: > smptest said 0",
        "linux: > mapped and unmapped 25 MiB",
        "linux: > mmaptest said 0",
        // glibc's dynamic linker and C library, Debian's, in GNU hello.
        "linux: > Hello, world!",
        "linux: > hello said 0",
        // tcc, driven by make, compiling, assembling and linking a C
        // program against musl, and the program it made running.
        "linux: > tcc -o hi hi.c",
        "linux: > built by tcc: 42",
        // GNU as and ld, with tcc: their program running.
        "linux: > assembled by as, linked by ld",
        // gcc: driver, cc1, as, collect2 and ld, and its program running.
        "linux: > compiled by gcc: 42",
        // vfork: what the child wrote in the memory it borrowed.
        "linux: > vfork shared: 42",
        // A program far larger than a page, loaded from its file.
        "linux: > ran a program of more than 200000 bytes",
        // Threads (clone, futexes) in pigz, and zlib loaded by musl: what
        // two threads compressed BusyBox's gzip takes back unchanged.
        " started thread ",
        " started thread ",
        "linux: > n.gz",
        "linux: > 72d4ff27a28afbc066d5804999d5a504  -",
        "linux: > 72d4ff27a28afbc066d5804999d5a504  -",
        "gzip -dc /tmp/n.gz | md5sum && md5sum < /tmp/n exited with status 0",
        // Files under /home, on the filesystem server.
        "linux: > link",
        "linux: > n.gz",
        "linux: > new",
        "linux: > note",
        "linux: > /home/docs",
        "linux: > first",
        "linux: > second",
        "&& mv old new && ls && pwd && cat link exited with status 0",
        "linux: > 1",
        "echo boot >> /home/boots; wc -l < /home/boots exited with status 0",
        // The root: the server's, with this tree's own laid over it.
        "linux: > bin",
        "linux: > data",
        "linux: > dev",
        "linux: > etc",
        "linux: > home",
        "linux: > lib",
        "linux: > tmp",
        "linux: > usr",
        "&& echo 42 > /data/answer && ls / exited with status 0",
        // Sockets over the network server: a page fetched from the host,
        // TCP and UDP echoed by it, and its connection in served.
        "linux: > hello over HTTP",
        "wget -q -O - http://10.0.3.2:47081/hello exited with status 0",
        "linux: > echoed over TCP",
        "nc 10.0.3.2 47002 exited with status 0",
        "linux: > echoed over UDP",
        "nc -u -w 2 10.0.3.2 47001 exited with status 0",
        "linux: nc -l -p 8080 -e echo served from Linux exited with status 0",
        // Ping sockets, and IPv6.
        "linux: > 1 packets transmitted, 1 packets received, 0% packet loss",
        "linux: ping -c 1 10.0.3.2 exited with status 0",
        "linux: > 64 bytes from fd00:3::2: seq=0",
        "linux: > 1 packets transmitted, 1 packets received, 0% packet loss",
        "linux: ping6 -c 1 fd00:3::2 exited with status 0",
        "linux: > hello over HTTP and IPv6",
        "wget -q -O - http://[fd00:3::2]:47081/hello6 exited with status 0",
        "linux: > echoed over TCP and IPv6",
        "nc fd00:3::2 47002 exited with status 0",
        "linux: > echoed over UDP and IPv6",
        "nc -u -w 2 fd00:3::2 47001 exited with status 0",
        // The terminal session (its steps were checked as it ran).
        "linux: running sh (pid ",
        "linux: sh exited with status 0",
        "[cm] linux asked to shut down (pass)",
    ];
    if let Err(step) = find_in_order(&out, &steps) {
        return Err(format!("Linux personality test: missing (in order) {step:?}"));
    }
    let cpus = format!("linux: > cpus {}", cpus());
    if !out.contains(&cpus) {
        return Err(format!("Linux personality test: missing {cpus:?}"));
    }
    // On x86-64 the CPU has AVX: its state is in the frame too.
    let ymm = "linux: > ymm registers kept across a handler";
    if img.arch == Arch::X86_64 && !out.contains(ymm) {
        return Err(format!("Linux personality test: missing {ymm:?}"));
    }
    for bad in ["[fail]", "could not", "panic", "[fault]", "not implemented", "killed"] {
        if out.contains(bad) {
            return Err(format!("Linux personality test: log contains {bad:?}"));
        }
    }
    // The second boot, on the same disk: what the first left on it.
    let verify = image_with(false, img.arch, "linux-verify")?;
    println!("== Linux personality test, second boot: {}", verify.path.display());
    let out = run_to_exit(&verify, Duration::from_secs(300))?;
    let steps = [
        "linux: the root is on the filesystem server, /bin, /usr, /lib, /dev and /tmp in memory over it",
        "linux: > 2",
        "echo boot >> /home/boots; wc -l < /home/boots exited with status 0",
        "linux: > link",
        "linux: > n.gz",
        "linux: > new",
        "linux: > note",
        "linux: > first",
        "linux: > second",
        "linux: > note",
        "linux: > 72d4ff27a28afbc066d5804999d5a504  -",
        "linux: > boots",
        "&& rm -r /home/docs && ls /home exited with status 0",
        "linux: > hello from the disk",
        "linux: > 42",
        "linux: > bin",
        "linux: > data",
        "linux: > dev",
        "linux: > etc",
        "linux: > home",
        "linux: > lib",
        "linux: > tmp",
        "linux: > usr",
        "linux: > bin",
        "linux: > dev",
        "linux: > home",
        "linux: > lib",
        "linux: > tmp",
        "linux: > usr",
        "cat /etc/motd /data/answer && ls / && rm -r /data /etc && ls / exited with status 0",
        "[cm] linux asked to shut down (pass)",
    ];
    check_log("Linux personality test (second boot)", &out, &steps)?;
    for bad in ["[fault]", "not implemented", "killed"] {
        if out.contains(bad) {
            return Err(format!("Linux personality test (second boot): log contains {bad:?}"));
        }
    }
    println!("== Linux personality test passed ({})", img.arch.name());
    Ok(())
}

/// The port the Linux personality test's guest fetches a page over HTTP
/// from (on the gateway, which QEMU passes to the host's loopback).
const LINUX_HTTP_PORT: u16 = 47081;

/// The host's side of the Linux personality's sockets, until `stop`: a
/// page over HTTP, the TCP and UDP echoes, and a client that connects in
/// (through QEMU's forwarding to the guest's port 8080) until it is
/// answered; what it was answered with.
fn linux_net_servers(
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(Vec<std::thread::JoinHandle<()>>, Arc<Mutex<String>>), String> {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut threads = vec![tcp_echo_server(stop.clone(), Arc::new(AtomicU64::new(0)))?];
    // IPv4 and IPv6 (QEMU passes the guest's to fd00:3::2 to ::1).
    let mut https = Vec::new();
    for host in ["127.0.0.1", "::1"] {
        let udp = UdpSocket::bind((host, ECHO_PORT)).map_err(|e| format!("binding the echo port {ECHO_PORT} on {host}: {e}"))?;
        udp.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
        let s = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !s.load(Ordering::Relaxed) {
                if let Ok((n, from)) = udp.recv_from(&mut buf) {
                    let _ = udp.send_to(&buf[..n], from);
                }
            }
        }));
        let http = TcpListener::bind((host, LINUX_HTTP_PORT))
            .map_err(|e| format!("binding the HTTP port {LINUX_HTTP_PORT} on {host}: {e}"))?;
        http.set_nonblocking(true).map_err(|e| e.to_string())?;
        https.push(http);
    }
    let s = stop.clone();
    threads.push(std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            let Some((mut c, _)) = https.iter().find_map(|h| h.accept().ok()) else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            let _ = c.set_nonblocking(false);
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(n) if n > 0 => req.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            let body = if req.starts_with(b"GET /hello ") {
                "hello over HTTP\n"
            } else if req.starts_with(b"GET /hello6 ") {
                "hello over HTTP and IPv6\n"
            } else {
                ""
            };
            let status = if body.is_empty() { "404 Not Found" } else { "200 OK" };
            let _ = write!(
                c,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    }));
    let served = Arc::new(Mutex::new(String::new()));
    let (s, got) = (stop.clone(), served.clone());
    threads.push(std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) && got.lock().unwrap().is_empty() {
            std::thread::sleep(Duration::from_millis(500));
            let Ok(mut c) = TcpStream::connect(("127.0.0.1", 47004)) else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let mut text = String::new();
            let _ = c.read_to_string(&mut text);
            if !text.is_empty() {
                println!("\n== the guest's nc answered: {text:?}");
                *got.lock().unwrap() = text;
            }
        }
    }));
    Ok((threads, served))
}

/// Linux's `driver` source, unmodified: downloaded once, and checked
/// against its pinned hash every time.
fn linux_source(driver: &str) -> Result<PathBuf, String> {
    let (_, in_tree, sha256) = *LINUX_SOURCES
        .iter()
        .find(|s| s.0 == driver)
        .ok_or_else(|| format!("no Linux source is known for {driver}"))?;
    let dir = root().join("target/lde").join(format!("linux-{}", &LINUX_TAG[1..]));
    let path = dir.join(format!("{driver}.c"));
    if !path.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let url = format!(
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{in_tree}?h={LINUX_TAG}"
        );
        println!("== fetching Linux's {in_tree} ({LINUX_TAG})");
        run(Command::new("curl").args(["-sSfL", "-o"]).arg(&path).arg(&url))?;
    }
    let hash = Command::new("certutil")
        .args(["-hashfile"])
        .arg(&path)
        .arg("SHA256")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .or_else(|| {
            let o = Command::new("sha256sum").arg(&path).output().ok()?;
            Some(String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .ok_or("could not hash a file (certutil or sha256sum)")?;
    if !hash.replace(' ', "").to_lowercase().contains(sha256) {
        return Err(format!(
            "{} is not Linux {LINUX_TAG}'s {in_tree}: delete it to fetch it again",
            path.display()
        ));
    }
    Ok(path)
}

/// Compiles Linux's `driver` (its source files) and the environment's C
/// half for `arch`, in the build container (clang, with only the
/// environment's headers), and points the component's build script at the
/// objects.
fn lde_objects(arch: Arch, driver: &str) -> Result<(), String> {
    let files = linux_files(driver);
    let sources = files.iter().map(|f| linux_source(f)).collect::<Result<Vec<_>, _>>()?;
    let out = root().join("target/lde").join(arch.name());
    let newest = |dir: PathBuf| -> Option<std::time::SystemTime> {
        let mut newest = None;
        let mut dirs = vec![dir];
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(d).ok()?.flatten() {
                if e.path().is_dir() {
                    dirs.push(e.path());
                } else {
                    newest = newest.max(e.metadata().ok()?.modified().ok());
                }
            }
        }
        newest
    };
    let built = files
        .iter()
        .map(|f| format!("{f}.o"))
        .chain(["lde", "lde-net", "lde-drm", "lde-snd"].map(|h| format!("{h}.o")))
        .map(|o| std::fs::metadata(out.join(o)).and_then(|m| m.modified()).ok())
        .min()
        .flatten();
    let changed = sources
        .iter()
        .map(|s| std::fs::metadata(s).and_then(|m| m.modified()).ok())
        .fold(newest(root().join("crates/lde")), Option::max);
    if built.is_none() || built < changed {
        println!("== compiling Linux's {driver} and the Linux Driver Environment ({})", arch.name());
        let rel = |p: &Path| {
            format!(
                "/work/{}",
                p.strip_prefix(root()).unwrap().to_string_lossy().replace('\\', "/")
            )
        };
        let mut args = vec!["sh".to_string(), "/work/crates/lde/cc.sh".into(), arch.name().into(), rel(&out)];
        // The module's name is its first file's, as Linux's Kbuild has it.
        args.push(files[0].into());
        args.extend(sources.iter().map(|s| rel(s)));
        docker(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    }
    // SAFETY: xtask has one thread here.
    unsafe { env::set_var("SUPERIOR_LDE_OBJECTS", &out) };
    Ok(())
}

/// Builds a user program as a static position-independent executable; the
/// kernel loads it into its user window and relocates it. User programs
/// build in their own target directory, since on AArch64 they need flags
/// the kernel must not get.
/// Linux programs of our own built as fixed-address executables.
const FIXED_ADDRESS: &[&str] = &["superior-linux-mmaptest"];

fn user_program(package: &str, arch: Arch) -> Result<PathBuf, String> {
    println!("== building {package} ({})", arch.name());
    let mut build = cargo();
    // The updater pins the update server's TLS key.
    build.env("SUPERIOR_UPDATE_KEY", update_key()?.1);
    // Loaders read only program headers: leave debug information out, so
    // the boot bundle stays small.
    build.env("CARGO_PROFILE_RELEASE_STRIP", "debuginfo");
    if FIXED_ADDRESS.contains(&package) {
        // Not position-independent: linked at 4 MiB, as Linux's linkers
        // place an executable.
        let var = match arch {
            Arch::X86_64 => "CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS",
            Arch::Aarch64 => "CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_RUSTFLAGS",
        };
        build.env(
            var,
            "-C relocation-model=static -C link-arg=--no-pie -C link-arg=--image-base=0x400000 -C link-arg=-zmax-page-size=4096",
        );
    } else if arch == Arch::Aarch64 {
        // x86_64-unknown-none is static-pie by default; this target is not.
        // Segments aligned to 4 KiB pages, not 64 KiB: the loader counts the
        // gaps against a component's image pages.
        build.env(
            "CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_RUSTFLAGS",
            "-C relocation-model=pie -C link-arg=-pie -C link-arg=--no-dynamic-linker -C link-arg=-zmax-page-size=4096",
        );
    }
    run(build.args([
        "build",
        "--quiet",
        "-p",
        package,
        "--release",
        "--target",
        arch.target(),
        "--target-dir",
        "target/user",
    ]))?;
    Ok(root()
        .join("target/user")
        .join(arch.target())
        .join("release")
        .join(package))
}

/// Packs `boot/<manifest>.manifest` and every component executable into a
/// boot bundle (format in `superior_objects::bundle`) and returns its path.
fn bundle(arch: Arch, manifest: &str, driver: &str) -> Result<PathBuf, String> {
    // Every Linux driver's test is lde.manifest, with its name in it.
    let file = if linux_nic(manifest).is_some() { "lde" } else { manifest };
    let mut text = std::fs::read(root().join("boot").join(format!("{file}.manifest")))
        .map_err(|e| format!("reading boot/{file}.manifest: {e}"))?;
    if let Some((linux, _)) = linux_nic(manifest) {
        text = String::from_utf8_lossy(&text)
            .replace("lde-8139cp", &format!("lde-{linux}"))
            .into_bytes();
    }
    if driver != "virtio-blk" {
        // The manifest names virtio-blk; the drivers test's client (role 4)
        // takes the role that knows this driver's device.
        let role = disk_driver(driver).2;
        let mut t = String::from_utf8_lossy(&text)
            .replace("\r\n", "\n")
            .replace("virtio-blk", driver);
        if manifest == "drivers" {
            assert_eq!(t.matches("  arg 4\n").count(), 1, "the drivers client");
            t = t.replace("  arg 4\n", &format!("  arg {role}\n"));
        }
        text = t.into_bytes();
    }
    let mut files = vec![("manifest".to_string(), text)];
    for (name, package) in [
        ("shell", "superior-shell"),
        ("echo", "superior-echo"),
        ("counter", "superior-counter"),
        ("pcibus", "superior-pcibus"),
        ("virtio-blk", "superior-virtio-blk"),
        ("virtio-gpu", "superior-virtio-gpu"),
        ("nvme", "superior-nvme"),
        ("ahci", "superior-ahci"),
        ("virtio-net", "superior-virtio-net"),
        ("net", "superior-net"),
        ("dns", "superior-dns"),
        ("xhci", "superior-xhci"),
        ("hid", "superior-hid"),
        ("memserver", "superior-memserver"),
        ("fs", "superior-fs"),
        ("testclient", "superior-testclient"),
        ("compositor", "superior-compositor"),
        ("greeter", "superior-greeter"),
        ("list", "superior-list"),
        ("notes", "superior-notes"),
        ("panel", "superior-panel"),
        ("mixer", "superior-mixer"),
        ("linux", "superior-linux"),
        // Need Linux's source and the build container: only where used.
        ("lde-8139cp", "superior-lde-8139cp"),
        ("lde-e100", "superior-lde-e100"),
        ("lde-bochs", "superior-lde-bochs"),
        ("lde-es1370", "superior-lde-es1370"),
    ] {
        if let Some(driver) = name.strip_prefix("lde-") {
            if linux_driver(manifest) != Some(driver) {
                continue;
            }
            lde_objects(arch, driver)?;
        }
        let path = user_program(package, arch)?;
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        files.push((name.to_string(), bytes));
    }
    // The Linux programs the personality runs (`file` in its manifest).
    if manifest.starts_with("linux") {
        files.extend(alpine_files(arch)?);
        files.extend(debian_files(arch)?);
        files.extend(toolchain_files(arch)?);
        // Linux programs of our own (the first boot's runs use them).
        for name in ["fptest", "smptest", "mmaptest"] {
            let package = format!("superior-linux-{name}");
            let path = user_program(&package, arch)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            // ET_EXEC (2), not ET_DYN, if it is to be fixed-address.
            let fixed = bytes.get(16..18) == Some(&[2, 0][..]);
            if fixed != FIXED_ADDRESS.contains(&package.as_str()) {
                return Err(format!("{package} is {}a fixed-address executable", if fixed { "" } else { "not " }));
            }
            files.push((name.to_string(), bytes));
        }
    }
    // Icon images (`icon NAME.pam` in a manifest), by their file names.
    let mut icons: Vec<_> = std::fs::read_dir(root().join("boot/icons"))
        .map_err(|e| format!("reading boot/icons: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    icons.sort();
    for path in icons {
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        files.push((path.file_name().unwrap().to_string_lossy().into_owned(), bytes));
    }
    // The key a system in the A/B slots must be signed with (the kernel
    // verifies this bundle; the Component Manager trusts what it holds).
    files.push(("trust.key".to_string(), signing_key()?.verifying_key().to_bytes().to_vec()));
    // The key app packages must be signed with (`superior_objects::package`).
    files.push((
        superior_objects::package::KEY_FILE.to_string(),
        publisher_key()?.verifying_key().to_bytes().to_vec(),
    ));
    let out = pack(&files);
    let path = root()
        .join("target")
        .join(format!("bundle-{}-{manifest}.bin", arch.name()));
    std::fs::write(&path, out).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Packs named files into a bundle (`superior_objects::bundle`).
fn pack(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SUPBNDL1");
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let mut offset = 16 + 40 * files.len();
    for (name, data) in files {
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        offset += data.len();
    }
    for (_, data) in files {
        out.extend_from_slice(data);
    }
    out
}

/// Appends the trailer (`superior_objects::bundle::Signed`): `version`
/// and `key`'s signature.
fn sign(mut bundle: Vec<u8>, version: u64, key: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer;
    bundle.extend_from_slice(superior_objects::bundle::SIG_MAGIC);
    bundle.extend_from_slice(&version.to_le_bytes());
    let signature = key.sign(&bundle).to_bytes();
    bundle.extend_from_slice(&signature);
    bundle
}

fn image(selftest: bool, arch: Arch) -> Result<Image, String> {
    image_with(selftest, arch, "shell")
}

/// Builds a bootable image. A self-test image runs the kernel's self-test
/// programs; any other boots the Component Manager with the bundle for
/// `boot/<manifest>.manifest`.
fn image_with(selftest: bool, arch: Arch, manifest: &str) -> Result<Image, String> {
    image_for(selftest, arch, manifest, "virtio-blk")
}

/// As [`image_with`], with `driver` in place of the manifest's disk driver
/// and the disk attached as its device.
fn image_for(
    selftest: bool,
    arch: Arch,
    manifest: &str,
    driver: &'static str,
) -> Result<Image, String> {
    image_sealed(selftest, arch, manifest, driver, Seal::Good)
}

/// The version every boot bundle is signed with, and the oldest a kernel
/// built here boots.
const BUNDLE_VERSION: u64 = 2;

/// How a boot bundle is signed: properly, or (for the verified boot test)
/// in one of the ways the kernel must refuse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seal {
    Good,
    /// Signed, then a byte of a component's image changed.
    Tampered,
    /// Signed with a key the kernel does not trust.
    OtherKey,
    /// No signature at all.
    Unsigned,
    /// Properly signed, but an older version than the kernel accepts.
    Old,
    /// Properly signed, one version newer than the kernel's oldest (the
    /// TPM test's update).
    Newer,
}

/// The development signing key: made from the OS's random source the
/// first time and kept in `target/keys` (never in the repository). A
/// release would be signed with a key kept off the build machine.
fn signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    dev_key("dev-signing.seed")
}

/// The development publisher key app packages are signed with, made like
/// [`signing_key`] in `target/keys` the first time.
fn publisher_key() -> Result<ed25519_dalek::SigningKey, String> {
    dev_key("dev-packages.seed")
}

/// A development key: its seed in `target/keys/<file>`, made from the
/// OS's random source the first time.
fn dev_key(file: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let path = root().join("target").join("keys").join(file);
    let seed: [u8; 32] = match std::fs::read(&path) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| format!("no random source: {e}"))?;
            std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(&path, seed).map_err(|e| format!("writing {}: {e}", path.display()))?;
            println!("== made a development key in {}", path.display());
            seed
        }
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// Signs the bundle at `path` (see `superior_objects::bundle`) as `seal`
/// says, writing the signed bundle beside it; returns its path and the
/// trusted public key's path.
fn seal_bundle(path: &Path, seal: Seal) -> Result<(PathBuf, PathBuf), String> {
    let key = signing_key()?;
    let public = root().join("target").join("keys").join("dev-signing.pub");
    std::fs::write(&public, key.verifying_key().to_bytes()).map_err(|e| e.to_string())?;
    let mut out = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let payload = out.len();
    if seal != Seal::Unsigned {
        let signer = if seal == Seal::OtherKey {
            ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32])
        } else {
            key
        };
        let version = match seal {
            Seal::Old => BUNDLE_VERSION - 1,
            Seal::Newer => BUNDLE_VERSION + 1,
            _ => BUNDLE_VERSION,
        };
        out = sign(out, version, &signer);
    }
    if seal == Seal::Tampered {
        // A byte in the middle of the last component's image.
        out[payload - 1000] ^= 0x40;
    }
    let signed = path.with_extension("signed");
    std::fs::write(&signed, &out).map_err(|e| format!("writing {}: {e}", signed.display()))?;
    Ok((signed, public))
}

fn image_sealed(
    selftest: bool,
    arch: Arch,
    manifest: &str,
    driver: &'static str,
    seal: Seal,
) -> Result<Image, String> {
    let user = user_program("superior-pingpong", arch)?;
    let shell = user_program("superior-shell", arch)?;
    let cm = user_program("superior-cm", arch)?;
    let (bundle, trust) = seal_bundle(&bundle(arch, manifest, driver)?, seal)?;
    println!(
        "== building kernel ({}{})",
        arch.name(),
        if selftest { ", selftest" } else { "" }
    );
    let mut build = cargo();
    build.env("SUPERIOR_USER_ELF", &user);
    build.env("SUPERIOR_SHELL_ELF", &shell);
    build.env("SUPERIOR_CM_ELF", &cm);
    build.env("SUPERIOR_BUNDLE", &bundle);
    build.env("SUPERIOR_TRUST_KEY", &trust);
    build.env("SUPERIOR_MIN_VERSION", BUNDLE_VERSION.to_string());
    build.args([
        "build",
        "--quiet",
        "-p",
        "superior-kernel",
        "--release",
        "--target",
        arch.target(),
    ]);
    if selftest {
        build.args(["--features", "selftest"]);
    }
    run(&mut build)?;

    let target = root().join("target");
    let kernel = target
        .join(arch.target())
        .join("release")
        .join("superior-kernel");
    let suffix = if selftest {
        "-selftest".to_string()
    } else if manifest == "shell" {
        String::new()
    } else {
        match driver {
            "virtio-blk" => format!("-{manifest}"),
            d => format!("-{manifest}-{d}"),
        }
    };
    let path = match arch {
        Arch::X86_64 => {
            let img = target.join(format!("superior{suffix}.img"));
            bootloader::BiosBoot::new(&kernel)
                .create_disk_image(&img)
                .map_err(|e| format!("creating disk image: {e}"))?;
            img
        }
        Arch::Aarch64 => {
            let elf = target.join(format!("superior-aarch64{suffix}.elf"));
            std::fs::copy(&kernel, &elf).map_err(|e| format!("copying kernel: {e}"))?;
            elf
        }
    };
    let fs = manifest.starts_with("fs");
    let disk = if matches!(manifest, "drivers" | "suspend") {
        Some(test_disk()?)
    } else if fs {
        Some(fs_disk())
    } else if manifest.starts_with("linux") {
        Some(linux_disk())
    } else if manifest == "ab" {
        Some(ab_disk(arch))
    } else if manifest == "update" {
        Some(update_disk(arch))
    } else if manifest == "packages" {
        Some(packages_disk(arch))
    } else {
        None
    };
    Ok(Image {
        path,
        arch,
        sel4: false,
        disk,
        writable: fs || matches!(manifest, "ab" | "update" | "packages" | "linux" | "linux-verify"),
        driver,
        net: matches!(manifest, "net" | "tcp" | "update" | "suspend" | "linux" | "linux-verify") || linux_nic(manifest).is_some(),
        linux_nic: linux_nic(manifest).map(|l| l.1),
        radio: manifest == "wifi",
        avx: manifest.starts_with("linux"),
        keyboard: matches!(manifest, "keyboard" | "input" | "windows" | "cursor" | "toolkit" | "panel" | "resize" | "widgets" | "notes"),
        xhci: false,
        mouse: matches!(manifest, "input" | "windows" | "cursor" | "toolkit" | "panel" | "resize" | "widgets" | "notes"),
        hotplug: manifest == "hotplug",
        monitor: manifest == "suspend",
        display: matches!(
            manifest,
            "display" | "desktop" | "input" | "windows" | "cursor" | "toolkit" | "panel" | "resize" | "widgets" | "notes"
        ),
        gpu: manifest == "cursor",
        audio: (manifest == "audio").then(|| audio_wav(arch)),
        uefi: false,
        acpi: false,
        el2: false,
        highmem: false,
        smp: None,
        vars: None,
        firmware: None,
    })
}

/// Runs `args` in the seL4 build container with the repository at /work,
/// building the container first if needed.
fn docker(args: &[&str]) -> Result<(), String> {
    let have = Command::new("docker")
        .args(["image", "inspect", "superior-sel4"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("could not run docker: {e}"))?;
    if !have.success() {
        println!("== building the seL4 build container");
        run(Command::new("docker")
            .args(["build", "-t", "superior-sel4"])
            .arg(root().join("sel4")))?;
    }
    run(Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work", root().display()))
        // Toolchains and crates survive between runs.
        .args(["-v", "superior-sel4-rustup:/root/.rustup"])
        .args(["-v", "superior-sel4-cargo:/root/.cargo/registry"])
        .args(["-v", "superior-sel4-git:/root/.cargo/git"])
        .arg("superior-sel4")
        .args(args))
}

/// The QEMU machine and memory seL4 is built for and booted on.
const SEL4_MACHINE: &str = "virt,secure=off,gic-version=2,virtualization=on";
const SEL4_MEMORY: &str = "1024M";

/// seL4 booting the shell as its root task: seL4 and rust-sel4's kernel
/// loader are built once (sel4/build.sh); the shell is built with its
/// `sel4` feature, as an ordinary static executable, and appended to the
/// loader as its payload.
fn sel4_image() -> Result<Image, String> {
    let out = root().join("target/sel4");
    if !out
        .join("loader/bin/sel4-kernel-loader-add-payload")
        .exists()
    {
        // seL4 is configured from the device tree of the machine it will
        // boot on, dumped from this QEMU.
        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        run(Command::new(qemu(Arch::Aarch64))
            .arg("-machine")
            .arg(format!(
                "{SEL4_MACHINE},dumpdtb={}",
                out.join("virt.dtb").display()
            ))
            .args(["-cpu", "cortex-a72", "-smp", "1", "-m", SEL4_MEMORY])
            .args(["-display", "none"]))?;
        println!("== building seL4 and its loader (once)");
        docker(&["sh", "/work/sel4/build.sh"])?;
    }
    println!("== building superior-shell for seL4");
    let target = Arch::Aarch64.target();
    run(cargo().args([
        "build",
        "--quiet",
        "-p",
        "superior-shell",
        "--release",
        "--features",
        "sel4",
        "--target",
        target,
        "--target-dir",
        "target/sel4-user",
    ]))?;
    let app = format!("/work/target/sel4-user/{target}/release/superior-shell");
    docker(&[
        "/work/target/sel4/loader/bin/sel4-kernel-loader-add-payload",
        "--sel4-prefix",
        "/work/target/sel4/prefix",
        "--loader",
        "/work/target/sel4/loader/bin/sel4-kernel-loader",
        "--app",
        &app,
        "-o",
        "/work/target/sel4/superior-shell-sel4.elf",
    ])?;
    Ok(Image {
        path: out.join("superior-shell-sel4.elf"),
        arch: Arch::Aarch64,
        sel4: true,
        disk: None,
        writable: false,
        driver: "virtio-blk",
        net: false,
        linux_nic: None,
        radio: false,
        avx: false,
        keyboard: false,
        xhci: false,
        mouse: false,
        hotplug: false,
        monitor: false,
        display: false,
        gpu: false,
        audio: None,
        uefi: false,
        acpi: false,
        el2: false,
        highmem: false,
        smp: None,
        vars: None,
        firmware: None,
    })
}

/// CPUs the test machines have: `SUPERIOR_CPUS`, else 2.
fn cpus() -> usize {
    env::var("SUPERIOR_CPUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| (1..=4).contains(&n))
        .unwrap_or(2)
}

fn qemu(arch: Arch) -> PathBuf {
    let (var, exe) = match arch {
        Arch::X86_64 => ("QEMU", "qemu-system-x86_64"),
        Arch::Aarch64 => ("QEMU_AARCH64", "qemu-system-aarch64"),
    };
    if let Ok(p) = env::var(var) {
        return p.into();
    }
    let windows_default = Path::new(r"C:\Program Files\qemu").join(format!("{exe}.exe"));
    if windows_default.exists() {
        return windows_default;
    }
    exe.into()
}

/// QEMU's x86-64 UEFI firmware (OVMF, from EDK II): beside QEMU's
/// executable in `share`, or $OVMF.
fn ovmf() -> PathBuf {
    if let Ok(p) = env::var("OVMF") {
        return p.into();
    }
    let exe = qemu(Arch::X86_64);
    let dirs = [exe.parent().map(|d| d.join("share")), Some(PathBuf::from("/usr/share/qemu"))];
    dirs.into_iter()
        .flatten()
        .map(|d| d.join("edk2-x86_64-code.fd"))
        .find(|p| p.exists())
        .unwrap_or_else(|| "edk2-x86_64-code.fd".into())
}

/// The x86-64 image for `boot/<manifest>.manifest` as a UEFI disk: a GPT
/// disk with an EFI system partition holding the bootloader's UEFI
/// application and the kernel, and no BIOS boot code.
fn uefi_image(arch: Arch, manifest: &str) -> Result<Image, String> {
    if arch == Arch::Aarch64 {
        return uefi_image_aarch64(manifest);
    }
    let mut img = image_with(false, Arch::X86_64, manifest)?;
    let kernel = root().join("target").join(Arch::X86_64.target()).join("release").join("superior-kernel");
    let name = if manifest == "shell" { "superior-uefi.img".to_string() } else { format!("superior-uefi-{manifest}.img") };
    let path = root().join("target").join(name);
    bootloader::UefiBoot::new(&kernel)
        .create_disk_image(&path)
        .map_err(|e| format!("creating UEFI disk image: {e}"))?;
    img.path = path;
    img.uefi = true;
    Ok(img)
}

/// The slot of the UEFI tests' lone xHCI controller, on bus 0.
const XHCI_SLOT: u8 = 0x0e;

/// What the kernel says of the UEFI tests' xHCI: found, with no Debug
/// Capability (QEMU's has none), so the log stays where it was.
fn no_dbc(serial: &str) -> String {
    format!("[ok] USB debug: no xHCI with a Debug Capability (the first, at 00:{XHCI_SLOT:02x}.0, has none); the log stays on {serial}")
}

/// The q35 chipset slot the x86-64 LDE test's RTL-8139 sits in.
const LDE_SLOT: u8 = 0x1b;

/// The virtio-blk disk's device on bus 0, and the memory its test DMAR
/// (x86-64) reserves for it: the BIOS area, which no firmware calls
/// usable; or its test IORT (AArch64, under ACPI): a piece of `virt`'s
/// second flash device, not RAM either.
const RESERVED_FOR: u8 = 0x10;
const RESERVED_RANGE: (u64, u64) = (0xf_0000, 0xf_ffff);
const RESERVED_RANGE_ARM: (u64, u64) = (0x0400_0000, 0x0400_ffff);

/// The x86-64 NVMe test's root port, on bus 0, with the controller
/// behind it (00:0c.0/00.0): the test DMAR reserves memory for it by that
/// path, and the bus server numbers the port's bus 10, after nine empty
/// ports.
const NVME_PORT: u8 = 0x0c;

/// QEMU `virt`'s SMMUv3: its registers and event interrupt, as its IORT
/// says.
const VIRT_SMMU: (u64, u32) = (0x0905_0000, 106);
/// The device on bus 0 the test DMAR puts under a second VT-d unit, and
/// where that unit's registers would be (nothing is there: QEMU emulates
/// one unit).
const SECOND_UNIT_FOR: u8 = 0x11;
const SECOND_UNIT: u64 = 0xfed9_a000;

/// A second DMAR, for QEMU's `-acpitable`, with what QEMU's own cannot
/// say: for the driver test, a second VT-d unit (DRHD) naming 00:11.0, as
/// a laptop's graphics have one of their own, and a reserved memory
/// region (RMRR) for 00:10.0; for the NVMe test, a reserved memory region
/// for the controller behind its root port, named by its path through it.
fn test_dmar(nvme: bool) -> Vec<u8> {
    // A device scope: an endpoint, its start bus 0, then a device and
    // function on it and each bus below.
    let endpoint = |path: &[(u8, u8)]| {
        let mut e = vec![1, 6 + 2 * path.len() as u8, 0, 0, 0, 0];
        e.extend(path.iter().flat_map(|&(d, f)| [d, f]));
        e
    };
    let mut drhd = Vec::new();
    if !nvme {
        drhd.extend(0u16.to_le_bytes()); // type: remapping unit
        drhd.extend(24u16.to_le_bytes());
        drhd.extend([0, 0, 0, 0]); // flags (just the functions named), size, segment 0
        drhd.extend(SECOND_UNIT.to_le_bytes());
        drhd.extend(endpoint(&[(SECOND_UNIT_FOR, 0)]));
    }
    let scope = if nvme { endpoint(&[(NVME_PORT, 0), (0, 0)]) } else { endpoint(&[(RESERVED_FOR, 0)]) };
    let mut rmrr = Vec::new();
    rmrr.extend(1u16.to_le_bytes()); // type: reserved memory region
    rmrr.extend((24 + scope.len() as u16).to_le_bytes());
    rmrr.extend([0, 0, 0, 0]); // reserved, segment 0
    rmrr.extend(RESERVED_RANGE.0.to_le_bytes());
    rmrr.extend(RESERVED_RANGE.1.to_le_bytes());
    rmrr.extend(scope);
    let mut t = Vec::new();
    t.extend(b"DMAR");
    t.extend((36 + 12 + drhd.len() as u32 + rmrr.len() as u32).to_le_bytes());
    t.extend([1, 0]); // revision, checksum (below)
    t.extend(b"SUPERI");
    t.extend(b"TESTDMAR");
    t.extend(1u32.to_le_bytes());
    t.extend(b"SUPR");
    t.extend(1u32.to_le_bytes());
    // Host address width (39 bits, less one), flags, 10 reserved bytes.
    t.extend([38, 0]);
    t.extend([0; 10]);
    // Units come before reserved regions.
    t.extend(drhd);
    t.extend(rmrr);
    t[9] = 0u8.wrapping_sub(t.iter().fold(0u8, |s, &b| s.wrapping_add(b)));
    t
}

/// A second IORT, which the UEFI loader installs (QEMU's Arm machines take
/// no `-acpitable`), with what QEMU's own cannot say: a reserved memory
/// range (RMR node) for 00:10.0, whose stream ID is its requester ID, on
/// `virt`'s SMMUv3 (a node of its own for it, the same registers).
fn test_iort() -> Vec<u8> {
    const SMMU_AT: u32 = 48;
    let mut smmu = Vec::new();
    smmu.extend([4u8]); // type: SMMUv3
    smmu.extend(68u16.to_le_bytes());
    smmu.extend([4u8]); // revision
    smmu.extend(0u32.to_le_bytes()); // identifier
    smmu.extend(0u32.to_le_bytes()); // ID mappings: none
    smmu.extend(0u32.to_le_bytes());
    smmu.extend(VIRT_SMMU.0.to_le_bytes());
    smmu.extend([0u8; 4 + 4 + 8 + 4]); // flags, reserved, VATOS, model
    smmu.extend(VIRT_SMMU.1.to_le_bytes()); // event interrupt
    smmu.extend([0u8; 4 * 5]); // PRI, GERR, sync, proximity, ID index
    assert_eq!(smmu.len(), 68);
    let mut rmr = Vec::new();
    rmr.extend([6u8]); // type: reserved memory range
    rmr.extend(68u16.to_le_bytes());
    rmr.extend([3u8]); // revision
    rmr.extend(1u32.to_le_bytes()); // identifier
    rmr.extend(1u32.to_le_bytes()); // one ID mapping, at 28
    rmr.extend(28u32.to_le_bytes());
    rmr.extend(0u32.to_le_bytes()); // flags
    rmr.extend(1u32.to_le_bytes()); // one memory range, at 48
    rmr.extend(48u32.to_le_bytes());
    // The ID mapping: input base, number of IDs less one, output base (the
    // stream ID), output reference (the SMMU node), flags.
    let sid = (RESERVED_FOR as u32) << 3;
    for v in [0, 0, sid, SMMU_AT, 0] {
        rmr.extend(v.to_le_bytes());
    }
    let (start, end) = RESERVED_RANGE_ARM;
    rmr.extend(start.to_le_bytes());
    rmr.extend((end + 1 - start).to_le_bytes());
    rmr.extend(0u32.to_le_bytes());
    assert_eq!(rmr.len(), 68);
    let mut t = Vec::new();
    t.extend(b"IORT");
    t.extend((48 + smmu.len() as u32 + rmr.len() as u32).to_le_bytes());
    t.extend([5, 0]); // revision (E.d, with RMR nodes), checksum (below)
    t.extend(b"SUPERI");
    t.extend(b"TESTIORT");
    t.extend(1u32.to_le_bytes());
    t.extend(b"SUPR");
    t.extend(1u32.to_le_bytes());
    t.extend(2u32.to_le_bytes()); // nodes
    t.extend(SMMU_AT.to_le_bytes());
    t.extend(0u32.to_le_bytes());
    t.extend(smmu);
    t.extend(rmr);
    t[9] = 0u8.wrapping_sub(t.iter().fold(0u8, |s, &b| s.wrapping_add(b)));
    t
}

/// The AArch64 image for `boot/<manifest>.manifest` as a UEFI disk: a GPT
/// disk whose EFI system partition holds `EFI/BOOT/BOOTAA64.EFI`, the
/// loader (`loader/`) with the kernel inside it.
fn uefi_image_aarch64(manifest: &str) -> Result<Image, String> {
    let mut img = image_with(false, Arch::Aarch64, manifest)?;
    println!("== building the UEFI loader (aarch64)");
    let kernel = std::fs::canonicalize(&img.path).map_err(|e| format!("{}: {e}", img.path.display()))?;
    // The driver test's loader carries a second IORT, with memory reserved
    // for its disk, to install when the kernel is to read ACPI.
    let extra = if manifest == "drivers" {
        let path = root().join("target").join("test-iort.bin");
        std::fs::write(&path, test_iort()).map_err(|e| format!("writing {}: {e}", path.display()))?;
        path.into_os_string()
    } else {
        Default::default()
    };
    run(cargo()
        .env("SUPERIOR_KERNEL_ELF", &kernel)
        .env("SUPERIOR_EXTRA_ACPI", &extra)
        .args(["build", "--quiet", "-p", "superior-uefi-loader", "--release", "--target", "aarch64-unknown-uefi"]))?;
    let efi = root().join("target").join("aarch64-unknown-uefi").join("release").join("superior-uefi-loader.efi");
    let name = if manifest == "shell" { "superior-uefi-aarch64.img".to_string() } else { format!("superior-uefi-aarch64-{manifest}.img") };
    let path = root().join("target").join(name);
    esp_disk(&[("EFI/BOOT/BOOTAA64.EFI", &efi)], &path)?;
    img.path = path;
    img.uefi = true;
    Ok(img)
}

/// Writes a GPT disk at `out` with one partition, an EFI system partition
/// (FAT) holding `files` (each a path on it, and the file to copy there).
fn esp_disk(files: &[(&str, &Path)], out: &Path) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    const MB: u64 = 1 << 20;
    let mut data = Vec::new();
    for (name, src) in files {
        data.push((*name, std::fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?));
    }
    let bytes: u64 = data.iter().map(|d| d.1.len() as u64).sum();
    // Room for FAT's own tables, rounded to whole MiB; at least 34 MiB so
    // FAT32 is chosen (UEFI reads FAT12, 16 and 32, but firmware differs).
    let fat_size = ((bytes + 2 * MB).div_ceil(MB) * MB).max(34 * MB);
    let mut fat = std::io::Cursor::new(vec![0u8; fat_size as usize]);
    fatfs::format_volume(&mut fat, fatfs::FormatVolumeOptions::new().volume_label(*b"SUPERIOR   "))
        .map_err(|e| format!("formatting the EFI system partition: {e}"))?;
    {
        let fs = fatfs::FileSystem::new(&mut fat, fatfs::FsOptions::new()).map_err(|e| format!("opening the EFI system partition: {e}"))?;
        let root_dir = fs.root_dir();
        for (name, bytes) in &data {
            // Each parent directory first.
            let parts: Vec<&str> = name.split('/').collect();
            for i in 1..parts.len() {
                let dir = parts[..i].join("/");
                if root_dir.open_dir(&dir).is_err() {
                    root_dir.create_dir(&dir).map_err(|e| format!("making {dir} on the EFI system partition: {e}"))?;
                }
            }
            let mut f = root_dir.create_file(name).map_err(|e| format!("making {name}: {e}"))?;
            f.truncate().map_err(|e| format!("{name}: {e}"))?;
            f.write_all(bytes).map_err(|e| format!("writing {name}: {e}"))?;
        }
    }
    let fat = fat.into_inner();
    let mut disk = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(out)
        .map_err(|e| format!("creating {}: {e}", out.display()))?;
    // The partition, and room before and after it for GPT's two copies.
    let disk_size = fat_size + 2 * MB;
    disk.set_len(disk_size).map_err(|e| format!("{}: {e}", out.display()))?;
    gpt::mbr::ProtectiveMBR::with_lb_size(u32::try_from(disk_size / 512 - 1).unwrap_or(u32::MAX))
        .overwrite_lba0(&mut disk)
        .map_err(|e| format!("writing the protective MBR: {e}"))?;
    let block = gpt::disk::LogicalBlockSize::Lb512;
    let mut table = gpt::GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(block)
        .create_from_device(Box::new(&mut disk), None)
        .map_err(|e| format!("making the GPT: {e}"))?;
    table.update_partitions(Default::default()).map_err(|e| format!("making the GPT: {e}"))?;
    let id = table
        .add_partition("EFI system partition", fat_size, gpt::partition_types::EFI, 0, None)
        .map_err(|e| format!("adding the EFI system partition: {e}"))?;
    let start = table
        .partitions()
        .get(&id)
        .and_then(|p| p.bytes_start(block).ok())
        .ok_or("finding the EFI system partition")?;
    table.write().map_err(|e| format!("writing the GPT: {e}"))?;
    disk.seek(SeekFrom::Start(start)).map_err(|e| format!("{}: {e}", out.display()))?;
    disk.write_all(&fat).map_err(|e| format!("writing the EFI system partition: {e}"))?;
    Ok(())
}

/// QEMU's AArch64 UEFI firmware (edk2's ArmVirtQemu), beside QEMU's
/// executable in `share`, or $AAVMF.
fn aavmf() -> PathBuf {
    if let Ok(p) = env::var("AAVMF") {
        return p.into();
    }
    let exe = qemu(Arch::Aarch64);
    [exe.parent().map(|d| d.join("share")), Some(PathBuf::from("/usr/share/qemu"))]
        .into_iter()
        .flatten()
        .map(|d| d.join("edk2-aarch64-code.fd"))
        .find(|p| p.exists())
        .unwrap_or_else(|| "edk2-aarch64-code.fd".into())
}

fn qemu_command(img: &Image) -> Command {
    let mut q = Command::new(qemu(img.arch));
    match img.arch {
        Arch::X86_64 => {
            // Images with a disk are driver tests: they need an IOMMU,
            // which QEMU emulates (VT-d) only on its q35 machine, with
            // interrupt remapping.
            if img.disk.is_some() || img.net || img.radio || img.keyboard || img.hotplug || img.display || img.audio.is_some() {
                q.args(["-machine", "q35", "-device", "intel-iommu,intremap=on"]);
            }
            if img.disk.is_some() && img.driver == "ahci" {
                // The boot disk would be q35's AHCI port 0, the first disk the
                // driver finds: put it on port 2, after the test disks on
                // ports 0 and 1 (so it is unit 2).
                q.arg("-drive")
                    .arg(format!(
                        "if=none,id=boot,format=raw,file={}",
                        img.path.display()
                    ))
                    .args(["-device", "ide-hd,drive=boot,bus=ide.2,bootindex=0"]);
            } else {
                q.arg("-drive")
                    .arg(format!("format=raw,file={}", img.path.display()));
            }
            if img.uefi {
                // OVMF, the UEFI firmware QEMU ships, in place of SeaBIOS.
                q.arg("-drive")
                    .arg(format!("if=pflash,format=raw,readonly=on,file={}", ovmf().display()))
                    .args(["-m", "512M"]);
            }
            q.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
            // The suspend test's clock keeps running while the machine is
            // asleep, as a battery-backed one does (QEMU stops the
            // machine's own clock in S3, so its alarm could never wake it).
            q.args(["-rtc", if img.monitor && !img.keyboard && !img.hotplug && !img.display { RTC_SLEEPING } else { RTC_BASE }]);
            if img.radio {
                // A CPU with random instructions, for the entropy pool.
                q.args(["-cpu", "qemu64,+rdrand,+rdseed"]);
            } else if img.avx {
                q.args(["-cpu", "max"]);
            }
        }
        Arch::Aarch64 => {
            // highmem=off keeps PCI's ECAM window below 4 GiB, where the
            // kernel hands it to the PCI bus server.
            // Driver tests get an SMMUv3 in front of PCI.
            let machine = if img.sel4 {
                SEL4_MACHINE
            } else if img.disk.is_some() || img.net || img.radio || img.keyboard || img.hotplug || img.display || img.audio.is_some() {
                "virt,highmem=off,gic-version=3,iommu=smmuv3"
            } else {
                "virt,highmem=off,gic-version=3"
            };
            let machine = if img.el2 && !img.sel4 {
                format!("{machine},virtualization=on")
            } else {
                machine.to_string()
            };
            let machine = if img.highmem { machine.replace("highmem=off", "highmem=on") } else { machine };
            let machine = machine.as_str();
            // The radio's test wants RNDR (FEAT_RNG), which "max" has.
            let cpu = if img.radio { "max" } else { "cortex-a72" };
            if img.uefi {
                // UEFI firmware (edk2) in flash, booting the disk's EFI
                // system partition. acpi=off: the firmware then hands over
                // QEMU's device tree, not ACPI tables.
                let acpi = if img.acpi { "on" } else { "off" };
                q.args(["-machine", &format!("{machine},acpi={acpi}"), "-cpu", cpu])
                    .arg("-drive")
                    .arg(format!(
                        "if=pflash,format=raw,readonly=on,file={}",
                        img.firmware.clone().unwrap_or_else(aavmf).display()
                    ));
                if let Some(vars) = &img.vars {
                    q.arg("-drive").arg(format!("if=pflash,format=raw,file={}", vars.display()));
                }
                q.arg("-drive")
                    .arg(format!("if=none,id=boot,format=raw,file={}", img.path.display()))
                    // On NVMe, so a virtio disk image's driver finds only
                    // its test disk.
                    .args(["-device", "nvme,serial=superior-boot,drive=boot,bootindex=0"]);
            } else {
                q.args(["-machine", machine, "-cpu", cpu, "-kernel"])
                    .arg(&img.path);
            }
            if !img.sel4 {
                q.args(["-rtc", RTC_BASE]);
            }
            if img.sel4 {
                // The shell's exit is a semihosting call from user mode.
                q.args([
                    "-semihosting-config",
                    "enable=on,target=native,userspace=on",
                ])
                .args(["-m", SEL4_MEMORY]);
            } else {
                q.args(["-semihosting-config", "enable=on,target=native"])
                    .args(["-m", "512M"]);
            }
        }
    }
    if img.arch == Arch::X86_64 {
        q.args(["-m", "512M"]);
    }
    // Several CPUs, except for seL4's images (built for one).
    if !img.sel4 {
        q.args(["-smp", &img.smp.map_or(cpus().to_string(), str::to_string)]);
    }
    // QEMU's IDE disks cannot be read-only; the drivers test's disk is
    // made afresh for every run anyway.
    let drive = |id: &str, disk: &PathBuf| {
        let writable = img.writable || img.driver == "ahci";
        format!(
            "if=none,id={id},format=raw,readonly={},file={}",
            if writable { "off" } else { "on" },
            disk.display()
        )
    };
    if let (Some(disk), "nvme") = (&img.disk, img.driver) {
        // QEMU's NVMe controller does its DMA through the IOMMU. Two
        // namespaces: the disk, and a small one of its own pattern.
        q.arg("-drive")
            .arg(drive("nvm0", disk))
            .arg("-drive")
            .arg(format!(
                "if=none,id=nvm1,format=raw,readonly=on,file={}",
                second_namespace().display()
            ))
            // The controller sits behind a PCI Express root port, on a
            // bus of its own, so the bus server must number that bus and
            // open the port's memory window to reach it. Nine empty root
            // ports come first, each taking a bus number, so the
            // controller is on bus 10: past the eight buses the kernel's
            // IOMMU and interrupt tables once reached. A conventional
            // bridge with a device behind it follows: found, but given no
            // DMA, since it would share the bridge's requester ID.
            .args(
                (1..=9).flat_map(|n| ["-device".to_string(), format!("pcie-root-port,id=empty{n},chassis={}", 10 + n)]),
            )
            .args([
                "-device",
                if img.arch == Arch::X86_64 { "pcie-root-port,id=rp0,chassis=1,addr=0xc" } else { "pcie-root-port,id=rp0,chassis=1" },
                "-device",
                "nvme,id=nvme0,serial=superior0,bus=rp0",
                "-device",
                "pci-bridge,id=br0,chassis_nr=2",
                "-device",
                "virtio-rng-pci,bus=br0,addr=1,disable-legacy=on",
                // A card with an I/O BAR behind another root port, for
                // the port's I/O window (it has no network behind it).
                "-device",
                "pcie-root-port,id=rp1,chassis=3",
                "-device",
                "rtl8139,bus=rp1",
                "-device",
                "nvme-ns,drive=nvm0,bus=nvme0,nsid=1",
                "-device",
                "nvme-ns,drive=nvm1,bus=nvme0,nsid=2",
            ]);
        if img.arch == Arch::X86_64 {
            // Memory reserved for the controller behind its root port,
            // named by its path from bus 0: the kernel must follow the
            // path through the port's bus as the bus server numbers it.
            let path = Path::new("target").join("test-dmar-nvme.bin");
            match std::fs::write(root().join(&path), test_dmar(true)) {
                Ok(()) => {
                    q.current_dir(root()).arg("-acpitable").arg(format!("file={}", path.display()));
                }
                Err(e) => eprintln!("writing {}: {e}", path.display()),
            }
        }
    } else if let (Some(disk), "ahci") = (&img.disk, img.driver) {
        // q35 has an AHCI controller (ICH9, 00:1f.2); virt needs one added.
        // Its DMA goes through the IOMMU. Two disks: the test disk on port
        // 0, and the small disk of its own pattern on port 1.
        q.arg("-drive")
            .arg(drive("sata0", disk))
            .arg("-drive")
            .arg(drive("sata1", &second_namespace()));
        let bus = if img.arch == Arch::X86_64 {
            "ide"
        } else {
            q.args(["-device", "ahci,id=ahci"]);
            "ahci"
        };
        q.args(["-device", &format!("ide-hd,drive=sata0,bus={bus}.0")])
            .args(["-device", &format!("ide-hd,drive=sata1,bus={bus}.1")]);
    } else if let Some(disk) = &img.disk {
        // Modern only (virtio 1.x): no legacy I/O BAR. iommu_platform:
        // the device's DMA goes through the IOMMU (QEMU's virtio devices
        // bypass it otherwise).
        q.arg("-drive")
            .arg(format!(
                "if=none,id=blk0,format=raw,readonly={},file={}",
                if img.writable { "off" } else { "on" },
                disk.display()
            ))
            .arg("-device")
            .arg(format!(
                "virtio-blk-pci,drive=blk0,disable-legacy=on,iommu_platform=on,addr={RESERVED_FOR:#x}"
            ));
        if img.arch == Arch::X86_64 {
            // At a known address, with memory the firmware reserves for
            // it, which the kernel must map for it; and a virtio entropy
            // source under a VT-d unit of its own that is not there, which
            // the kernel must not bind. QEMU's DMAR can say neither: a
            // second DMAR says both.
            q.arg("-device").arg(format!("virtio-rng-pci,disable-legacy=on,iommu_platform=on,addr={SECOND_UNIT_FOR:#x}"));
            let path = Path::new("target").join("test-dmar.bin");
            match std::fs::write(root().join(&path), test_dmar(false)) {
                Ok(()) => {
                    // The path must be relative: QEMU splits it at colons.
                    q.current_dir(root()).arg("-acpitable").arg(format!("file={}", path.display()));
                }
                Err(e) => eprintln!("writing {}: {e}", path.display()),
            }
        }
    }
    if img.net {
        // User-mode networking, on a network other than QEMU's default
        // so no address can be assumed: DHCP gives the guest 10.0.3.30,
        // the gateway (the host) is 10.0.3.2 and the DNS server 10.0.3.3.
        // Modern virtio only, its DMA through the IOMMU.
        q.args([
            "-netdev",
            // IPv6 on fd00:3::/64 (the host fd00:3::2, DNS fd00:3::3; the
            // guest makes fd00:3::5054:ff:fe12:3456 from its MAC). The TCP
            // test's host connects in through 47004 (QEMU forwards IPv4
            // only).
            "user,id=n0,net=10.0.3.0/24,dhcpstart=10.0.3.30,ipv6-net=fd00:3::/64,hostfwd=tcp:127.0.0.1:47004-:8080",
            "-device",
            // The cards Linux's drivers are for have no MSI: their
            // interrupt is a legacy line. On x86-64 the RTL-8139 sits in
            // slot 27, one of the q35 chipset's, whose pins _PRT routes its
            // own way rather than as the other slots' rotated wires: the
            // bus server must ask the kernel which line its pin reaches.
            &match img.linux_nic {
                Some(nic) if nic.starts_with("rtl8139") => format!("{nic},addr={LDE_SLOT:#x}"),
                Some(nic) => nic.to_string(),
                None => "virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on".to_string(),
            },
        ]);
    }
    if img.radio {
        // The simulated radio: each frame one UDP datagram to the test's
        // access point, and back.
        q.args([
            "-netdev",
            &format!(
                "socket,id=r0,udp=127.0.0.1:{},localaddr=127.0.0.1:{}",
                wifi_ap::AP_PORT,
                wifi_ap::RADIO_PORT
            ),
            "-device",
            "virtio-net-pci,netdev=r0,disable-legacy=on,iommu_platform=on",
        ]);
    }
    if img.xhci {
        q.args(["-device", &format!("qemu-xhci,addr={XHCI_SLOT:#x}")]);
    }
    if img.keyboard {
        // A USB keyboard on an xHCI controller (its DMA through the
        // IOMMU), and the monitor the test types through.
        q.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,id=kbd0,bus=xhci.0"]);
        if img.mouse {
            q.args(["-device", "usb-mouse,id=mouse0,bus=xhci.0", "-device", "usb-tablet,id=tablet0,bus=xhci.0"]);
        }
    }
    if img.hotplug {
        // An empty root port to plug cards into, and the monitor that
        // does it. On q35 QEMU would announce hot-plug through ACPI,
        // which nothing here reads: it is told to leave the port's own
        // PCI Express hot-plug in charge.
        if img.arch == Arch::X86_64 {
            q.args(["-global", "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off"]);
        }
        q.args(["-device", "pcie-root-port,id=hp0,chassis=1"]);
    }
    if img.display {
        // One display, which the Linux bochs driver drives, its EDID giving
        // the screen's size as the preferred mode: on x86 QEMU's standard
        // VGA in place of the default one (the bootloader needs its BIOS),
        // on AArch64 bochs-display (no BIOS there; the same registers in
        // MMIO).
        let card = match (img.arch, img.gpu) {
            (Arch::X86_64, false) => "VGA",
            (Arch::Aarch64, false) => "bochs-display",
            // The virtio GPU, modern only, its DMA through the IOMMU; on
            // x86 with the VGA registers and BIOS too.
            (Arch::X86_64, true) => "virtio-vga,disable-legacy=on,iommu_platform=on",
            (Arch::Aarch64, true) => "virtio-gpu-pci,disable-legacy=on,iommu_platform=on",
        };
        if img.arch == Arch::X86_64 {
            q.args(["-vga", "none"]);
        }
        let edid = if img.gpu { "off" } else { "on" };
        q.arg("-device")
            .arg(format!("{card},xres={},yres={},edid={edid}", SCREEN.0, SCREEN.1));
    }
    if let Some(wav) = &img.audio {
        // The card Linux's ES1370 driver is for, its DMA through the
        // IOMMU; QEMU records what it plays, at the rate the driver plays
        // at (so nothing is resampled), to a WAV file.
        q.arg("-audiodev")
            .arg(format!(
                "wav,id=snd0,path={},out.frequency={AUDIO_RATE},out.channels=2,out.format=s16",
                wav.display()
            ))
            .args(["-device", "ES1370,audiodev=snd0"]);
    }
    if img.keyboard || img.hotplug || img.display || img.monitor {
        // QEMU's monitor, to type, plug cards, take screenshots and wake
        // the machine through.
        q.arg("-qmp").arg(format!("tcp:127.0.0.1:{QMP_PORT},server=on,wait=off"));
    }
    q.args(["-serial", "stdio", "-no-reboot"]);
    q
}

fn boot(img: &Image, selftest: bool) -> Result<(), String> {
    println!("== booting {}", img.path.display());
    let mut q = qemu_command(img);
    if selftest || img.arch == Arch::Aarch64 {
        q.args(["-display", "none"]);
    }
    let status = q
        .status()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu(img.arch).display()))?;
    match (selftest, status.code()) {
        (true, Some(QEMU_PASS)) => {
            println!("== boot self-tests passed ({})", img.arch.name());
            Ok(())
        }
        (true, code) => Err(format!(
            "boot self-tests failed on {} (QEMU exit {code:?})",
            img.arch.name()
        )),
        (false, _) => Ok(()),
    }
}

/// Boots the image built from `boot/test.manifest` and checks, from the
/// boot log, that the Component Manager:
/// - starts each boot component in an address space of its own (the
///   probe's read of the manager's bundle address faults, and the fault
///   reaches the manager as its fault handler);
/// - starts the lazy `echo` only when the client first calls it, and the
///   first call still gets its answer (forwarded under the client's
///   badge), as do later calls straight to the service;
/// - never starts `spare`, which nothing calls;
/// - powers off with the pass code when the client reports success.
fn cm_test(img: &Image) -> Result<(), String> {
    println!("== Component Manager test on {}", img.path.display());
    let out = run_to_exit(img, Duration::from_secs(60))?;
    let bundle_va = 0x7001_0000_0000u64;
    // In order.
    let steps = [
        "[cm] manifest: 5 components".to_string(),
        "[cm] started probe (boot)".to_string(),
        "[cm] started client (boot)".to_string(),
        format!("probe: reading {bundle_va:#x}"),
        "[cm] probe faulted: page fault at pc".to_string(),
        format!("address {bundle_va:#x}"),
        "[cm] probe stays stopped (restart never)".to_string(),
        "[cm] started echo (lazy: first call to its service)".to_string(),
        "echo: running in its own address space".to_string(),
        "[pass] client: call 1: sent 100, got 101".to_string(),
        "[pass] client: call 2: sent 200, got 201".to_string(),
        "[pass] client: call 3: sent 300, got 301".to_string(),
        "[pass] client: slept 20 ticks".to_string(),
        "[cm] client asked to shut down (pass)".to_string(),
        "[cm] never started: spare (nothing used it)".to_string(),
    ];
    let steps: Vec<&str> = steps.iter().map(String::as_str).collect();
    if let Err(step) = find_in_order(&out, &steps) {
        return Err(format!("Component Manager test: missing (in order) {step:?}"));
    }
    // An interrupt that lands while user code has the direction flag set
    // must not run the kernel with it set (x86-64 only).
    if img.arch == Arch::X86_64 && !out.contains("[pass] client: direction flag set across") {
        return Err("Component Manager test: the direction-flag check did not pass".into());
    }
    for bad in ["[fail]", "started spare", "could not start", "panic"] {
        if out.contains(bad) {
            return Err(format!("Component Manager test: log contains {bad:?}"));
        }
    }
    println!("== Component Manager test passed ({})", img.arch.name());
    Ok(())
}

/// Boots `boot/supervise.manifest` and checks that the manager
/// - restarts a crashed one-for-one component, whose state page survives
///   and whose journal answers a retried request instead of applying it
///   twice (the client's own checks, `[pass]` lines);
/// - gives up on a component after five restarts and tombstones its
///   service;
/// - restarts the component after a crashed rest-for-one one.
fn supervise_test(img: &Image) -> Result<(), String> {
    println!("== supervision test on {}", img.path.display());
    let out = run_to_exit(img, Duration::from_secs(60))?;
    let steps = [
        "[cm] manifest: 5 components",
        "[pass] supervise: counter starts at 0 (instance 1)",
        "[pass] supervise: add 5 (request 1): 5",
        "[cm] counter faulted: page fault",
        "[cm] restarting counter (one-for-one)",
        "[pass] supervise: the counter crashed under a call",
        "[pass] supervise: after the restart: value 5 (instance 2)",
        "counter: instance 3 starting, value 15",
        "[pass] supervise: add 10 (request 2), crashed before replying, retried: 15 (from the journal: 1)",
        "[pass] supervise: applied once: value 15 (instance 3)",
        "[pass] supervise: a service given up on answers unavailable",
        "[pass] supervise: after: call 1 of its instance",
        "[cm] restarting base and 1 after it (rest-for-one)",
        "[cm] started after (restart)",
        "[pass] supervise: base crashed under a call",
        "[pass] supervise: after was restarted with base: call 1 of a new instance",
        "[cm] client asked to shut down (pass)",
    ];
    if let Err(step) = find_in_order(&out, &steps) {
        return Err(format!("supervision test: missing (in order) {step:?}"));
    }
    // The new counter and the client are ready together after the
    // restart, at one priority: either may print first.
    if !out.contains("counter: instance 2 starting, value 5") {
        return Err("supervision test: the restarted counter did not find its value".into());
    }
    // Independent of the client's order: the crasher's five restarts and
    // the manager giving up.
    let restarts = out.matches("[cm] restarting crasher (one-for-one)").count();
    if restarts != 5 {
        return Err(format!(
            "supervision test: crasher restarted {restarts} times, not 5"
        ));
    }
    if !out.contains("[cm] crasher: more than 5 restarts in 60 s; giving up") {
        return Err("supervision test: the manager never gave up on crasher".into());
    }
    for bad in ["[fail]", "could not", "panic"] {
        if out.contains(bad) {
            return Err(format!("supervision test: log contains {bad:?}"));
        }
    }
    println!("== supervision test passed ({})", img.arch.name());
    Ok(())
}

/// The NVMe tests' second namespace (and the AHCI tests' second disk): 64 sectors, word `k` of sector `s`
/// being `0x4e32 << 48 | s << 16 | k`. Written afresh each time (it is
/// small).
fn second_namespace() -> PathBuf {
    let mut bytes = Vec::with_capacity(64 * 512);
    for s in 0..64u64 {
        for k in 0..64u64 {
            bytes.extend_from_slice(&(0x4e32u64 << 48 | s << 16 | k).to_le_bytes());
        }
    }
    let path = root().join("target").join("nvme-namespace-2.img");
    if let Err(e) = std::fs::write(&path, bytes) {
        eprintln!("xtask: writing {}: {e}", path.display());
    }
    path
}

/// Writes the drivers test's disk: 128 sectors, word `k` (little-endian
/// u64) of sector `s` being `0x5355 << 48 | s << 16 | k`, so a client can
/// check every word it reads (`user/testclient`).
fn test_disk() -> Result<PathBuf, String> {
    let mut bytes = Vec::with_capacity(128 * 512);
    for s in 0..128u64 {
        for k in 0..64u64 {
            bytes.extend_from_slice(&(0x5355u64 << 48 | s << 16 | k).to_le_bytes());
        }
    }
    let path = root().join("target").join("drivers-test-disk.img");
    std::fs::write(&path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Boots `boot/drivers.manifest` with the test disk on virtio-blk and
/// checks that
/// - the PCI bus server finds the device and gives it to the driver, which
///   brings it up with an MSI-X interrupt;
/// - the client reads the disk by DMA into its own page, every word right;
/// - the bus server refuses the client the driver's device and its BARs;
/// - MSIs are remapped, and (virtio-blk) a device made to raise a vector
///   routed to no device raises nothing, which VT-d reports;
/// - DMA aimed outside the device's domain does not land and is reported;
/// - a crashed driver is restarted, its device reset and reopened, and
///   reads work again.
fn drivers_test(img: &Image) -> Result<(), String> {
    drivers_test_log(img).map(|_| ())
}

/// As [`drivers_test`], returning the log.
fn drivers_test_log(img: &Image) -> Result<String, String> {
    println!("== driver framework test on {}", img.path.display());
    let out = run_to_exit(img, Duration::from_secs(60))?;
    let (d, device, _) = disk_driver(img.driver);
    let ready = format!("{d}: ready:");
    let stray = format!("{d}: stray DMA: page untouched");
    let crashing = format!("{d}: crashing (fault injection)");
    let restarting = format!("[cm] restarting {d} (one-for-one)");
    // MSIs are remapped: VT-d's remapping table, or the GICv3 ITS.
    let (remap, remap_at) = match img.arch {
        Arch::X86_64 => ("IOMMU: Intel VT-d, interrupt remapping", ""),
        Arch::Aarch64 => ("[ok] GICv3 with ITS", "IOMMU: "),
    };
    // virtio-blk also has its device raise a vector routed to no device:
    // nothing may arrive, and VT-d must report it.
    let forged = format!(
        "{d}: forged MSI: a vector routed to no device was not raised, request completed; {}",
        match img.arch {
            Arch::X86_64 => "the IOMMU reported the blocked interrupt",
            Arch::Aarch64 => "the ITS mapped it for no device",
        }
    );
    let forged: &str = if d == "virtio-blk" { &forged } else { "" };
    // NVMe: two I/O queues, each with its own thread, and the second
    // namespace a unit of its own. AHCI: two command slots, each with its
    // own thread, queued (NCQ), and the disk on port 1 a unit of its own
    // (on x86 the boot disk, on port 2, is a third).
    let nvme = d == "nvme";
    let ahci = d == "ahci";
    let pick = |s: &'static str| if nvme { s } else { "" };
    let sata = |s: &'static str| if ahci { s } else { "" };
    let units = if ahci && img.arch == Arch::X86_64 { 3 } else { 2 };
    let unit1 = if nvme || ahci {
        format!("[pass] block: unit 1 of {units}: 64 sectors of 512 bytes")
    } else {
        String::new()
    };
    let no_unit = if nvme || ahci {
        format!("[pass] block: unit 1 ends at its own size, and there is no unit {units}")
    } else {
        String::new()
    };
    let both = |s: &'static str| if nvme || ahci { s } else { "" };
    let steps: &[&str] = &[
        remap,
        remap_at,
        "[cm] manifest: 3 components",
        "pci: BAR window at",
        device,
        // The NVMe controller is behind the tenth root port, on bus 10;
        // a conventional bridge with a device behind it makes bus 11.
        pick("pci: 0b:01.0 1af4:1044"),
        pick("pci: 0c:00.0 10ec:8139"),
        pick("bridges to bus 0a (to 0a), 1 functions behind it; a PCI Express port"),
        pick("windows: memory 0x"),
        // The virtio device's registers are in a prefetchable BAR, the
        // RTL-8139's in an I/O BAR too: each bridge's window for those.
        pick("bridges to bus 0b (to 0b), 1 functions behind it; a conventional bridge, so what is behind it shares its requester ID and gets no DMA"),
        pick(", prefetchable 0x"),
        pick("bridges to bus 0c (to 0c), 1 functions behind it; a PCI Express port"),
        pick(", I/O 0x"),
        "given to client 2 (reset:",
        "new, empty IOMMU domain",
        // AHCI names its disks before it is ready, NVMe after.
        sata("ahci: unit 0: port 0 "),
        sata("128 sectors, write cache, NCQ"),
        sata("ahci: unit 1: port 1 "),
        sata("64 sectors, write cache, NCQ"),
        &ready,
        sata(" disks, 2 command slots, interrupts on MSI"),
        pick("2 I/O queues, interrupts on MSI-X vectors 0-1"),
        pick("nvme: unit 0: namespace 1, 128 blocks of 512 bytes"),
        pick("nvme: unit 1: namespace 2, 64 blocks of 512 bytes"),
        "[pass] block: 128 sectors of 512 bytes",
        "[pass] block: read 8 sectors from 0 by DMA into its page: every word right",
        "[pass] block: read 8 sectors from 100 by DMA into its page: every word right",
        "[pass] block: read 1 sectors from 127 by DMA into its page: every word right",
        &unit1,
        both("[pass] block: read 8 sectors from 0 of unit 1: its own data, every word right"),
        both("[pass] block: read 4 sectors from 60 of unit 1: its own data, every word right"),
        &no_unit,
        "[pass] block: two threads read 40 times each at once: every word right",
        both("[pass] block: the driver used all 2 of its queues, with up to 2 commands in flight at once"),
        "may not have",
        "[pass] block: the bus server will not give it the driver's device",
        "[pass] block: nor any BAR page",
        pick("behind a conventional bridge, so no bus mastering"),
        pick("[pass] block: the device behind the conventional bridge (0b:01.0) opens with no IOMMU domain, and may not master the bus"),
        pick("[pass] block: its prefetchable BAR answers through the bridge's prefetchable window; then it is given back"),
        pick("[pass] block: the RTL-8139 behind a root port (0c:00.0): MAC 52:54:00:12:34:"),
        pick("by its I/O BAR and its memory BAR alike; writes cross over; no port past the BAR"),
        forged,
        &stray,
        "the IOMMU reported a blocked write to it",
        &crashing,
        &restarting,
        "reopened by client 2 (reset:",
        "new, empty IOMMU domain",
        "[pass] block: read 8 sectors from 32 after the driver restarted on a fresh domain: every word right",
        &crashing,
        &restarting,
        "reopened by client 2 (reset:",
        // The driver's "ready" may come before or after the client's verdict.
        "[pass] block: the driver crashed under a call",
        "[pass] block: read 8 sectors from 64 after the restart: every word right",
        "[cm] client asked to shut down (pass)",
    ];
    if let Err(step) = find_in_order(&out, steps) {
        return Err(format!("driver framework test: missing (in order) {step:?}"));
    }
    // The client's verdict on the stray DMA, which (on several CPUs) may
    // come before or after the driver crashes and is restarted.
    let verdict = "[pass] block: DMA aimed outside the device's IOMMU domain did not land and was reported";
    if !out.contains(verdict) {
        return Err(format!("driver framework test: missing {verdict:?}"));
    }
    // The IOMMU raised its fault interrupt (the kernel drains faults then,
    // not at the next tick), and virtio-blk's driver, which bound a
    // notification to its domain's faults, was signalled.
    let mut wanted = vec!["[iommu] fault interrupt 1"];
    if d == "virtio-blk" {
        wanted.push("the IOMMU reported a blocked write to it; the driver was signalled");
    }
    for line in wanted {
        if !out.contains(line) {
            return Err(format!("driver framework test: missing {line:?}"));
        }
    }
    // Memory reserved for a function, by a second IORT the UEFI loader
    // installs (AArch64 under ACPI, for the virtio-blk disk), or a second
    // DMAR naming the NVMe controller behind its root port by its path
    // (x86-64): read at boot, and mapped each time the function is bound
    // to a domain (first, and the restarted driver's fresh one).
    let bound = |bdf: &str, (start, end): (u64, u64)| {
        format!("[ok] IOMMU: {bdf} bound, with its {} pages of reserved memory mapped where they are", (end + 1 - start) / 4096)
    };
    let reserved: Option<Vec<String>> = match (img.arch, d) {
        (Arch::Aarch64, "virtio-blk") if img.uefi && img.acpi => {
            let (start, end) = RESERVED_RANGE_ARM;
            let b = bound(&format!("00:{RESERVED_FOR:02x}.0"), RESERVED_RANGE_ARM);
            Some(vec![
                "loader: installed its own ACPI table IORT (0xb8 bytes)".to_string(),
                "[ok] ACPI: 1 reserved memory range (IORT)".to_string(),
                format!("[ok] ACPI: reserved memory {start:#x} to {end:#x}, for 00:{RESERVED_FOR:02x}.0"),
                b.clone(),
                b,
            ])
        }
        (Arch::X86_64, "nvme") => {
            let (start, end) = RESERVED_RANGE;
            let b = bound("0a:00.0", RESERVED_RANGE);
            Some(vec![
                "[ok] ACPI: 1 VT-d unit; 1 reserved memory region".to_string(),
                format!("[ok] ACPI: reserved memory {start:#x} to {end:#x}, for 00:{NVME_PORT:02x}.0/00.0"),
                b.clone(),
                b,
            ])
        }
        _ => None,
    };
    if let Some(steps) = &reserved {
        let steps: Vec<&str> = steps.iter().map(String::as_str).collect();
        if let Err(step) = find_in_order(&out, &steps) {
            return Err(format!("driver framework test: missing (in order) {step:?}"));
        }
    }
    if img.arch == Arch::Aarch64 && img.uefi && !img.acpi && !out.contains("loader: its built-in ACPI tables are not installed: the kernel reads the device tree") {
        return Err("driver framework test: the loader did not say its ACPI tables went unused".into());
    }
    // x86-64's virtio-blk disk has memory reserved for it in a second
    // DMAR: the kernel reads it, and maps it each time the function is
    // bound to a domain (first, and on the restarted driver's fresh one),
    // with the reads still right.
    if img.arch == Arch::X86_64 && d == "virtio-blk" {
        let (start, end) = RESERVED_RANGE;
        let region = format!("[ok] ACPI: reserved memory {start:#x} to {end:#x}, for 00:{RESERVED_FOR:02x}.0");
        let bound = format!(
            "[ok] IOMMU: 00:{RESERVED_FOR:02x}.0 bound, with its {} pages of reserved memory mapped where they are",
            (end + 1 - start) / 4096
        );
        if let Err(step) = find_in_order(&out, &[&region, &bound, &bound]) {
            return Err(format!("driver framework test: missing (in order) {step:?}"));
        }
        // Its second unit, which names 00:11.0 (taking it from QEMU's,
        // which names every function), is not there: the kernel cannot
        // drive it, so will not bind the function, and the bus server
        // opens it with no domain and no bus mastering.
        let second = [
            "[ok] ACPI: 2 VT-d units; 1 reserved memory region".to_string(),
            format!("[ok] ACPI: VT-d unit at {SECOND_UNIT:#x}: 1 function it names on bus 0"),
            format!("[warn] IOMMU: the VT-d unit at {SECOND_UNIT:#x} cannot be driven"),
            "IOMMU: Intel VT-d, interrupt remapping".to_string(),
            format!("pci: 00:{SECOND_UNIT_FOR:02x}.0 given to client"),
            "under no IOMMU unit the kernel drives, so no bus mastering".to_string(),
            format!(
                "[pass] block: the device under a VT-d unit the kernel cannot drive (00:{SECOND_UNIT_FOR:02x}.0) opens with no IOMMU domain and may not master the bus; its registers answer"
            ),
        ];
        let second: Vec<&str> = second.iter().map(String::as_str).collect();
        if let Err(step) = find_in_order(&out, &second) {
            return Err(format!("driver framework test: missing (in order) {step:?}"));
        }
    }
    for bad in ["[fail]", "could not", "panic", "[warn] ACPI"] {
        if out.contains(bad) {
            return Err(format!("driver framework test: log contains {bad:?}"));
        }
    }
    println!("== driver framework test passed ({}, {d})", img.arch.name());
    Ok(out)
}

/// The filesystem tests' disk (4 MiB), shared by both boots.
fn fs_disk() -> PathBuf {
    root().join("target").join("fs-test-disk.img")
}

/// The Linux personality test's disk, under its `/home`: made empty
/// before the first boot, read back by the second.
fn linux_disk() -> PathBuf {
    root().join("target").join("linux-test-disk.img")
}

/// The filesystem server, in two boots of one fresh disk:
/// - `boot/fs.manifest`: a client appends records while the injector kills
///   the server and the driver; every acknowledged record reads back; one
///   more is acknowledged and the machine stops at once (a power cut);
/// - `boot/fs-verify.manifest`: every acknowledged record is on the disk,
///   and another component's container does not hold the file.
/// The driver framework and filesystem tests with the disk on `driver`.
fn disk_test(arch: Arch, driver: &'static str) -> Result<(), String> {
    image_for(false, arch, "drivers", driver)
        .and_then(|img| drivers_test(&img))
        .and_then(|_| fs_test(arch, driver))
}

fn fs_test(arch: Arch, driver: &'static str) -> Result<(), String> {
    let first = image_for(false, arch, "fs", driver)?;
    let second = image_for(false, arch, "fs-verify", driver)?;
    let killing = format!("[cm] fault injection: killing {driver}");
    let disk = fs_disk();
    std::fs::write(&disk, vec![0u8; 16 << 20])
        .map_err(|e| format!("writing {}: {e}", disk.display()))?;
    println!("== filesystem test, first boot: {}", first.path.display());
    // Generous: 600 files into one directory under fault injection, each
    // of the server's many restarts checking every one of them, take
    // AArch64 under emulated NVMe some 800 s (4,367 kills in one run), and
    // x86-64 now and then over 360 s: how long depends on where the kills
    // fall. Only a run that hangs waits this long.
    let out = run_to_exit(&first, Duration::from_secs(1200))?;
    // The server may be killed during the format (and format again, or
    // find it done); either way the first mount sees an empty filesystem.
    let steps = [
        "fs: formatting",
        "fs: mounted in",
        "fs: check: 0 blocks used by 0 files and 0 directories; all accounted for",
        "[pass] fs: created an empty logs/app.log",
        "[cm] fault injection: killing fs",
        killing.as_str(),
        "[pass] fs: 400 records written under fault injection",
        "[pass] fs: every acknowledged record reads back",
        "[pass] fs: the file is 25600 bytes",
        "[pass] fs: a 280000-byte file (through its indirect block) reads back",
        "[pass] fs: truncated to 10000 and written at 20000: 20004 bytes, zeros between",
        "[pass] fs: unlinking a 53248-byte file returned its 14 blocks; its handle is dead",
        "[pass] fs: a sparse 9004096-byte file through the double indirect block: every piece reads back, the holes read as zeros, 10 blocks used",
        "[pass] fs: cut to 4300100 bytes and written past the end again; unlinked, every block came back",
        "[pass] fs: a/b/c/f: exclusive create refused",
        "[pass] fs: renamed a/b/c/f to a/g (the same file); a cannot move into itself",
        "[pass] fs: a non-empty directory stays; a lists b and g, then g alone",
        "[pass] fs: 600 files in one directory (ten blocks of entries, through its indirect block) listed, then removed, every inode back",
        "[pass] fs: 9 symbolic links made; relative, absolute, through a directory, with .. and chained, each opens links/dir/target",
        "[pass] fs: a target climbing past the root stays in the container",
        "[pass] fs: a loop of links and NOFOLLOW answer TooManyLinks; an exclusive create finds the name taken",
        "[pass] fs: READLINK gives the target (and refuses a file); a name taken is refused, the same link again is not",
        "[pass] fs: creating through a dangling link makes links/dir/made-through-a-link",
        "[pass] fs: unlinking a link leaves its target; a renamed link keeps its target; links list as links",
        "[pass] fs: ring: 376 requests, 15 in flight, every write acknowledged and read back",
        "fs: ring: ",
        "[pass] fs: record 400 and a rename of a/g to g2 acknowledged; cutting the power",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("filesystem test (first boot)", &out, &steps)?;
    // Three load clients beside it: calls waiting at once share a commit.
    let loads = out
        .matches("[pass] fs load: 120 records written alongside the other clients, every one read back")
        .count();
    let grouped = out
        .rfind("fs: group commit: ")
        .map(|i| out[i..].lines().next().unwrap_or_default());
    let Some(grouped) = grouped.filter(|_| loads == 3) else {
        return Err(format!(
            "filesystem test: {loads} of 3 load clients read their records back; group commit {}",
            if out.contains("fs: group commit: ") { "seen" } else { "never answered two requests at once" }
        ));
    };
    println!("== {}", grouped.trim_start_matches(|c| c != 'f'));
    let kills = out.matches("[cm] fault injection: killing").count();
    // Kills land in the later phases too (the tree, renames, unlinks).
    let later = out
        .find("[pass] fs: the file is 25600 bytes")
        .map_or(0, |i| {
            out[i..].matches("[cm] fault injection: killing fs").count()
        });
    if kills < 8 || later < 2 {
        return Err(format!(
            "filesystem test: {kills} kills, {later} of the server after the appends; want 8 and 2"
        ));
    }
    let replays = out.matches("replayed a committed transaction").count();
    let checks = out.matches("all accounted for").count();
    println!(
        "== {kills} services killed under load ({later} of the server after the appends); {replays} mounts replayed the journal; {checks} mount checks passed"
    );
    println!("== filesystem test, second boot: {}", second.path.display());
    let out = run_to_exit(&second, Duration::from_secs(60))?;
    let steps = [
        "fs: mounted in",
        "all accounted for",
        "[pass] fs other: another component's logs/app.log is not in its container, which is empty",
        "[pass] fs other: its own logs/app.log is a separate file, alone in its tree",
        "[pass] fs: after the power cut logs/app.log is 25664 bytes",
        "[pass] fs: all 401 acknowledged records survived",
        "[pass] fs: the last rename survived: g2 is there, a/g is not; the root lists 7 entries",
        "[pass] fs: symbolic links survived the power cut",
        "symbolic links; all accounted for",
        "[pass] fs: ring.log survived: 307200 bytes",
        "[pass] fs: ring, no faults: 300 reads with",
        "[pass] fs: data/big survived: 20004 bytes",
        "[cm] client asked to shut down (pass)",
    ];
    // The two clients run side by side: their lines interleave.
    for step in steps {
        check_log("filesystem test (second boot)", &out, &[step])?;
    }
    if out.contains("fs: formatting") {
        return Err("filesystem test: the second boot formatted the disk".into());
    }
    println!("== filesystem test passed ({}, {driver})", arch.name());
    Ok(())
}

/// Finds `steps` in `out` in order, as far as order means anything: each
/// thread's lines (tagged `[tN]`; the kernel's own are untagged) come in
/// the order it printed them, but on several CPUs lines of different
/// threads interleave as they run. So each step must come after the
/// previous step of the same thread. Empty steps are skipped. Returns the
/// first step not found.
fn find_in_order<'a>(out: &str, steps: &[&'a str]) -> Result<(), &'a str> {
    // The thread tag of the line holding byte `i`.
    let tag = |i: usize| -> &str {
        let start = out[..i].rfind('\n').map_or(0, |n| n + 1);
        let line = &out[start..];
        match line.strip_prefix("[t") {
            Some(rest) => match rest.find(']') {
                Some(e) if e > 0 && rest[..e].bytes().all(|b| b.is_ascii_digit()) => {
                    &line[..e + 3]
                }
                _ => "",
            },
            None => "",
        }
    };
    let mut cursors: std::collections::HashMap<&str, usize> = Default::default();
    for &step in steps {
        if step.is_empty() {
            continue;
        }
        let found = out.match_indices(step).find(|&(i, _)| {
            let t = tag(i);
            i >= cursors.get(t).copied().unwrap_or(0)
        });
        match found {
            Some((i, _)) => {
                cursors.insert(tag(i), i + step.len());
            }
            None => return Err(step),
        }
    }
    Ok(())
}

/// Checks `steps` appear in `out` in order, and no failure markers.
fn check_log(what: &str, out: &str, steps: &[&str]) -> Result<(), String> {
    if let Err(step) = find_in_order(out, steps) {
        return Err(format!("{what}: missing (in order) {step:?}"));
    }
    for bad in ["[fail]", "could not", "panic", "check FAILED"] {
        if out.contains(bad) {
            return Err(format!("{what}: log contains {bad:?}"));
        }
    }
    Ok(())
}

/// The port the network test's client sends UDP to (on the gateway, which
/// QEMU's user-mode network passes to the host's loopback).
const ECHO_PORT: u16 = 47001;

/// Boots `boot/net.manifest` on QEMU's user-mode network while a thread
/// here echoes UDP datagrams back, and checks that every ping and every
/// datagram came back right while the injector killed the network server
/// and the virtio-net driver.
/// The port xtask answers DNS on in the network test, reached from the
/// guest at the gateway.
const DNS_PORT: u16 = 47053;

/// The network test's DNS answer to a query for `name` (lower case, no
/// final dot): records `(owner, type, TTL, data)` (A, AAAA or CNAME), or
/// none for a name that does not exist.
fn dns_records(name: &str) -> Option<Vec<(String, u16, u32, Vec<u8>)>> {
    let a = |owner: &str, ttl: u32, ip: [u8; 4]| (owner.to_string(), 1u16, ttl, ip.to_vec());
    // 2001:db8::`last`.
    let aaaa = |owner: &str, last: u8| {
        let mut ip = vec![0x20, 0x01, 0x0d, 0xb8];
        ip.resize(16, 0);
        ip[15] = last;
        (owner.to_string(), 28u16, 60, ip)
    };
    Some(match name {
        "www.superior.test" => vec![a(name, 60, [192, 0, 2, 10]), aaaa(name, 0x10)],
        "alias.superior.test" => vec![
            (name.to_string(), 5, 60, dns_name("www.superior.test")),
            a("www.superior.test", 60, [192, 0, 2, 10]),
            aaaa("www.superior.test", 0x10),
        ],
        "v6only.superior.test" => vec![aaaa(name, 0x66)],
        // Records other than addresses. A TXT record is character
        // strings, each a length and its bytes; the second has two.
        "txt.superior.test" | "alias-txt.superior.test" => {
            let txt = |strings: &[&str]| {
                let mut d = Vec::new();
                for s in strings {
                    d.push(s.len() as u8);
                    d.extend_from_slice(s.as_bytes());
                }
                ("txt.superior.test".to_string(), 16u16, 120, d)
            };
            let mut v = vec![txt(&["v=spf1 -all"]), txt(&["hello ", "world"])];
            if name != "txt.superior.test" {
                v.insert(0, (name.to_string(), 5, 60, dns_name("txt.superior.test")));
            }
            v
        }
        // Too much for a UDP answer (512 bytes): six TXT records of one
        // 200-byte string each, which go over TCP.
        "big.superior.test" => (0..6usize)
            .map(|i| {
                let mut d = vec![200u8];
                d.extend((0..200usize).map(|j| b'a' + ((i * 7 + j) % 26) as u8));
                (name.to_string(), 16u16, 60, d)
            })
            .collect(),
        "superior.test" => {
            // Mail exchangers: a preference and a host, the first host's
            // name ending in a compression pointer to the question's.
            let mut mx1 = vec![0, 10, 3, b'm', b'x', b'1', 0xc0, 12];
            mx1.shrink_to_fit();
            let mut mx2 = vec![0, 20];
            mx2.extend(dns_name("mx2.superior.test"));
            vec![
                (name.to_string(), 15, 300, mx1),
                (name.to_string(), 15, 300, mx2),
                (name.to_string(), 2, 300, dns_name("ns1.superior.test")),
            ]
        }
        "_sip._tcp.superior.test" => {
            // Priority 0, weight 5, port 5060.
            let mut srv = vec![0, 0, 0, 5, 0x13, 0xc4];
            srv.extend(dns_name("sip.superior.test"));
            vec![(name.to_string(), 33, 60, srv)]
        }
        "10.2.0.192.in-addr.arpa" => {
            vec![(name.to_string(), 12, 60, dns_name("www.superior.test"))]
        }
        "cached.superior.test" => vec![a(name, 300, [192, 0, 2, 20])],
        "short.superior.test" => vec![a(name, 1, [192, 0, 2, 30])],
        _ => {
            let k: u16 = name.strip_prefix('n')?.strip_suffix(".superior.test")?.parse().ok()?;
            vec![a(name, 60, [198, 51, (k >> 8) as u8, k as u8])]
        }
    })
}

/// `name` in DNS wire form.
fn dns_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

/// Answers one DNS query (`q`): the response, and the name asked.
fn dns_answer(q: &[u8]) -> Option<(Vec<u8>, String)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    while q[at] != 0 {
        let n = q[at] as usize;
        labels.push(String::from_utf8_lossy(q.get(at + 1..at + 1 + n)?).to_lowercase());
        at += 1 + n;
    }
    let question = q.get(12..at + 5)?;
    let qtype = u16::from_be_bytes([q[at + 1], q[at + 2]]);
    let name = labels.join(".");
    let records = dns_records(&name);
    let answers: Vec<_> = records
        .iter()
        .flatten()
        // The type asked for, and the CNAMEs leading to it.
        .filter(|r| r.1 == qtype || r.1 == 5)
        .collect();
    let mut r = Vec::new();
    r.extend_from_slice(&q[0..2]);
    // A response, recursion available; NXDOMAIN for an unknown name.
    r.extend_from_slice(&[0x81, if records.is_none() { 0x83 } else { 0x80 }]);
    r.extend_from_slice(&[0, 1]);
    r.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(question);
    for (owner, kind, ttl, data) in answers {
        // The question's name by a compression pointer, others in full.
        if *owner == name {
            r.extend_from_slice(&[0xc0, 12]);
        } else {
            r.extend_from_slice(&dns_name(owner));
        }
        r.extend_from_slice(&kind.to_be_bytes());
        r.extend_from_slice(&[0, 1]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
    }
    Some((r, name))
}

/// The host's TCP echo for the guest (`net-test`, `tcp-test`), a port
/// nothing listens on, and the port forwarded to the TCP test's listener.
const TCP_ECHO_PORT: u16 = 47002;
const TCP_FORWARD_PORT: u16 = 47004;

/// Byte `j` of TCP stream `k`, as the guest's test client makes them.
fn tcp_byte(k: u64, j: u64) -> u8 {
    (k.wrapping_mul(0x9e37) ^ j.wrapping_mul(13) ^ j >> 9) as u8
}

/// Echoes TCP connections to `TCP_ECHO_PORT` until `stop`: what a
/// connection sends comes back, and when it shuts down, so does the echo.
/// Counts the bytes echoed.
fn tcp_echo_server(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    echoed: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<std::thread::JoinHandle<()>, String> {
    use std::io::Read;
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::Ordering;
    let mut ls = Vec::new();
    for host in ["127.0.0.1", "::1"] {
        let l = TcpListener::bind((host, TCP_ECHO_PORT))
            .map_err(|e| format!("binding the TCP echo port {TCP_ECHO_PORT} on {host}: {e}"))?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        ls.push(l);
    }
    Ok(std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let mut accepted = None;
            for l in &ls {
                if let Ok(a) = l.accept() {
                    accepted = Some(a);
                    break;
                }
            }
            match accepted.ok_or(()) {
                Ok((mut s, _)) => {
                    let echoed = echoed.clone();
                    std::thread::spawn(move || {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(scaled(Duration::from_secs(30))));
                        let mut buf = [0u8; 16384];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) => {
                                    let _ = s.shutdown(Shutdown::Write);
                                    break;
                                }
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                    echoed.fetch_add(n as u64, Ordering::Relaxed);
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }))
}

/// Connects `n` times, one after another, to the guest's listener through
/// QEMU's forwarding: each sends `len` bytes of
/// stream 1000 + its number,
/// shuts down, and must get them all back. Connections QEMU accepted
/// before the guest listened come to nothing, and are made again. Returns
/// the connections echoed right.
fn tcp_inbound(n: u64, len: u64, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> u64 {
    use std::io::Read;
    use std::net::{Shutdown, TcpStream};
    use std::sync::atomic::Ordering;
    let mut done = 0;
    while done < n && !stop.load(Ordering::Relaxed) {
        let k = 1000 + done;
        let to = ("127.0.0.1", TCP_FORWARD_PORT);
        let Ok(mut s) = TcpStream::connect(to) else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        let _ = s.set_read_timeout(Some(scaled(Duration::from_secs(20))));
        let data: Vec<u8> = (0..len).map(|j| tcp_byte(k, j)).collect();
        let writer = s.try_clone().map(|mut w| {
            let data = data.clone();
            std::thread::spawn(move || {
                let ok = w.write_all(&data).is_ok();
                let _ = w.shutdown(Shutdown::Write);
                ok
            })
        });
        let mut back = Vec::new();
        let read = s.read_to_end(&mut back).is_ok();
        let wrote = writer.map(|w| w.join().unwrap_or(false)).unwrap_or(false);
        if read && wrote && back == data {
            done += 1;
        } else {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    done
}

/// Boots `boot/tcp.manifest`: the network server drops one TCP segment in
/// 20 each way; the client is refused by a closed port, has 100,000
/// bytes echoed by the host, and echoes three connections the host makes
/// to it (each 30,000 bytes, more than its window).
fn tcp_test(arch: Arch) -> Result<(), String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let img = image_with(false, arch, "tcp")?;
    let stop = Arc::new(AtomicBool::new(false));
    let echoed = Arc::new(AtomicU64::new(0));
    let echo = tcp_echo_server(stop.clone(), echoed.clone())?;
    let inbound = {
        let stop = stop.clone();
        std::thread::spawn(move || tcp_inbound(3, 30_000, stop))
    };
    println!("== TCP test on {}", img.path.display());
    let out = run_to_exit(&img, Duration::from_secs(180));
    stop.store(true, Ordering::Relaxed);
    let _ = echo.join();
    let served = inbound.join().unwrap_or(0);
    let out = out?;
    let steps = [
        "virtio-net: ready:",
        "net: leased 10.0.3.30/24",
        "[pass] tcp: this host is 10.0.3.30",
        "[pass] tcp: a connection to a closed port of this host's is refused, through the loopback",
        "[pass] tcp: 100000 bytes echoed by the host with one segment in 20 dropped each way, every byte right",
        "[pass] tcp: 14 connections at once echoed by the host, 20000 bytes each, every byte right",
        "[pass] tcp: listening on port 8080, which a second listener cannot take",
        "[pass] tcp: 3 connections from the host accepted, 90000 bytes checked and echoed back, every byte right",
        "[pass] tcp: a connection between two sockets of this host's carried 20000 bytes each way, every byte right",
        "[pass] tcp: over IPv6, a connection to a closed port of this host's is refused",
        "[pass] tcp: over IPv6, 50000 bytes echoed by the host with one segment in 20 dropped each way, every byte right",
        "[pass] tcp: over IPv6, a connection between two sockets of this host's carried 20000 bytes each way, every byte right, the accepted end's peer",
        "segments sent again,",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("TCP test", &out, &steps)?;
    if served != 3 {
        return Err(format!("TCP test: the host got {served} of its 3 connections echoed back right"));
    }
    println!(
        "== the host echoed {} bytes and had 3 connections echoed back",
        echoed.load(Ordering::Relaxed)
    );
    println!("== TCP test passed ({})", arch.name());
    Ok(())
}

/// The network test, with the native virtio driver (`net`) or with
/// Linux's 8139cp driver in the Linux Driver Environment (`lde`).
/// The Wi-Fi test: the virtio-net driver as a simulated radio hosting the
/// station, the access point here (`wifi_ap`). The client has the radio
/// join the network; the station must find it, authenticate, associate
/// and finish the 4-way handshake, and then the network server lease an
/// address by DHCP (its answers broadcast, under the group key), ping the
/// gateway and have it echo UDP datagrams, some in fragments, every frame
/// sealed with CCMP both ways.
fn wifi_test(arch: Arch) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let img = image_with(false, arch, "wifi")?;
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(wifi_ap::Seen::default());
    let ap = wifi_ap::start(stop.clone(), seen.clone())?;
    println!("== Wi-Fi test on {}", img.path.display());
    let out = run_to_exit(&img, Duration::from_secs(120));
    stop.store(true, Ordering::Relaxed);
    let _ = ap.join();
    let out = out?;
    check_log(
        "Wi-Fi test",
        &out,
        &[
            match arch {
                Arch::X86_64 => "[ok] entropy: seeded from RDSEED and the cycle counter's jitter",
                Arch::Aarch64 => "[ok] entropy: seeded from RNDR and the cycle counter's jitter",
            },
            "virtio-net: ready as a Wi-Fi radio:",
            "[pass] wifi: a page of its own",
            "[pass] wifi: the kernel gives random bytes, a fresh 32 at every draw",
            "[pass] wifi: the radio starts with no network (link 0)",
            "virtio-net: wifi: surveying the networks in range",
            "virtio-net: wifi: survey done: 3 networks in range",
            "[pass] wifi: a survey finds the 3 networks in range, strongest first",
            "[pass] wifi: a second scan during a survey is refused (in use)",
            "[pass] wifi: surveying joined nothing",
            "[pass] wifi: a passphrase under 8 characters is refused",
            "[pass] wifi: the radio is told to join \"superior-test\"",
            "virtio-net: wifi: scanning for \"superior-test\"",
            "virtio-net: wifi: found \"superior-test\" at 02:57:49:46:49:01 (WPA2-PSK, CCMP); authenticating",
            "virtio-net: wifi: associating",
            "virtio-net: wifi: associated; 4-way handshake",
            "virtio-net: wifi: keyed, link up: frames sealed with CCMP",
            "[pass] wifi: joined and keyed in",
            "BSSID 02:57:49:46:49:01",
            "net: leased 10.0.5.30/24 from 10.0.5.1 via 10.0.5.1",
            "[pass] wifi: leased 10.0.5.30 (netmask /24) over Wi-Fi, the gateway 10.0.5.1",
            "[pass] wifi: 10 of 10 pings to the gateway answered, every byte right",
            "[pass] wifi: 40 of 40 UDP datagrams echoed by the gateway, every byte right (",
            "virtio-net: wifi: pairwise keys renewed (1 so far)",
            "virtio-net: wifi: group key renewed (1 so far)",
            "[pass] wifi: the keys were renewed under way,",
            "[pass] wifi: a survey while linked finds the same networks, and the link stays up",
            "[pass] wifi: the radio is told to join \"superior-wpa3\"",
            "virtio-net: wifi: found \"superior-wpa3\" at 02:57:49:46:49:03 (WPA3-SAE, CCMP); authenticating by SAE (hash-to-element)",
            "virtio-net: wifi: keyed, link up: frames sealed with CCMP",
            "[pass] wifi: joined by SAE and keyed in",
            "[pass] wifi: 10 of 10 pings answered over WPA3, the link up through a forged deauthentication",
        ],
    )?;
    if !out.contains("virtio-net: wifi: ignored an unprotected deauthentication (management frames are protected)") {
        return Err("Wi-Fi test: the station did not report ignoring the forged deauthentication".into());
    }
    // Both to every station (the one with no MMIE, then the one with a
    // wrong MIC; reported once or twice, as they arrive together or not).
    if !out.contains("virtio-net: wifi: ignored a deauthentication to every station: a wrong MIC under BIP (2 so far)") {
        return Err("Wi-Fi test: the station did not report ignoring both deauthentications to every station (BIP)".into());
    }
    if out.contains("[fail]") {
        return Err("Wi-Fi test: a check failed".into());
    }
    let (from, to) = (seen.from_station.load(Ordering::Relaxed), seen.to_station.load(Ordering::Relaxed));
    let (dhcp, refused) = (seen.dhcp.load(Ordering::Relaxed), seen.refused.load(Ordering::Relaxed));
    let (rekeys, group_rekeys, arp) = (
        seen.rekeys.load(Ordering::Relaxed),
        seen.group_rekeys.load(Ordering::Relaxed),
        seen.arp_answers.load(Ordering::Relaxed),
    );
    println!(
        "== access point: station keyed, {from} frames from it and {to} to it under CCMP, {dhcp} DHCP answers broadcast under the group key, {refused} frames refused"
    );
    println!(
        "== access point: keys renewed {rekeys} times pairwise and {group_rekeys} times the group key; the station answered {arp} broadcast ARP requests sent under a new group key"
    );
    if !seen.keyed.load(Ordering::Relaxed) || from == 0 || to == 0 || dhcp < 2 || refused != 0 {
        return Err("Wi-Fi test: the access point did not see the station keyed and carrying frames".into());
    }
    if rekeys == 0 || group_rekeys == 0 || arp == 0 {
        return Err("Wi-Fi test: the keys were not renewed, or the station did not answer under a new group key".into());
    }
    let (wpa3_from, forged, wpa3_refused) = (
        seen.wpa3_from_station.load(Ordering::Relaxed),
        seen.forged_deauths.load(Ordering::Relaxed),
        seen.wpa3_refused.load(Ordering::Relaxed),
    );
    println!(
        "== WPA3 access point: station keyed by SAE ({}, after {} anti-clogging token asked for), {wpa3_from} frames from it, {forged} forged deauthentications sent (one to the station, two to every station), {wpa3_refused} frames refused",
        if seen.wpa3_h2e.load(Ordering::Relaxed) { "hash-to-element" } else { "hunting and pecking" },
        seen.wpa3_tokens.load(Ordering::Relaxed)
    );
    if !seen.wpa3_keyed.load(Ordering::Relaxed) || !seen.wpa3_h2e.load(Ordering::Relaxed) || seen.wpa3_tokens.load(Ordering::Relaxed) == 0 || wpa3_from == 0 || forged == 0 || wpa3_refused != 0 {
        return Err("Wi-Fi test: the WPA3 access point did not see the station keyed by SAE and carrying frames".into());
    }
    println!("== Wi-Fi test passed ({})", arch.name());
    Ok(())
}

fn net_test(arch: Arch, manifest: &str) -> Result<(), String> {
    net_test_on(image_with(false, arch, manifest)?, manifest)
}

/// As [`net_test`], on an image already built for `manifest` (a UEFI one,
/// say).
fn net_test_on(img: Image, manifest: &str) -> Result<(), String> {
    use std::collections::HashMap;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    let lde = linux_nic(manifest).map(|l| l.0);
    let stop = Arc::new(AtomicBool::new(false));
    let echoed = Arc::new(AtomicU64::new(0));
    // UDP echoes over IPv4 and IPv6 (QEMU sends the guest's datagrams to
    // its gateway to the host's loopback, ::1 for IPv6).
    let mut echoes = Vec::new();
    for host in ["127.0.0.1", "::1"] {
        let socket = UdpSocket::bind((host, ECHO_PORT))
            .map_err(|e| format!("binding the echo port {ECHO_PORT} on {host}: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| e.to_string())?;
        let (stop, echoed) = (stop.clone(), echoed.clone());
        echoes.push(std::thread::spawn(move || {
            // The largest datagram: the guest's go up to 65,507 bytes.
            let mut buf = vec![0u8; 65_536];
            while !stop.load(Ordering::Relaxed) {
                if let Ok((n, from)) = socket.recv_from(&mut buf) {
                    if socket.send_to(&buf[..n], from).is_ok() {
                        echoed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    // A DNS server for the resolver, counting the queries for each name.
    let resolver = UdpSocket::bind(("127.0.0.1", DNS_PORT))
        .map_err(|e| format!("binding the DNS port {DNS_PORT}: {e}"))?;
    resolver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let asked = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let answering = {
        let (stop, asked) = (stop.clone(), asked.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop.load(Ordering::Relaxed) {
                if let Ok((n, from)) = resolver.recv_from(&mut buf) {
                    if let Some((mut r, name)) = dns_answer(&buf[..n]) {
                        *asked.lock().unwrap().entry(name).or_default() += 1;
                        if r.len() > 512 {
                            // Too long for UDP: the header and the question,
                            // marked truncated (TC), with no records.
                            let question = 12 + buf[12..n].iter().position(|&b| b == 0).unwrap_or(0) + 5;
                            r.truncate(question.min(r.len()));
                            r[2] |= 0x02;
                            r[6..8].copy_from_slice(&[0, 0]);
                        }
                        let _ = resolver.send_to(&r, from);
                    }
                }
            }
        })
    };
    // The same server over TCP (RFC 7766): each message has its length
    // before it. Its queries are counted under `tcp:<name>`.
    let tcp_resolver = std::net::TcpListener::bind(("127.0.0.1", DNS_PORT))
        .map_err(|e| format!("binding the DNS port {DNS_PORT} for TCP: {e}"))?;
    tcp_resolver.set_nonblocking(true).map_err(|e| e.to_string())?;
    let answering_tcp = {
        let (stop, asked) = (stop.clone(), asked.clone());
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            while !stop.load(Ordering::Relaxed) {
                let Ok((mut c, _)) = tcp_resolver.accept() else {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                };
                let _ = c.set_nonblocking(false);
                let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
                let mut len = [0u8; 2];
                if c.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if c.read_exact(&mut q).is_err() {
                    continue;
                }
                if let Some((r, name)) = dns_answer(&q) {
                    *asked.lock().unwrap().entry(format!("tcp:{name}")).or_default() += 1;
                    let mut out = (r.len() as u16).to_be_bytes().to_vec();
                    out.extend(r);
                    let _ = c.write_all(&out);
                }
            }
        })
    };
    let tcp_echoed = Arc::new(AtomicU64::new(0));
    let tcp_echo = tcp_echo_server(stop.clone(), tcp_echoed.clone())?;
    println!("== network test on {}", img.path.display());
    let out = run_to_exit(&img, Duration::from_secs(180));
    stop.store(true, Ordering::Relaxed);
    for e in echoes {
        let _ = e.join();
    }
    let _ = tcp_echo.join();
    let _ = answering.join();
    let _ = answering_tcp.join();
    let out = out?;
    // The Linux driver's own words, through the environment's printk.
    let linux: &[&str] = match lde {
        Some("8139cp") => &[
            "pci: 00:",
            "10ec:8139 class 020000",
            "lde 8139cp: 10ec:8139 at 00:",
            "lde 8139cp: 8139cp: 8139cp: 10/100 PCI Ethernet driver v1.3 (Mar 22, 2004)",
            "lde 8139cp: eth0: RTL-8139C+ at 0x",
            "52:54:00:12:34:56, IRQ",
            "lde 8139cp: the device's legacy interrupt line (wire",
            "lde 8139cp: eth0: link up, 100Mbps, full-duplex",
            "lde 8139cp: Linux's 8139cp driver runs the interface: MAC 52:54:00:12:34:56, link up",
            "lde 8139cp: frame rings started",
        ],
        Some(_) => &[
            "pci: 00:",
            "8086:1229 class 020000",
            "lde e100: 8086:1229 at 00:",
            "lde e100: e100: Intel(R) PRO/100 Network Driver",
            "lde e100: eth0: addr 0x",
            "52:54:00:12:34:56",
            "lde e100: the device's legacy interrupt line (wire",
            "lde e100: Linux's e100 driver runs the interface: MAC 52:54:00:12:34:56",
            "lde e100: frame rings started",
            "lde e100: eth0: NIC Link is Up 100 Mbps Full Duplex",
        ],
        None => &[],
    };
    check_log("Linux Driver Environment test", &out, linux)?;
    // The RTL-8139 is in slot 27. On x86-64 that is a q35 chipset slot,
    // whose INTA# _PRT routes to GSI 16, the fifth GSI it names: not where
    // four rotated wires would put it (the fourth line, GSI 23). On
    // AArch64 the device tree's interrupt-map (under its mask) or ACPI's
    // _PRT sends it to the fourth of virt's four, interrupt 38. The kernel
    // routes every slot's pins, and the bus server asks it which line the
    // card's pin reaches.
    if lde == Some("8139cp") {
        let slot = format!("lde 8139cp: 10ec:8139 at 00:{LDE_SLOT:02x}.0 opened");
        let (routes, wire) = match img.arch {
            Arch::X86_64 => (
                "[ok] PCI interrupt pins through the I/O APIC, as _PRT says: 128 pins on 8 lines, at GSIs 20, 21, 22, 23, 16, 17, 18, 19".to_string(),
                "lde 8139cp: the device's legacy interrupt line (wire 4) is the driver's",
            ),
            Arch::Aarch64 => (
                format!(
                    "[ok] PCI interrupt pins through the GIC, as {} says: 128 pins on 4 lines, at interrupts 35, 36, 37, 38 (level, active high)",
                    if img.acpi { "_PRT" } else { "the device tree's interrupt-map" }
                ),
                "lde 8139cp: the device's legacy interrupt line (wire 3) is the driver's",
            ),
        };
        check_log("Linux Driver Environment test", &out, &[&routes, &slot, wire])?;
    }
    let ready = lde.map(|d| format!("lde {d}: Linux's {d} driver runs"));
    let steps = [
        ready.as_deref().unwrap_or("virtio-net: ready:"),
        "net: ready: MAC",
        "net: leased 10.0.3.30/24 from 10.0.3.2 via 10.0.3.2, DNS 10.0.3.3, for 86400 s",
        "[pass] net: a page of its own",
        "[pass] net: this host is 10.0.3.30, the gateway 10.0.3.2",
        "[pass] net: netmask /24, DNS server 10.0.3.3,",
        "[cm] fault injection: killing",
        "net: lease kept: 10.0.3.30/24 via 10.0.3.2",
        "pings to 10.0.3.2 answered, every byte right",
        "UDP datagrams of 1 to 4000 bytes echoed by the host, every byte right",
        "UDP datagrams of 4097 to 65507 bytes echoed by the host, every byte right",
        "[pass] net: datagrams of 5000, 40000 and 65507 bytes sent to itself in fragments, and a 65507-byte ping of this host answered, every byte right",
        "datagrams reassembled from fragments,",
        "[pass] net: www.superior.test is 192.0.2.10",
        "[pass] net: alias.superior.test, a CNAME for www, is 192.0.2.10",
        "[pass] net: www.superior.test's IPv6 address is 2001:db8::10, alias's too, and the second answer was cached",
        "[pass] net: cached.superior.test has no IPv6 address; v6only.superior.test has 2001:db8::66 and no IPv4 one",
        "[pass] net: big.superior.test's six 200-byte TXT records, too long for UDP, came over TCP, every byte right; superior.test's MX answered from the cache",
        "[pass] net: DNS records: superior.test's MX are mx1 (10) and mx2 (20), its NS ns1, its SIP SRV sip:5060; txt and its alias have two TXT; 192.0.2.10's PTR is www",
        "[pass] net: nowhere.superior.test does not exist, and no..dots is no name",
        "[pass] net: cached.superior.test resolved 20 times,",
        "[pass] net: short.superior.test (TTL 1 s) asked of the server again after 1.5 s",
        "names resolved under fault injection, every address right",
        "TCP connections echoed",
        "bytes through the host under fault injection, every byte right",
        "[pass] net: IPv6: this host is fd00:3::5054:ff:fe12:3456/64, the router fe80::",
        "pings to fd00:3::2 over IPv6 answered, every byte right",
        "UDP datagrams of 1 to 1452 bytes over IPv6 echoed by the host, every byte right",
        "UDP datagrams of 1453 to 4000 bytes sent to itself over IPv6, in fragments, every byte right",
        "[pass] net: datagrams of 4097, 30000 and 65507 bytes sent to itself over IPv6, and a 20000-byte IPv6 ping of this host answered, every byte right",
        "TCP connections over IPv6 echoed",
        "UDP datagrams echoed through the client's ring, every byte right:",
        "requests from clients' rings since it last started",
        "frames through the rings with the driver,",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("network test", &out, &steps)?;
    if !out.contains("net: 10.0.3.2 is at") {
        return Err("network test: the gateway's MAC address was never learned".into());
    }
    // IPv6's addresses passed duplicate detection once each, in spite of
    // the restarts, and were kept after.
    for line in [
        "net: IPv6 link-local fe80::5054:ff:fe12:3456",
        "net: IPv6 address fd00:3::5054:ff:fe12:3456/64 via fe80::",
        "net: IPv6 kept: fd00:3::5054:ff:fe12:3456/64 via fe80::",
        "net: IPv6 DNS fd00:3::3 (DHCPv6)",
    ] {
        if !out.contains(line) {
            return Err(format!("network test: missing {line:?}"));
        }
    }
    let kills = |what: &str| {
        out.matches(&format!("[cm] fault injection: killing {what}\n"))
            .count()
            + out
                .matches(&format!("[cm] fault injection: killing {what}\r\n"))
                .count()
    };
    let nic = lde.map_or("virtio-net".to_string(), |d| format!("lde-{d}"));
    let (server, driver, resolver) = (kills("net"), kills(&nic), kills("dns"));
    // Kills land among the pings and the echoes, not only after them.
    let during = |what: &str| {
        out.find(what).map_or(0, |i| {
            out[..i].matches("[cm] fault injection: killing").count()
        })
    };
    let (by_pings, by_echoes) = (during("pings to 10.0.3.2"), during("echoed by the host"));
    let by_names = during("names resolved under fault injection");
    let by_tcp = during("bytes through the host under fault injection");
    // The resolver asked the host for a cached name once (once more per
    // restart in between at most), and for the 1 s one again.
    let asked = asked.lock().unwrap().clone();
    let count = |name: &str| asked.get(name).copied().unwrap_or(0);
    if count("tcp:big.superior.test") < 1 {
        return Err("network test: the host's DNS server was never asked over TCP".into());
    }
    if count("cached.superior.test") > 5 || count("short.superior.test") < 2 {
        return Err(format!(
            "network test: the host was asked for cached.superior.test {} times and short.superior.test {}; want at most 5 and at least 2",
            count("cached.superior.test"),
            count("short.superior.test")
        ));
    }
    if by_tcp < by_names + 10 {
        return Err(format!(
            "network test: {} kills while TCP connections were echoed; want 10",
            by_tcp - by_names
        ));
    }
    if resolver < 5 || by_names < by_echoes + 10 {
        return Err(format!(
            "network test: the resolver was killed {resolver} times, {} times while names were resolved; want 5 and 10",
            by_names - by_echoes
        ));
    }
    // A restarted server keeps its lease: it asks DHCP only once.
    let discovered = out.matches("net: leased ").count();
    let kept = out.matches("net: lease kept").count();
    let renewed = out.matches("net: lease renewed").count();
    if discovered != 1 || kept < 10 || renewed < 2 {
        return Err(format!(
            "network test: {discovered} leases from DISCOVER, {kept} kept across restarts, {renewed} renewals; want 1, 10 and 2"
        ));
    }
    if server < 10 || driver < 10 || by_pings < 5 || by_echoes < by_pings + 20 {
        return Err(format!(
            "network test: the server was killed {server} times and the driver {driver}, {by_pings} kills by the end of the pings and {by_echoes} by the end of the echoes; want 10, 10, 5 and 20 more"
        ));
    }
    println!(
        "== the server was killed {server} times, the driver {driver} and the resolver {resolver}; the host echoed {} datagrams and {} TCP bytes and answered {} DNS queries",
        echoed.load(Ordering::Relaxed),
        tcp_echoed.load(Ordering::Relaxed),
        asked.values().sum::<u32>()
    );
    println!("== network test passed ({})", img.arch.name());
    Ok(())
}

/// The port QEMU's monitor (QMP) listens on in the keyboard test.
const QMP_PORT: u16 = 47011;

/// The size the display test gives QEMU's bochs-display, which its EDID
/// reports as the preferred mode.
const SCREEN: (usize, usize) = (800, 600);
/// The patch the display client redraws in the first picture.
const PATCH: (usize, usize, usize, usize) = (100, 150, 320, 200);

/// The display client's test picture (user/testclient: `test_pixel`):
/// (red, green, blue) at (x, y) in phase `phase`.
fn test_pixel(x: usize, y: usize, phase: usize) -> [u8; 3] {
    [
        ((x + 64 * phase) & 0xff) as u8,
        ((y + 32 * phase) & 0xff) as u8,
        ((((x >> 3) ^ (y >> 3)) * 8 + 16 * phase) & 0xff) as u8,
    ]
}

/// What screenshot `k` must show: the first picture (phase 1, the patch
/// in phase 2), then the second (phase 3).
fn expected_pixel(k: usize, x: usize, y: usize) -> [u8; 3] {
    let (px, py, pw, ph) = PATCH;
    match k {
        0 if (px..px + pw).contains(&x) && (py..py + ph).contains(&y) => test_pixel(x, y, 2),
        0 => test_pixel(x, y, 1),
        _ => test_pixel(x, y, 3),
    }
}

/// Has QEMU's monitor write the screen to `path` (a PPM file).
fn screendump(path: &Path) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    let s = TcpStream::connect(("127.0.0.1", QMP_PORT)).map_err(|e| format!("QMP: {e}"))?;
    s.set_read_timeout(Some(scaled(Duration::from_secs(20)))).map_err(|e| e.to_string())?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    // Each answer is a line with "return" (or "error"); events come too.
    let mut answer = |r: &mut BufReader<TcpStream>| -> Result<String, String> {
        loop {
            line.clear();
            if r.read_line(&mut line).map_err(|e| format!("QMP: {e}"))? == 0 {
                return Err("QMP: the monitor hung up".into());
            }
            if line.contains("\"return\"") || line.contains("\"error\"") {
                return Ok(line.clone());
            }
        }
    };
    let file = path.to_string_lossy().replace('\\', "/");
    w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").map_err(|e| e.to_string())?;
    answer(&mut r)?;
    let cmd = format!("{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{file}\"}}}}\n");
    w.write_all(cmd.as_bytes()).map_err(|e| e.to_string())?;
    let a = answer(&mut r)?;
    if a.contains("\"error\"") {
        return Err(format!("QMP screendump: {}", a.trim()));
    }
    Ok(())
}

/// Checks screenshot `k`, a PPM file, pixel by pixel.
fn check_screenshot(path: &Path, k: usize) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    // "P6", width, height, the largest value, each followed by one
    // whitespace byte, then the pixels.
    let mut fields = Vec::new();
    let mut at = 0;
    while fields.len() < 4 && at < data.len() {
        while at < data.len() && data[at].is_ascii_whitespace() {
            at += 1;
        }
        let start = at;
        while at < data.len() && !data[at].is_ascii_whitespace() {
            at += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..at]).into_owned());
    }
    at += 1;
    let size = (fields.get(1).and_then(|f| f.parse().ok()), fields.get(2).and_then(|f| f.parse().ok()));
    if fields.first().map(String::as_str) != Some("P6") || size != (Some(SCREEN.0), Some(SCREEN.1)) {
        return Err(format!("screenshot {}: {:?}, not an {}x{} PPM", k + 1, fields, SCREEN.0, SCREEN.1));
    }
    let pixels = &data[at.min(data.len())..];
    if pixels.len() < SCREEN.0 * SCREEN.1 * 3 {
        return Err(format!("screenshot {}: {} bytes of pixels, too few", k + 1, pixels.len()));
    }
    let mut wrong = 0;
    let mut first = None;
    for y in 0..SCREEN.1 {
        for x in 0..SCREEN.0 {
            let i = (y * SCREEN.0 + x) * 3;
            let (have, want) = ([pixels[i], pixels[i + 1], pixels[i + 2]], expected_pixel(k, x, y));
            if have != want {
                wrong += 1;
                first.get_or_insert((x, y, have, want));
            }
        }
    }
    match first {
        None => Ok(format!(
            "screenshot {}: all {} pixels of the {}x{} screen are the picture's",
            k + 1,
            SCREEN.0 * SCREEN.1,
            SCREEN.0,
            SCREEN.1
        )),
        Some((x, y, have, want)) => Err(format!(
            "screenshot {}: {wrong} pixels wrong, the first at ({x}, {y}): {have:?}, not {want:?}",
            k + 1
        )),
    }
}

/// The desktop behind the windows (user/compositor: `desktop`).
fn desktop_pixel(x: usize, y: usize) -> [u8; 3] {
    if ((x >> 4) + (y >> 4)) & 1 == 0 { [0x28, 0x30, 0x40] } else { [0x30, 0x38, 0x48] }
}

/// A desktop client's window pixel at (x, y) of it (user/testclient:
/// `window_pixel`).
fn window_pixel(x: usize, y: usize, id: usize, phase: usize) -> [u8; 3] {
    [
        ((2 * x + 80 * id + 40 * phase) & 0xff) as u8,
        ((2 * y + 50 * id) & 0xff) as u8,
        (((x ^ y) + 30 * phase) & 0xff) as u8,
    ]
}

/// A window on a desktop screenshot: its number in the picture, where it
/// is, its size and phase. Listed back to front.
#[derive(Clone, Copy)]
struct ShownWindow {
    id: usize,
    at: (usize, usize),
    size: (usize, usize),
    phase: usize,
}

/// What each of the desktop test's screenshots must show.
fn desktop_pictures() -> Vec<Vec<ShownWindow>> {
    let a = ShownWindow { id: 0, at: (100, 100), size: (300, 200), phase: 0 };
    let b = ShownWindow { id: 1, at: (250, 180), size: (320, 240), phase: 0 };
    let moved = ShownWindow { at: (420, 300), ..b };
    vec![
        vec![a, b],
        vec![a, moved],
        vec![a, moved],
        vec![moved],
        vec![ShownWindow { phase: 1, ..moved }],
    ]
}

/// Reads a screenshot (a P6 PPM file of `SCREEN`'s size): its pixels.
fn read_screenshot(path: &Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut fields = Vec::new();
    let mut at = 0;
    while fields.len() < 4 && at < data.len() {
        while at < data.len() && data[at].is_ascii_whitespace() {
            at += 1;
        }
        let start = at;
        while at < data.len() && !data[at].is_ascii_whitespace() {
            at += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..at]).into_owned());
    }
    at += 1;
    let size = (fields.get(1).and_then(|f| f.parse().ok()), fields.get(2).and_then(|f| f.parse().ok()));
    if fields.first().map(String::as_str) != Some("P6") || size != (Some(SCREEN.0), Some(SCREEN.1)) {
        return Err(format!("{}: {:?}, not an {}x{} PPM", path.display(), fields, SCREEN.0, SCREEN.1));
    }
    let pixels = data[at.min(data.len())..].to_vec();
    if pixels.len() < SCREEN.0 * SCREEN.1 * 3 {
        return Err(format!("{}: {} bytes of pixels, too few", path.display(), pixels.len()));
    }
    Ok(pixels)
}

/// Checks desktop screenshot `k` pixel by pixel.
fn check_desktop(path: &Path, k: usize) -> Result<String, String> {
    check_windows(path, k + 1, &desktop_pictures()[k], None)
}

/// Checks screenshot `k` (from 1) pixel by pixel: the desktop, `windows`
/// over it back to front, and the pointer over everything if it is
/// shown.
fn check_windows(
    path: &Path,
    k: usize,
    windows: &[ShownWindow],
    pointer: Option<(usize, usize)>,
) -> Result<String, String> {
    let pixels = read_screenshot(path)?;
    let mut wrong = 0;
    let mut first = None;
    for y in 0..SCREEN.1 {
        for x in 0..SCREEN.0 {
            let mut want = desktop_pixel(x, y);
            for w in windows {
                if (w.at.0..w.at.0 + w.size.0).contains(&x) && (w.at.1..w.at.1 + w.size.1).contains(&y) {
                    want = window_pixel(x - w.at.0, y - w.at.1, w.id, w.phase);
                }
            }
            if let Some((px, py)) = pointer {
                if x >= px && y >= py && y - py < CURSOR.len() && x - px < CURSOR[0].len() {
                    match CURSOR[y - py].as_bytes()[x - px] {
                        b'#' => want = [0, 0, 0],
                        b'o' => want = [0xff, 0xff, 0xff],
                        _ => {}
                    }
                }
            }
            let i = (y * SCREEN.0 + x) * 3;
            let have = [pixels[i], pixels[i + 1], pixels[i + 2]];
            if have != want {
                wrong += 1;
                first.get_or_insert((x, y, have, want));
            }
        }
    }
    match first {
        None => Ok(format!(
            "screenshot {k}: all {} pixels are the desktop and its {} window{}{}",
            SCREEN.0 * SCREEN.1,
            windows.len(),
            if windows.len() == 1 { "" } else { "s" },
            pointer.map_or(String::new(), |(x, y)| format!(", the pointer at ({x}, {y})"))
        )),
        Some((x, y, have, want)) => Err(format!(
            "screenshot {k}: {wrong} pixels wrong, the first at ({x}, {y}): {have:?}, not {want:?}"
        )),
    }
}

/// Boots `boot/desktop.manifest`: the compositor over Linux's bochs
/// driver, with two clients' windows. At each picture the second client
/// announces, QEMU's monitor takes a screenshot and every pixel must be
/// the desktop's or the right window's: window B over A, B moved (what it
/// covered painted again), both made again after the compositor's
/// restart, A gone with its client, and B drawn anew after the display
/// driver's restart.
fn desktop_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "desktop")?;
    println!("== desktop test on {}", img.path.display());
    let shots: Arc<Mutex<Vec<Result<String, String>>>> = Arc::default();
    let markers: Vec<String> = (1..=desktop_pictures().len())
        .map(|k| format!("[pass] desktop: picture {k} on the screen"))
        .collect();
    let taken = shots.clone();
    let watched = markers.clone();
    let out = run_to_exit_watching(&img, Duration::from_secs(150), move |all| {
        let mut taken = taken.lock().unwrap();
        let k = taken.len();
        if k < watched.len() && all.contains(&watched[k]) {
            let path = root().join("target").join(format!("desktop-{}-{}.ppm", arch.name(), k + 1));
            let _ = std::fs::remove_file(&path);
            taken.push(screendump(&path).and_then(|()| check_desktop(&path, k)));
        }
    })?;
    let steps = [
        "compositor: ready: the desktop on a 800x600 screen",
        "[pass] desktop: 59 pages for a 300x200 window",
        "[pass] desktop: window A shown (window 0)",
        "[pass] desktop: 75 pages for a 320x240 window",
        "[pass] desktop: the screen is 800x600",
        "[pass] desktop: window A is on the screen",
        "[pass] desktop: another client's window cannot be moved, raised, destroyed or drawn (32 calls refused)",
        "[pass] desktop: picture 1 on the screen: window B over window A",
        "[pass] desktop: picture 2 on the screen: window B moved",
        "desktop: killing the compositor",
        "[cm] fault injection: killing compositor",
        "compositor: ready: the desktop on a 800x600 screen",
        "desktop: window A: the compositor restarted; making the window again",
        "[pass] desktop: window A made again after the compositor's restart",
        "[pass] desktop: picture 3 on the screen after the compositor's restart",
        "desktop: killing window A's client",
        "[cm] fault injection: killing first",
        "compositor: window 0 is gone with its client; taken off the screen",
        "[pass] desktop: picture 4 on the screen: window A gone with its client",
        "desktop: killing the display driver",
        "[cm] fault injection: killing lde-bochs",
        "compositor: the display lost the screen; lending it again",
        "compositor: the whole screen shown again (1 window)",
        "[pass] desktop: picture 5 on the screen after the display driver's restart",
        "desktop: done (0 failed)",
        "[cm] second asked to shut down (pass)",
    ];
    check_log("desktop test", &out, &steps)?;
    let shots = shots.lock().unwrap();
    if shots.len() != markers.len() {
        return Err(format!("desktop test: {} screenshots taken, want {}", shots.len(), markers.len()));
    }
    for s in shots.iter() {
        println!("== {}", s.clone()?);
    }
    println!("== desktop test passed ({})", arch.name());
    Ok(())
}

/// The pointer the compositor draws (user/compositor: `CURSOR`), its tip
/// at the top left: `#` black, `o` white, a space what is under it.
const CURSOR: [&str; 17] = [
    "#           ",
    "##          ",
    "#o#         ",
    "#oo#        ",
    "#ooo#       ",
    "#oooo#      ",
    "#ooooo#     ",
    "#oooooo#    ",
    "#ooooooo#   ",
    "#oooooooo#  ",
    "#ooooo##### ",
    "#oo#oo#     ",
    "#o# #oo#    ",
    "##  #oo#    ",
    "#    #oo#   ",
    "     #oo#   ",
    "      ##    ",
];

/// What each of the input test's screenshots must show: the windows,
/// back to front, and where the pointer is.
fn input_pictures() -> Vec<(Vec<ShownWindow>, (usize, usize))> {
    let a = ShownWindow { id: 0, at: (100, 100), size: (300, 200), phase: 0 };
    let b = ShownWindow { id: 1, at: (300, 200), size: (320, 240), phase: 0 };
    let a3 = ShownWindow { phase: 3, ..a };
    let b_at = |phase| ShownWindow { phase, ..b };
    let over_a = (150, 130);
    vec![
        (vec![a, b], over_a),
        (vec![b, a], over_a),
        (vec![b, a3], over_a),
        (vec![a3, b_at(1)], (700, 450)),
        (vec![a3, b_at(2)], over_a),
        (vec![b_at(3), a3], over_a),
        (vec![b_at(3), a3], TABLET_AT),
    ]
}

/// Where the input test's tablet puts the pointer: over window B alone.
const TABLET_AT: (usize, usize) = (460, 300);

/// The value of the tablet's axis (QEMU's 0..=0x7fff) that puts the
/// pointer at pixel `at` of `size`: the HID driver scales it to
/// 0..=0xffff over the axis's range, the compositor that to the screen.
fn tablet_value(at: usize, size: usize) -> u64 {
    (0..=0x7fffu64).find(|v| ((v * 0xffff / 0x7fff) * size as u64) >> 16 == at as u64).unwrap_or(0)
}

/// What the host does through QEMU's monitor at a step of the input test.
enum Act {
    /// Moves the mouse this far right and down.
    Move(i64, i64),
    /// Presses (true) or lets go of the left button.
    Button(bool),
    /// Types these letters on the keyboard.
    Type(&'static str),
    /// Presses and lets go of the key with this QEMU name ("left", "end"),
    /// or of keys joined by '+' ("shift+home"), held down in order and let
    /// go in reverse.
    Key(&'static str),
    /// Holds the key with this QEMU name down for this many milliseconds.
    Hold(&'static str, u64),
    /// Puts the tablet where it puts the pointer at this pixel.
    Tablet(usize, usize),
    /// Turns the wheel one step up (1) or down (-1).
    Wheel(i64),
    /// Takes screenshot `k` (from 1) and checks it.
    Shot(usize),
}

/// The input test's script: at each step, what must be in the output
/// first, then what the host does. The pointer starts in the middle of
/// the screen (400, 300) whenever the compositor starts, and every move
/// stays on the screen, so where it ends is known.
fn input_script() -> Vec<(Vec<&'static str>, Vec<Act>)> {
    use Act::*;
    vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "window B shown over window A, with the focus",
            ],
            // To (150, 130), over window A alone.
            vec![Move(-250, -170)],
        ),
        (vec!["the pointer came to (50, 30) (time 1)"], vec![Shot(1), Button(true), Button(false)]),
        (vec!["so it has the focus and is in front (time 1)"], vec![Shot(2), Type("abc")]),
        // To (500, 350), over window B alone.
        (vec!["typed \"abc\""], vec![Shot(3), Move(350, 220)]),
        // Pressed there, held to (700, 450), off window B, and let go.
        (vec!["window B: the pointer came to (200, 150)"], vec![Button(true), Move(200, 100), Button(false)]),
        (vec!["window B: held the pointer from"], vec![Type("d")]),
        (vec!["typed \"d\", the first key"], vec![Shot(4)]),
        // The compositor restarted: from (400, 300) to (150, 130) again.
        (vec!["window B made again after the compositor's restart"], vec![Type("e"), Move(-250, -170)]),
        (vec!["typed \"de\"", "the pointer came to (50, 30) (time 2)"], vec![Shot(5)]),
        (vec!["input subscribed again"], vec![Type("f")]),
        (vec!["typed \"def\""], vec![Button(true), Button(false)]),
        (vec!["picture 6 on the screen"], vec![Shot(6)]),
        // The tablet puts the pointer over window B, and the wheel turns.
        (vec!["window B got only the keys typed to it"], vec![Tablet(TABLET_AT.0, TABLET_AT.1)]),
        (vec!["the tablet put the pointer at (160, 100)"], vec![Wheel(1), Wheel(1)]),
        (vec!["the wheel turned 2 steps up"], vec![Wheel(-1)]),
        (vec!["picture 7 on the screen"], vec![Shot(7)]),
    ]
}

/// Sends QMP commands (one JSON object a line) through QEMU's monitor,
/// each answered before the next.
fn qmp(commands: &[String]) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    let s = TcpStream::connect(("127.0.0.1", QMP_PORT)).map_err(|e| format!("QMP: {e}"))?;
    s.set_read_timeout(Some(scaled(Duration::from_secs(20)))).map_err(|e| e.to_string())?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    let all = std::iter::once("{\"execute\":\"qmp_capabilities\"}".to_string()).chain(commands.iter().cloned());
    for c in all {
        w.write_all(c.as_bytes()).and_then(|()| w.write_all(b"\n")).map_err(|e| format!("QMP: {e}"))?;
        loop {
            line.clear();
            if r.read_line(&mut line).map_err(|e| format!("QMP: {e}"))? == 0 {
                return Err("QMP: the monitor hung up".into());
            }
            if line.contains("\"error\"") {
                return Err(format!("QMP: {} answered {}", c, line.trim()));
            }
            if line.contains("\"return\"") {
                break;
            }
        }
    }
    Ok(())
}

/// Does one act of the input test's script.
fn input_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let send = |events: String| format!("{{\"execute\":\"input-send-event\",\"arguments\":{{\"events\":[{events}]}}}}");
    match act {
        Act::Move(dx, dy) => qmp(&[send(format!(
            "{{\"type\":\"rel\",\"data\":{{\"axis\":\"x\",\"value\":{dx}}}}},{{\"type\":\"rel\",\"data\":{{\"axis\":\"y\",\"value\":{dy}}}}}"
        ))])?,
        Act::Button(down) => qmp(&[send(format!(
            "{{\"type\":\"btn\",\"data\":{{\"down\":{down},\"button\":\"left\"}}}}"
        ))])?,
        Act::Tablet(x, y) => qmp(&[send(format!(
            "{{\"type\":\"abs\",\"data\":{{\"axis\":\"x\",\"value\":{}}}}},{{\"type\":\"abs\",\"data\":{{\"axis\":\"y\",\"value\":{}}}}}",
            tablet_value(*x, SCREEN.0),
            tablet_value(*y, SCREEN.1)
        ))])?,
        Act::Wheel(steps) => {
            let button = if *steps > 0 { "wheel-up" } else { "wheel-down" };
            for down in [true, false] {
                qmp(&[send(format!(
                    "{{\"type\":\"btn\",\"data\":{{\"down\":{down},\"button\":\"{button}\"}}}}"
                ))])?;
            }
        }
        Act::Key(keys) => {
            let keys: Vec<&str> = keys.split('+').collect();
            let order = keys.iter().map(|k| (true, k)).chain(keys.iter().rev().map(|k| (false, k)));
            for (down, k) in order {
                qmp(&[send(format!(
                    "{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"{k}\"}}}}}}"
                ))])?;
                std::thread::sleep(Duration::from_millis(KEY_GAP_MS));
            }
        }
        Act::Hold(k, ms) => {
            for down in [true, false] {
                qmp(&[send(format!(
                    "{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"{k}\"}}}}}}"
                ))])?;
                std::thread::sleep(Duration::from_millis(if down { *ms } else { KEY_GAP_MS }));
            }
        }
        Act::Type(keys) => {
            for k in keys.chars() {
                let k = if k == ' ' { "spc".to_string() } else { k.to_string() };
                for down in [true, false] {
                    qmp(&[send(format!(
                        "{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"{k}\"}}}}}}"
                    ))])?;
                    std::thread::sleep(Duration::from_millis(KEY_GAP_MS));
                }
            }
        }
        Act::Shot(k) => {
            let path = root().join("target").join(format!("input-{}-{k}.ppm", arch.name()));
            let _ = std::fs::remove_file(&path);
            screendump(&path)?;
            let (windows, pointer) = &input_pictures()[k - 1];
            return check_windows(&path, *k, windows, Some(*pointer)).map(Some);
        }
    }
    // Long enough for the mouse to be polled, so separate acts are separate
    // reports.
    std::thread::sleep(Duration::from_millis(60));
    Ok(None)
}

/// Whether `all` holds what a script waits for: `what`, or with a prefix
/// `<n>x ` that many times.
fn script_ready(all: &str, what: &str) -> bool {
    match what.split_once("x ").and_then(|(n, rest)| Some((n.parse::<usize>().ok()?, rest))) {
        Some((n, rest)) => all.matches(rest).count() >= n,
        None => all.contains(what),
    }
}

/// Runs `img`, doing `script` through QEMU's monitor as its output comes
/// (`act` does each act): the output, and how many screenshots were taken
/// and checked.
fn run_script(
    img: &Image,
    arch: Arch,
    what: &'static str,
    script: Vec<(Vec<&'static str>, Vec<Act>)>,
    act: fn(&Act, Arch) -> Result<Option<String>, String>,
) -> Result<(String, usize), String> {
    let results: Arc<Mutex<(usize, Vec<Result<String, String>>)>> = Arc::default();
    let done = results.clone();
    let steps = script.len();
    let out = run_to_exit_watching(img, Duration::from_secs(180), move |all| {
        let mut done = done.lock().unwrap();
        while done.0 < script.len() && done.1.iter().all(Result::is_ok) {
            let (wait, acts) = &script[done.0];
            if !wait.iter().all(|w| script_ready(all, w)) {
                return;
            }
            for a in acts {
                match act(a, arch) {
                    Ok(Some(shot)) => done.1.push(Ok(shot)),
                    Ok(None) => {}
                    Err(e) => {
                        done.1.push(Err(e));
                        return;
                    }
                }
            }
            done.0 += 1;
        }
    });
    let (at, shots) = {
        let r = results.lock().unwrap();
        (r.0, r.1.clone())
    };
    for s in &shots {
        match s {
            Ok(s) => println!("== {s}"),
            Err(e) => return Err(format!("{what}: {e}")),
        }
    }
    let out = out?;
    if at != steps {
        return Err(format!("{what}: the script stopped at step {} of {steps}", at + 1));
    }
    Ok((out, shots.len()))
}

/// A window of the window style test's screenshots: its number, where it
/// is, its size, and its style. Listed back to front.
#[derive(Clone, Copy)]
struct StyledWindow {
    id: usize,
    at: (usize, usize),
    size: (usize, usize),
    /// Translucent: its pixel at (x, y) is as opaque as `translucence`.
    alpha: bool,
    decorated: bool,
    /// Resizable: a maximise box between its close and minimise boxes.
    resizable: bool,
    focused: bool,
    /// Its title, written in its title bar.
    title: &'static [u8],
}

/// How opaque window B's pixel at (x, y) of it is (user/testclient:
/// `translucence`).
fn translucence(x: usize, y: usize) -> u32 {
    ((x * 3 + y) & 0xff) as u32
}

/// Decorations' colours and sizes (user/compositor, and the `window`
/// interface).
const BORDER_COLOUR: [u8; 3] = [0x18, 0x1c, 0x22];
const TITLE_FOCUSED: [u8; 3] = [0x35, 0x6a, 0x9e];
const TITLE_UNFOCUSED: [u8; 3] = [0x50, 0x56, 0x5e];
const CLOSE_COLOUR: [u8; 3] = [0xc0, 0x40, 0x38];
const CLOSE_CROSS: [u8; 3] = [0xf0, 0xf0, 0xf0];
const TITLE_TEXT: [u8; 3] = [0xf0, 0xf0, 0xf0];
/// Where a title starts in its title bar (from its left and top), its
/// scale, and the space it leaves before the close box.
const TITLE_LEFT: usize = 4;
const TITLE_TOP: usize = 2;
const TITLE_SCALE: usize = 2;
const TITLE_GAP: usize = 4;

impl StyledWindow {
    /// Its pixel at (x, y) on the screen over `under`, if it covers it.
    fn pixel(&self, x: usize, y: usize, under: [u8; 3]) -> Option<[u8; 3]> {
        use superior_objects::idl::window::{BORDER, CLOSE_BOX, CLOSE_MARGIN, TITLE};
        let (b, t, m, c) = (BORDER as usize, TITLE as usize, CLOSE_MARGIN as usize, CLOSE_BOX as usize);
        let (ax, ay, w, h) = (self.at.0, self.at.1, self.size.0, self.size.1);
        if (ax..ax + w).contains(&x) && (ay..ay + h).contains(&y) {
            let p = window_pixel(x - ax, y - ay, self.id, 0);
            if !self.alpha {
                return Some(p);
            }
            let a = translucence(x - ax, y - ay);
            let mix = |s: u8, d: u8| ((s as u32 * a + d as u32 * (255 - a) + 127) / 255) as u8;
            return Some([mix(p[0], under[0]), mix(p[1], under[1]), mix(p[2], under[2])]);
        }
        if !self.decorated || !(ax - b..ax + w + b).contains(&x) || !(ay - t - b..ay + h + b).contains(&y) {
            return None;
        }
        if !(ax..ax + w).contains(&x) || !(ay - t..ay).contains(&y) {
            return Some(BORDER_COLOUR);
        }
        let (right, top) = (ax + w, ay - t);
        if (right - m - c..right - m).contains(&x) && (top + m..top + m + c).contains(&y) {
            let (cx, cy) = (x + m + c - right, y - top - m);
            let cross = (3..c - 3).contains(&cx) && (cx == cy || cx + cy == c - 1);
            return Some(if cross { CLOSE_CROSS } else { CLOSE_COLOUR });
        }
        // Box k from the right: [right - (k + 1)(m + c), that + c).
        let boxes = if self.resizable { 3 } else { 2 };
        let in_box = |k: usize| {
            ((right - (k + 1) * (m + c)..right - (k + 1) * (m + c) + c).contains(&x) && (top + m..top + m + c).contains(&y))
                .then(|| (x + (k + 1) * (m + c) - right, y - top - m))
        };
        // The maximise box, left of it: a square outline, its top thicker.
        if let Some((cx, cy)) = in_box(1).filter(|_| self.resizable) {
            let inside = (3..c - 3).contains(&cx) && (3..c - 3).contains(&cy);
            let lit = inside && (cx == 3 || cx == c - 4 || cy <= 4 || cy == c - 4);
            return Some(if lit { CLOSE_CROSS } else { CLOSE_COLOUR });
        }
        // The minimise box, left of the rest: a bar along its bottom.
        if let Some((cx, cy)) = in_box(boxes - 1) {
            let bar = (3..c - 3).contains(&cx) && (c - 5..c - 3).contains(&cy);
            return Some(if bar { CLOSE_CROSS } else { CLOSE_COLOUR });
        }
        let (tx, ty) = (ax + TITLE_LEFT, top + TITLE_TOP);
        // The characters wholly before the boxes, less the gap.
        let room = w.saturating_sub(TITLE_LEFT + TITLE_GAP + boxes * (m + c));
        let fits = (room / TITLE_SCALE + 1) / superior_toolkit::font::ADVANCE as usize;
        let title = &self.title[..superior_toolkit::font::ahead(self.title, 0, fits)];
        if x >= tx && y >= ty {
            // A character at a time, as the toolkit's font reads UTF-8.
            let (cx, cy) = ((x - tx) / TITLE_SCALE, (y - ty) / TITLE_SCALE);
            let adv = superior_toolkit::font::ADVANCE as usize;
            let at = superior_toolkit::font::ahead(title, 0, cx / adv);
            if superior_toolkit::font::first(&title[at..])
                .is_some_and(|c| superior_toolkit::font::lit(c, (cx % adv) as u32, cy as u32))
            {
                return Some(TITLE_TEXT);
            }
        }
        Some(if self.focused { TITLE_FOCUSED } else { TITLE_UNFOCUSED })
    }
}

/// What each of the window style test's screenshots must show: the
/// windows, back to front, and where the pointer is (if it has moved).
fn windows_pictures() -> Vec<(Vec<StyledWindow>, Option<(usize, usize)>)> {
    let a = StyledWindow {
        id: 0,
        at: (100, 120),
        size: (300, 200),
        alpha: false,
        decorated: true,
        resizable: false,
        focused: false,
        title: b"",
    };
    let b = StyledWindow {
        id: 1,
        at: (300, 220),
        size: (320, 240),
        alpha: true,
        decorated: true,
        resizable: false,
        focused: true,
        title: b"",
    };
    let dragged = StyledWindow { at: (300, 270), focused: true, ..a };
    vec![
        (vec![a, b], None),
        (vec![StyledWindow { focused: false, ..b }, dragged], Some((350, 260))),
        (vec![dragged], Some((610, 210))),
    ]
}

/// Checks the window style test's screenshot `k` (from 1) pixel by pixel.
fn check_styled(path: &Path, k: usize) -> Result<String, String> {
    check_styled_on(path, k, false)
}

/// Checks the window style test's screenshot `k` (from 1) pixel by pixel,
/// the pointer left out if the display has a cursor plane (`plane`: the
/// host draws it over the scanout, and a screenshot is the scanout alone).
fn check_styled_on(path: &Path, k: usize, plane: bool) -> Result<String, String> {
    let (windows, pointer) = &windows_pictures()[k - 1];
    let pointer = if plane { &None } else { pointer };
    let pixels = read_screenshot(path)?;
    let mut wrong = 0;
    let mut first = None;
    let (mut blended, mut framed) = (0, 0);
    for y in 0..SCREEN.1 {
        for x in 0..SCREEN.0 {
            let mut want = desktop_pixel(x, y);
            // Whether a translucent window's own pixel shows here.
            let mut blend = false;
            for w in windows {
                if let Some(p) = w.pixel(x, y, want) {
                    want = p;
                    blend = w.alpha && (w.at.0..w.at.0 + w.size.0).contains(&x) && (w.at.1..w.at.1 + w.size.1).contains(&y);
                }
            }
            blended += blend as usize;
            if let Some((px, py)) = *pointer {
                if x >= px && y >= py && y - py < CURSOR.len() && x - px < CURSOR[0].len() {
                    match CURSOR[y - py].as_bytes()[x - px] {
                        b'#' => want = [0, 0, 0],
                        b'o' => want = [0xff, 0xff, 0xff],
                        _ => {}
                    }
                }
            }
            if [BORDER_COLOUR, TITLE_FOCUSED, TITLE_UNFOCUSED].contains(&want) {
                framed += 1;
            }
            let i = (y * SCREEN.0 + x) * 3;
            let have = [pixels[i], pixels[i + 1], pixels[i + 2]];
            if have != want {
                wrong += 1;
                first.get_or_insert((x, y, have, want));
            }
        }
    }
    match first {
        None => Ok(format!(
            "screenshot {k}: all {} pixels right: {} window{}, {framed} of frames, {blended} blended{}",
            SCREEN.0 * SCREEN.1,
            windows.len(),
            if windows.len() == 1 { "" } else { "s" },
            pointer.map_or(String::new(), |(x, y)| format!(", the pointer at ({x}, {y})"))
        )),
        Some((x, y, have, want)) => Err(format!(
            "screenshot {k}: {wrong} pixels wrong, the first at ({x}, {y}): {have:?}, not {want:?}"
        )),
    }
}

/// Does one act of the cursor test's script: screenshots are checked as
/// the window style test's pictures without the pointer.
fn cursor_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("cursor-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    check_styled_on(&path, *k, true).map(|s| Some(format!("{s} (the pointer on the cursor plane)")))
}

/// Boots `boot/cursor.manifest`: the window style test's desktop on QEMU's
/// virtio GPU (`user/virtio-gpu`), whose cursor plane draws the pointer.
/// The compositor finds the plane and gives it the pointer's picture,
/// then moves the cursor there at each move instead of drawing the
/// pointer and flushing. The host does the window style test's drag and
/// close; its three screenshots must have every pixel right with no
/// pointer in them, and the driver must have moved the cursor where the
/// pointer went.
fn cursor_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "cursor")?;
    println!("== cursor plane test on {}", img.path.display());
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "picture 1 on the screen",
            ],
            vec![Shot(1), Move(-250, -190), Button(true), Move(200, 150), Button(false)],
        ),
        (vec!["picture 2 on the screen"], vec![Shot(2), Move(260, -50), Button(true), Button(false)]),
        (vec!["picture 3 on the screen"], vec![Shot(3)]),
    ];
    let (out, shots) = run_script(&img, arch, "cursor plane test", script, cursor_act)?;
    let log = [
        "virtio-gpu: ready: ",
        ", scanout 0 is 800x600, a 64x64 cursor plane",
        "virtio-gpu: 800x600 shown on scanout 0 from the caller's 469 pages, pitch 3200",
        "virtio-gpu: cursor picture set: 32x32, its point at (0, 0)",
        "compositor: the display has a cursor plane: the pointer is drawn there",
        "compositor: ready: the desktop on a 800x600 screen",
        "compositor: input subscribed: keys and the pointer",
        "[pass] windows: picture 1 on the screen: window B shown over window A, translucent and decorated",
        "virtio-gpu: cursor at (150, 110)",
        "compositor: window 0 dragged to (300, 270)",
        "virtio-gpu: cursor at (350, 260)",
        "[pass] windows: window A dragged by its title bar to (300, 270), in front, with the focus, and no pointer events of its own (0): picture 2 on the screen",
        "virtio-gpu: cursor at (610, 210)",
        "compositor: window 1: its close box was pressed",
        "[pass] windows: window B closed from its close box: picture 3 on the screen",
        "windows: done (0 failed)",
        "[cm] second asked to shut down (pass)",
    ];
    check_log("cursor plane test", &out, &log)?;
    if shots != windows_pictures().len() {
        return Err(format!("cursor plane test: {shots} screenshots taken, want {}", windows_pictures().len()));
    }
    println!("== cursor plane test passed ({})", arch.name());
    Ok(())
}

/// Does one act of the window style test's script: screenshots are
/// checked as its pictures, the rest as the input test's acts.
fn windows_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("windows-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    check_styled(&path, *k).map(Some)
}

/// Boots `boot/windows.manifest`: the input test's desktop with styled
/// windows. Window B, translucent and decorated, is shown over window A,
/// decorated; the host drags A by its title bar (it comes in front with
/// the focus) and presses B's close box (its client closes it). Three
/// screenshots must show every pixel right: the blend, the frames, the
/// focused title bar and the pointer.
fn windows_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "windows")?;
    println!("== window style test on {}", img.path.display());
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "picture 1 on the screen",
            ],
            // From (400, 300) to (150, 110), on window A's title bar; held
            // there and moved to (350, 260), dragging A from (100, 120) to
            // (300, 270), in front of B.
            vec![Shot(1), Move(-250, -190), Button(true), Move(200, 150), Button(false)],
        ),
        // To (610, 210), on window B's close box.
        (vec!["picture 2 on the screen"], vec![Shot(2), Move(260, -50), Button(true), Button(false)]),
        (vec!["picture 3 on the screen"], vec![Shot(3)]),
    ];
    let (out, shots) = run_script(&img, arch, "window style test", script, windows_act)?;
    let log = [
        "compositor: ready: the desktop on a 800x600 screen",
        "compositor: input subscribed: keys and the pointer",
        "[pass] windows: window A shown, decorated",
        "[pass] windows: window A is on the screen",
        "[pass] windows: decorations that would reach off the screen, and unknown styles, are refused",
        "[pass] windows: picture 1 on the screen: window B shown over window A, translucent and decorated",
        "compositor: window 0 has the focus",
        "compositor: window 0 dragged to (300, 270)",
        "[pass] windows: window A dragged by its title bar to (300, 270), in front, with the focus, and no pointer events of its own (0): picture 2 on the screen",
        "compositor: window 1: its close box was pressed",
        "[pass] windows: window B closed from its close box: picture 3 on the screen",
        "[pass] windows: window A moved to (480, 150), under the pointer",
        "[pass] windows: window A moved under the still pointer and was told it is at (130, 60) in it",
        "[pass] windows: window A moved away from the pointer",
        "[pass] windows: window A was told the still pointer left it",
        "windows: done (0 failed)",
        "[cm] second asked to shut down (pass)",
    ];
    check_log("window style test", &out, &log)?;
    if shots != windows_pictures().len() {
        return Err(format!("window style test: {shots} screenshots taken, want {}", windows_pictures().len()));
    }
    println!("== window style test passed ({})", arch.name());
    Ok(())
}

/// The greeter's window (user/greeter): its size, where it is, and its
/// widgets as it lays them out: the field, the button and the line it
/// greets on.
const GREETER_SIZE: (usize, usize) = (280, 124);
const GREETER_AT: (usize, usize) = (260, 180);

fn greeter_ui() -> (superior_toolkit::Ui, usize, usize, usize) {
    let mut ui = superior_toolkit::Ui::new(GREETER_SIZE.0 as u32, GREETER_SIZE.1 as u32);
    ui.label("Your name:");
    let field = ui.field();
    let button = ui.button("Greet");
    let out = ui.label("");
    (ui, field, button, out)
}

/// What the greeter's window holds at each of the toolkit test's
/// screenshots, as the toolkit draws it after the same events (the
/// pointer in the window's pixels): `None` once it is closed. And where the
/// pointer is.
fn toolkit_pictures() -> Vec<(Option<Vec<u32>>, Option<(usize, usize)>)> {
    use superior_toolkit::{Event, Surface};
    let (mut ui, field, _, out) = greeter_ui();
    let draw = |ui: &superior_toolkit::Ui| {
        let mut px = vec![0u32; GREETER_SIZE.0 * GREETER_SIZE.1];
        ui.draw(&mut Surface { px: &mut px, w: GREETER_SIZE.0 as u32, h: GREETER_SIZE.1 as u32 });
        px
    };
    let local = |at: (usize, usize)| ((at.0 - GREETER_AT.0) as i32, (at.1 - GREETER_AT.1) as i32);
    let click = |ui: &mut superior_toolkit::Ui, at: (usize, usize)| {
        let (x, y) = local(at);
        for buttons in [0, 1, 0] {
            ui.event(Event::Pointer { x, y, buttons });
        }
    };
    // A newly shown window has the focus.
    ui.event(Event::Focus(true));
    let first = draw(&ui);
    click(&mut ui, TOOLKIT_FIELD);
    for usage in [4, 7, 4] {
        ui.event(Event::us_key(usage, true, 0));
        ui.event(Event::us_key(usage, false, 0));
    }
    assert_eq!(ui.text(field), "ada");
    let typed = draw(&ui);
    // Back two, the 'd' deleted, "nn" typed there.
    let key = |ui: &mut superior_toolkit::Ui, usage: u64| {
        ui.event(Event::us_key(usage, true, 0));
        ui.event(Event::us_key(usage, false, 0));
    };
    for usage in [80, 80, 76, 17, 17] {
        key(&mut ui, usage);
    }
    assert_eq!((ui.text(field), ui.cursor(field)), ("anna", 3));
    let edited = draw(&ui);
    // Pressed before the text, "jo" typed there, then End.
    click(&mut ui, TOOLKIT_FIELD_START);
    for usage in [13, 18, 77] {
        key(&mut ui, usage);
    }
    assert_eq!((ui.text(field), ui.cursor(field)), ("joanna", 6));
    click(&mut ui, TOOLKIT_BUTTON);
    ui.set_text(out, "Hello, joanna!");
    let greeted = draw(&ui);
    vec![
        (Some(first), None),
        (Some(typed), Some(TOOLKIT_FIELD)),
        (Some(edited), Some(TOOLKIT_FIELD)),
        (Some(greeted), Some(TOOLKIT_BUTTON)),
        (None, Some(TOOLKIT_CLOSE)),
    ]
}

/// Where the toolkit test's pointer goes on the screen: on the greeter's
/// field, its button and its close box.
const TOOLKIT_FIELD: (usize, usize) = (400, 225);
/// Just inside the field's left edge, before its text.
const TOOLKIT_FIELD_START: (usize, usize) = (275, 225);
const TOOLKIT_BUTTON: (usize, usize) = (309, 259);
const TOOLKIT_CLOSE: (usize, usize) = (530, 170);

/// Checks the toolkit test's screenshot `k` (from 1) pixel by pixel: the
/// desktop, the greeter's window as the toolkit draws it in its frame,
/// and the pointer.
fn check_toolkit(path: &Path, k: usize) -> Result<String, String> {
    let (content, pointer) = &toolkit_pictures()[k - 1];
    let frame = StyledWindow {
        id: 0,
        at: GREETER_AT,
        size: GREETER_SIZE,
        alpha: false,
        decorated: true,
        resizable: true,
        focused: true,
        title: b"Greeter",
    };
    let pixels = read_screenshot(path)?;
    let (mut wrong, mut first, mut inked) = (0, None, 0);
    for y in 0..SCREEN.1 {
        for x in 0..SCREEN.0 {
            let mut want = desktop_pixel(x, y);
            if let Some(content) = content {
                let (ax, ay) = GREETER_AT;
                if (ax..ax + GREETER_SIZE.0).contains(&x) && (ay..ay + GREETER_SIZE.1).contains(&y) {
                    let p = content[(y - ay) * GREETER_SIZE.0 + x - ax];
                    want = [(p >> 16) as u8, (p >> 8) as u8, p as u8];
                    inked += (p == superior_toolkit::INK) as usize;
                } else if let Some(p) = frame.pixel(x, y, want) {
                    want = p;
                    inked += (p == TITLE_TEXT) as usize;
                }
            }
            if let Some((px, py)) = *pointer {
                if x >= px && y >= py && y - py < CURSOR.len() && x - px < CURSOR[0].len() {
                    match CURSOR[y - py].as_bytes()[x - px] {
                        b'#' => want = [0, 0, 0],
                        b'o' => want = [0xff, 0xff, 0xff],
                        _ => {}
                    }
                }
            }
            let i = (y * SCREEN.0 + x) * 3;
            let have = [pixels[i], pixels[i + 1], pixels[i + 2]];
            if have != want {
                wrong += 1;
                first.get_or_insert((x, y, have, want));
            }
        }
    }
    match first {
        None => Ok(format!(
            "screenshot {k}: all {} pixels right: {}{}",
            SCREEN.0 * SCREEN.1,
            if content.is_some() { format!("the greeter's window, {inked} pixels of text") } else { "the desktop alone".into() },
            pointer.map_or(String::new(), |(x, y)| format!(", the pointer at ({x}, {y})"))
        )),
        Some((x, y, have, want)) => Err(format!(
            "screenshot {k}: {wrong} pixels wrong, the first at ({x}, {y}): {have:?}, not {want:?}"
        )),
    }
}

/// Does one act of the toolkit test's script: screenshots are checked as
/// its pictures, the rest as the input test's acts.
fn toolkit_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("toolkit-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    check_toolkit(&path, *k).map(Some)
}

/// Boots `boot/toolkit.manifest`: the greeter, the first toolkit app, in a
/// decorated window the compositor titles. The host clicks its field,
/// types "ada", edits it to "anna" with the arrows and Delete, clicks
/// before the text and types "jo" there, presses End, clicks its button
/// (it greets the name), holds Backspace at the field's end until key
/// repeat empties it, and presses its close box (it closes). Five
/// screenshots must have every pixel as the
/// toolkit draws the window after the same events, in its frame with its
/// title.
fn toolkit_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "toolkit")?;
    println!("== toolkit test on {}", img.path.display());
    let rel = |from: (usize, usize), to: (usize, usize)| Move(to.0 as i64 - from.0 as i64, to.1 as i64 - from.1 as i64);
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "greeter: ready",
                "toolkit: the greeter's window is on the screen",
            ],
            // From the middle of the screen to the field: pressed there, it
            // takes the keyboard.
            vec![Shot(1), rel((400, 300), TOOLKIT_FIELD), Button(true), Button(false), Type("ada")],
        ),
        (
            vec!["greeter: the field holds \"ada\", the cursor at 3"],
            vec![Shot(2), Key("left"), Key("left"), Key("delete"), Type("nn")],
        ),
        (
            vec!["greeter: the field holds \"anna\", the cursor at 3"],
            vec![Shot(3), rel(TOOLKIT_FIELD, TOOLKIT_FIELD_START), Button(true), Button(false), Type("jo"), Key("end")],
        ),
        (
            vec!["greeter: the field holds \"joanna\", the cursor at 6"],
            vec![rel(TOOLKIT_FIELD_START, TOOLKIT_BUTTON), Button(true), Button(false)],
        ),
        (
            vec!["greeter: said \"Hello, joanna!\""],
            // Back to the field's end, and Backspace held: key repeat
            // takes all six letters out.
            vec![Shot(4), rel(TOOLKIT_BUTTON, TOOLKIT_FIELD), Button(true), Button(false), Key("end"), Hold("backspace", 2500)],
        ),
        (
            vec!["greeter: the field holds \"\", the cursor at 0", "compositor: window 0: key 42 held, repeated"],
            vec![rel(TOOLKIT_FIELD, TOOLKIT_CLOSE), Button(true), Button(false)],
        ),
        (vec!["toolkit: the greeter's window is gone"], vec![Shot(5)]),
    ];
    let (out, shots) = run_script(&img, arch, "toolkit test", script, toolkit_act)?;
    let log = [
        "compositor: ready: the desktop on a 800x600 screen",
        "greeter: ready: window 0, decorated, titled \"Greeter\"",
        "toolkit: the greeter's window is on the screen",
        "greeter: the field holds \"a\", the cursor at 1",
        "greeter: the field holds \"ad\", the cursor at 2",
        "greeter: the field holds \"ada\", the cursor at 3",
        "greeter: the field holds \"ada\", the cursor at 2",
        "greeter: the field holds \"ada\", the cursor at 1",
        "greeter: the field holds \"aa\", the cursor at 1",
        "greeter: the field holds \"ana\", the cursor at 2",
        "greeter: the field holds \"anna\", the cursor at 3",
        "greeter: the field holds \"anna\", the cursor at 0",
        "greeter: the field holds \"janna\", the cursor at 1",
        "greeter: the field holds \"joanna\", the cursor at 2",
        "greeter: the field holds \"joanna\", the cursor at 6",
        "greeter: said \"Hello, joanna!\"",
        "greeter: the field holds \"joann\", the cursor at 5",
        "greeter: the field holds \"joan\", the cursor at 4",
        "greeter: the field holds \"j\", the cursor at 1",
        "greeter: the field holds \"\", the cursor at 0",
        "compositor: window 0: key 42 held, repeated",
        "compositor: window 0: its close box was pressed",
        "greeter: closed",
        "toolkit: the greeter's window is gone",
        "[cm] watcher asked to shut down (pass)",
    ];
    check_log("toolkit test", &out, &log)?;
    if shots != toolkit_pictures().len() {
        return Err(format!("toolkit test: {shots} screenshots taken, want {}", toolkit_pictures().len()));
    }
    println!("== toolkit test passed ({})", arch.name());
    Ok(())
}

/// Where every boot's real-time clock starts (QEMU's `-rtc`), running
/// with the machine: the desktop shell's clock shows 09:41 at first.
const RTC_BASE: &str = "base=2026-11-14T09:41:00,clock=vm";
/// The same, on the host's clock, which runs on through a suspend.
const RTC_SLEEPING: &str = "base=2026-11-14T09:41:00,clock=rt";

/// Where every boot's clock starts, in seconds since 1970: 2026-11-14
/// 09:41 UTC (`RTC_BASE`).
const RTC_SECONDS: u64 = 1_794_649_260;

/// How many minutes past 09:41 the desktop shell's clock may show in the
/// test's screenshots.
const PANEL_MINUTES: u64 = 5;

/// The zone the panel test chooses: half an hour off the hour, and in its
/// summer time in November.
fn adelaide_zone() -> usize {
    superior_objects::time::zone_named("Adelaide").unwrap()
}

/// The clock's text `minute` minutes past `RTC_SECONDS` in time zone
/// `zone` (of `ZONES`), as the panel shows it.
fn panel_clock(minute: u64, zone: usize) -> String {
    use superior_objects::time::{ZONES, clock};
    String::from_utf8(clock(&ZONES[zone], (RTC_SECONDS + minute * 60) as i64).to_vec()).unwrap()
}

/// The panel (user/panel): its height, and its layout for these windows
/// (title, focused, minimised), with a menu open or none and the clock
/// showing `clock`, the same as the panel's `layout`.
const PANEL_H: usize = 32;

/// Which of the panel's menus is open.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellMenu {
    Closed,
    Apps,
    Zones,
    Layouts,
}

/// The icon each test app's window has (its client's `SET_ICON`), where
/// its launcher's manifest names no image file.
fn task_icon(title: &str) -> u8 {
    superior_toolkit::icon_by_name(match title {
        "Greeter" => b"person",
        "Hello" => b"wave",
        _ => b"",
    })
}

fn panel_ui(tasks: &[(&str, bool, bool)], menu: ShellMenu, clock: &str, kb: u64) -> superior_toolkit::Ui {
    use superior_toolkit::keymap;
    let mut ui = superior_toolkit::Ui::row(SCREEN.0 as u32, PANEL_H as u32);
    // A launcher's icon from an image file goes on its windows' task
    // buttons (each window's title is its launcher's name, capitalised).
    let pictures: Vec<(String, u8)> = PANEL_LAUNCHERS
        .iter()
        .filter(|(_, icon)| superior_toolkit::icon_by_name(icon.as_bytes()) == 0)
        .map(|(l, icon)| (l.to_string(), ui.picture(&icon_file_pixels(icon))))
        .collect();
    let apps = ui.button("Apps");
    ui.select(apps, menu == ShellMenu::Apps);
    for (title, focused, _) in tasks {
        let picture = pictures.iter().find(|(l, _)| l.eq_ignore_ascii_case(title)).map(|p| p.1);
        let id = ui.icon_button(picture.unwrap_or_else(|| task_icon(title)), title);
        ui.select(id, *focused);
    }
    let k = ui.icon_button(superior_toolkit::icon_by_name(b"keyboard"), keymap::NAMES[kb as usize]);
    ui.select(k, menu == ShellMenu::Layouts);
    let c = ui.icon_button(superior_toolkit::icon_by_name(b"clock"), clock);
    ui.select(c, menu == ShellMenu::Zones);
    ui.push_right(c);
    ui.push_left_of(k, c);
    ui
}

/// The launcher menu (user/panel's `menu_layout`): a button for each of
/// the apps boot/panel.manifest may launch (with the icon it names), above
/// the panel's left end.
const MENU_W: usize = 160;
const MENU_H: usize = 8 + 2 * 34;
const MENU_AT: (usize, usize) = (0, SCREEN.1 - PANEL_H - MENU_H);

fn menu_ui() -> superior_toolkit::Ui {
    let mut ui = superior_toolkit::Ui::new(MENU_W as u32, MENU_H as u32);
    for (l, icon) in PANEL_LAUNCHERS {
        let mut k = superior_toolkit::icon_by_name(icon.as_bytes());
        if k == 0 {
            k = ui.picture(&icon_file_pixels(icon));
        }
        ui.icon_button(k, l);
    }
    ui
}

/// The pixels of `boot/icons/<name>`, as the Component Manager hands them
/// to the panel (`launch::OP_ICON_PIXELS`).
fn icon_file_pixels(name: &str) -> [u32; superior_toolkit::PICTURE_PIXELS] {
    use superior_objects::interfaces::launch;
    let bytes = std::fs::read(root().join("boot/icons").join(name)).expect("an icon file");
    let image = superior_objects::image::Image::parse(&bytes).expect("an icon image");
    let mut px = [0; superior_toolkit::PICTURE_PIXELS];
    for from in (0..launch::ICON_PIXELS).step_by(launch::ICON_PIXELS_PER_CALL) {
        launch::take_icon_words(launch::icon_words(&image, from).expect("16 pixels square"), from, &mut px);
    }
    px
}

/// The time zones' menu (user/panel's `zone_layout`): a button for each
/// zone, UTC chosen, above the panel's right end.
const ZONES_H: usize = 8 + superior_objects::time::ZONES.len() * 34;
const ZONES_AT: (usize, usize) = (SCREEN.0 - MENU_W, SCREEN.1 - PANEL_H - ZONES_H);

fn zones_ui() -> superior_toolkit::Ui {
    let mut ui = superior_toolkit::Ui::new(MENU_W as u32, ZONES_H as u32);
    for (k, z) in superior_objects::time::ZONES.iter().enumerate() {
        let id = ui.button(z.name);
        ui.select(id, k == 0);
    }
    ui
}

/// The keyboard layouts' menu (user/panel's `keyboard_layout`): a button
/// for each layout, `kb` chosen, above the panel's keyboard button (which
/// names layout `kb`, and so is as wide as its name).
const LAYOUTS_H: usize = 8 + superior_toolkit::keymap::NAMES.len() * 34;

fn layouts_at(kb: u64) -> (usize, usize) {
    let ui = panel_ui(&[], ShellMenu::Closed, &panel_clock(0, 0), kb);
    let x = ui.widget(ui.len() - 2).rect.x as usize;
    (x.min(SCREEN.0 - MENU_W), SCREEN.1 - PANEL_H - LAYOUTS_H)
}

fn layouts_ui(kb: u64) -> superior_toolkit::Ui {
    let mut ui = superior_toolkit::Ui::new(MENU_W as u32, LAYOUTS_H as u32);
    for (k, name) in superior_toolkit::keymap::NAMES.iter().enumerate() {
        let id = ui.button(name);
        ui.select(id, k as u64 == kb);
    }
    ui
}

/// The middle of button `k` of a menu laid out as `ui` at `at`, on the
/// screen.
fn menu_spot_of(ui: &superior_toolkit::Ui, at: (usize, usize), k: usize) -> (usize, usize) {
    let r = ui.widget(k).rect;
    (at.0 + (r.x + r.w / 2) as usize, at.1 + (r.y + r.h / 2) as usize)
}

fn menu_spot(k: usize) -> (usize, usize) {
    menu_spot_of(&menu_ui(), MENU_AT, k)
}

/// A menu laid out as `ui` at `at`, with the pointer at `pointer` (on the
/// screen) over it or not.
fn menu_layer_of(mut ui: superior_toolkit::Ui, at: (usize, usize), pointer: Option<(usize, usize)>) -> Layer {
    use superior_toolkit::Event;
    let size = (ui.w as usize, ui.h as usize);
    let over = |&(x, y): &(usize, usize)| (at.0..at.0 + size.0).contains(&x) && (at.1..at.1 + size.1).contains(&y);
    if let Some((x, y)) = pointer.filter(over) {
        ui.event(Event::Pointer { x: (x - at.0) as i32, y: (y - at.1) as i32, buttons: 0 });
    }
    let mut pixels = vec![0u32; size.0 * size.1];
    ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: size.0 as u32, h: size.1 as u32 });
    Layer { at, size, frame: None, pixels }
}

fn menu_layer(pointer: Option<(usize, usize)>) -> Layer {
    menu_layer_of(menu_ui(), MENU_AT, pointer)
}

/// The middle of widget `id` of the panel, on the screen.
fn panel_spot(ui: &superior_toolkit::Ui, id: usize) -> (usize, usize) {
    let r = ui.widget(id).rect;
    ((r.x + r.w / 2) as usize, SCREEN.1 - PANEL_H + (r.y + r.h / 2) as usize)
}

/// A window on a desktop shell test screenshot: where it is, its size,
/// its frame (if decorated) and its pixels.
struct Layer {
    at: (usize, usize),
    size: (usize, usize),
    frame: Option<StyledWindow>,
    pixels: Vec<u32>,
}

/// The greeter's window (its `arg`'s variant: the greeter or "Hello"),
/// freshly drawn, with the focus or not.
fn greeter_layer(hello: bool, focused: bool) -> Layer {
    let (ui, ..) = greeter_ui();
    let mut pixels = vec![0u32; GREETER_SIZE.0 * GREETER_SIZE.1];
    ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: GREETER_SIZE.0 as u32, h: GREETER_SIZE.1 as u32 });
    let (at, title): (_, &'static [u8]) = if hello { ((330, 250), b"Hello") } else { (GREETER_AT, b"Greeter") };
    Layer {
        at,
        size: GREETER_SIZE,
        frame: Some(StyledWindow { id: 0, at, size: GREETER_SIZE, alpha: false, decorated: true, resizable: true, focused, title }),
        pixels,
    }
}

/// The panel, laid out for `tasks` (the menu open or not, the clock at
/// `clock`, keyboard layout `kb`) with the pointer at `pointer` (on the
/// screen) if it is on the panel.
fn panel_layer(tasks: &[(&str, bool, bool)], menu: ShellMenu, clock: &str, kb: u64, pointer: Option<(usize, usize)>) -> Layer {
    use superior_toolkit::Event;
    let mut ui = panel_ui(tasks, menu, clock, kb);
    if let Some((x, y)) = pointer.filter(|&(_, y)| y >= SCREEN.1 - PANEL_H) {
        ui.event(Event::Pointer { x: x as i32, y: (y - (SCREEN.1 - PANEL_H)) as i32, buttons: 0 });
    }
    let mut pixels = vec![0u32; SCREEN.0 * PANEL_H];
    ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: SCREEN.0 as u32, h: PANEL_H as u32 });
    Layer { at: (0, SCREEN.1 - PANEL_H), size: (SCREEN.0, PANEL_H), frame: None, pixels }
}

/// The apps boot/panel.manifest may launch, in manifest order, and their
/// icons.
const PANEL_LAUNCHERS: &[(&str, &str)] = &[("greeter", "person"), ("hello", "hello.pam")];

/// Where the desktop shell test's pointer goes: "Apps", the menu's two
/// launchers, the greeter's and Hello's task buttons (with both apps'
/// windows on the panel), the greeter's minimise and close boxes, the
/// clock and the time zones' menu's Adelaide, the keyboard button and the
/// layouts' menu's Dvorak and French (opened on Dvorak).
struct PanelSpots {
    apps: (usize, usize),
    clock: (usize, usize),
    adelaide: (usize, usize),
    keyboard: (usize, usize),
    dvorak: (usize, usize),
    french: (usize, usize),
    run: [(usize, usize); 2],
    greeter_task: (usize, usize),
    hello_task: (usize, usize),
    minimise: (usize, usize),
    close: (usize, usize),
}

fn panel_spots() -> PanelSpots {
    use superior_toolkit::keymap;
    let ui = panel_ui(&[("Greeter", false, false), ("Hello", true, false)], ShellMenu::Closed, &panel_clock(0, 0), keymap::US);
    PanelSpots {
        apps: panel_spot(&ui, 0),
        clock: panel_spot(&ui, 4),
        adelaide: menu_spot_of(&zones_ui(), ZONES_AT, adelaide_zone()),
        keyboard: panel_spot(&ui, 3),
        dvorak: menu_spot_of(&layouts_ui(keymap::US), layouts_at(keymap::US), keymap::DVORAK as usize),
        french: menu_spot_of(&layouts_ui(keymap::DVORAK), layouts_at(keymap::DVORAK), keymap::FRENCH as usize),
        run: [menu_spot(0), menu_spot(1)],
        greeter_task: panel_spot(&ui, 1),
        hello_task: panel_spot(&ui, 2),
        // A box CLOSE_BOX square, CLOSE_MARGIN left of the maximise box
        // (the greeter is resizable), itself that far left of the close
        // box.
        minimise: (TOOLKIT_CLOSE.0 - 30, TOOLKIT_CLOSE.1),
        close: TOOLKIT_CLOSE,
    }
}

/// What each of the desktop shell test's screenshots must show, the
/// clock `minute` minutes past 09:41 UTC (shown in UTC, then in Adelaide):
/// the windows back to front, and where the pointer is.
fn panel_pictures(minute: u64) -> Vec<(Vec<Layer>, Option<(usize, usize)>)> {
    use ShellMenu::*;
    use superior_toolkit::keymap::{DVORAK, FRENCH, US};
    let s = panel_spots();
    let (utc, adelaide) = (panel_clock(minute, 0), panel_clock(minute, adelaide_zone()));
    let panel = |tasks: &[(&str, bool, bool)], menu: ShellMenu, pointer: (usize, usize)| {
        panel_layer(tasks, menu, &adelaide, US, Some(pointer))
    };
    let both = [("Greeter", false, false), ("Hello", true, false)];
    vec![
        (vec![panel_layer(&[], Closed, &utc, US, None)], None),
        (
            vec![panel_layer(&[], Zones, &utc, US, Some(s.clock)), menu_layer_of(zones_ui(), ZONES_AT, Some(s.clock))],
            Some(s.clock),
        ),
        (vec![panel_layer(&[], Closed, &adelaide, US, Some(s.adelaide))], Some(s.adelaide)),
        (vec![panel(&[], Apps, s.apps), menu_layer(Some(s.apps))], Some(s.apps)),
        (
            vec![
                greeter_layer(false, false),
                greeter_layer(true, true),
                panel(&[("Greeter", false, false), ("Hello", true, false)], Closed, s.run[1]),
            ],
            Some(s.run[1]),
        ),
        (
            vec![greeter_layer(true, true), panel(&[("Greeter", false, true), ("Hello", true, false)], Closed, s.minimise)],
            Some(s.minimise),
        ),
        (vec![panel(&[("Greeter", false, true), ("Hello", false, true)], Closed, s.hello_task)], Some(s.hello_task)),
        (
            vec![greeter_layer(false, true), panel(&[("Greeter", true, false), ("Hello", false, true)], Closed, s.run[0])],
            Some(s.run[0]),
        ),
        (
            vec![
                greeter_layer(false, false),
                greeter_layer(true, true),
                panel(&both, Layouts, s.keyboard),
                menu_layer_of(layouts_ui(US), layouts_at(US), Some(s.keyboard)),
            ],
            Some(s.keyboard),
        ),
        (
            vec![greeter_layer(false, false), hello_dvorak(), panel_layer(&both, Closed, &adelaide, DVORAK, None)],
            Some(PANEL_HELLO_FIELD),
        ),
        (
            {
                let [hello, greeter] = greeter_french();
                let tasks = [("Greeter", true, false), ("Hello", false, false)];
                vec![hello, greeter, panel_layer(&tasks, Closed, &adelaide, FRENCH, None)]
            },
            Some(PANEL_GREETER_FIELD),
        ),
    ]
}

/// Hello's window behind, "pear" in its field, and the greeter's in front
/// with the focus: "pear" pasted in its field, then "éèçà" typed on the
/// French layout by the keys under "2790" on a US keyboard.
fn greeter_french() -> [Layer; 2] {
    use superior_toolkit::{Event, keymap};
    let mut hello = greeter_layer(true, false);
    let (mut ui, field, ..) = greeter_ui();
    ui.set_text(field, "pear");
    ui.draw(&mut superior_toolkit::Surface { px: &mut hello.pixels, w: hello.size.0 as u32, h: hello.size.1 as u32 });
    let mut greeter = greeter_layer(false, true);
    let (mut ui, field, ..) = greeter_ui();
    ui.event(Event::Focus(true));
    let (x, y) = ((PANEL_GREETER_FIELD.0 - greeter.at.0) as i32, (PANEL_GREETER_FIELD.1 - greeter.at.1) as i32);
    for buttons in [0, 1, 0] {
        ui.event(Event::Pointer { x, y, buttons });
    }
    ui.set_text(field, "pear");
    for usage in [31, 36, 38, 39] {
        for down in [true, false] {
            ui.event(Event::Key { usage, down, modifiers: 0, ch: keymap::character(keymap::FRENCH, usage, 0) });
        }
    }
    assert_eq!(ui.text(field), "pear\u{e9}\u{e8}\u{e7}\u{e0}");
    ui.draw(&mut superior_toolkit::Surface { px: &mut greeter.pixels, w: greeter.size.0 as u32, h: greeter.size.1 as u32 });
    [hello, greeter]
}

/// Hello's window with the focus, its field pressed and "pear" typed on
/// the Dvorak layout by the keys under "rdao" on a US keyboard.
fn hello_dvorak() -> Layer {
    use superior_toolkit::{Event, keymap};
    let mut layer = greeter_layer(true, true);
    let (mut ui, field, ..) = greeter_ui();
    ui.event(Event::Focus(true));
    let (x, y) = ((PANEL_HELLO_FIELD.0 - layer.at.0) as i32, (PANEL_HELLO_FIELD.1 - layer.at.1) as i32);
    for buttons in [0, 1, 0] {
        ui.event(Event::Pointer { x, y, buttons });
    }
    for usage in [21, 7, 4, 18] {
        for down in [true, false] {
            ui.event(Event::Key { usage, down, modifiers: 0, ch: keymap::character(keymap::DVORAK, usage, 0) });
        }
    }
    assert_eq!(ui.text(field), "pear");
    ui.draw(&mut superior_toolkit::Surface { px: &mut layer.pixels, w: layer.size.0 as u32, h: layer.size.1 as u32 });
    layer
}

/// Checks the desktop shell test's screenshot `k` (from 1) pixel by pixel,
/// with the clock at any of the minutes it may show.
fn check_panel(path: &Path, k: usize) -> Result<String, String> {
    let mut last = Err(String::new());
    for minute in 0..PANEL_MINUTES {
        let (layers, pointer) = &panel_pictures(minute)[k - 1];
        last = check_layers(path, k, layers, None, *pointer).map(|()| {
            format!(
                "screenshot {k}: all {} pixels right: the panel (its clock at 09:{} UTC, in the zone chosen) and {} other window{}{}",
                SCREEN.0 * SCREEN.1,
                41 + minute,
                layers.len() - 1,
                if layers.len() == 2 { "" } else { "s" },
                pointer.map_or(String::new(), |(x, y)| format!(", the pointer at ({x}, {y})"))
            )
        });
        if last.is_ok() {
            break;
        }
    }
    last
}

/// The outline a resize drags (user/compositor): its colour and
/// thickness.
const OUTLINE_COLOUR: [u8; 3] = [0xf0, 0xc0, 0x40];
const OUTLINE: usize = 2;

/// Checks screenshot `k` pixel by pixel: the desktop, `layers` back to
/// front, a resize's `outline` (a rectangle on the screen) over them, and
/// the pointer over everything.
fn check_layers(
    path: &Path,
    k: usize,
    layers: &[Layer],
    outline: Option<(usize, usize, usize, usize)>,
    pointer: Option<(usize, usize)>,
) -> Result<(), String> {
    let pixels = read_screenshot(path)?;
    let (mut wrong, mut first) = (0, None);
    for y in 0..SCREEN.1 {
        for x in 0..SCREEN.0 {
            let mut want = desktop_pixel(x, y);
            for l in layers {
                let (ax, ay) = l.at;
                if (ax..ax + l.size.0).contains(&x) && (ay..ay + l.size.1).contains(&y) {
                    let p = l.pixels[(y - ay) * l.size.0 + x - ax];
                    want = [(p >> 16) as u8, (p >> 8) as u8, p as u8];
                } else if let Some(p) = l.frame.and_then(|f| f.pixel(x, y, want)) {
                    want = p;
                }
            }
            if let Some((ox, oy, ow, oh)) = outline {
                let on = (ox..ox + ow).contains(&x) && (oy..oy + oh).contains(&y);
                let inner = (ox + OUTLINE..ox + ow - OUTLINE).contains(&x) && (oy + OUTLINE..oy + oh - OUTLINE).contains(&y);
                if on && !inner {
                    want = OUTLINE_COLOUR;
                }
            }
            if let Some((px, py)) = pointer {
                if x >= px && y >= py && y - py < CURSOR.len() && x - px < CURSOR[0].len() {
                    match CURSOR[y - py].as_bytes()[x - px] {
                        b'#' => want = [0, 0, 0],
                        b'o' => want = [0xff, 0xff, 0xff],
                        _ => {}
                    }
                }
            }
            let i = (y * SCREEN.0 + x) * 3;
            let have = [pixels[i], pixels[i + 1], pixels[i + 2]];
            if have != want {
                wrong += 1;
                first.get_or_insert((x, y, have, want));
            }
        }
    }
    match first {
        None => Ok(()),
        Some((x, y, have, want)) => Err(format!(
            "screenshot {k}: {wrong} pixels wrong, the first at ({x}, {y}): {have:?}, not {want:?}"
        )),
    }
}

/// The greeter's window at `size`, drawn fresh at that size, focused.
fn greeter_sized(size: (usize, usize)) -> Layer {
    let (mut ui, ..) = greeter_ui();
    ui.resize(size.0 as u32, size.1 as u32);
    greeter_drawn(&ui)
}

/// The greeter's window as `ui` draws it, focused, at its place.
fn greeter_drawn(ui: &superior_toolkit::Ui) -> Layer {
    greeter_drawn_at(ui, GREETER_AT)
}

/// The greeter's window as `ui` draws it, focused, at `at`.
fn greeter_drawn_at(ui: &superior_toolkit::Ui, at: (usize, usize)) -> Layer {
    let size = (ui.w as usize, ui.h as usize);
    let mut pixels = vec![0u32; size.0 * size.1];
    ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: size.0 as u32, h: size.1 as u32 });
    Layer {
        at,
        size,
        frame: Some(StyledWindow { id: 0, at, size, alpha: false, decorated: true, resizable: true, focused: true, title: b"Greeter" }),
        pixels,
    }
}

/// Where the resize test's pointer goes: the greeter's frame's
/// bottom-right corner, dragged out, then in; once it is the least it
/// takes, its top-left corner, dragged out (its bottom-right corner
/// staying put, so it moves to `RESIZE_MOVED`); its maximise box (it
/// goes to `MAXIMISED_AT` as big as it takes), that box there (it comes
/// back); then its close box.
const RESIZE_CORNER: (usize, usize) = (541, 305);
const RESIZE_OUT: (usize, usize) = (641, 365);
const RESIZE_IN: (usize, usize) = (391, 245);
const RESIZE_TOP_LEFT: (usize, usize) = (258, 160);
const RESIZE_LEFT_OUT: (usize, usize) = (208, 110);
const RESIZE_MOVED: (usize, usize) = (210, 130);
const RESIZE_CLOSE: (usize, usize) = (450, 120);
const RESIZE_MAXIMISE: (usize, usize) = (436, 121);
const MAXIMISED_AT: (usize, usize) = (2, 20);
const MAXIMISED_BOX: (usize, usize) = (578, 11);

/// A rectangle on the screen: x, y, width, height.
type Area = (usize, usize, usize, usize);

/// What each of the resize test's screenshots must show: the greeter's
/// window, the outline being dragged (if any), and the pointer.
fn resize_pictures() -> Vec<(Layer, Option<Area>, (usize, usize))> {
    // The frames of a 380x184 window at the greeter's place, and of a
    // 250x174 one where its top-left corner was dragged to.
    let (b, t) = (2, 18);
    let frame = |at: (usize, usize), size: (usize, usize)| (at.0 - b, at.1 - t - b, size.0 + 2 * b, size.1 + t + 2 * b);
    let mut grown = greeter_typed_ui(true);
    grown.resize(250, 174);
    // Maximised: as big as it takes (600x400) at the screen's top left.
    let mut big = greeter_typed_ui(true);
    big.resize(600, 400);
    vec![
        (greeter_sized(GREETER_SIZE), Some(frame(GREETER_AT, (380, 184))), RESIZE_OUT),
        (greeter_sized((380, 184)), None, RESIZE_OUT),
        // Asked for 130x64, it takes the least it can: 200x124.
        (greeter_sized((200, 124)), None, RESIZE_IN),
        (greeter_typed(false), None, TOOLKIT_FIELD),
        (greeter_typed(true), None, TOOLKIT_FIELD),
        (greeter_typed(true), Some(frame(RESIZE_MOVED, (250, 174))), RESIZE_LEFT_OUT),
        (greeter_drawn_at(&grown, RESIZE_MOVED), None, RESIZE_LEFT_OUT),
        (greeter_drawn_at(&big, MAXIMISED_AT), None, RESIZE_MAXIMISE),
        (greeter_drawn_at(&grown, RESIZE_MOVED), None, MAXIMISED_BOX),
    ]
}

/// The name the resize test types into the narrowed greeter: wider than
/// its field, which shows 14 characters.
const LONG_NAME: &str = "abcdefghijklmnopq";

/// The greeter at its least size, its field pressed and `LONG_NAME` typed
/// (scrolled to show its end), then with Home pressed (`home`).
fn greeter_typed(home: bool) -> Layer {
    greeter_drawn(&greeter_typed_ui(home))
}

/// The greeter's toolkit state as `greeter_typed` draws it.
fn greeter_typed_ui(home: bool) -> superior_toolkit::Ui {
    use superior_toolkit::Event;
    let (mut ui, field, ..) = greeter_ui();
    ui.resize(200, 124);
    ui.event(Event::Focus(true));
    let (x, y) = ((TOOLKIT_FIELD.0 - GREETER_AT.0) as i32, (TOOLKIT_FIELD.1 - GREETER_AT.1) as i32);
    for buttons in [0, 1, 0] {
        ui.event(Event::Pointer { x, y, buttons });
    }
    let usages = LONG_NAME.bytes().map(|c| 4 + (c - b'a') as u64).chain(home.then_some(74));
    for usage in usages {
        ui.event(Event::us_key(usage, true, 0));
        ui.event(Event::us_key(usage, false, 0));
    }
    assert_eq!(ui.text(field), LONG_NAME);
    assert_eq!(ui.widget(field).scroll, if home { 0 } else { 3 });
    ui
}

fn resize_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("resize-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    let (layer, outline, pointer) = &resize_pictures()[*k - 1];
    check_layers(&path, *k, std::slice::from_ref(layer), *outline, Some(*pointer)).map(|()| {
        Some(format!(
            "screenshot {k}: all {} pixels right: the greeter at {}x{}{}, the pointer at {pointer:?}",
            SCREEN.0 * SCREEN.1,
            layer.size.0,
            layer.size.1,
            outline.map_or(String::new(), |o| format!(", an outline of {}x{} dragged", o.2, o.3))
        ))
    })
}

/// Boots `boot/resize.manifest`: the greeter in a resizable window.
/// Through QEMU's monitor the host drags its frame's bottom-right corner
/// out (an outline shows the size asked for; let go, the greeter draws
/// itself at that size and sets it), then in past the least it takes (it
/// takes that), types a name wider than its field there (it scrolls to
/// show the cursor, and back with Home), drags its top-left corner out
/// (it grows up and to the left, its bottom-right corner staying where it
/// was), maximises it by its maximise box (it is as big as it takes at
/// the screen's top left) and puts it back by that box, then closes it.
/// Nine screenshots must have every pixel right.
fn resize_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "resize")?;
    println!("== resize test on {}", img.path.display());
    let to = |from: (usize, usize), to: (usize, usize)| Move(to.0 as i64 - from.0 as i64, to.1 as i64 - from.1 as i64);
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "greeter: ready",
                "toolkit: the greeter's window is on the screen",
            ],
            vec![to((400, 300), RESIZE_CORNER), Button(true), to(RESIZE_CORNER, RESIZE_OUT)],
        ),
        (vec!["compositor: window 0: asking for 380x184"], vec![Shot(1), Button(false)]),
        (
            vec!["greeter: resized to 380x184 (status 0)"],
            vec![Shot(2), Button(true), to(RESIZE_OUT, RESIZE_IN), Button(false)],
        ),
        (
            vec!["greeter: resized to 200x124 (status 0)"],
            vec![Shot(3), to(RESIZE_IN, TOOLKIT_FIELD), Button(true), Button(false), Type(LONG_NAME)],
        ),
        (vec!["greeter: the field holds \"abcdefghijklmnopq\", the cursor at 17"], vec![Shot(4), Key("home")]),
        (
            vec!["greeter: the field holds \"abcdefghijklmnopq\", the cursor at 0"],
            vec![Shot(5), to(TOOLKIT_FIELD, RESIZE_TOP_LEFT), Button(true), to(RESIZE_TOP_LEFT, RESIZE_LEFT_OUT)],
        ),
        (vec!["compositor: window 0: asking for 250x174"], vec![Shot(6), Button(false)]),
        (
            vec!["greeter: resized to 250x174 (status 0)"],
            vec![Shot(7), to(RESIZE_LEFT_OUT, RESIZE_MAXIMISE), Button(true), Button(false)],
        ),
        (
            vec!["greeter: resized to 600x400 (status 0)"],
            vec![Shot(8), to(RESIZE_MAXIMISE, MAXIMISED_BOX), Button(true), Button(false)],
        ),
        (
            vec!["2x greeter: resized to 250x174 (status 0)"],
            vec![Shot(9), to(MAXIMISED_BOX, RESIZE_CLOSE), Button(true), Button(false)],
        ),
        (vec!["toolkit: the greeter's window is gone"], vec![]),
    ];
    let (out, shots) = run_script(&img, arch, "resize test", script, resize_act)?;
    let log = [
        "greeter: ready: window 0, decorated, titled \"Greeter\"",
        "compositor: window 0: asking for 380x184",
        "compositor: window 0 resized to 380x184",
        "greeter: resized to 380x184 (status 0)",
        "compositor: window 0: asking for 130x64",
        "compositor: window 0 resized to 200x124",
        "greeter: resized to 200x124 (status 0)",
        "greeter: the field holds \"abcdefghijklmnopq\", the cursor at 17",
        "greeter: the field holds \"abcdefghijklmnopq\", the cursor at 0",
        "compositor: window 0: asking for 250x174",
        "compositor: window 0 resized to 250x174",
        "compositor: window 0 moved to (210, 130) to keep its right and bottom edges",
        "greeter: resized to 250x174 (status 0)",
        "compositor: window 0: its maximise box was pressed",
        "compositor: window 0 maximised: asked to be 796x578",
        "compositor: window 0 resized to 600x400",
        "compositor: window 0 moved to (2, 20)",
        "greeter: resized to 600x400 (status 0)",
        "compositor: window 0: its maximise box was pressed",
        "compositor: window 0 asked back to 250x174 at (210, 130)",
        "compositor: window 0 resized to 250x174",
        "compositor: window 0 moved to (210, 130)",
        "greeter: resized to 250x174 (status 0)",
        "compositor: window 0: its close box was pressed",
        "greeter: closed",
        "[cm] watcher asked to shut down (pass)",
    ];
    check_log("resize test", &out, &log)?;
    if shots != resize_pictures().len() {
        return Err(format!("resize test: {shots} screenshots taken, want {}", resize_pictures().len()));
    }
    println!("== resize test passed ({})", arch.name());
    Ok(())
}

/// The List app's window: its size and place, and its widgets as
/// `user/list` lays them out (`layout` there): the field, "Add", the
/// list, "Remove" and the status label.
const LIST_SIZE: (usize, usize) = (320, 206);
const LIST_AT: (usize, usize) = (240, 140);

struct ListUi {
    ui: superior_toolkit::Ui,
    field: usize,
    list: usize,
    status: usize,
}

fn list_ui() -> ListUi {
    let mut ui = superior_toolkit::Ui::new(LIST_SIZE.0 as u32, LIST_SIZE.1 as u32);
    ui.begin_row();
    ui.label("Item:");
    let field = ui.field();
    ui.button("Add");
    ui.end_row();
    let list = ui.list(6);
    for f in ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "kiwi", "lemon", "mango"] {
        ui.push_item(list, f);
    }
    ui.begin_row();
    ui.button("Remove");
    let status = ui.label("");
    ui.stretch(status);
    ui.end_row();
    let mut l = ListUi { ui, field, list, status };
    l.status();
    l
}

impl ListUi {
    /// The status label as the app sets it: the item chosen, or how many.
    fn status(&mut self) {
        let text = match self.ui.chosen(self.list) {
            Some(k) => format!("Chosen: {}", self.ui.item(self.list, k)),
            None => format!("{} items", self.ui.items(self.list)),
        };
        self.ui.set_text(self.status, &text);
    }

    fn event(&mut self, e: superior_toolkit::Event) -> superior_toolkit::Response {
        let r = self.ui.event(e);
        self.status();
        r
    }

    /// The pointer moved to `at` on the screen, holding the button or not.
    fn pointer(&mut self, at: (usize, usize), held: bool) -> superior_toolkit::Response {
        let (x, y) = ((at.0 - LIST_AT.0) as i32, (at.1 - LIST_AT.1) as i32);
        self.event(superior_toolkit::Event::Pointer { x, y, buttons: held as u64 })
    }

    fn click(&mut self, at: (usize, usize)) -> superior_toolkit::Response {
        self.pointer(at, false);
        self.pointer(at, true);
        self.pointer(at, false)
    }

    fn key(&mut self, usage: u64, modifiers: u8) -> superior_toolkit::Response {
        use superior_toolkit::Event;
        let r = self.event(Event::us_key(usage, true, modifiers));
        self.event(Event::us_key(usage, false, modifiers));
        r
    }

    fn layer(&self) -> Layer {
        let size = LIST_SIZE;
        let mut pixels = vec![0u32; size.0 * size.1];
        self.ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: size.0 as u32, h: size.1 as u32 });
        let at = LIST_AT;
        Layer {
            at,
            size,
            frame: Some(StyledWindow { id: 0, at, size, alpha: false, decorated: true, resizable: true, focused: true, title: b"List" }),
            pixels,
        }
    }
}

/// Where the widgets test's pointer goes: the list's third row; its
/// scroll bar's thumb (once scrolled to the end), dragged up past the
/// top; the field; "Remove"; the close box.
const WIDGETS_ROW: (usize, usize) = (300, 233);
const WIDGETS_THUMB: (usize, usize) = (545, 260);
const WIDGETS_THUMB_UP: (usize, usize) = (545, 160);
const WIDGETS_FIELD: (usize, usize) = (340, 160);
const WIDGETS_REMOVE: (usize, usize) = (290, 325);
const WIDGETS_CLOSE: (usize, usize) = (550, 130);

/// What each of the widgets test's screenshots must show: the List app's
/// window after the same events, and the pointer.
fn widgets_pictures() -> Vec<(Layer, Option<(usize, usize)>)> {
    use superior_toolkit::Event;
    let mut l = list_ui();
    let mut shots = Vec::new();
    l.event(Event::Focus(true));
    shots.push((l.layer(), None));
    // The third row chosen, then Down five times: the eighth, scrolled to
    // show it.
    let r = l.click(WIDGETS_ROW);
    assert_eq!(l.ui.chosen(l.list), Some(2), "{r:?}");
    for _ in 0..5 {
        l.key(81, 0);
    }
    assert_eq!((l.ui.chosen(l.list), l.ui.widget(l.list).scroll), (Some(7), 2));
    shots.push((l.layer(), Some(WIDGETS_ROW)));
    // The wheel down two steps: scrolled to the end.
    let (x, y) = ((WIDGETS_ROW.0 - LIST_AT.0) as i32, (WIDGETS_ROW.1 - LIST_AT.1) as i32);
    for _ in 0..2 {
        l.event(Event::Wheel { x, y, up: -1 });
    }
    assert_eq!(l.ui.widget(l.list).scroll, 4);
    shots.push((l.layer(), Some(WIDGETS_ROW)));
    // The thumb taken and dragged up past the top: scrolled back.
    l.pointer(WIDGETS_THUMB, false);
    l.pointer(WIDGETS_THUMB, true);
    l.pointer(WIDGETS_THUMB_UP, true);
    l.pointer(WIDGETS_THUMB_UP, false);
    assert_eq!((l.ui.widget(l.list).scroll, l.ui.chosen(l.list)), (0, Some(7)));
    shots.push((l.layer(), Some(WIDGETS_THUMB_UP)));
    // The field pressed, "milk" typed, all of it selected with Shift and
    // Home and replaced by "plum", the last two selected with Shift and
    // Left.
    l.click(WIDGETS_FIELD);
    let letters = |w: &str| w.bytes().map(|c| 4 + (c - b'a') as u64).collect::<Vec<_>>();
    for u in letters("milk") {
        l.key(u, 0);
    }
    l.key(74, 0x02);
    for u in letters("plum") {
        l.key(u, 0);
    }
    l.key(80, 0x02);
    l.key(80, 0x02);
    assert_eq!((l.ui.text(l.field), l.ui.selection(l.field)), ("plum", Some((2, 4))));
    shots.push((l.layer(), Some(WIDGETS_FIELD)));
    // Cut, pasted back, Enter: "plum" added to the list and chosen.
    l.key(27, 0x01);
    l.key(25, 0x01);
    assert_eq!(l.key(40, 0).entered, Some(l.field));
    l.ui.push_item(l.list, "plum");
    l.ui.choose(l.list, Some(10));
    l.ui.set_text(l.field, "");
    l.status();
    assert_eq!(l.ui.widget(l.list).scroll, 5);
    shots.push((l.layer(), Some(WIDGETS_FIELD)));
    // "Remove": it goes, the item before it chosen.
    let r = l.click(WIDGETS_REMOVE);
    assert!(r.clicked.is_some());
    l.ui.remove_item(l.list, 10);
    l.status();
    assert_eq!((l.ui.chosen(l.list), l.ui.widget(l.list).scroll), (Some(9), 4));
    shots.push((l.layer(), Some(WIDGETS_REMOVE)));
    shots
}

fn widgets_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("widgets-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    let (layer, pointer) = &widgets_pictures()[*k - 1];
    check_layers(&path, *k, std::slice::from_ref(layer), None, *pointer)
        .map(|()| Some(format!("screenshot {k}: all {} pixels right: the List window, the pointer at {pointer:?}", SCREEN.0 * SCREEN.1)))
}

/// Boots `boot/widgets.manifest`: the List app, on the toolkit's lines,
/// list and text selection. Through QEMU's monitor the host chooses a
/// row, moves down past the rows shown (the list scrolls), turns the wheel
/// (to the end), drags the scroll bar's thumb back up, types into the
/// field, selects all of it with Shift and Home and types over it,
/// selects two characters with Shift and Left, cuts and pastes them, adds
/// the text with Enter, removes it with "Remove" and closes the window.
/// Seven screenshots must have every pixel as the toolkit draws the window
/// after the same events.
fn widgets_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "widgets")?;
    println!("== widgets test on {}", img.path.display());
    let to = |from: (usize, usize), to: (usize, usize)| Move(to.0 as i64 - from.0 as i64, to.1 as i64 - from.1 as i64);
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "list: ready",
                "widgets: the List window is on the screen",
            ],
            vec![
                Shot(1),
                to((400, 300), WIDGETS_ROW),
                Button(true),
                Button(false),
                Key("down"),
                Key("down"),
                Key("down"),
                Key("down"),
                Key("down"),
            ],
        ),
        (vec!["list: 10 items, \"kiwi\" chosen (item 7), items 2 to 7 shown"], vec![Shot(2), Wheel(-1), Wheel(-1)]),
        (
            vec!["list: 10 items, \"kiwi\" chosen (item 7), items 4 to 9 shown"],
            vec![Shot(3), to(WIDGETS_ROW, WIDGETS_THUMB), Button(true), to(WIDGETS_THUMB, WIDGETS_THUMB_UP), Button(false)],
        ),
        (
            vec!["list: 10 items, \"kiwi\" chosen (item 7), items 0 to 5 shown"],
            vec![
                Shot(4),
                to(WIDGETS_THUMB_UP, WIDGETS_FIELD),
                Button(true),
                Button(false),
                Type("milk"),
                Key("shift+home"),
                Type("plum"),
                Key("shift+left"),
                Key("shift+left"),
            ],
        ),
        (
            vec!["list: the field holds \"plum\", the cursor at 2, \"um\" selected"],
            vec![Shot(5), Key("ctrl+x"), Key("ctrl+v"), Key("ret")],
        ),
        (
            vec!["list: 11 items, \"plum\" chosen (item 10), items 5 to 10 shown"],
            vec![Shot(6), to(WIDGETS_FIELD, WIDGETS_REMOVE), Button(true), Button(false)],
        ),
        (
            vec!["list: 10 items, \"mango\" chosen (item 9), items 4 to 9 shown"],
            vec![Shot(7), to(WIDGETS_REMOVE, WIDGETS_CLOSE), Button(true), Button(false)],
        ),
        (vec!["widgets: the List window is gone"], vec![]),
    ];
    let (out, shots) = run_script(&img, arch, "widgets test", script, widgets_act)?;
    let log = [
        "list: ready: window 0, decorated, titled \"List\"",
        "list: 10 items, none chosen, items 0 to 5 shown",
        "list: 10 items, \"cherry\" chosen (item 2), items 0 to 5 shown",
        "list: 10 items, \"date\" chosen (item 3), items 0 to 5 shown",
        "list: 10 items, \"elderberry\" chosen (item 4), items 0 to 5 shown",
        "list: 10 items, \"fig\" chosen (item 5), items 0 to 5 shown",
        "list: 10 items, \"grape\" chosen (item 6), items 1 to 6 shown",
        "list: 10 items, \"kiwi\" chosen (item 7), items 2 to 7 shown",
        "list: 10 items, \"kiwi\" chosen (item 7), items 3 to 8 shown",
        "list: 10 items, \"kiwi\" chosen (item 7), items 4 to 9 shown",
        "list: 10 items, \"kiwi\" chosen (item 7), items 0 to 5 shown",
        "list: the field holds \"milk\", the cursor at 4",
        "list: the field holds \"milk\", the cursor at 0, \"milk\" selected",
        "list: the field holds \"p\", the cursor at 1",
        "list: the field holds \"plum\", the cursor at 4",
        "list: the field holds \"plum\", the cursor at 3, \"m\" selected",
        "list: the field holds \"plum\", the cursor at 2, \"um\" selected",
        "list: the field holds \"pl\", the cursor at 2",
        "list: the field holds \"plum\", the cursor at 4",
        "list: added \"plum\"",
        "list: 11 items, \"plum\" chosen (item 10), items 5 to 10 shown",
        "list: removed \"plum\"",
        "list: 10 items, \"mango\" chosen (item 9), items 4 to 9 shown",
        "compositor: window 0: its close box was pressed",
        "list: closed",
        "widgets: the List window is gone",
        "[cm] watcher asked to shut down (pass)",
    ];
    check_log("widgets test", &out, &log)?;
    if shots != widgets_pictures().len() {
        return Err(format!("widgets test: {shots} screenshots taken, want {}", widgets_pictures().len()));
    }
    println!("== widgets test passed ({})", arch.name());
    Ok(())
}

/// The Notes app's window: its size and place, and its widgets as
/// `user/notes` lays them out (`layout` there): the text area of six
/// lines and the label under it.
const NOTES_SIZE: (usize, usize) = (320, 200);
const NOTES_AT: (usize, usize) = (240, 150);

struct NotesUi {
    ui: superior_toolkit::Ui,
    status: usize,
}

fn notes_ui() -> NotesUi {
    let mut ui = superior_toolkit::Ui::new(NOTES_SIZE.0 as u32, NOTES_SIZE.1 as u32);
    ui.area(6);
    ui.set_area_wrap(true);
    let status = ui.label("");
    let mut n = NotesUi { ui, status };
    n.status();
    n
}

impl NotesUi {
    /// The label as the app sets it: where the cursor is, from 1.
    fn status(&mut self) {
        let (l, c) = self.ui.area_cursor();
        self.ui.set_text(self.status, &format!("Line {}, column {}", l + 1, c + 1));
    }

    fn event(&mut self, e: superior_toolkit::Event) {
        self.ui.event(e);
        self.status();
    }

    /// The pointer at `at` on the screen, the button held or not.
    fn pointer(&mut self, at: (usize, usize), held: bool) {
        let (x, y) = ((at.0 - NOTES_AT.0) as i32, (at.1 - NOTES_AT.1) as i32);
        self.event(superior_toolkit::Event::Pointer { x, y, buttons: held as u64 });
    }

    fn click(&mut self, at: (usize, usize)) {
        self.pointer(at, false);
        self.pointer(at, true);
        self.pointer(at, false);
    }

    fn key(&mut self, usage: u64) {
        use superior_toolkit::Event;
        self.event(Event::us_key(usage, true, 0));
        self.event(Event::us_key(usage, false, 0));
    }

    /// Lower-case letters typed.
    fn type_letters(&mut self, s: &str) {
        for c in s.bytes() {
            self.key(4 + (c - b'a') as u64);
        }
    }

    fn layer(&self) -> Layer {
        let size = NOTES_SIZE;
        let mut pixels = vec![0u32; size.0 * size.1];
        self.ui.draw(&mut superior_toolkit::Surface { px: &mut pixels, w: size.0 as u32, h: size.1 as u32 });
        let at = NOTES_AT;
        Layer {
            at,
            size,
            frame: Some(StyledWindow { id: 0, at, size, alpha: false, decorated: true, resizable: false, focused: true, title: b"Notes" }),
            pixels,
        }
    }
}

/// Where the notes test's pointer goes: into the area's first line, far
/// past its end on that line; the first and third lines' starts (left of
/// their first characters); the close box.
const NOTES_LINE: (usize, usize) = (300, 171);
const NOTES_LINE_END: (usize, usize) = (500, 171);
const NOTES_START: (usize, usize) = (252, 171);
const NOTES_THIRD: (usize, usize) = (252, 171 + 2 * superior_toolkit::LINE_H as usize);
const NOTES_CLOSE: (usize, usize) = (550, 140);

/// The usages the notes test presses.
const RET: u64 = 40;
const UP_KEY: u64 = 82;
const DOWN_KEY: u64 = 81;
const HOME_KEY: u64 = 74;
const END_KEY: u64 = 77;
const BACKSPACE_KEY: u64 = 42;

/// What each of the notes test's screenshots must show: the Notes window
/// after the same events, and the pointer.
fn notes_pictures() -> Vec<(Layer, Option<(usize, usize)>)> {
    notes_session().0
}

/// The words the notes test types on a line of their own, wider than the
/// area: they wrap.
const NOTES_WORDS: &str = "the quick brown fox jumps over the lazy dog";

/// The notes test's screenshots as the toolkit draws them after the same
/// events, and the window's state at the end.
fn notes_session() -> (Vec<(Layer, Option<(usize, usize)>)>, NotesUi) {
    use superior_toolkit::Event;
    let mut n = notes_ui();
    let mut shots = Vec::new();
    n.event(Event::Focus(true));
    shots.push((n.layer(), None));
    // The area pressed; three lines typed.
    n.click(NOTES_LINE);
    for (k, w) in ["milk", "eggs", "bread"].into_iter().enumerate() {
        if k > 0 {
            n.key(RET);
        }
        n.type_letters(w);
    }
    assert_eq!((n.ui.area_text(), n.ui.area_cursor()), ("milk\neggs\nbread", (2, 5)));
    shots.push((n.layer(), Some(NOTES_LINE)));
    // Up, Home, Backspace (the first two lines joined), Enter (split
    // again), Down, End; four more lines: seven, scrolled by one.
    for u in [UP_KEY, HOME_KEY, BACKSPACE_KEY, RET, DOWN_KEY, END_KEY] {
        n.key(u);
    }
    for w in ["jam", "tea", "rice", "salt"] {
        n.key(RET);
        n.type_letters(w);
    }
    assert_eq!(n.ui.area_text(), "milk\neggs\nbread\njam\ntea\nrice\nsalt");
    assert_eq!((n.ui.area_cursor(), n.ui.widget(0).scroll), ((6, 4), 1));
    shots.push((n.layer(), Some(NOTES_LINE)));
    // The wheel up a step: the first line shown again; a press past its
    // end puts the cursor there.
    let (x, y) = ((NOTES_LINE.0 - NOTES_AT.0) as i32, (NOTES_LINE.1 - NOTES_AT.1) as i32);
    n.event(Event::Wheel { x, y, up: 1 });
    n.click(NOTES_LINE_END);
    assert_eq!((n.ui.area_cursor(), n.ui.widget(0).scroll), ((0, 4), 0));
    shots.push((n.layer(), Some(NOTES_LINE_END)));
    // Dragged from the first line's start to the third's: two lines
    // selected.
    n.pointer(NOTES_START, false);
    n.pointer(NOTES_START, true);
    n.pointer(NOTES_THIRD, true);
    n.pointer(NOTES_THIRD, false);
    assert_eq!((n.ui.area_selection(), n.ui.area_cursor()), (Some((0, 10)), (2, 0)));
    shots.push((n.layer(), Some(NOTES_THIRD)));
    // Control-X cuts them; down to the last line's end, Enter and
    // Control-V paste them there (scrolled to show the cursor).
    let control = |n: &mut NotesUi, usage: u64| {
        n.event(Event::us_key(224, true, 0x01));
        n.event(Event::us_key(usage, true, 0x01));
        n.event(Event::us_key(usage, false, 0x01));
        n.event(Event::us_key(224, false, 0));
    };
    control(&mut n, 27);
    assert_eq!((n.ui.area_text(), n.ui.clipboard()), ("bread\njam\ntea\nrice\nsalt", "milk\neggs\n"));
    for u in [DOWN_KEY, DOWN_KEY, DOWN_KEY, DOWN_KEY, END_KEY, RET] {
        n.key(u);
    }
    control(&mut n, 25);
    assert_eq!(n.ui.area_text(), "bread\njam\ntea\nrice\nsalt\nmilk\neggs\n");
    assert_eq!((n.ui.area_cursor(), n.ui.widget(0).scroll), ((7, 0), 2));
    shots.push((n.layer(), Some(NOTES_THIRD)));
    // A line of words wider than the area: it wraps; Up goes to the row
    // above within it.
    for c in NOTES_WORDS.bytes() {
        n.key(if c == b' ' { 44 } else { 4 + (c - b'a') as u64 });
    }
    assert_eq!((n.ui.area_lines(), n.ui.area_rows()), (8, 9));
    n.key(UP_KEY);
    assert_eq!(n.ui.area_cursor().0, 7, "still on the last line");
    shots.push((n.layer(), Some(NOTES_THIRD)));
    (shots, n)
}

/// The Notes app's log line for `n`'s text area as it stands.
fn notes_state(n: &NotesUi) -> &'static str {
    let ui = &n.ui;
    notes_line(ui.area_lines(), ui.area_cursor(), ui.widget(0).scroll, ui.area_text())
}

fn notes_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("notes-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    let (layer, pointer) = &notes_pictures()[*k - 1];
    check_layers(&path, *k, std::slice::from_ref(layer), None, *pointer)
        .map(|()| Some(format!("screenshot {k}: all {} pixels right: the Notes window, the pointer at {pointer:?}", SCREEN.0 * SCREEN.1)))
}

/// The notes test's log lines for the text area's state: lines, cursor,
/// first line shown, text (with `\n` for newlines, as the app's `{:?}`).
fn notes_line(lines: usize, cursor: (usize, usize), top: usize, text: &str) -> &'static str {
    let t = format!("{text:?}");
    format!("notes: {lines} lines, the cursor at line {}, column {}, line {top} at the top: {t}", cursor.0, cursor.1).leak()
}

/// The same, with `selected` bytes selected.
fn notes_line_selected(lines: usize, cursor: (usize, usize), top: usize, text: &str, selected: usize) -> &'static str {
    format!("{} ({selected} bytes selected)", notes_line(lines, cursor, top, text)).leak()
}

/// Boots `boot/notes.manifest`: the Notes app, on the toolkit's text area.
/// Through QEMU's monitor the host presses the area and types three lines;
/// goes up, to the line's start, joins it to the line above with Backspace
/// and splits them again with Enter; goes down to the last line's end and
/// types four more, past the lines shown (the area scrolls); turns the
/// wheel up a step, presses past the first line's end (the cursor goes
/// there); drags from the first line's start to the third's (two lines
/// selected), cuts them with Control-X and pastes them after the last line
/// with Control-V; types a line of words wider than the area (it wraps)
/// and goes up a row within it; and closes the window. Seven screenshots
/// must have every pixel as the toolkit draws the window after the same
/// events.
fn notes_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "notes")?;
    println!("== notes test on {}", img.path.display());
    let to = |from: (usize, usize), to: (usize, usize)| Move(to.0 as i64 - from.0 as i64, to.1 as i64 - from.1 as i64);
    let all = "milk\neggs\nbread\njam\ntea\nrice\nsalt";
    let three = notes_line(3, (2, 5), 0, "milk\neggs\nbread");
    let seven = notes_line(7, (6, 4), 1, all);
    let back = notes_line(7, (0, 4), 0, all);
    let selected = notes_line_selected(7, (2, 0), 0, all, 10);
    let cut = notes_line(5, (0, 0), 0, "bread\njam\ntea\nrice\nsalt");
    let pasted = notes_line(8, (7, 0), 2, "bread\njam\ntea\nrice\nsalt\nmilk\neggs\n");
    let up = notes_state(&notes_session().1);
    // Nine rows, six shown: scrolled by three.
    let with_words = format!("bread
jam
tea
rice
salt
milk
eggs
{NOTES_WORDS}");
    let typed = notes_line(8, (7, NOTES_WORDS.len()), 3, &with_words);
    let script = vec![
        (
            vec!["relative X and Y", "absolute X and Y", "compositor: input subscribed", "notes: ready", "notes: the Notes window is on the screen"],
            vec![
                Shot(1),
                to((400, 300), NOTES_LINE),
                Button(true),
                Button(false),
                Type("milk"),
                Key("ret"),
                Type("eggs"),
                Key("ret"),
                Type("bread"),
            ],
        ),
        (
            vec![three],
            vec![
                Shot(2),
                Key("up"),
                Key("home"),
                Key("backspace"),
                Key("ret"),
                Key("down"),
                Key("end"),
                Key("ret"),
                Type("jam"),
                Key("ret"),
                Type("tea"),
                Key("ret"),
                Type("rice"),
                Key("ret"),
                Type("salt"),
            ],
        ),
        (vec![seven], vec![Shot(3), Wheel(1), to(NOTES_LINE, NOTES_LINE_END), Button(true), Button(false)]),
        (
            vec![back],
            vec![Shot(4), to(NOTES_LINE_END, NOTES_START), Button(true), to(NOTES_START, NOTES_THIRD), Button(false)],
        ),
        (vec![selected], vec![Shot(5), Key("ctrl+x")]),
        (
            vec![cut, "notes: copied 10 bytes to the clipboard"],
            vec![Key("down"), Key("down"), Key("down"), Key("down"), Key("end"), Key("ret"), Key("ctrl+v")],
        ),
        (vec![pasted], vec![Shot(6), Type(NOTES_WORDS)]),
        (vec![typed], vec![Key("up")]),
        (vec![up], vec![Shot(7), to(NOTES_THIRD, NOTES_CLOSE), Button(true), Button(false)]),
        (vec!["notes: the Notes window is gone"], vec![]),
    ];
    let (out, shots) = run_script(&img, arch, "notes test", script, notes_act)?;
    let log = [
        "notes: ready: window 0, decorated, titled \"Notes\"",
        notes_line(1, (0, 1), 0, "m"),
        three,
        notes_line(3, (1, 4), 0, "milk\neggs\nbread"),
        notes_line(2, (0, 4), 0, "milkeggs\nbread"),
        notes_line(3, (1, 0), 0, "milk\neggs\nbread"),
        notes_line(7, (6, 1), 1, "milk\neggs\nbread\njam\ntea\nrice\ns"),
        seven,
        notes_line(7, (6, 4), 0, all),
        back,
        selected,
        "compositor: window 0 copied 10 bytes to the clipboard",
        "notes: copied 10 bytes to the clipboard",
        cut,
        pasted,
        typed,
        up,
        "compositor: window 0: its close box was pressed",
        "notes: closed",
        "notes: the Notes window is gone",
        "[cm] watcher asked to shut down (pass)",
    ];
    check_log("notes test", &out, &log)?;
    if shots != notes_pictures().len() {
        return Err(format!("notes test: {shots} screenshots taken, want {}", notes_pictures().len()));
    }
    println!("== notes test passed ({})", arch.name());
    Ok(())
}

fn panel_act(act: &Act, arch: Arch) -> Result<Option<String>, String> {
    let Act::Shot(k) = act else { return input_act(act, arch) };
    let path = root().join("target").join(format!("panel-{}-{k}.ppm", arch.name()));
    let _ = std::fs::remove_file(&path);
    screendump(&path)?;
    check_panel(&path, *k).map(Some)
}

/// Where the panel test clicks Hello's and the greeter's text fields: a
/// way into each window (at (330, 250) and (260, 180)) down to its field.
const PANEL_HELLO_FIELD: (usize, usize) = (430, 290);
const PANEL_GREETER_FIELD: (usize, usize) = (360, 220);

/// Boots `boot/panel.manifest`: the desktop shell's panel, which manages
/// the compositor and may launch the greeter and "Hello". Through QEMU's
/// monitor the host launches both from the panel, puts the greeter back
/// in front from its task button, closes it from its close box (it exits)
/// and launches it again; then chooses the Dvorak layout from the panel's
/// keyboard menu, types "pear" in Hello by the keys that type it there,
/// copies it and pastes it in the greeter; then chooses French and types
/// "éèçà" in the greeter by the keys under "2790". Eleven screenshots must
/// have every
/// pixel right:
/// the panel as the toolkit lays it out on the host, the apps' windows in
/// their titled frames, the focus and the stacking.
fn panel_test(arch: Arch) -> Result<(), String> {
    use Act::*;
    let img = image_with(false, arch, "panel")?;
    println!("== desktop shell test on {}", img.path.display());
    let s = panel_spots();
    let mut at = (400, 300);
    // To `to` and a click there.
    let mut click = |to: (usize, usize)| {
        let v = vec![Move(to.0 as i64 - at.0 as i64, to.1 as i64 - at.1 as i64), Button(true), Button(false)];
        at = to;
        v
    };
    let with = |shot: Option<usize>, acts: Vec<Act>| shot.map(Shot).into_iter().chain(acts).collect::<Vec<_>>();
    let script = vec![
        (
            vec![
                "relative X and Y",
                "absolute X and Y",
                "compositor: input subscribed",
                "panel: hello: its icon from hello.pam",
                "panel: ready",
                "panel: the clock shows Sat 14 Nov 09:4",
                "panel: windows: none",
            ],
            with(Some(1), click(s.clock)),
        ),
        (vec!["panel: time zones open: UTC chosen"], with(Some(2), click(s.adelaide))),
        (vec!["panel: the clock shows Sat 14 Nov 20:1"], with(Some(3), click(s.apps))),
        (vec!["panel: menu open: greeter, hello"], with(Some(4), click(s.run[0]))),
        (vec!["greeter: ready", "panel: windows: \"Greeter\" (focused)"], with(None, click(s.apps))),
        (vec!["2x panel: menu open: greeter, hello"], with(None, click(s.run[1]))),
        (vec!["hello: ready", "panel: windows: \"Greeter\", \"Hello\" (focused)"], with(Some(5), click(s.greeter_task))),
        (vec!["panel: windows: \"Greeter\" (focused), \"Hello\""], with(None, click(s.minimise))),
        (vec!["panel: windows: \"Greeter\" (minimised), \"Hello\" (focused)"], with(Some(6), click(s.hello_task))),
        (vec!["panel: windows: \"Greeter\" (minimised), \"Hello\" (minimised)"], with(Some(7), click(s.greeter_task))),
        (vec!["panel: windows: \"Greeter\" (focused), \"Hello\" (minimised)"], with(None, click(s.close))),
        (vec!["greeter: closed", "panel: windows: \"Hello\" (minimised)"], with(None, click(s.apps))),
        (vec!["3x panel: menu open: greeter, hello"], with(None, click(s.run[0]))),
        (vec!["2x greeter: ready", "2x panel: windows: \"Greeter\" (focused), \"Hello\" (minimised)"], with(Some(8), click(s.hello_task))),
        // The Dvorak layout chosen from the panel's keyboard menu.
        (vec!["2x panel: windows: \"Greeter\", \"Hello\" (focused)"], click(s.keyboard)),
        (vec!["panel: keyboard layouts open: US chosen"], with(Some(9), click(s.dvorak))),
        // The clipboard: "pear" copied in Hello's field, pasted in the
        // greeter's. Typed on the Dvorak layout: the keys under "rdao" on a
        // US keyboard.
        (vec!["panel: keyboard layout Dvorak (status 0)"], {
            let mut v = click(PANEL_HELLO_FIELD);
            v.push(Type("rdao"));
            v
        }),
        (vec!["hello: the field holds \"pear\", the cursor at 4"], with(Some(10), vec![Key("ctrl+a"), Key("ctrl+c")])),
        (vec!["hello: copied \"pear\" to the clipboard"], click(s.greeter_task)),
        (vec!["greeter: the clipboard holds \"pear\""], {
            let mut v = click(PANEL_GREETER_FIELD);
            v.push(Key("ctrl+v"));
            v
        }),
        // French chosen, and accented letters typed after it: the keys
        // under "2790" on a US keyboard.
        (vec!["greeter: the field holds \"pear\", the cursor at 4"], click(s.keyboard)),
        (vec!["panel: keyboard layouts open: Dvorak chosen"], click(s.french)),
        (vec!["panel: keyboard layout French (status 0)"], {
            let mut v = click(PANEL_GREETER_FIELD);
            v.extend([Key("end"), Type("2790")]);
            v
        }),
        (vec!["greeter: the field holds \"pear\u{e9}\u{e8}\u{e7}\u{e0}\", the cursor at 12"], with(Some(11), vec![])),
    ];
    let (out, shots) = run_script(&img, arch, "desktop shell test", script, panel_act)?;
    let log = [
        "compositor: ready: the desktop on a 800x600 screen",
        "panel: hello: its icon from hello.pam",
        "panel: windows: none",
        "panel: ready: 800x32 at the bottom, 2 launchers in its menu",
        "panel: the clock shows Sat 14 Nov 09:4",
        "panel: time zones open: UTC chosen",
        "panel: time zones closed",
        "panel: time zone Adelaide",
        "panel: the clock shows Sat 14 Nov 20:1",
        "panel: menu open: greeter, hello",
        "panel: menu closed",
        "panel: launched greeter (status 0)",
        "[cm] started greeter (launched)",
        "greeter: ready: window 1, decorated, titled \"Greeter\"",
        "panel: launched hello (status 0)",
        "[cm] started hello (launched)",
        "hello: ready: window 2, decorated, titled \"Hello\"",
        "panel: activated \"Greeter\" (status 0)",
        "compositor: window 1 activated by the desktop shell",
        "compositor: window 1: its minimise box was pressed",
        "compositor: window 1 minimised",
        "panel: minimised \"Hello\" (status 0)",
        "compositor: window 2 minimised",
        "compositor: window 1 restored",
        "compositor: window 1 activated by the desktop shell",
        "compositor: window 1: its close box was pressed",
        "greeter: closed",
        "[cm] greeter exited",
        "panel: launched greeter (status 0)",
        "[cm] started greeter (launched)",
        "greeter: ready: window 1, decorated, titled \"Greeter\"",
        "panel test: both apps minimised (step 1)",
        "panel test: the greeter gone, Hello minimised (step 2)",
        "panel test: the greeter back with the focus, Hello minimised (step 3)",
        "panel: keyboard layouts open: US chosen",
        "panel: keyboard layouts closed",
        "compositor: keyboard layout Dvorak",
        "panel: keyboard layout Dvorak (status 0)",
        "hello: the field holds \"pear\", the cursor at 4",
        "hello: copied \"pear\" to the clipboard",
        "compositor: window 2 copied 4 bytes to the clipboard",
        "compositor: window 1 activated by the desktop shell",
        "greeter: the clipboard holds \"pear\"",
        "greeter: the field holds \"pear\", the cursor at 4",
        "panel test: Hello back with the focus (step 4)",
        "panel test: the greeter with the focus again (step 5)",
        "panel test: keyboard layout 2",
        "panel: keyboard layouts open: Dvorak chosen",
        "compositor: keyboard layout French",
        "panel: keyboard layout French (status 0)",
        "greeter: the field holds \"pear\u{e9}\", the cursor at 6",
        "greeter: the field holds \"pear\u{e9}\u{e8}\u{e7}\u{e0}\", the cursor at 12",
        "panel test: keyboard layout 3",
        "[cm] watcher asked to shut down (pass)",
    ];
    check_log("desktop shell test", &out, &log)?;
    if shots != 11 {
        return Err(format!("desktop shell test: {shots} screenshots taken, want 11"));
    }
    println!("== desktop shell test passed ({})", arch.name());
    Ok(())
}

/// Boots `boot/input.manifest`: the compositor with a USB keyboard and
/// mouse. Through QEMU's monitor the host moves the pointer over window
/// A, clicks it (it takes the focus and comes in front) and types to it
/// (it is drawn anew at each key); presses on window B, holds the
/// pointer off it and lets go, and types to B; then, after the second
/// client kills the compositor and later the HID driver, types and points
/// again; last, a USB tablet puts the pointer over window B and the wheel
/// turns there. Seven screenshots must show every pixel right, the pointer
/// included.
fn input_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "input")?;
    println!("== input test on {}", img.path.display());
    let (out, shots) = run_script(&img, arch, "input test", input_script(), input_act)?;
    let log = [
        "hid: ready: a boot keyboard on device",
        "hid: ready: a pointer on device",
        "hid: ready: a pointer on device",
        "compositor: ready: the desktop on a 800x600 screen",
        "compositor: input subscribed: keys and the pointer",
        "[pass] input: window A shown",
        "[pass] input: window A is on the screen",
        "[pass] input: window B shown",
        "[pass] input: window B shown over window A, with the focus",
        "input: window A: the pointer came to (50, 30) (time 1)",
        "[pass] input: window A: clicked at (50, 30), so it has the focus and is in front (time 1)",
        "[pass] input: window A: typed \"abc\", drawn anew at each key",
        "input: window B: the pointer came to (200, 150)",
        "[pass] input: window B: held the pointer from (200, 150) to (400, 250), outside it, and let it go",
        "[pass] input: window B: typed \"d\", the first key it got: picture 4 on the screen",
        "input: killing the compositor",
        "[cm] fault injection: killing compositor",
        "compositor: ready: the desktop on a 800x600 screen",
        "input: window A: the compositor restarted; making the window again",
        "[pass] input: window A made again after the compositor's restart",
        "[pass] input: window B made again",
        "[pass] input: window B made again after the compositor's restart, with the focus",
        "[pass] input: window B: typed \"de\"",
        "input: window A: the pointer came to (50, 30) (time 2)",
        "input: killing the input driver",
        "[cm] fault injection: killing hid",
        "compositor: the input driver restarted; input subscribed again",
        "[pass] input: window B: typed \"def\" after the input driver's restart",
        "[pass] input: window A: clicked at (50, 30), so it has the focus and is in front (time 2)",
        "[pass] input: window B lost the focus to window A: picture 6 on the screen",
        "[pass] input: window B got only the keys typed to it (\"def\") and was told the pointer left it",
        "input: window B: the tablet put the pointer at (160, 100)",
        "input: window B: the wheel turned 2 steps up",
        "[pass] input: window B: the wheel turned 2 steps up and 1 down, the pointer at (160, 100): picture 7 on the screen",
        "input: done (0 failed)",
        "[cm] second asked to shut down (pass)",
    ];
    check_log("input test", &out, &log)?;
    if shots != input_pictures().len() {
        return Err(format!("input test: {shots} screenshots taken, want {}", input_pictures().len()));
    }
    println!("== input test passed ({})", arch.name());
    Ok(())
}

/// The rate the audio test's sound card plays at and QEMU records at.
const AUDIO_RATE: u32 = 22050;

/// Where QEMU records the audio test's sound.
fn audio_wav(arch: Arch) -> PathBuf {
    root().join("target").join(format!("audio-{}.wav", arch.name()))
}

/// A test sound of the audio test: length in frames, amplitude, and the
/// left and right channels' periods. The test client has the same table.
struct TestSound {
    name: &'static str,
    frames: usize,
    amp: i64,
    periods: (i64, i64),
}

const A1: TestSound = TestSound { name: "a1", frames: 6615, amp: 6000, periods: (100, 150) };
const A2: TestSound = TestSound { name: "a2", frames: 44100, amp: 7000, periods: (60, 90) };
const B2: TestSound = TestSound { name: "b2", frames: 11025, amp: 9000, periods: (44, 70) };
const B3: TestSound = TestSound { name: "b3", frames: 6615, amp: 8000, periods: (80, 120) };
const B4: TestSound = TestSound { name: "b4", frames: 6615, amp: 5000, periods: (50, 200) };

/// A triangle wave, as the test client makes it.
fn triangle(i: usize, period: i64, amp: i64) -> i16 {
    let p = i as i64 % period;
    let half = period / 2;
    let v = if p < half { -amp + 2 * amp * p / half } else { amp - 2 * amp * (p - half) / (period - half) };
    v as i16
}

impl TestSound {
    /// Frame `i`, silence past the end.
    fn frame(&self, i: usize) -> (i16, i16) {
        if i >= self.frames {
            return (0, 0);
        }
        (triangle(i, self.periods.0, self.amp), triangle(i, self.periods.1, self.amp))
    }
}

/// Checks the audio test's recording: a1, then a2 with b2 mixed into it
/// from some frame on, then b3, then b4, each frame exact, with nothing
/// but silence between them (of any length). A summary of what was found.
fn check_recording(bytes: &[u8]) -> Result<String, String> {
    // QEMU writes the header's sizes when it closes the file, which an
    // exit through the debug port does not wait for: the samples are
    // everything after the 44-byte header.
    let data = bytes.get(44..).ok_or("no WAV header")?;
    let w: Vec<(i16, i16)> = data
        .chunks_exact(4)
        .map(|f| (i16::from_le_bytes([f[0], f[1]]), i16::from_le_bytes([f[2], f[3]])))
        .collect();
    let mut at = 0;
    let mut gaps = Vec::new();
    let skip = |at: &mut usize, gaps: &mut Vec<usize>| {
        let from = *at;
        while *at < w.len() && w[*at] == (0, 0) {
            *at += 1;
        }
        gaps.push(*at - from);
    };
    let exact = |at: &mut usize, s: &TestSound| -> Result<(), String> {
        for i in 0..s.frames {
            let got = w.get(*at + i).copied();
            if got != Some(s.frame(i)) {
                return Err(format!(
                    "{} differs at its frame {i} (recording frame {}): {got:?}, want {:?}",
                    s.name,
                    *at + i,
                    s.frame(i)
                ));
            }
        }
        *at += s.frames;
        Ok(())
    };
    skip(&mut at, &mut gaps);
    exact(&mut at, &A1)?;
    skip(&mut at, &mut gaps);
    // a2 alone until b2 comes in, then the sum, saturating.
    let d = (0..A2.frames).find(|&t| w.get(at + t).copied() != Some(A2.frame(t))).ok_or("a2 played with no b2 in it")?;
    if d == 0 {
        return Err("a2 differs at its first frame".into());
    }
    let mixed = |t: usize| {
        let (a, b) = (A2.frame(t), if t >= d { B2.frame(t - d) } else { (0, 0) });
        (a.0.saturating_add(b.0), a.1.saturating_add(b.1))
    };
    for t in 0..A2.frames.max(d + B2.frames) {
        let got = w.get(at + t).copied();
        if got != Some(mixed(t)) {
            return Err(format!(
                "a2 with b2 from its frame {d} differs at frame {t} (recording frame {}): {got:?}, want {:?}",
                at + t,
                mixed(t)
            ));
        }
    }
    at += A2.frames.max(d + B2.frames);
    skip(&mut at, &mut gaps);
    exact(&mut at, &B3)?;
    skip(&mut at, &mut gaps);
    exact(&mut at, &B4)?;
    skip(&mut at, &mut gaps);
    if at != w.len() {
        return Err(format!("sound after b4, at recording frame {at}: {:?}", w[at]));
    }
    let ms = |frames: usize| frames * 1000 / AUDIO_RATE as usize;
    Ok(format!(
        "{} frames recorded ({} ms): a1; a2 with b2 mixed in from its frame {d} ({} ms on); b3; b4, every sample exact; silences of {:?} frames around them",
        w.len(),
        ms(w.len()),
        ms(d),
        gaps
    ))
}

/// The A/B test's system disk.
fn ab_disk(arch: Arch) -> PathBuf {
    root().join("target").join(format!("ab-test-disk-{}.img", arch.name()))
}

/// A signed system bundle for the A/B slots: `boot/ab-system.manifest`
/// with its client in `role`, and the test client's image.
fn system_bundle(arch: Arch, role: u64, version: u64) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(root().join("boot").join("ab-system.manifest"))
        .map_err(|e| format!("reading boot/ab-system.manifest: {e}"))?
        .replace("\r\n", "\n");
    assert_eq!(text.matches("  arg 32\n").count(), 1, "the A/B client");
    let text = text.replace("  arg 32\n", &format!("  arg {role}\n"));
    let client = user_program("superior-testclient", arch)?;
    let image = std::fs::read(&client).map_err(|e| format!("reading {}: {e}", client.display()))?;
    let files = vec![("manifest".to_string(), text.into_bytes()), ("testclient".to_string(), image)];
    Ok(sign(pack(&files), version, &signing_key()?))
}

/// The update test's system disk.
fn update_disk(arch: Arch) -> PathBuf {
    root().join("target").join(format!("update-test-disk-{}.img", arch.name()))
}

/// The update test's system (`boot/update-system.manifest`: the network
/// and the updater), signed as `version`.
fn update_bundle(arch: Arch, version: u64) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(root().join("boot/update-system.manifest"))
        .map_err(|e| format!("reading boot/update-system.manifest: {e}"))?
        .replace("\r\n", "\n");
    let mut files = vec![("manifest".to_string(), text.into_bytes())];
    for (name, package) in [("virtio-net", "superior-virtio-net"), ("net", "superior-net"), ("updater", "superior-updater")] {
        let path = user_program(package, arch)?;
        files.push((name.to_string(), std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?));
    }
    Ok(sign(pack(&files), version, &signing_key()?))
}

/// Where the update test's host serves updates (the guest asks the
/// gateway's port of this number).
const UPDATE_PORT: u16 = 47080;

/// The update server's TLS key (a development key in `target/keys`, made
/// the first time): its seed, and its public key in hex, which the updater
/// is built with.
fn update_key() -> Result<([u8; 32], String), String> {
    let key = dev_key("update-server.seed")?;
    let public: String = key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    Ok((key.to_bytes(), public))
}

/// A TLS 1.3 server configuration with a self-signed certificate for the
/// Ed25519 key of `seed`.
fn tls_server_config(seed: &[u8; 32]) -> Result<std::sync::Arc<rustls::ServerConfig>, String> {
    // PKCS #8 for an Ed25519 private key (RFC 8410), the seed last.
    let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    pkcs8.extend_from_slice(seed);
    let key = rcgen::KeyPair::try_from(&pkcs8[..]).map_err(|e| format!("the update server's key: {e}"))?;
    let cert = rcgen::CertificateParams::new(vec!["updates.superior.test".to_string()])
        .and_then(|p| p.self_signed(&key))
        .map_err(|e| format!("the update server's certificate: {e}"))?;
    let private = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.into());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .and_then(|b| b.with_no_client_auth().with_single_cert(vec![cert.der().clone()], private))
        .map_err(|e| format!("the update server's TLS configuration: {e}"))?;
    Ok(std::sync::Arc::new(config))
}

/// Serves `GET /system?have=N` over TLS 1.3 on `UPDATE_PORT` until `stop`.
/// The first connection is an impostor's (a certificate for another key,
/// which the updater must refuse before it asks anything); then the
/// requests are answered in turn: `v3` changed after signing, `v3` cut off
/// half way (the connection closed early, with no close_notify), `v3`, then
/// 204 (nothing newer). The request lines, in order.
fn update_server(
    v3: Vec<u8>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<std::thread::JoinHandle<Vec<String>>, String> {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;
    let l = TcpListener::bind(("127.0.0.1", UPDATE_PORT))
        .map_err(|e| format!("binding the update port {UPDATE_PORT}: {e}"))?;
    l.set_nonblocking(true).map_err(|e| e.to_string())?;
    let real = tls_server_config(&update_key()?.0)?;
    let impostor = tls_server_config(&[0x77; 32])?;
    Ok(std::thread::spawn(move || {
        let mut asked = Vec::new();
        let mut connections = 0;
        while !stop.load(Ordering::Relaxed) {
            let Ok((s, _)) = l.accept() else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            connections += 1;
            let config = if connections == 1 { impostor.clone() } else { real.clone() };
            let Ok(conn) = rustls::ServerConnection::new(config) else { continue };
            let mut r = BufReader::new(rustls::StreamOwned::new(conn, s));
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            // The rest of the head.
            let mut h = String::new();
            while r.read_line(&mut h).is_ok_and(|n| n > 2) {
                h.clear();
            }
            asked.push(line.trim_end().to_string());
            let mut s = r.into_inner();
            let ok = |len: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: application/octet-stream\r\n\r\n");
            let _ = match asked.len() {
                1 => {
                    let mut changed = v3.clone();
                    let n = changed.len();
                    changed[n / 2] ^= 0x10;
                    s.write_all(ok(n).as_bytes()).and_then(|_| s.write_all(&changed))
                }
                2 => s.write_all(ok(v3.len()).as_bytes()).and_then(|_| s.write_all(&v3[..v3.len() / 2])),
                3 => s.write_all(ok(v3.len()).as_bytes()).and_then(|_| s.write_all(&v3)),
                _ => s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n"),
            };
            // Cut short: the connection just ends. Otherwise close_notify.
            if asked.len() != 2 {
                s.conn.send_close_notify();
            }
            let _ = s.flush();
            let _ = s.sock.shutdown(std::net::Shutdown::Both);
        }
        asked
    }))
}

/// The downloading updater (`user/updater`), in one run of
/// `boot/update.manifest` on a disk whose slot A holds the system at
/// version 2: the updater confirms it once the network is up and asks the
/// host for a newer system, over TLS 1.3 to the key it was built with. The
/// first server it reaches holds another key and is refused in the
/// handshake; the next download (changed after signing) is refused by the
/// manager and the one after cut short, each tried again; the fourth is
/// staged, and the updater restarts the machine into it; version 3 boots
/// from slot B, confirms, and finds nothing newer.
fn update_test(arch: Arch) -> Result<(), String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use superior_objects::ab::{SECTOR, SLOT_FIRST, SLOT_SECTORS, slot_header};
    let img = image_with(false, arch, "update")?;
    let v2 = update_bundle(arch, 2)?;
    let v3 = update_bundle(arch, 3)?;
    let mut disk = vec![0u8; ((SLOT_FIRST[1] + SLOT_SECTORS) as usize) * SECTOR];
    let at = SLOT_FIRST[0] as usize * SECTOR;
    disk[at..at + SECTOR].copy_from_slice(&slot_header(v2.len()));
    disk[at + SECTOR..at + SECTOR + v2.len()].copy_from_slice(&v2);
    let path = update_disk(arch);
    std::fs::write(&path, disk).map_err(|e| format!("writing {}: {e}", path.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let server = update_server(v3.clone(), stop.clone())?;
    println!("== update test on {} (version 3 is {} bytes)", img.path.display(), v3.len());
    let out = run_to_exit(&img, Duration::from_secs(240));
    stop.store(true, Ordering::Relaxed);
    let asked = server.join().unwrap_or_default();
    let out = out?;
    let staged = format!("updater: download 4: {} bytes written to the free slot and staged; restarting into it", v3.len());
    let cut = format!("updater: download 3: cut short, {} of {} bytes; trying again", v3.len() / 2, v3.len());
    let key = &update_key()?.1[..8];
    let asking = |have: u32| format!("updater: asking https://10.0.3.2:47080/system?have={have} (TLS 1.3, the server's key {key}...)");
    check_log(
        "update test",
        &out,
        &[
            "[cm] booting system slot A (version 2)",
            "updater: running version 2 from slot A",
            "[cm] system slot A confirmed: active, rollback floor 2",
            "updater: the network is up (10.0.3.30): version 2 confirmed",
            &asking(2),
            "updater: download 1 failed: TLS: the server does not hold the update server's key; trying again",
            "[cm] update in slot B refused: its signature does not verify",
            "updater: download 2: refused by the manager (status 3); trying again",
            &cut,
            "[cm] update staged in slot B (version 3): the next boot tries it once",
            &staged,
            "[cm] updater asked to restart the machine",
            "[cm] booting system slot B (version 3)",
            "updater: running version 3 from slot B",
            "[cm] system slot B confirmed: active, rollback floor 3",
            "updater: the network is up (10.0.3.30): version 3 confirmed",
            &asking(3),
            "updater: no system newer than version 3",
            "[cm] updater asked to shut down (pass)",
        ],
    )?;
    let want = ["have=2", "have=2", "have=2", "have=3"].map(|h| format!("GET /system?{h} HTTP/1.1"));
    if asked != want {
        return Err(format!("update test: the host was asked {asked:?}, not {want:?}"));
    }
    println!("== the host served 4 requests: {}", asked.join(", "));
    println!("== update test passed ({})", arch.name());
    Ok(())
}

/// Writes a fresh A/B disk (`superior_objects::ab`): no boot record, slot
/// A holding system version 2 (client role 32), slot B empty, and after
/// the slots three downloads for the client to stage: version 3 (role 33)
/// changed after signing, version 3, and version 4 (role 34).
fn write_ab_disk(arch: Arch) -> Result<(), String> {
    use superior_objects::ab::{SECTOR, SLOT_FIRST, SLOT_SECTORS, slot_header};
    let downloads = SLOT_FIRST[1] + SLOT_SECTORS;
    let mut disk = vec![0u8; ((downloads + 3 * SLOT_SECTORS) as usize) * SECTOR];
    let mut put = |first: u64, bundle: &[u8]| {
        let at = first as usize * SECTOR;
        disk[at..at + SECTOR].copy_from_slice(&slot_header(bundle.len()));
        disk[at + SECTOR..at + SECTOR + bundle.len()].copy_from_slice(bundle);
    };
    put(SLOT_FIRST[0], &system_bundle(arch, 32, 2)?);
    let mut changed = system_bundle(arch, 33, 3)?;
    let n = changed.len();
    changed[n / 2] ^= 0x10;
    put(downloads, &changed);
    put(downloads + SLOT_SECTORS, &system_bundle(arch, 33, 3)?);
    put(downloads + 2 * SLOT_SECTORS, &system_bundle(arch, 34, 4)?);
    let path = ab_disk(arch);
    std::fs::write(&path, disk).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// A/B updates, in five boots of one disk (`boot/ab.manifest`: the boot
/// bundle holds the disk drivers; the system is in the slots):
/// 1. a fresh disk boots version 2 from slot A, which confirms, has an
///    update changed after signing refused, and stages version 3 in B;
/// 2. version 3 boots from B (its one try) and never confirms;
/// 3. so slot A again, the update dropped; it stages version 4;
/// 4. version 4 boots from B and confirms: B active, rollback floor 4;
///    version 2, still in A, may not be staged again;
/// 5. with slot B damaged on the disk, nothing boots: B fails its
///    signature, and A is older than the floor.
fn ab_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "ab")?;
    write_ab_disk(arch)?;
    let boots: [(&str, &[&str]); 4] = [
        (
            "fresh disk",
            &[
                "[cm] booting system slot A (version 2): 1 more components",
                "[pass] ab: running version 2 from slot A, rollback floor 0",
                "[pass] ab: a fresh disk boots slot A",
                "[cm] system slot A confirmed: active, rollback floor 2",
                "[pass] ab: confirmed it came up",
                "[cm] update in slot B refused: its signature does not verify",
                "[pass] ab: an update changed after signing is refused",
                "[cm] update staged in slot B (version 3): the next boot tries it once",
                "[pass] ab: version 3 written to slot B and staged",
                "[cm] client asked to shut down (pass)",
            ],
        ),
        (
            "update to version 3",
            &[
                "[cm] booting system slot B (version 3): 1 more components",
                "[pass] ab: running version 3 from slot B, rollback floor 2",
                "[pass] ab: the staged update boots, and does not confirm",
                "[cm] client asked to shut down (pass)",
            ],
        ),
        (
            "fall back",
            &[
                "[cm] the update in slot B never confirmed it came up; dropped it",
                "[cm] booting system slot A (version 2, fell back): 1 more components",
                "[pass] ab: running version 2 from slot A (fell back), rollback floor 2",
                "[pass] ab: version 3 never confirmed, so slot A again",
                "[cm] update staged in slot B (version 4): the next boot tries it once",
                "[pass] ab: version 4 written to slot B and staged",
                "[cm] client asked to shut down (pass)",
            ],
        ),
        (
            "update to version 4",
            &[
                "[cm] booting system slot B (version 4): 1 more components",
                "[pass] ab: the staged version 4 boots",
                "[cm] system slot B confirmed: active, rollback floor 4",
                "[pass] ab: confirmed it came up: slot B active, rollback floor 4",
                "[cm] update in slot A refused: older than the rollback floor",
                "[pass] ab: version 2, still in slot A, may not be staged again: a rollback",
                "[cm] client asked to shut down (pass)",
            ],
        ),
    ];
    for (k, (what, steps)) in boots.iter().enumerate() {
        println!("== A/B test, boot {} ({what}) on {}", k + 1, img.path.display());
        let out = run_to_exit(&img, Duration::from_secs(90))?;
        check_log(&format!("A/B boot {} ({what})", k + 1), &out, steps)?;
    }
    // Damage slot B's bundle on the disk.
    let path = ab_disk(arch);
    let mut disk = std::fs::read(&path).map_err(|e| e.to_string())?;
    let at = (superior_objects::ab::SLOT_FIRST[1] as usize + 1) * superior_objects::ab::SECTOR + 4096;
    disk[at] ^= 0x01;
    std::fs::write(&path, disk).map_err(|e| e.to_string())?;
    println!("== A/B test, boot 5 (slot B damaged) on {}", img.path.display());
    let (code, out) = run_capture(&img, Duration::from_secs(90), |_| {})?;
    find_in_order(
        &out,
        &[
            "[cm] system slot B refused: its signature does not verify",
            "[cm] system slot A refused: older than the rollback floor",
            "[cm] no system slot to boot",
        ],
    )
    .map_err(|step| format!("A/B boot 5: missing (in order) {step:?}"))?;
    if out.contains("[cm] booting system slot") || code.is_none() || code == Some(QEMU_PASS) {
        return Err(format!("A/B boot 5: something booted, or QEMU exit {code:?}"));
    }
    println!("A/B test passed");
    Ok(())
}

/// The package test's system disk.
fn packages_disk(arch: Arch) -> PathBuf {
    root().join("target").join(format!("packages-test-disk-{}.img", arch.name()))
}

/// The app the package test installs: the test client in role 36, which
/// calls the installer's `report` service.
const APP_MANIFEST: &str = "component app\n  image app\n  arg 36\n  uses report 0\n";

/// A package holding `manifest` and the test client as `app`, signed with
/// `key` as version 1.
fn app_package(arch: Arch, manifest: &str, key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>, String> {
    app_package_version(arch, manifest, key, 1)
}

/// [`app_package`] signed as `version`.
fn app_package_version(arch: Arch, manifest: &str, key: &ed25519_dalek::SigningKey, version: u64) -> Result<Vec<u8>, String> {
    let client = user_program("superior-testclient", arch)?;
    let image = std::fs::read(&client).map_err(|e| format!("reading {}: {e}", client.display()))?;
    let files = vec![("manifest".to_string(), manifest.as_bytes().to_vec()), ("app".to_string(), image)];
    Ok(sign(pack(&files), version, key))
}

/// Writes a fresh package test disk: an empty store, and after it the
/// packages the installer downloads (see the test client's
/// `PACKAGE_DOWNLOADS`): the app signed by another key, the app changed
/// after signing, apps asking for the disk, a device and the right to
/// install, the app, and its versions 2 and 3 (the test client in roles 44
/// and 45, saying so).
fn write_packages_disk(arch: Arch) -> Result<(), String> {
    use superior_objects::ab::SECTOR;
    use superior_objects::package::{COUNT, FIRST, SECTORS, header};
    let key = publisher_key()?;
    let mut changed = app_package(arch, APP_MANIFEST, &key)?;
    let n = changed.len();
    changed[n / 2] ^= 0x04;
    let downloads = [
        app_package(arch, APP_MANIFEST, &ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]))?,
        changed,
        app_package(arch, &format!("{APP_MANIFEST}  uses block 1\n"), &key)?,
        app_package(arch, &format!("{APP_MANIFEST}  device pci-config 1\n"), &key)?,
        app_package(arch, &format!("{APP_MANIFEST}  install-control\n"), &key)?,
        app_package(arch, APP_MANIFEST, &key)?,
        app_package_version(arch, &APP_MANIFEST.replace("arg 36", "arg 44"), &key, 2)?,
        app_package_version(arch, &APP_MANIFEST.replace("arg 36", "arg 45"), &key, 3)?,
    ];
    let first = FIRST + COUNT as u64 * SECTORS;
    let mut disk = vec![0u8; ((first + downloads.len() as u64 * SECTORS) as usize) * SECTOR];
    for (k, p) in downloads.iter().enumerate() {
        let at = (first + k as u64 * SECTORS) as usize * SECTOR;
        disk[at..at + SECTOR].copy_from_slice(&header(p.len()));
        disk[at + SECTOR..at + SECTOR + p.len()].copy_from_slice(p);
    }
    let path = packages_disk(arch);
    std::fs::write(&path, disk).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Signed app packages, in three boots of one disk
/// (`boot/packages.manifest`):
/// 1. the installer has five bad packages refused (another key, changed
///    after signing, asking for the disk, a device, the right to
///    install) and cleared from the store, then installs the app, which
///    runs and calls it; a second copy is refused; version 2 replaces it
///    and calls in, version 1 is refused in its place, and version 3 is
///    written to the store and left, as by an upgrade cut short;
/// 2. version 3 is installed at boot from the store and version 2
///    refused and cleared, the app calls in as version 3, and is
///    uninstalled;
/// 3. nothing is installed.
fn packages_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "packages")?;
    write_packages_disk(arch)?;
    let boots: [(&str, &[&str]); 3] = [
        (
            "installing",
            &[
                "[cm] package store: 0 installed",
                "[pass] packages: a fresh store holds no packages",
                "[cm] package in store slot 0 refused: its signature does not verify",
                "[pass] packages: the app signed by another key is refused",
                "[cm] package in store slot 0 refused: its signature does not verify",
                "[pass] packages: the app changed after signing is refused",
                "[cm] package in store slot 0 refused: uses a service not offered to apps (block)",
                "[pass] packages: an app that uses the disk is refused",
                "[cm] package in store slot 0 refused: asks for a device (pci-config)",
                "[pass] packages: an app that asks for a device is refused",
                "[cm] package in store slot 0 refused: asks for a manager privilege (app)",
                "[pass] packages: an app that asks to install packages is refused",
                "[pass] packages: refused packages are cleared from the store",
                "[cm] installed package in store slot 0 (version 1): app",
                "[cm] started app (boot)",
                "[pass] packages: the app is installed",
                "[pass] packages: the installed app runs, and calls the installer",
                "[cm] package in store slot 1 refused: a component of that name is installed (app)",
                "[pass] packages: installing it twice is refused",
                "[pass] packages: the store holds the app alone",
                "[cm] package in store slot 1 (version 2) replaces slot 0's (version 1)",
                "[cm] uninstalled package in store slot 0: app",
                "[cm] installed package in store slot 1 (version 2): app",
                "[pass] packages: version 2 replaces version 1 (status 0, slot 0 replaced)",
                "[pass] packages: the app runs as version 2 (2)",
                "[pass] packages: the store holds version 2 alone (0b10)",
                "[cm] package in store slot 0 refused: no newer than the installed one",
                "[pass] packages: an older version is refused in its place (status",
                "[pass] packages: version 3 is written to the store and left there",
                "[cm] installer asked to shut down (pass)",
            ],
        ),
        (
            "installed from the store",
            &[
                "[cm] installed package in store slot 0 (version 3): app",
                "[cm] package in store slot 1 refused: no newer than the installed one",
                "[cm] package store: 1 installed",
                "[pass] packages: the app was installed at boot from the store",
                "[pass] packages: it runs as version 3, the newer left in the store (3)",
                "[cm] uninstalled package in store slot 0: app",
                "[pass] packages: the app is uninstalled",
                "[cm] installer asked to shut down (pass)",
            ],
        ),
        (
            "uninstalled",
            &[
                "[cm] package store: 0 installed",
                "[pass] packages: once uninstalled, nothing is installed at boot",
                "[cm] installer asked to shut down (pass)",
            ],
        ),
    ];
    for (k, (what, steps)) in boots.iter().enumerate() {
        println!("== package test, boot {} ({what}) on {}", k + 1, img.path.display());
        let out = run_to_exit(&img, Duration::from_secs(90))?;
        check_log(&format!("package boot {} ({what})", k + 1), &out, steps)?;
        if k == 2 && out.contains("[cm] started app (boot)") {
            return Err("package boot 3: the uninstalled app started".into());
        }
    }
    println!("package test passed");
    Ok(())
}

/// Verified boot: boots `boot/test.manifest` signed properly and checks
/// the kernel verified it and printed its measurement (the SHA-256 of the
/// signed bundle, computed here too); then signed in each way it must
/// refuse (a changed byte, an untrusted key, no signature, an older
/// version) and checks it stopped the machine before running anything.
fn verified_boot_test(arch: Arch) -> Result<(), String> {
    let img = image_sealed(false, arch, "test", "virtio-blk", Seal::Good)?;
    println!("== verified boot test on {}", img.path.display());
    let signed = root().join("target").join(format!("bundle-{}-test.signed", arch.name()));
    let bytes = std::fs::read(&signed).map_err(|e| format!("reading {}: {e}", signed.display()))?;
    let measurement: String = superior_objects::crypto::sha2::sha256(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let public = signing_key()?.verifying_key().to_bytes();
    let line = format!(
        "[boot] bundle verified: version {BUNDLE_VERSION}, signed by key {:02x}{:02x}{:02x}{:02x}..., measurement sha256:{measurement}",
        public[0], public[1], public[2], public[3]
    );
    let out = run_to_exit(&img, Duration::from_secs(60))?;
    check_log("verified boot (signed)", &out, &[&line, "[ok] Component Manager loaded", "[cm] manifest:"])?;
    println!("verified: the kernel measured {measurement}, as computed here");
    for (seal, why) in [
        (Seal::Tampered, "its signature does not verify against the built-in key"),
        (Seal::OtherKey, "its signature does not verify against the built-in key"),
        (Seal::Unsigned, "it is not signed"),
        (Seal::Old, "it is older than this kernel accepts (a rollback)"),
    ] {
        let img = image_sealed(false, arch, "test", "virtio-blk", seal)?;
        println!("== verified boot test: a bundle {seal:?}");
        let (code, out) = run_capture(&img, Duration::from_secs(60), |_| {})?;
        let refused = format!("[boot] boot bundle REFUSED: {why}");
        if !out.contains(&refused) {
            return Err(format!("verified boot ({seal:?}): missing {refused:?}"));
        }
        if out.contains("Component Manager loaded") || out.contains("[cm]") {
            return Err(format!("verified boot ({seal:?}): something from the bundle ran"));
        }
        if code.is_none() || code == Some(QEMU_PASS) {
            return Err(format!("verified boot ({seal:?}): QEMU exit {code:?}, not the failure code"));
        }
        println!("refused ({seal:?}): {why}");
    }
    println!("verified boot test passed");
    Ok(())
}

/// The container with QEMU and swtpm (`tpm/Dockerfile`), built the first
/// time it is wanted.
fn tpm_container() -> Result<(), String> {
    let have = Command::new("docker")
        .args(["image", "inspect", "superior-tpm"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("could not run docker: {e}"))?;
    if !have.success() {
        println!("== building the TPM test container");
        run(Command::new("docker").args(["build", "-t", "superior-tpm"]).arg(root().join("tpm")))?;
    }
    Ok(())
}

/// Measured boot and the TPM's rollback counter. QEMU's Windows build has
/// no TPM backend, so the three boots run in a Linux container (QEMU with
/// swtpm, `tpm/`), on one TPM whose state lasts across them: version 2 of
/// the boot bundle, then version 3, then version 2 again. Each accepted
/// boot must extend PCR 9 with the bundle's measurement (the PCR's value
/// as computed here from a fresh one) and raise the counter to its
/// version; the last, though signed and no older than the kernel's own
/// floor, must be refused as older than the counter, with nothing from it
/// run.
fn tpm_test(arch: Arch) -> Result<(), String> {
    use superior_objects::crypto::sha2::sha256;
    tpm_container()?;
    let dir = root().join("target").join("tpm");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut boots = vec![];
    for (k, seal, version) in [(1, Seal::Good, BUNDLE_VERSION), (2, Seal::Newer, BUNDLE_VERSION + 1), (3, Seal::Good, BUNDLE_VERSION)] {
        let img = image_sealed(false, arch, "test", "virtio-blk", seal)?;
        let signed = root().join("target").join(format!("bundle-{}-test.signed", arch.name()));
        let bundle = std::fs::read(&signed).map_err(|e| format!("reading {}: {e}", signed.display()))?;
        let m = sha256(&bundle);
        // The PCR from zero, extended once.
        let mut both = [0u8; 64];
        both[32..].copy_from_slice(&m);
        let name = format!("boot-{}-{k}", arch.name());
        std::fs::copy(&img.path, dir.join(&name)).map_err(|e| format!("copying {}: {e}", img.path.display()))?;
        boots.push((name, version, hex(&m), hex(&sha256(&both))));
    }
    let tpm = "-chardev socket,id=chrtpm,path=/tmp/tpm/sock -tpmdev emulator,id=tpm0,chardev=chrtpm";
    let qemu = match arch {
        Arch::X86_64 => format!(
            "qemu-system-x86_64 -m 512M -smp 1 -drive format=raw,file=/work/target/tpm/$IMG -device isa-debug-exit,iobase=0xf4,iosize=0x04 {tpm} -device tpm-tis,tpmdev=tpm0"
        ),
        Arch::Aarch64 => format!(
            "qemu-system-aarch64 -machine virt,highmem=off,gic-version=3 -cpu cortex-a72 -m 512M -smp 1 -kernel /work/target/tpm/$IMG -semihosting-config enable=on,target=native {tpm} -device tpm-tis-device,tpmdev=tpm0"
        ),
    };
    let mut script = String::from("rm -rf /tmp/tpm && mkdir -p /tmp/tpm\n");
    for (k, (name, ..)) in boots.iter().enumerate() {
        script += &format!(
            "IMG={name}\nswtpm socket --tpm2 --tpmstate dir=/tmp/tpm --ctrl type=unixio,path=/tmp/tpm/sock --terminate --daemon\n\
             timeout 90 {qemu} -serial stdio -display none -no-reboot -monitor none </dev/null\n\
             echo \"== tpm boot {} exit $?\"\nsleep 1\n",
            k + 1
        );
    }
    println!("== TPM test ({}): three boots on one software TPM", arch.name());
    let out = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work", root().display()))
        .args(["superior-tpm", "sh", "-c", &script])
        .output()
        .map_err(|e| format!("could not run docker: {e}"))?;
    let all = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    let log = root().join("target").join(format!("tpm-{}.log", arch.name()));
    let _ = std::fs::write(&log, format!("{all}\n{}", String::from_utf8_lossy(&out.stderr)));
    let mut rest = all.as_str();
    for (k, (_, version, m, pcr)) in boots.iter().enumerate() {
        let marker = format!("== tpm boot {} exit ", k + 1);
        let at = rest.find(&marker).ok_or_else(|| format!("tpm: boot {} did not finish (see {})", k + 1, log.display()))?;
        let (this, after) = rest.split_at(at);
        let code: i32 = after[marker.len()..].lines().next().unwrap_or("").trim().parse().unwrap_or(-1);
        rest = &after[marker.len()..];
        let what = format!("tpm boot {} (version {version})", k + 1);
        if k < 2 {
            let lines = [
                "[ok] TPM 2.0 over TIS".to_string(),
                format!("[boot] bundle verified: version {version}, signed by key "),
                format!("[tpm] PCR 9 extended with the bundle's measurement: now sha256:{pcr}"),
                format!("[tpm] rollback counter: {version} (nothing older boots)"),
                "[ok] Component Manager loaded".to_string(),
                "[cm] manifest:".to_string(),
            ];
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            check_log(&what, this, &lines)?;
            if !this.contains(&format!("measurement sha256:{m}")) {
                return Err(format!("{what}: the kernel's measurement is not sha256:{m}"));
            }
            println!("{what}: PCR 9 = sha256:{pcr} as computed here; the counter raised to {version}");
        } else {
            let lines = [
                format!("[tpm] bundle version {version} is older than the TPM's rollback counter ({})", version + 1),
                "[boot] boot bundle REFUSED: it is older than the TPM's rollback counter (a rollback)".to_string(),
            ];
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            check_log(&what, this, &lines)?;
            if this.contains("Component Manager loaded") || this.contains("[cm]") {
                return Err(format!("{what}: something from the bundle ran"));
            }
            if code == QEMU_PASS || code == 124 {
                return Err(format!("{what}: exit {code}, not the failure code"));
            }
            println!("{what}: refused, though signed and no older than the kernel's own floor ({BUNDLE_VERSION})");
        }
    }
    println!("== TPM test passed ({})", arch.name());
    Ok(())
}

/// UEFI Secure Boot over the AArch64 loader, which carries the kernel and
/// with it the boot bundle's key: the firmware checks the loader against
/// its `db`, the kernel checks the bundle. In the TPM container (which has
/// openssl, sbsign and virt-fw-vars) the test makes a Secure Boot PK, KEK
/// and db (kept in `target/keys/secure-boot`, never in the repository) and
/// another key, signs the loader with db and with the other key, and makes
/// edk2's variable store with PK, KEK and db enrolled. Then QEMU's edk2,
/// with that store: the loader signed with db boots, says Secure Boot is
/// on and the kernel's boot test runs; signed with the other key, changed
/// after signing, or unsigned, the firmware refuses it and nothing of
/// Superior runs. The firmware is Debian's AArch64 edk2 (AAVMF), from the
/// container: QEMU's own build has no Secure Boot.
///
/// x86-64 is not covered: its UEFI loader is the `bootloader` crate's,
/// which loads the kernel from a file of its own that Secure Boot would
/// not check.
fn secure_boot_test(arch: Arch) -> Result<(), String> {
    if arch != Arch::Aarch64 {
        println!("== Secure Boot test: AArch64 only (x86-64's loader leaves the kernel unchecked)");
        return Ok(());
    }
    tpm_container()?;
    let img = uefi_image(Arch::Aarch64, "test")?;
    let dir = root().join("target").join("sb");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let efi = root().join("target").join("aarch64-unknown-uefi").join("release").join("superior-uefi-loader.efi");
    std::fs::copy(&efi, dir.join("loader.efi")).map_err(|e| format!("copying {}: {e}", efi.display()))?;
    // The variable store's template: QEMU's (the same layout as Debian's,
    // which virt-fw-vars misreads).
    let template = aavmf().with_file_name("edk2-arm-vars.fd");
    std::fs::copy(&template, dir.join("template-vars.fd")).map_err(|e| format!("copying {}: {e}", template.display()))?;
    let script = r#"set -e
# Debian's AArch64 edk2, which has Secure Boot.
cp /usr/share/AAVMF/AAVMF_CODE.fd /work/target/sb/code.fd
cd /work/target
mkdir -p keys/secure-boot && cd keys/secure-boot
for k in PK KEK db other; do
  [ -f $k.crt ] || openssl req -quiet -new -x509 -newkey rsa:2048 -nodes -days 3650 -sha256      -subj "/CN=Superior development $k/" -keyout $k.key -out $k.crt 2>/dev/null
done
cd /work/target/sb
sbsign --key ../keys/secure-boot/db.key --cert ../keys/secure-boot/db.crt --output signed.efi loader.efi
sbsign --key ../keys/secure-boot/other.key --cert ../keys/secure-boot/other.crt --output foreign.efi loader.efi
python3 -c "import sys; b=bytearray(open('signed.efi','rb').read()); b[len(b)//3]^=0x40; open('tampered.efi','wb').write(b)"
G=6f8c0a2e-2a3c-4d25-9b1f-5e5d0c1b7a01
virt-fw-vars --input template-vars.fd --output /tmp/vars.fd --set-pk $G ../keys/secure-boot/PK.crt --add-kek $G ../keys/secure-boot/KEK.crt   --add-db $G ../keys/secure-boot/db.crt --secure-boot
cp /tmp/vars.fd vars.fd
echo signed and enrolled"#;
    println!("== Secure Boot: keys, signatures and the firmware's variables (in the container)");
    run(Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work", root().display()))
        .args(["superior-tpm", "sh", "-c", script]))?;
    for (file, good, what) in [
        ("signed.efi", true, "signed with db"),
        ("foreign.efi", false, "signed with a key not in db"),
        ("tampered.efi", false, "changed after signing"),
        ("loader.efi", false, "unsigned"),
    ] {
        let disk = dir.join(format!("disk-{file}.img"));
        esp_disk(&[("EFI/BOOT/BOOTAA64.EFI", &dir.join(file))], &disk)?;
        let vars = dir.join("run-vars.fd");
        std::fs::copy(dir.join("vars.fd"), &vars).map_err(|e| format!("copying the variable store: {e}"))?;
        let mut run_img = img.clone();
        run_img.path = disk;
        run_img.vars = Some(vars);
        run_img.firmware = Some(dir.join("code.fd"));
        println!("== Secure Boot: the loader {what}");
        if good {
            let out = run_to_exit(&run_img, Duration::from_secs(120))?;
            let out = out.find("Superior UEFI loader").map_or("", |at| &out[at..]);
            check_log(
                &format!("secure boot ({what})"),
                out,
                &[
                    "Superior UEFI loader (AArch64)",
                    "loader: Secure Boot is on: the firmware verified this loader, the kernel inside it",
                    "Superior microkernel",
                    "[boot] bundle verified: version",
                    "[cm] manifest:",
                ],
            )?;
            println!("booted: Secure Boot on, the loader and the kernel in it verified by the firmware");
        } else {
            let (_, out) = run_capture(&run_img, Duration::from_secs(25), |_| {})?;
            if out.contains("Superior UEFI loader") || out.contains("Superior microkernel") {
                return Err(format!("secure boot ({what}): the firmware started it"));
            }
            if !out.contains("Access Denied") {
                return Err(format!("secure boot ({what}): the firmware did not say Access Denied"));
            }
            println!("refused by the firmware (Access Denied)");
        }
    }
    println!("== Secure Boot test passed (aarch64)");
    Ok(())
}

/// Boots `boot/suspend.manifest` and checks that the client's two
/// suspends each quiesce the virtio-blk driver (which resets its disk) and
/// the PCI bus server (which keeps every function's configuration), stop
/// the machine, and bring the disk back so that it reads right after.
///
/// On x86-64 the machine suspends to RAM (ACPI S3: QEMU resets every
/// device, keeping only memory): the first time for the 200 ticks asked
/// (the RTC alarm wakes it, 2 s on the host's clock), the second time for
/// a minute, which a key pressed on QEMU's PS/2 keyboard cuts short once
/// QEMU says the machine is asleep. On AArch64 (QEMU's `virt` has no
/// sleep states) every CPU parks with its tick stopped for 200 ticks,
/// twice.
fn suspend_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "suspend")?;
    println!("== suspend test on {}", img.path.display());
    let ram = arch == Arch::X86_64;
    // When each suspend began and ended, on the host's clock.
    let marks: Arc<Mutex<Vec<(usize, Instant)>>> = Arc::default();
    let seen = marks.clone();
    let pressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let press = pressed.clone();
    let woken: Arc<Mutex<Option<Result<Duration, String>>>> = Arc::default();
    let wake = woken.clone();
    let out = run_to_exit_watching(&img, Duration::from_secs(120), move |all| {
        let n = all.matches("[power] suspending").count() + all.matches("[power] resumed").count();
        let mut m = seen.lock().unwrap();
        while m.len() < n {
            let k = m.len();
            m.push((k, Instant::now()));
        }
        // The second suspend to RAM: press a key once QEMU has the
        // machine asleep.
        if ram && n == 3 && !press.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let wake = wake.clone();
            std::thread::spawn(move || {
                *wake.lock().unwrap() = Some(press_key_when_asleep());
            });
        }
    })?;
    let (to, woke_by) = if ram {
        ("[power] suspending to RAM (ACPI S3) for", ["[power] woke from S3: the RTC alarm", "[power] woke from S3: the power button (or a key)"])
    } else {
        ("[power] suspending to idle for", ["[power] suspending to idle", "[power] suspending to idle"])
    };
    let mut steps = vec![];
    if ram {
        steps.push("[ok] ACPI: S3 (suspend to RAM): SLP_TYP");
    }
    steps.extend([
        "[cm] manifest: 5 components",
        "virtio-blk: ready:",
        "virtio-net: ready: ",
        "[pass] suspend: read 8 sectors before suspending: every word right",
        "[pass] suspend: the driver refuses SUSPEND from a client",
    ]);
    for k in 0..2 {
        steps.extend([
            "net: suspended: the driver and DHCP left alone",
            "virtio-net: suspended: device reset, bus mastering off",
            "virtio-blk: suspended: device reset, bus mastering off",
            "pci: suspended: ",
            "[cm] every power component quiesced; suspending for",
            to,
        ]);
        if ram {
            steps.push(woke_by[k]);
        }
        steps.extend([
            "[power] resumed at tick",
            "[cm] resumed",
            "pci: resumed: ",
            "virtio-blk: ready:",
            "virtio-blk: resumed: device initialized again",
            "virtio-net: resumed: device initialized again, every buffer free",
        ]);
        // The first suspend may come before DHCP has answered (the
        // server then goes on asking after the resume); by the second
        // there is a lease, renewed at the resume.
        if k == 0 {
            steps.push("net: resumed");
        } else {
            steps.extend(["net: resumed: renewing the lease on 10.0.3.30", "net: lease renewed: 10.0.3.30 for "]);
        }
    }
    steps.extend([
        "[pass] suspend: suspend 1: suspended for up to 200 ticks and resumed",
        "[pass] suspend: suspend 1: the disk reads after the resume: every word right",
        "[pass] suspend: suspend 1: the ticks run again: a 10-tick sleep took",
        "[pass] suspend: suspend 2: suspended for up to",
        "[pass] suspend: suspend 2: the disk reads after the resume: every word right",
        "[pass] suspend: suspend 2: the ticks run again: a 10-tick sleep took",
        "[cm] client asked to shut down (pass)",
    ]);
    check_log("suspend", &out, &steps)?;
    if !out.contains("net: leased 10.0.3.30/") {
        return Err("suspend: the network server got no DHCP lease".into());
    }
    if ram && out.contains("S3 failed") {
        return Err("suspend: the machine did not suspend to RAM".into());
    }
    let m = marks.lock().unwrap();
    if m.len() != 4 {
        return Err(format!("suspend: saw {} suspend and resume lines, not 4", m.len()));
    }
    for (k, pair) in m.chunks(2).enumerate() {
        let took = pair[1].1 - pair[0].1;
        println!("suspend {}: {:.2} s on the host's clock", k + 1, took.as_secs_f64());
        // The alarm's 2 s (at least); under S3 the second ends when the
        // key is pressed, long before its minute.
        if took < Duration::from_millis(1500) && !(ram && k == 1) {
            return Err(format!("suspend {}: over after {took:?}, not 2 s", k + 1));
        }
        if ram && k == 1 && took > Duration::from_secs(40) {
            return Err(format!("suspend 2: over after {took:?}: the key press did not wake it"));
        }
    }
    if ram {
        match woken.lock().unwrap().take() {
            Some(Ok(asleep)) => println!("suspend 2: QEMU said the machine was asleep after {:.2} s; a key woke it", asleep.as_secs_f64()),
            Some(Err(e)) => return Err(format!("suspend 2: {e}")),
            None => return Err("suspend 2: no key was pressed".into()),
        }
    }
    println!("suspend test passed");
    Ok(())
}

/// Waits (up to 30 s) for QEMU to report the machine suspended, then
/// presses and releases a key on its PS/2 keyboard, which wakes it.
/// Returns how long the wait was.
fn press_key_when_asleep() -> Result<Duration, String> {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    let start = Instant::now();
    loop {
        let asleep = (|| -> Result<bool, String> {
            let s = TcpStream::connect(("127.0.0.1", QMP_PORT)).map_err(|e| format!("QMP: {e}"))?;
            s.set_read_timeout(Some(scaled(Duration::from_secs(20)))).map_err(|e| e.to_string())?;
            let mut w = s.try_clone().map_err(|e| e.to_string())?;
            let mut r = BufReader::new(s);
            let mut line = String::new();
            for c in ["{\"execute\":\"qmp_capabilities\"}", "{\"execute\":\"query-status\"}"] {
                w.write_all(c.as_bytes()).and_then(|()| w.write_all(b"\n")).map_err(|e| format!("QMP: {e}"))?;
                loop {
                    line.clear();
                    if r.read_line(&mut line).map_err(|e| format!("QMP: {e}"))? == 0 {
                        return Err("QMP: the monitor hung up".into());
                    }
                    if line.contains("\"return\"") || line.contains("\"error\"") {
                        break;
                    }
                }
            }
            Ok(line.contains("\"suspended\""))
        })()?;
        if asleep {
            break;
        }
        if start.elapsed() > scaled(Duration::from_secs(30)) {
            return Err("QEMU never said the machine was suspended".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let asleep = start.elapsed();
    let key = |down: bool| {
        format!(
            "{{\"execute\":\"input-send-event\",\"arguments\":{{\"events\":[{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"spc\"}}}}}}]}}}}"
        )
    };
    qmp(&[key(true), key(false)])?;
    Ok(asleep)
}

/// Boots `boot/audio.manifest`: Linux's ES1370 driver in the Linux Driver
/// Environment on QEMU's ENSONIQ AudioPCI, which records what it plays to
/// a WAV file, and the mixer between it and two clients. The first plays
/// a sound, then a long one, over which the second plays one of its own;
/// the second has the mixer killed and plays another, then the driver
/// killed and plays a last one. Every sample of the recording must be
/// what the clients played, mixed.
fn audio_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "audio")?;
    let wav = img.audio.clone().ok_or("the audio image has no recording")?;
    println!("== audio test on {}", img.path.display());
    let _ = std::fs::remove_file(&wav);
    let out = run_to_exit(&img, Duration::from_secs(180))?;
    let log = [
        "Linux's es1370 driver runs the sound card",
        "mixer: ready: up to 4 streams mixed at 22050 Hz",
        "[pass] audio: the mixer plays at 22050 Hz",
        "audio: a1: 6615 frames played",
        "[pass] audio: stream A: a1 played to the end",
        "[pass] audio: a2 playing",
        "audio: b2: 11025 frames played",
        "audio: a2: 44100 frames played",
        "[pass] audio: b2 played over a2, and both done",
        "audio: killing the mixer",
        "[cm] fault injection: killing mixer",
        "mixer: ready: up to 4 streams",
        "[pass] audio: both streams set up again after the mixer's restart",
        "audio: b3: 6615 frames played",
        "[pass] audio: b3 played after the mixer's restart",
        "audio: killing the sound driver",
        "[cm] fault injection: killing lde-es1370",
        "Linux's es1370 driver runs the sound card",
        "mixer: the sound driver restarted; ring lent again",
        "audio: b4: 6615 frames played",
        "[pass] audio: b4 played after the sound driver's restart",
        "audio: done (0 failed)",
        "[cm] second asked to shut down (pass)",
    ];
    check_log("audio test", &out, &log)?;
    for line in [
        "[pass] audio: stream A set up again after the mixer's restart",
        "[pass] audio: stream A: a2 played to the end, in pieces of a ring",
    ] {
        if !out.contains(line) {
            return Err(format!("audio test: missing {line:?}"));
        }
    }
    let bytes = std::fs::read(&wav).map_err(|e| format!("audio test: reading {}: {e}", wav.display()))?;
    let found = check_recording(&bytes).map_err(|e| format!("audio test: the recording: {e}"))?;
    println!("== {found}");
    println!("== audio test passed ({})", arch.name());
    Ok(())
}

/// Boots `boot/display.manifest`: Linux's bochs driver in the Linux
/// Driver Environment on QEMU's bochs-display. When the client says a
/// picture is on the screen, QEMU's monitor takes a screenshot, and every
/// pixel must be the picture's: the first after two flips (the second
/// framebuffer must hold the first picture and the patch), the second
/// after the driver was killed and restarted.
fn display_test(arch: Arch) -> Result<(), String> {
    let img = image_with(false, arch, "display")?;
    println!("== display test on {}", img.path.display());
    let shots: Arc<Mutex<Vec<Result<String, String>>>> = Arc::default();
    let markers = [
        "[pass] display: picture 1 on the screen",
        "[pass] display: picture 2 on the screen",
    ];
    let taken = shots.clone();
    let out = run_to_exit_watching(&img, Duration::from_secs(120), move |all| {
        let mut taken = taken.lock().unwrap();
        let k = taken.len();
        if k < markers.len() && all.contains(markers[k]) {
            let path = root().join("target").join(format!("display-{}-{}.ppm", arch.name(), k + 1));
            let _ = std::fs::remove_file(&path);
            taken.push(screendump(&path).and_then(|()| check_screenshot(&path, k)));
        }
    });
    let out = out?;
    let steps = [
        "lde bochs: 1234:1111 at 00:",
        "lde bochs: BAR 0 (16384 KiB) mapped whole, as one frame",
        "lde bochs: [drm] Found bochs VGA, ID 0xb0c",
        "lde bochs: [drm] Framebuffer size 16384 kB @ 0x",
        "lde bochs: [drm] Found EDID data blob.",
        "lde bochs: [drm] Initialized bochs-drm 1.0.0 20130925 for 00:",
        "modes from the display's EDID; 800x600 at",
        "lde bochs: Linux's bochs driver runs the display",
        "[pass] display: a surface of 469 pages for 800x600",
        "[pass] display: the display's EDID gives",
        "lde bochs: 800x600 at",
        "[pass] display: 469 surface pages lent; 800x600 shown, pitch 3200",
        "lde bochs: flip 1: framebuffer 1 shown, 800x600 at (0, 0) copied in",
        "lde bochs: flip 2: framebuffer 0 shown, 320x200 at (100, 150) copied in",
        "[pass] display: picture 1 on the screen: flipped to framebuffer 1 and back to 0",
        "[pass] display: a rectangle past the screen's edge is refused",
        "display: killing the driver",
        "[cm] fault injection: killing lde-bochs",
        "lde bochs: [drm] Found EDID data blob.",
        "[pass] display: 469 surface pages lent; 800x600 shown, pitch 3200",
        "[pass] display: picture 2 on the screen after the driver's restart (flip 1)",
        "display: done (0 failed)",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("display test", &out, &steps)?;
    let shots = shots.lock().unwrap();
    if shots.len() != markers.len() {
        return Err(format!("display test: {} screenshots taken, want {}", shots.len(), markers.len()));
    }
    for s in shots.iter() {
        println!("== {}", s.clone()?);
    }
    println!("== display test passed ({})", arch.name());
    Ok(())
}


/// Types `word` and a space, again and again, on the USB keyboard `kbd0`
/// through QEMU's monitor, until `stop`. Returns the words typed.
fn type_words(
    word: &str,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> u64 {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::sync::atomic::Ordering;
    let mut stream = None;
    while stream.is_none() && !stop.load(Ordering::Relaxed) {
        stream = TcpStream::connect(("127.0.0.1", QMP_PORT)).ok();
        if stream.is_none() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let Some(mut s) = stream else { return 0 };
    // Answers are read (and dropped) on their own thread, so QEMU never
    // blocks on a full socket.
    if let Ok(r) = s.try_clone() {
        std::thread::spawn(move || for _ in BufReader::new(r).lines().map_while(Result::ok) {});
    }
    let _ = s.write_all(b"{\"execute\":\"qmp_capabilities\"}\n");
    // Give the guest time to boot and find the keyboard.
    std::thread::sleep(Duration::from_secs(2));
    let mut typed = 0;
    let keys: Vec<String> = word
        .chars()
        .map(|c| c.to_string())
        .chain(["spc".to_string()])
        .collect();
    while !stop.load(Ordering::Relaxed) {
        for key in &keys {
            for down in [true, false] {
                let cmd = format!(
                    "{{\"execute\":\"input-send-event\",\"arguments\":{{\"events\":[{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"{key}\"}}}}}}]}}}}\n"
                );
                if s.write_all(cmd.as_bytes()).is_err() {
                    return typed;
                }
                std::thread::sleep(Duration::from_millis(KEY_GAP_MS));
            }
        }
        typed += 1;
    }
    typed
}

/// Plugs a virtio entropy card into root port `hp0` through QEMU's
/// monitor, takes it out, and plugs another in, some seconds apart.
fn plug_cards(stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::sync::atomic::Ordering;
    let mut stream = None;
    while stream.is_none() && !stop.load(Ordering::Relaxed) {
        stream = TcpStream::connect(("127.0.0.1", QMP_PORT)).ok();
        if stream.is_none() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let Some(mut s) = stream else { return };
    if let Ok(r) = s.try_clone() {
        std::thread::spawn(move || for _ in BufReader::new(r).lines().map_while(Result::ok) {});
    }
    let _ = s.write_all(b"{\"execute\":\"qmp_capabilities\"}\n");
    let add = |id: &str| {
        format!(
            "{{\"execute\":\"device_add\",\"arguments\":{{\"driver\":\"virtio-rng-pci\",\"bus\":\"hp0\",\"id\":\"{id}\",\"disable-legacy\":\"on\"}}}}\n"
        )
    };
    let del = "{\"execute\":\"device_del\",\"arguments\":{\"id\":\"hot0\"}}\n".to_string();
    // The guest has booted by the first; each later step leaves it time
    // to act on the one before.
    for (wait, command) in [(5, add("hot0")), (8, del), (8, add("hot1"))] {
        for _ in 0..wait * 10 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if s.write_all(command.as_bytes()).is_err() {
            return;
        }
    }
}

/// Boots `boot/hotplug.manifest` with an empty root port and plugs a
/// card in, takes it out and plugs another in while the machine runs.
fn hotplug_test(arch: Arch) -> Result<(), String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let img = image_with(false, arch, "hotplug")?;
    println!("== hot-plug test on {}", img.path.display());
    let stop = Arc::new(AtomicBool::new(false));
    let plugger = {
        let stop = stop.clone();
        std::thread::spawn(move || plug_cards(stop))
    };
    let out = run_to_exit(&img, Duration::from_secs(120));
    stop.store(true, Ordering::Relaxed);
    let _ = plugger.join();
    let out = out?;
    let steps = [
        "pci: 1 hot-plug slots, looked at every 200 ms",
        "pci: 01:00.0 1af4:1044",
        "a card was plugged in (bus 01); windows: memory 0x",
        "[pass] hotplug: a card plugged in while running (01:00.0) opens with an IOMMU domain of its own, and its registers answer",
        "pci: 01:00.0 1af4:1044 removed; what its driver held is revoked",
        "its card is let go (bus 01)",
        "[pass] hotplug: taken out: the page of its registers and its domain are revoked, and there is no card to open",
        "pci: 01:00.0 1af4:1044",
        "a card was plugged in (bus 01); windows: memory 0x",
        "[pass] hotplug: a card plugged in again (01:00.0) opens and answers like the first",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("hot-plug test", &out, &steps)?;
    println!("== hot-plug test passed ({})", arch.name());
    Ok(())
}

/// Milliseconds between key events: more than the keyboard's polling
/// interval, so its 16-event queue never overflows.
const KEY_GAP_MS: u64 = 12;

/// Boots `boot/keyboard.manifest` with a USB keyboard on QEMU's xHCI
/// controller, types "superior " on it over and over through QMP, and
/// checks that whole words came through while the injector killed the
/// xHCI and HID drivers, and that no key that was not typed arrived.
fn keyboard_test(arch: Arch) -> Result<(), String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let img = image_with(false, arch, "keyboard")?;
    println!("== keyboard test on {}", img.path.display());
    let stop = Arc::new(AtomicBool::new(false));
    let typist = {
        let stop = stop.clone();
        std::thread::spawn(move || type_words("superior", stop))
    };
    let out = run_to_exit(&img, Duration::from_secs(150));
    stop.store(true, Ordering::Relaxed);
    let typed = typist.join().unwrap_or(0);
    let out = out?;
    let steps = [
        "xhci: ready:",
        "device 0627:0001 class 000000",
        "hid: ready: a boot keyboard on device 0",
        "[pass] keyboard: subscribed to the keyboard",
        "[cm] fault injection: killing",
        "keyboard: the first whole word came through",
        "words typed on the USB keyboard came through whole, no key that was not typed",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("keyboard test", &out, &steps)?;
    let kills = |what: &str| {
        out.matches(&format!("[cm] fault injection: killing {what}\n"))
            .count()
            + out
                .matches(&format!("[cm] fault injection: killing {what}\r\n"))
                .count()
    };
    let (xhci, hid) = (kills("xhci"), kills("hid"));
    // Kills land while words are coming through.
    let between = |a: &str, b: &str| match (out.find(a), out.find(b)) {
        (Some(i), Some(j)) if i < j => out[i..j].matches("[cm] fault injection: killing").count(),
        _ => 0,
    };
    let during = between("the first whole word came through", "words typed on the USB keyboard");
    if xhci < 10 || hid < 10 || during < 20 {
        return Err(format!(
            "keyboard test: the xHCI driver was killed {xhci} times and the HID driver {hid}, {during} while words came through; want 10, 10 and 20"
        ));
    }
    println!("== the xHCI driver was killed {xhci} times and the HID driver {hid}; the host typed {typed} words");
    println!("== keyboard test passed ({})", arch.name());
    Ok(())
}

/// Boots `boot/memory.manifest` and checks the Memory Server: quotas
/// enforced, heaps paged in on first touch, frames granted and freed, and
/// a component that overran its quota restarted with every page back.
fn memory_test(img: &Image) -> Result<(), String> {
    println!("== Memory Server test on {}", img.path.display());
    let out = run_to_exit(img, Duration::from_secs(60))?;
    let steps = [
        "[cm] manifest: 5 components",
        "spare RAM in",
        "mem: pool of",
        "room for 130",
        "hog: touching 12 heap pages with a quota of 8",
        "mem: client 2: heap page refused (8 pages is its quota)",
        "[cm] hog is out of memory: heap page at",
        "[cm] hog faulted: page fault",
        "[cm] hog: 8 pages back to the Memory Server",
        "[cm] restarting hog (one-for-one)",
        "[pass] hog: restarted (instance 2) holding 0 pages: all came back",
        "[pass] hog: 8 heap pages again, every one zeroed though reused",
        "hog: done (0 failed)",
        "[pass] memory: quota 40 pages, 0 in use",
        "[pass] memory: 32 heap pages appeared on first touch, each zeroed",
        "[pass] memory: and kept what was written",
        "[pass] memory: 32 pages charged to it; the pool has 32 fewer",
        "[pass] memory: 8 frames granted, filling the quota",
        "[pass] memory: one more is refused: the quota is spent",
        "[pass] memory: a granted frame arrives zeroed; freed, its capability is gone",
        "[pass] memory: 39 pages in use after freeing one",
        "[pass] memory: so another frame is granted",
        "[pass] memory: a component may not release another's pages",
        "[cm] started clone (a clone of client, sharing 32 heap pages)",
        "[pass] memory: cloned into clone, still 40 pages charged to it",
        "[pass] memory: its write to shared page 0 is its own, at no extra charge",
        "[pass] clone: 32 heap pages charged to it, quota 40",
        "[pass] clone: every page reads as the client wrote it before the clone",
        "[pass] clone: its write to page 1 stays its own, at no extra charge",
        "clone: done (0 failed)",
        "[cm] clone exited",
        "[pass] memory: the clone exited and the pool is back to",
        "[pass] memory: the clone's write to page 1 never reached the client",
        "[pass] big: the pool holds",
        "[pass] big: 4096 heap pages (16 MiB) appeared on first touch, each zeroed",
        "[pass] big: and kept what was written",
        "[pass] big: 4096 pages charged to it; the pool has 4096 fewer",
        "[pass] memory: the big client paged in 4096 heap pages, all from spare RAM",
        "[cm] client asked to shut down (pass)",
    ];
    if let Err(step) = find_in_order(&out, &steps) {
        return Err(format!("Memory Server test: missing (in order) {step:?}"));
    }
    for bad in ["[fail]", "could not", "panic"] {
        if out.contains(bad) {
            return Err(format!("Memory Server test: log contains {bad:?}"));
        }
    }
    println!("== Memory Server test passed ({})", img.arch.name());
    Ok(())
}

/// Boots `boot/reboot.manifest`: the Memory Server is killed (the manager
/// asks for a fast reboot), then the manager crashes (the kernel reboots
/// unasked); each time every component is rebuilt and the state store
/// keeps what the client wrote.
fn reboot_test(img: &Image) -> Result<(), String> {
    println!("== fast reboot test on {}", img.path.display());
    let out = run_to_exit(img, Duration::from_secs(60))?;
    let steps = [
        "[cm] manifest: 2 components",
        "[pass] reboot: boot 0: 4 heap pages from the Memory Server, zeroed",
        "reboot: state written; killing the Memory Server",
        "[cm] fault injection: killing memserver",
        "[cm] the Memory Server failed; fast reboot",
        "[reboot] the Component Manager asked for a restart: fast reboot 1",
        "[reboot] Component Manager started again",
        "[cm] started again after fast reboot 1; state store kept",
        "[pass] reboot: boot 1: 4 heap pages from the Memory Server, zeroed",
        "[pass] reboot: after the Memory Server failed, the state store kept what was written",
        "reboot: crashing the Component Manager",
        "[cm] fault injection: the Component Manager crashes",
        "[fault] the Component Manager: PageFault",
        "[reboot] the Component Manager failed: fast reboot 2",
        "[reboot] Component Manager started again",
        "[cm] started again after fast reboot 2; state store kept",
        "[pass] reboot: boot 2: 4 heap pages from the Memory Server, zeroed",
        "[pass] reboot: after the Component Manager failed, the state store kept it too",
        "[cm] client asked to shut down (pass)",
    ];
    check_log("fast reboot test", &out, &steps)?;
    println!("== fast reboot test passed ({})", img.arch.name());
    Ok(())
}

/// Stretches a QEMU time limit by `SUPERIOR_TIMEOUT_SCALE` (a number, 1 when
/// unset), for slow hosts where emulation cannot finish inside the limits.
fn scaled(limit: Duration) -> Duration {
    match env::var("SUPERIOR_TIMEOUT_SCALE").ok().and_then(|s| s.parse::<f64>().ok()) {
        Some(k) if k.is_finite() && k > 0.0 => limit.mul_f64(k),
        _ => limit,
    }
}

/// Boots `img` with no input until QEMU exits, echoing its output, and
/// returns the output if it exited with the pass code.
fn run_to_exit(img: &Image, limit: Duration) -> Result<String, String> {
    run_to_exit_watching(img, limit, |_| {})
}

/// As [`run_to_exit`], calling `watch` with all the output so far each
/// time more arrives (the guest waits meanwhile only if its output pipe
/// fills).
fn run_to_exit_watching(
    img: &Image,
    limit: Duration,
    watch: impl FnMut(&str) + Send + 'static,
) -> Result<String, String> {
    let (code, out) = run_capture(img, limit, watch)?;
    // AArch64 edk2 says this when the host has no TRNG to offer: the
    // firmware's notice, which the suites' "could not" check is not about.
    let out = out.replace("ArmTrngLib could not be correctly initialized.", "");
    match code {
        Some(QEMU_PASS) => Ok(out),
        code => Err(format!(
            "QEMU did not exit with the pass code (exit {code:?})"
        )),
    }
}

/// Runs `img` until QEMU exits or `limit` passes (then kills it): QEMU's
/// exit code (`None` if killed) and all the output.
fn run_capture(
    img: &Image,
    limit: Duration,
    mut watch: impl FnMut(&str) + Send + 'static,
) -> Result<(Option<i32>, String), String> {
    let mut child = qemu_command(img)
        .args(["-display", "none"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu(img.arch).display()))?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut all = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = std::io::stdout().write_all(&buf[..n]);
            let _ = std::io::stdout().flush();
            all.extend_from_slice(&buf[..n]);
            watch(&String::from_utf8_lossy(&all));
        }
        all
    });
    let deadline = Instant::now() + scaled(limit);
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();
    println!();
    Ok((status.and_then(|s| s.code()), out))
}

/// Boots the normal image and drives the shell over the serial port as a
/// person would: wait for the prompt, type a command, check the answer.
/// The shell's own `shutdown` command must then end QEMU with the pass
/// code.
/// The shell session's script: (typed text, text the answer must contain).
const SHELL_SCRIPT: &[(&str, &str)] = &[
    ("help", "shutdown        power off"),
    ("echo hello from user space", "\nhello from user space"),
    ("about", "its own serial driver"),
    ("sleep 20", "slept 20 ticks"),
    ("ipc 20000", "20000 round trips to another thread"),
    ("frobnicate", "unknown command: frobnicate"),
    // A typo fixed with backspace: the shell runs "echo fixed".
    ("echp\x7fo fixed", "\nfixed"),
];

fn shell_session(img: &Image) -> Result<(), String> {
    println!("== shell session on {}", img.path.display());
    drive_shell(img, &[], SHELL_SCRIPT)?;
    println!(
        "== shell session passed ({}{})",
        img.arch.name(),
        if img.sel4 { ", on seL4" } else { "" }
    );
    Ok(())
}

/// AArch64 booted by UEFI firmware (QEMU's edk2) from a GPT disk: the
/// firmware starts the loader on the EFI system partition, which places
/// the kernel, hands it a device tree of its own (the RAM the firmware's
/// memory map leaves free, and where the firmware's description is) and
/// leaves boot services. Twice: with the firmware's device tree
/// (`acpi=off`), then with its ACPI tables alone. Each time the shell
/// session, which must show all of that, then the driver framework test
/// (the SMMU, the ITS and PCI as the kernel finds them after the firmware).
fn uefi_test_aarch64() -> Result<(), String> {
    for acpi in [false, true] {
        let how = if acpi { "ACPI" } else { "device tree" };
        let mut img = uefi_image(Arch::Aarch64, "shell")?;
        img.acpi = acpi;
        img.xhci = true;
        println!("== UEFI shell session ({how}) on {}", img.path.display());
        let out = drive_shell(&img, &[], SHELL_SCRIPT)?;
        // The firmware's boot manager starts the disk. What the firmware
        // says before that is its own: the log is held to the usual words
        // from the loader on.
        if !out.contains("BdsDxe: starting Boot0001 \"UEFI QEMU NVMe Ctrl superior-boot") {
            return Err(format!("UEFI test (aarch64, {how}): the firmware's boot manager did not start the disk"));
        }
        let banner = "Superior UEFI loader (AArch64)";
        let out = out.find(banner).map_or("", |at| &out[at..]);
        let usb = no_dbc("the PL011");
        let described: &[&str] = if acpi {
            &[
                "; ACPI tables, RSDP at ",
                "loader: leaving boot services; the kernel's RAM is what the final memory map leaves free",
                "Superior microkernel",
                "[ok] MMU on; exception vectors installed",
                "[ok] ACPI (RSDP at ",
                "2 CPUs (MADT), PSCI by hvc (FADT)",
                "[ok] machine (ACPI): GICv3 at 0x8000000, redistributors at 0x80a0000, ITS at 0x8080000; timer interrupt 27; PL011 at 0x9000000, interrupt 33; PCI: ECAM at 0x3f000000, memory at 0x10000000 (256 MiB), I/O ports at 0x3eff0000",
                "[ok] machine (ACPI): no SMMU",
                "[ok] PCI interrupt pins through the GIC, as _PRT says: 128 pins on 4 lines, at interrupts 35, 36, 37, 38 (level, active high)",
                &usb,
                "[ok] 2 CPUs online",
                "superior> ",
            ]
        } else {
            &[
                "; device tree (",
                "loader: leaving boot services; the kernel's RAM is what the final memory map leaves free",
                "Superior microkernel",
                "[ok] MMU on; exception vectors installed",
                "[ok] machine (device tree): GICv3 at 0x8000000, redistributors at 0x80a0000, ITS at 0x8080000; timer interrupt 27; PL011 at 0x9000000, interrupt 33; PCI: ECAM at 0x3f000000, memory at 0x10000000 (256 MiB), I/O ports at 0x3eff0000",
                &usb,
                "[ok] 2 CPUs online",
                "superior> ",
            ]
        };
        let mut steps = vec![banner, "loader: kernel at 0x40200000 to "];
        steps.extend_from_slice(described);
        check_log(&format!("UEFI test (aarch64, {how})"), out, &steps)?;
        if !acpi && out.contains("[ok] ACPI") {
            return Err("UEFI test (aarch64, device tree): the kernel read ACPI tables".into());
        }
        println!("== UEFI shell session passed (aarch64, {how})");
        let mut img = uefi_image(Arch::Aarch64, "drivers")?;
        img.acpi = acpi;
        let out = drivers_test_log(&img)?;
        if acpi {
            // A Linux driver on a legacy interrupt pin, routed by _PRT.
            let mut img = uefi_image(Arch::Aarch64, "lde")?;
            img.acpi = true;
            println!("== Linux Driver Environment test (ACPI) on {}", img.path.display());
            net_test_on(img, "lde")?;
        }
        if acpi && !out.contains("[ok] machine (ACPI): SMMUv3 at 0x9050000, event interrupt 106") {
            return Err("UEFI test (aarch64, ACPI): the SMMU was not found from the IORT".into());
        }
    }
    println!("== UEFI test passed (aarch64)");
    Ok(())
}

/// x86-64 booted by UEFI firmware (QEMU's OVMF) from a GPT disk with no
/// BIOS boot code: the shell session, which must show the firmware's boot
/// manager starting the disk and the bootloader's UEFI stage, on four CPUs
/// whose APIC IDs have a gap (found from ACPI's MADT), then the driver
/// framework test on q35 (PCI Express, the VT-d IOMMU from ACPI's DMAR
/// table, MSI).
/// AArch64 with EL2 (QEMU's `virtualization=on`), where firmware and PSCI
/// start the CPUs: each steps down to EL1 itself, and PSCI is called by
/// `smc`, as the device tree or ACPI's FADT then says. From QEMU's
/// `-kernel` the shell session and the driver framework test (the SMMU
/// and the ITS); from UEFI firmware at EL2 the shell session, with its
/// device tree and with its ACPI tables.
fn el2_test() -> Result<(), String> {
    let entered = "[ok] entered at EL2: set EL1 up, with nothing trapped, and stepped down to it";
    let mut img = image(false, Arch::Aarch64)?;
    img.el2 = true;
    println!("== shell session at EL2 on {}", img.path.display());
    let out = drive_shell(&img, &[], SHELL_SCRIPT)?;
    check_log(
        "EL2 test (-kernel)",
        &out,
        &["Superior microkernel", entered, "[ok] MMU on; exception vectors installed", "[ok] 2 CPUs online", "superior> "],
    )?;
    let mut img = image_with(false, Arch::Aarch64, "drivers")?;
    img.el2 = true;
    let out = drivers_test_log(&img)?;
    if !out.contains(entered) {
        return Err("EL2 test: the driver test's kernel did not step down from EL2".into());
    }
    for acpi in [false, true] {
        let how = if acpi { "ACPI" } else { "device tree" };
        let mut img = uefi_image(Arch::Aarch64, "shell")?;
        img.acpi = acpi;
        img.el2 = true;
        println!("== UEFI shell session at EL2 ({how}) on {}", img.path.display());
        let out = drive_shell(&img, &[], SHELL_SCRIPT)?;
        let banner = "Superior UEFI loader (AArch64)";
        let out = out.find(banner).map_or("", |at| &out[at..]);
        let mut steps = vec![
            banner,
            "loader: the firmware runs at EL2; the kernel steps down to EL1 itself",
            "loader: kernel at 0x40200000 to ",
            "loader: leaving boot services",
            "Superior microkernel",
            entered,
        ];
        if acpi {
            steps.push(", PSCI by smc (FADT)");
        }
        steps.extend(["[ok] 2 CPUs online", "superior> "]);
        check_log(&format!("EL2 test (UEFI, {how})"), out, &steps)?;
        println!("== UEFI shell session at EL2 passed ({how})");
    }
    println!("== EL2 test passed (aarch64)");
    Ok(())
}

/// AArch64 with QEMU `virt`'s `highmem=on`, which puts PCI's ECAM at
/// 0x40_1000_0000 rather than below 4 GiB: the kernel must take it from the
/// firmware, map it and hand it to the bus server there. The driver
/// framework test, from QEMU's device tree (`-kernel`) and from ACPI's MCFG
/// (UEFI); in both the rest of the machine is where it always is.
fn layout_test() -> Result<(), String> {
    for acpi in [false, true] {
        let how = if acpi { "ACPI" } else { "device tree" };
        let mut img = if acpi { uefi_image(Arch::Aarch64, "drivers")? } else { image_with(false, Arch::Aarch64, "drivers")? };
        img.acpi = acpi;
        img.highmem = true;
        println!("== driver test with ECAM moved ({how})");
        let out = drivers_test_log(&img)?;
        let want = format!("[ok] machine ({how}): GICv3 at 0x8000000, redistributors at 0x80a0000, ITS at 0x8080000; timer interrupt 27; PL011 at 0x9000000, interrupt 33; PCI: ECAM at 0x4010000000, memory at 0x10000000 (256 MiB), I/O ports at 0x3eff0000");
        if !out.contains(&want) {
            return Err(format!("layout test ({how}): the kernel did not report the machine as {want:?}"));
        }
    }
    println!("== layout test passed (aarch64)");
    Ok(())
}

fn uefi_test(arch: Arch) -> Result<(), String> {
    if arch == Arch::Aarch64 {
        return uefi_test_aarch64();
    }
    let mut img = uefi_image(Arch::X86_64, "shell")?;
    // Four CPUs of six possible, over two sockets of three cores: APIC IDs
    // 0, 1, 2 and 4, with a gap at 3 as on real machines. The kernel must
    // start the four ACPI's MADT lists enabled, not stop at the gap.
    img.smp = Some("4,sockets=2,cores=3,threads=1,maxcpus=6");
    // An xHCI controller the firmware sets up: the kernel finds it and
    // looks for a Debug Capability.
    img.xhci = true;
    println!("== UEFI shell session on {}", img.path.display());
    let out = drive_shell(&img, &[], SHELL_SCRIPT)?;
    check_log(
        "UEFI test",
        &out,
        &[
            "BdsDxe: starting Boot0001 \"UEFI QEMU HARDDISK",
            "UEFI bootloader started",
            "Superior microkernel",
            "[ok] ACPI: 4 of 6 CPUs listed taken, APIC IDs [0, 1, 2, 4]",
            "[ok] ACPI: no DMAR (no VT-d)",
            &no_dbc("COM1"),
            "[ok] 4 CPUs online",
            "superior> ",
        ],
    )?;
    println!("== UEFI shell session passed");
    drivers_test(&uefi_image(Arch::X86_64, "drivers")?)?;
    println!("== UEFI test passed (x86_64)");
    Ok(())
}

/// The kernel's log on the boot framebuffer (kernel/src/arch/x86_64/
/// fbcon.rs): its scale, margin, character cell and colour.
const CON_SCALE: usize = 2;
const CON_MARGIN: usize = 8;
const CON_CELL: (usize, usize) = (6 * CON_SCALE, 9 * CON_SCALE);
const CON_INK: [u8; 3] = [0xc8, 0xcc, 0xd0];

/// Reads a binary PPM of any size: its width, height and RGB bytes.
fn read_ppm(path: &Path) -> Result<(usize, usize, Vec<u8>), String> {
    let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let (mut fields, mut at) = (Vec::new(), 0);
    while fields.len() < 4 && at < data.len() {
        while at < data.len() && data[at].is_ascii_whitespace() {
            at += 1;
        }
        let start = at;
        while at < data.len() && !data[at].is_ascii_whitespace() {
            at += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..at]).into_owned());
    }
    let num = |i: usize| fields.get(i).and_then(|f| f.parse::<usize>().ok());
    match (fields.first().map(String::as_str), num(1), num(2)) {
        (Some("P6"), Some(w), Some(h)) if data.len() >= at + 1 + w * h * 3 => Ok((w, h, data[at + 1..].to_vec())),
        _ => Err(format!("{}: not a binary PPM", path.display())),
    }
}

/// A picture in memory for `superior_console` to draw into, RGB.
struct Picture {
    w: usize,
    h: usize,
    px: Vec<[u8; 3]>,
}

impl superior_console::Canvas for Picture {
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, rgb: [u8; 3]) {
        for yy in y..(y + h).min(self.h) {
            for xx in x..(x + w).min(self.w) {
                self.px[yy * self.w + xx] = rgb;
            }
        }
    }
}

/// Checks a screenshot of the screen console after `echo Hi PS/2!` was
/// typed on the PS/2 keyboard: below the bar, every pixel must be as the
/// console draws the same session on the host, but for the cursor's cell
/// (it blinks).
fn check_screen_console(path: &Path) -> Result<String, String> {
    use superior_console::{BAR_H, HINT, Ink, OUTPUT_COL, PROMPT_COL, Term, WELCOME};
    let (w, h, px) = read_ppm(path)?;
    let mut p = Picture { w, h, px: vec![[0; 3]; w * h] };
    let mut t = Box::new(Term::new());
    t.init(&mut p, w, h);
    t.style(Ink::Text, PROMPT_COL);
    t.write(&mut p, WELCOME);
    t.ink(Ink::Muted);
    t.write(&mut p, HINT);
    t.style(Ink::Text, OUTPUT_COL);
    t.prompt(&mut p);
    t.edit(&mut p, b"echo Hi PS/2!", 13);
    t.submit(&mut p);
    t.write(&mut p, b"Hi PS/2!\n");
    t.prompt(&mut p);
    let (cx, cy, cw, ch) = t.cursor_cell().map(|(c, r)| t.cell_rect(c, r)).ok_or("no cursor")?;
    let mut wrong = 0;
    let mut first = None;
    let mut checked = 0;
    for y in BAR_H..h {
        for x in 0..w {
            if (cx..cx + cw).contains(&x) && (cy..cy + ch).contains(&y) {
                continue;
            }
            let i = y * w + x;
            let have = [px[i * 3], px[i * 3 + 1], px[i * 3 + 2]];
            checked += 1;
            if have != p.px[i] {
                wrong += 1;
                first.get_or_insert((x, y, have, p.px[i]));
            }
        }
    }
    match first {
        None => Ok(format!("{w}x{h}, all {checked} pixels below the bar right")),
        Some((x, y, have, want)) => Err(format!(
            "{}: {wrong} pixels wrong below the bar, the first at ({x}, {y}): {have:?}, not {want:?}",
            path.display()
        )),
    }
}

/// Checks the screenshot at `path`: the top of the screen must be the
/// kernel's first log lines (`lines`), laid out as the kernel does
/// (wrapped at the screen's width), every pixel light grey or black.
/// The screen's size, and how many pixels were checked.
fn check_console(path: &Path, lines: &dyn Fn(usize, usize) -> Vec<String>) -> Result<String, String> {
    use superior_toolkit::font;
    let (w, h, px) = read_ppm(path)?;
    let columns = (w - 2 * CON_MARGIN) / CON_CELL.0;
    // Where each character lands: (column, row).
    let mut cells = Vec::new();
    let mut row = 0;
    for line in lines(w, h) {
        for (i, c) in line.bytes().enumerate() {
            if i > 0 && i % columns == 0 {
                row += 1;
            }
            cells.push((i % columns, row, c));
        }
        row += 1;
    }
    let mut want = vec![[0u8; 3]; w * (CON_MARGIN + row * CON_CELL.1)];
    for &(col, row, c) in &cells {
        let (x0, y0) = (CON_MARGIN + col * CON_CELL.0, CON_MARGIN + row * CON_CELL.1);
        for dy in 0..7 * CON_SCALE {
            for dx in 0..CON_CELL.0 {
                if font::lit(c, (dx / CON_SCALE) as u32, (dy / CON_SCALE) as u32) {
                    want[(y0 + dy) * w + x0 + dx] = CON_INK;
                }
            }
        }
    }
    let mut wrong = 0;
    let mut first = None;
    for (i, want) in want.iter().enumerate() {
        let have = [px[i * 3], px[i * 3 + 1], px[i * 3 + 2]];
        if have != *want {
            wrong += 1;
            first.get_or_insert((i % w, i / w, have, *want));
        }
    }
    match first {
        None => Ok(format!("{w}x{h}, the first {row} lines' {} pixels right", want.len())),
        Some((x, y, have, want)) => Err(format!(
            "{}: {wrong} pixels wrong at the top, the first at ({x}, {y}): {have:?}, not {want:?}",
            path.display()
        )),
    }
}

/// The kernel's log on the boot framebuffer, from a BIOS (the
/// bootloader's VESA mode) and from UEFI firmware (its GOP): once the
/// shell's prompt shows, QEMU's monitor takes a screenshot whose top must
/// be the kernel's first lines, every pixel as the host draws them in the
/// same font.
fn console_test() -> Result<(), String> {
    let lines = |w: usize, h: usize| {
        vec![
            String::new(),
            format!("Superior microkernel {} (x86_64)", env!("CARGO_PKG_VERSION")),
            format!("[ok] this log on the boot framebuffer too, {w}x{h}, until user space starts"),
            "[ok] gdt + tss loaded".to_string(),
            "[ok] idt loaded".to_string(),
            "[ok] syscall/sysret enabled".to_string(),
        ]
    };
    let qmp = format!("tcp:127.0.0.1:{QMP_PORT},server=on,wait=off");
    for (img, firmware) in [(image(false, Arch::X86_64)?, "BIOS"), (uefi_image(Arch::X86_64, "shell")?, "UEFI")] {
        println!("== console test ({firmware}) on {}", img.path.display());
        let path = root().join("target").join(format!("console-{}.ppm", firmware.to_lowercase()));
        let checked = std::cell::RefCell::new(String::new());
        let out = drive_shell_at(&img, &["-qmp", &qmp], &SHELL_SCRIPT[..1], &|| {
            let _ = std::fs::remove_file(&path);
            screendump(&path)?;
            *checked.borrow_mut() = check_console(&path, &lines)?;
            Ok(())
        })?;
        check_log(
            "console test",
            &out,
            &["[ok] this log on the boot framebuffer too", "[ok] the screen is user space's from here"],
        )?;
        println!("== console test passed ({firmware}): {}", checked.borrow());
    }
    Ok(())
}

/// Types `text` on QEMU's keyboard through its monitor, one key press and
/// release at a time (Shift held for capitals and `!`), as a person
/// would. With no USB keyboard, QEMU's keyboard is the PS/2 one.
fn qmp_type(text: &str) -> Result<(), String> {
    let key = |qcode: &str, down: bool| {
        format!(
            "{{\"execute\":\"input-send-event\",\"arguments\":{{\"events\":[{{\"type\":\"key\",\"data\":{{\"down\":{down},\"key\":{{\"type\":\"qcode\",\"data\":\"{qcode}\"}}}}}}]}}}}"
        )
    };
    let mut commands = Vec::new();
    for c in text.chars() {
        let lower = c.to_ascii_lowercase().to_string();
        let (shift, qcode) = match c {
            'a'..='z' | '0'..='9' => (false, lower.as_str()),
            'A'..='Z' => (true, lower.as_str()),
            ' ' => (false, "spc"),
            '/' => (false, "slash"),
            '!' => (true, "1"),
            '\n' => (false, "ret"),
            other => return Err(format!("qmp_type: no key for {other:?}")),
        };
        if shift {
            commands.push(key("shift", true));
        }
        commands.push(key(qcode, true));
        commands.push(key(qcode, false));
        if shift {
            commands.push(key("shift", false));
        }
    }
    qmp(&commands)
}

/// The shell as a console on the screen and the PS/2 keyboard
/// (boot/console.manifest): a command typed on QEMU's PS/2 keyboard must
/// be answered, and the screen must show the session every pixel as
/// `superior_console` draws it on the host (the bar, whose clock moves,
/// and the blinking cursor's cell left out); the serial console must
/// still work beside it, its line editing and suggestions too.
fn console_shell_test() -> Result<(), String> {
    let img = image_with(false, Arch::X86_64, "console")?;
    println!("== screen console test on {}", img.path.display());
    let qmp_arg = format!("tcp:127.0.0.1:{QMP_PORT},server=on,wait=off");
    let path = root().join("target").join("console-shell.ppm");
    let checked = std::cell::RefCell::new(String::new());
    let script = [
        ("help", "reboot          restart the machine"),
        // A typo gets a suggestion; Tab completes a command.
        ("ech hi", "unknown command: ech (did you mean 'echo'?)"),
        ("ec\tthere", "\nthere"),
        // The arrows: Left twice, then a letter goes in the middle.
        ("echo ac\x1b[D\x1b[Db", "\nbac"),
        // Up recalls the last line.
        ("\x1b[A", "\nbac"),
    ];
    let out = drive_shell_at(&img, &["-qmp", &qmp_arg], &script, &|| {
        qmp_type("echo Hi PS/2!\n")?;
        // The shell reads the keyboard every tick: look until the screen
        // shows the answer.
        let deadline = Instant::now() + scaled(Duration::from_secs(30));
        loop {
            let _ = std::fs::remove_file(&path);
            screendump(&path)?;
            match check_screen_console(&path) {
                Ok(s) => {
                    *checked.borrow_mut() = s;
                    return Ok(());
                }
                Err(e) if Instant::now() > deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    })?;
    check_log(
        "screen console test",
        &out,
        &["Console on the screen", "the PS/2 keyboard", "echo Hi PS/2!", "\nHi PS/2!", "reboot"],
    )?;
    println!("== screen console test passed: {}", checked.borrow());
    Ok(())
}

/// Boots `img` with `extra` QEMU arguments and drives the shell over the
/// serial port as a person would: wait for the prompt, type a command,
/// check the answer, and finally `shutdown`, which must end QEMU with the
/// pass code. Returns everything the shell printed.
fn drive_shell(img: &Image, extra: &[&str], script: &[(&str, &str)]) -> Result<String, String> {
    drive_shell_at(img, extra, script, &|| Ok(()))
}

/// As [`drive_shell`], calling `at_prompt` once the first prompt shows.
fn drive_shell_at(
    img: &Image,
    extra: &[&str],
    script: &[(&str, &str)],
    at_prompt: &dyn Fn() -> Result<(), String>,
) -> Result<String, String> {
    let mut child = qemu_command(img)
        .args(["-display", "none"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu(img.arch).display()))?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = std::io::stdout().write_all(&buf[..n]);
            let _ = std::io::stdout().flush();
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });

    // Waits until `want` appears after byte `from` of the output; returns
    // the position just past it.
    let expect = |want: &str, from: usize| -> Result<usize, String> {
        let deadline = Instant::now() + scaled(Duration::from_secs(60));
        loop {
            {
                let out = seen.lock().unwrap();
                let text = String::from_utf8_lossy(&out[from.min(out.len())..]).into_owned();
                if let Some(i) = text.find(want) {
                    return Ok(from + text[..i].len() + want.len());
                }
            }
            if Instant::now() > deadline {
                return Err(format!("shell session: timed out waiting for {want:?}"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let prompt = "superior> ";
    let mut at = expect(prompt, 0)?;
    // Typing goes one byte at a time, as from a keyboard.
    let mut result = at_prompt();
    for (typed, want) in script {
        // Enter is sent as a line feed: QEMU on Windows drops a bare
        // carriage return read from a pipe. The shell accepts either.
        for b in typed.bytes().chain(*b"\n") {
            stdin.write_all(&[b]).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(5));
        }
        match expect(want, at).and_then(|p| expect(prompt, p)) {
            Ok(p) => at = p,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    if result.is_ok() {
        for b in b"shutdown\n" {
            stdin.write_all(&[*b]).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let deadline = Instant::now() + scaled(Duration::from_secs(30));
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if Instant::now() > deadline || result.is_err() {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    println!();
    result?;
    match status.and_then(|s| s.code()) {
        Some(QEMU_PASS) => Ok(String::from_utf8_lossy(&seen.lock().unwrap()).into_owned()),
        code => Err(format!(
            "shell did not power off cleanly (QEMU exit {code:?})"
        )),
    }
}

/// seL4's published one-way IPC costs on x86-64, in cycles: the MCS
/// configuration (Superior's kernel is MCS) on an i7-6700 (Skylake),
/// without Meltdown mitigation, from https://sel4.systems/performance.html
/// (sel4bench-manifest 818079b1, generated 2026-11-07).
const SEL4_CALL: u64 = 771;
const SEL4_REPLY: u64 = 667;
/// The Phase 0 exit gate: Tier 1 IPC within 1.5x of seL4, in tenths.
const GATE_TENTHS: u64 = 15;
const BENCH_RUNS: usize = 5;

/// Times IPC in the shell under hardware virtualization, where `rdtsc`
/// counts real cycles (under QEMU's emulator it counts emulated time and
/// means nothing). Each run does 100,000 round trips after a warm-up and
/// reports one-way call and reply costs measured as sel4bench does. The
/// gate is on the middle run's medians, since host interrupts stretch a
/// few rounds under a hypervisor; the means are reported too.
fn bench(img: &Image) -> Result<(), String> {
    let accel: &[&str] = if cfg!(windows) {
        // WHPX: the in-kernel irqchip and nested VT-x are not available
        // on every Hyper-V host.
        &["-accel", "whpx,kernel-irqchip=off", "-cpu", "host,-vmx"]
    } else {
        &["-accel", "kvm", "-cpu", "host"]
    };
    println!("== IPC benchmark on {} ({})", img.path.display(), accel[1]);
    let script = [("ipc 100000", "(median)"); BENCH_RUNS];
    let out = drive_shell(img, accel, &script)?;
    let number_after = |line: &str, key: &str| -> Option<u64> {
        let rest = &line[line.find(key)? + key.len()..];
        rest.trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    let (mut med, mut mean) = (Vec::new(), Vec::new());
    for line in out.lines().filter(|l| l.starts_with("one way:")) {
        let (Some(c), Some(r)) = (number_after(line, "call"), number_after(line, "reply")) else {
            continue;
        };
        if line.contains("(median)") {
            med.push((c, r));
        } else if line.contains("(mean)") {
            mean.push((c, r));
        }
    }
    if med.len() != BENCH_RUNS || mean.len() != BENCH_RUNS {
        return Err("bench: could not read the shell's timings".into());
    }
    let middle = |mut v: Vec<u64>| {
        v.sort();
        v[v.len() / 2]
    };
    let call = middle(med.iter().map(|m| m.0).collect());
    let reply = middle(med.iter().map(|m| m.1).collect());
    let call_mean = middle(mean.iter().map(|m| m.0).collect());
    let reply_mean = middle(mean.iter().map(|m| m.1).collect());
    let ratio = |ours: u64, theirs: u64| ours as f64 / theirs as f64;
    println!("== one-way IPC, cycles   Superior median (mean)   seL4 MCS Skylake   ratio");
    println!(
        "   call                 {call:>6} ({call_mean:>5})           {SEL4_CALL:>5}          {:.2}x",
        ratio(call, SEL4_CALL)
    );
    println!(
        "   reply                {reply:>6} ({reply_mean:>5})           {SEL4_REPLY:>5}          {:.2}x",
        ratio(reply, SEL4_REPLY)
    );
    let within = |ours: u64, theirs: u64| ours * 10 <= theirs * GATE_TENTHS;
    if within(call, SEL4_CALL) && within(reply, SEL4_REPLY) {
        println!("== IPC within 1.5x of seL4");
        Ok(())
    } else {
        Err("IPC is not within 1.5x of seL4's published figures".into())
    }
}
