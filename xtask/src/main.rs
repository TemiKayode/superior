//! Superior build driver. Each command takes an optional architecture,
//! `x86_64` (the default) or `aarch64`:
//!
//!   cargo xtask image [arch]       build the kernel and a bootable image
//!   cargo xtask run [arch]         boot it in QEMU, into the shell (serial on
//!                                  this terminal)
//!   cargo xtask test               host unit tests, the exhaustive model check
//!                                  and long simulation, then on each
//!                                  architecture the boot self-tests in QEMU and
//!                                  a scripted session with the shell
//!   cargo xtask boot-test [arch]   just the boot self-tests
//!   cargo xtask shell-test [arch]  just the shell session
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
    /// A USB keyboard on an xHCI controller, typed on through QEMU's
    /// monitor (the keyboard test).
    keyboard: bool,
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
        Some("image") => image(false, arch).map(|i| println!("image: {}", i.path.display())),
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
                        .and_then(|_| tcp_test(a))
                        .and_then(|_| keyboard_test(a))
                        .and_then(|_| image(false, a))
                        .and_then(|img| shell_session(&img))
                })
            })
            .and_then(|_| sel4_image())
            .and_then(|img| shell_session(&img)),
        Some("sel4-test") => sel4_image().and_then(|img| shell_session(&img)),
        Some("boot-test") => image(true, arch).and_then(|img| boot(&img, true)),
        Some("shell-test") => image(false, arch).and_then(|img| shell_session(&img)),
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
        Some("tcp-test") => tcp_test(arch),
        Some("keyboard-test") => keyboard_test(arch),
        Some("memory-test") => {
            image_with(false, arch, "memory").and_then(|img| memory_test(&img))
        }
        Some("reboot-test") => {
            image_with(false, arch, "reboot").and_then(|img| reboot_test(&img))
        }
        Some("bench") => image(false, Arch::X86_64).and_then(|img| bench(&img)),
        _ => Err(
            "usage: cargo xtask <image | run | test | boot-test | shell-test | cm-test | supervise-test | drivers-test | memory-test | reboot-test | fs-test | nvme-test | ahci-test | net-test | lde-test | lde-e100-test | tcp-test | keyboard-test | bench | sel4-test> [x86_64 | aarch64]"
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

fn host_tests() -> Result<(), String> {
    println!("== host unit tests");
    run(cargo().args(["test", "--quiet", "-p", "superior-objects", "-p", "superior-inet"]))?;
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
const LINUX_SOURCES: [(&str, &str, &str); 2] = [
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
];

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

/// Compiles Linux's `driver` and the environment's C half for `arch`, in
/// the build container (clang, with only the environment's headers), and
/// points the component's build script at the objects.
fn lde_objects(arch: Arch, driver: &str) -> Result<(), String> {
    let source = linux_source(driver)?;
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
    let built = [format!("{driver}.o"), "lde.o".into()]
        .iter()
        .map(|o| std::fs::metadata(out.join(o)).and_then(|m| m.modified()).ok())
        .min()
        .flatten();
    let sources = newest(root().join("crates/lde"))
        .max(std::fs::metadata(&source).and_then(|m| m.modified()).ok());
    if built.is_none() || built < sources {
        println!("== compiling Linux's {driver} and the Linux Driver Environment ({})", arch.name());
        let rel = |p: &Path| {
            format!(
                "/work/{}",
                p.strip_prefix(root()).unwrap().to_string_lossy().replace('\\', "/")
            )
        };
        docker(&[
            "sh",
            "/work/crates/lde/cc.sh",
            arch.name(),
            &rel(&source),
            driver,
            &rel(&out),
        ])?;
    }
    // SAFETY: xtask has one thread here.
    unsafe { env::set_var("SUPERIOR_LDE_OBJECTS", &out) };
    Ok(())
}

/// Builds a user program as a static position-independent executable; the
/// kernel loads it into its user window and relocates it. User programs
/// build in their own target directory, since on AArch64 they need flags
/// the kernel must not get.
fn user_program(package: &str, arch: Arch) -> Result<PathBuf, String> {
    println!("== building {package} ({})", arch.name());
    let mut build = cargo();
    // Loaders read only program headers: leave debug information out, so
    // the boot bundle stays small.
    build.env("CARGO_PROFILE_RELEASE_STRIP", "debuginfo");
    if arch == Arch::Aarch64 {
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
        // Need Linux's source and the build container: only where used.
        ("lde-8139cp", "superior-lde-8139cp"),
        ("lde-e100", "superior-lde-e100"),
    ] {
        if let Some(driver) = name.strip_prefix("lde-") {
            if linux_nic(manifest).map(|l| l.0) != Some(driver) {
                continue;
            }
            lde_objects(arch, driver)?;
        }
        let path = user_program(package, arch)?;
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        files.push((name.to_string(), bytes));
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"SUPBNDL1");
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let mut offset = 16 + 40 * files.len();
    for (name, data) in &files {
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        offset += data.len();
    }
    for (_, data) in &files {
        out.extend_from_slice(data);
    }
    let path = root()
        .join("target")
        .join(format!("bundle-{}-{manifest}.bin", arch.name()));
    std::fs::write(&path, out).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
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
    let user = user_program("superior-pingpong", arch)?;
    let shell = user_program("superior-shell", arch)?;
    let cm = user_program("superior-cm", arch)?;
    let bundle = bundle(arch, manifest, driver)?;
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
    let disk = if manifest == "drivers" {
        Some(test_disk()?)
    } else if fs {
        Some(fs_disk())
    } else {
        None
    };
    Ok(Image {
        path,
        arch,
        sel4: false,
        disk,
        writable: fs,
        driver,
        net: matches!(manifest, "net" | "tcp") || linux_nic(manifest).is_some(),
        linux_nic: linux_nic(manifest).map(|l| l.1),
        keyboard: manifest == "keyboard",
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
        keyboard: false,
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

fn qemu_command(img: &Image) -> Command {
    let mut q = Command::new(qemu(img.arch));
    match img.arch {
        Arch::X86_64 => {
            // Images with a disk are driver tests: they need an IOMMU,
            // which QEMU emulates (VT-d) only on its q35 machine, with
            // interrupt remapping.
            if img.disk.is_some() || img.net || img.keyboard {
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
            q.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
        }
        Arch::Aarch64 => {
            // highmem=off keeps PCI's ECAM window below 4 GiB, where the
            // kernel hands it to the PCI bus server.
            // Driver tests get an SMMUv3 in front of PCI.
            let machine = if img.sel4 {
                SEL4_MACHINE
            } else if img.disk.is_some() || img.net || img.keyboard {
                "virt,highmem=off,gic-version=3,iommu=smmuv3"
            } else {
                "virt,highmem=off,gic-version=3"
            };
            q.args(["-machine", machine, "-cpu", "cortex-a72", "-kernel"])
                .arg(&img.path);
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
        q.args(["-smp", &cpus().to_string()]);
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
                "pcie-root-port,id=rp0,chassis=1",
                "-device",
                "nvme,id=nvme0,serial=superior0,bus=rp0",
                "-device",
                "pci-bridge,id=br0,chassis_nr=2",
                "-device",
                "virtio-rng-pci,bus=br0,addr=1,disable-legacy=on",
                "-device",
                "nvme-ns,drive=nvm0,bus=nvme0,nsid=1",
                "-device",
                "nvme-ns,drive=nvm1,bus=nvme0,nsid=2",
            ]);
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
            .args([
                "-device",
                "virtio-blk-pci,drive=blk0,disable-legacy=on,iommu_platform=on",
            ]);
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
            // interrupt is a legacy line.
            img.linux_nic
                .unwrap_or("virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on"),
        ]);
    }
    if img.keyboard {
        // A USB keyboard on an xHCI controller (its DMA through the
        // IOMMU), and the monitor the test types through.
        q.args([
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-kbd,id=kbd0,bus=xhci.0",
            "-qmp",
        ])
        .arg(format!("tcp:127.0.0.1:{QMP_PORT},server=on,wait=off"));
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
        pick("bridges to bus 0a (to 0a), 1 functions behind it, memory window"),
        pick("pci: 0b:01.0 1af4:1044"),
        pick("bridges to bus 0b (to 0b), 1 functions behind it, memory window"),
        pick("a conventional bridge, so what is behind it shares its requester ID and gets no DMA"),
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
    for bad in ["[fail]", "could not", "panic"] {
        if out.contains(bad) {
            return Err(format!("driver framework test: log contains {bad:?}"));
        }
    }
    println!("== driver framework test passed ({}, {d})", img.arch.name());
    Ok(())
}

/// The filesystem tests' disk (4 MiB), shared by both boots.
fn fs_disk() -> PathBuf {
    root().join("target").join("fs-test-disk.img")
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
    // Generous: 600 files into one directory under fault injection take
    // AArch64 under emulated NVMe over two minutes.
    let out = run_to_exit(&first, Duration::from_secs(360))?;
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
                        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
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
        let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
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
fn net_test(arch: Arch, manifest: &str) -> Result<(), String> {
    use std::collections::HashMap;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    let lde = linux_nic(manifest).map(|l| l.0);
    let img = image_with(false, arch, manifest)?;
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
    println!("== network test passed ({})", arch.name());
    Ok(())
}

/// The port QEMU's monitor (QMP) listens on in the keyboard test.
const QMP_PORT: u16 = 47011;

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
        "[cm] manifest: 4 components",
        "mem: pool of 512 pages",
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

/// Boots `img` with no input until QEMU exits, echoing its output, and
/// returns the output if it exited with the pass code.
fn run_to_exit(img: &Image, limit: Duration) -> Result<String, String> {
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
        }
        all
    });
    let deadline = Instant::now() + limit;
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
    match status.and_then(|s| s.code()) {
        Some(QEMU_PASS) => Ok(out),
        code => Err(format!(
            "QEMU did not exit with the pass code (exit {code:?})"
        )),
    }
}

/// Boots the normal image and drives the shell over the serial port as a
/// person would: wait for the prompt, type a command, check the answer.
/// The shell's own `shutdown` command must then end QEMU with the pass
/// code.
fn shell_session(img: &Image) -> Result<(), String> {
    println!("== shell session on {}", img.path.display());
    // (typed text, text the answer must contain).
    let script: &[(&str, &str)] = &[
        ("help", "shutdown        power off"),
        ("echo hello from user space", "\nhello from user space"),
        ("about", "its own serial driver"),
        ("sleep 20", "slept 20 ticks"),
        ("ipc 20000", "20000 round trips to another thread"),
        ("frobnicate", "unknown command: frobnicate"),
        // A typo fixed with backspace: the shell runs "echo fixed".
        ("echp\x7fo fixed", "\nfixed"),
    ];
    drive_shell(img, &[], script)?;
    println!(
        "== shell session passed ({}{})",
        img.arch.name(),
        if img.sel4 { ", on seL4" } else { "" }
    );
    Ok(())
}

/// Boots `img` with `extra` QEMU arguments and drives the shell over the
/// serial port as a person would: wait for the prompt, type a command,
/// check the answer, and finally `shutdown`, which must end QEMU with the
/// pass code. Returns everything the shell printed.
fn drive_shell(img: &Image, extra: &[&str], script: &[(&str, &str)]) -> Result<String, String> {
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
        let deadline = Instant::now() + Duration::from_secs(60);
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
    let mut result = Ok(());
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
    let deadline = Instant::now() + Duration::from_secs(30);
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
