//! Superior build driver.
//!
//!   cargo xtask image   build the kernel and a BIOS-bootable disk image
//!   cargo xtask run     build and boot it in QEMU (serial on this terminal)
//!   cargo xtask test    host unit tests, then boot self-tests in QEMU
//!
//! QEMU is found through $QEMU, then the default Windows install path, then PATH.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const KERNEL_TARGET: &str = "x86_64-unknown-none";
/// isa-debug-exit maps the kernel's 0x10 to QEMU status (0x10 << 1) | 1.
const QEMU_PASS: i32 = 33;

fn main() -> ExitCode {
    let cmd = env::args().nth(1);
    let result = match cmd.as_deref() {
        Some("image") => image(false).map(|p| println!("image: {}", p.display())),
        Some("run") => image(false).and_then(|img| boot(&img, false)),
        Some("test") => host_tests()
            .and_then(|_| image(true))
            .and_then(|img| boot(&img, true)),
        _ => Err("usage: cargo xtask <image | run | test>".into()),
    };
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
    run(cargo().args(["test", "--quiet", "-p", "superior-objects"]))
}

/// Builds the boot user program as a static position-independent
/// executable; the kernel loads it into its user window and relocates it.
fn user_program() -> Result<PathBuf, String> {
    println!("== building user program");
    run(cargo().args([
        "build",
        "--quiet",
        "-p",
        "superior-pingpong",
        "--release",
        "--target",
        KERNEL_TARGET,
    ]))?;
    Ok(root()
        .join("target")
        .join(KERNEL_TARGET)
        .join("release")
        .join("superior-pingpong"))
}

fn image(selftest: bool) -> Result<PathBuf, String> {
    let user = user_program()?;
    println!(
        "== building kernel{}",
        if selftest { " (selftest)" } else { "" }
    );
    let mut build = cargo();
    build.env("SUPERIOR_USER_ELF", &user);
    build.args([
        "build",
        "--quiet",
        "-p",
        "superior-kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
    ]);
    if selftest {
        build.args(["--features", "selftest"]);
    }
    run(&mut build)?;

    let target = root().join("target");
    let kernel = target
        .join(KERNEL_TARGET)
        .join("release")
        .join("superior-kernel");
    let img = target.join(if selftest {
        "superior-selftest.img"
    } else {
        "superior.img"
    });
    bootloader::BiosBoot::new(&kernel)
        .create_disk_image(&img)
        .map_err(|e| format!("creating disk image: {e}"))?;
    Ok(img)
}

fn qemu() -> PathBuf {
    if let Ok(p) = env::var("QEMU") {
        return p.into();
    }
    let windows_default = Path::new(r"C:\Program Files\qemu\qemu-system-x86_64.exe");
    if windows_default.exists() {
        return windows_default.into();
    }
    "qemu-system-x86_64".into()
}

fn boot(img: &Path, selftest: bool) -> Result<(), String> {
    println!("== booting {}", img.display());
    let mut q = Command::new(qemu());
    q.arg("-drive")
        .arg(format!("format=raw,file={}", img.display()))
        .args(["-m", "512M", "-serial", "stdio", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    if selftest {
        q.args(["-display", "none"]);
    }
    let status = q
        .status()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu().display()))?;
    match (selftest, status.code()) {
        (true, Some(QEMU_PASS)) => {
            println!("== boot self-tests passed");
            Ok(())
        }
        (true, code) => Err(format!("boot self-tests failed (QEMU exit {code:?})")),
        (false, _) => Ok(()),
    }
}
