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
//!   cargo xtask bench              time IPC under hardware virtualization
//!                                  (WHPX or KVM, x86-64) and check it against
//!                                  seL4's published figures
//!   cargo xtask sel4-test          the same shell session with the shell
//!                                  running on seL4 (AArch64) instead; `test`
//!                                  ends with it. seL4 and its loader are built
//!                                  once, in Docker (sel4/Dockerfile)
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
                        .and_then(|_| image(false, a))
                        .and_then(|img| shell_session(&img))
                })
            })
            .and_then(|_| sel4_image())
            .and_then(|img| shell_session(&img)),
        Some("sel4-test") => sel4_image().and_then(|img| shell_session(&img)),
        Some("boot-test") => image(true, arch).and_then(|img| boot(&img, true)),
        Some("shell-test") => image(false, arch).and_then(|img| shell_session(&img)),
        Some("bench") => image(false, Arch::X86_64).and_then(|img| bench(&img)),
        _ => Err(
            "usage: cargo xtask <image | run | test | boot-test | shell-test | bench | sel4-test> [x86_64 | aarch64]"
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
    run(cargo().args(["test", "--quiet", "-p", "superior-objects"]))?;
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

/// Builds a user program as a static position-independent executable; the
/// kernel loads it into its user window and relocates it. User programs
/// build in their own target directory, since on AArch64 they need flags
/// the kernel must not get.
fn user_program(package: &str, arch: Arch) -> Result<PathBuf, String> {
    println!("== building {package} ({})", arch.name());
    let mut build = cargo();
    if arch == Arch::Aarch64 {
        // x86_64-unknown-none is static-pie by default; this target is not.
        build.env(
            "CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_RUSTFLAGS",
            "-C relocation-model=pie -C link-arg=-pie -C link-arg=--no-dynamic-linker",
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

fn image(selftest: bool, arch: Arch) -> Result<Image, String> {
    let user = user_program("superior-pingpong", arch)?;
    let shell = user_program("superior-shell", arch)?;
    println!(
        "== building kernel ({}{})",
        arch.name(),
        if selftest { ", selftest" } else { "" }
    );
    let mut build = cargo();
    build.env("SUPERIOR_USER_ELF", &user);
    build.env("SUPERIOR_SHELL_ELF", &shell);
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
    let suffix = if selftest { "-selftest" } else { "" };
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
    Ok(Image {
        path,
        arch,
        sel4: false,
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
    })
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
            q.arg("-drive")
                .arg(format!("format=raw,file={}", img.path.display()))
                .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
        }
        Arch::Aarch64 => {
            let machine = if img.sel4 { SEL4_MACHINE } else { "virt" };
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
