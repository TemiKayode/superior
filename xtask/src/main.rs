//! Superior build driver.
//!
//!   cargo xtask image   build the kernel and a BIOS-bootable disk image
//!   cargo xtask run     build and boot it in QEMU, into the shell (serial on
//!                       this terminal)
//!   cargo xtask test    host unit tests, the exhaustive model check and long
//!                       simulation, the boot self-tests in QEMU, then a
//!                       scripted session with the shell
//!   cargo xtask boot-test   just the boot self-tests
//!   cargo xtask shell-test  just the shell session
//!   cargo xtask bench   time IPC under hardware virtualization (WHPX or KVM)
//!                       and check it against seL4's published figures
//!
//! QEMU is found through $QEMU, then the default Windows install path, then PATH.

use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
            .and_then(|img| boot(&img, true))
            .and_then(|_| image(false))
            .and_then(|img| shell_session(&img)),
        Some("boot-test") => image(true).and_then(|img| boot(&img, true)),
        Some("shell-test") => image(false).and_then(|img| shell_session(&img)),
        Some("bench") => image(false).and_then(|img| bench(&img)),
        _ => Err("usage: cargo xtask <image | run | test | boot-test | shell-test | bench>".into()),
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
/// kernel loads it into its user window and relocates it.
fn user_program(package: &str) -> Result<PathBuf, String> {
    println!("== building {package}");
    run(cargo().args([
        "build",
        "--quiet",
        "-p",
        package,
        "--release",
        "--target",
        KERNEL_TARGET,
    ]))?;
    Ok(root()
        .join("target")
        .join(KERNEL_TARGET)
        .join("release")
        .join(package))
}

fn image(selftest: bool) -> Result<PathBuf, String> {
    let user = user_program("superior-pingpong")?;
    let shell = user_program("superior-shell")?;
    println!(
        "== building kernel{}",
        if selftest { " (selftest)" } else { "" }
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

fn qemu_command(img: &Path) -> Command {
    let mut q = Command::new(qemu());
    q.arg("-drive")
        .arg(format!("format=raw,file={}", img.display()))
        .args(["-m", "512M", "-serial", "stdio", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    q
}

fn boot(img: &Path, selftest: bool) -> Result<(), String> {
    println!("== booting {}", img.display());
    let mut q = qemu_command(img);
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

/// Boots the normal image and drives the shell over the serial port as a
/// person would: wait for the prompt, type a command, check the answer.
/// The shell's own `shutdown` command must then end QEMU with the pass
/// code.
fn shell_session(img: &Path) -> Result<(), String> {
    println!("== shell session on {}", img.display());
    // (typed text, text the answer must contain).
    let script: &[(&str, &str)] = &[
        ("help", "shutdown        power off"),
        ("echo hello from user space", "\nhello from user space"),
        ("about", "its own COM1 driver"),
        ("sleep 20", "slept 20 ticks"),
        ("ipc 20000", "20000 round trips to another thread"),
        ("frobnicate", "unknown command: frobnicate"),
        // A typo fixed with backspace: the shell runs "echo fixed".
        ("echp\x7fo fixed", "\nfixed"),
    ];
    drive_shell(img, &[], script)?;
    println!("== shell session passed");
    Ok(())
}

/// Boots `img` with `extra` QEMU arguments and drives the shell over the
/// serial port as a person would: wait for the prompt, type a command,
/// check the answer, and finally `shutdown`, which must end QEMU with the
/// pass code. Returns everything the shell printed.
fn drive_shell(img: &Path, extra: &[&str], script: &[(&str, &str)]) -> Result<String, String> {
    let mut child = qemu_command(img)
        .args(["-display", "none"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start QEMU ({}): {e}", qemu().display()))?;
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
fn bench(img: &Path) -> Result<(), String> {
    let accel: &[&str] = if cfg!(windows) {
        // WHPX: the in-kernel irqchip and nested VT-x are not available
        // on every Hyper-V host.
        &["-accel", "whpx,kernel-irqchip=off", "-cpu", "host,-vmx"]
    } else {
        &["-accel", "kvm", "-cpu", "host"]
    };
    println!("== IPC benchmark on {} ({})", img.display(), accel[1]);
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
