//! The Superior boot shell.
//!
//! One user process that is also its own serial driver: the kernel gives it
//! the UART and its interrupt line as capabilities, and nothing about the
//! console lives in the kernel. Each UART interrupt arrives as a signal on
//! a notification; the shell drains the UART's receive buffer, then
//! acknowledges the interrupt so the kernel unmasks the line.
//!
//! Its capabilities (slots), from the kernel at boot:
//!
//! | Slot | Capability |
//! | --- | --- |
//! | 0 | the UART: I/O ports 0x3f8-0x3ff (COM1) on x86-64; on AArch64 the PL011's register page, a device frame the shell maps |
//! | 1 | the UART's interrupt line |
//! | 2 | a notification the interrupt signals |
//! | 3 | the timer notification (one signal per 10 ms tick) |
//! | 4 | 64 KiB of untyped memory |
//! | 5 | I/O port 0xf4, QEMU's exit device (emulated on AArch64) |
//! | 10, 11 | (`console.manifest`) the PS/2 controller's data and status ports |
//! | 12 | (`console.manifest`) the boot framebuffer, as device memory |
//!
//! Given the PS/2 controller and the framebuffer, the shell is also a
//! console on the machine's own screen and keyboard ([`screen`], [`ps2`]),
//! for PCs with no serial port: what it prints goes to both, and it reads
//! from both. Where COM1 is missing (its status port reads as all ones),
//! the shell leaves it alone.

#![no_std]
#![no_main]

mod ps2;
mod screen;

use core::fmt::{self, Write};
use superior_objects::abi::{ObjectType, Syscall};
use superior_sys::{USER_BASE, cycles, syscall};

const UART: u64 = 0;
const UART_IRQ: u64 = 1;
const UART_NTFN: u64 = 2;
const TIMER: u64 = 3;
const UNTYPED: u64 = 4;
const EXIT_PORT: u64 = 5;
// Slots for the IPC demo's objects.
const ECHO_EP: u64 = 7;
const ECHO_TCB: u64 = 8;
const ECHO_STACK: u64 = 9;
// The screen console's devices, when the manifest gives them, and the
// framebuffer's frame, made here.
const PS2_DATA: u64 = 10;
const PS2_STATUS: u64 = 11;
const FB_MEMORY: u64 = 12;
const FB_FRAME: u64 = 13;
/// The echo thread's endpoint, in its own CSpace.
const ECHO_SLOT: u64 = 0;

const ECHO_STACK_VA: u64 = USER_BASE + 0x4000_0000;
const RIGHT_READ: u64 = 1 << 0;
const RIGHT_WRITE: u64 = 1 << 1;

const PROMPT: &str = "superior> ";
const LINE_MAX: usize = 120;

// ---- the serial driver -------------------------------------------------

/// COM1, a 16550, through I/O-port system calls.
#[cfg(target_arch = "x86_64")]
mod uart {
    use super::*;

    const PORT_DATA: u64 = 0x3f8;
    const PORT_LSR: u64 = 0x3fd;
    const LSR_DATA_READY: u64 = 1 << 0;
    const LSR_THR_EMPTY: u64 = 1 << 5;

    fn port_in(port: u64) -> u64 {
        syscall(Syscall::IoPortIn, UART, [port, 1, 0, 0]).msg[0]
    }

    fn port_out(port: u64, value: u64) {
        syscall(Syscall::IoPortOut, UART, [port, 1, value, 0]);
    }

    /// The kernel already enabled the receive interrupt for its console.
    pub fn init() -> u64 {
        0
    }

    /// Whether there is a UART at COM1: with nothing there, its line
    /// status reads as all ones (which would look like a byte always
    /// waiting).
    pub fn present() -> bool {
        port_in(PORT_LSR) & 0xff != 0xff
    }

    pub fn try_read() -> Option<u8> {
        (port_in(PORT_LSR) & LSR_DATA_READY != 0).then(|| port_in(PORT_DATA) as u8)
    }

    pub fn write(b: u8) {
        while port_in(PORT_LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        port_out(PORT_DATA, b as u64);
    }

    /// Reading the data register cleared the interrupt.
    pub fn clear_interrupt() {}
}

/// A PL011, through its register page mapped into this address space.
#[cfg(target_arch = "aarch64")]
mod uart {
    use super::*;

    const UART_VA: u64 = USER_BASE + 0x3000_0000;
    const DR: u64 = 0x00;
    const FR: u64 = 0x18;
    const IMSC: u64 = 0x38;
    const ICR: u64 = 0x44;
    const FR_RXFE: u32 = 1 << 4;
    const FR_TXFF: u32 = 1 << 5;
    /// Receive and receive-timeout interrupts.
    const RX_INTERRUPTS: u32 = (1 << 4) | (1 << 6);

    fn reg(off: u64) -> *mut u32 {
        (UART_VA + off) as *mut u32
    }

    fn read_reg(off: u64) -> u32 {
        // SAFETY: the register page is mapped at UART_VA by `init`.
        unsafe { core::ptr::read_volatile(reg(off)) }
    }

    fn write_reg(off: u64, v: u32) {
        // SAFETY: as in `read_reg`.
        unsafe { core::ptr::write_volatile(reg(off), v) }
    }

    /// Maps the register page and enables the receive interrupts.
    pub fn init() -> u64 {
        let status = syscall(Syscall::FrameMap, UART, [UART_VA, 1, 0, 0]).status;
        if status == 0 {
            write_reg(IMSC, read_reg(IMSC) | RX_INTERRUPTS);
        }
        status
    }

    /// The PL011 is always there on the machines the shell runs on.
    pub fn present() -> bool {
        true
    }

    pub fn try_read() -> Option<u8> {
        (read_reg(FR) & FR_RXFE == 0).then(|| read_reg(DR) as u8)
    }

    pub fn write(b: u8) {
        while read_reg(FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        write_reg(DR, b as u32);
    }

    pub fn clear_interrupt() {
        write_reg(ICR, RX_INTERRUPTS);
    }
}

/// What the shell talks through: the UART if there is one, and the
/// screen and the PS/2 keyboard if it was given them.
struct Devices {
    uart: bool,
    keyboard: Option<ps2::Keyboard>,
}

static mut DEVICES: Devices = Devices {
    uart: true,
    keyboard: None,
};

fn devices() -> &'static mut Devices {
    // SAFETY: only the shell's main thread touches it (the echo thread
    // never prints), and nothing holds it past a call.
    unsafe { &mut *core::ptr::addr_of_mut!(DEVICES) }
}

fn put_byte(b: u8) {
    if devices().uart {
        uart::write(b);
    }
    screen::put(b);
}

/// The console: output goes to the UART, and to the screen if there is one.
struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                put_byte(b'\r');
            }
            put_byte(b);
        }
        Ok(())
    }
}

macro_rules! out {
    ($($arg:tt)*) => {{ let _ = write!(Console, $($arg)*); }};
}
macro_rules! outln {
    ($($arg:tt)*) => {{ let _ = writeln!(Console, $($arg)*); }};
}

/// Next byte typed: read whatever the UART or the keyboard holds, else
/// sleep until the UART's interrupt, or with a keyboard until the next
/// tick at the latest (the keyboard is polled), on the same notification.
fn get_byte() -> u8 {
    loop {
        if devices().uart {
            if let Some(b) = uart::try_read() {
                return b;
            }
        }
        if let Some(k) = devices().keyboard.as_mut() {
            if let Some(b) = k.poll() {
                return b;
            }
            syscall(Syscall::TimerSignal, UART_NTFN, [1, 0, 0, 0]);
        }
        syscall(Syscall::Wait, UART_NTFN, [0; 4]);
        if devices().uart {
            uart::clear_interrupt();
            syscall(Syscall::IrqAck, UART_IRQ, [0; 4]);
        }
    }
}

/// Reads a line with echo and backspace. Returns its length.
fn read_line(buf: &mut [u8; LINE_MAX]) -> usize {
    let mut len = 0;
    loop {
        match get_byte() {
            b'\r' | b'\n' => {
                out!("\n");
                return len;
            }
            0x08 | 0x7f => {
                if len > 0 {
                    len -= 1;
                    out!("\x08 \x08");
                }
            }
            b @ 0x20..=0x7e if len < LINE_MAX => {
                buf[len] = b;
                len += 1;
                put_byte(b);
            }
            _ => {}
        }
    }
}

// ---- commands ----------------------------------------------------------

fn help() {
    outln!("commands:");
    outln!("  help            this list");
    outln!("  about           what is running");
    outln!("  echo <text>     print <text>");
    outln!("  sleep <ticks>   sleep on the timer notification (100 ticks a second)");
    outln!("  ipc [rounds]    time call/reply round trips to a thread this shell starts");
    outln!("  shutdown        power off (exits QEMU)");
    if devices().keyboard.is_some() {
        outln!("  reboot          restart the machine (through the keyboard controller)");
    }
}

fn about() {
    outln!(
        "Superior {} on {}",
        env!("CARGO_PKG_VERSION"),
        superior_sys::ARCH
    );
    outln!("This shell is a user process and its own serial driver: the kernel");
    outln!("gave it the UART and its interrupt line as capabilities.");
    if devices().keyboard.is_some() {
        outln!("It also reads the PS/2 keyboard and draws on the boot framebuffer,");
        outln!("given to it as an I/O-port capability and as device memory.");
    }
}

fn reboot() {
    if devices().keyboard.is_none() {
        outln!("reboot needs the keyboard controller (boot the console image)");
        return;
    }
    outln!("restarting");
    if let Some(k) = devices().keyboard.as_ref() {
        k.reset_machine();
    }
    // The reset takes a moment; if it never comes, say so.
    for _ in 0..100 {
        syscall(Syscall::Wait, TIMER, [0; 4]);
    }
    outln!("the machine did not restart");
}

fn sleep(arg: &str) {
    let Ok(ticks) = arg.trim().parse::<u32>() else {
        outln!("usage: sleep <ticks>");
        return;
    };
    for _ in 0..ticks {
        syscall(Syscall::Wait, TIMER, [0; 4]);
    }
    outln!("slept {ticks} ticks");
}

/// Answers each call with its first word plus one, and with two
/// timestamps: when the call arrived and when the reply started. With the
/// caller's own timestamps these split a round trip into its call and
/// reply halves, measured one way each as seL4's sel4bench does (both
/// threads share a core, so they share the time-stamp counter).
extern "C" fn echo_server(_: u64) -> ! {
    let mut r = syscall(Syscall::Recv, ECHO_SLOT, [0; 4]);
    loop {
        let arrived = cycles();
        let n = r.msg[0] + 1;
        let replying = cycles();
        r = syscall(Syscall::ReplyRecv, ECHO_SLOT, [n, arrived, replying, 0]);
    }
}

/// Starts the echo thread on first use: an endpoint, a thread and its
/// stack, all made from this shell's untyped memory.
fn start_echo() -> Result<(), u64> {
    let check = |status: u64| if status == 0 { Ok(()) } else { Err(status) };
    let retype =
        |ty: ObjectType, dst: u64| syscall(Syscall::Retype, UNTYPED, [ty as u64, 0, dst, 0]).status;
    check(retype(ObjectType::Endpoint, ECHO_EP))?;
    check(retype(ObjectType::Thread, ECHO_TCB))?;
    check(retype(ObjectType::Frame, ECHO_STACK))?;
    check(syscall(Syscall::FrameMap, ECHO_STACK, [ECHO_STACK_VA, 1, 0, 0]).status)?;
    let tcb = |op: Syscall, args: [u64; 4]| syscall(op, ECHO_TCB, args).status;
    check(tcb(
        Syscall::ThreadCopyCap,
        [ECHO_EP, ECHO_SLOT, RIGHT_READ | RIGHT_WRITE, 0],
    ))?;
    let entry = echo_server as *const () as u64;
    check(tcb(
        Syscall::ThreadConfigure,
        [entry, ECHO_STACK_VA + 0x1000, 0, 10],
    ))?;
    check(tcb(Syscall::ThreadResume, [0; 4]))
}

/// Histograms of timings in 8-cycle buckets, for medians: under a
/// hypervisor a few rounds are stretched by host interrupts, which move the
/// mean but not the median.
const BUCKETS: usize = 1024;
const BUCKET_CYCLES: u64 = 8;

struct Histogram([u32; BUCKETS]);

impl Histogram {
    fn add(&mut self, cycles: u64) {
        let b = ((cycles / BUCKET_CYCLES) as usize).min(BUCKETS - 1);
        self.0[b] += 1;
    }

    /// The value below which `pct` percent of samples fall.
    fn percentile(&self, pct: u64) -> u64 {
        let total: u64 = self.0.iter().map(|&n| n as u64).sum();
        let want = (total * pct).div_ceil(100).max(1);
        let mut seen = 0;
        for (b, &n) in self.0.iter().enumerate() {
            seen += n as u64;
            if seen >= want {
                return b as u64 * BUCKET_CYCLES;
            }
        }
        BUCKETS as u64 * BUCKET_CYCLES
    }
}

static mut HISTOGRAMS: [Histogram; 3] = [
    Histogram([0; BUCKETS]),
    Histogram([0; BUCKETS]),
    Histogram([0; BUCKETS]),
];

fn ipc(arg: &str, started: &mut bool) {
    let rounds = match arg.trim() {
        "" => 10_000,
        a => match a.parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                outln!("usage: ipc [rounds]");
                return;
            }
        },
    };
    if !*started {
        if let Err(e) = start_echo() {
            outln!("could not start the echo thread: error {e}");
            return;
        }
        *started = true;
    }
    // Warm caches and TLBs first; these rounds are not counted.
    for i in 0..rounds.min(1000) {
        syscall(Syscall::Call, ECHO_EP, [i, 0, 0, 0]);
    }
    // SAFETY: the shell is the only thread touching these, and only here.
    let [round, call, reply] = unsafe { &mut *core::ptr::addr_of_mut!(HISTOGRAMS) };
    for h in [&mut *round, &mut *call, &mut *reply] {
        h.0 = [0; BUCKETS];
    }
    let (mut min, mut total) = (u64::MAX, 0u64);
    let (mut call_total, mut reply_total) = (0u64, 0u64);
    for i in 0..rounds {
        let t0 = cycles();
        let r = syscall(Syscall::Call, ECHO_EP, [i, 0, 0, 0]);
        let t1 = cycles();
        if r.status != 0 || r.msg[0] != i + 1 {
            outln!("round {i} failed: status {} reply {}", r.status, r.msg[0]);
            return;
        }
        let dt = t1.wrapping_sub(t0);
        min = min.min(dt);
        total += dt;
        let (c, rp) = (r.msg[1].wrapping_sub(t0), t1.wrapping_sub(r.msg[2]));
        call_total += c;
        reply_total += rp;
        round.add(dt);
        call.add(c);
        reply.add(rp);
    }
    outln!(
        "{rounds} round trips to another thread: min {min} cycles, mean {} cycles",
        total / rounds
    );
    outln!(
        "one way: call {} cycles, reply {} cycles (mean)",
        call_total / rounds,
        reply_total / rounds
    );
    outln!(
        "one way: call {} cycles, reply {} cycles (median); round trip median {}, 90th percentile {}",
        call.percentile(50),
        reply.percentile(50),
        round.percentile(50),
        round.percentile(90)
    );
}

fn shutdown() -> ! {
    outln!("powering off");
    syscall(Syscall::IoPortOut, EXIT_PORT, [0xf4, 4, 0x10, 0]);
    // Not under QEMU: stop here.
    loop {
        syscall(Syscall::Wait, UART_NTFN, [0; 4]);
    }
}

// On seL4 the runtime in superior-sys owns `_start` and calls this.
#[cfg_attr(not(feature = "sel4"), unsafe(no_mangle))]
#[cfg_attr(feature = "sel4", unsafe(export_name = "superior_main"))]
pub extern "C" fn _start(_: u64) -> ! {
    let mapped = uart::init();
    let bound = syscall(Syscall::IrqSetNotification, UART_IRQ, [UART_NTFN, 0, 0, 0]);
    devices().uart = uart::present();
    let screen = screen::init(FB_MEMORY, FB_FRAME);
    devices().keyboard = ps2::Keyboard::new(PS2_DATA, PS2_STATUS);
    outln!();
    outln!("Superior shell. Type 'help' for commands.");
    if devices().uart && (mapped != 0 || bound.status != 0) {
        outln!(
            "(serial interrupt not set up: map {mapped}, bind {})",
            bound.status
        );
    }
    if let Some((w, h)) = screen {
        let keyboard = if devices().keyboard.is_some() { "the PS/2 keyboard" } else { "no keyboard" };
        let serial = if devices().uart { "and COM1" } else { "no serial port" };
        outln!("Console on the screen ({w}x{h}), {keyboard}, {serial}.");
    }
    let mut echo_started = false;
    let mut buf = [0u8; LINE_MAX];
    loop {
        out!("{PROMPT}");
        let len = read_line(&mut buf);
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("").trim();
        let (cmd, arg) = line.split_once(' ').unwrap_or((line, ""));
        match cmd {
            "" => {}
            "help" => help(),
            "about" => about(),
            "echo" => outln!("{arg}"),
            "sleep" => sleep(arg),
            "ipc" => ipc(arg, &mut echo_started),
            "shutdown" | "exit" => shutdown(),
            "reboot" => reboot(),
            other => outln!("unknown command: {other} (try 'help')"),
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    outln!("shell panic");
    loop {
        syscall(Syscall::Wait, UART_NTFN, [0; 4]);
    }
}
