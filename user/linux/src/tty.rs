//! The terminal: the serial console as Linux's `/dev/tty`, with its line
//! discipline.
//!
//! Bytes typed arrive from the UART (its interrupt signals the
//! personality's notification) and go through the discipline as Linux's
//! `n_tty` does, by the `termios` the programs set: in canonical mode a
//! line is edited (erase, kill) and becomes readable at the end of the
//! line or at end-of-file (`^D`); otherwise bytes are readable as they
//! come. The interrupt, quit and suspend characters raise signals in the
//! foreground process group instead; what is typed is echoed if `ECHO` is
//! set. Output goes straight to the UART, newlines as carriage return and
//! line feed (`ONLCR`).

use superior_objects::abi::Syscall;
use superior_sys::syscall;

/// Linux's `termios` flags used here.
const ICRNL: u32 = 0o400;
const IGNCR: u32 = 0o200;
const INLCR: u32 = 0o100;
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const ECHOCTL: u32 = 0o1000;
/// `c_cc` indexes.
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VMIN: usize = 6;
const VSUSP: usize = 10;

/// Linux's (kernel) `struct termios`: four flag words, the line
/// discipline, 19 control characters.
pub const TERMIOS_LEN: usize = 36;

const INPUT: usize = 1024;

pub struct Tty {
    pub termios: [u8; TERMIOS_LEN],
    /// The foreground process group: where typed signals go.
    pub fg: u32,
    pub rows: u16,
    pub cols: u16,
    /// Typed bytes not yet read; the first `ready` are readable (the rest
    /// are the line being edited, in canonical mode).
    buf: [u8; INPUT],
    len: usize,
    ready: usize,
    /// `^D` on an empty line: the next read returns 0.
    eof: bool,
}

impl Tty {
    /// Linux's defaults (`stty sane`) and a 24 by 80 window, input empty.
    pub fn reset(&mut self, fg: u32) {
        let mut t = [0u8; TERMIOS_LEN];
        let flags: [u32; 4] = [
            ICRNL | 0o2000,                                                // IXON
            OPOST | ONLCR,                                                 //
            0o277,                                                         // B38400 | CS8 | CREAD
            ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | 0o4000 | 0o100000, // ECHOKE, IEXTEN
        ];
        for (k, f) in flags.iter().enumerate() {
            t[k * 4..k * 4 + 4].copy_from_slice(&f.to_le_bytes());
        }
        let cc = [3u8, 0x1c, 0x7f, 0x15, 4, 0, 1, 0, 0x11, 0x13, 0x1a, 0, 0x12, 0x0f, 0x17, 0x16, 0, 0, 0];
        t[17..].copy_from_slice(&cc);
        self.termios = t;
        self.fg = fg;
        self.rows = 24;
        self.cols = 80;
        self.len = 0;
        self.ready = 0;
        self.eof = false;
    }

    fn flag(&self, k: usize) -> u32 {
        u32::from_le_bytes(self.termios[k * 4..k * 4 + 4].try_into().unwrap())
    }

    fn cc(&self, k: usize) -> u8 {
        self.termios[17 + k]
    }

    fn canonical(&self) -> bool {
        self.flag(3) & ICANON != 0
    }

    /// New settings (`TCSETS`); `flush` drops what was typed (`TCSETSF`).
    pub fn set(&mut self, t: [u8; TERMIOS_LEN], flush: bool) {
        self.termios = t;
        if flush {
            self.len = 0;
            self.ready = 0;
        }
        if !self.canonical() {
            // Leaving canonical mode makes the line typed so far readable.
            self.ready = self.len;
        }
    }

    /// Bytes a read could take now.
    pub fn available(&self) -> usize {
        self.ready
    }

    /// Whether a read returns at once (with bytes, or 0 at end-of-file or
    /// with `VMIN` 0 in raw mode).
    pub fn readable(&self) -> bool {
        self.ready > 0 || self.eof || (!self.canonical() && self.cc(VMIN) == 0)
    }

    /// A read: up to `out.len()` bytes, in canonical mode no further than
    /// one line.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        if self.ready == 0 {
            self.eof = false;
            return 0;
        }
        let mut n = self.ready.min(out.len());
        if self.canonical() {
            if let Some(nl) = self.buf[..n].iter().position(|&b| b == b'\n') {
                n = nl + 1;
            }
        }
        out[..n].copy_from_slice(&self.buf[..n]);
        self.buf.copy_within(n..self.len, 0);
        self.len -= n;
        self.ready -= n;
        n
    }

    /// Output from a program.
    pub fn write(&self, bytes: &[u8]) {
        let crlf = self.flag(1) & (OPOST | ONLCR) == OPOST | ONLCR;
        for &b in bytes {
            if b == b'\n' && crlf {
                uart::write(b'\r');
            }
            uart::write(b);
        }
    }

    fn echo(&self, b: u8) {
        let l = self.flag(3);
        if l & ECHO != 0 || b == b'\n' && l & ECHONL != 0 {
            if l & ECHOCTL != 0 && b < 0x20 && b != b'\n' && b != b'\t' {
                self.write(&[b'^', b + 0x40]);
            } else {
                self.write(&[b]);
            }
        }
    }

    /// A byte typed. A signal for the foreground group if it was one of
    /// the signal characters (with `ISIG`).
    pub fn input(&mut self, mut b: u8) -> Option<u32> {
        let (i, l) = (self.flag(0), self.flag(3));
        if b == b'\r' {
            if i & IGNCR != 0 {
                return None;
            }
            if i & ICRNL != 0 {
                b = b'\n';
            }
        } else if b == b'\n' && i & INLCR != 0 {
            b = b'\r';
        }
        if l & ISIG != 0 {
            let sig = match b {
                _ if b == self.cc(VINTR) => Some(2),
                _ if b == self.cc(VQUIT) => Some(3),
                _ if b == self.cc(VSUSP) => Some(20),
                _ => None,
            };
            if sig.is_some() {
                // Typed input is dropped, as Linux does without NOFLSH.
                self.len = self.ready;
                self.echo(b);
                return sig;
            }
        }
        if l & ICANON != 0 {
            let line = self.len - self.ready;
            if b == self.cc(VERASE) || b == 0x08 {
                if line > 0 {
                    self.len -= 1;
                    if l & ECHO != 0 && l & ECHOE != 0 {
                        self.write(b"\x08 \x08");
                    }
                }
                return None;
            }
            if b == self.cc(VKILL) {
                for _ in 0..line {
                    if l & ECHO != 0 && l & ECHOK != 0 {
                        self.write(b"\x08 \x08");
                    }
                }
                self.len = self.ready;
                return None;
            }
            if b == self.cc(VEOF) {
                if line == 0 {
                    self.eof = true;
                }
                self.ready = self.len;
                return None;
            }
        }
        if self.len == INPUT {
            return None;
        }
        self.buf[self.len] = b;
        self.len += 1;
        if l & ICANON == 0 || b == b'\n' {
            self.ready = self.len;
        }
        self.echo(b);
        None
    }
}

/// The console UART, as the boot shell drives it: slot [`UART`] holds it,
/// [`UART_IRQ`] its interrupt line.
pub const UART: u64 = 3;
pub const UART_IRQ: u64 = 4;

/// COM1, a 16550, through I/O-port system calls.
#[cfg(target_arch = "x86_64")]
pub mod uart {
    use super::*;

    const PORT_DATA: u64 = 0x3f8;
    const PORT_LSR: u64 = 0x3fd;
    const LSR_DATA_READY: u64 = 1 << 0;
    const LSR_THR_EMPTY: u64 = 1 << 5;

    fn port_in(port: u64) -> u64 {
        syscall(Syscall::IoPortIn, UART, [port, 1, 0, 0]).msg[0]
    }

    /// The kernel already enabled the receive interrupt for its console.
    pub fn init() -> u64 {
        0
    }

    pub fn try_read() -> Option<u8> {
        (port_in(PORT_LSR) & LSR_DATA_READY != 0).then(|| port_in(PORT_DATA) as u8)
    }

    pub fn write(b: u8) {
        while port_in(PORT_LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        syscall(Syscall::IoPortOut, UART, [PORT_DATA, 1, b as u64, 0]);
    }

    /// Reading the data register cleared the interrupt.
    pub fn clear_interrupt() {}
}

/// A PL011, through its register page mapped here.
#[cfg(target_arch = "aarch64")]
pub mod uart {
    use super::*;
    use superior_sys::USER_BASE;

    const UART_VA: u64 = USER_BASE + 0x3000_0000;
    const DR: u64 = 0x00;
    const FR: u64 = 0x18;
    const IMSC: u64 = 0x38;
    const ICR: u64 = 0x44;
    const FR_RXFE: u32 = 1 << 4;
    const FR_TXFF: u32 = 1 << 5;
    /// Receive and receive-timeout interrupts.
    const RX_INTERRUPTS: u32 = (1 << 4) | (1 << 6);

    fn read_reg(off: u64) -> u32 {
        // SAFETY: the register page is mapped at UART_VA by `init`.
        unsafe { core::ptr::read_volatile((UART_VA + off) as *const u32) }
    }

    fn write_reg(off: u64, v: u32) {
        // SAFETY: as in `read_reg`.
        unsafe { core::ptr::write_volatile((UART_VA + off) as *mut u32, v) }
    }

    /// Maps the register page and enables the receive interrupts.
    pub fn init() -> u64 {
        let status = syscall(Syscall::FrameMap, UART, [UART_VA, 1, 0, 0]).status;
        if status == 0 {
            write_reg(IMSC, read_reg(IMSC) | RX_INTERRUPTS);
        }
        status
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
