//! The PS/2 keyboard: where a laptop's built-in keyboard is (and where a
//! PC's firmware puts a USB keyboard while it emulates one).
//!
//! The kernel gives the root task the i8042 controller's two ports, data
//! (0x60) and status/command (0x64), as one I/O-port capability each; a
//! manifest that gives them to the shell (`device ps2`) gets this driver.
//! It polls: the shell looks at the controller whenever it wakes, and
//! while waiting for input it asks the kernel to wake it every tick, so a
//! key is seen within 10 ms. (Its interrupt, ISA IRQ 1, is not routed.)
//!
//! The controller translates the keyboard's codes to scancode set 1 (the
//! driver makes sure of that), read here with a US layout: letters,
//! digits and punctuation, Shift and Caps Lock, Enter, Backspace and Tab,
//! the arrows, Home, End and Delete, and Control with L, C, U, A and E.
//! Bytes from the mouse port (a touchpad) are dropped.

use superior_console::editor::Key;

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::Key;
    use superior_objects::abi::Syscall;
    use superior_sys::syscall;

    const DATA: u16 = 0x60;
    const STATUS: u16 = 0x64;
    /// Status: a byte waits in the output buffer, the controller has not
    /// yet taken the last one written to it, the byte is from the mouse.
    const OUTPUT_FULL: u64 = 1 << 0;
    const INPUT_FULL: u64 = 1 << 1;
    const FROM_MOUSE: u64 = 1 << 5;
    /// Controller commands: read and write its configuration byte; pulse
    /// the CPU's reset line.
    const READ_CONFIG: u64 = 0x20;
    const WRITE_CONFIG: u64 = 0x60;
    const RESET_CPU: u64 = 0xfe;
    /// Configuration: the keyboard's clock disabled; translation to set 1.
    const KEYBOARD_OFF: u64 = 1 << 4;
    const TRANSLATE: u64 = 1 << 6;

    pub struct Keyboard {
        data: u64,
        status: u64,
        shift: bool,
        caps: bool,
        control: bool,
        /// The last byte was 0xe0: an extended key's code follows.
        extended: bool,
    }

    /// The US layout, scancode set 1 make codes 0x00 to 0x39: unshifted
    /// and shifted (0: no character).
    const PLAIN: &[u8; 0x3a] = b"\0\x1b1234567890-=\x08\tqwertyuiop[]\r\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
    const SHIFTED: &[u8; 0x3a] = b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\r\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

    impl Keyboard {
        fn read(&self, cap: u64, port: u16) -> Option<u64> {
            let r = syscall(Syscall::IoPortIn, cap, [port as u64, 1, 0, 0]);
            (r.status == 0).then_some(r.msg[0])
        }

        fn write(&self, cap: u64, port: u16, v: u64) {
            syscall(Syscall::IoPortOut, cap, [port as u64, 1, v, 0]);
        }

        fn status(&self) -> u64 {
            self.read(self.status, STATUS).unwrap_or(0)
        }

        /// Waits (briefly) until the controller takes a byte.
        fn ready_to_write(&self) -> bool {
            (0..100_000).any(|_| self.status() & INPUT_FULL == 0)
        }

        /// Waits (briefly) for a byte from the controller.
        fn read_reply(&self) -> Option<u64> {
            (0..100_000)
                .any(|_| self.status() & OUTPUT_FULL != 0)
                .then(|| self.read(self.data, DATA))
                .flatten()
        }

        /// A controller is there if the ports answer and the status port
        /// does not read as all ones (nothing on the bus).
        pub fn new(data: u64, status: u64) -> Option<Keyboard> {
            let k = Keyboard {
                data,
                status,
                shift: false,
                caps: false,
                control: false,
                extended: false,
            };
            k.read(data, DATA)?;
            let s = k.read(status, STATUS)?;
            if s == 0xff {
                return None;
            }
            // Whatever the firmware left waiting.
            for _ in 0..32 {
                if k.status() & OUTPUT_FULL == 0 {
                    break;
                }
                k.read(data, DATA);
            }
            // Translation on and the keyboard's clock running (firmware
            // leaves both so on a PC; QEMU's too), the rest as it was.
            if k.ready_to_write() {
                k.write(status, STATUS, READ_CONFIG);
                if let Some(config) = k.read_reply() {
                    let want = (config | TRANSLATE) & !KEYBOARD_OFF;
                    if want != config && k.ready_to_write() {
                        k.write(status, STATUS, WRITE_CONFIG);
                        if k.ready_to_write() {
                            k.write(data, DATA, want);
                        }
                    }
                }
            }
            Some(k)
        }

        /// The next key pressed, if one is waiting.
        pub fn poll(&mut self) -> Option<Key> {
            loop {
                let s = self.status();
                if s & OUTPUT_FULL == 0 || s == 0xff {
                    return None;
                }
                let code = self.read(self.data, DATA)? as u8;
                if s & FROM_MOUSE != 0 {
                    continue;
                }
                if let Some(c) = self.key(code) {
                    return Some(c);
                }
            }
        }

        /// What scancode `code` presses, keeping track of the modifiers.
        fn key(&mut self, code: u8) -> Option<Key> {
            if code == 0xe0 {
                self.extended = true;
                return None;
            }
            let extended = core::mem::take(&mut self.extended);
            let (released, make) = (code & 0x80 != 0, code & 0x7f);
            match make {
                // Left and right Shift (an extended 0x2a is a fake shift
                // some keys send around themselves).
                0x2a | 0x36 if !extended => {
                    self.shift = !released;
                    None
                }
                0x3a if !released => {
                    self.caps = !self.caps;
                    None
                }
                // Left and right Control (the right one is extended).
                0x1d => {
                    self.control = !released;
                    None
                }
                _ if released => None,
                // The keypad's Enter, the arrows, Home, End and Delete.
                0x1c if extended => Some(Key::Enter),
                0x48 if extended => Some(Key::Up),
                0x50 if extended => Some(Key::Down),
                0x4b if extended => Some(Key::Left),
                0x4d if extended => Some(Key::Right),
                0x47 if extended => Some(Key::Home),
                0x4f if extended => Some(Key::End),
                0x53 if extended => Some(Key::Delete),
                _ if extended => None,
                m if (m as usize) < PLAIN.len() => {
                    let letter = PLAIN[m as usize].is_ascii_lowercase();
                    let shifted = self.shift ^ (self.caps && letter);
                    let c = if shifted { SHIFTED[m as usize] } else { PLAIN[m as usize] };
                    if self.control {
                        return match PLAIN[m as usize] {
                            b'l' => Some(Key::Clear),
                            b'c' => Some(Key::Cancel),
                            b'u' => Some(Key::KillLine),
                            b'a' => Some(Key::Home),
                            b'e' => Some(Key::End),
                            _ => None,
                        };
                    }
                    match c {
                        0 | 0x1b => None,
                        b'\t' => Some(Key::Tab),
                        b'\r' => Some(Key::Enter),
                        0x08 => Some(Key::Backspace),
                        c => Some(Key::Char(c)),
                    }
                }
                _ => None,
            }
        }

        /// Restarts the machine: the controller pulses the CPU's reset line.
        pub fn reset_machine(&self) {
            if self.ready_to_write() {
                self.write(self.status, STATUS, RESET_CPU);
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    use super::Key;

    /// No PS/2 controller on this architecture.
    pub struct Keyboard;

    impl Keyboard {
        pub fn new(_data: u64, _status: u64) -> Option<Keyboard> {
            None
        }

        pub fn poll(&mut self) -> Option<Key> {
            None
        }

        pub fn reset_machine(&self) {}
    }
}

pub use imp::Keyboard;
