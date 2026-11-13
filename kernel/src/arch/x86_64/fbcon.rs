//! The kernel's log on the screen, as well as on COM1: drawn on the
//! framebuffer the firmware (UEFI's GOP) or the bootloader (a VESA mode)
//! set up, so a machine without a serial port still shows how far boot
//! got, and why it stopped.
//!
//! Only until user space starts ([`hand_over`]): from then on the PCI bus
//! server and a display driver own the display, and may move its memory
//! (the framebuffer is a BAR), so the kernel must not write there. Light
//! grey text on black, in the toolkit's 5x7 font at twice its size, from
//! the top left; when the screen is full, everything moves up a line.

use bootloader_api::info::{FrameBuffer, PixelFormat};
use core::fmt;
use spin::Mutex;
use superior_toolkit::font;

/// Text is drawn at twice the font's size, with this much space around.
pub const SCALE: usize = 2;
pub const MARGIN: usize = 8;
/// A character cell: the font's advance, and its height with two rows
/// between lines.
pub const CELL_W: usize = font::ADVANCE as usize * SCALE;
pub const CELL_H: usize = (font::HEIGHT as usize + 2) * SCALE;
/// The text's colour (red, green, blue); the background is black.
pub const INK: [u8; 3] = [0xc8, 0xcc, 0xd0];

struct Console {
    buf: &'static mut [u8],
    width: usize,
    height: usize,
    stride: usize,
    bpp: usize,
    format: PixelFormat,
    col: usize,
    row: usize,
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// Starts drawing the log on `fb`, cleared to black, if the format is one
/// it knows (RGB or BGR, 3 or 4 bytes a pixel).
pub fn init(fb: Option<&'static mut FrameBuffer>) {
    let Some(fb) = fb else { return };
    let info = fb.info();
    if !matches!(info.pixel_format, PixelFormat::Rgb | PixelFormat::Bgr) || !(3..=4).contains(&info.bytes_per_pixel) {
        return;
    }
    let buf = fb.buffer_mut();
    buf.fill(0);
    *CONSOLE.lock() = Some(Console {
        buf,
        width: info.width,
        height: info.height,
        stride: info.stride,
        bpp: info.bytes_per_pixel,
        format: info.pixel_format,
        col: 0,
        row: 0,
    });
}

/// The screen's size, if the log is on it.
pub fn size() -> Option<(usize, usize)> {
    CONSOLE.lock().as_ref().map(|c| (c.width, c.height))
}

/// Stops drawing: user space is about to start and may take the display.
pub fn hand_over() {
    *CONSOLE.lock() = None;
}

impl Console {
    fn columns(&self) -> usize {
        (self.width.saturating_sub(2 * MARGIN) / CELL_W).max(1)
    }

    fn rows(&self) -> usize {
        (self.height.saturating_sub(2 * MARGIN) / CELL_H).max(1)
    }

    fn pixel(&mut self, x: usize, y: usize, lit: bool) {
        let [r, g, b] = if lit { INK } else { [0; 3] };
        let at = (y * self.stride + x) * self.bpp;
        let px = match self.format {
            PixelFormat::Bgr => [b, g, r],
            _ => [r, g, b],
        };
        self.buf[at..at + 3].copy_from_slice(&px);
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows() {
            self.row += 1;
            return;
        }
        // Everything up a line, and the last line cleared.
        let line = CELL_H * self.stride * self.bpp;
        let top = MARGIN * self.stride * self.bpp;
        let end = top + self.rows() * line;
        self.buf.copy_within(top + line..end, top);
        self.buf[end - line..end].fill(0);
    }

    fn put(&mut self, c: u8) {
        match c {
            b'\n' => return self.newline(),
            b'\r' => return,
            _ => {}
        }
        if self.col == self.columns() {
            self.newline();
        }
        let (x0, y0) = (MARGIN + self.col * CELL_W, MARGIN + self.row * CELL_H);
        for dy in 0..font::HEIGHT as usize * SCALE {
            for dx in 0..CELL_W {
                let lit = font::lit(c, (dx / SCALE) as u32, (dy / SCALE) as u32);
                self.pixel(x0 + dx, y0 + dy, lit);
            }
        }
        self.col += 1;
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.put(b);
        }
        Ok(())
    }
}

/// Draws `args`, if the log is on the screen.
pub fn print(args: fmt::Arguments) {
    if let Some(c) = CONSOLE.lock().as_mut() {
        let _ = fmt::Write::write_fmt(c, args);
    }
}
