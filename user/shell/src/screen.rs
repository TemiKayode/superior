//! The console on the screen: the shell's output drawn on the boot
//! framebuffer, for machines with no serial port.
//!
//! The kernel hands the framebuffer the bootloader or firmware set up to
//! the root task as device memory; a manifest that gives it to the shell
//! (`device framebuffer`) gets this console. `UntypedInfo` on it says the
//! screen's geometry. The shell maps it whole and draws text as the
//! kernel's boot log does (kernel/src/arch/x86_64/fbcon.rs): light grey on
//! black, the toolkit's 5x7 font at twice its size, from the top left
//! inside an 8-pixel margin. When the screen is full, the text moves up a
//! line: redrawn from a copy of the characters kept here, since reading
//! the framebuffer back is slow.

use superior_objects::abi::Syscall;
use superior_objects::abi::framebuffer::{BGR, Geometry};
use superior_sys::{USER_BASE, syscall};
use superior_toolkit::font;

/// Where the framebuffer is mapped.
const SCREEN_VA: u64 = USER_BASE + 0x4800_0000;
const SCALE: usize = 2;
const MARGIN: usize = 8;
const CELL_W: usize = font::ADVANCE as usize * SCALE;
const CELL_H: usize = (font::HEIGHT as usize + 2) * SCALE;
const INK: [u8; 3] = [0xc8, 0xcc, 0xd0];
/// The most text kept: wider or taller screens use this much of it.
const MAX_COLUMNS: usize = 320;
const MAX_ROWS: usize = 120;

pub struct Screen {
    g: Geometry,
    columns: usize,
    rows: usize,
    col: usize,
    row: usize,
    /// The characters on the screen (static, not on the shell's small
    /// stack).
    text: &'static mut [[u8; MAX_COLUMNS]; MAX_ROWS],
}

static mut SCREEN: Option<Screen> = None;
static mut TEXT: [[u8; MAX_COLUMNS]; MAX_ROWS] = [[b' '; MAX_COLUMNS]; MAX_ROWS];

/// The console, once [`init`] found a screen.
fn screen() -> Option<&'static mut Screen> {
    // SAFETY: the shell is one thread (its echo thread never draws), and
    // nothing holds this past a call.
    unsafe { (*core::ptr::addr_of_mut!(SCREEN)).as_mut() }
}

/// Maps the framebuffer in slot `memory` (its frame made into slot
/// `frame`) and clears it, if the slot holds the boot framebuffer. Returns
/// its size in pixels.
pub fn init(memory: u64, frame: u64) -> Option<(u64, u64)> {
    let info = syscall(Syscall::UntypedInfo, memory, [0; 4]);
    if info.status != 0 {
        return None;
    }
    let g = Geometry::unpack([info.msg[2], info.msg[3]])?;
    let bits = info.msg[0];
    if syscall(Syscall::DeviceFrame, memory, [0, frame, bits, 0]).status != 0 {
        return None;
    }
    if syscall(Syscall::FrameMap, frame, [SCREEN_VA, 1, 0, 0]).status != 0 {
        return None;
    }
    let (w, h) = (g.width as usize, g.height as usize);
    let columns = (w.saturating_sub(2 * MARGIN) / CELL_W).clamp(1, MAX_COLUMNS);
    let rows = (h.saturating_sub(2 * MARGIN) / CELL_H).clamp(1, MAX_ROWS);
    let s = Screen {
        g,
        columns,
        rows,
        col: 0,
        row: 0,
        // SAFETY: taken once, here; only the console uses it.
        text: unsafe { &mut *core::ptr::addr_of_mut!(TEXT) },
    };
    // SAFETY: as in `screen`; set once, before any drawing.
    unsafe { *core::ptr::addr_of_mut!(SCREEN) = Some(s) };
    let s = screen()?;
    s.clear();
    Some((g.width, g.height))
}

/// Draws `b` at the cursor, if there is a screen: printable characters,
/// newline, and backspace (the cursor back one, as a terminal does).
pub fn put(b: u8) {
    if let Some(s) = screen() {
        s.put(b);
    }
}

impl Screen {
    fn pixel(&self, x: usize, y: usize, lit: bool) {
        if x >= self.g.width as usize || y >= self.g.height as usize {
            return;
        }
        let [r, g, b] = if lit { INK } else { [0; 3] };
        let px = if self.g.format == BGR { [b, g, r] } else { [r, g, b] };
        let bpp = self.g.bytes_per_pixel as usize;
        let at = (y * self.g.stride as usize + x) * bpp;
        let p = (SCREEN_VA as usize + at) as *mut u8;
        // SAFETY: the framebuffer is mapped at SCREEN_VA, and (x, y) is on
        // the screen, so all `bpp` bytes are inside it.
        unsafe {
            if bpp == 4 {
                let word = u32::from_le_bytes([px[0], px[1], px[2], 0]);
                core::ptr::write_volatile(p as *mut u32, word);
            } else {
                for (i, v) in px.iter().enumerate() {
                    core::ptr::write_volatile(p.add(i), *v);
                }
            }
        }
    }

    /// Draws character `c` in cell (`col`, `row`).
    fn draw(&self, col: usize, row: usize, c: u8) {
        let (x0, y0) = (MARGIN + col * CELL_W, MARGIN + row * CELL_H);
        for dy in 0..CELL_H {
            for dx in 0..CELL_W {
                let lit = dy < font::HEIGHT as usize * SCALE
                    && font::lit(c, (dx / SCALE) as u32, (dy / SCALE) as u32);
                self.pixel(x0 + dx, y0 + dy, lit);
            }
        }
    }

    fn clear(&mut self) {
        let (w, h) = (self.g.width as usize, self.g.height as usize);
        for y in 0..h {
            for x in 0..w {
                self.pixel(x, y, false);
            }
        }
        for line in self.text.iter_mut() {
            line.fill(b' ');
        }
        self.col = 0;
        self.row = 0;
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        // Everything up a line: redraw the cells that change.
        for r in 0..self.rows - 1 {
            for c in 0..self.columns {
                let (old, new) = (self.text[r][c], self.text[r + 1][c]);
                if old != new {
                    self.text[r][c] = new;
                    self.draw(c, r, new);
                }
            }
        }
        let last = self.rows - 1;
        for c in 0..self.columns {
            if self.text[last][c] != b' ' {
                self.text[last][c] = b' ';
                self.draw(c, last, b' ');
            }
        }
    }

    fn put(&mut self, b: u8) {
        match b {
            b'\n' => return self.newline(),
            b'\r' => return,
            0x08 => {
                self.col = self.col.saturating_sub(1);
                return;
            }
            _ => {}
        }
        if self.col == self.columns {
            self.newline();
        }
        let c = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
        self.text[self.row][self.col] = c;
        self.draw(self.col, self.row, c);
        self.col += 1;
    }
}
