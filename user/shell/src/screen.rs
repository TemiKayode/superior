//! The console on the screen: the shell's session drawn on the boot
//! framebuffer, for machines with no serial port.
//!
//! The kernel hands the framebuffer the bootloader or firmware set up to
//! the root task as device memory; a manifest that gives it to the shell
//! (`device framebuffer`) gets this console. `UntypedInfo` on it says the
//! screen's geometry. How the screen looks (the bar, the prompt, the
//! inks, the blinking cursor) is `superior_console::Term`; this module is
//! the framebuffer under it.
//!
//! Before clearing the screen the shell reads back what the kernel's boot
//! log left on it (kernel/src/arch/x86_64/fbcon.rs draws it in the same
//! font, light grey on black, at twice its size inside an 8-pixel margin),
//! so `log` can show it on a machine with no serial port.

use superior_console::{Canvas, Ink, Pieces, Term};
use superior_objects::abi::Syscall;
use superior_objects::abi::framebuffer::{BGR, Geometry};
use superior_sys::{USER_BASE, syscall};
use superior_toolkit::font;

/// Where the framebuffer is mapped.
const SCREEN_VA: u64 = USER_BASE + 0x4800_0000;

/// The kernel's boot log on the screen: its margin, its cell and its ink.
const LOG_MARGIN: usize = 8;
const LOG_SCALE: usize = 2;
const LOG_CELL_W: usize = font::ADVANCE as usize * LOG_SCALE;
const LOG_CELL_H: usize = (font::HEIGHT as usize + 2) * LOG_SCALE;
const LOG_INK: [u8; 3] = [0xc8, 0xcc, 0xd0];
/// The most of it kept.
const LOG_COLUMNS: usize = 160;
const LOG_ROWS: usize = 64;

struct Framebuffer {
    g: Geometry,
}

impl Framebuffer {
    fn at(&self, x: usize, y: usize) -> *mut u8 {
        let at = (y * self.g.stride as usize + x) * self.g.bytes_per_pixel as usize;
        (SCREEN_VA as usize + at) as *mut u8
    }

    /// The colour of pixel (`x`, `y`), red first.
    fn read(&self, x: usize, y: usize) -> [u8; 3] {
        if x >= self.g.width as usize || y >= self.g.height as usize {
            return [0; 3];
        }
        let p = self.at(x, y);
        // SAFETY: the framebuffer is mapped at SCREEN_VA and (x, y) is on
        // the screen, so its bytes are inside it.
        let v = unsafe { [0, 1, 2].map(|i| core::ptr::read_volatile(p.add(i))) };
        if self.g.format == BGR { [v[2], v[1], v[0]] } else { v }
    }
}

impl Canvas for Framebuffer {
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, [r, g, b]: [u8; 3]) {
        let (width, height) = (self.g.width as usize, self.g.height as usize);
        let px = if self.g.format == BGR { [b, g, r] } else { [r, g, b] };
        let word = u32::from_le_bytes([px[0], px[1], px[2], 0]);
        let bpp = self.g.bytes_per_pixel as usize;
        for yy in y..(y + h).min(height) {
            for xx in x..(x + w).min(width) {
                let p = self.at(xx, yy);
                // SAFETY: as in `read`: (xx, yy) is on the mapped screen.
                unsafe {
                    if bpp == 4 {
                        core::ptr::write_volatile(p as *mut u32, word);
                    } else {
                        for (i, v) in px.iter().enumerate() {
                            core::ptr::write_volatile(p.add(i), *v);
                        }
                    }
                }
            }
        }
    }
}

struct Screen {
    fb: Framebuffer,
    /// The kernel's boot log, as it was on the screen.
    log: [[u8; LOG_COLUMNS]; LOG_ROWS],
    log_len: [u8; LOG_ROWS],
    log_rows: usize,
}

static mut SCREEN: Option<Screen> = None;
static mut TERM: Term = Term::new();

/// The console, once [`init`] found a screen, and what it shows.
fn screen() -> Option<(&'static mut Framebuffer, &'static mut Term)> {
    // SAFETY: the shell is one thread (its echo thread never draws), and
    // nothing holds these past a call.
    unsafe {
        let s = (*core::ptr::addr_of_mut!(SCREEN)).as_mut()?;
        Some((&mut s.fb, &mut *core::ptr::addr_of_mut!(TERM)))
    }
}

fn state() -> Option<&'static mut Screen> {
    // SAFETY: as in `screen`.
    unsafe { (*core::ptr::addr_of_mut!(SCREEN)).as_mut() }
}

/// Maps the framebuffer in slot `memory` (its frame made into slot
/// `frame`), keeps the boot log it shows and clears it, if the slot holds
/// the boot framebuffer. Returns its size in pixels.
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
    let s = Screen {
        fb: Framebuffer { g },
        log: [[b' '; LOG_COLUMNS]; LOG_ROWS],
        log_len: [0; LOG_ROWS],
        log_rows: 0,
    };
    // SAFETY: as in `screen`; set once, before any drawing.
    unsafe { *core::ptr::addr_of_mut!(SCREEN) = Some(s) };
    read_log();
    let (fb, term) = screen()?;
    term.init(fb, g.width as usize, g.height as usize);
    Some((g.width, g.height))
}

/// Reads the kernel's log off the screen: in each cell, the 35 font
/// pixels lit in its ink make a character.
fn read_log() {
    let Some(s) = state() else { return };
    let (w, h) = (s.fb.g.width as usize, s.fb.g.height as usize);
    let columns = (w.saturating_sub(2 * LOG_MARGIN) / LOG_CELL_W).min(LOG_COLUMNS);
    let rows = (h.saturating_sub(2 * LOG_MARGIN) / LOG_CELL_H).min(LOG_ROWS);
    for row in 0..rows {
        let mut len = 0;
        for col in 0..columns {
            let (x0, y0) = (LOG_MARGIN + col * LOG_CELL_W, LOG_MARGIN + row * LOG_CELL_H);
            let mut bits = 0u64;
            for y in 0..font::HEIGHT as usize {
                for x in 0..font::WIDTH as usize {
                    bits <<= 1;
                    if s.fb.read(x0 + x * LOG_SCALE, y0 + y * LOG_SCALE) == LOG_INK {
                        bits |= 1;
                    }
                }
            }
            let c = superior_console::recognise(bits);
            s.log[row][col] = c;
            if c != b' ' {
                len = col + 1;
            }
        }
        s.log_len[row] = len as u8;
        if len > 0 {
            s.log_rows = row + 1;
        }
    }
}

/// The boot log's lines, as read off the screen.
pub fn log_lines() -> impl Iterator<Item = &'static [u8]> {
    let s = state();
    let rows = s.as_ref().map_or(0, |s| s.log_rows);
    (0..rows).filter_map(move |r| {
        let s: &'static Screen = state()?;
        Some(&s.log[r][..s.log_len[r] as usize])
    })
}

/// The boot log line containing `needle`, if there is one.
pub fn log_line_with(needle: &[u8]) -> Option<&'static [u8]> {
    log_lines().find(|l| l.windows(needle.len()).any(|w| w == needle))
}

pub fn present() -> bool {
    state().is_some()
}

/// Writes output in the current ink.
pub fn write(text: &[u8]) {
    if let Some((fb, t)) = screen() {
        t.write(fb, text);
    }
}

pub fn ink(ink: Ink) {
    if let Some((_, t)) = screen() {
        t.ink(ink);
    }
}

pub fn style(ink: Ink, indent: usize) {
    if let Some((_, t)) = screen() {
        t.style(ink, indent);
    }
}

pub fn prompt() {
    if let Some((fb, t)) = screen() {
        t.prompt(fb);
    }
}

pub fn edit(line: &[u8], cursor: usize) {
    if let Some((fb, t)) = screen() {
        t.edit(fb, line, cursor);
    }
}

pub fn submit() {
    if let Some((fb, t)) = screen() {
        t.submit(fb);
    }
}

pub fn clear() {
    if let Some((fb, t)) = screen() {
        t.clear(fb);
    }
}

pub fn tick() {
    if let Some((fb, t)) = screen() {
        t.tick(fb);
    }
}

pub fn bar(left: Pieces, right: Pieces) {
    if let Some((fb, t)) = screen() {
        t.bar(fb, left, right);
    }
}
