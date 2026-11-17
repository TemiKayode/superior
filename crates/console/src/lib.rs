//! The shell's console on a machine's own screen.
//!
//! [`Term`] is what the screen shows: a status bar along the top, then
//! the session, with output indented under a quiet prompt (`~ ›`), the line
//! being typed in a brighter ink and a blinking beam for the cursor. It
//! draws through [`Canvas`], so the shell gives it the boot framebuffer
//! and the host tests (and `cargo xtask console-shell-test`) give it a
//! picture in memory and get the same pixels.
//!
//! [`editor`] edits the line: history, the editing keys, Tab completion and
//! a suggestion for a mistyped command. [`recognise`] reads back the
//! characters the kernel left on the screen, so the shell can keep the boot
//! log before it clears it.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod editor;

use superior_toolkit::font;

// ---- the look ----------------------------------------------------------

/// How much each font pixel is magnified.
pub const SCALE: usize = 2;
/// A character cell: the 5x7 font's advance, and a line with room above
/// and below the glyph.
pub const CELL_W: usize = font::ADVANCE as usize * SCALE;
pub const CELL_H: usize = 20;
/// Where in its cell a glyph starts.
const GLYPH_TOP: usize = 2;
/// The font squeezes descenders into its 7 rows; on the screen these
/// letters get 9, their bodies as tall as the other small letters' and
/// their tails below the line.
const TALL: [(u8, [u8; 9]); 5] = [
    (b'g', [0x00, 0x00, 0x0f, 0x11, 0x11, 0x11, 0x0f, 0x01, 0x0e]),
    (b'j', [0x02, 0x00, 0x06, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0c]),
    (b'p', [0x00, 0x00, 0x1e, 0x11, 0x11, 0x11, 0x1e, 0x10, 0x10]),
    (b'q', [0x00, 0x00, 0x0f, 0x11, 0x11, 0x11, 0x0f, 0x01, 0x01]),
    (b'y', [0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x0f, 0x01, 0x0e]),
];
/// The space left and right of the text.
pub const SIDE: usize = 16;
/// The status bar's height, the rule under it, and the gap before the text.
pub const BAR_H: usize = 30;
const RULE_H: usize = 1;
const GAP: usize = 10;
/// Where the session's first line starts.
pub const TOP: usize = BAR_H + RULE_H + GAP;

/// Where the prompt starts on its line, and where the line typed starts.
pub const PROMPT_COL: usize = 2;
pub const INPUT_COL: usize = PROMPT_COL + 4;
/// Where output starts on its line.
pub const OUTPUT_COL: usize = 4;

/// The screen's colours, warm and low in contrast except where the eye
/// should go: the line being typed and the prompt's mark.
pub const BACKGROUND: [u8; 3] = [0x13, 0x12, 0x11];
pub const BAR: [u8; 3] = [0x1c, 0x1b, 0x19];
pub const RULE: [u8; 3] = [0x2c, 0x2a, 0x27];
pub const CURSOR: [u8; 3] = [0xe3, 0xa8, 0x5c];

/// The inks text is written in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ink {
    /// Output.
    Text,
    /// What matters less: descriptions, hints, the boot log.
    Muted,
    /// The prompt's mark and the bar's name.
    Accent,
    /// The line being typed, and names worth picking out.
    Strong,
    /// Something went wrong.
    Error,
    /// Something went right.
    Good,
}

impl Ink {
    pub const fn rgb(self) -> [u8; 3] {
        match self {
            Ink::Text => [0xd6, 0xd1, 0xc7],
            Ink::Muted => [0x86, 0x81, 0x78],
            Ink::Accent => [0xe3, 0xa8, 0x5c],
            Ink::Strong => [0xf3, 0xef, 0xe7],
            Ink::Error => [0xe3, 0x8a, 0x73],
            Ink::Good => [0x9f, 0xc4, 0x8d],
        }
    }
}

/// The screen's greeting, and the hint under it.
pub const WELCOME: &[u8] = b"Welcome to Superior. Type a command, or 'help' to list them.\n";
pub const HINT: &[u8] = b"Tab completes \x81 \x82\x83 history \x81 'log' shows the boot log\n";

/// Characters beyond ASCII, as bytes the console draws itself.
pub const ARROW: u8 = 0x80;
pub const DOT: u8 = 0x81;
pub const UP: u8 = 0x82;
pub const DOWN: u8 = 0x83;

/// Their glyphs, in the font's form (7 rows, bit 4 the leftmost column).
const EXTRA: [[u8; 7]; 4] = [
    [0x00, 0x08, 0x04, 0x02, 0x04, 0x08, 0x00], // › (ARROW)
    [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00], // · (DOT)
    [0x04, 0x0e, 0x15, 0x04, 0x04, 0x04, 0x04], // ↑ (UP)
    [0x04, 0x04, 0x04, 0x04, 0x15, 0x0e, 0x04], // ↓ (DOWN)
];

/// Whether pixel (`x`, `y`) of character `c`'s glyph is lit.
pub fn lit(c: u8, x: u32, y: u32) -> bool {
    match c {
        ARROW..=DOWN => {
            x < font::WIDTH && y < font::HEIGHT && EXTRA[(c - ARROW) as usize][y as usize] & (0x10 >> x) != 0
        }
        _ => font::lit(c, x, y),
    }
}

// ---- drawing -----------------------------------------------------------

/// Where the console draws: the boot framebuffer, or a picture in memory.
pub trait Canvas {
    /// Fills the rectangle at (`x`, `y`), `w` by `h` pixels, clipped to the
    /// canvas.
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, rgb: [u8; 3]);
}

/// Draws `c` with its top-left corner at (`x`, `y`), a whole cell: the
/// background, then the glyph.
fn glyph(cv: &mut impl Canvas, x: usize, y: usize, c: u8, fg: [u8; 3], bg: [u8; 3]) {
    cv.fill(x, y, CELL_W, CELL_H, bg);
    if c == b' ' {
        return;
    }
    let top = y + GLYPH_TOP;
    if let Some((_, rows)) = TALL.iter().find(|(t, _)| *t == c) {
        for (gy, bits) in rows.iter().enumerate() {
            for gx in 0..font::WIDTH as usize {
                if bits & (0x10 >> gx) != 0 {
                    cv.fill(x + gx * SCALE, top + gy * SCALE, SCALE, SCALE, fg);
                }
            }
        }
        return;
    }
    for gy in 0..font::HEIGHT {
        for gx in 0..font::WIDTH {
            if lit(c, gx, gy) {
                let px = x + gx as usize * SCALE;
                let py = top + gy as usize * SCALE;
                cv.fill(px, py, SCALE, SCALE, fg);
            }
        }
    }
}

/// The text the bar shows: a few pieces on the left, a few on the right.
pub type Pieces<'a> = &'a [(&'a [u8], Ink)];

// ---- the terminal ------------------------------------------------------

/// The most text kept: wider or taller screens use this much of it (a
/// 1920x1080 screen has 158 columns and 51 rows). It is kept small: the
/// shell's whole image, this included, must fit the Component Manager's
/// 76 pages.
pub const MAX_COLUMNS: usize = 200;
pub const MAX_ROWS: usize = 80;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Cell {
    c: u8,
    ink: Ink,
}

const BLANK: Cell = Cell { c: b' ', ink: Ink::Text };

/// Ticks (10 ms each) the cursor stays lit, then dark.
pub const BLINK_TICKS: u32 = 50;

/// What the screen shows, and where the next character goes.
pub struct Term {
    width: usize,
    height: usize,
    columns: usize,
    rows: usize,
    cells: [[Cell; MAX_COLUMNS]; MAX_ROWS],
    col: usize,
    row: usize,
    /// The ink and the indent output is written with.
    ink: Ink,
    indent: usize,
    /// Something has been written on this line.
    dirty_line: bool,
    /// Output came since the last prompt (a blank line goes before the
    /// next one).
    since_prompt: bool,
    /// The row the line being typed starts on, while there is one.
    input_row: Option<usize>,
    /// How many characters of it are on the screen.
    shown: usize,
    /// Where the cursor is drawn, and whether it is lit now.
    cursor: Option<(usize, usize)>,
    lit: bool,
    ticks: u32,
}

impl Term {
    pub const fn new() -> Term {
        Term {
            width: 0,
            height: 0,
            columns: 1,
            rows: 1,
            cells: [[BLANK; MAX_COLUMNS]; MAX_ROWS],
            col: 0,
            row: 0,
            ink: Ink::Text,
            indent: OUTPUT_COL,
            dirty_line: false,
            since_prompt: false,
            input_row: None,
            shown: 0,
            cursor: None,
            lit: false,
            ticks: 0,
        }
    }

    /// Sets the screen's size and clears it, bar and all.
    pub fn init(&mut self, cv: &mut impl Canvas, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.columns = (width.saturating_sub(2 * SIDE) / CELL_W).clamp(INPUT_COL + 8, MAX_COLUMNS);
        self.rows = (height.saturating_sub(TOP + GAP) / CELL_H).clamp(2, MAX_ROWS);
        cv.fill(0, 0, width, height, BACKGROUND);
        cv.fill(0, BAR_H, width, RULE_H, RULE);
        self.bar(cv, &[], &[]);
        self.reset();
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    fn reset(&mut self) {
        for row in self.cells.iter_mut() {
            row.fill(BLANK);
        }
        (self.col, self.row) = (0, 0);
        self.dirty_line = false;
        self.since_prompt = false;
        self.input_row = None;
        self.shown = 0;
        self.cursor = None;
    }

    /// Clears the session (the bar stays).
    pub fn clear(&mut self, cv: &mut impl Canvas) {
        cv.fill(0, BAR_H + RULE_H, self.width, self.height.saturating_sub(BAR_H + RULE_H), BACKGROUND);
        self.reset();
    }

    /// Redraws the bar: `left` from the left edge, `right` against the
    /// right one (dropped if the two would meet).
    pub fn bar(&mut self, cv: &mut impl Canvas, left: Pieces, right: Pieces) {
        cv.fill(0, 0, self.width, BAR_H, BAR);
        let y = (BAR_H - CELL_H) / 2;
        let mut x = SIDE;
        for &(text, ink) in left {
            for &c in text {
                glyph(cv, x, y, c, ink.rgb(), BAR);
                x += CELL_W;
            }
        }
        let len: usize = right.iter().map(|(t, _)| t.len()).sum();
        let start = self.width.saturating_sub(SIDE + len * CELL_W);
        if start < x + 2 * CELL_W {
            return;
        }
        let mut x = start;
        for &(text, ink) in right {
            for &c in text {
                glyph(cv, x, y, c, ink.rgb(), BAR);
                x += CELL_W;
            }
        }
    }

    fn origin(&self, col: usize, row: usize) -> (usize, usize) {
        (SIDE + col * CELL_W, TOP + row * CELL_H)
    }

    /// Puts `cell` at (`col`, `row`), drawing it if it changed.
    fn set(&mut self, cv: &mut impl Canvas, col: usize, row: usize, cell: Cell) {
        if self.cells[row][col] == cell {
            return;
        }
        self.cells[row][col] = cell;
        let (x, y) = self.origin(col, row);
        glyph(cv, x, y, cell.c, cell.ink.rgb(), BACKGROUND);
    }

    /// Everything up a line, redrawing only the cells that change.
    fn scroll(&mut self, cv: &mut impl Canvas) {
        self.hide_cursor(cv);
        for r in 0..self.rows - 1 {
            for c in 0..self.columns {
                let below = self.cells[r + 1][c];
                self.set(cv, c, r, below);
            }
        }
        let last = self.rows - 1;
        for c in 0..self.columns {
            self.set(cv, c, last, BLANK);
        }
        if let Some(r) = self.input_row.as_mut() {
            *r = r.saturating_sub(1);
        }
    }

    fn newline(&mut self, cv: &mut impl Canvas) {
        self.col = 0;
        self.dirty_line = false;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.scroll(cv);
        }
    }

    /// The ink and the indent of what is written next.
    pub fn style(&mut self, ink: Ink, indent: usize) {
        self.ink = ink;
        self.indent = indent.min(self.columns / 2);
    }

    pub fn ink(&mut self, ink: Ink) {
        self.ink = ink;
    }

    /// Writes output: printable characters (and the console's own),
    /// newlines, and tabs to the next multiple of four. Long lines wrap
    /// to the indent.
    pub fn write(&mut self, cv: &mut impl Canvas, text: &[u8]) {
        for &b in text {
            match b {
                b'\n' => {
                    self.newline(cv);
                    continue;
                }
                b'\r' | 0x08 => continue,
                _ => {}
            }
            if !self.dirty_line && self.col < self.indent {
                self.col = self.indent;
            }
            if self.col >= self.columns {
                self.newline(cv);
                self.col = self.indent;
                self.dirty_line = true;
                if b == b' ' {
                    continue;
                }
            }
            self.dirty_line = true;
            self.since_prompt = true;
            if b == b'\t' {
                self.col = (self.col.saturating_sub(self.indent) / 4 + 1) * 4 + self.indent;
                continue;
            }
            let c = if (0x20..=0x7e).contains(&b) || (ARROW..=DOWN).contains(&b) { b } else { b'?' };
            let ink = self.ink;
            self.set(cv, self.col, self.row, Cell { c, ink });
            self.col += 1;
        }
    }

    /// Starts a new prompt: on a fresh line, after a blank one if output
    /// came since the last.
    pub fn prompt(&mut self, cv: &mut impl Canvas) {
        self.hide_cursor(cv);
        if self.dirty_line {
            self.newline(cv);
        }
        if self.since_prompt && self.row > 0 {
            self.newline(cv);
        }
        let row = self.row;
        self.set(cv, PROMPT_COL, row, Cell { c: b'~', ink: Ink::Muted });
        self.set(cv, PROMPT_COL + 2, row, Cell { c: ARROW, ink: Ink::Accent });
        self.input_row = Some(row);
        self.col = INPUT_COL;
        self.shown = 0;
        self.since_prompt = false;
        self.dirty_line = true;
        self.place_cursor(cv, 0);
    }

    /// How many characters of the line fit on one screen line.
    fn per_line(&self) -> usize {
        self.columns - INPUT_COL
    }

    /// Where character `i` of the line being typed goes.
    fn input_at(&self, i: usize) -> (usize, usize) {
        let start = self.input_row.unwrap_or(self.row);
        (INPUT_COL + i % self.per_line(), start + i / self.per_line())
    }

    /// Scrolls until row `row` (counted from the line's first) is on the
    /// screen.
    fn make_room(&mut self, cv: &mut impl Canvas, upto: usize) {
        loop {
            let (_, row) = self.input_at(upto);
            if row < self.rows {
                return;
            }
            self.scroll(cv);
        }
    }

    /// Shows `line` as the line being typed, with the cursor before
    /// character `cursor`.
    pub fn edit(&mut self, cv: &mut impl Canvas, line: &[u8], cursor: usize) {
        if self.input_row.is_none() {
            return;
        }
        self.hide_cursor(cv);
        self.make_room(cv, line.len().max(self.shown));
        for (i, &b) in line.iter().enumerate() {
            let (col, row) = self.input_at(i);
            let c = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
            self.set(cv, col, row, Cell { c, ink: Ink::Strong });
        }
        for i in line.len()..self.shown {
            let (col, row) = self.input_at(i);
            self.set(cv, col, row, BLANK);
        }
        self.shown = line.len();
        self.place_cursor(cv, cursor.min(line.len()));
    }

    /// Ends the line being typed: output starts on the next line.
    pub fn submit(&mut self, cv: &mut impl Canvas) {
        self.hide_cursor(cv);
        self.cursor = None;
        let last = self.shown.saturating_sub(1);
        let (_, row) = self.input_at(last);
        self.row = row.min(self.rows - 1);
        self.input_row = None;
        self.shown = 0;
        self.newline(cv);
        self.since_prompt = false;
        self.style(Ink::Text, OUTPUT_COL);
    }

    fn place_cursor(&mut self, cv: &mut impl Canvas, i: usize) {
        self.make_room(cv, i);
        self.cursor = Some(self.input_at(i));
        self.lit = true;
        self.ticks = 0;
        self.draw_cursor(cv);
    }

    fn draw_cursor(&mut self, cv: &mut impl Canvas) {
        if let Some((col, row)) = self.cursor {
            let (x, y) = self.origin(col, row);
            if self.lit {
                cv.fill(x, y + 1, 2, CELL_H - 2, CURSOR);
            } else {
                let cell = self.cells[row][col];
                glyph(cv, x, y, cell.c, cell.ink.rgb(), BACKGROUND);
            }
        }
    }

    fn hide_cursor(&mut self, cv: &mut impl Canvas) {
        if self.lit {
            self.lit = false;
            self.draw_cursor(cv);
        }
    }

    /// One timer tick: the cursor blinks.
    pub fn tick(&mut self, cv: &mut impl Canvas) {
        if self.cursor.is_none() {
            return;
        }
        self.ticks += 1;
        if self.ticks >= BLINK_TICKS {
            self.ticks = 0;
            self.lit = !self.lit;
            self.draw_cursor(cv);
        }
    }

    /// Where the cursor is drawn (column, row), if anywhere: for tests
    /// that compare screens and must leave its blink out.
    pub fn cursor_cell(&self) -> Option<(usize, usize)> {
        self.cursor
    }

    /// The pixel rectangle of cell (`col`, `row`).
    pub fn cell_rect(&self, col: usize, row: usize) -> (usize, usize, usize, usize) {
        let (x, y) = self.origin(col, row);
        (x, y, CELL_W, CELL_H)
    }

    /// The text on row `row`, for tests.
    pub fn row_text(&self, row: usize, out: &mut [u8]) -> usize {
        let mut n = 0;
        for (i, cell) in self.cells[row][..self.columns].iter().enumerate() {
            if i < out.len() {
                out[i] = cell.c;
                if cell.c != b' ' {
                    n = i + 1;
                }
            }
        }
        n
    }
}

impl Default for Term {
    fn default() -> Term {
        Term::new()
    }
}

// ---- reading the kernel's log back --------------------------------------

/// A glyph's lit pixels as 35 bits, row by row from the top, the leftmost
/// pixel of a row first.
pub fn pattern(c: u8) -> u64 {
    let mut bits = 0u64;
    for y in 0..font::HEIGHT {
        for x in 0..font::WIDTH {
            bits <<= 1;
            if font::lit(c, x, y) {
                bits |= 1;
            }
        }
    }
    bits
}

/// The character whose glyph has these lit pixels, as [`pattern`] lays
/// them out: a space for none, `?` for a shape no character has.
pub fn recognise(bits: u64) -> u8 {
    if bits == 0 {
        return b' ';
    }
    (0x21..=0x7e).find(|&c| pattern(c) == bits).unwrap_or(b'?')
}

#[cfg(test)]
mod tests;
