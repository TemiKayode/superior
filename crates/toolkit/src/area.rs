//! A text area: lines of text, edited at a cursor. One per [`Ui`], its
//! text (up to [`AREA_TEXT`] bytes, lines ended by `\n`) kept by the `Ui`.
//!
//! Typing inserts at the cursor and Enter starts a new line; Backspace and
//! Delete take out the character before or after it (joining lines when
//! that is a line's end). Left and Right move by a character, across
//! lines; Up and Down to the line above or below, as near the same column
//! as it reaches; Home and End to the line's start or end; Page Up and
//! Down by the lines shown. A press puts the cursor at the gap nearest it,
//! and the wheel scrolls. Lines wider than the area scroll sideways with
//! the cursor; the area scrolls down and up to keep the cursor's line
//! shown.

use crate::{
    EDGE, FIELD, FIELD_INSET, FOCUS_EDGE, INK, Id, Kind, Rect, Response, STEP, SCALE, Surface, Ui,
    font,
};

/// The most bytes of text an area holds, newlines included.
pub const AREA_TEXT: usize = 512;

/// The height of an area's line.
pub const LINE_H: u32 = font::HEIGHT * SCALE + 4;

/// Space between an area's edge and its first line.
const TOP: u32 = 4;

impl Ui {
    /// An empty text area showing `rows` lines, the window's width (on a
    /// line, what the others leave). One per `Ui`.
    pub fn area(&mut self, rows: u32) -> Id {
        assert!(self.area_id.is_none(), "one text area per Ui");
        let w = self.column_width();
        let id = self.add(Kind::Area, w, rows * LINE_H + 2 * TOP, b"");
        self.area_id = Some(id);
        (self.widgets[id].cursor, self.widgets[id].anchor) = (0, 0);
        id
    }

    /// The text area's text.
    pub fn area_text(&self) -> &str {
        core::str::from_utf8(&self.area[..self.area_len]).unwrap_or("")
    }

    /// Sets the text area's text (cut at [`AREA_TEXT`] bytes, ASCII and
    /// newlines kept, the rest left out), the cursor at its end: the part
    /// of the window to show again.
    pub fn set_area_text(&mut self, text: &str) -> Rect {
        let Some(id) = self.area_id else { return Rect::NONE };
        self.area_len = 0;
        for &c in text.as_bytes().iter().filter(|&&c| c == b'\n' || (b' '..=b'~').contains(&c)) {
            if self.area_len == AREA_TEXT {
                break;
            }
            self.area[self.area_len] = c;
            self.area_len += 1;
        }
        self.widgets[id].cursor = self.area_len;
        self.keep_area_cursor_shown(id);
        self.widgets[id].rect
    }

    /// The text area's cursor as its line and column (both from 0).
    pub fn area_cursor(&self) -> (usize, usize) {
        let Some(id) = self.area_id else { return (0, 0) };
        let c = self.widgets[id].cursor;
        (self.line_of(c), c - self.line_start(c))
    }

    /// How many lines the text area's text has (at least one).
    pub fn area_lines(&self) -> usize {
        self.line_of(self.area_len) + 1
    }

    fn area_bytes(&self) -> &[u8] {
        &self.area[..self.area_len]
    }

    /// The start of the line holding byte `at`.
    fn line_start(&self, at: usize) -> usize {
        self.area_bytes()[..at].iter().rposition(|&c| c == b'\n').map_or(0, |k| k + 1)
    }

    /// The end of the line holding byte `at` (its newline, or the text's
    /// end).
    fn line_end(&self, at: usize) -> usize {
        self.area_bytes()[at..].iter().position(|&c| c == b'\n').map_or(self.area_len, |k| at + k)
    }

    /// Which line byte `at` is on.
    fn line_of(&self, at: usize) -> usize {
        self.area_bytes()[..at].iter().filter(|&&c| c == b'\n').count()
    }

    /// Where line `n` starts (the text's end past the last line).
    fn start_of_line(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        self.area_bytes().iter().enumerate().filter(|&(_, &c)| c == b'\n').nth(n - 1).map_or(self.area_len, |(k, _)| k + 1)
    }

    /// Byte `col` of line `n`, or its end if shorter.
    fn at_line_col(&self, n: usize, col: usize) -> usize {
        let s = self.start_of_line(n.min(self.area_lines() - 1));
        (s + col).min(self.line_end(s))
    }

    /// How many lines, and characters of a line, the area shows (with room
    /// for the cursor after the last).
    fn area_shown(&self, id: Id) -> (usize, usize) {
        let r = self.widgets[id].rect;
        (
            (r.h.saturating_sub(2 * TOP) / LINE_H).max(1) as usize,
            (r.w.saturating_sub(FIELD_INSET + 1) / STEP).max(1) as usize,
        )
    }

    /// Scrolls the area as little as keeps its cursor shown: `scroll` its
    /// first line shown, `hscroll` its first column.
    pub(crate) fn keep_area_cursor_shown(&mut self, id: Id) {
        let (rows, cols) = self.area_shown(id);
        let (line, col) = self.area_cursor();
        let lines = self.area_lines();
        let w = &mut self.widgets[id];
        if line < w.scroll {
            w.scroll = line;
        } else if line >= w.scroll + rows {
            w.scroll = line + 1 - rows;
        }
        w.scroll = w.scroll.min(lines.saturating_sub(rows));
        if col < w.hscroll {
            w.hscroll = col;
        } else if col > w.hscroll + cols - 1 {
            w.hscroll = col + 1 - cols;
        }
    }

    /// A key down for the text area.
    pub(crate) fn area_key(&mut self, id: Id, usage: u64, control: bool, ch: Option<u8>, r: &mut Response) {
        use crate::{BACKSPACE, DELETE, DOWN, END, ENTER, HOME, LEFT, PAGE_DOWN, PAGE_UP, RIGHT, UP};
        let before = (self.area_len, self.widgets[id].cursor, self.widgets[id].scroll, self.widgets[id].hscroll);
        let c = self.widgets[id].cursor;
        let (line, col) = self.area_cursor();
        let rows = self.area_shown(id).0;
        let to = match usage {
            LEFT => c.saturating_sub(1),
            RIGHT => (c + 1).min(self.area_len),
            HOME => self.line_start(c),
            END => self.line_end(c),
            UP if line > 0 => self.at_line_col(line - 1, col),
            UP => 0,
            DOWN if line + 1 < self.area_lines() => self.at_line_col(line + 1, col),
            DOWN => self.area_len,
            PAGE_UP => self.at_line_col(line.saturating_sub(rows), col),
            PAGE_DOWN => self.at_line_col(line + rows, col),
            BACKSPACE if c > 0 => {
                self.remove(c - 1);
                c - 1
            }
            DELETE if c < self.area_len => {
                self.remove(c);
                c
            }
            ENTER => self.insert(c, b'\n'),
            _ => match ch.filter(|_| !control) {
                Some(k) => self.insert(c, k),
                None => c,
            },
        };
        self.widgets[id].cursor = to;
        self.keep_area_cursor_shown(id);
        let w = self.widgets[id];
        if (self.area_len, w.cursor, w.scroll, w.hscroll) != before {
            r.damage = w.rect;
        }
    }

    /// Inserts `k` at `at` if there is room: where the cursor goes.
    fn insert(&mut self, at: usize, k: u8) -> usize {
        if self.area_len == AREA_TEXT {
            return at;
        }
        self.area.copy_within(at..self.area_len, at + 1);
        self.area[at] = k;
        self.area_len += 1;
        at + 1
    }

    fn remove(&mut self, at: usize) {
        self.area.copy_within(at + 1..self.area_len, at);
        self.area_len -= 1;
    }

    /// A press at (x, y) in the text area: the cursor to the gap nearest it.
    pub(crate) fn area_press(&mut self, id: Id, x: i32, y: i32) {
        let w = self.widgets[id];
        let row = ((y - (w.rect.y + TOP) as i32).max(0) as u32 / LINE_H) as usize;
        let from = x - (w.rect.x + FIELD_INSET) as i32 + STEP as i32 / 2;
        let col = w.hscroll + (from.max(0) as u32 / STEP) as usize;
        self.widgets[id].cursor = self.at_line_col(w.scroll + row, col);
        self.keep_area_cursor_shown(id);
    }

    /// The wheel turned `up` steps over the text area: the part of the
    /// window to show again.
    pub(crate) fn area_wheel(&mut self, id: Id, up: i32) -> Rect {
        let rows = self.area_shown(id).0;
        let most = self.area_lines().saturating_sub(rows);
        let w = &mut self.widgets[id];
        let to = (w.scroll as i64 - up as i64).clamp(0, most as i64) as usize;
        if to == w.scroll {
            return Rect::NONE;
        }
        w.scroll = to;
        w.rect
    }

    /// Draws the text area: its lines shown, and the cursor if it has the
    /// keyboard.
    pub(crate) fn draw_area(&self, s: &mut Surface, id: Id) {
        let w = self.widgets[id];
        let r = w.rect;
        let keyboard = self.keyboard() == Some(id);
        s.fill(r, FIELD);
        s.outline(r, if keyboard { FOCUS_EDGE } else { EDGE });
        let (rows, cols) = self.area_shown(id);
        let th = font::HEIGHT * SCALE;
        let tx = r.x + FIELD_INSET;
        let (cl, cc) = self.area_cursor();
        for row in 0..rows {
            let n = w.scroll + row;
            if n >= self.area_lines() {
                break;
            }
            let ty = r.y + TOP + row as u32 * LINE_H + (LINE_H - th) / 2;
            let s0 = self.start_of_line(n);
            let line = &self.area_bytes()[s0..self.line_end(s0)];
            let shown = &line[w.hscroll.min(line.len())..(w.hscroll + cols).min(line.len())];
            s.text(tx, ty, shown, SCALE, INK);
            if keyboard && n == cl && cc >= w.hscroll {
                let cx = tx + (cc - w.hscroll) as u32 * STEP - SCALE;
                s.fill(Rect { x: cx, y: ty - 1, w: SCALE, h: th + 2 }, INK);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::{Event, Ui};

    const BACKSPACE: u64 = 42;
    const ENTER: u64 = 40;
    const DELETE: u64 = 76;
    const HOME: u64 = 74;
    const END: u64 = 77;
    const RIGHT: u64 = 79;
    const LEFT: u64 = 80;
    const DOWN: u64 = 81;
    const UP: u64 = 82;

    fn key(ui: &mut Ui, usage: u64) {
        ui.event(Event::us_key(usage, true, 0));
        ui.event(Event::us_key(usage, false, 0));
    }

    fn typ(ui: &mut Ui, s: &str) {
        for c in s.bytes() {
            match c {
                b'\n' => key(ui, ENTER),
                b' ' => key(ui, 44),
                _ => key(ui, 4 + (c - b'a') as u64),
            }
        }
    }

    /// A notes window: a label over a 4-line area, which has the keyboard.
    fn notes() -> (Ui, usize) {
        let mut ui = Ui::new(300, 140);
        ui.label("Notes:");
        let a = ui.area(4);
        ui.event(Event::Pointer { x: 50, y: 50, buttons: 0 });
        ui.event(Event::Pointer { x: 50, y: 50, buttons: 1 });
        ui.event(Event::Pointer { x: 50, y: 50, buttons: 0 });
        ui.event(Event::Focus(true));
        (ui, a)
    }

    #[test]
    fn lines_are_typed_joined_and_moved_through() {
        let (mut ui, _) = notes();
        assert_eq!(ui.keyboard(), Some(1));
        typ(&mut ui, "milk\neggs\nbread");
        assert_eq!((ui.area_text(), ui.area_cursor(), ui.area_lines()), ("milk\neggs\nbread", (2, 5), 3));
        // Up twice to the first line's end (as near column 5 as it gets),
        // Home, Down: the second line's start.
        key(&mut ui, UP);
        assert_eq!(ui.area_cursor(), (1, 4));
        key(&mut ui, UP);
        key(&mut ui, HOME);
        key(&mut ui, DOWN);
        assert_eq!(ui.area_cursor(), (1, 0));
        // Backspace joins it to the first; Enter splits them again.
        key(&mut ui, BACKSPACE);
        assert_eq!((ui.area_text(), ui.area_cursor()), ("milkeggs\nbread", (0, 4)));
        key(&mut ui, ENTER);
        assert_eq!((ui.area_text(), ui.area_cursor()), ("milk\neggs\nbread", (1, 0)));
        // Left crosses back over the line's end; Delete there joins.
        key(&mut ui, LEFT);
        assert_eq!(ui.area_cursor(), (0, 4));
        key(&mut ui, DELETE);
        key(&mut ui, RIGHT);
        assert_eq!((ui.area_text(), ui.area_cursor()), ("milkeggs\nbread", (0, 5)));
        key(&mut ui, END);
        typ(&mut ui, " jam");
        assert_eq!(ui.area_text(), "milkeggs jam\nbread");
        // Down past the last line: its end.
        key(&mut ui, DOWN);
        key(&mut ui, DOWN);
        assert_eq!(ui.area_cursor(), (1, 5));
    }

    #[test]
    fn it_scrolls_to_keep_the_cursor_shown_and_a_press_moves_it() {
        let (mut ui, a) = notes();
        typ(&mut ui, "a\nb\nc\nd\ne\nf");
        // Six lines, four shown: scrolled to the last.
        assert_eq!((ui.widget(a).scroll, ui.area_cursor()), (2, (5, 1)));
        // The wheel up: the first lines shown; a press on the top line,
        // past its end, puts the cursor at its end.
        let r = ui.widget(a).rect;
        ui.event(Event::Wheel { x: r.x as i32 + 20, y: r.y as i32 + 20, up: 5 });
        assert_eq!(ui.widget(a).scroll, 0);
        let (x, y) = (r.x as i32 + 200, r.y as i32 + 8);
        ui.event(Event::Pointer { x, y, buttons: 1 });
        ui.event(Event::Pointer { x, y, buttons: 0 });
        assert_eq!(ui.area_cursor(), (0, 1));
        // A line wider than the area scrolls sideways with the cursor.
        key(&mut ui, END);
        typ(&mut ui, "bcdefghijklmnopqrstuvwxyz");
        let shown = ui.widget(a).hscroll;
        assert!(shown > 0, "scrolled sideways");
        key(&mut ui, HOME);
        assert_eq!(ui.widget(a).hscroll, 0);
    }

    #[test]
    fn it_holds_what_fits_and_set_text_keeps_ascii_and_newlines() {
        let (mut ui, _) = notes();
        let long: std::string::String = core::iter::repeat_n('x', 600).collect();
        ui.set_area_text(&long);
        assert_eq!(ui.area_text().len(), super::AREA_TEXT);
        typ(&mut ui, "y");
        assert_eq!(ui.area_text().len(), super::AREA_TEXT, "full: nothing more typed");
        ui.set_area_text("one\ttwo\nthree\u{e9}");
        assert_eq!((ui.area_text(), ui.area_cursor()), ("onetwo\nthree", (1, 5)));
    }
}
