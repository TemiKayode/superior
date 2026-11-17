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
//!
//! Text is selected as in a field: by dragging across it (down past its
//! last line shown, or up past its first, it scrolls), by Shift with any
//! of the keys that move the cursor or with a press, and by Control-A.
//! Typing, Enter, Backspace and Delete replace the selection; Control-C
//! copies it and Control-X cuts it (the first [`crate::MAX_TEXT`] bytes,
//! newlines kept), and Control-V pastes at the cursor.

use crate::{
    CONTROL, EDGE, FIELD, FIELD_INSET, FOCUS_EDGE, INK, Id, KEY_A, KEY_C, KEY_V, KEY_X, Kind, MAX_TEXT, Rect,
    Response, SCALE, SELECTION, SHIFT, STEP, Surface, Text, Ui, font,
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
        (self.widgets[id].cursor, self.widgets[id].anchor) = (self.area_len, self.area_len);
        self.keep_area_cursor_shown(id);
        self.widgets[id].rect
    }

    /// The text area's selection, if any: from the first byte selected to
    /// the byte after the last.
    pub fn area_selection(&self) -> Option<(usize, usize)> {
        self.area_id.and_then(|id| self.widgets[id].selection())
    }

    /// Takes the selection out of the text: whether there was one.
    fn area_cut(&mut self, id: Id) -> bool {
        let Some((a, b)) = self.widgets[id].selection() else { return false };
        self.area.copy_within(b..self.area_len, a);
        self.area_len -= b - a;
        (self.widgets[id].cursor, self.widgets[id].anchor) = (a, a);
        true
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
    pub(crate) fn area_key(&mut self, id: Id, usage: u64, modifiers: u8, ch: Option<u8>, r: &mut Response) {
        use crate::{BACKSPACE, DELETE, DOWN, END, ENTER, HOME, LEFT, PAGE_DOWN, PAGE_UP, RIGHT, UP};
        let (shift, control) = (modifiers & SHIFT != 0, modifiers & CONTROL != 0);
        let w = self.widgets[id];
        let before = (self.area_len, w.cursor, w.anchor, w.scroll, w.hscroll);
        let c = w.cursor;
        let sel = w.selection();
        let (line, col) = self.area_cursor();
        let rows = self.area_shown(id).0;
        // Moved with Shift (the selection stretched), or a key that leaves
        // the selection be: the anchor stays.
        let moves = matches!(usage, LEFT | RIGHT | HOME | END | UP | DOWN | PAGE_UP | PAGE_DOWN);
        let mut keep = moves && shift;
        let to = match usage {
            // Moved off a selection, the cursor goes to its end that way.
            LEFT if !shift && sel.is_some() => sel.map_or(c, |s| s.0),
            RIGHT if !shift && sel.is_some() => sel.map_or(c, |s| s.1),
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
            KEY_A if control => {
                self.widgets[id].anchor = 0;
                keep = true;
                self.area_len
            }
            KEY_C | KEY_X if control => match sel {
                Some((a, b)) => {
                    self.clipboard = Text::new(&self.area[a..b.min(a + MAX_TEXT)]);
                    r.copied = true;
                    keep = usage == KEY_C;
                    if usage == KEY_X {
                        self.area_cut(id);
                    }
                    self.widgets[id].cursor
                }
                None => c,
            },
            KEY_V if control => {
                self.area_cut(id);
                let mut at = self.widgets[id].cursor;
                let clip = self.clipboard;
                for &k in clip.as_bytes().iter().filter(|&&k| k == b'\n' || (b' '..=b'~').contains(&k)) {
                    at = self.insert(at, k);
                }
                at
            }
            BACKSPACE | DELETE if self.area_cut(id) => self.widgets[id].cursor,
            BACKSPACE if c > 0 => {
                self.remove(c - 1);
                c - 1
            }
            DELETE if c < self.area_len => {
                self.remove(c);
                c
            }
            ENTER => {
                self.area_cut(id);
                self.insert(self.widgets[id].cursor, b'\n')
            }
            _ => match ch.filter(|_| !control) {
                Some(k) => {
                    self.area_cut(id);
                    self.insert(self.widgets[id].cursor, k)
                }
                // Shift itself, say.
                None => {
                    keep = true;
                    c
                }
            },
        };
        self.widgets[id].cursor = to;
        if !keep {
            self.widgets[id].anchor = to;
        }
        self.keep_area_cursor_shown(id);
        let w = self.widgets[id];
        if (self.area_len, w.cursor, w.anchor, w.scroll, w.hscroll) != before {
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

    /// The gap in the text nearest (x, y): on the line there (the first or
    /// last line shown's neighbour above or below the area).
    fn area_gap_at(&self, id: Id, x: i32, y: i32) -> usize {
        let w = self.widgets[id];
        let dy = y - (w.rect.y + TOP) as i32;
        let row = dy.div_euclid(LINE_H as i32).clamp(-1, self.area_shown(id).0 as i32);
        let from = x - (w.rect.x + FIELD_INSET) as i32 + STEP as i32 / 2;
        let col = w.hscroll + (from.max(0) as u32 / STEP) as usize;
        self.at_line_col((w.scroll as i64 + row as i64).max(0) as usize, col)
    }

    /// A press at (x, y) in the text area: the cursor to the gap nearest
    /// it, and the selection from there unless it is to stretch (`keep`,
    /// Shift held).
    pub(crate) fn area_press(&mut self, id: Id, x: i32, y: i32, keep: bool) {
        let gap = self.area_gap_at(id, x, y);
        let w = &mut self.widgets[id];
        w.cursor = gap;
        if !keep {
            w.anchor = gap;
        }
        self.keep_area_cursor_shown(id);
    }

    /// Dragged to (x, y) with the button held after a press in the text
    /// area: the selection reaches the gap nearest it. The part of the
    /// window to show again.
    pub(crate) fn area_drag(&mut self, id: Id, x: i32, y: i32) -> Rect {
        let before = (self.widgets[id].cursor, self.widgets[id].scroll, self.widgets[id].hscroll);
        self.widgets[id].cursor = self.area_gap_at(id, x, y);
        self.keep_area_cursor_shown(id);
        let w = self.widgets[id];
        if (w.cursor, w.scroll, w.hscroll) == before { Rect::NONE } else { w.rect }
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
        let sel = w.selection().filter(|_| keyboard);
        for row in 0..rows {
            let n = w.scroll + row;
            if n >= self.area_lines() {
                break;
            }
            let ty = r.y + TOP + row as u32 * LINE_H + (LINE_H - th) / 2;
            let s0 = self.start_of_line(n);
            let line = &self.area_bytes()[s0..self.line_end(s0)];
            if let Some((a, b)) = sel {
                // The selected characters' cells behind them, and the
                // line's end's if its newline is selected.
                let e0 = s0 + line.len();
                let from = a.max(s0) - s0;
                let to = (b.min(e0 + 1)).max(s0) - s0;
                for k in from.max(w.hscroll)..to.min(w.hscroll + cols) {
                    let x = tx + (k - w.hscroll) as u32 * STEP - SCALE / 2;
                    s.fill(Rect { x, y: ty - 2, w: STEP, h: th + 4 }, SELECTION);
                }
            }
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

    fn shift_key(ui: &mut Ui, usage: u64, modifiers: u8) {
        ui.event(Event::us_key(225, true, modifiers));
        ui.event(Event::us_key(usage, true, modifiers));
        ui.event(Event::us_key(usage, false, modifiers));
        ui.event(Event::us_key(225, false, 0));
    }

    #[test]
    fn text_is_selected_copied_cut_and_pasted_across_lines() {
        use crate::{FIELD_INSET, STEP};
        let (mut ui, a) = notes();
        typ(&mut ui, "milk\neggs\nbread");
        // Shift-Up then Shift-Home from the end: "eggs\nbread" selected.
        shift_key(&mut ui, UP, 0x02);
        shift_key(&mut ui, HOME, 0x02);
        assert_eq!(ui.area_selection(), Some((5, 15)));
        // Copied, newlines kept.
        ui.event(Event::us_key(6, true, 0x01));
        assert_eq!(ui.clipboard(), "eggs\nbread");
        // Typing replaces it.
        typ(&mut ui, "x");
        assert_eq!((ui.area_text(), ui.area_selection()), ("milk\nx", None));
        // Pasted at the cursor: lines again.
        ui.event(Event::us_key(25, true, 0x01));
        assert_eq!((ui.area_text(), ui.area_cursor()), ("milk\nxeggs\nbread", (2, 5)));
        // Control-A and Control-X: all of it cut.
        ui.event(Event::us_key(4, true, 0x01));
        assert_eq!(ui.area_selection(), Some((0, 16)));
        ui.event(Event::us_key(27, true, 0x01));
        assert_eq!((ui.area_text(), ui.clipboard()), ("", "milk\nxeggs\nbread"));
        // A drag from the first line's gap 1 to the second line's gap 2
        // selects across the newline; Backspace takes it out.
        typ(&mut ui, "abc\ndef");
        let r = ui.widget(a).rect;
        let (x0, y0) = ((r.x + FIELD_INSET + STEP) as i32, (r.y + super::TOP + super::LINE_H / 2) as i32);
        let (x1, y1) = (x0 + STEP as i32, y0 + super::LINE_H as i32);
        ui.event(Event::Pointer { x: x0, y: y0, buttons: 1 });
        ui.event(Event::Pointer { x: x1, y: y1, buttons: 1 });
        ui.event(Event::Pointer { x: x1, y: y1, buttons: 0 });
        assert_eq!(ui.area_selection(), Some((1, 6)));
        key(&mut ui, BACKSPACE);
        assert_eq!((ui.area_text(), ui.area_cursor()), ("af", (0, 1)));
        // Shift with a press stretches the selection; Right without Shift
        // goes to its end.
        key(&mut ui, HOME);
        ui.event(Event::us_key(225, true, 0x02));
        ui.event(Event::Pointer { x: x1, y: y0, buttons: 1 });
        ui.event(Event::Pointer { x: x1, y: y0, buttons: 0 });
        ui.event(Event::us_key(225, false, 0));
        assert_eq!(ui.area_selection(), Some((0, 2)));
        key(&mut ui, RIGHT);
        assert_eq!((ui.area_selection(), ui.area_cursor()), (None, (0, 2)));
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
