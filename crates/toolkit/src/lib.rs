//! The Superior UI toolkit: what an app draws its window with.
//!
//! An app lays out widgets in a column or a row ([`Ui`]): labels, buttons,
//! text fields and lists. In a column, widgets may share a line
//! ([`Ui::begin_row`]); a field or list on one takes the width the others
//! leave, and follows the window's width when it is resized. The toolkit
//! draws them into the window's pixels ([`Surface`]), takes the events the
//! compositor gives the window ([`Event`]) and answers what they changed:
//! the part of the window to show again, the button clicked and the list
//! whose chosen item changed, if any.
//!
//! A button is clicked when pressed and let go over it. A field pressed
//! takes the keyboard, with its cursor where it was pressed, and keys
//! typed to it edit its text at the cursor (letters, digits, space and
//! some punctuation, Shift for capitals, Backspace and Delete; the arrows,
//! Home and End move the cursor; text wider than the field scrolls to keep
//! the cursor shown). Text is selected by dragging across it, Shift with
//! the arrows, Home or End (or a press), or Control-A for all of it;
//! typing replaces the selection, and Control-C, -X and -V copy, cut and
//! paste within the app. A list shows as many of its items as fit, one of
//! them chosen at most: a press chooses one and gives it the keyboard
//! (the arrows, Page Up and Down, Home and End choose another, scrolling
//! to show it); the wheel scrolls it, and its scroll bar pages it (pressed
//! above or below the thumb) or follows the thumb dragged.
//!
//! No heap: a `Ui` holds up to [`MAX_WIDGETS`], each text up to
//! [`MAX_TEXT`] bytes, and up to [`MAX_ITEMS`] items in all its lists.
//!
//! The host draws the same to check the screenshots of the toolkit test,
//! so drawing must not depend on anything but the widgets' state.

#![no_std]

pub mod font;

pub const MAX_WIDGETS: usize = 16;
pub const MAX_TEXT: usize = 32;
pub const MAX_ITEMS: usize = 48;

/// Text is drawn at twice the font's size.
pub const SCALE: u32 = 2;
/// Space around and between widgets.
pub const PAD: u32 = 8;
/// A label's height, and a button's or field's.
pub const LABEL_H: u32 = font::HEIGHT * SCALE + 2;
pub const BOX_H: u32 = font::HEIGHT * SCALE + 12;
/// Space between a button's text and its sides.
pub const BUTTON_SIDE: u32 = 12;
/// A list's rows' height; its scroll bar's width, and its thumb's least
/// height.
pub const ITEM_H: u32 = font::HEIGHT * SCALE + 6;
pub const BAR_W: u32 = 12;
pub const BAR_MIN: u32 = 16;

/// Colours (XRGB8888).
pub const BACKGROUND: u32 = 0x00e8_eaed;
pub const INK: u32 = 0x0020_2428;
pub const EDGE: u32 = 0x0080_8890;
pub const FOCUS_EDGE: u32 = 0x0035_6a9e;
pub const FACE: u32 = 0x00d0_d4da;
pub const FACE_HOVER: u32 = 0x00c0_c6ce;
pub const FACE_PRESSED: u32 = 0x0090_a0b0;
/// A selected button's face (the focused window's, on the desktop shell's
/// panel).
pub const FACE_SELECTED: u32 = 0x00a8_bcd4;
pub const FIELD: u32 = 0x00ff_ffff;
/// Selected text's cells, and a list's chosen row (with the keyboard, and
/// without).
pub const SELECTION: u32 = 0x00b4_d0f0;
pub const SELECTION_IDLE: u32 = 0x00d8_dce2;
/// A scroll bar's thumb.
pub const THUMB: u32 = 0x00a0_a8b2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub const NONE: Rect = Rect { x: 0, y: 0, w: 0, h: 0 };

    pub fn empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    pub fn contains(self, x: i32, y: i32) -> bool {
        x >= self.x as i32 && y >= self.y as i32 && x < (self.x + self.w) as i32 && y < (self.y + self.h) as i32
    }

    /// The smallest rectangle holding both.
    pub fn union(self, o: Rect) -> Rect {
        if self.empty() {
            return o;
        }
        if o.empty() {
            return self;
        }
        let (x0, y0) = (self.x.min(o.x), self.y.min(o.y));
        let (x1, y1) = ((self.x + self.w).max(o.x + o.w), (self.y + self.h).max(o.y + o.h));
        Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
    }
}

/// A window's pixels: `w` by `h`, rows `w` pixels apart.
pub struct Surface<'a> {
    pub px: &'a mut [u32],
    pub w: u32,
    pub h: u32,
}

impl Surface<'_> {
    /// Fills `r` (clipped to the surface) with `colour`.
    pub fn fill(&mut self, r: Rect, colour: u32) {
        let (x1, y1) = ((r.x + r.w).min(self.w), (r.y + r.h).min(self.h));
        for y in r.y..y1 {
            for x in r.x..x1 {
                self.px[(y * self.w + x) as usize] = colour;
            }
        }
    }

    /// A one-pixel outline of `r`.
    pub fn outline(&mut self, r: Rect, colour: u32) {
        if r.empty() {
            return;
        }
        self.fill(Rect { h: 1, ..r }, colour);
        self.fill(Rect { y: r.y + r.h - 1, h: 1, ..r }, colour);
        self.fill(Rect { w: 1, ..r }, colour);
        self.fill(Rect { x: r.x + r.w - 1, w: 1, ..r }, colour);
    }

    /// Draws `text` at `scale` with its top left at (x, y), clipped to the
    /// surface.
    pub fn text(&mut self, x: u32, y: u32, text: &[u8], scale: u32, colour: u32) {
        let (w, h) = (font::width(text, scale), font::HEIGHT * scale);
        for dy in 0..h.min(self.h.saturating_sub(y)) {
            for dx in 0..w.min(self.w.saturating_sub(x)) {
                if font::text_lit(text, scale, dx, dy) {
                    self.px[((y + dy) * self.w + x + dx) as usize] = colour;
                }
            }
        }
    }
}

/// Up to [`MAX_TEXT`] bytes of text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text {
    bytes: [u8; MAX_TEXT],
    len: usize,
}

impl Text {
    pub const EMPTY: Text = Text { bytes: [0; MAX_TEXT], len: 0 };

    /// `s`, cut at `MAX_TEXT` bytes.
    pub fn new(s: &[u8]) -> Text {
        let mut t = Text::EMPTY;
        for &b in s {
            t.push(b);
        }
        t
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("?")
    }

    /// Adds `b`; false if full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len == MAX_TEXT {
            return false;
        }
        self.bytes[self.len] = b;
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        true
    }

    /// Puts `b` before byte `at` (at most the length); false if full.
    pub fn insert(&mut self, at: usize, b: u8) -> bool {
        if self.len == MAX_TEXT || at > self.len {
            return false;
        }
        self.bytes.copy_within(at..self.len, at + 1);
        self.bytes[at] = b;
        self.len += 1;
        true
    }

    /// Takes out byte `at`; false if there is none.
    pub fn remove(&mut self, at: usize) -> bool {
        if at >= self.len {
            return false;
        }
        self.bytes.copy_within(at + 1..self.len, at);
        self.len -= 1;
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Label,
    Button,
    Field,
    /// Items in rows, one of them chosen at most, scrolled to show as many
    /// as fit.
    List,
}

/// A list's chosen item when none is.
pub const NO_ITEM: usize = usize::MAX;

#[derive(Clone, Copy)]
pub struct Widget {
    pub kind: Kind,
    pub rect: Rect,
    pub text: Text,
    /// A button drawn as chosen.
    pub selected: bool,
    /// A field's cursor: the byte of its text it is before. A list's
    /// chosen item ([`NO_ITEM`] if none).
    pub cursor: usize,
    /// The other end of a field's selection: the cursor's own place when
    /// nothing is selected.
    pub anchor: usize,
    /// A field's first character shown, when its text is wider than it; a
    /// list's first item shown.
    pub scroll: usize,
    /// A list's items: where the first is in its `Ui`'s, and how many.
    first: usize,
    count: usize,
    /// The first widget on its line, and whether it takes the width the
    /// others on its line leave.
    line: Id,
    stretch: bool,
}

impl Widget {
    /// How many characters a field shows (with room for the cursor after
    /// the last); how many items a list does.
    pub fn shown(&self) -> usize {
        match self.kind {
            Kind::List => (self.rect.h.saturating_sub(2) / ITEM_H) as usize,
            _ => (self.rect.w.saturating_sub(FIELD_INSET + 1) / STEP) as usize,
        }
    }

    /// A field's selection, if any: from the first byte selected to the
    /// byte after the last.
    pub fn selection(&self) -> Option<(usize, usize)> {
        (self.kind == Kind::Field && self.anchor != self.cursor)
            .then(|| (self.anchor.min(self.cursor), self.anchor.max(self.cursor)))
    }

    /// Scrolls a field as little as keeps its cursor shown, and as much of
    /// its text as fits; a list as little as keeps its chosen item shown,
    /// and as many items as fit.
    fn keep_cursor_shown(&mut self) {
        let n = self.shown();
        if self.kind == Kind::List {
            if self.cursor != NO_ITEM {
                if self.cursor < self.scroll {
                    self.scroll = self.cursor;
                } else if self.cursor >= self.scroll + n.max(1) {
                    self.scroll = self.cursor + 1 - n.max(1);
                }
            }
            self.scroll = self.scroll.min(self.count.saturating_sub(n));
            return;
        }
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor > self.scroll + n {
            self.scroll = self.cursor - n;
        }
        self.scroll = self.scroll.min(self.text.len().saturating_sub(n));
    }

    /// Takes a field's selection out of its text: whether there was one.
    fn cut(&mut self) -> bool {
        let Some((a, b)) = self.selection() else { return false };
        for _ in a..b {
            self.text.remove(a);
        }
        (self.cursor, self.anchor) = (a, a);
        true
    }

    /// Whether a list has more items than it shows, and so a scroll bar.
    fn has_bar(&self) -> bool {
        self.kind == Kind::List && self.count > self.shown()
    }

    /// A list's scroll bar, inside its right edge.
    fn bar(&self) -> Rect {
        let r = self.rect;
        Rect { x: r.x + r.w - 1 - BAR_W, y: r.y + 1, w: BAR_W, h: r.h.saturating_sub(2) }
    }

    /// The thumb on a list's scroll bar: as tall as the share of its items
    /// shown, as far down as it is scrolled.
    fn thumb(&self) -> Rect {
        let b = self.bar();
        let (n, c) = (self.shown() as u32, self.count.max(1) as u32);
        let h = (b.h * n / c).max(BAR_MIN).min(b.h);
        let travel = b.h - h;
        let over = c.saturating_sub(n).max(1);
        Rect { y: b.y + travel * self.scroll as u32 / over, h, ..b }
    }

    /// Where a list's rows are drawn: inside its edge, left of its bar.
    fn rows(&self) -> Rect {
        let r = self.rect;
        let bar = if self.has_bar() { BAR_W } else { 0 };
        Rect { x: r.x + 1, y: r.y + 1, w: r.w.saturating_sub(2 + bar), h: self.shown() as u32 * ITEM_H }
    }
}

/// A widget's number in its [`Ui`], in the order added.
pub type Id = usize;

/// An event from the compositor, in the window's pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The pointer is at (x, y) with these buttons held (bit 0 the left).
    Pointer { x: i32, y: i32, buttons: u64 },
    /// The wheel turned `up` steps (down if negative) with the pointer at
    /// (x, y).
    Wheel { x: i32, y: i32, up: i32 },
    /// The pointer left the window.
    Leave,
    /// A key (its USB HID usage) went down or up, with the modifier byte.
    Key { usage: u64, down: bool, modifiers: u8 },
    /// The window got or lost the keyboard focus.
    Focus(bool),
}

/// What an event changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Response {
    /// The part of the window to draw and show again.
    pub damage: Rect,
    /// The button clicked.
    pub clicked: Option<Id>,
    /// The field (or list) Enter was pressed in.
    pub entered: Option<Id>,
    /// The list whose chosen item changed.
    pub picked: Option<Id>,
}

/// The character a key types, if it types one: `usage` is its USB HID
/// usage, `modifiers` the modifier byte (Shift is bit 1 or bit 5).
pub fn character(usage: u64, modifiers: u8) -> Option<u8> {
    let shift = modifiers & SHIFT != 0;
    Some(match usage {
        4..=29 => (if shift { b'A' } else { b'a' }) + (usage - 4) as u8,
        30..=38 if !shift => b'1' + (usage - 30) as u8,
        39 if !shift => b'0',
        30 => b'!',
        31 => b'@',
        44 => b' ',
        45 => if shift { b'_' } else { b'-' },
        46 => if shift { b'+' } else { b'=' },
        51 => if shift { b':' } else { b';' },
        52 => if shift { b'"' } else { b'\'' },
        54 => if shift { b'<' } else { b',' },
        55 => if shift { b'>' } else { b'.' },
        56 => if shift { b'?' } else { b'/' },
        _ => return None,
    })
}

/// The modifier byte's Shift and Control bits (left or right).
const SHIFT: u8 = 0x22;
const CONTROL: u8 = 0x11;

const BACKSPACE: u64 = 42;
const ENTER: u64 = 40;
const DELETE: u64 = 76;
const HOME: u64 = 74;
const END: u64 = 77;
const RIGHT: u64 = 79;
const LEFT: u64 = 80;
const DOWN: u64 = 81;
const UP: u64 = 82;
const PAGE_UP: u64 = 75;
const PAGE_DOWN: u64 = 78;
/// With Control: select all, copy, paste, cut.
const KEY_A: u64 = 4;
const KEY_C: u64 = 6;
const KEY_V: u64 = 25;
const KEY_X: u64 = 27;

/// How far apart characters are drawn in a field.
const STEP: u32 = font::ADVANCE * SCALE;
/// Where a field's text starts, from its left edge.
const FIELD_INSET: u32 = 6;

/// Widgets laid out in a column (or a row) on a window `w` by `h`, and
/// their state.
pub struct Ui {
    pub w: u32,
    pub h: u32,
    widgets: [Widget; MAX_WIDGETS],
    len: usize,
    /// The lists' items, each list's in a run of their own.
    items: [Text; MAX_ITEMS],
    nitems: usize,
    /// Laid out left to right, each centred on the window's height.
    row: bool,
    /// In a column, a line begun ([`Ui::begin_row`]): its first widget and
    /// its top.
    line: Option<(Id, u32)>,
    /// Where the next widget goes.
    next_y: u32,
    next_x: u32,
    /// The field (or list) with the keyboard, the button under the
    /// pointer, the one pressed (held until the buttons are let go), and
    /// whether the window has the focus.
    field: Option<Id>,
    hover: Option<Id>,
    pressed: Option<Id>,
    focused: bool,
    buttons: u64,
    /// The modifier byte of the last key.
    modifiers: u8,
    /// A list whose thumb is dragged, and where on the thumb it was taken;
    /// whether the pointer is selecting in the field with the keyboard.
    dragging: Option<(Id, i32)>,
    selecting: bool,
    /// What was last copied or cut.
    clipboard: Text,
}

impl Ui {
    /// A column, top to bottom.
    pub fn new(w: u32, h: u32) -> Ui {
        let none = Widget {
            kind: Kind::Label,
            rect: Rect::NONE,
            text: Text::EMPTY,
            selected: false,
            cursor: 0,
            anchor: 0,
            scroll: 0,
            first: 0,
            count: 0,
            line: 0,
            stretch: false,
        };
        Ui {
            w,
            h,
            widgets: [none; MAX_WIDGETS],
            len: 0,
            items: [Text::EMPTY; MAX_ITEMS],
            nitems: 0,
            row: false,
            line: None,
            next_y: PAD,
            next_x: PAD,
            field: None,
            hover: None,
            pressed: None,
            focused: false,
            buttons: 0,
            modifiers: 0,
            dragging: None,
            selecting: false,
            clipboard: Text::EMPTY,
        }
    }

    /// A row, left to right.
    pub fn row(w: u32, h: u32) -> Ui {
        Ui { row: true, ..Ui::new(w, h) }
    }

    /// Takes every widget away, to lay out anew (state tied to them goes:
    /// the field with the keyboard, the button under the pointer or
    /// pressed, the lists' items).
    pub fn clear(&mut self) {
        (self.len, self.nitems, self.line) = (0, 0, None);
        (self.next_x, self.next_y) = (PAD, PAD);
        (self.field, self.hover, self.pressed) = (None, None, None);
        (self.dragging, self.selecting) = (None, false);
    }

    /// In a column, the widgets added until [`Ui::end_row`] go on one line,
    /// left to right, centred on its height. A field or list on it takes
    /// the width the others leave (shared, if there are more), as does a
    /// label made to ([`Ui::stretch`]).
    pub fn begin_row(&mut self) {
        assert!(!self.row && self.line.is_none(), "a line begun in a row, or in a line");
        self.line = Some((self.len, self.next_y));
    }

    /// Ends the line begun: the next widget goes below it.
    pub fn end_row(&mut self) {
        let Some((start, y)) = self.line.take() else { return };
        let lh = self.widgets[start..self.len].iter().map(|w| w.rect.h).max().unwrap_or(0);
        for w in &mut self.widgets[start..self.len] {
            w.rect.y = y + (lh - w.rect.h) / 2;
        }
        self.next_y = y + lh + PAD;
        if start < self.len {
            self.lay_line(start);
        }
    }

    /// Widget `id` takes the width the others on its line leave.
    pub fn stretch(&mut self, id: Id) {
        self.widgets[id].stretch = true;
        if !self.row {
            self.lay_line(self.widgets[id].line);
        }
    }

    /// In a row, moves widget `id` to the window's right end (it must be
    /// the last laid out, or it may cover others).
    pub fn push_right(&mut self, id: Id) {
        let r = &mut self.widgets[id].rect;
        r.x = self.w.saturating_sub(PAD + r.w);
    }

    /// Lays out across the window the line that starts with `start`: the
    /// widgets left to right, those that stretch sharing what the others
    /// leave.
    fn lay_line(&mut self, start: Id) {
        let end = (start + 1..self.len).find(|&k| self.widgets[k].line != start).unwrap_or(self.len);
        let line = &mut self.widgets[start..end];
        let fixed: u32 = line.iter().filter(|w| !w.stretch).map(|w| w.rect.w).sum();
        let stretchers = line.iter().filter(|w| w.stretch).count() as u32;
        let gaps = PAD * (line.len() as u32 - 1);
        let share = self.w.saturating_sub(2 * PAD + fixed + gaps) / stretchers.max(1);
        let mut x = PAD;
        for w in line {
            if w.stretch {
                w.rect.w = share;
            }
            w.rect.x = x;
            x += w.rect.w + PAD;
            w.keep_cursor_shown();
        }
    }

    fn add(&mut self, kind: Kind, w: u32, h: u32, text: &[u8]) -> Id {
        assert!(self.len < MAX_WIDGETS, "too many widgets");
        let id = self.len;
        let (rect, line, stretch) = if self.row {
            let r = Rect { x: self.next_x, y: self.h.saturating_sub(h) / 2, w, h };
            self.next_x += w + PAD;
            (r, id, false)
        } else if let Some((start, y)) = self.line {
            (Rect { x: 0, y, w, h }, start, matches!(kind, Kind::Field | Kind::List))
        } else {
            let r = Rect { x: PAD, y: self.next_y, w, h };
            self.next_y += h + PAD;
            (r, id, kind != Kind::Button)
        };
        let text = Text::new(text);
        let cursor = if kind == Kind::List { NO_ITEM } else { text.len() };
        self.widgets[id] = Widget {
            kind,
            rect,
            text,
            selected: false,
            cursor,
            anchor: cursor,
            scroll: 0,
            first: self.nitems,
            count: 0,
            line,
            stretch,
        };
        self.len += 1;
        if !self.row {
            self.lay_line(line);
        }
        id
    }

    /// The window is now `w` by `h`: in a column, the widgets that stretch
    /// take its new width (a row stays as it is laid out). Draw it all
    /// again.
    pub fn resize(&mut self, w: u32, h: u32) {
        (self.w, self.h) = (w, h);
        if self.row {
            return;
        }
        for id in 0..self.len {
            if self.widgets[id].line == id {
                self.lay_line(id);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The width a widget of its own width is given in a column: the
    /// window's, but on a line (where it is laid out), none yet.
    fn column_width(&self) -> u32 {
        if self.line.is_some() { 0 } else { self.w - 2 * PAD }
    }

    /// A line of text: the window's width in a column, its own in a row
    /// or on a line.
    pub fn label(&mut self, text: &str) -> Id {
        let w = if self.row || self.line.is_some() { font::width(text.as_bytes(), SCALE) } else { self.w - 2 * PAD };
        self.add(Kind::Label, w, LABEL_H, text.as_bytes())
    }

    /// Draws button `id` as chosen, or not: the part of the window to show
    /// again.
    pub fn select(&mut self, id: Id, selected: bool) -> Rect {
        if self.widgets[id].selected == selected {
            return Rect::NONE;
        }
        self.widgets[id].selected = selected;
        self.widgets[id].rect
    }

    /// A button as wide as its text.
    pub fn button(&mut self, text: &str) -> Id {
        let w = font::width(text.as_bytes(), SCALE) + 2 * BUTTON_SIDE;
        self.add(Kind::Button, w, BOX_H, text.as_bytes())
    }

    /// An empty text field, the window's width (on a line, what the others
    /// leave).
    pub fn field(&mut self) -> Id {
        let w = self.column_width();
        self.add(Kind::Field, w, BOX_H, b"")
    }

    /// An empty list showing `rows` items, as wide as a field.
    pub fn list(&mut self, rows: u32) -> Id {
        let w = self.column_width();
        self.add(Kind::List, w, rows * ITEM_H + 2, b"")
    }

    pub fn widget(&self, id: Id) -> &Widget {
        &self.widgets[id]
    }

    pub fn text(&self, id: Id) -> &str {
        self.widgets[id].text.as_str()
    }

    /// A field's cursor: the byte of its text it is before.
    pub fn cursor(&self, id: Id) -> usize {
        self.widgets[id].cursor
    }

    /// A field's selection, if any (see [`Widget::selection`]).
    pub fn selection(&self, id: Id) -> Option<(usize, usize)> {
        self.widgets[id].selection()
    }

    /// What was last copied or cut from a field.
    pub fn clipboard(&self) -> &str {
        self.clipboard.as_str()
    }

    /// Sets widget `id`'s text: the part of the window to show again. A
    /// field's cursor goes to its end, nothing selected.
    pub fn set_text(&mut self, id: Id, text: &str) -> Rect {
        let t = Text::new(text.as_bytes());
        if self.widgets[id].text == t {
            return Rect::NONE;
        }
        let w = &mut self.widgets[id];
        w.text = t;
        (w.cursor, w.anchor) = (t.len(), t.len());
        w.keep_cursor_shown();
        w.rect
    }

    /// Adds an item at the end of list `id` (none past [`MAX_ITEMS`] in
    /// all): the part of the window to show again.
    pub fn push_item(&mut self, id: Id, text: &str) -> Rect {
        if self.nitems == MAX_ITEMS || self.widgets[id].kind != Kind::List {
            return Rect::NONE;
        }
        let at = self.widgets[id].first + self.widgets[id].count;
        self.items.copy_within(at..self.nitems, at + 1);
        self.items[at] = Text::new(text.as_bytes());
        self.nitems += 1;
        for (k, w) in self.widgets[..self.len].iter_mut().enumerate() {
            if k != id && w.kind == Kind::List && w.first >= at {
                w.first += 1;
            }
        }
        let w = &mut self.widgets[id];
        w.count += 1;
        w.rect
    }

    /// Takes item `k` out of list `id`; the chosen one, if it was, becomes
    /// the item after it (or before, if it was the last). The part of the
    /// window to show again.
    pub fn remove_item(&mut self, id: Id, k: usize) -> Rect {
        let Widget { first, count, .. } = self.widgets[id];
        if k >= count {
            return Rect::NONE;
        }
        let at = first + k;
        self.items.copy_within(at + 1..self.nitems, at);
        self.nitems -= 1;
        for (j, w) in self.widgets[..self.len].iter_mut().enumerate() {
            if j != id && w.kind == Kind::List && w.first > at {
                w.first -= 1;
            }
        }
        let w = &mut self.widgets[id];
        w.count -= 1;
        if w.cursor != NO_ITEM && (w.cursor > k || w.cursor == w.count) {
            w.cursor = w.cursor.checked_sub(1).filter(|_| w.count > 0).unwrap_or(NO_ITEM);
        }
        w.keep_cursor_shown();
        w.rect
    }

    /// How many items list `id` has.
    pub fn items(&self, id: Id) -> usize {
        self.widgets[id].count
    }

    /// Item `k` of list `id`.
    pub fn item(&self, id: Id, k: usize) -> &str {
        let w = &self.widgets[id];
        if k < w.count { self.items[w.first + k].as_str() } else { "" }
    }

    /// List `id`'s chosen item, if any.
    pub fn chosen(&self, id: Id) -> Option<usize> {
        let c = self.widgets[id].cursor;
        (self.widgets[id].kind == Kind::List && c != NO_ITEM).then_some(c)
    }

    /// Chooses item `k` of list `id` (or none), scrolling to show it: the
    /// part of the window to show again.
    pub fn choose(&mut self, id: Id, k: Option<usize>) -> Rect {
        let w = &mut self.widgets[id];
        let to = k.filter(|&k| k < w.count).unwrap_or(NO_ITEM);
        let before = (w.cursor, w.scroll);
        w.cursor = to;
        w.keep_cursor_shown();
        if (w.cursor, w.scroll) == before { Rect::NONE } else { w.rect }
    }

    /// The field (or list) with the keyboard, if any.
    pub fn keyboard(&self) -> Option<Id> {
        self.field.filter(|_| self.focused)
    }

    fn whole(&self) -> Rect {
        Rect { x: 0, y: 0, w: self.w, h: self.h }
    }

    /// Draws the whole window.
    pub fn draw(&self, s: &mut Surface) {
        s.fill(self.whole(), BACKGROUND);
        for id in 0..self.len {
            self.draw_widget(s, id);
        }
    }

    fn draw_widget(&self, s: &mut Surface, id: Id) {
        let w = self.widgets[id];
        let Widget { kind, rect: r, text, selected, cursor, scroll, .. } = w;
        let t = text.as_bytes();
        let th = font::HEIGHT * SCALE;
        let keyboard = self.keyboard() == Some(id);
        match kind {
            Kind::Label => {
                s.fill(r, BACKGROUND);
                let fits = (r.w / STEP + 1) as usize;
                s.text(r.x, r.y + 1, &t[..t.len().min(fits)], SCALE, INK);
            }
            Kind::Button => {
                let face = if self.pressed == Some(id) && self.hover == Some(id) {
                    FACE_PRESSED
                } else if selected {
                    FACE_SELECTED
                } else if self.hover == Some(id) {
                    FACE_HOVER
                } else {
                    FACE
                };
                s.fill(r, face);
                s.outline(r, EDGE);
                let tw = font::width(t, SCALE);
                s.text(r.x + (r.w - tw.min(r.w)) / 2, r.y + (r.h - th) / 2, t, SCALE, INK);
            }
            Kind::Field => {
                s.fill(r, FIELD);
                s.outline(r, if keyboard { FOCUS_EDGE } else { EDGE });
                let (tx, ty) = (r.x + FIELD_INSET, r.y + (r.h - th) / 2);
                let n = w.shown();
                if let Some((a, b)) = w.selection().filter(|_| keyboard) {
                    // The selected characters' cells, behind them.
                    for k in a.max(scroll)..b.min(scroll + n) {
                        let x = tx + (k - scroll) as u32 * STEP - SCALE / 2;
                        s.fill(Rect { x, y: ty - 2, w: STEP, h: th + 4 }, SELECTION);
                    }
                }
                let shown = &t[scroll.min(t.len())..(scroll + n).min(t.len())];
                s.text(tx, ty, shown, SCALE, INK);
                if keyboard {
                    // The cursor, in the gap before the character it is
                    // before (or after the last one).
                    let cx = tx + (cursor - scroll) as u32 * STEP - SCALE;
                    s.fill(Rect { x: cx, y: ty - 1, w: SCALE, h: th + 2 }, INK);
                }
            }
            Kind::List => {
                s.fill(r, FIELD);
                s.outline(r, if keyboard { FOCUS_EDGE } else { EDGE });
                let rows = w.rows();
                let fits = (rows.w.saturating_sub(FIELD_INSET) / STEP) as usize;
                for row in 0..w.shown() {
                    let k = scroll + row;
                    if k >= w.count {
                        break;
                    }
                    let y = rows.y + row as u32 * ITEM_H;
                    if k == cursor {
                        let colour = if keyboard { SELECTION } else { SELECTION_IDLE };
                        s.fill(Rect { y, h: ITEM_H, ..rows }, colour);
                    }
                    let item = self.items[w.first + k].as_bytes();
                    s.text(rows.x + FIELD_INSET, y + (ITEM_H - th) / 2, &item[..item.len().min(fits)], SCALE, INK);
                }
                if w.has_bar() {
                    s.fill(w.bar(), FACE);
                    let thumb = w.thumb();
                    s.fill(thumb, THUMB);
                    s.outline(thumb, EDGE);
                }
            }
        }
    }

    /// Draws the part `r` of the window: every widget it touches (whole),
    /// over the background. The part drawn.
    pub fn draw_part(&self, s: &mut Surface, r: Rect) -> Rect {
        s.fill(r, BACKGROUND);
        let mut drawn = r;
        for id in 0..self.len {
            if overlaps(self.widgets[id].rect, r) {
                self.draw_widget(s, id);
                drawn = drawn.union(self.widgets[id].rect);
            }
        }
        drawn
    }

    /// The widget at (x, y), if any.
    fn at(&self, x: i32, y: i32) -> Option<Id> {
        (0..self.len).find(|&id| self.widgets[id].rect.contains(x, y))
    }

    fn rect(&self, id: Option<Id>) -> Rect {
        id.map_or(Rect::NONE, |id| self.widgets[id].rect)
    }

    /// The gap in field `f`'s text nearest `x`.
    fn gap_at(&self, f: Id, x: i32) -> usize {
        let w = &self.widgets[f];
        let from = x - (w.rect.x + FIELD_INSET) as i32 + STEP as i32 / 2;
        (w.scroll + (from.max(0) as u32 / STEP) as usize).min(w.text.len())
    }

    /// Scrolls list `id` by `by` items (back if negative), as far as it
    /// goes: the part of the window to show again.
    fn scroll_list(&mut self, id: Id, by: i64) -> Rect {
        let w = &mut self.widgets[id];
        let most = w.count.saturating_sub(w.shown());
        let to = (w.scroll as i64 + by).clamp(0, most as i64) as usize;
        if to == w.scroll {
            return Rect::NONE;
        }
        w.scroll = to;
        w.rect
    }

    /// Takes an event: what it changed.
    pub fn event(&mut self, e: Event) -> Response {
        let mut r = Response::default();
        match e {
            Event::Pointer { x, y, buttons } => self.pointer(x, y, buttons, &mut r),
            Event::Wheel { x, y, up } => {
                if let Some(l) = self.at(x, y).filter(|&id| self.widgets[id].kind == Kind::List) {
                    r.damage = self.scroll_list(l, -(up as i64));
                }
            }
            Event::Leave => {
                r.damage = self.rect(self.hover);
                self.hover = None;
            }
            Event::Focus(f) => {
                if f != self.focused {
                    self.focused = f;
                    r.damage = self.rect(self.field);
                }
            }
            Event::Key { usage, down, modifiers } => {
                self.modifiers = modifiers;
                match self.keyboard() {
                    Some(id) if down && self.widgets[id].kind == Kind::Field => self.field_key(id, usage, modifiers, &mut r),
                    Some(id) if down && self.widgets[id].kind == Kind::List => self.list_key(id, usage, &mut r),
                    _ => {}
                }
            }
        }
        r
    }

    fn pointer(&mut self, x: i32, y: i32, buttons: u64, r: &mut Response) {
        let under = self.at(x, y);
        let button = under.filter(|&id| self.widgets[id].kind == Kind::Button);
        if button != self.hover {
            r.damage = r.damage.union(self.rect(self.hover)).union(self.rect(button));
            self.hover = button;
        }
        let pressed_now = buttons & 1 != 0 && self.buttons & 1 == 0;
        let let_go = buttons & 1 == 0 && self.buttons & 1 != 0;
        self.buttons = buttons;
        if pressed_now {
            self.pressed = button;
            r.damage = r.damage.union(self.rect(button));
            let kind = under.map(|id| self.widgets[id].kind);
            if let (Some(id), Some(Kind::Field | Kind::List)) = (under, kind) {
                // It takes the keyboard.
                if self.field != Some(id) {
                    r.damage = r.damage.union(self.rect(self.field)).union(self.rect(Some(id)));
                }
                let was = self.field.replace(id);
                let w = self.widgets[id];
                if kind == Some(Kind::Field) {
                    // The cursor goes to the gap nearest the press; with
                    // Shift, in a field that had the keyboard, the
                    // selection reaches there.
                    let gap = self.gap_at(id, x);
                    let keep = self.modifiers & SHIFT != 0 && was == Some(id);
                    let f = &mut self.widgets[id];
                    f.cursor = gap;
                    if !keep {
                        f.anchor = gap;
                    }
                    f.keep_cursor_shown();
                    self.selecting = true;
                } else if w.has_bar() && w.bar().contains(x, y) {
                    // On the bar: the thumb is taken, or the list goes a
                    // page up or down.
                    let thumb = w.thumb();
                    if thumb.contains(x, y) {
                        self.dragging = Some((id, y - thumb.y as i32));
                    } else {
                        let page = w.shown() as i64;
                        let by = if y < thumb.y as i32 { -page } else { page };
                        r.damage = r.damage.union(self.scroll_list(id, by));
                    }
                } else {
                    let row = ((y - w.rows().y as i32).max(0) as u32 / ITEM_H) as usize;
                    if w.scroll + row < w.count && w.scroll + row != w.cursor {
                        r.damage = r.damage.union(self.choose(id, Some(w.scroll + row)));
                        r.picked = Some(id);
                    }
                }
                let after = self.widgets[id];
                if (after.cursor, after.anchor, after.scroll) != (w.cursor, w.anchor, w.scroll) {
                    r.damage = r.damage.union(after.rect);
                }
            }
        } else if buttons & 1 != 0 {
            if let Some((l, off)) = self.dragging {
                // The thumb follows the pointer.
                let w = self.widgets[l];
                let (bar, thumb) = (w.bar(), w.thumb());
                let travel = (bar.h - thumb.h) as i64;
                let over = w.count.saturating_sub(w.shown()) as i64;
                if travel > 0 {
                    let at = (y as i64 - off as i64 - bar.y as i64).clamp(0, travel);
                    let to = (at * over + travel / 2) / travel;
                    r.damage = r.damage.union(self.scroll_list(l, to - w.scroll as i64));
                }
            } else if let Some(f) = self.field.filter(|_| self.selecting) {
                // Dragged across the field: the selection follows.
                let gap = self.gap_at(f, x);
                let w = &mut self.widgets[f];
                let before = (w.cursor, w.scroll);
                w.cursor = gap;
                w.keep_cursor_shown();
                if (w.cursor, w.scroll) != before {
                    r.damage = r.damage.union(w.rect);
                }
            }
        }
        if let_go {
            (self.dragging, self.selecting) = (None, false);
            if let Some(p) = self.pressed.take() {
                r.damage = r.damage.union(self.rect(Some(p)));
                if button == Some(p) {
                    r.clicked = Some(p);
                }
            }
        }
    }

    /// A key down for field `id`.
    fn field_key(&mut self, id: Id, usage: u64, modifiers: u8, r: &mut Response) {
        let (shift, control) = (modifiers & SHIFT != 0, modifiers & CONTROL != 0);
        let mut w = self.widgets[id];
        let before = (w.text, w.cursor, w.anchor, w.scroll);
        let sel = w.selection();
        let len = w.text.len();
        match usage {
            LEFT | RIGHT | HOME | END => {
                // Moved, or with Shift the selection stretched; moved off a
                // selection, the cursor goes to its end that way.
                let to = match (usage, sel.filter(|_| !shift)) {
                    (LEFT, Some((a, _))) => a,
                    (RIGHT, Some((_, b))) => b,
                    (LEFT, None) => w.cursor.saturating_sub(1),
                    (RIGHT, None) => (w.cursor + 1).min(len),
                    (HOME, _) => 0,
                    _ => len,
                };
                w.cursor = to;
                if !shift {
                    w.anchor = to;
                }
            }
            KEY_A if control => (w.anchor, w.cursor) = (0, len),
            KEY_C | KEY_X if control => {
                if let Some((a, b)) = sel {
                    self.clipboard = Text::new(&w.text.as_bytes()[a..b]);
                    if usage == KEY_X {
                        w.cut();
                    }
                }
            }
            KEY_V if control => {
                w.cut();
                for &c in self.clipboard.as_bytes() {
                    if !w.text.insert(w.cursor, c) {
                        break;
                    }
                    w.cursor += 1;
                }
                w.anchor = w.cursor;
            }
            BACKSPACE => {
                if !w.cut() && w.cursor > 0 && w.text.remove(w.cursor - 1) {
                    w.cursor -= 1;
                }
                w.anchor = w.cursor;
            }
            DELETE => {
                if !w.cut() {
                    w.text.remove(w.cursor);
                }
            }
            ENTER => r.entered = Some(id),
            _ if !control => {
                if let Some(c) = character(usage, modifiers) {
                    w.cut();
                    if w.text.insert(w.cursor, c) {
                        w.cursor += 1;
                    }
                    w.anchor = w.cursor;
                }
            }
            _ => {}
        }
        w.keep_cursor_shown();
        self.widgets[id] = w;
        if (w.text, w.cursor, w.anchor, w.scroll) != before {
            r.damage = w.rect;
        }
    }

    /// A key down for list `id`: the arrows, Page Up and Down, Home and
    /// End choose another item; Enter.
    fn list_key(&mut self, id: Id, usage: u64, r: &mut Response) {
        let w = self.widgets[id];
        if usage == ENTER {
            r.entered = Some(id);
            return;
        }
        if w.count == 0 {
            return;
        }
        let (last, page) = (w.count - 1, w.shown().max(1));
        let cur = self.chosen(id);
        let to = match (usage, cur) {
            (DOWN | UP | PAGE_DOWN | PAGE_UP, None) => 0,
            (DOWN, Some(c)) => (c + 1).min(last),
            (UP, Some(c)) => c.saturating_sub(1),
            (PAGE_DOWN, Some(c)) => (c + page).min(last),
            (PAGE_UP, Some(c)) => c.saturating_sub(page),
            (HOME, _) => 0,
            (END, _) => last,
            _ => return,
        };
        r.damage = self.choose(id, Some(to));
        if cur != Some(to) {
            r.picked = Some(id);
        }
    }
}

fn overlaps(a: Rect, b: Rect) -> bool {
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEFT_BUTTON: u64 = 1;

    fn greeter() -> (Ui, Id, Id, Id) {
        let mut ui = Ui::new(280, 124);
        ui.label("Your name:");
        let field = ui.field();
        let button = ui.button("Greet");
        let out = ui.label("");
        (ui, field, button, out)
    }

    fn press(ui: &mut Ui, x: i32, y: i32) -> Response {
        ui.event(Event::Pointer { x, y, buttons: 0 });
        ui.event(Event::Pointer { x, y, buttons: LEFT_BUTTON });
        ui.event(Event::Pointer { x, y, buttons: 0 })
    }

    fn key(ui: &mut Ui, usage: u64, modifiers: u8) -> Response {
        let r = ui.event(Event::Key { usage, down: true, modifiers });
        ui.event(Event::Key { usage, down: false, modifiers });
        r
    }

    #[test]
    fn the_font_covers_printable_ascii() {
        assert_eq!(font::glyph(b'A'), &[0x0e, 0x11, 0x11, 0x11, 0x1f, 0x11, 0x11]);
        assert_eq!(font::glyph(0x7f), font::glyph(b'?'));
        assert!(font::lit(b'I', 2, 3) && !font::lit(b'I', 0, 3) && !font::lit(b'I', 5, 3));
        assert_eq!(font::width(b"Greet", 2), 58);
        assert_eq!(font::width(b"", 2), 0);
        // Every glyph but the space marks something, in its 5 columns.
        for c in 33..=126u8 {
            let g = font::glyph(c);
            assert!(g.iter().any(|&r| r != 0) && g.iter().all(|&r| r < 0x20), "glyph {}", c as char);
        }
    }

    #[test]
    fn widgets_go_down_a_column() {
        let (ui, field, button, out) = greeter();
        assert_eq!(ui.widget(0).rect, Rect { x: 8, y: 8, w: 264, h: 16 });
        assert_eq!(ui.widget(field).rect, Rect { x: 8, y: 32, w: 264, h: 26 });
        assert_eq!(ui.widget(button).rect, Rect { x: 8, y: 66, w: 82, h: 26 });
        assert_eq!(ui.widget(out).rect, Rect { x: 8, y: 100, w: 264, h: 16 });
    }

    #[test]
    fn a_click_is_a_press_and_a_release_on_the_button() {
        let (mut ui, _, button, _) = greeter();
        assert_eq!(press(&mut ui, 40, 70).clicked, Some(button));
        // Pressed on it, let go off it: no click.
        ui.event(Event::Pointer { x: 40, y: 70, buttons: LEFT_BUTTON });
        assert_eq!(ui.event(Event::Pointer { x: 200, y: 70, buttons: 0 }).clicked, None);
        // Pressed off it, let go on it: no click.
        ui.event(Event::Pointer { x: 200, y: 70, buttons: LEFT_BUTTON });
        assert_eq!(ui.event(Event::Pointer { x: 40, y: 70, buttons: 0 }).clicked, None);
    }

    #[test]
    fn a_field_takes_keys_once_pressed_and_focused() {
        let (mut ui, field, _, _) = greeter();
        key(&mut ui, 4, 0);
        assert_eq!(ui.text(field), "", "no field has the keyboard yet");
        press(&mut ui, 100, 40);
        key(&mut ui, 4, 0);
        assert_eq!(ui.text(field), "", "the window does not have the focus");
        ui.event(Event::Focus(true));
        let r = key(&mut ui, 4, 0x02);
        assert_eq!(r.damage, ui.widget(field).rect);
        for (u, m) in [(7, 0), (4, 0), (44, 0), (30, 0), (39, 0), (30, 0x20)] {
            key(&mut ui, u, m);
        }
        assert_eq!(ui.text(field), "Ada 10!");
        key(&mut ui, BACKSPACE, 0);
        assert_eq!(ui.text(field), "Ada 10");
        assert_eq!(key(&mut ui, ENTER, 0).entered, Some(field));
        ui.event(Event::Focus(false));
        key(&mut ui, 4, 0);
        assert_eq!(ui.text(field), "Ada 10");
    }

    #[test]
    fn text_stops_at_its_limit() {
        let mut t = Text::EMPTY;
        for _ in 0..MAX_TEXT {
            assert!(t.push(b'x'));
        }
        assert!(!t.push(b'x'));
        assert_eq!(Text::new(&[b'y'; 40]).as_bytes().len(), MAX_TEXT);
    }

    #[test]
    fn drawing_follows_the_state() {
        let (mut ui, field, button, _) = greeter();
        let mut px = [0u32; 280 * 124];
        let mut s = Surface { px: &mut px, w: 280, h: 124 };
        ui.draw(&mut s);
        let at = |s: &Surface, x: u32, y: u32| s.px[(y * 280 + x) as usize];
        assert_eq!(at(&s, 0, 0), BACKGROUND);
        assert_eq!(at(&s, 8, 32), EDGE, "the field's edge");
        assert_eq!(at(&s, 9, 67), FACE, "the button's face");
        // The pointer over the button: its face changes, and only it is to
        // be shown again.
        let r = ui.event(Event::Pointer { x: 9, y: 67, buttons: 0 });
        assert_eq!(r.damage, ui.widget(button).rect);
        ui.draw_part(&mut s, r.damage);
        assert_eq!(at(&s, 9, 67), FACE_HOVER);
        press(&mut ui, 100, 40);
        ui.event(Event::Focus(true));
        ui.draw(&mut s);
        assert_eq!(at(&s, 8, 32), FOCUS_EDGE, "the field with the keyboard");
        // The cursor at the start of the empty field, just before where
        // text starts.
        assert_eq!(at(&s, 12, 38), INK);
        assert_eq!(at(&s, 14, 38), FIELD);
        key(&mut ui, 4, 0);
        assert_eq!(ui.text(field), "a");
        ui.draw(&mut s);
        // The 'a' (its row 2 is 0x0e: columns 1 to 3), then the cursor in
        // the gap after it.
        assert_eq!(at(&s, 14 + 2, 39 + 4), INK);
        assert_eq!(at(&s, 14, 39 + 4), FIELD);
        assert_eq!(at(&s, 14 + 10, 38), INK);
        assert_eq!(at(&s, 12, 38), FIELD, "the cursor has moved on");
    }

    #[test]
    fn the_cursor_moves_and_edits_happen_at_it() {
        let (mut ui, field, ..) = greeter();
        press(&mut ui, 100, 40);
        ui.event(Event::Focus(true));
        for u in [4, 7, 4] {
            key(&mut ui, u, 0);
        }
        assert_eq!((ui.text(field), ui.cursor(field)), ("ada", 3));
        // Moving the cursor shows the field again, though the text is the
        // same; at either end it stays.
        assert_eq!(key(&mut ui, LEFT, 0).damage, ui.widget(field).rect);
        key(&mut ui, LEFT, 0);
        assert_eq!(ui.cursor(field), 1);
        key(&mut ui, DELETE, 0);
        assert_eq!((ui.text(field), ui.cursor(field)), ("aa", 1));
        key(&mut ui, 17, 0);
        key(&mut ui, 17, 0);
        assert_eq!((ui.text(field), ui.cursor(field)), ("anna", 3));
        key(&mut ui, HOME, 0);
        assert_eq!(key(&mut ui, LEFT, 0).damage, Rect::NONE, "already at the start");
        assert_eq!(key(&mut ui, BACKSPACE, 0).damage, Rect::NONE, "nothing before it");
        key(&mut ui, RIGHT, 0);
        key(&mut ui, BACKSPACE, 0);
        assert_eq!((ui.text(field), ui.cursor(field)), ("nna", 0));
        key(&mut ui, END, 0);
        key(&mut ui, RIGHT, 0);
        assert_eq!(ui.cursor(field), 3);
        // A press puts the cursor in the gap nearest it: text starts at 14,
        // a character every 12 pixels.
        let down = |ui: &mut Ui, x: i32| {
            let r = ui.event(Event::Pointer { x, y: 40, buttons: LEFT_BUTTON });
            ui.event(Event::Pointer { x, y: 40, buttons: 0 });
            r.damage
        };
        assert_eq!(down(&mut ui, 14 + 12 + 5), ui.widget(field).rect);
        assert_eq!(ui.cursor(field), 1);
        press(&mut ui, 14 + 12 + 7, 40);
        assert_eq!(ui.cursor(field), 2);
        press(&mut ui, 9, 40);
        assert_eq!(ui.cursor(field), 0);
        press(&mut ui, 250, 40);
        assert_eq!(ui.cursor(field), 3, "past the text, at its end");
        assert_eq!(down(&mut ui, 250), Rect::NONE, "where it was already");
        // Setting the text puts the cursor at its end.
        ui.set_text(field, "ab");
        assert_eq!(ui.cursor(field), 2);
    }

    #[test]
    fn a_row_goes_left_to_right_and_lays_out_anew() {
        let mut ui = Ui::row(800, 32);
        let a = ui.button("+ greeter");
        let b = ui.button("Hello");
        let l = ui.label("ab");
        assert_eq!(ui.widget(a).rect, Rect { x: 8, y: 3, w: 130, h: 26 });
        assert_eq!(ui.widget(b).rect, Rect { x: 146, y: 3, w: 82, h: 26 });
        assert_eq!(ui.widget(l).rect, Rect { x: 236, y: 8, w: 22, h: 16 });
        ui.push_right(l);
        assert_eq!(ui.widget(l).rect.x, 800 - 8 - 22);
        assert_eq!(press(&mut ui, 150, 10).clicked, Some(b));
        ui.event(Event::Pointer { x: 150, y: 10, buttons: 0 });
        assert_eq!(ui.select(b, true), ui.widget(b).rect);
        assert_eq!(ui.select(b, true), Rect::NONE);
        let mut px = [0u32; 800 * 32];
        let mut s = Surface { px: &mut px, w: 800, h: 32 };
        ui.draw(&mut s);
        assert_eq!(s.px[(4 * 800 + 147) as usize], FACE_SELECTED, "selected over the pointer's hover");
        ui.clear();
        assert!(ui.is_empty());
        let c = ui.button("Greeter");
        assert_eq!(ui.widget(c).rect.x, 8);
        assert!(!ui.widget(c).selected);
    }

    #[test]
    fn a_column_follows_the_window_width() {
        let (mut ui, field, button, out) = greeter();
        ui.resize(380, 184);
        assert_eq!((ui.w, ui.h), (380, 184));
        assert_eq!(ui.widget(field).rect, Rect { x: 8, y: 32, w: 364, h: 26 });
        assert_eq!(ui.widget(button).rect, Rect { x: 8, y: 66, w: 82, h: 26 }, "a button keeps its own width");
        assert_eq!(ui.widget(out).rect.w, 364);
    }

    #[test]
    fn text_wider_than_its_field_scrolls_to_keep_the_cursor_shown() {
        let (mut ui, field, ..) = greeter();
        press(&mut ui, 100, 40);
        ui.event(Event::Focus(true));
        // 264 pixels wide: 21 characters, a character every 12 pixels.
        assert_eq!(ui.widget(field).shown(), 21);
        for u in 4..29 {
            key(&mut ui, u, 0);
        }
        let w = ui.widget(field);
        assert_eq!((w.text.len(), w.cursor, w.scroll), (25, 25, 4));
        // The cursor moves within what is shown without scrolling...
        key(&mut ui, LEFT, 0);
        assert_eq!((ui.cursor(field), ui.widget(field).scroll), (24, 4));
        // ...and past it, scrolling as little as shows it.
        key(&mut ui, HOME, 0);
        assert_eq!(ui.widget(field).scroll, 0);
        for _ in 0..22 {
            key(&mut ui, RIGHT, 0);
        }
        assert_eq!((ui.cursor(field), ui.widget(field).scroll), (22, 1));
        // A press counts from the first character shown.
        press(&mut ui, 14 + 1, 40);
        assert_eq!(ui.cursor(field), 1);
        key(&mut ui, END, 0);
        // Drawn from the first character shown, 'e', to the 21st, 'y'.
        let mut px = [0u32; 280 * 124];
        let mut s = Surface { px: &mut px, w: 280, h: 124 };
        ui.draw(&mut s);
        let ty = 32 + (26 - 14) / 2;
        for dy in 0..14 {
            for dx in 0..21 * 12 - 2 {
                let want = if font::text_lit(b"efghijklmnopqrstuvwxy", SCALE, dx, dy) { INK } else { FIELD };
                assert_eq!(s.px[((ty + dy) * 280 + 14 + dx) as usize], want, "({dx}, {dy})");
            }
        }
        // Text taken out scrolls back to show as much as fits.
        key(&mut ui, BACKSPACE, 0);
        assert_eq!((ui.cursor(field), ui.widget(field).scroll), (24, 3));
        // A narrower window shows fewer.
        ui.resize(200, 124);
        assert_eq!(ui.widget(field).shown(), 14);
        assert_eq!(ui.widget(field).scroll, 10);
        ui.resize(380, 184);
        assert_eq!(ui.widget(field).scroll, 0, "all of it fits again");
    }

    #[test]
    fn keys_type_characters() {
        assert_eq!(character(4, 0), Some(b'a'));
        assert_eq!(character(29, 0x20), Some(b'Z'));
        assert_eq!(character(39, 0), Some(b'0'));
        assert_eq!(character(55, 0), Some(b'.'));
        assert_eq!(character(42, 0), None);
    }
    #[test]
    fn a_line_shares_the_column_and_follows_its_width() {
        let mut ui = Ui::new(320, 240);
        ui.begin_row();
        let l = ui.label("Item:");
        let f = ui.field();
        let b = ui.button("Add");
        ui.end_row();
        let list = ui.list(4);
        ui.begin_row();
        let rm = ui.button("Remove");
        let status = ui.label("x");
        ui.stretch(status);
        ui.end_row();
        // The label (58 wide for 5 characters) and the button (34 + 24) keep
        // their widths; the field takes the rest; the line is as tall as
        // its tallest, the label centred on it.
        assert_eq!(ui.widget(l).rect, Rect { x: 8, y: 13, w: 58, h: 16 });
        assert_eq!(ui.widget(b).rect, Rect { x: 254, y: 8, w: 58, h: 26 });
        assert_eq!(ui.widget(f).rect, Rect { x: 74, y: 8, w: 172, h: 26 });
        assert_eq!(ui.widget(list).rect, Rect { x: 8, y: 42, w: 304, h: 4 * ITEM_H + 2 });
        assert_eq!(ui.widget(rm).rect.y, 42 + 82 + 8);
        assert_eq!(ui.widget(status).rect.x, 8 + ui.widget(rm).rect.w + 8);
        assert_eq!(ui.widget(status).rect.w, 304 - ui.widget(rm).rect.w - 8);
        ui.resize(400, 240);
        assert_eq!(ui.widget(f).rect.w, 252);
        assert_eq!(ui.widget(b).rect.x, 334);
        assert_eq!(ui.widget(list).rect.w, 384);
    }

    fn fruit() -> (Ui, Id) {
        let mut ui = Ui::new(200, 200);
        let list = ui.list(4);
        for f in ["apple", "banana", "cherry", "date", "elder", "fig", "grape"] {
            ui.push_item(list, f);
        }
        ui.event(Event::Focus(true));
        (ui, list)
    }

    #[test]
    fn a_list_chooses_and_scrolls() {
        let (mut ui, list) = fruit();
        let w = *ui.widget(list);
        assert_eq!((ui.items(list), w.shown(), ui.chosen(list)), (7, 4, None));
        assert_eq!(ui.item(list, 2), "cherry");
        // A press on the third row chooses it.
        let y = 8 + 1 + 2 * ITEM_H as i32 + 5;
        let r = ui.event(Event::Pointer { x: 30, y, buttons: 1 });
        ui.event(Event::Pointer { x: 30, y, buttons: 0 });
        assert_eq!((r.picked, ui.chosen(list)), (Some(list), Some(2)));
        assert_eq!(ui.keyboard(), Some(list));
        // Down past the last row shown scrolls as little as shows it.
        key(&mut ui, DOWN, 0);
        assert_eq!((ui.chosen(list), ui.widget(list).scroll), (Some(3), 0));
        let r = key(&mut ui, DOWN, 0);
        assert_eq!((r.picked, ui.chosen(list), ui.widget(list).scroll), (Some(list), Some(4), 1));
        key(&mut ui, END, 0);
        assert_eq!((ui.chosen(list), ui.widget(list).scroll), (Some(6), 3));
        assert_eq!(key(&mut ui, DOWN, 0).picked, None, "already the last");
        key(&mut ui, PAGE_UP, 0);
        assert_eq!((ui.chosen(list), ui.widget(list).scroll), (Some(2), 2));
        key(&mut ui, HOME, 0);
        assert_eq!((ui.chosen(list), ui.widget(list).scroll), (Some(0), 0));
        // The wheel scrolls without choosing, as far as it goes.
        let r = ui.event(Event::Wheel { x: 30, y: 30, up: -2 });
        assert_eq!((r.damage, ui.widget(list).scroll, ui.chosen(list)), (w.rect, 2, Some(0)));
        ui.event(Event::Wheel { x: 30, y: 30, up: -5 });
        assert_eq!(ui.widget(list).scroll, 3);
        ui.event(Event::Wheel { x: 30, y: 30, up: 9 });
        assert_eq!(ui.widget(list).scroll, 0);
    }

    #[test]
    fn a_scroll_bar_pages_and_follows_its_thumb() {
        let (mut ui, list) = fruit();
        let w = *ui.widget(list);
        let bar = w.bar();
        assert_eq!(bar, Rect { x: 8 + 184 - 1 - BAR_W, y: 9, w: BAR_W, h: 80 });
        // 4 of 7 shown: the thumb is 4/7 of the bar.
        assert_eq!(w.thumb(), Rect { y: 9, h: 45, ..bar });
        // Pressed below the thumb: a page down (as far as it goes).
        press(&mut ui, bar.x as i32 + 4, 85);
        assert_eq!(ui.widget(list).scroll, 3);
        assert_eq!(ui.widget(list).thumb().y, 9 + 35);
        press(&mut ui, bar.x as i32 + 4, 12);
        assert_eq!(ui.widget(list).scroll, 0);
        // The thumb dragged down halfway: halfway scrolled, then back.
        let (x, y) = (bar.x as i32 + 4, 20);
        ui.event(Event::Pointer { x, y, buttons: 1 });
        ui.event(Event::Pointer { x, y: y + 18, buttons: 1 });
        assert_eq!(ui.widget(list).scroll, 2);
        ui.event(Event::Pointer { x, y: y + 200, buttons: 1 });
        assert_eq!(ui.widget(list).scroll, 3);
        ui.event(Event::Pointer { x, y: -50, buttons: 1 });
        ui.event(Event::Pointer { x, y: -50, buttons: 0 });
        assert_eq!(ui.widget(list).scroll, 0);
        assert_eq!(ui.chosen(list), None, "the bar chooses nothing");
        // Drawn: the chosen row, the bar and its thumb.
        key(&mut ui, DOWN, 0);
        let mut px = [0u32; 200 * 200];
        let mut s = Surface { px: &mut px, w: 200, h: 200 };
        ui.draw(&mut s);
        let at = |s: &Surface, x: u32, y: u32| s.px[(y * 200 + x) as usize];
        assert_eq!(at(&s, 9, 10), SELECTION);
        assert_eq!(at(&s, 9, 10 + ITEM_H), FIELD);
        assert_eq!(at(&s, bar.x + 4, 9 + 2), THUMB);
        assert_eq!(at(&s, bar.x + 4, 9 + 70), FACE);
    }

    #[test]
    fn items_come_and_go() {
        let (mut ui, list) = fruit();
        let other = ui.list(2);
        ui.push_item(other, "x");
        ui.push_item(list, "honeydew");
        assert_eq!((ui.items(list), ui.item(list, 7), ui.item(other, 0)), (8, "honeydew", "x"));
        ui.choose(list, Some(7));
        assert_eq!(ui.widget(list).scroll, 4);
        ui.remove_item(list, 7);
        assert_eq!((ui.chosen(list), ui.widget(list).scroll), (Some(6), 3), "the last gone: the one before");
        ui.remove_item(list, 0);
        assert_eq!((ui.chosen(list), ui.item(list, 0), ui.item(other, 0)), (Some(5), "banana", "x"));
        ui.choose(list, Some(1));
        ui.remove_item(list, 1);
        assert_eq!((ui.chosen(list), ui.item(list, 1)), (Some(1), "date"), "the next takes its place");
        while ui.items(list) > 0 {
            ui.remove_item(list, 0);
        }
        assert_eq!(ui.chosen(list), None);
        assert_eq!(ui.item(other, 0), "x");
    }

    #[test]
    fn text_is_selected_replaced_cut_and_pasted() {
        let (mut ui, field, ..) = greeter();
        press(&mut ui, 100, 40);
        ui.event(Event::Focus(true));
        for u in [11, 8, 15, 15, 18] {
            key(&mut ui, u, 0);
        }
        assert_eq!((ui.text(field), ui.selection(field)), ("hello", None));
        // Shift with Left twice: the last two selected; typing replaces them.
        key(&mut ui, LEFT, 0x02);
        let r = key(&mut ui, LEFT, 0x20);
        assert_eq!((ui.selection(field), r.damage), (Some((3, 5)), ui.widget(field).rect));
        key(&mut ui, 18, 0);
        assert_eq!((ui.text(field), ui.cursor(field), ui.selection(field)), ("helo", 4, None));
        // Shift and Home, then Left: the cursor at the selection's start.
        key(&mut ui, HOME, 0x02);
        assert_eq!(ui.selection(field), Some((0, 4)));
        key(&mut ui, RIGHT, 0);
        assert_eq!((ui.cursor(field), ui.selection(field)), (4, None));
        // Control-A, Control-X: all of it cut; pasted twice.
        key(&mut ui, KEY_A, 0x01);
        assert_eq!(ui.selection(field), Some((0, 4)));
        key(&mut ui, KEY_X, 0x01);
        assert_eq!((ui.text(field), ui.clipboard()), ("", "helo"));
        key(&mut ui, KEY_V, 0x10);
        key(&mut ui, KEY_V, 0x10);
        assert_eq!((ui.text(field), ui.cursor(field)), ("helohelo", 8));
        // Dragged across from the gap before 'o' to after the second 'h':
        // that selected, the cursor where the drag ended. Control-C copies.
        let gap = |k: i32| 14 + 12 * k;
        ui.event(Event::Pointer { x: gap(3), y: 40, buttons: 1 });
        ui.event(Event::Pointer { x: gap(5), y: 40, buttons: 1 });
        ui.event(Event::Pointer { x: gap(5), y: 40, buttons: 0 });
        assert_eq!((ui.selection(field), ui.cursor(field)), (Some((3, 5)), 5));
        key(&mut ui, KEY_C, 0x01);
        assert_eq!((ui.clipboard(), ui.text(field)), ("oh", "helohelo"));
        // Shift and a press stretch it; Backspace takes it out.
        ui.event(Event::Key { usage: 225, down: true, modifiers: 0x02 });
        press(&mut ui, gap(7), 40);
        ui.event(Event::Key { usage: 225, down: false, modifiers: 0 });
        assert_eq!(ui.selection(field), Some((3, 7)));
        key(&mut ui, BACKSPACE, 0);
        assert_eq!((ui.text(field), ui.cursor(field)), ("helo", 3));
        // Drawn: the selected cells behind the text.
        key(&mut ui, LEFT, 0x02);
        let mut px = [0u32; 280 * 124];
        let mut s = Surface { px: &mut px, w: 280, h: 124 };
        ui.draw(&mut s);
        let ty = 32 + (26 - 14) / 2;
        assert_eq!(s.px[((ty - 1) * 280 + 14 + 2 * 12 + 4) as usize], SELECTION);
        assert_eq!(s.px[((ty - 1) * 280 + 14 + 1 * 12 + 4) as usize], FIELD);
    }
}
