//! The Superior UI toolkit: what an app draws its window with.
//!
//! An app lays out widgets in a column or a row ([`Ui`]): labels, buttons
//! and text fields. The toolkit draws them into the window's pixels ([`Surface`]),
//! takes the events the compositor gives the window ([`Event`]) and
//! answers what they changed: the part of the window to show again, and
//! the button clicked, if any. A button is clicked when pressed and let go
//! over it; a field pressed takes the keyboard, with its cursor where it
//! was pressed, and keys typed to it edit its text at the cursor (letters,
//! digits, space and some punctuation, Shift for capitals, Backspace and
//! Delete; the arrows, Home and End move the cursor). No heap: a `Ui` holds up to [`MAX_WIDGETS`],
//! each text up to [`MAX_TEXT`] bytes.
//!
//! The host draws the same to check the screenshots of the toolkit test,
//! so drawing must not depend on anything but the widgets' state.

#![no_std]

pub mod font;

pub const MAX_WIDGETS: usize = 16;
pub const MAX_TEXT: usize = 32;

/// Text is drawn at twice the font's size.
pub const SCALE: u32 = 2;
/// Space around and between widgets.
pub const PAD: u32 = 8;
/// A label's height, and a button's or field's.
pub const LABEL_H: u32 = font::HEIGHT * SCALE + 2;
pub const BOX_H: u32 = font::HEIGHT * SCALE + 12;
/// Space between a button's text and its sides.
pub const BUTTON_SIDE: u32 = 12;

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
}

#[derive(Clone, Copy)]
pub struct Widget {
    pub kind: Kind,
    pub rect: Rect,
    pub text: Text,
    /// A button drawn as chosen.
    pub selected: bool,
    /// A field's cursor: the byte of its text it is before.
    pub cursor: usize,
}

/// A widget's number in its [`Ui`], in the order added.
pub type Id = usize;

/// An event from the compositor, in the window's pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The pointer is at (x, y) with these buttons held (bit 0 the left).
    Pointer { x: i32, y: i32, buttons: u64 },
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
    /// The field Enter was pressed in.
    pub entered: Option<Id>,
}

/// The character a key types, if it types one: `usage` is its USB HID
/// usage, `modifiers` the modifier byte (Shift is bit 1 or bit 5).
pub fn character(usage: u64, modifiers: u8) -> Option<u8> {
    let shift = modifiers & 0x22 != 0;
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

const BACKSPACE: u64 = 42;
const ENTER: u64 = 40;
const DELETE: u64 = 76;
const HOME: u64 = 74;
const END: u64 = 77;
const RIGHT: u64 = 79;
const LEFT: u64 = 80;

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
    /// Laid out left to right, each centred on the window's height.
    row: bool,
    /// Where the next widget goes.
    next_y: u32,
    next_x: u32,
    /// The field with the keyboard, the button under the pointer, the one
    /// pressed (held until the buttons are let go), and whether the window
    /// has the focus.
    field: Option<Id>,
    hover: Option<Id>,
    pressed: Option<Id>,
    focused: bool,
    buttons: u64,
}

impl Ui {
    /// A column, top to bottom.
    pub fn new(w: u32, h: u32) -> Ui {
        let none = Widget { kind: Kind::Label, rect: Rect::NONE, text: Text::EMPTY, selected: false, cursor: 0 };
        Ui {
            w,
            h,
            widgets: [none; MAX_WIDGETS],
            len: 0,
            row: false,
            next_y: PAD,
            next_x: PAD,
            field: None,
            hover: None,
            pressed: None,
            focused: false,
            buttons: 0,
        }
    }

    /// A row, left to right.
    pub fn row(w: u32, h: u32) -> Ui {
        Ui { row: true, ..Ui::new(w, h) }
    }

    /// Takes every widget away, to lay out anew (state tied to them goes:
    /// the field with the keyboard, the button under the pointer or
    /// pressed).
    pub fn clear(&mut self) {
        self.len = 0;
        (self.next_x, self.next_y) = (PAD, PAD);
        (self.field, self.hover, self.pressed) = (None, None, None);
    }

    fn add(&mut self, kind: Kind, w: u32, h: u32, text: &[u8]) -> Id {
        assert!(self.len < MAX_WIDGETS, "too many widgets");
        let rect = if self.row {
            let r = Rect { x: self.next_x, y: self.h.saturating_sub(h) / 2, w, h };
            self.next_x += w + PAD;
            r
        } else {
            let r = Rect { x: PAD, y: self.next_y, w, h };
            self.next_y += h + PAD;
            r
        };
        let text = Text::new(text);
        self.widgets[self.len] = Widget { kind, rect, text, selected: false, cursor: text.len() };
        self.len += 1;
        self.len - 1
    }

    /// The window is now `w` by `h`: in a column, labels and fields take
    /// its new width (a row stays as it is laid out). Draw it all again.
    pub fn resize(&mut self, w: u32, h: u32) {
        (self.w, self.h) = (w, h);
        if self.row {
            return;
        }
        for widget in &mut self.widgets[..self.len] {
            if widget.kind != Kind::Button {
                widget.rect.w = w.saturating_sub(2 * PAD);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// A line of text: the window's width in a column, its own in a row.
    pub fn label(&mut self, text: &str) -> Id {
        let w = if self.row { font::width(text.as_bytes(), SCALE) } else { self.w - 2 * PAD };
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

    /// An empty text field, the window's width.
    pub fn field(&mut self) -> Id {
        self.add(Kind::Field, self.w - 2 * PAD, BOX_H, b"")
    }

    pub fn widget(&self, id: Id) -> &Widget {
        &self.widgets[id]
    }

    pub fn text(&self, id: Id) -> &str {
        self.widgets[id].text.as_str()
    }

    /// Sets widget `id`'s text: the part of the window to show again.
    /// A field's cursor: the byte of its text it is before.
    pub fn cursor(&self, id: Id) -> usize {
        self.widgets[id].cursor
    }

    pub fn set_text(&mut self, id: Id, text: &str) -> Rect {
        let t = Text::new(text.as_bytes());
        if self.widgets[id].text == t {
            return Rect::NONE;
        }
        self.widgets[id].text = t;
        self.widgets[id].cursor = t.len();
        self.widgets[id].rect
    }

    /// The field with the keyboard, if any.
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
        let Widget { kind, rect: r, text, selected, cursor } = self.widgets[id];
        let t = text.as_bytes();
        let th = font::HEIGHT * SCALE;
        match kind {
            Kind::Label => {
                s.fill(r, BACKGROUND);
                s.text(r.x, r.y + 1, t, SCALE, INK);
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
                let keyboard = self.keyboard() == Some(id);
                s.fill(r, FIELD);
                s.outline(r, if keyboard { FOCUS_EDGE } else { EDGE });
                let (tx, ty) = (r.x + FIELD_INSET, r.y + (r.h - th) / 2);
                s.text(tx, ty, t, SCALE, INK);
                if keyboard {
                    // The cursor, in the gap before the character it is
                    // before (or after the last one).
                    let cx = tx + cursor as u32 * STEP - SCALE;
                    s.fill(Rect { x: cx, y: ty - 1, w: SCALE, h: th + 2 }, INK);
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

    /// Takes an event: what it changed.
    pub fn event(&mut self, e: Event) -> Response {
        let mut r = Response::default();
        match e {
            Event::Pointer { x, y, buttons } => {
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
                    let field = under.filter(|&id| self.widgets[id].kind == Kind::Field);
                    if let Some(f) = field {
                        // The cursor goes to the gap nearest the press.
                        let w = &mut self.widgets[f];
                        let from = x - (w.rect.x + FIELD_INSET) as i32 + STEP as i32 / 2;
                        let cursor = (from.max(0) as u32 / STEP).min(w.text.len() as u32) as usize;
                        if field != self.field || cursor != w.cursor {
                            w.cursor = cursor;
                            r.damage = r.damage.union(self.rect(self.field)).union(self.rect(field));
                            self.field = field;
                        }
                    }
                }
                if let_go {
                    if let Some(p) = self.pressed.take() {
                        r.damage = r.damage.union(self.rect(Some(p)));
                        if button == Some(p) {
                            r.clicked = Some(p);
                        }
                    }
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
            Event::Key { usage, down: true, modifiers } => {
                if let Some(id) = self.keyboard() {
                    let Widget { text, cursor, .. } = &mut self.widgets[id];
                    let before = *cursor;
                    let changed = match usage {
                        BACKSPACE => *cursor > 0 && text.remove(*cursor - 1) && {
                            *cursor -= 1;
                            true
                        },
                        DELETE => text.remove(*cursor),
                        LEFT => {
                            *cursor = cursor.saturating_sub(1);
                            false
                        }
                        RIGHT => {
                            *cursor = (*cursor + 1).min(text.len());
                            false
                        }
                        HOME => {
                            *cursor = 0;
                            false
                        }
                        END => {
                            *cursor = text.len();
                            false
                        }
                        ENTER => {
                            r.entered = Some(id);
                            false
                        }
                        _ => character(usage, modifiers).is_some_and(|c| text.insert(*cursor, c)) && {
                            *cursor += 1;
                            true
                        },
                    };
                    if changed || *cursor != before {
                        r.damage = self.widgets[id].rect;
                    }
                }
            }
            Event::Key { .. } => {}
        }
        r
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
    fn keys_type_characters() {
        assert_eq!(character(4, 0), Some(b'a'));
        assert_eq!(character(29, 0x20), Some(b'Z'));
        assert_eq!(character(39, 0), Some(b'0'));
        assert_eq!(character(55, 0), Some(b'.'));
        assert_eq!(character(42, 0), None);
    }
}
