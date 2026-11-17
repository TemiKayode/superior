use super::editor::{Action, Editor, Key, suggest};
use super::*;
use std::vec;
use std::vec::Vec;

const COMMANDS: &[&str] = &["help", "about", "echo", "sleep", "ipc", "clear", "log", "reboot", "shutdown"];

/// A picture in memory, RGB.
pub struct Picture {
    pub w: usize,
    pub h: usize,
    pub px: Vec<[u8; 3]>,
}

impl Picture {
    pub fn new(w: usize, h: usize) -> Picture {
        Picture { w, h, px: vec![[0xff, 0, 0xff]; w * h] }
    }
}

impl Canvas for Picture {
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, rgb: [u8; 3]) {
        for yy in y..(y + h).min(self.h) {
            for xx in x..(x + w).min(self.w) {
                self.px[yy * self.w + xx] = rgb;
            }
        }
    }
}

fn typed(e: &mut Editor, s: &str) {
    for b in s.bytes() {
        e.key(Key::Char(b), COMMANDS);
    }
}

fn line(e: &Editor) -> &str {
    core::str::from_utf8(e.line()).unwrap()
}

#[test]
fn editing_in_the_middle() {
    let mut e = Editor::new();
    typed(&mut e, "eho hi");
    for _ in 0..5 {
        e.key(Key::Left, COMMANDS);
    }
    e.key(Key::Char(b'c'), COMMANDS);
    assert_eq!(line(&e), "echo hi");
    assert_eq!(e.cursor(), 2);
    e.key(Key::End, COMMANDS);
    e.key(Key::Backspace, COMMANDS);
    assert_eq!(line(&e), "echo h");
    e.key(Key::Home, COMMANDS);
    e.key(Key::Delete, COMMANDS);
    assert_eq!(line(&e), "cho h");
    e.key(Key::Right, COMMANDS);
    e.key(Key::KillLine, COMMANDS);
    assert_eq!(line(&e), "ho h");
    assert_eq!(e.cursor(), 0);
    assert_eq!(e.key(Key::Backspace, COMMANDS), Action::Nothing);
}

#[test]
fn history_walks_back_and_keeps_the_draft() {
    let mut e = Editor::new();
    for l in ["help", "echo one", "echo one", "  ", "about"] {
        typed(&mut e, l);
        assert_eq!(e.key(Key::Enter, COMMANDS), Action::Submit);
        e.finish();
    }
    typed(&mut e, "ec");
    e.key(Key::Up, COMMANDS);
    assert_eq!(line(&e), "about");
    e.key(Key::Up, COMMANDS);
    assert_eq!(line(&e), "echo one", "a repeated line is kept once");
    e.key(Key::Up, COMMANDS);
    assert_eq!(line(&e), "help");
    assert_eq!(e.key(Key::Up, COMMANDS), Action::Nothing, "the oldest line");
    e.key(Key::Down, COMMANDS);
    e.key(Key::Down, COMMANDS);
    e.key(Key::Down, COMMANDS);
    assert_eq!(line(&e), "ec", "back to what was being typed");
    assert_eq!(e.key(Key::Down, COMMANDS), Action::Nothing);
}

#[test]
fn history_is_a_ring() {
    let mut e = Editor::new();
    for i in 0..editor::HISTORY + 5 {
        typed(&mut e, &std::format!("echo {i}"));
        e.finish();
    }
    for _ in 0..editor::HISTORY {
        e.key(Key::Up, COMMANDS);
    }
    assert_eq!(line(&e), "echo 5");
    assert_eq!(e.key(Key::Up, COMMANDS), Action::Nothing);
}

#[test]
fn tab_completes_the_command() {
    let mut e = Editor::new();
    typed(&mut e, "sh");
    assert_eq!(e.key(Key::Tab, COMMANDS), Action::Edited);
    assert_eq!(line(&e), "shutdown ");
    let mut e = Editor::new();
    typed(&mut e, "e");
    e.key(Key::Tab, COMMANDS);
    assert_eq!(line(&e), "echo ");
    // "s" could be sleep or shutdown, and they share nothing more.
    let mut e = Editor::new();
    typed(&mut e, "s");
    assert_eq!(e.key(Key::Tab, COMMANDS), Action::Candidates);
    let found: Vec<_> = e.candidates(COMMANDS).collect();
    assert_eq!(found, ["sleep", "shutdown"]);
    // Only the command word completes.
    let mut e = Editor::new();
    typed(&mut e, "echo he");
    assert_eq!(e.key(Key::Tab, COMMANDS), Action::Nothing);
    // Completing a word with arguments after it.
    let mut e = Editor::new();
    typed(&mut e, "sl 20");
    e.key(Key::Home, COMMANDS);
    e.key(Key::Right, COMMANDS);
    e.key(Key::Right, COMMANDS);
    e.key(Key::Tab, COMMANDS);
    assert_eq!(line(&e), "sleep 20");
    assert_eq!(e.cursor(), 6);
}

#[test]
fn suggestions_for_typos() {
    assert_eq!(suggest("ech", COMMANDS), Some("echo"));
    assert_eq!(suggest("hlep", COMMANDS), Some("help"));
    assert_eq!(suggest("shtudown", COMMANDS), Some("shutdown"));
    assert_eq!(suggest("rebot", COMMANDS), Some("reboot"));
    assert_eq!(suggest("frobnicate", COMMANDS), None);
    assert_eq!(suggest("xyz", COMMANDS), None);
    assert_eq!(suggest("", COMMANDS), None);
}

#[test]
fn every_character_is_recognised() {
    for c in 0x20..=0x7eu8 {
        assert_eq!(recognise(pattern(c)), c, "{:?}", c as char);
    }
    assert_eq!(recognise(0x7_ffff_ffff), b'?');
}

fn text(t: &Term, row: usize) -> std::string::String {
    let mut buf = [0u8; MAX_COLUMNS];
    let n = t.row_text(row, &mut buf);
    buf[..n].iter().map(|&b| if b >= 0x80 { '>' } else { b as char }).collect()
}

#[test]
fn a_session_on_the_screen() {
    let mut p = Picture::new(800, 600);
    let mut t = std::boxed::Box::new(Term::new());
    t.init(&mut p, 800, 600);
    assert_eq!((t.columns(), t.rows()), (64, 27));
    assert!(p.px.iter().all(|&c| c != [0xff, 0, 0xff]), "every pixel drawn");
    t.style(Ink::Text, PROMPT_COL);
    t.write(&mut p, b"Welcome.\n");
    t.prompt(&mut p);
    t.edit(&mut p, b"echo hi", 7);
    t.submit(&mut p);
    t.write(&mut p, b"hi\n");
    t.prompt(&mut p);
    assert_eq!(text(&t, 0), "  Welcome.");
    assert_eq!(text(&t, 1), "");
    assert_eq!(text(&t, 2), "  ~ > echo hi");
    assert_eq!(text(&t, 3), "    hi");
    assert_eq!(text(&t, 4), "");
    assert_eq!(text(&t, 5), "  ~ >");
    assert_eq!(t.cursor_cell(), Some((INPUT_COL, 5)));
    // A long line wraps under its own start and shrinks back.
    let long = [b'x'; 70];
    t.edit(&mut p, &long, 70);
    assert_eq!(text(&t, 6), std::format!("      {}", "x".repeat(70 - (64 - INPUT_COL))));
    t.edit(&mut p, b"x", 1);
    assert_eq!(text(&t, 6), "");
    // The screen scrolls, the line being typed with it.
    t.submit(&mut p);
    for i in 0..40 {
        t.write(&mut p, std::format!("line {i}\n").as_bytes());
    }
    t.prompt(&mut p);
    assert_eq!(text(&t, t.rows() - 1), "  ~ >");
    assert_eq!(text(&t, t.rows() - 3), "    line 39");
}

#[test]
fn the_cursor_blinks() {
    let mut p = Picture::new(640, 480);
    let mut t = std::boxed::Box::new(Term::new());
    t.init(&mut p, 640, 480);
    t.prompt(&mut p);
    let (x, y, _, _) = t.cell_rect(INPUT_COL, 0);
    let at = |p: &Picture| p.px[(y + 5) * p.w + x];
    assert_eq!(at(&p), CURSOR);
    for _ in 0..BLINK_TICKS {
        t.tick(&mut p);
    }
    assert_eq!(at(&p), BACKGROUND);
    for _ in 0..BLINK_TICKS {
        t.tick(&mut p);
    }
    assert_eq!(at(&p), CURSOR);
}

/// Writes a picture of a session to `target/console-preview-*.ppm` when
/// `CONSOLE_PREVIEW` is set, to look at the design.
#[test]
fn preview() {
    let Ok(dir) = std::env::var("CONSOLE_PREVIEW") else { return };
    for (w, h) in [(800, 600), (1280, 720)] {
        let mut p = Picture::new(w, h);
        let mut t = std::boxed::Box::new(Term::new());
        t.init(&mut p, w, h);
        t.bar(
            &mut p,
            &[(b"SUPERIOR", Ink::Accent), (b"   x86-64 \x81 2 CPUs \x81 415 MiB free", Ink::Muted)],
            &[(b"up 0:04:12", Ink::Muted), (b"   14:32", Ink::Text)],
        );
        t.style(Ink::Text, PROMPT_COL);
        t.write(&mut p, WELCOME);
        t.ink(Ink::Muted);
        t.write(&mut p, HINT);
        t.prompt(&mut p);
        t.edit(&mut p, b"help", 4);
        t.submit(&mut p);
        for (name, what) in [
            ("help", "this list"),
            ("about", "what is running"),
            ("echo", "print text"),
            ("sleep", "wait a number of ticks"),
            ("log", "the kernel's boot log"),
            ("clear", "clear the screen (Ctrl-L)"),
            ("reboot", "restart the machine"),
            ("shutdown", "power off"),
        ] {
            t.ink(Ink::Strong);
            t.write(&mut p, name.as_bytes());
            t.write(&mut p, &b"            "[..12 - name.len()]);
            t.ink(Ink::Muted);
            t.write(&mut p, what.as_bytes());
            t.write(&mut p, b"\n");
        }
        t.prompt(&mut p);
        t.edit(&mut p, b"ech hello", 9);
        t.submit(&mut p);
        t.ink(Ink::Error);
        t.write(&mut p, b"no command 'ech'.");
        t.ink(Ink::Muted);
        t.write(&mut p, b" did you mean ");
        t.ink(Ink::Strong);
        t.write(&mut p, b"echo");
        t.ink(Ink::Muted);
        t.write(&mut p, b"?\n");
        t.prompt(&mut p);
        t.edit(&mut p, b"echo hello", 10);
        t.submit(&mut p);
        t.write(&mut p, b"hello\n");
        t.prompt(&mut p);
        t.edit(&mut p, b"ab", 2);
        let mut out = std::format!("P6\n{w} {h}\n255\n").into_bytes();
        for px in &p.px {
            out.extend_from_slice(px);
        }
        std::fs::write(std::format!("{dir}/console-preview-{w}x{h}.ppm"), out).unwrap();
    }
}
