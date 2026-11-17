//! Editing the line being typed: the editing keys, a history the arrows
//! walk, Tab completion of the command, and a suggestion for a mistyped
//! one. No allocation and no I/O: the shell turns key presses and serial
//! escapes into [`Key`]s and shows the line however its device needs.

/// The longest line.
pub const LINE_MAX: usize = 120;
/// How many earlier lines are kept.
pub const HISTORY: usize = 32;

/// A key press, from the PS/2 keyboard or a serial terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(u8),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    /// Earlier and later lines in the history.
    Up,
    Down,
    Home,
    End,
    Tab,
    /// Control-L: clear the screen.
    Clear,
    /// Control-C: drop the line.
    Cancel,
    /// Control-U: delete back to the start of the line.
    KillLine,
}

/// What a key did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Nothing changed.
    Nothing,
    /// The line or the cursor changed: show it again.
    Edited,
    /// Enter: run [`Editor::line`], then call [`Editor::finish`].
    Submit,
    /// Clear the screen, then show the line again.
    Clear,
    /// The line was dropped: start a new prompt.
    Cancel,
    /// Tab found several commands: list [`Editor::candidates`], then show
    /// the line again.
    Candidates,
}

pub struct Editor {
    buf: [u8; LINE_MAX],
    len: usize,
    cursor: usize,
    history: [[u8; LINE_MAX]; HISTORY],
    lens: [usize; HISTORY],
    /// Lines kept, and where the next goes (a ring).
    kept: usize,
    next: usize,
    /// How far back the arrows have gone (0: the line being typed).
    back: usize,
    /// The line being typed, kept while the arrows show older ones.
    draft: [u8; LINE_MAX],
    draft_len: usize,
}

impl Editor {
    pub const fn new() -> Editor {
        Editor {
            buf: [0; LINE_MAX],
            len: 0,
            cursor: 0,
            history: [[0; LINE_MAX]; HISTORY],
            lens: [0; HISTORY],
            kept: 0,
            next: 0,
            back: 0,
            draft: [0; LINE_MAX],
            draft_len: 0,
        }
    }

    /// The line as it stands.
    pub fn line(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Keeps the line just run in the history (unless it is empty or the
    /// same as the last) and starts an empty one.
    pub fn finish(&mut self) {
        let line = trim(&self.buf[..self.len]);
        if !line.is_empty() && self.earlier(1) != Some(line) {
            let n = line.len();
            let mut copy = [0u8; LINE_MAX];
            copy[..n].copy_from_slice(line);
            self.history[self.next][..n].copy_from_slice(&copy[..n]);
            self.lens[self.next] = n;
            self.next = (self.next + 1) % HISTORY;
            self.kept = (self.kept + 1).min(HISTORY);
        }
        self.len = 0;
        self.cursor = 0;
        self.back = 0;
    }

    /// The line `n` back in the history (1: the last one run).
    fn earlier(&self, n: usize) -> Option<&[u8]> {
        if n == 0 || n > self.kept {
            return None;
        }
        let i = (self.next + HISTORY - n) % HISTORY;
        Some(&self.history[i][..self.lens[i]])
    }

    fn load(&mut self, from: &[u8]) {
        let n = from.len().min(LINE_MAX);
        let mut copy = [0u8; LINE_MAX];
        copy[..n].copy_from_slice(&from[..n]);
        self.buf[..n].copy_from_slice(&copy[..n]);
        self.len = n;
        self.cursor = n;
    }

    /// Shows the line `back` steps back in the history, keeping what was
    /// being typed when leaving it.
    fn browse(&mut self, back: usize) -> Action {
        if back == self.back || back > self.kept {
            return Action::Nothing;
        }
        if self.back == 0 {
            self.draft[..self.len].copy_from_slice(&self.buf[..self.len]);
            self.draft_len = self.len;
        }
        self.back = back;
        if back == 0 {
            let draft = self.draft;
            self.load(&draft[..self.draft_len]);
        } else {
            let mut line = [0u8; LINE_MAX];
            let n = self.earlier(back).map(|l| {
                line[..l.len()].copy_from_slice(l);
                l.len()
            });
            self.load(&line[..n.unwrap_or(0)]);
        }
        Action::Edited
    }

    /// Applies key `key`; `commands` are what Tab completes.
    pub fn key(&mut self, key: Key, commands: &[&str]) -> Action {
        match key {
            Key::Char(c) if (0x20..=0x7e).contains(&c) => {
                if self.len == LINE_MAX {
                    return Action::Nothing;
                }
                self.buf.copy_within(self.cursor..self.len, self.cursor + 1);
                self.buf[self.cursor] = c;
                self.len += 1;
                self.cursor += 1;
                Action::Edited
            }
            Key::Char(_) => Action::Nothing,
            Key::Enter => Action::Submit,
            Key::Backspace if self.cursor > 0 => {
                self.buf.copy_within(self.cursor..self.len, self.cursor - 1);
                self.len -= 1;
                self.cursor -= 1;
                Action::Edited
            }
            Key::Delete if self.cursor < self.len => {
                self.buf.copy_within(self.cursor + 1..self.len, self.cursor);
                self.len -= 1;
                Action::Edited
            }
            Key::Left if self.cursor > 0 => {
                self.cursor -= 1;
                Action::Edited
            }
            Key::Right if self.cursor < self.len => {
                self.cursor += 1;
                Action::Edited
            }
            Key::Home if self.cursor > 0 => {
                self.cursor = 0;
                Action::Edited
            }
            Key::End if self.cursor < self.len => {
                self.cursor = self.len;
                Action::Edited
            }
            Key::Up => self.browse(self.back + 1),
            Key::Down if self.back > 0 => self.browse(self.back - 1),
            Key::KillLine if self.cursor > 0 => {
                self.buf.copy_within(self.cursor..self.len, 0);
                self.len -= self.cursor;
                self.cursor = 0;
                Action::Edited
            }
            Key::Tab => self.complete(commands),
            Key::Clear => Action::Clear,
            Key::Cancel => {
                self.len = 0;
                self.cursor = 0;
                self.back = 0;
                Action::Cancel
            }
            _ => Action::Nothing,
        }
    }

    /// The command word, if the cursor is in or just after it: its start
    /// and end.
    fn word(&self) -> Option<(usize, usize)> {
        let start = self.buf[..self.len].iter().position(|&b| b != b' ').unwrap_or(self.len);
        let end = self.buf[start..self.len].iter().position(|&b| b == b' ').map_or(self.len, |i| start + i);
        (self.cursor >= start && self.cursor <= end).then_some((start, end))
    }

    /// The commands the word typed so far could be.
    pub fn candidates<'a>(&self, commands: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
        let mut typed = [0u8; LINE_MAX];
        let n = self.word().map_or(0, |(s, e)| {
            typed[..e - s].copy_from_slice(&self.buf[s..e]);
            e - s
        });
        let ok = self.word().is_some();
        commands.iter().copied().filter(move |c| ok && c.as_bytes().starts_with(&typed[..n]))
    }

    fn complete(&mut self, commands: &[&str]) -> Action {
        let Some((start, end)) = self.word() else {
            return Action::Nothing;
        };
        let typed = &self.buf[start..end];
        let mut matches = commands.iter().filter(|c| c.as_bytes().starts_with(typed));
        let Some(first) = matches.next() else {
            return Action::Nothing;
        };
        // What every match shares.
        let mut common = first.len();
        let mut several = false;
        for m in matches {
            several = true;
            common = common.min(first.bytes().zip(m.bytes()).take_while(|(a, b)| a == b).count());
        }
        let mut add = [0u8; LINE_MAX];
        let mut n = 0;
        for &b in &first.as_bytes()[typed.len()..common] {
            add[n] = b;
            n += 1;
        }
        if !several && (end == self.len || self.buf[end] != b' ') {
            add[n] = b' ';
            n += 1;
        }
        if n == 0 {
            return if several { Action::Candidates } else { Action::Nothing };
        }
        if self.len + n > LINE_MAX {
            return Action::Nothing;
        }
        self.buf.copy_within(end..self.len, end + n);
        self.buf[end..end + n].copy_from_slice(&add[..n]);
        self.len += n;
        self.cursor = end + n;
        if !several && self.cursor < self.len && self.buf[self.cursor] == b' ' {
            self.cursor += 1;
        }
        Action::Edited
    }
}

impl Default for Editor {
    fn default() -> Editor {
        Editor::new()
    }
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&b| b != b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

/// The command `word` was most likely meant to be: the one fewest edits
/// away (insertions, deletions, substitutions and swaps of neighbours), if
/// that is close enough to be a typo.
pub fn suggest<'a>(word: &str, commands: &[&'a str]) -> Option<&'a str> {
    let w = word.as_bytes();
    if w.is_empty() || w.len() > 24 {
        return None;
    }
    let limit = if w.len() <= 3 { 1 } else { 2 };
    commands
        .iter()
        .map(|c| (distance(w, c.as_bytes()), *c))
        .filter(|&(d, _)| d <= limit)
        .min_by_key(|&(d, _)| d)
        .map(|(_, c)| c)
}

/// Edits between `a` and `b` (optimal string alignment distance), for
/// words up to 24 bytes.
fn distance(a: &[u8], b: &[u8]) -> usize {
    const N: usize = 25;
    if a.len() >= N || b.len() >= N {
        return usize::MAX;
    }
    let mut d = [[0usize; N]; N];
    for (i, row) in d.iter_mut().enumerate().take(a.len() + 1) {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate().take(b.len() + 1) {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}
