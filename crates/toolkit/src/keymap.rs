//! Keyboard layouts: the character a key types, by its USB HID usage (the
//! key's place on the keyboard), whether Shift is held, and the layout.
//! Characters are Latin-1 (the font's): ASCII, and from 0xA0 `£`, `é` and
//! the like. A dead key (an accent typed before its letter) types nothing.
//!
//! The compositor maps keys under the system's layout and gives each
//! `KEY` event the character; shortcuts (Control with a letter) go by the
//! key's place, as on the US layout, whatever the layout.

/// The layouts, as the compositor's `SET_LAYOUT` numbers them.
pub const US: u64 = 0;
pub const UK: u64 = 1;
pub const DVORAK: u64 = 2;
pub const FRENCH: u64 = 3;
pub const LAYOUTS: u64 = 4;

/// Each layout's name, by number.
pub const NAMES: [&str; LAYOUTS as usize] = ["US", "UK", "Dvorak", "French"];

/// The modifier byte's Shift bits (left or right).
const SHIFT: u8 = 0x22;

/// What a key types on the US layout, unshifted, by usage from 4 (`a`)
/// to 56 (`/`); 0 for keys that type nothing.
const US_KEYS: &[u8; 53] = b"abcdefghijklmnopqrstuvwxyz1234567890\0\0\0\t -=[]\\\0;'`,./";

/// The US layout's shifted form of an unshifted character.
fn us_shift(c: u8) -> u8 {
    match c {
        b'a'..=b'z' => c - 32,
        b'1' => b'!',
        b'2' => b'@',
        b'3' => b'#',
        b'4' => b'$',
        b'5' => b'%',
        b'6' => b'^',
        b'7' => b'&',
        b'8' => b'*',
        b'9' => b'(',
        b'0' => b')',
        b'-' => b'_',
        b'=' => b'+',
        b'[' => b'{',
        b']' => b'}',
        b'\\' => b'|',
        b';' => b':',
        b'\'' => b'"',
        b'`' => b'~',
        b',' => b'<',
        b'.' => b'>',
        b'/' => b'?',
        _ => c,
    }
}

/// The US layout's unshifted character for `usage`, if it types one.
fn us_key(usage: u64) -> Option<u8> {
    let c = *US_KEYS.get(usage.checked_sub(4)? as usize)?;
    (c != 0 && c != b'\t').then_some(c)
}

/// The character key `usage` types with modifier byte `modifiers` under
/// layout `layout` (US for an unknown one), if it types one.
pub fn character(layout: u64, usage: u64, modifiers: u8) -> Option<u8> {
    let shift = modifiers & SHIFT != 0;
    match layout {
        UK => uk(usage, shift),
        DVORAK => dvorak(usage, shift),
        FRENCH => french(usage, shift),
        _ => us_key(usage).map(|c| if shift { us_shift(c) } else { c }),
    }
}

/// UK: as the US layout but for `"` and `@` swapped, `£` and `¬`, and the
/// keys beside Enter (`#~`, usage 50) and left Shift (`\|`, usage 100).
fn uk(usage: u64, shift: bool) -> Option<u8> {
    match (usage, shift) {
        (31, true) => Some(b'"'),
        (52, true) => Some(b'@'),
        (32, true) => Some(0xa3),
        (53, true) => Some(0xac),
        (50, false) => Some(b'#'),
        (50, true) => Some(b'~'),
        (100, false) => Some(b'\\'),
        (100, true) => Some(b'|'),
        (49, _) => None,
        _ => us_key(usage).map(|c| if shift { us_shift(c) } else { c }),
    }
}

/// Dvorak (the US form): the letters and most punctuation in other places;
/// the digits where they are on the US layout.
fn dvorak(usage: u64, shift: bool) -> Option<u8> {
    const FROM: &[u8] = b"qwertyuiop[]asdfghjkl;'zxcvbnm,./-=";
    const TO: &[u8] = b"',.pyfgcrl/=aoeuidhtns-;qjkxbmwvz[]";
    let c = us_key(usage)?;
    let c = FROM.iter().position(|&f| f == c).map_or(c, |k| TO[k]);
    Some(if shift { us_shift(c) } else { c })
}

/// French AZERTY: A and Q, Z and W swapped, M right of L; the digits
/// shifted, unshifted the row's symbols and accented letters.
fn french(usage: u64, shift: bool) -> Option<u8> {
    // The top row from `1` to `0`, unshifted: & é " ' ( - è _ ç à.
    const TOP: &[u8; 10] = &[b'&', 0xe9, b'"', b'\'', b'(', b'-', 0xe8, b'_', 0xe7, 0xe0];
    let pair = |plain: u8, shifted: u8| {
        let c = if shift { shifted } else { plain };
        (c != 0).then_some(c)
    };
    match usage {
        30..=39 => pair(TOP[usage as usize - 30], US_KEYS[usage as usize - 4]),
        4 => pair(b'q', b'Q'),
        20 => pair(b'a', b'A'),
        26 => pair(b'z', b'Z'),
        29 => pair(b'w', b'W'),
        51 => pair(b'm', b'M'),
        16 => pair(b',', b'?'),
        45 => pair(b')', 0xb0),
        46 => pair(b'=', b'+'),
        // `^` and `¨` are dead keys there.
        47 => None,
        48 => pair(b'$', 0xa3),
        49 | 50 => pair(b'*', 0xb5),
        52 => pair(0xf9, b'%'),
        53 => pair(0xb2, 0),
        54 => pair(b';', b'.'),
        55 => pair(b':', b'/'),
        56 => pair(b'!', 0xa7),
        100 => pair(b'<', b'>'),
        _ => us_key(usage).map(|c| if shift { us_shift(c) } else { c }),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// What typing `keys` (usage and Shift) gives under `layout`.
    fn typed(layout: u64, keys: &[(u64, bool)]) -> std::string::String {
        // Latin-1 is Unicode's first 256 code points.
        keys.iter().filter_map(|&(u, s)| character(layout, u, if s { 0x02 } else { 0 })).map(char::from).collect()
    }

    /// The usages of the keys a US typist presses for `s` (lower case,
    /// digits and the unshifted punctuation of `US_KEYS`), and Shift for
    /// upper case.
    fn us_keys(s: &str) -> std::vec::Vec<(u64, bool)> {
        s.bytes()
            .map(|c| {
                let lower = c.to_ascii_lowercase();
                let k = US_KEYS.iter().position(|&u| u == lower).expect("a key for it");
                (k as u64 + 4, c.is_ascii_uppercase())
            })
            .collect()
    }

    #[test]
    fn the_us_layout_types_every_printable_character() {
        let mut all = std::vec::Vec::new();
        for u in 4..=56 {
            for s in [false, true] {
                all.extend(character(US, u, if s { 0x20 } else { 0 }));
            }
        }
        all.sort();
        all.dedup();
        assert_eq!(all, (b' '..=b'~').collect::<std::vec::Vec<_>>());
        assert_eq!(character(US, 42, 0), None, "Backspace types nothing");
        assert_eq!(character(US, 40, 0), None, "nor Enter");
        assert_eq!(character(US, 43, 0), None, "nor Tab");
        assert_eq!(character(9, 4, 0), Some(b'a'), "an unknown layout is US");
    }

    #[test]
    fn dvorak_moves_the_letters() {
        // The keys a US typist would press for "rdao" type "pear".
        assert_eq!(typed(DVORAK, &us_keys("rdao")), "pear");
        assert_eq!(typed(DVORAK, &us_keys("Jdppsw")), "Hello,");
        assert_eq!(typed(DVORAK, &us_keys("qwe-=")), "',.[]");
        assert_eq!(typed(DVORAK, &[(20, true), (26, true), (52, true), (30, true)]), "\"<_!");
    }

    #[test]
    fn uk_differs_from_us_in_a_few_places() {
        assert_eq!(typed(UK, &[(31, true), (52, true), (50, false), (50, true), (100, false), (100, true)]), "\"@#~\\|");
        assert_eq!(typed(UK, &[(32, true), (53, true), (49, false)]), "£¬", "the US backslash key types nothing");
        assert_eq!(typed(UK, &us_keys("Pear 42")), "Pear 42");
    }

    #[test]
    fn french_is_azerty() {
        // The keys under "azerty" on a French keyboard are "qwerty" on a
        // US one.
        assert_eq!(typed(FRENCH, &us_keys("qwerty")), "azerty");
        assert_eq!(typed(FRENCH, &us_keys("q;")), "am");
        // The top row: symbols, digits with Shift.
        assert_eq!(typed(FRENCH, &us_keys("1234567890")), "&é\"'(-è_çà");
        assert_eq!(typed(FRENCH, &(30..=39).map(|u| (u, true)).collect::<std::vec::Vec<_>>()), "1234567890");
        assert_eq!(typed(FRENCH, &[(16, false), (54, false), (55, false), (56, false), (100, true)]), ",;:!>");
        assert_eq!(character(FRENCH, 47, 0), None, "a dead key");
        // The accented letters and symbols beside them.
        assert_eq!(typed(FRENCH, &[(52, false), (53, false), (45, true), (48, true), (49, true), (56, true)]), "ù²°£µ§");
        assert_eq!(typed(FRENCH, &[(52, true), (53, true)]), "%");
    }
}
