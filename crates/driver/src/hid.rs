//! USB HID report descriptors: where a pointing device puts its buttons,
//! its X and Y (relative, as a mouse's, or absolute, as a tablet's), its
//! wheel and its horizontal wheel in the reports it sends.
//!
//! [`pointer`] reads a report descriptor (HID 1.11, section 6.2.2) and
//! finds the input report that holds X: the [`Pointer`] layout, with
//! which [`Field::read`] takes each value out of a report. Only what a
//! pointer needs is kept; array items (a keyboard's keys), output and
//! feature reports are passed over.

/// A value in a report: where it is, how wide, and its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// The first bit, from the start of the report after its ID byte.
    pub bit: u16,
    /// Its width in bits (1 to 32).
    pub size: u8,
    /// Its logical range: a negative minimum makes it signed.
    pub min: i32,
    pub max: i32,
    /// A change since the last report (a mouse's motion, a wheel's
    /// steps), not where it is.
    pub relative: bool,
}

impl Field {
    /// The value in `report` (its ID byte, if it has one, taken off);
    /// `None` if the report is too short.
    pub fn read(&self, report: &[u8]) -> Option<i32> {
        let (bit, size) = (self.bit as usize, self.size as usize);
        if size == 0 || size > 32 || bit + size > report.len() * 8 {
            return None;
        }
        let mut v: u64 = 0;
        for i in 0..size {
            let b = bit + i;
            v |= ((report[b / 8] >> (b % 8)) as u64 & 1) << i;
        }
        Some(if self.min < 0 && size < 64 && v >> (size - 1) & 1 == 1 {
            (v | !0u64 << size) as i64 as i32
        } else {
            v as u32 as i32
        })
    }

    /// An absolute value scaled to 0..=`to` over its logical range.
    pub fn scale(&self, v: i32, to: u64) -> u64 {
        let span = self.max as i64 - self.min as i64;
        if span <= 0 {
            return 0;
        }
        ((v as i64 - self.min as i64).clamp(0, span) as u64 * to) / span as u64
    }
}

/// The buttons a layout can name.
pub const BUTTONS: usize = 8;

/// Where a pointing device's input report keeps what it says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    /// The report's ID, its first byte, if the device numbers its reports.
    pub id: Option<u8>,
    /// The report's length in bytes, the ID byte included.
    pub bytes: usize,
    /// Buttons 1 to 8 (left, right, middle, then others).
    pub buttons: [Option<Field>; BUTTONS],
    pub x: Field,
    pub y: Field,
    pub wheel: Option<Field>,
    /// The horizontal wheel (AC Pan, on the consumer page).
    pub pan: Option<Field>,
}

impl Pointer {
    /// How many buttons it has.
    pub fn button_count(&self) -> usize {
        self.buttons.iter().filter(|b| b.is_some()).count()
    }

    /// The report without its ID byte, if it is this layout's report.
    pub fn body<'a>(&self, report: &'a [u8]) -> Option<&'a [u8]> {
        match self.id {
            Some(id) => (report.first() == Some(&id)).then(|| &report[1..]),
            None => Some(report),
        }
    }
}

const X: u32 = 0x0001_0030;
const Y: u32 = 0x0001_0031;
const WHEEL: u32 = 0x0001_0038;
const PAN: u32 = 0x000c_0238;
const BUTTON_PAGE: u32 = 0x0009;

#[derive(Clone, Copy, Default)]
struct Globals {
    page: u32,
    min: i32,
    max: i32,
    size: u32,
    count: u32,
    id: u8,
}

/// The fields found so far, each with the report ID it is in.
#[derive(Default)]
struct Found {
    x: Option<(u8, Field)>,
    y: Option<(u8, Field)>,
    wheel: Option<(u8, Field)>,
    pan: Option<(u8, Field)>,
    buttons: [Option<(u8, Field)>; BUTTONS],
}

/// The pointer layout a report descriptor gives, if it has a report with
/// X and Y in it.
pub fn pointer(d: &[u8]) -> Option<Pointer> {
    let mut g = Globals::default();
    let mut stack = [Globals::default(); 4];
    let mut depth = 0;
    let mut usages = [0u32; 16];
    let mut n_usages = 0;
    let mut range: Option<(u32, u32)> = None;
    // Bits so far in each report, by its ID.
    let mut bits = [0u32; 256];
    let mut numbered = false;
    let mut found = Found::default();
    let mut at = 0;
    while at < d.len() {
        let prefix = d[at];
        if prefix == 0xfe {
            // A long item: its size, its tag, its data.
            let size = *d.get(at + 1)? as usize;
            at += 3 + size;
            continue;
        }
        let size = [0, 1, 2, 4][(prefix & 3) as usize];
        let raw = d.get(at + 1..at + 1 + size)?;
        at += 1 + size;
        let mut u = 0u32;
        for (i, &b) in raw.iter().enumerate() {
            u |= (b as u32) << (8 * i);
        }
        let signed = match size {
            1 => u as u8 as i8 as i32,
            2 => u as u16 as i16 as i32,
            _ => u as i32,
        };
        let usage = |u: u32, page: u32| if size == 4 { u } else { page << 16 | u };
        match prefix & 0xfc {
            // Main items.
            0x80 => {
                let id = g.id;
                let width = g.size * g.count;
                let constant = u & 1 != 0;
                let variable = u & 2 != 0;
                let relative = u & 4 != 0;
                if !constant && variable && g.size >= 1 && g.size <= 32 {
                    for i in 0..g.count {
                        let what = match range {
                            Some((lo, hi)) => Some((lo + i).min(hi)),
                            None if n_usages > 0 => Some(usages[(i as usize).min(n_usages - 1)]),
                            None => None,
                        };
                        let Some(what) = what else { continue };
                        let bit = bits[id as usize] + i * g.size;
                        let Ok(bit) = u16::try_from(bit) else { continue };
                        let max = if g.min < 0 { g.max } else { g.max & mask(g.size) };
                        let f = Field { bit, size: g.size as u8, min: g.min, max, relative };
                        let slot = match what {
                            X => &mut found.x,
                            Y => &mut found.y,
                            WHEEL => &mut found.wheel,
                            PAN => &mut found.pan,
                            w if w >> 16 == BUTTON_PAGE && (1..=BUTTONS as u32).contains(&(w & 0xffff)) => {
                                &mut found.buttons[(w & 0xffff) as usize - 1]
                            }
                            _ => continue,
                        };
                        if slot.is_none() {
                            *slot = Some((id, f));
                        }
                    }
                }
                bits[id as usize] += width;
                (n_usages, range) = (0, None);
            }
            // Output, feature, collection, end of collection.
            0x90 | 0xb0 | 0xa0 | 0xc0 => (n_usages, range) = (0, None),
            // Global items.
            0x04 => g.page = u,
            0x14 => g.min = signed,
            0x24 => g.max = signed,
            0x74 => g.size = u,
            0x84 => {
                g.id = u as u8;
                numbered = true;
            }
            0x94 => g.count = u,
            0xa4 => {
                *stack.get_mut(depth)? = g;
                depth += 1;
            }
            0xb4 => {
                depth = depth.checked_sub(1)?;
                g = stack[depth];
            }
            // Local items.
            0x08 => {
                if n_usages < usages.len() {
                    usages[n_usages] = usage(u, g.page);
                    n_usages += 1;
                }
            }
            0x18 => range = Some((usage(u, g.page), range.map_or(u32::MAX, |r| r.1))),
            0x28 => range = Some((range.map_or(0, |r| r.0), usage(u, g.page))),
            _ => {}
        }
    }
    let (id, x) = found.x?;
    let in_report = |f: Option<(u8, Field)>| f.filter(|f| f.0 == id).map(|f| f.1);
    let y = in_report(found.y)?;
    let mut buttons = [None; BUTTONS];
    for (b, f) in buttons.iter_mut().zip(found.buttons) {
        *b = in_report(f);
    }
    Some(Pointer {
        id: numbered.then_some(id),
        bytes: (bits[id as usize] as usize).div_ceil(8) + numbered as usize,
        buttons,
        x,
        y,
        wheel: in_report(found.wheel),
        pan: in_report(found.pan),
    })
}

fn mask(size: u32) -> i32 {
    if size >= 32 { -1 } else { ((1u64 << size) - 1) as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mouse: three buttons and padding, then X, Y and the wheel as
    /// signed bytes (the shape of QEMU's usb-mouse).
    const MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, // page, mouse, app, pointer, physical
        0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, // buttons 1-3, 0..1
        0x95, 0x03, 0x75, 0x01, 0x81, 0x02, // 3 x 1 bit, data var abs
        0x95, 0x01, 0x75, 0x05, 0x81, 0x01, // 5 bits constant
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, // X, Y, wheel
        0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, // -127..127, 3 bytes, relative
        0xc0, 0xc0,
    ];

    /// A tablet: three buttons, then absolute X and Y (0..0x7fff, 16 bits),
    /// a relative wheel and a horizontal wheel on the consumer page.
    const TABLET: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, //
        0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, //
        0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01, //
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x00, 0x26, 0xff, 0x7f, // X, Y, 0..0x7fff
        0x35, 0x00, 0x46, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x02, 0x81, 0x02, // physical, 2 x 16, abs
        0x05, 0x01, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x35, 0x00, 0x45, 0x00, //
        0x75, 0x08, 0x95, 0x01, 0x81, 0x06, // wheel, relative
        0x05, 0x0c, 0x0a, 0x38, 0x02, 0x95, 0x01, 0x81, 0x06, // AC Pan, relative
        0xc0, 0xc0,
    ];

    #[test]
    fn a_mouse() {
        let p = pointer(MOUSE).unwrap();
        assert_eq!(p.id, None);
        assert_eq!(p.bytes, 4);
        assert_eq!(p.button_count(), 3);
        assert_eq!(p.x, Field { bit: 8, size: 8, min: -127, max: 127, relative: true });
        assert_eq!(p.y.bit, 16);
        assert_eq!(p.wheel.unwrap().bit, 24);
        assert_eq!(p.pan, None);
        let report = [0b101, 0xfb, 7, 0xff];
        assert_eq!(p.buttons[0].unwrap().read(&report), Some(1));
        assert_eq!(p.buttons[1].unwrap().read(&report), Some(0));
        assert_eq!(p.buttons[2].unwrap().read(&report), Some(1));
        assert_eq!(p.x.read(&report), Some(-5));
        assert_eq!(p.y.read(&report), Some(7));
        assert_eq!(p.wheel.unwrap().read(&report), Some(-1));
    }

    #[test]
    fn a_tablet() {
        let p = pointer(TABLET).unwrap();
        assert_eq!(p.bytes, 7);
        assert_eq!(p.x, Field { bit: 8, size: 16, min: 0, max: 0x7fff, relative: false });
        assert_eq!(p.y.bit, 24);
        assert_eq!(p.wheel.unwrap().bit, 40);
        assert_eq!(p.pan.unwrap(), Field { bit: 48, size: 8, min: -127, max: 127, relative: true });
        let report = [1, 0xff, 0x7f, 0x00, 0x40, 1, 0xfe];
        assert_eq!(p.x.read(&report), Some(0x7fff));
        assert_eq!(p.x.scale(0x7fff, 0xffff), 0xffff);
        assert_eq!(p.y.read(&report), Some(0x4000));
        assert_eq!(p.y.scale(0, 0xffff), 0);
        assert_eq!(p.pan.unwrap().read(&report), Some(-2));
    }

    #[test]
    fn numbered_reports_and_a_keyboard_beside_it() {
        // Report 1 a keyboard (modifier bits and a key array), report 2 a
        // mouse with buttons given one usage each.
        let d = [
            0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, //
            0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, //
            0x95, 0x06, 0x75, 0x08, 0x25, 0x65, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0, //
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, //
            0x05, 0x09, 0x09, 0x01, 0x09, 0x02, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02, //
            0x95, 0x06, 0x81, 0x03, //
            0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x01, 0x80, 0x26, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x02, 0x81,
            0x06, 0xc0,
        ];
        let p = pointer(&d).unwrap();
        assert_eq!(p.id, Some(2));
        assert_eq!(p.bytes, 6);
        assert_eq!(p.button_count(), 2);
        assert_eq!(p.x, Field { bit: 8, size: 16, min: -32767, max: 32767, relative: true });
        assert_eq!(p.body(&[1, 0, 0]), None);
        let body = p.body(&[2, 0b10, 0xfe, 0xff, 3, 0]).unwrap();
        assert_eq!(p.buttons[1].unwrap().read(body), Some(1));
        assert_eq!(p.x.read(body), Some(-2));
        assert_eq!(p.y.read(body), Some(3));
    }

    #[test]
    fn no_pointer_in_a_keyboard_or_garbage() {
        let keyboard = [0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xc0];
        assert_eq!(pointer(&keyboard), None);
        assert_eq!(pointer(&[0x05]), None);
        assert_eq!(pointer(&[0xb4]), None);
        assert_eq!(pointer(&[]), None);
    }
}
