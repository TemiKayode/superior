//! Dates, times of day and time zones, for clocks: seconds since
//! 1970-01-01 00:00 UTC (what the kernel's `Time` gives) turned into a
//! zone's local date and time.
//!
//! The zones are a small built-in table, each a standard offset from UTC
//! and a daylight-saving rule: the European Union's (an hour ahead from the
//! last Sunday of March to the last Sunday of October, changing at 01:00
//! UTC) or the United States' (an hour ahead from the second Sunday of
//! March, 02:00 local standard time, to the first Sunday of November, 02:00
//! local daylight time).

/// A daylight-saving rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dst {
    None,
    Eu,
    Us,
}

/// A time zone: what clocks call it, its standard offset from UTC in
/// minutes (east positive), and its daylight-saving rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: &'static str,
    pub offset: i32,
    pub dst: Dst,
}

/// The built-in zones, UTC first.
pub const ZONES: [Zone; 6] = [
    Zone { name: "UTC", offset: 0, dst: Dst::None },
    Zone { name: "London", offset: 0, dst: Dst::Eu },
    Zone { name: "Lagos", offset: 60, dst: Dst::None },
    Zone { name: "Berlin", offset: 60, dst: Dst::Eu },
    Zone { name: "New York", offset: -300, dst: Dst::Us },
    Zone { name: "Tokyo", offset: 540, dst: Dst::None },
];

/// Days from 1970-01-01 to `y`-`m`-`d` (Howard Hinnant's civil calendar
/// arithmetic; any proleptic Gregorian date).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01: year, month (1 to 12), day.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

/// The day of the week `days` after 1970-01-01 (a Thursday): 0 is Sunday.
pub fn weekday(days: i64) -> u32 {
    (days + 4).rem_euclid(7) as u32
}

/// The day of month `m` of year `y` that is its `n`th Sunday (from 1), or
/// its last Sunday if `n` is 0.
fn sunday(y: i64, m: u32, n: u32) -> u32 {
    if n == 0 {
        let next = if m == 12 { days_from_civil(y + 1, 1, 1) } else { days_from_civil(y, m + 1, 1) };
        let last = next - 1;
        return civil_from_days(last - weekday(last) as i64).2;
    }
    let first = days_from_civil(y, m, 1);
    1 + (7 - weekday(first)) % 7 + 7 * (n - 1)
}

/// Whether daylight saving is in effect in `zone` at `t` (seconds since
/// 1970, UTC).
pub fn daylight(zone: &Zone, t: i64) -> bool {
    let (y, ..) = civil_from_days(t.div_euclid(86_400));
    let at = |m: u32, d: u32, utc_hour: i64| days_from_civil(y, m, d) * 86_400 + utc_hour * 3600;
    match zone.dst {
        Dst::None => false,
        Dst::Eu => t >= at(3, sunday(y, 3, 0), 1) && t < at(10, sunday(y, 10, 0), 1),
        Dst::Us => {
            // 02:00 local: standard time going on, daylight time coming off.
            let std = -(zone.offset as i64) / 60;
            t >= at(3, sunday(y, 3, 2), 2 + std) && t < at(11, sunday(y, 11, 1), 1 + std)
        }
    }
}

/// `t` (seconds since 1970, UTC) as seconds since 1970 on `zone`'s
/// clocks.
pub fn local(zone: &Zone, t: i64) -> i64 {
    t + zone.offset as i64 * 60 + if daylight(zone, t) { 3600 } else { 0 }
}

const DAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// `t` on `zone`'s clocks as a clock shows it: "Sat 14 Nov 09:41".
pub fn clock(zone: &Zone, t: i64) -> [u8; 16] {
    let l = local(zone, t);
    let days = l.div_euclid(86_400);
    let (_, m, d) = civil_from_days(days);
    let secs = l.rem_euclid(86_400);
    let (h, min) = (secs / 3600, secs / 60 % 60);
    let digit = |v: i64| b'0' + v as u8;
    let mut out = [b' '; 16];
    out[..3].copy_from_slice(DAYS[weekday(days) as usize]);
    out[4..6].copy_from_slice(&[digit(d as i64 / 10), digit(d as i64 % 10)]);
    out[7..10].copy_from_slice(MONTHS[m as usize - 1]);
    out[11..].copy_from_slice(&[digit(h / 10), digit(h % 10), b':', digit(min / 10), digit(min % 10)]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_794_649_260; // 2026-11-14 09:41 UTC

    #[test]
    fn dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2026, 11, 14), 20_771);
        assert_eq!(civil_from_days(20_771), (2026, 11, 14));
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        for d in -800_000..800_000 {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
        assert_eq!(weekday(20_771), 6, "a Saturday");
        assert_eq!(weekday(days_from_civil(2024, 2, 29)), 4, "a Thursday");
    }

    #[test]
    fn sundays() {
        assert_eq!(sunday(2026, 3, 0), 29);
        assert_eq!(sunday(2026, 10, 0), 25);
        assert_eq!(sunday(2026, 3, 2), 8);
        assert_eq!(sunday(2026, 11, 1), 1);
        assert_eq!(sunday(2026, 3, 1), 1);
    }

    #[test]
    fn daylight_saving_changes_on_time() {
        let [_, london, lagos, berlin, new_york, _] = ZONES;
        // The EU's: 2026-03-29 01:00 UTC to 2026-10-25 01:00 UTC.
        assert!(!daylight(&london, 1_774_746_000 - 1) && daylight(&london, 1_774_746_000));
        assert!(daylight(&berlin, 1_792_890_000 - 1) && !daylight(&berlin, 1_792_890_000));
        // The US's: 2026-03-08 07:00 UTC to 2026-11-01 06:00 UTC in New York.
        assert!(!daylight(&new_york, 1_772_953_200 - 1) && daylight(&new_york, 1_772_953_200));
        assert!(daylight(&new_york, 1_793_512_800 - 1) && !daylight(&new_york, 1_793_512_800));
        assert!(!daylight(&lagos, 1_780_000_000));
    }

    #[test]
    fn clocks_show_local_dates_and_times() {
        let show = |z: usize, t: i64| clock(&ZONES[z], t);
        assert_eq!(&show(0, NOW), b"Sat 14 Nov 09:41");
        assert_eq!(&show(2, NOW), b"Sat 14 Nov 10:41");
        assert_eq!(&show(4, NOW), b"Sat 14 Nov 04:41");
        assert_eq!(&show(5, NOW), b"Sat 14 Nov 18:41");
        // A summer time, and a date the zone has already turned over to.
        assert_eq!(&show(3, 1_780_000_000), b"Thu 28 May 22:26");
        assert_eq!(&show(5, NOW + 6 * 3600), b"Sun 15 Nov 00:41");
        assert_eq!(&show(0, 0), b"Thu 01 Jan 00:00");
    }
}
