//! The time of day, for [`Syscall::Time`]: the machine's real-time clock,
//! read when asked (to the second).
//!
//! [`Syscall::Time`]: superior_objects::abi::Syscall::Time

use crate::arch;

/// Seconds since 1970-01-01 00:00 UTC, if the machine has a clock.
pub fn now() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let (y, mo, d, h, m, s) = arch::rtc()?;
        Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + m * 60 + s)
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch::rtc_seconds()
    }
}

/// Days from 1970-01-01 to `y`-`m`-`d` (a date from 1970 on), by Howard
/// Hinnant's civil calendar arithmetic.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

