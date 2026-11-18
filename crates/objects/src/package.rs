//! Signed app packages: the store on the system disk, and what an app may
//! ask for.
//!
//! A package is a bundle ([`crate::bundle`]) signed like the system
//! ([`crate::bundle::Signed`]), but with the publisher key: the
//! [`KEY_FILE`] in the system bundle, or else in the boot bundle. It holds
//! a `manifest` naming its components and their images. The Component
//! Manager admits a package only if it verifies and asks for nothing an
//! app may not have ([`admit`]): no devices, no services of its own, no
//! manager privileges, no more memory or priority than an app gets, and
//! only the services the system offers apps (`app-service`).
//!
//! The store is [`COUNT`] slots on the disk named by `packages`, after the
//! A/B system slots, each laid out like a system slot: a header sector
//! (magic [`MAGIC`], the bundle's length), then the signed bundle. The
//! manager installs every package in the store at boot; an installer
//! writes one into a free slot and asks the manager to install it, which
//! clears the slot if it refuses, or to put it in place of an older
//! version of the same package ([`admit_replacing`]); of two versions
//! found in the store at boot, the newer is kept.

use crate::ab::{SECTOR, SLOT_FIRST, SLOT_SECTORS};
use crate::manifest::{CapKind, Manifest, Start};

pub const COUNT: usize = 4;
/// Each store slot's size: 512 KiB.
pub const SECTORS: u64 = 1024;
pub const FIRST: u64 = SLOT_FIRST[1] + SLOT_SECTORS;
/// The largest package a slot holds (its header takes a sector).
pub const BYTES: usize = (SECTORS as usize - 1) * SECTOR;
pub const MAGIC: &[u8; 8] = b"SUPPKG01";
/// The bundle entry holding the publisher's Ed25519 public key.
pub const KEY_FILE: &str = "packages.key";

/// Limits on an app's components.
pub const MAX_PRIORITY: u8 = 10;
pub const MAX_MEMORY_BITS: u8 = 20;
pub const MAX_UNTYPED_BITS: u8 = 16;
pub const MAX_CSPACE_BITS: u8 = 8;
pub const MAX_VSPACE_BITS: u8 = 18;

/// Store slot `k`'s first sector (its header).
pub const fn first(k: usize) -> u64 {
    FIRST + k as u64 * SECTORS
}

/// A store slot's header sector: the package's length, if it holds one
/// that fits.
pub fn length(header: &[u8; SECTOR]) -> Option<usize> {
    if &header[..8] != MAGIC {
        return None;
    }
    let len = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    (len > 0 && len <= BYTES).then_some(len)
}

/// The header sector for a package of `len` bytes.
pub fn header(len: usize) -> [u8; SECTOR] {
    let mut h = [0; SECTOR];
    h[..8].copy_from_slice(MAGIC);
    h[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    h
}

/// Why a package was refused, and the word at fault (a component, a
/// service or a device).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal<'a> {
    pub why: &'static str,
    pub word: &'a str,
    /// Another of that name is installed already (not a matter of
    /// privilege).
    pub taken: bool,
}

/// Checks a package's manifest `pkg` against the running system's
/// `host`: what an app may ask for.
pub fn admit<'a>(pkg: &Manifest<'a>, host: &Manifest<'_>) -> Result<(), Refusal<'a>> {
    admit_replacing(pkg, host, |_| false)
}

/// [`admit`], for a package that replaces the components of `host` that
/// `replaced` picks (by index): their names are not taken.
pub fn admit_replacing<'a>(
    pkg: &Manifest<'a>,
    host: &Manifest<'_>,
    replaced: impl Fn(usize) -> bool,
) -> Result<(), Refusal<'a>> {
    let no = |why, word| Err(Refusal { why, word, taken: false });
    if pkg.configures_system() {
        return no("a package may not configure the system", "");
    }
    if pkg.is_empty() {
        return no("it has no components", "");
    }
    for (_, c) in pkg.iter() {
        let name = c.name;
        if host.iter().any(|(i, h)| h.name == name && !replaced(i)) {
            return Err(Refusal { why: "a component of that name is installed", word: name, taken: true });
        }
        if c.start != Start::Boot {
            return no("an app starts when it is installed", name);
        }
        if c.injector || c.power || c.power_control || c.update_control || c.install_control || c.launch_control {
            return no("asks for a manager privilege", name);
        }
        if c.heap_pages > 0 || c.quota_pages > 0 {
            return no("asks for a heap", name);
        }
        if c.priority > MAX_PRIORITY {
            return no("priority above an app's", name);
        }
        if c.memory_bits > MAX_MEMORY_BITS || c.cspace_bits > MAX_CSPACE_BITS || c.vspace_bits > MAX_VSPACE_BITS {
            return no("more memory than an app may have", name);
        }
        for cap in c.caps() {
            match cap.kind {
                CapKind::Uses(s) if !host.offers(s) => return no("uses a service not offered to apps", s),
                CapKind::Uses(_) | CapKind::Notification => {}
                CapKind::Untyped(bits) if bits <= MAX_UNTYPED_BITS => {}
                CapKind::Untyped(_) => return no("more memory than an app may have", name),
                CapKind::Provides(s) => return no("provides a service", s),
                CapKind::Manages(s) => return no("asks to manage a service", s),
                CapKind::Device(d) => return no("asks for a device", d),
                CapKind::Control | CapKind::State | CapKind::Shared(_) | CapKind::Spare => {
                    return no("asks for a manager privilege", name);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "
app-service report
component disk
  image disk
  provides block 0
component installer
  image installer
  provides report 0
";

    fn check(pkg: &str) -> Result<(), Refusal<'_>> {
        let host = Manifest::parse(HOST).unwrap();
        let pkg = Manifest::parse_unchecked(pkg).unwrap();
        admit(&pkg, &host)
    }

    #[test]
    fn an_app_that_asks_for_little() {
        assert_eq!(check("component app\n image app\n uses report 0\n notification 1\n untyped 16 2\n"), Ok(()));
    }

    #[test]
    fn what_an_app_may_not_have() {
        let why = |pkg| check(pkg).unwrap_err().why;
        assert_eq!(why("component app\n image app\n uses block 0\n"), "uses a service not offered to apps");
        assert_eq!(why("component app\n image app\n device pci-config 1\n"), "asks for a device");
        assert_eq!(why("component app\n image app\n provides x 0\n"), "provides a service");
        assert_eq!(why("component app\n image app\n control 1\n"), "asks for a manager privilege");
        assert_eq!(why("component app\n image app\n install-control\n"), "asks for a manager privilege");
        assert_eq!(why("component app\n image app\n launch-control\n"), "asks for a manager privilege");
        assert_eq!(why("component app\n image app\n manages report 0\n"), "asks to manage a service");
        assert_eq!(why("component app\n image app\n start launch\n"), "an app starts when it is installed");
        assert_eq!(why("component app\n image app\n priority 11\n"), "priority above an app's");
        assert_eq!(why("component app\n image app\n untyped 17 1\n"), "more memory than an app may have");
        assert_eq!(why("component app\n image app\n memory 21\n"), "more memory than an app may have");
        assert_eq!(why("app-service block\ncomponent app\n image app\n"), "a package may not configure the system");
        assert_eq!(why(""), "it has no components");
        let taken = check("component installer\n image app\n").unwrap_err();
        assert!(taken.taken && taken.word == "installer");
    }

    #[test]
    fn a_replacement_may_take_the_names_it_replaces() {
        let host = Manifest::parse(HOST).unwrap();
        let pkg = Manifest::parse_unchecked("component installer\n image app\n").unwrap();
        let installer = host.iter().find(|(_, c)| c.name == "installer").unwrap().0;
        assert_eq!(admit_replacing(&pkg, &host, |i| i == installer), Ok(()));
        assert!(admit_replacing(&pkg, &host, |i| i != installer).unwrap_err().taken);
        // What it asks for is checked all the same.
        let pkg = Manifest::parse_unchecked("component installer\n image app\n device pci-config 1\n").unwrap();
        assert_eq!(admit_replacing(&pkg, &host, |_| true).unwrap_err().why, "asks for a device");
    }

    #[test]
    fn store_headers() {
        assert_eq!(length(&header(4321)), Some(4321));
        assert_eq!(length(&header(BYTES + 1)), None);
        assert_eq!(length(&crate::ab::slot_header(10)), None, "a system slot is not a package");
        assert_eq!(first(1), FIRST + SECTORS);
    }
}
