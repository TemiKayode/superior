//! The interfaces drivers and the services around them speak (spec section
//! 5, "stable driver ABI").
//!
//! Each interface is a module with a `VERSION`: its major version number.
//! A major version is frozen once released: operations and their message
//! layouts never change, only new operations are added. A client states
//! the version it was built for in its first call, and a server that
//! speaks a newer major version serves the old one through an adapter.
//! These are written by hand for now; an IDL compiler that generates them
//! (and C bindings) comes later.
//!
//! Every call is one IPC message: word 0 is the operation, words 1-3 its
//! arguments. Every reply's word 0 is a [`Status`]; capabilities travel
//! with the message.

/// Word 0 of every reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Status {
    Ok = 0,
    /// No such device, BAR, page or vector.
    NotFound = 1,
    /// Another driver has the device.
    InUse = 2,
    /// The caller has not opened a device, or asked for one it may not
    /// have (a register it may not write).
    Denied = 3,
    /// The operation or version is unknown, or an argument is invalid.
    Invalid = 4,
    /// The device failed the request.
    DeviceError = 5,
}

impl Status {
    pub const fn from_u64(n: u64) -> Status {
        match n {
            0 => Status::Ok,
            1 => Status::NotFound,
            2 => Status::InUse,
            3 => Status::Denied,
            5 => Status::DeviceError,
            _ => Status::Invalid,
        }
    }
}

/// The PCI bus server: the one component that touches PCI configuration
/// space. A driver opens one function and gets only that function's BAR
/// pages and MSI vectors; configuration writes go through the server, which
/// allows only the few a driver needs.
pub mod pci {
    pub const VERSION: u64 = 1;

    /// `[OPEN, VERSION, vendor << 16 | device, instance]`: claims the
    /// `instance`th function (from 0) with these IDs, resets it, assigns
    /// its BARs and enables memory decoding (bus mastering stays off).
    /// Opening again (a restarted driver: same badge) resets the device
    /// again first. Reply: `[status, bus << 8 | device << 3 | function,
    /// bitmask of memory BARs present, 0]`.
    pub const OPEN: u64 = 1;
    /// `[BAR_PAGE, bar, page]`: a capability to page `page` of memory BAR
    /// `bar` (a device frame), in the call's accept slot. Reply: `[status,
    /// BAR size in bytes]`.
    pub const BAR_PAGE: u64 = 2;
    /// `[CONFIG_READ, offset]`: a dword of the function's configuration
    /// space. Reply: `[status, value]`.
    pub const CONFIG_READ: u64 = 3;
    /// `[BUS_MASTER, on]`: lets the device do DMA (or stops it).
    pub const BUS_MASTER: u64 = 4;
    /// `[MSIX, on]`: enables MSI-X (the driver programs the table in its
    /// BAR) and disables legacy interrupts.
    pub const MSIX: u64 = 5;
    /// `[MSI_VECTOR, n]`: the function's `n`th MSI vector (an IRQ
    /// capability) in the call's accept slot. The driver asks the kernel
    /// for its message (`IrqMsiMessage`) and programs it into the device.
    pub const MSI_VECTOR: u64 = 6;
}

/// Block devices: what a storage driver serves.
pub mod block {
    pub const VERSION: u64 = 1;
    /// Bytes per sector.
    pub const SECTOR: u64 = 512;

    /// `[INFO, VERSION]`: reply `[status, capacity in sectors, sector
    /// size, 0]`.
    pub const INFO: u64 = 1;
    /// `[READ, first sector, count]` with a frame granted: reads `count`
    /// sectors (at most 8, one page) into the frame by DMA. The frame is
    /// the caller's: the driver hands it back (deletes its copy) before
    /// replying. Reply: `[status]`. Reads are idempotent, so a client may
    /// retry one that failed with `PeerRestarted`.
    pub const READ: u64 = 2;
    /// `[WRITE, first sector, count]` with a frame granted: writes `count`
    /// sectors (at most 8) from the frame. The driver hands the frame back
    /// before replying. A write is not durable until a `FLUSH` after it
    /// succeeds. Idempotent, so it may be retried.
    pub const WRITE: u64 = 3;
    /// `[FLUSH]`: every write that succeeded before it is on stable
    /// storage when it succeeds. Idempotent.
    pub const FLUSH: u64 = 4;
    /// Most sectors one `READ` or `WRITE` moves.
    pub const MAX_SECTORS: u64 = 4096 / SECTOR;
}

/// Files: what the filesystem server serves.
///
/// There is no global namespace: each component sees only its own
/// container of files, chosen by the badge on its capability. A write is
/// acknowledged only once it is committed to the journal on stable
/// storage, so an acknowledged write survives the server, the driver or
/// the whole machine stopping at any instant. Every operation is
/// idempotent, so a client retries one that failed with `PeerRestarted`.
pub mod fs {
    pub const VERSION: u64 = 1;
    /// Bytes in a file name, NUL-padded, packed little-endian into three
    /// message words ([`name`]).
    pub const MAX_NAME: usize = 24;
    /// Bytes in a block; one `READ` or `WRITE` stays inside one.
    pub const BLOCK: u64 = 4096;
    /// Largest file, in bytes.
    pub const MAX_FILE: u64 = 8 * BLOCK;

    /// `[CREATE, name...]`: opens the named file in the caller's container,
    /// making it empty if there is none. Reply `[status, handle, size]`.
    pub const CREATE: u64 = 1;
    /// `[OPEN, name...]`: as `CREATE`, but `NotFound` if there is none.
    pub const OPEN: u64 = 2;
    /// `[READ, handle, offset, length]` with a frame granted: copies the
    /// bytes into the start of the frame. Reply `[status, bytes read]`.
    pub const READ: u64 = 3;
    /// `[WRITE, handle, offset, length]` with a frame granted: writes the
    /// first `length` bytes of the frame. Reply `[status]`, sent only once
    /// the write is durable.
    pub const WRITE: u64 = 4;
    /// `[STAT, handle]`: reply `[status, size]`.
    pub const STAT: u64 = 5;

    /// A file name packed into message words; `None` if it is empty, too
    /// long, or contains a NUL.
    pub fn name(s: &str) -> Option<[u64; 3]> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME || b.contains(&0) {
            return None;
        }
        let mut w = [0u64; 3];
        for (i, &c) in b.iter().enumerate() {
            w[i / 8] |= (c as u64) << (8 * (i % 8));
        }
        Some(w)
    }

    #[cfg(test)]
    #[test]
    fn names_pack_into_three_words() {
        assert_eq!(name("ab"), Some([0x6261, 0, 0]));
        assert_eq!(name("abcdefghi").unwrap()[1], 0x69);
        assert!(name("").is_none());
        assert!(name("0123456789abcdefghijklmnX").is_none());
    }
}

/// The Memory Server: pages of RAM under a per-component quota.
///
/// A component's capability to it is badged by the Component Manager with
/// the component's number (low 16 bits) and its quota in pages (the rest),
/// so neither can be forged. The manager's own capability is unbadged
/// (badge 0) and alone may use [`mem::FAULT`] and [`mem::RELEASE`].
pub mod mem {
    pub const VERSION: u64 = 1;

    /// `[INFO, VERSION]`: reply `[status, quota, pages in use, pages free
    /// in the whole pool]`.
    pub const INFO: u64 = 1;
    /// `[FRAME]` with an accept slot: a zeroed page, granted. Reply
    /// `[status, handle]`; `Denied` over quota, `InUse` if the pool is
    /// empty.
    pub const FRAME: u64 = 2;
    /// `[FREE, handle]`: gives a page from `FRAME` back. Every copy of its
    /// capability is revoked (and unmapped) first.
    pub const FREE: u64 = 3;
    /// Manager only. `[FAULT, component, quota, address]` with the
    /// component's address space lent: maps a zeroed page at `address`
    /// (its heap took a page fault there), charged to the component.
    /// `Denied` over quota.
    pub const FAULT: u64 = 0x10;
    /// Manager only. `[RELEASE, component]`: takes back every page the
    /// component holds (it is being stopped). Reply `[status, pages]`.
    pub const RELEASE: u64 = 0x11;

    /// The badge on component `index`'s capability, with `quota` pages.
    pub const fn badge(index: usize, quota: u64) -> u64 {
        quota << 16 | (index as u64 + 1)
    }

    /// The (component number, quota) a badge carries.
    pub const fn from_badge(badge: u64) -> (u64, u64) {
        (badge & 0xffff, badge >> 16)
    }

    /// Where a component's heap starts (from `USER_BASE`): pages there
    /// appear, zeroed, on first touch.
    pub const HEAP_OFFSET: u64 = 0x2000_0000;
}
