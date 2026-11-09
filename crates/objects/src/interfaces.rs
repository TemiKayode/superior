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
    /// Most sectors one `READ` moves.
    pub const MAX_SECTORS: u64 = 4096 / SECTOR;
}
