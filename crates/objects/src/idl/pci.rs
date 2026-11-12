// Generated from interfaces/pci.idl by the IDL compiler (`cargo xtask idl`).
// Do not edit: change the description and generate again.

/// The PCI bus server's interface: what a driver asks of it for the one
/// function it opens. The capabilities that travel with some of these (an
/// IOMMU domain with OPEN, a BAR page, an interrupt line) arrive in the
/// slot the caller names as the call's accept slot.
pub mod pci {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 1;

    /// Claims the `instance`th function (from 0) with these IDs (`ids`:
    /// vendor << 16 | device), resets it, assigns its BARs and enables
    /// decoding (bus mastering stays off). Its IOMMU domain, empty, comes with
    /// the reply. `location`: bus << 8 | device << 3 | function; the BARs are
    /// bitmasks.
    pub const OPEN: u64 = 1;
    /// The message of a `OPEN` call.
    pub const fn open(ids: u64, instance: u64) -> [u64; 4] {
        [OPEN, VERSION, ids, instance]
    }
    /// What a `OPEN` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenReply {
        pub location: u64,
        pub memory_bars: u64,
        pub io_bars: u64,
    }
    /// Reads a `OPEN` reply: its results, or the status it failed with.
    pub fn open_reply(m: [u64; 4]) -> Result<OpenReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(OpenReply {
                location: m[1],
                memory_bars: m[2],
                io_bars: m[3],
            }),
            s => Err(s),
        }
    }

    /// A capability to page `page` of memory BAR `bar` (a device frame).
    pub const BAR_PAGE: u64 = 2;
    /// The message of a `BAR_PAGE` call.
    pub const fn bar_page(bar: u64, page: u64) -> [u64; 4] {
        [BAR_PAGE, bar, page, 0]
    }
    /// What a `BAR_PAGE` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BarPageReply {
        pub size: u64,
    }
    /// Reads a `BAR_PAGE` reply: its results, or the status it failed with.
    pub fn bar_page_reply(m: [u64; 4]) -> Result<BarPageReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(BarPageReply {
                size: m[1],
            }),
            s => Err(s),
        }
    }

    /// A dword of the function's configuration space.
    pub const CONFIG_READ: u64 = 3;
    /// The message of a `CONFIG_READ` call.
    pub const fn config_read(offset: u64) -> [u64; 4] {
        [CONFIG_READ, offset, 0, 0]
    }
    /// What a `CONFIG_READ` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ConfigReadReply {
        pub value: u64,
    }
    /// Reads a `CONFIG_READ` reply: its results, or the status it failed with.
    pub fn config_read_reply(m: [u64; 4]) -> Result<ConfigReadReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(ConfigReadReply {
                value: m[1],
            }),
            s => Err(s),
        }
    }

    /// Lets the device do DMA (or stops it).
    pub const BUS_MASTER: u64 = 4;
    /// The message of a `BUS_MASTER` call.
    pub const fn bus_master(on: u64) -> [u64; 4] {
        [BUS_MASTER, on, 0, 0]
    }

    /// Enables MSI-X (the driver programs the table in its BAR) and disables
    /// legacy interrupts.
    pub const MSIX: u64 = 5;
    /// The message of a `MSIX` call.
    pub const fn msix(on: u64) -> [u64; 4] {
        [MSIX, on, 0, 0]
    }

    /// The function's `n`th MSI vector (an IRQ capability).
    pub const MSI_VECTOR: u64 = 6;
    /// The message of a `MSI_VECTOR` call.
    pub const fn msi_vector(n: u64) -> [u64; 4] {
        [MSI_VECTOR, n, 0, 0]
    }

    /// As OPEN, for the `instance`th function of a class (`class`: class << 16
    /// | subclass << 8 | interface), whoever made it.
    pub const OPEN_CLASS: u64 = 7;
    /// The message of a `OPEN_CLASS` call.
    pub const fn open_class(class: u64, instance: u64) -> [u64; 4] {
        [OPEN_CLASS, VERSION, class, instance]
    }
    /// What a `OPEN_CLASS` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenClassReply {
        pub location: u64,
        pub memory_bars: u64,
        pub io_bars: u64,
    }
    /// Reads a `OPEN_CLASS` reply: its results, or the status it failed with.
    pub fn open_class_reply(m: [u64; 4]) -> Result<OpenClassReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(OpenClassReply {
                location: m[1],
                memory_bars: m[2],
                io_bars: m[3],
            }),
            s => Err(s),
        }
    }

    /// For a function with plain MSI: has the bus server write vector 0's
    /// message into its MSI capability and enable it, or disable it.
    pub const MSI: u64 = 8;
    /// The message of a `MSI` call.
    pub const fn msi(on: u64) -> [u64; 4] {
        [MSI, on, 0, 0]
    }

    /// For a function with no MSI: its legacy interrupt line (an IRQ
    /// capability), and which of the bus's four wires it is.
    pub const INTX: u64 = 9;
    /// The message of a `INTX` call.
    pub const fn intx() -> [u64; 4] {
        [INTX, 0, 0, 0]
    }
    /// What a `INTX` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IntxReply {
        pub wire: u64,
    }
    /// Reads a `INTX` reply: its results, or the status it failed with.
    pub fn intx_reply(m: [u64; 4]) -> Result<IntxReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(IntxReply {
                wire: m[1],
            }),
            s => Err(s),
        }
    }

    /// Reads `width` bytes (1, 2 or 4) at `offset` in I/O BAR `bar`.
    pub const IO_READ: u64 = 10;
    /// The message of a `IO_READ` call.
    pub const fn io_read(bar: u64, offset: u64, width: u64) -> [u64; 4] {
        [IO_READ, bar, offset, width]
    }
    /// What a `IO_READ` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IoReadReply {
        pub value: u64,
    }
    /// Reads a `IO_READ` reply: its results, or the status it failed with.
    pub fn io_read_reply(m: [u64; 4]) -> Result<IoReadReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(IoReadReply {
                value: m[1],
            }),
            s => Err(s),
        }
    }

    /// Writes likewise (`bar_and_width`: bar | width << 8).
    pub const IO_WRITE: u64 = 11;
    /// The message of a `IO_WRITE` call.
    pub const fn io_write(bar_and_width: u64, offset: u64, value: u64) -> [u64; 4] {
        [IO_WRITE, bar_and_width, offset, value]
    }

    /// Gives the function back: reset as for OPEN, and anyone's to open.
    pub const CLOSE: u64 = 12;
    /// The message of a `CLOSE` call.
    pub const fn close() -> [u64; 4] {
        [CLOSE, 0, 0, 0]
    }

    /// A capability to all of memory BAR `bar` as one device frame, its pages
    /// in a row (mapped from one address on): for a BAR too large to take a
    /// page at a time, such as a video card's memory.
    pub const BAR_FRAME: u64 = 13;
    /// The message of a `BAR_FRAME` call.
    pub const fn bar_frame(bar: u64) -> [u64; 4] {
        [BAR_FRAME, bar, 0, 0]
    }
    /// What a `BAR_FRAME` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BarFrameReply {
        pub size: u64,
    }
    /// Reads a `BAR_FRAME` reply: its results, or the status it failed with.
    pub fn bar_frame_reply(m: [u64; 4]) -> Result<BarFrameReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(BarFrameReply {
                size: m[1],
            }),
            s => Err(s),
        }
    }
}
