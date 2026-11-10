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
    /// The name is already taken.
    Exists = 6,
    /// The directory is not empty.
    NotEmpty = 7,
    /// A path component, or the target, is not a directory.
    NotDir = 8,
    /// The target is a directory.
    IsDir = 9,
    /// No free blocks or inodes, or the file would pass its largest size;
    /// or no room to queue a frame.
    NoSpace = 10,
    /// Nothing waiting to be received.
    Empty = 11,
    /// The address could not be resolved (no answer to ARP) or no driver
    /// is there to send through; the caller may try again.
    Unreachable = 12,
    /// A path went through too many symbolic links (a loop, likely), or
    /// `NOFOLLOW` met one.
    TooManyLinks = 13,
    /// Nothing listens at the address a TCP connection was made to.
    Refused = 14,
    /// The TCP connection was reset: by the peer, or because the network
    /// server restarted and forgot it.
    Reset = 15,
    /// The TCP peer stopped answering.
    TimedOut = 16,
}

impl Status {
    pub const fn from_u64(n: u64) -> Status {
        match n {
            0 => Status::Ok,
            1 => Status::NotFound,
            2 => Status::InUse,
            3 => Status::Denied,
            5 => Status::DeviceError,
            6 => Status::Exists,
            7 => Status::NotEmpty,
            8 => Status::NotDir,
            9 => Status::IsDir,
            10 => Status::NoSpace,
            11 => Status::Empty,
            12 => Status::Unreachable,
            13 => Status::TooManyLinks,
            14 => Status::Refused,
            15 => Status::Reset,
            16 => Status::TimedOut,
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
    /// `[OPEN_CLASS, VERSION, class << 16 | subclass << 8 | interface,
    /// instance]`: as `OPEN`, but claims the `instance`th function of
    /// this class, whoever made it (a class driver: NVMe, xHCI, AHCI).
    pub const OPEN_CLASS: u64 = 7;
    /// `[MSI, on]`: for a function with plain MSI rather than MSI-X: the
    /// bus server writes the message of the function's vector 0 (taken
    /// first with `MSI_VECTOR`) into its MSI capability and enables it,
    /// one vector, legacy interrupts off; or disables it.
    pub const MSI: u64 = 8;
}

/// Block devices: what a storage driver serves.
pub mod block {
    pub const VERSION: u64 = 1;
    /// Bytes per sector.
    pub const SECTOR: u64 = 512;

    /// A driver serves one or more units (NVMe namespaces; a virtio or
    /// AHCI disk is one unit), numbered from 0; calls name one in their
    /// last word, so a client that knows of none uses unit 0.
    ///
    /// `[INFO, VERSION, unit]`: reply `[status, the unit's capacity in
    /// sectors, sector size, how many units there are]`; `NotFound` for a
    /// unit there is not.
    pub const INFO: u64 = 1;
    /// `[READ, first sector, count, unit]` with a frame granted: reads `count`
    /// sectors (at most 8, one page) into the frame by DMA. The frame is
    /// the caller's: the driver hands it back (deletes its copy) before
    /// replying. Reply: `[status]`. Reads are idempotent, so a client may
    /// retry one that failed with `PeerRestarted`.
    pub const READ: u64 = 2;
    /// `[WRITE, first sector, count, unit]` with a frame granted: writes `count`
    /// sectors (at most 8) from the frame. The driver hands the frame back
    /// before replying. A write is not durable until a `FLUSH` after it
    /// succeeds. Idempotent, so it may be retried.
    pub const WRITE: u64 = 3;
    /// `[FLUSH]`: every write that succeeded before it, to any unit, is on
    /// stable storage when it succeeds. Idempotent.
    pub const FLUSH: u64 = 4;
    /// Most sectors one `READ` or `WRITE` moves.
    pub const MAX_SECTORS: u64 = 4096 / SECTOR;
}

/// Network interfaces: what a NIC driver serves (to the network server).
///
/// Frames are whole Ethernet frames (destination, source, type, payload;
/// no FCS), at most [`nic::MAX_FRAME`] bytes, at the start of a frame
/// (memory page) lent with the call; the driver copies them, so the page
/// comes back with the reply.
pub mod nic {
    pub const VERSION: u64 = 1;
    /// The largest frame: 1500 bytes of payload and a 14-byte header.
    pub const MAX_FRAME: u64 = 1514;

    /// `[INFO, VERSION]`: reply `[status, MAC address (its six bytes, the
    /// first the most significant, in the low 48 bits), MAX_FRAME, 0]`.
    pub const INFO: u64 = 1;
    /// `[ATTACH]` with a notification granted: the driver signals it
    /// whenever received frames are waiting. A restarted driver has lost
    /// it: `RECV` says so, and the caller attaches again.
    pub const ATTACH: u64 = 2;
    /// `[RECV]` with a frame lent: the oldest received frame, copied into
    /// it. Reply `[status, length, attached, 0]`: `Empty` if none is
    /// waiting; `attached` is 0 if no notification is attached.
    pub const RECV: u64 = 3;
    /// `[SEND, length]` with a frame lent: queues the frame at its start
    /// for transmission. Reply `[status]`: `NoSpace` if the transmit
    /// queue is full.
    pub const SEND: u64 = 4;
}

/// The network: what the network server serves. IPv4 with ICMP echo, UDP
/// and TCP; each socket belongs to the client that bound it.
///
/// An address and port travel in one word, [`net::addr`]: the IPv4
/// address (its first byte the most significant) shifted up 16 bits, and
/// the port (or, for ICMP echo, the sequence number) in the low 16.
/// Payloads are at the start of a frame lent with the call.
///
/// A socket comes with a notification, granted with the reply to
/// `UDP_BIND` or `ICMP_BIND`: the server signals it when something
/// arrives, and its deletion (the server restarted, or the socket closed)
/// wakes a client waiting on it with `ObjectDestroyed`. The client may
/// also set a `TimerSignal` on it to wait with a timeout. A restarted
/// server has no sockets: calls on old handles answer `NotFound` (or fail
/// with `PeerRestarted`), and the client binds again. Datagrams are not
/// reliable: one may be lost at any time, and the client resends.
///
/// TCP connections are reliable streams while they last, but the server
/// is crash-only: a restart forgets them (the peer is reset when it next
/// sends), and the client connects again and picks up where its own
/// protocol lets it. `SEND` and `RECV` on a connection never block:
/// `Empty` means "wait for the notification". A connection whose peer
/// reset it, or which timed out, answers `Reset` or `TimedOut` (or
/// `Refused`, for one nothing listened for) until it is closed.
pub mod net {
    pub const VERSION: u64 = 1;
    /// The largest UDP payload in one unfragmented 1500-byte IPv4 packet.
    pub const MAX_PAYLOAD: u64 = 1472;
    /// The largest payload a socket sends or receives: bigger than
    /// `MAX_PAYLOAD`, it goes (and arrives) in IPv4 fragments.
    pub const MAX_DATAGRAM: u64 = 4000;

    /// `[INFO, VERSION]`: reply `[status, this host's address (IPv4, as
    /// in addr), its MAC address, the gateway's address]`; `Unreachable`
    /// while the server has no address yet (DHCP has not answered).
    pub const INFO: u64 = 1;
    /// `[UDP_BIND, port]`: a UDP socket on `port` (0: any free one). Reply
    /// `[status, handle, port]` and the socket's notification; `InUse` if
    /// the port is taken, `NoSpace` if every socket is.
    pub const UDP_BIND: u64 = 2;
    /// `[ICMP_BIND]`: a socket for ICMP echo: requests sent through it
    /// carry its identifier, and the replies arrive on it. Reply `[status,
    /// handle]` and the socket's notification.
    pub const ICMP_BIND: u64 = 3;
    /// On a TCP connection, `[SEND, handle, 0, length]` queues up to
    /// `length` bytes of the frame (at most a page). Reply `[status, bytes
    /// taken]`: `Empty` if none fit (wait for the notification).
    ///
    /// `[SEND, handle, address, length]` with a frame lent: sends a UDP
    /// datagram from the socket to `address`, or an ICMP echo request
    /// with the sequence number in its low 16 bits; the payload is the
    /// first `length` bytes of the frame, at most `MAX_DATAGRAM`. Reply
    /// `[status]`: `Unreachable` if the next hop did not answer ARP (the
    /// datagram is dropped), or for a datagram sent in fragments, whose
    /// next hop's address is not yet known (it is asked for).
    pub const SEND: u64 = 4;
    /// `[RECV, handle]` with a frame lent: the oldest datagram (or echo
    /// reply payload) that arrived on the socket, copied into the frame.
    /// On a TCP connection, what has arrived in order, up to a page:
    /// `[status, length, peer address]`, a length of 0 meaning the peer
    /// has sent all it will.
    /// Reply `[status, length, source address]`; `Empty` if none is
    /// waiting. A socket keeps the last few; more are dropped.
    pub const RECV: u64 = 5;
    /// `[CLOSE, handle]`: closes the socket; its notification is deleted.
    /// A TCP connection is closed gracefully (a FIN after what is queued,
    /// which the server goes on sending); a listening socket's connections
    /// not yet accepted are reset.
    pub const CLOSE: u64 = 6;
    /// `[LEASE, VERSION]`: reply `[status, the netmask (IPv4, as a 32-bit
    /// number), the DNS server's address (as in addr), seconds left on the
    /// DHCP lease]`; `Unreachable` while there is none.
    pub const LEASE: u64 = 7;
    /// `[STATS, VERSION]`: reply `[status, datagrams reassembled from
    /// fragments, datagrams sent in fragments, datagrams dropped half
    /// reassembled]`, counted across the server's restarts.
    pub const STATS: u64 = 8;
    /// `[TCP_CONNECT, address]`: opens a TCP connection to `address`
    /// from a free port. Reply `[status, handle, local port]` and the
    /// connection's notification, signalled once it is established (or
    /// failed), and then whenever data or room arrives. `SEND` answers
    /// `Empty` until it is established.
    pub const TCP_CONNECT: u64 = 9;
    /// `[TCP_LISTEN, port]`: listens for TCP connections on `port`. Reply
    /// `[status, handle, port]` and a notification signalled when a
    /// connection is ready to accept; `InUse` if the port is taken.
    pub const TCP_LISTEN: u64 = 10;
    /// `[TCP_ACCEPT, listening handle]`: the oldest connection made to
    /// it. Reply `[status, handle, peer address]` and the connection's
    /// notification; `Empty` if none is waiting.
    pub const TCP_ACCEPT: u64 = 11;
    /// `[TCP_SHUTDOWN, handle]`: no more data will be sent; the peer gets
    /// a FIN after what is queued. Receiving goes on.
    pub const TCP_SHUTDOWN: u64 = 12;
    /// `[TCP_STATE, handle]`: reply `[status, state (TCP_* below), bytes
    /// sent and not yet acknowledged, bytes waiting to be received]`.
    pub const TCP_STATE: u64 = 13;
    /// `[TCP_STATS, VERSION]`: reply `[status, TCP segments sent again,
    /// segments dropped on purpose (a test setting), segments kept that
    /// arrived out of order]`, counted across restarts.
    pub const TCP_STATS: u64 = 14;

    /// TCP states, as `TCP_STATE` gives them (RFC 9293's names).
    pub const TCP_CLOSED: u64 = 0;
    pub const TCP_SYN_SENT: u64 = 1;
    pub const TCP_SYN_RECEIVED: u64 = 2;
    pub const TCP_ESTABLISHED: u64 = 3;
    pub const TCP_FIN_WAIT_1: u64 = 4;
    pub const TCP_FIN_WAIT_2: u64 = 5;
    pub const TCP_CLOSE_WAIT: u64 = 6;
    pub const TCP_CLOSING: u64 = 7;
    pub const TCP_LAST_ACK: u64 = 8;
    pub const TCP_TIME_WAIT: u64 = 9;

    /// The word for IPv4 address `ip` and `port`.
    pub const fn addr(ip: [u8; 4], port: u16) -> u64 {
        (u32::from_be_bytes(ip) as u64) << 16 | port as u64
    }
}

/// DNS: names to IPv4 addresses, served by the resolver (`user/dns`).
///
/// Answers come from the resolver's cache while their time to live lasts,
/// otherwise from the DNS server. A restarted resolver has lost its cache
/// and fails the call it was serving with `PeerRestarted`: the client
/// asks again.
pub mod dns {
    pub const VERSION: u64 = 1;
    /// The longest name, without a final dot.
    pub const MAX_NAME: u64 = 253;

    /// `[RESOLVE, VERSION, length]` with a frame lent whose first `length`
    /// bytes are the name (ASCII, labels separated by dots): reply
    /// `[status, the address (as in net::addr), seconds the answer stays
    /// good, 1 if it came from the cache]`. `NotFound` if the name does
    /// not exist or has no IPv4 address, `Unreachable` if no DNS server
    /// answered, `Invalid` if the name is malformed.
    pub const RESOLVE: u64 = 1;
}

/// USB: what a host controller driver serves to class drivers.
///
/// The host controller driver finds and addresses the devices on its root
/// ports; a class driver (HID, mass storage) reads their descriptors with
/// control transfers and has interrupt-IN endpoints polled for it. A
/// device belongs to the first client that claims it (`ATTACH`), and only
/// that client may use it; any client may read a device's descriptors
/// (`GET_DESCRIPTOR`) to decide whether to claim it. Devices are numbered from 0 in root-port order.
/// A restarted host controller driver finds the devices again but has no
/// endpoints configured: `READ` answers `NotFound`, and the class driver
/// sets the device up again.
pub mod usb {
    pub const VERSION: u64 = 1;

    /// `[INFO, VERSION]`: reply `[status, devices found, 0, 0]`.
    pub const INFO: u64 = 1;
    /// `[DEVICE, n]`: reply `[status, root port | speed << 8, vendor << 16
    /// | product, class << 16 | subclass << 8 | protocol]` (from the device
    /// descriptor). Speeds: 1 full, 2 low, 3 high, 4 super.
    pub const DEVICE: u64 = 2;
    /// `[ATTACH, n]` with a notification granted: claims device `n`; its
    /// interrupt-IN endpoints signal the notification when they have data.
    /// `InUse` if another client has it.
    pub const ATTACH: u64 = 3;
    /// `[CONTROL, n, setup packet (its 8 bytes, little-endian)]` with a page
    /// lent: a control transfer on endpoint 0, its data stage (`wLength`
    /// bytes, at most a page) in the page. Reply `[status, bytes moved]`.
    pub const CONTROL: u64 = 4;
    /// `[ENDPOINT, n, address | max packet << 8 | bInterval << 24]`: adds
    /// the interrupt-IN endpoint with this descriptor and starts polling
    /// it. Reply `[status]`.
    pub const ENDPOINT: u64 = 5;
    /// `[READ, n, address]` with a page lent: the oldest transfer an
    /// interrupt-IN endpoint completed, copied into the page. Reply
    /// `[status, length]`: `Empty` if none is waiting, `NotFound` if the
    /// endpoint is not configured (the driver restarted).
    pub const READ: u64 = 6;
}

/// Input: what an input driver (a HID keyboard) serves.
///
/// A subscriber gets a notification of the driver's, signalled when
/// events arrive; a driver restart deletes it, which wakes the
/// subscriber to subscribe again. Every subscriber sees every event from
/// when it subscribed; one that falls far behind loses the oldest.
pub mod input {
    pub const VERSION: u64 = 1;

    /// `[SUBSCRIBE, VERSION]`: reply `[status]` and the notification.
    pub const SUBSCRIBE: u64 = 1;
    /// `[READ]`: the subscriber's next event. Reply `[status, key, pressed,
    /// modifiers]`: `key` is a USB HID usage (keyboard page: 4 is `a`, 0x2c
    /// space; 0xe0 to 0xe7 the modifiers), `pressed` 1 or 0, `modifiers`
    /// the modifier byte after it. `Empty` if there is none.
    pub const READ: u64 = 2;
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
    //! Paths are UTF-8, `/`-separated and relative to the caller's own
    //! container (a leading `/` is allowed); `.` and empty components are
    //! skipped, `..` is refused (the POSIX view resolves it). Operations
    //! taking a path have it at the start of a granted frame.
    //!
    //! Symbolic links: a link holds a path, its target, relative to the
    //! directory holding the link or, with a leading `/`, to the
    //! container's root; a target may use `..`, which never goes above
    //! the container's root, so no link leads out of the container. Links
    //! are followed in every component of a path but the last, and in the
    //! last by `OPEN` (unless `NOFOLLOW`); `MKDIR`, `UNLINK`, `RENAME`,
    //! `SYMLINK` and `READLINK` act on the link itself. A path may go
    //! through at most [`MAX_LINKS`] links (`TooManyLinks` otherwise).
    //!
    //! Every operation may be retried after `PeerRestarted` (the server was
    //! restarted): `OPEN`, `MKDIR`, `READ`, `WRITE` and `TRUNCATE` give
    //! the same result again; a retried `UNLINK` or `RENAME` that had
    //! already happened answers `NotFound`, which the caller takes as done.

    pub const VERSION: u64 = 2;
    /// Bytes in one path component.
    pub const MAX_NAME: usize = 58;
    /// Bytes in a block; one `READ` or `WRITE` moves at most this many
    /// (it may span two blocks).
    pub const BLOCK: u64 = 4096;
    /// Blocks a file can hold: 9 direct and 1024 through one indirect
    /// block.
    pub const MAX_BLOCKS: u64 = 9 + BLOCK / 4;
    /// Largest file, in bytes (a little over 4 MiB).
    pub const MAX_FILE: u64 = MAX_BLOCKS * BLOCK;

    /// What a handle or directory entry is.
    pub const KIND_FILE: u64 = 1;
    pub const KIND_DIR: u64 = 2;
    pub const KIND_LINK: u64 = 3;
    /// The longest link target.
    pub const MAX_LINK: u64 = 1024;
    /// Links one path may go through.
    pub const MAX_LINKS: u32 = 8;

    /// `OPEN` flags.
    pub const CREATE: u64 = 1;
    /// With `CREATE`: `Exists` if it is already there.
    pub const EXCL: u64 = 2;
    /// Empties a file opened for writing.
    pub const TRUNC: u64 = 4;
    /// `NotDir` unless it is a directory.
    pub const DIRECTORY: u64 = 8;
    /// `TooManyLinks` if the last component is a symbolic link.
    pub const NOFOLLOW: u64 = 16;

    /// `[OPEN, path length, flags]`, path granted: opens a file or
    /// directory (`""` or `"/"` is the container's root). `CREATE` makes
    /// an empty file. Reply `[status, handle, size, kind]`.
    pub const OPEN: u64 = 1;
    /// `[READ, handle, offset, length]` with a frame granted: copies the
    /// bytes into the start of the frame. Reply `[status, bytes read]`.
    pub const READ: u64 = 3;
    /// `[WRITE, handle, offset, length]` with a frame granted: writes the
    /// first `length` bytes of the frame. Reply `[status]`, sent only once
    /// the write is durable.
    pub const WRITE: u64 = 4;
    /// `[STAT, handle]`: reply `[status, size, kind]`.
    pub const STAT: u64 = 5;
    /// `[MKDIR, path length]`, path granted: `Exists` if the name is taken
    /// by a file; `Ok` if it is already a directory.
    pub const MKDIR: u64 = 6;
    /// `[UNLINK, path length]`, path granted: removes a file or an empty
    /// directory (`NotEmpty` otherwise). Handles to it stop working.
    pub const UNLINK: u64 = 7;
    /// `[RENAME, from length, to length]`, granted frame holding both
    /// paths back to back: moves the entry, replacing a file (or empty
    /// directory) of the same kind at `to`. A directory cannot move into
    /// itself.
    pub const RENAME: u64 = 8;
    /// `[READDIR, handle, cookie]` with a frame granted: fills it with up
    /// to 64 [`Entry`] records from position `cookie` (start with 0).
    /// Reply `[status, entries, next cookie]`; no entries means the end.
    pub const READDIR: u64 = 9;
    /// `[TRUNCATE, handle, size]`: sets a file's size; bytes past the old
    /// end read as zero.
    pub const TRUNCATE: u64 = 10;
    /// `[STATFS]`: reply `[status, free blocks, free inodes]`.
    pub const STATFS: u64 = 11;
    /// `[SYMLINK, path length, target length]`, granted frame holding the
    /// link's path and its target back to back: makes a symbolic link.
    /// `Exists` if the name is taken (`Ok` if by a link to the same
    /// target, so a retry gives the same result).
    pub const SYMLINK: u64 = 15;
    /// `[READLINK, path length]`, path granted (writable): copies the
    /// link's target into the start of the frame. Reply `[status, target
    /// length]`; `Invalid` if it is not a link.
    pub const READLINK: u64 = 16;

    /// `[RING_ATTACH, page]` with page `page` of the caller's ring granted
    /// (pages 0 to [`ring::PAGES`] - 1, in order; page 0 drops a ring the
    /// caller had). The pages should be ones the manager keeps across
    /// restarts (`shared`), so neither side's restart unmaps the other's.
    pub const RING_ATTACH: u64 = 12;
    /// `[RING_START]` once every page is attached: the server clears the
    /// ring header and starts taking requests from it. The reply grants
    /// the completion notification (Read) the caller sleeps on. It belongs
    /// to the server: if the server is restarted it is destroyed, and a
    /// caller waiting on it wakes with `ObjectDestroyed`, its cue to set
    /// the ring up again and submit what had no completion.
    pub const RING_START: u64 = 13;
    /// `[RING_DOORBELL]`: the reply grants the doorbell (Write), signalled
    /// when the server has said it is going to sleep.
    pub const RING_DOORBELL: u64 = 14;

    /// Tier 2 rings (spec section 3): a submission and a completion queue
    /// in a page shared with the server, single-producer single-consumer,
    /// and data pages after it. Under load neither side makes a system
    /// call per request: the server polls the submission queue while it
    /// has work and asks for the doorbell ([`ring::NEED_WAKEUP`]) only
    /// before it sleeps; the caller asks for a completion signal
    /// ([`ring::CLIENT_WAITING`]) only before it sleeps.
    ///
    /// A submission is the words of a call (`[op, a, b, c]`, any operation
    /// above but the `RING_` ones) with a tag the completion carries back,
    /// and the offset in the data pages of what the call would have lent:
    /// a path, or data to write, or room for data read. A completion is
    /// the tag and the reply's words. It is posted only once the change is
    /// durable. The caller keeps at most [`ring::ENTRIES`] requests in
    /// flight.
    pub mod ring {
        pub const ENTRIES: u32 = 16;
        pub const DATA_PAGES: u64 = 15;
        /// The ring page and the data pages.
        pub const PAGES: u64 = 1 + DATA_PAGES;
        /// Bytes of data area (the pages after the ring page).
        pub const DATA: u64 = DATA_PAGES * 4096;

        // Header words (u32), a cache line apart.
        /// Next submission the server takes (server writes).
        pub const SQ_HEAD: usize = 0;
        /// Next free submission slot (caller writes).
        pub const SQ_TAIL: usize = 64;
        /// Next completion the caller takes (caller writes).
        pub const CQ_HEAD: usize = 128;
        /// Next free completion slot (server writes).
        pub const CQ_TAIL: usize = 192;
        /// [`NEED_WAKEUP`] (server writes).
        pub const FLAGS: usize = 256;
        /// While the caller sleeps on the completion notification: how
        /// many completions it waits for (caller writes; the server clears
        /// it as it signals). Asking for several coalesces the signals.
        pub const CLIENT_WAITING: usize = 320;
        /// The server sleeps: signal the doorbell after submitting.
        pub const NEED_WAKEUP: u32 = 1;

        /// Submission queue: `ENTRIES` of [`SQE`] bytes.
        pub const SQ: usize = 1024;
        /// Completion queue: `ENTRIES` of [`CQE`] bytes.
        pub const CQ: usize = 2048;
        /// Submission words: op, tag, a, b, c, data offset.
        pub const SQE: usize = 64;
        /// Completion words: tag, status, then the reply's three words.
        pub const CQE: usize = 64;
    }

    /// A directory entry as `READDIR` returns it: 64 bytes.
    pub const ENTRY: usize = 64;

    /// One `READDIR` record.
    pub struct Entry<'a>(pub &'a [u8]);

    impl<'a> Entry<'a> {
        pub fn kind(&self) -> u64 {
            self.0[4] as u64
        }
        pub fn name(&self) -> &'a [u8] {
            let n = (self.0[5] as usize).min(MAX_NAME);
            &self.0[6..6 + n]
        }
    }

    /// Writes `path` at the start of `frame`; its length, or `None` if it
    /// does not fit.
    pub fn put_path(frame: &mut [u8], path: &str) -> Option<u64> {
        let b = path.as_bytes();
        let f = frame.get_mut(..b.len())?;
        f.copy_from_slice(b);
        Some(b.len() as u64)
    }

    #[cfg(test)]
    #[test]
    fn entries_and_paths() {
        let mut e = [0u8; ENTRY];
        e[4] = KIND_DIR as u8;
        e[5] = 3;
        e[6..9].copy_from_slice(b"abc");
        assert_eq!(Entry(&e).kind(), KIND_DIR);
        assert_eq!(Entry(&e).name(), b"abc");
        let mut f = [0u8; 8];
        assert_eq!(put_path(&mut f, "a/b"), Some(3));
        assert_eq!(&f[..3], b"a/b");
        assert_eq!(put_path(&mut f, "too/long/path"), None);
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
