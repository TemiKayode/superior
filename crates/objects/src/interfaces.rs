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
    /// bitmask of memory BARs present, bitmask of I/O BARs given ports]`.
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
    /// `[INTX]`: for a function with no MSI at all: the legacy interrupt
    /// line its interrupt pin is wired to (an IRQ capability) in the
    /// call's accept slot, and its legacy interrupts enabled. The line is
    /// level-triggered: the kernel masks it as it signals, and the driver
    /// unmasks it (`IrqAck`) once the device has let go of it. A line is
    /// one function's at a time: `InUse` if another function that shares
    /// the wire has it, `NotFound` if the function has no pin or the
    /// machine's routing is not known. Reply: `[status, wire]`.
    pub const INTX: u64 = 9;
    /// `[IO_READ, bar, offset, width]`: reads `width` bytes (1, 2 or 4)
    /// at `offset` in I/O BAR `bar`. The ports stay the bus server's: it
    /// makes the access, inside the BAR. Reply: `[status, value]`.
    pub const IO_READ: u64 = 10;
    /// `[IO_WRITE, bar | width << 8, offset, value]`: writes likewise.
    pub const IO_WRITE: u64 = 11;
    /// `[CLOSE]`: gives the caller's function back: it is reset as for
    /// `OPEN` (domain, BAR pages and interrupts revoked), and anyone's
    /// to open.
    pub const CLOSE: u64 = 12;
    /// `[BAR_FRAME, bar]`: a capability to all of memory BAR `bar` as one
    /// device frame, its pages in a row, in the call's accept slot: for a
    /// BAR too large to take a page at a time (a video card's memory).
    /// Reply: `[status, BAR size in bytes]`.
    pub const BAR_FRAME: u64 = 13;
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
    /// it. Reply `[status, length, attached, ring]`: `Empty` if none is
    /// waiting (always, while a ring is started: frames go there);
    /// `attached` is 0 if no notification is attached, `ring` 0 if no
    /// ring is started. A restarted driver has neither.
    pub const RECV: u64 = 3;
    /// `[SEND, length]` with a frame lent: queues the frame at its start
    /// for transmission. Reply `[status]`: `NoSpace` if the transmit
    /// queue is full.
    pub const SEND: u64 = 4;
    /// `[RING_ATTACH, page]` with page `page` of the caller's ring
    /// granted (pages 0 to [`ring::PAGES`] - 1, in order; page 0 drops a
    /// ring the driver had). The pages should be ones the manager keeps
    /// across restarts (`shared`), so neither side's restart unmaps the
    /// other's.
    pub const RING_ATTACH: u64 = 5;
    /// `[RING_START]` once every page is attached: the driver clears the
    /// ring's header and from then on puts received frames in the ring
    /// and sends what the caller puts there. The reply grants the
    /// doorbell (Write). It belongs to the driver: a restart destroys it.
    pub const RING_START: u64 = 6;

    /// Frame rings (spec section 3, tier 2): received frames one way and
    /// frames to send the other, in pages shared by the driver and its
    /// caller, each ring with one producer and one consumer. Under load
    /// neither side makes a system call per frame: a side signals the
    /// other only when the other has said it is going to sleep.
    ///
    /// Slot `i % SLOTS` of a ring holds frame `i`: its bytes in the data
    /// pages, its length in the header page. The producer fills the slot,
    /// then moves the tail; the consumer copies the frame out (the
    /// producer could change it at any time: nothing in these pages is to
    /// be trusted or parsed in place), then moves the head. Neither side
    /// believes the other's index further than the ring's size, or a
    /// length beyond `MAX_FRAME`.
    ///
    /// Before it sleeps a side sets its flag and looks at its ring once
    /// more; the other side, after moving a tail, clears the flag and
    /// signals if it was set: the caller the doorbell, the driver the
    /// notification from `ATTACH`. A driver that finds the receive ring
    /// full keeps the frames in the device's buffers and says so
    /// (`RX_STALLED`, then one more look); the caller, after taking
    /// frames, clears that and rings the doorbell if it was set.
    pub mod ring {
        /// Bytes for each frame slot.
        pub const SLOT: u64 = 2048;
        pub const RX_SLOTS: u32 = 16;
        pub const TX_SLOTS: u32 = 8;
        /// The header page, then the receive slots, then the transmit
        /// slots.
        pub const RX_PAGE: u64 = 1;
        pub const TX_PAGE: u64 = RX_PAGE + RX_SLOTS as u64 * SLOT / 4096;
        pub const PAGES: u64 = TX_PAGE + TX_SLOTS as u64 * SLOT / 4096;

        // Header words (u32), a cache line apart.
        /// Next received frame the caller takes (caller writes).
        pub const RX_HEAD: usize = 0;
        /// Next free receive slot (driver writes).
        pub const RX_TAIL: usize = 64;
        /// Next frame the driver sends (driver writes).
        pub const TX_HEAD: usize = 128;
        /// Next free transmit slot (caller writes).
        pub const TX_TAIL: usize = 192;
        /// 1 while the driver sleeps: signal the doorbell.
        pub const DRIVER_SLEEPS: usize = 256;
        /// 1 while the caller sleeps: signal its notification.
        pub const CALLER_SLEEPS: usize = 320;
        /// 1 while the driver holds received frames back because the
        /// receive ring was full (driver writes; the caller clears it).
        pub const RX_STALLED: usize = 384;
        /// Lengths of the frames in the receive slots (u32 each).
        pub const RX_LEN: usize = 1024;
        /// Lengths of the frames in the transmit slots.
        pub const TX_LEN: usize = 2048;

        /// How many frames wait between `head` and `tail`, whatever the
        /// other side wrote: never more than the ring holds.
        pub const fn waiting(head: u32, tail: u32, slots: u32) -> u32 {
            let n = tail.wrapping_sub(head);
            if n > slots { slots } else { n }
        }

        #[cfg(test)]
        #[test]
        fn layout() {
            assert_eq!(PAGES, 13);
            assert!(super::MAX_FRAME <= SLOT);
            assert!(RX_SLOTS.is_power_of_two() && TX_SLOTS.is_power_of_two());
            assert!(RX_LEN + 4 * RX_SLOTS as usize <= TX_LEN);
            assert!(TX_LEN + 4 * TX_SLOTS as usize <= 4096);
            assert_eq!(waiting(5, 9, 16), 4);
            assert_eq!(waiting(u32::MAX, 1, 16), 2);
            // A tail behind the head, or too far ahead, is not believed.
            assert_eq!(waiting(9, 5, 16), 16);
            assert_eq!(waiting(0, 1000, 8), 8);
        }
    }
}

/// The network: what the network server serves. IPv4 and IPv6 with ICMP
/// echo, UDP and TCP; each socket belongs to the client that bound it.
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
    /// The largest payload a socket sends or receives, UDP's largest over
    /// IPv4 (65,535 bytes less the IPv4 and UDP headers): bigger than
    /// `MAX_PAYLOAD`, it goes (and arrives) in fragments. One that does
    /// not fit the lent page goes in pieces: `SEND_PART` stages it, and
    /// `RECV_PART` fetches what `RECV` could not copy.
    pub const MAX_DATAGRAM: u64 = 65_507;

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
    /// first `length` bytes of the frame, or, for a `length` past the
    /// frame (or past what follows `SEND6`'s address), the `length` bytes
    /// `SEND_PART` staged (all of them; `Invalid` otherwise), at most
    /// `MAX_DATAGRAM`. Reply
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
    /// waiting. A socket keeps the last few; more are dropped. The length
    /// is the datagram's: if it is more than the frame took, `RECV_PART`
    /// gives the rest.
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

    /// IPv6. Addresses are 16 bytes, most significant first, at the start
    /// of the lent page; an IPv4 address in its mapped form
    /// (`::ffff:a.b.c.d`) works too. Sockets and connections serve both
    /// families.
    ///
    /// `[SEND6, handle, port, length]` with a frame lent: as `SEND`, to
    /// the address in the page's first 16 bytes, the payload after it
    /// (for ICMP echo, `port` is the sequence number).
    pub const SEND6: u64 = 15;
    /// `[RECV6, handle]` with a frame lent: as `RECV`, the sender's
    /// address in the first 16 bytes and the payload after it. Reply
    /// `[status, length, port, family (4 or 6)]`. (`RECV` gives an IPv6
    /// sender's address word as 0, and the family in its last word.)
    pub const RECV6: u64 = 16;
    /// `[TCP_CONNECT6, port]` with a frame lent holding the address: as
    /// `TCP_CONNECT`.
    pub const TCP_CONNECT6: u64 = 17;
    /// `[TCP_PEER, handle]` with a frame lent: the peer's address, written
    /// to the page's first 16 bytes. Reply `[status, port, family]`.
    /// (`TCP_ACCEPT` and `RECV` give an IPv6 peer's address word as 0.)
    pub const TCP_PEER: u64 = 18;
    /// `[INFO6, VERSION]` with a frame lent: this host's link-local and
    /// global addresses, the router's and the DNS server's (from router
    /// advertisements), 16 bytes each in that order. Reply `[status,
    /// prefix length, seconds the address has left, seconds the router
    /// has left]`; `Unreachable` until there is a global address.
    pub const INFO6: u64 = 19;
    /// `[SEND_PART, handle, offset, length]` with a frame lent: stages
    /// the frame's first `length` bytes (at most a page) as payload bytes
    /// `offset..offset + length` of the socket's next datagram, for a
    /// `SEND` or `SEND6` too long for its frame. `offset` 0 starts a new
    /// datagram; any other must be where the last piece ended. Reply
    /// `[status]`: `NoSpace` if the server has no room for it now.
    pub const SEND_PART: u64 = 20;
    /// `[RECV_PART, handle, offset]` with a frame lent: copies payload
    /// bytes from `offset` (up to a page) of the datagram the socket last
    /// received, which the server keeps until the next `RECV` or `RECV6`.
    /// Reply `[status, bytes]`; `Empty` if there are none.
    pub const RECV_PART: u64 = 21;

    /// `[LINK_STATS, VERSION]`: reply `[status, frames that went to or
    /// came from the driver through the frame rings, frames that took a
    /// call each, times the rings were set up]`, counted across restarts.
    pub const LINK_STATS: u64 = 22;

    /// `[RING_ATTACH, page]` with page `page` of the caller's ring granted
    /// (pages 0 to [`ring::PAGES`] - 1, in order; page 0 drops a ring the
    /// caller had). The pages should be ones the manager keeps across
    /// restarts (`shared`), so neither side's restart unmaps the other's.
    pub const RING_ATTACH: u64 = 23;
    /// `[RING_START]` once every page is attached: the server clears the
    /// ring header and starts taking requests from it. The reply grants
    /// the completion notification (Read) the caller sleeps on. It belongs
    /// to the server: if the server is restarted it is destroyed, and a
    /// caller waiting on it wakes with `ObjectDestroyed`, its cue to set
    /// the ring up again (and its sockets: they went with the server).
    pub const RING_START: u64 = 24;
    /// `[RING_DOORBELL]`: the reply grants the doorbell (Write), signalled
    /// when the server has said it is going to sleep.
    pub const RING_DOORBELL: u64 = 25;
    /// `[RING_STATS, VERSION]`: reply `[status, requests taken from
    /// clients' rings, doorbells that woke the server for them]`.
    pub const RING_STATS: u64 = 26;

    /// Tier 2 rings (spec section 3) between a client and the network
    /// server, laid out as the filesystem's are ([`super::fs::ring`]): a
    /// submission and a completion queue in a page shared with the
    /// server, and data pages after it. Under load a client's datagrams
    /// and TCP bytes take no system call each: the server takes
    /// submissions while it has work and asks for the doorbell
    /// (`NEED_WAKEUP`) only before it sleeps; the caller asks for a
    /// completion signal (`CLIENT_WAITING`) only before it sleeps.
    ///
    /// A submission is the words of a call that lends a page (`SEND`,
    /// `SEND6`, `RECV`, `RECV6`, `SEND_PART` or `RECV_PART`: `[op, a, b,
    /// c]`) with a tag the completion carries back, and the offset in the
    /// data pages (a whole page's) of the page the call would have lent.
    /// A completion is the tag and the reply's words. `RECV` answers
    /// `Empty` at once when nothing has arrived: the caller waits on the
    /// socket's notification, as with calls.
    pub mod ring {
        pub use super::super::fs::ring::*;
    }

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
    /// `[RESOLVE6, VERSION, length]`, the same with an IPv6 address (an
    /// AAAA record): the frame lent (writable) gets the 16-byte address
    /// in its first 16 bytes; reply `[status, seconds the answer stays
    /// good, 1 if it came from the cache]`. `NotFound` if the name does
    /// not exist or has no IPv6 address.
    pub const RESOLVE6: u64 = 2;
    /// `[RECORDS, VERSION, length | type << 16]` with a frame lent
    /// (writable) whose first `length` bytes are the name: the name's
    /// records of that type (a DNS record type's number: [`TXT`], [`MX`],
    /// [`SRV`], [`PTR`], [`NS`] or any other), found through CNAMEs like
    /// an address. The frame gets them one after another, each a length
    /// (two bytes, little-endian) and that many bytes: a TXT record's
    /// strings joined; an MX record as `preference host`; SRV as
    /// `priority weight port target`; PTR, NS and CNAME as the name;
    /// names lower case and dotted, numbers decimal; any other type's
    /// data as it came. Reply `[status, records, seconds they stay good,
    /// 1 if they came from the cache]`: `NotFound` if the name does not
    /// exist or has none, `NoSpace` if they do not fit in the page. An
    /// answer the server could not fit in a UDP datagram is fetched over
    /// TCP (up to 4,096 bytes of it).
    pub const RECORDS: u64 = 3;
    pub const NS: u64 = 2;
    pub const PTR: u64 = 12;
    pub const MX: u64 = 15;
    pub const TXT: u64 = 16;
    pub const SRV: u64 = 33;
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

/// Input: what an input driver (a HID keyboard and mouse) serves.
///
/// A subscriber is signalled when events arrive: on a notification it
/// lends with `SUBSCRIBE` (a server waiting for calls lends a badged copy
/// of the one bound to its thread), or else on one of the driver's,
/// granted in the reply, which a driver restart deletes, waking the
/// subscriber to subscribe again. A subscriber that lent its own finds
/// out about a restart when `READ` fails or answers `Denied`. Every
/// subscriber sees every event from when it subscribed; one that falls
/// far behind loses the oldest.
pub mod input {
    pub const VERSION: u64 = 3;

    /// `[SUBSCRIBE, VERSION]`, optionally with a notification lent: reply
    /// `[status]`, and the driver's notification if none was lent.
    pub const SUBSCRIBE: u64 = 1;
    /// `[READ]`: the subscriber's next event. Reply `[status, kind, a,
    /// b]`, `Empty` if there is none.
    pub const READ: u64 = 2;

    /// A key: `a` is its USB HID usage (keyboard page: 4 is `a`, 0x2c
    /// space; 0xe0 to 0xe7 the modifiers), `b` is 1 if pressed, 0 if
    /// released, with the modifier byte after it in bits 8 to 15.
    pub const KEY: u64 = 1;
    /// The pointer moved: `a` and `b` are how far right and down, as
    /// signed 64-bit numbers.
    pub const MOTION: u64 = 2;
    /// A pointer button: `a` is which (0 left, 1 right, 2 middle, then
    /// any others the device has, up to 7), `b` is 1 if pressed, 0 if
    /// released.
    pub const BUTTON: u64 = 3;
    /// An absolute pointing device (a tablet, a touch screen) is at `a`
    /// across and `b` down, each from 0 to [`POSITION_MAX`] over all of
    /// its range: the whole screen. Sent when it changes.
    pub const POSITION: u64 = 4;
    /// The wheel turned: `a` steps up (away from the user) and `b` steps
    /// right, as signed 64-bit numbers.
    pub const WHEEL: u64 = 5;
    pub const POSITION_MAX: u64 = 0xffff;
}

/// Suspend and resume: what the Component Manager asks of a `power`
/// component (manifest), on that component's first service, unbadged
/// (badge 0, which no client is given). Before suspending the machine it
/// sends `SUSPEND` to every such component, last in the manifest first
/// (consumers before the drivers they use); after, `RESUME` in manifest
/// order. A driver quiesces its device on `SUSPEND` (finishing or
/// failing what it had in flight, then resetting it) and brings it up
/// again on `RESUME`. In between it answers its clients' calls with
/// `Unreachable`, and they retry after the resume.
///
/// A `power-control` component asks for a suspend through its `control`
/// capability: `[cm OP_SUSPEND, ticks]`, answered after the resume.
pub mod power {
    pub const VERSION: u64 = 1;

    /// `[SUSPEND]`: quiesce. Reply `[status]`.
    pub const SUSPEND: u64 = 0x5050;
    /// `[RESUME]`: work again. Reply `[status]`.
    pub const RESUME: u64 = 0x5051;
    /// `[OP_SUSPEND, ticks]` on the control capability: suspend the
    /// machine for `ticks` ticks. Reply `[status]`.
    pub const OP_SUSPEND: u64 = 7;
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
    /// Blocks a file can hold: 9 direct, 1024 through an indirect block
    /// and 1024 * 1024 through a double indirect one.
    pub const MAX_BLOCKS: u64 = 9 + BLOCK / 4 + (BLOCK / 4) * (BLOCK / 4);
    /// Largest file, in bytes (a little over 4 GiB; the disk, at most 128
    /// MiB, runs out first).
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
    /// `Denied` over quota. If a copy-on-write page is mapped there, the
    /// component gets a private writable copy instead (or the page itself,
    /// writable, if nobody else maps it any more), at no extra charge.
    pub const FAULT: u64 = 0x10;
    /// Manager only. `[RELEASE, component]`: takes back every page the
    /// component holds (it is being stopped). Reply `[status, pages]`.
    pub const RELEASE: u64 = 0x11;
    /// Manager only. `[SHARE, component]` with the component's address
    /// space lent: every heap page it holds becomes copy-on-write (mapped
    /// read-only; the next write fault, through `FAULT`, gives the writer
    /// its own copy). Reply `[status, pages]`.
    pub const SHARE: u64 = 0x12;
    /// Manager only. `[CLONE, parent, child, child's quota]` with the
    /// child's address space lent, after `SHARE` of the parent: maps every
    /// copy-on-write heap page of the parent read-only at the same address
    /// in the child, charged to the child. `Denied` over the child's quota,
    /// `InUse` if this server has no slot left for the copies. Reply
    /// `[status, pages]`.
    pub const CLONE: u64 = 0x13;

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
