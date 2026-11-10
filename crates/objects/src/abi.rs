//! The user/kernel system call ABI, shared by the kernel and user programs.
//!
//! Entry is the x86-64 `syscall` instruction. Registers:
//!
//! | Register | In | Out |
//! | --- | --- | --- |
//! | `rax` | syscall number | status (0 = ok, else an [`Error`] code) |
//! | `rdi` | capability slot in the caller's CSpace | badge of the message received |
//! | `rsi`, `rdx`, `r8`, `r9` | message words 0 to 3 | message words received |
//! | `r10` | capability transfer, see [`CapTransfer`] | slot a capability arrived in, plus 1 (0 = none) |
//!
//! `rcx` and `r11` are clobbered by the `syscall` instruction itself. Every
//! other register is preserved. After a syscall that does not receive, the
//! output message registers hold unspecified values.

/// Message words passed in registers (the IPC fast path).
pub const MSG_WORDS: usize = 4;

/// Capability transfer with a message, passed in `r10`.
///
/// - `grant`: a slot in the sender's CSpace. The receiver gets a copy
///   derived from it (same rights and badge), so the sender can revoke it.
///   `Send` and `Call` need the Grant right on the endpoint capability; a
///   reply may grant if the caller's capability had Grant or GrantReply.
/// - `accept`: an empty slot in the receiver's CSpace where an arriving
///   capability goes. `Call` names the slot for the reply's capability.
///   With no accept slot, or one that has filled up meanwhile, an offered
///   capability is dropped and the message still arrives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapTransfer {
    pub grant: Option<u16>,
    pub accept: Option<u16>,
}

impl CapTransfer {
    pub const NONE: CapTransfer = CapTransfer {
        grant: None,
        accept: None,
    };

    /// Bits 0-15: grant slot + 1; bits 16-31: accept slot + 1; 0 = none.
    pub const fn encode(self) -> u64 {
        let g = match self.grant {
            Some(s) => s as u64 + 1,
            None => 0,
        };
        let a = match self.accept {
            Some(s) => s as u64 + 1,
            None => 0,
        };
        g | a << 16
    }

    /// Decodes `r10`; `None` if reserved bits (32-63) are set.
    pub const fn decode(word: u64) -> Option<CapTransfer> {
        if word >> 32 != 0 {
            return None;
        }
        let g = (word & 0xffff) as u16;
        let a = (word >> 16) as u16;
        Some(CapTransfer {
            grant: if g == 0 { None } else { Some(g - 1) },
            accept: if a == 0 { None } else { Some(a - 1) },
        })
    }
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    Send = 0,
    NBSend = 1,
    Call = 2,
    Recv = 3,
    NBRecv = 4,
    Reply = 5,
    ReplyRecv = 6,
    Signal = 7,
    Wait = 8,
    Yield = 9,
    /// Removes every capability derived from the one in slot `rdi`,
    /// in any CSpace, including copies granted through IPC.
    CapRevoke = 10,
    /// Empties slot `rdi`. Capabilities derived from it stay revocable
    /// through its parent.
    CapDelete = 11,
    /// The caller gives up its own scheduling context the next time it
    /// blocks; afterwards it runs only on contexts lent by its callers.
    SchedPassive = 12,
    /// Makes a new kernel object from the untyped capability in slot `rdi`:
    /// `rsi` = [`ObjectType`], `rdx` = size in bits (untyped, CNode and
    /// address space), `r8` = the empty slot for the new capability, which
    /// becomes a child of the untyped one (revoking it destroys the
    /// object). `r9` = 0 puts it in the caller's own CSpace; otherwise
    /// `r9 - 1` is the slot of a CNode (Write right) and `r8` an index in it, so
    /// a parent can give a child an original capability, such as untyped
    /// memory it can retype in turn.
    Retype = 13,
    /// Copies the capability in slot `rdi` into the empty slot `rsi` with
    /// rights `rdx` (a mask: rights only shrink) and badge `r8` (0 = keep).
    CapMint = 14,
    /// Maps the frame in slot `rdi` at page-aligned `rsi` in the caller's
    /// own address space; `rdx` = 1 for writable. Needs the Map right (and
    /// Write for writable). Never executable. A frame capability is mapped
    /// at most once; map a copy to share the frame.
    FrameMap = 15,
    /// Unmaps the frame in slot `rdi`.
    FrameUnmap = 16,
    /// Makes the endpoint in slot `rdi` (Write right needed) the caller's
    /// fault handler: a user-mode fault becomes a `Call` to it with the
    /// message [`FaultKind`], address, rip, error code, and the badge of
    /// that capability. The reply says how to go on ([`FaultReply`]).
    SetFaultHandler = 17,
    /// Sets up the inactive thread in slot `rdi` (Write right) to run in
    /// the caller's address space: `rsi` = entry, `rdx` = stack top
    /// (16-byte aligned), `r8` = argument (its `rdi`), `r9` = priority, at
    /// most the caller's. It inherits the caller's fault handler and budget.
    ThreadConfigure = 18,
    /// Starts (or restarts after `ThreadSuspend`) the thread in slot `rdi`.
    ThreadResume = 19,
    /// Stops the thread in slot `rdi`. A blocked system call is cancelled
    /// with `Interrupted`.
    ThreadSuspend = 20,
    /// Copies the caller's slot `rsi` into slot `rdx` of the CSpace of the
    /// thread in slot `rdi`, with rights mask `r8`.
    ThreadCopyCap = 21,
    /// Copies the caller's slot `rdx` into index `rsi` of the CNode in slot
    /// `rdi` (Write right), with rights mask `r8` and badge `r9` (0 = keep).
    CNodeCopy = 22,
    /// Empties index `rsi` of the CNode in slot `rdi` (Write right).
    CNodeDelete = 23,
    /// Removes everything derived from index `rsi` of the CNode in slot
    /// `rdi` (Write right).
    CNodeRevoke = 24,
    /// Makes the CNode in slot `rsi` the CSpace of the inactive thread in
    /// slot `rdi`. The thread holds its own copy of the CNode capability,
    /// so the CNode lives as long as the thread does (or until revoked).
    ThreadSetSpace = 25,
    /// Delivers interrupts of the line in IRQ capability `rdi` as a signal
    /// of the notification in slot `rsi` (Write right), with that
    /// capability's badge, and unmasks the line.
    IrqSetNotification = 26,
    /// Unmasks the line in IRQ capability `rdi` after its interrupt was
    /// handled. Each interrupt masks the line until acknowledged.
    IrqAck = 27,
    /// Reads I/O port `rsi` (in the range of the I/O-port capability in
    /// `rdi`, Read right), `rdx` bytes wide (1, 2 or 4). The value is
    /// returned in message word 0.
    IoPortIn = 28,
    /// Writes `r8` to I/O port `rsi` (in the range of the I/O-port
    /// capability in `rdi`, Write right), `rdx` bytes wide (1, 2 or 4).
    IoPortOut = 29,
    /// Timer ticks since boot ([`TICK_HZ`] a second), in message word 0.
    /// Supervisors use it to count restarts per unit of time.
    Ticks = 33,
    /// The message a device writes to raise the MSI vector in IRQ
    /// capability `rdi`: the address in message word 0, the data in word 1.
    /// A driver programs these into its device's MSI-X table, then binds
    /// the vector to a notification with [`Syscall::IrqSetNotification`].
    /// `rsi` is the I/O address space (Write right) of the function that
    /// may raise it: where interrupts are remapped (VT-d's remapping table,
    /// the GICv3 ITS), the vector is from then on routed for that
    /// function's requester ID alone, and a message from any other device
    /// raises nothing. `rsi` = `u64::MAX` routes it for no device. Fails
    /// with `InvalidArgument` for a line that is not an MSI vector or a
    /// space bound to no function.
    IrqMsiMessage = 34,
    /// The address a device uses to reach the frame in slot `rdi` (Map
    /// right), in message word 0, for programming DMA. Today that is the
    /// physical address; with an IOMMU it becomes the frame's address in
    /// the driver's I/O address space, so drivers need no change.
    FrameDmaAddress = 35,
    /// Makes a frame over page `rsi` (a byte offset, page-aligned) of the
    /// device memory in slot `rdi`, in empty slot `rdx`: a child of the
    /// device-memory capability, so revoking that removes it. Unlike
    /// `Retype` this picks the page, so the holder can reach exactly the
    /// registers it needs (one PCI function's configuration space, one BAR
    /// page). Device frames may alias; who gets which is the holder's
    /// policy (the PCI bus server's).
    DeviceFrame = 36,
    /// Binds the I/O address space in slot `rdi` to the PCI function with
    /// requester ID `rdx` (bus << 8 | device << 3 | function), using the
    /// IOMMU-control capability in slot `rsi`. From then on the function's
    /// DMA is translated through that space and can reach only what is
    /// mapped in it. A function is bound to at most one space, and a space
    /// to one function; destroying the space unbinds it, which blocks the
    /// function's DMA altogether.
    IoSpaceBind = 37,
    /// Maps the frame in slot `rdi` (Map right; RAM, not device memory)
    /// into the I/O address space in slot `rsi`, writable by the device if
    /// `rdx` = 1. Returns the address the device uses for it in message
    /// word 0. Deleting or revoking that frame capability unmaps it, so a
    /// buffer lent to a driver is reachable only while it is lent.
    IoMap = 38,
    /// Unmaps the frame in slot `rdi` from the I/O address space it was
    /// mapped into, and waits until the IOMMU has forgotten it.
    IoUnmap = 39,
    /// Binds the notification in slot `rdi` (Read right) to the calling
    /// thread: its `Recv` and `ReplyRecv` then also return when the
    /// notification is signalled, with status [`Error::Notified`] and the
    /// bits as the badge. A thread binds at most one notification, and a
    /// notification is bound to at most one thread, for as long as both
    /// exist.
    NotificationBind = 40,
    /// Signals the notification in slot `rdi` (Write right) once, `rsi`
    /// ticks ([`TICK_HZ`] a second) from now, with the capability's badge
    /// (1 if it has none), as the timer interrupt would. Setting it again
    /// replaces the earlier deadline; `rsi` = 0 cancels it. A component
    /// sleeps with a timeout by waiting (or receiving, if it is bound) on
    /// the notification. Fails with `ObjectTableFull` when every kernel
    /// timer is in use.
    TimerSignal = 41,
    /// Reports the DMA requests the IOMMU blocked for the function bound
    /// to the I/O address space in slot `rdi` (Read right) since the last
    /// call, and forgets them: message word 0 is how many, word 1 the
    /// first one's page address (0 if the IOMMU gave none) and word 2 is 1
    /// if it was a write; word 3 counts interrupt messages it blocked
    /// (VT-d only: the ITS drops them without a report). Without this, a
    /// device aimed outside its domain fails without anyone hearing of it.
    IoFaults = 42,
    /// Blocks the caller for `rdi` ticks ([`TICK_HZ`] a second), on a
    /// notification of its own that only the kernel signals: no
    /// capability, and no CPU spent waiting. Returns early with
    /// `Interrupted` if the thread is stopped meanwhile. 0 returns at once.
    Sleep = 43,
    /// Maps the frame in slot `rdi` at page-aligned `rsi` in the address
    /// space in slot `r8` (Write right). `rdx` = [`MAP_WRITE`] and/or
    /// [`MAP_EXEC`], never both. Needs the frame's Map right, plus Write
    /// for a writable mapping and Read otherwise. This is how a component
    /// loader puts code into another component's address space.
    FrameMapInto = 30,
    /// Puts the inactive thread in slot `rdi` (Write right) in the address
    /// space in slot `rsi` (Write right). The thread holds its own copy of
    /// that capability, so the address space lives as long as the thread
    /// does (or until revoked). Without this, a thread runs in its
    /// creator's address space.
    ThreadSetVSpace = 31,
    /// Makes the endpoint in slot `rsi` (Write right) the fault handler of
    /// the thread in slot `rdi` (Write right), with that capability's
    /// badge: how a supervisor learns which of its children faulted.
    ThreadSetFaultHandler = 32,
    /// Debug build only: print a UTF-8 string. rdi = pointer, rsi = length.
    DebugPutStr = 0x100,
    /// Debug build only: report a self-test result. rdi = 0 for pass.
    DebugSelftestDone = 0x101,
}

impl Syscall {
    pub const fn from_u64(n: u64) -> Option<Syscall> {
        Some(match n {
            0 => Syscall::Send,
            1 => Syscall::NBSend,
            2 => Syscall::Call,
            3 => Syscall::Recv,
            4 => Syscall::NBRecv,
            5 => Syscall::Reply,
            6 => Syscall::ReplyRecv,
            7 => Syscall::Signal,
            8 => Syscall::Wait,
            9 => Syscall::Yield,
            10 => Syscall::CapRevoke,
            11 => Syscall::CapDelete,
            12 => Syscall::SchedPassive,
            13 => Syscall::Retype,
            14 => Syscall::CapMint,
            15 => Syscall::FrameMap,
            16 => Syscall::FrameUnmap,
            17 => Syscall::SetFaultHandler,
            18 => Syscall::ThreadConfigure,
            19 => Syscall::ThreadResume,
            20 => Syscall::ThreadSuspend,
            21 => Syscall::ThreadCopyCap,
            22 => Syscall::CNodeCopy,
            23 => Syscall::CNodeDelete,
            24 => Syscall::CNodeRevoke,
            25 => Syscall::ThreadSetSpace,
            26 => Syscall::IrqSetNotification,
            27 => Syscall::IrqAck,
            28 => Syscall::IoPortIn,
            29 => Syscall::IoPortOut,
            30 => Syscall::FrameMapInto,
            31 => Syscall::ThreadSetVSpace,
            32 => Syscall::ThreadSetFaultHandler,
            33 => Syscall::Ticks,
            34 => Syscall::IrqMsiMessage,
            35 => Syscall::FrameDmaAddress,
            36 => Syscall::DeviceFrame,
            37 => Syscall::IoSpaceBind,
            38 => Syscall::IoMap,
            39 => Syscall::IoUnmap,
            40 => Syscall::NotificationBind,
            41 => Syscall::TimerSignal,
            43 => Syscall::Sleep,
            42 => Syscall::IoFaults,
            0x100 => Syscall::DebugPutStr,
            0x101 => Syscall::DebugSelftestDone,
            _ => return None,
        })
    }
}

/// Status codes returned in `rax`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Unknown syscall number.
    IllegalOperation = 1,
    /// The slot is empty, out of range, or holds the wrong object type.
    InvalidCapability = 2,
    /// The capability lacks a right the operation needs.
    InsufficientRights = 3,
    /// A non-blocking receive found nothing.
    WouldBlock = 4,
    /// A pointer argument is outside the caller's user window.
    InvalidArgument = 5,
    /// The server received a new call before replying to this one.
    ReplyAbandoned = 6,
    /// The untyped block has no aligned room left for the object.
    NotEnoughMemory = 7,
    /// The destination slot already holds a capability.
    SlotOccupied = 8,
    /// The kernel's table for this object type is full.
    ObjectTableFull = 9,
    /// The object was destroyed while this thread waited on it.
    ObjectDestroyed = 10,
    /// The frame capability is already mapped, or the address is in use.
    AlreadyMapped = 11,
    /// The thread was suspended while blocked; its system call was cancelled.
    Interrupted = 12,
    /// The server that received this call was destroyed before replying
    /// (it crashed, or its supervisor restarted it). The call may or may
    /// not have taken effect: retry it if it is idempotent, or with the
    /// same request id so the new instance can recognise it.
    PeerRestarted = 13,
    /// Not a failure: a `Recv` or `ReplyRecv` returned because the
    /// thread's bound notification was signalled; the badge holds its
    /// bits and no message or capability arrived.
    Notified = 14,
}

/// What a fault message (`msg[0]`) reports.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// `msg[1]` = faulting address, `msg[3]` = x86 page-fault error code
    /// (bit 0 present, 1 write, 2 user, 4 instruction fetch).
    PageFault = 1,
    /// `msg[3]` = error code (usually 0).
    GeneralProtection = 2,
    InvalidOpcode = 3,
    DivideError = 4,
}

impl FaultKind {
    pub const fn from_u64(n: u64) -> Option<FaultKind> {
        Some(match n {
            1 => FaultKind::PageFault,
            2 => FaultKind::GeneralProtection,
            3 => FaultKind::InvalidOpcode,
            4 => FaultKind::DivideError,
            _ => return None,
        })
    }
}

/// The fault handler's reply, `msg[0]`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReply {
    /// Run the faulting instruction again (after fixing the cause).
    Retry = 0,
    /// Continue at `msg[1]` (in the user window) with `rax` = `msg[2]`:
    /// enough to emulate or skip the faulting instruction.
    ResumeAt = 1,
    /// Stop the thread. Any other value, or a failed reply, also stops it.
    Stop = 2,
}

/// The kernel's timer rate on every architecture.
pub const TICK_HZ: u64 = 100;

/// Message word 0 of every reply from a service the Component Manager
/// has given up on (too many restarts): the call reached nobody who can
/// serve it. Clients should stop retrying.
pub const SERVICE_UNAVAILABLE: u64 = u64::MAX;

/// Frames are 4 KiB.
pub const FRAME_BITS: u8 = 12;
/// A CNode holds from 2^4 to 2^11 slots, each taking 2^5 bytes.
pub const CNODE_MIN_BITS: u64 = 4;
pub const CNODE_MAX_BITS: u64 = 11;
pub const CNODE_SLOT_BITS: u8 = 5;
/// An address space takes from 2^14 to 2^20 bytes: one page for its
/// top-level table, the rest a pool for the page tables under it.
pub const VSPACE_MIN_BITS: u64 = 14;
pub const VSPACE_MAX_BITS: u64 = 20;
/// [`Syscall::FrameMapInto`] flags.
pub const MAP_WRITE: u64 = 1;
pub const MAP_EXEC: u64 = 2;

/// Kernel object types for [`Syscall::Retype`].
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    Untyped = 0,
    Endpoint = 1,
    Notification = 2,
    /// A 4 KiB page of memory, zeroed when made.
    Frame = 3,
    /// A thread, inactive until configured and resumed.
    Thread = 4,
    /// A table of capability slots, usable as a thread's CSpace. The size
    /// argument is the slot count in bits; each slot takes 32 bytes.
    CNode = 5,
    /// An address space. The size argument is its total size in bits
    /// ([`VSPACE_MIN_BITS`] to [`VSPACE_MAX_BITS`]): page tables for its
    /// mappings come from that memory, so it can map only as much as its
    /// pool has tables for, and gives every table back when destroyed.
    AddressSpace = 6,
    /// An I/O address space (an IOMMU domain): what one PCI function's DMA
    /// can reach. Sized like an address space, and its I/O page tables
    /// come out of its memory the same way. Only made when the machine
    /// has an IOMMU the kernel drives.
    IoSpace = 7,
}

impl ObjectType {
    pub const fn from_u64(n: u64) -> Option<ObjectType> {
        Some(match n {
            0 => ObjectType::Untyped,
            1 => ObjectType::Endpoint,
            2 => ObjectType::Notification,
            3 => ObjectType::Frame,
            4 => ObjectType::Thread,
            5 => ObjectType::CNode,
            6 => ObjectType::AddressSpace,
            7 => ObjectType::IoSpace,
            _ => return None,
        })
    }

    /// Memory the object takes from its untyped block, as a power of two.
    /// Untyped blocks take their requested size, from 16 bytes up.
    pub const fn size_bits(self, requested: u64) -> Option<u8> {
        match self {
            ObjectType::Untyped if requested >= 4 && requested <= 47 => Some(requested as u8),
            ObjectType::Untyped => None,
            ObjectType::Endpoint => Some(4),
            ObjectType::Notification => Some(5),
            ObjectType::Frame => Some(FRAME_BITS),
            ObjectType::Thread => Some(11),
            ObjectType::CNode if requested >= CNODE_MIN_BITS && requested <= CNODE_MAX_BITS => {
                Some(requested as u8 + CNODE_SLOT_BITS)
            }
            ObjectType::CNode => None,
            ObjectType::AddressSpace
                if requested >= VSPACE_MIN_BITS && requested <= VSPACE_MAX_BITS =>
            {
                Some(requested as u8)
            }
            ObjectType::AddressSpace => None,
            ObjectType::IoSpace if requested >= VSPACE_MIN_BITS && requested <= VSPACE_MAX_BITS => {
                Some(requested as u8)
            }
            ObjectType::IoSpace => None,
        }
    }
}

impl Error {
    pub const fn code(self) -> u64 {
        self as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_transfer_round_trips() {
        for t in [
            CapTransfer::NONE,
            CapTransfer {
                grant: Some(0),
                accept: None,
            },
            CapTransfer {
                grant: None,
                accept: Some(15),
            },
            CapTransfer {
                grant: Some(0xfffe),
                accept: Some(7),
            },
        ] {
            assert_eq!(CapTransfer::decode(t.encode()), Some(t));
        }
        assert_eq!(CapTransfer::decode(0), Some(CapTransfer::NONE));
        assert_eq!(CapTransfer::decode(1 << 32), None, "reserved bits");
    }
}

/// What the kernel gives the root task, the Component Manager, at boot.
/// Its CSpace is a CNode of `1 << CNODE_BITS` slots; the boot bundle (see
/// [`crate::bundle`]) is mapped read-only at [`BUNDLE_VA`](root::BUNDLE_VA)
/// and its length is the root task's first argument.
pub mod root {
    pub const CNODE_BITS: u8 = 11;
    /// A capability to the root task's own CSpace CNode.
    pub const SELF_CNODE: u64 = 0;
    /// All the memory it hands out to components.
    pub const UNTYPED: u64 = 1;
    /// The timer notification (Read): one signal per tick.
    pub const TIMER: u64 = 2;
    /// QEMU's exit device: I/O port 0xf4 (emulated on AArch64).
    pub const EXIT_PORT: u64 = 3;
    /// The console UART: I/O ports 0x3f8-0x3ff on x86-64, the PL011's
    /// register page (a device frame) on AArch64.
    pub const UART: u64 = 4;
    /// The UART's interrupt line.
    pub const UART_IRQ: u64 = 5;
    /// PCI configuration space: I/O ports 0xcf8-0xcff on x86-64 (the
    /// legacy address/data pair), the ECAM window (device memory, buses 0
    /// to 15) on AArch64.
    pub const PCI_CONFIG: u64 = 6;
    /// Device memory for PCI BARs: a window no RAM or firmware device uses,
    /// which the PCI bus server assigns BARs from.
    pub const PCI_MMIO: u64 = 7;
    /// [`MSI_COUNT`] MSI vectors (IRQ capabilities), in consecutive slots.
    pub const MSI: u64 = 8;
    pub const MSI_COUNT: u64 = 8;
    /// The IOMMU-control capability, if the machine has an IOMMU the
    /// kernel drives: the right to bind I/O address spaces to PCI
    /// functions.
    pub const IOMMU: u64 = MSI + MSI_COUNT;
    /// The first slot with nothing in it.
    pub const FIRST_FREE: u64 = IOMMU + 1;
    /// Size of [`UNTYPED`], in bits.
    pub const UNTYPED_BITS: u8 = 25;
    /// Where the bundle is mapped, as an offset from the user window's base.
    pub const BUNDLE_OFFSET: u64 = 0x1_0000_0000;
    /// The root task's priority; a component can be given at most this.
    pub const PRIORITY: u8 = 60;
}
