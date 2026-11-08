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
    /// `rsi` = [`ObjectType`], `rdx` = size in bits (untyped only), `r8` =
    /// the empty slot for the new capability, which becomes a child of the
    /// untyped one (revoking it destroys the object).
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

/// Frames are 4 KiB.
pub const FRAME_BITS: u8 = 12;
/// A CNode holds from 2^4 to 2^8 slots, each taking 2^5 bytes.
pub const CNODE_MIN_BITS: u64 = 4;
pub const CNODE_MAX_BITS: u64 = 8;
pub const CNODE_SLOT_BITS: u8 = 5;

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
