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
