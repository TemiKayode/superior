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
    /// Timer ticks since boot ([`TICK_HZ`] a second), in message word 0,
    /// and how many CPUs are online in word 1. Supervisors use the ticks to
    /// count restarts per unit of time.
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
    /// policy (the PCI bus server's). `r8`, if not 0, makes the frame
    /// `2^r8` bytes (up to [`DEVICE_FRAME_MAX_BITS`]): a run of pages a
    /// map maps from its address on (a video card's memory, say).
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
    /// The fast reboot (spec section 4), for the root task only, showing
    /// its untyped capability in slot `rdi`: the kernel destroys every
    /// object made from that memory and the root task itself, then starts
    /// the root task again from the boot bundle with the same capabilities.
    /// The state store ([`root::STATE_STORE`]) keeps its contents. Also
    /// what happens when the root task faults.
    Reboot = 44,
    /// Has the notification in slot `rsi` (Write right) signalled, with its
    /// badge (bit 0 if unbadged), whenever the IOMMU blocks a request from
    /// the device of the I/O address space in slot `rdi` (Read right): the
    /// IOMMU's fault interrupt has the kernel collect it at once, so the
    /// holder hears of it without asking (`IoFaults` then says what it
    /// was). Slot `rsi` = `u64::MAX` unbinds it.
    IoFaultNotify = 45,
    /// Sets aside the caller this thread owes a reply, so it may receive
    /// further calls before answering it: the reply's word 0 is the place
    /// it went in, for `ReplyTo`. Up to `ipc::SAVED_CALLERS` at once; a
    /// caller set aside whose server is destroyed gets `PeerRestarted`
    /// (or `ReplyAbandoned`, suspended), as the one it owes does.
    /// `InvalidArgument` if no caller waits; `ObjectTableFull` if every
    /// place is taken or the thread is passive.
    ReplySave = 46,
    /// Answers the caller set aside in place `rdi` with the message (no
    /// capability may go with it). A place with nobody in it is a no-op.
    ReplyTo = 47,
    /// What the untyped capability in slot `rdi` holds: message word 0 is
    /// its size in bits, word 1 the bytes not yet carved from it (all of
    /// it once nothing made from it is left).
    UntypedInfo = 48,
    /// Suspends the machine to idle for `rsi` ticks (at least 1): every
    /// CPU stops its tick and halts, no thread runs, and time (`Ticks`)
    /// stands still, until a one-shot alarm ends it; then the ticks start
    /// again and the caller continues. Interrupts that arrive meanwhile
    /// are kept for afterwards. Only the root task may, naming its
    /// untyped capability in `rdi` (as for `Reboot`); `InvalidCapability`
    /// otherwise. Devices are the drivers' to quiesce first.
    Suspend = 49,
    /// 32 random bytes, in message words 0 to 3 (little-endian), from the
    /// kernel's entropy pool: seeded from the CPU's random instruction
    /// where it has one and the cycle counter's jitter, and fed interrupt
    /// timings. For keys and nonces; it needs no capability.
    Random = 50,
    /// The time of day: seconds since 1970-01-01 00:00 UTC in message word
    /// 0, from the machine's real-time clock (the CMOS clock on x86-64, a
    /// PL031 on AArch64). `IllegalOperation` where there is none. It needs
    /// no capability.
    Time = 51,
    /// Which legacy PCI interrupt line pin `rsi` (1 to 4, INTA# to INTD#)
    /// of device `rdi` on the root bus reaches, as the firmware routes it
    /// (ACPI's `_PRT` on x86-64, the device tree on AArch64): its index
    /// among the [`root::INTX`] lines, in message word 0. A function
    /// behind bridges asks for the root-bus device and pin its pin comes
    /// out on. `IllegalOperation` if the pin reaches none the kernel routes;
    /// `InvalidArgument` for a device past 31 or a pin outside 1 to 4. It
    /// needs no capability: the wiring is no secret, and the lines
    /// themselves are capabilities.
    IntxLine = 52,
    /// A foreign-ABI thread's registers, for the personality server that
    /// is its fault handler: `rdi` = the thread (Write right), `rsi` = one
    /// of the `REGS_*` operations, `rdx` = its value. Meaningful while the
    /// thread waits on its handler.
    ThreadRegisters = 53,
    /// Makes the endpoint in slot `rsi` (Write right) the timeout handler
    /// of the thread in slot `rdi` (Write right), with that capability's
    /// badge: a context lent to the thread running dry then becomes a
    /// [`FaultKind::Timeout`] call to it. `rsi` = `u64::MAX` removes it.
    /// A thread inherits its creator's.
    ThreadSetTimeoutHandler = 54,
    /// Binds the thread in slot `rdi` (Write right) to the scheduling
    /// context in slot `rsi` (Write right): it runs on that context's
    /// budget, shared with every other thread bound to it. `rsi` =
    /// `u64::MAX` unbinds it, and a thread bound to no context cannot run.
    /// A thread starts bound to its creator's context.
    SchedContextBind = 55,
    /// Sets the budget of the scheduling context in slot `rsi` (Write
    /// right): `rdx` ticks in every `r8` ticks, starting full now.
    /// `r8` = 0 makes it unlimited, `rdx` = 0 empties it (its threads
    /// cannot run). Needs the sched-control capability in slot `rdi`: CPU
    /// time is handed out only by its holder (the Component Manager).
    SchedControlConfigure = 56,
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
            44 => Syscall::Reboot,
            45 => Syscall::IoFaultNotify,
            46 => Syscall::ReplySave,
            47 => Syscall::ReplyTo,
            48 => Syscall::UntypedInfo,
            49 => Syscall::Suspend,
            50 => Syscall::Random,
            51 => Syscall::Time,
            52 => Syscall::IntxLine,
            53 => Syscall::ThreadRegisters,
            54 => Syscall::ThreadSetTimeoutHandler,
            55 => Syscall::SchedContextBind,
            56 => Syscall::SchedControlConfigure,
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
    /// A system call from a thread running a foreign ABI (see
    /// [`Syscall::ThreadRegisters`]): `msg[1]` = its number (`rax` on
    /// x86-64, `x8` on AArch64), `msg[2]` = the address after the
    /// instruction. The handler reads the arguments with `ThreadRegisters`
    /// and answers [`FaultReply::ResumeAt`] that address with the result.
    ForeignSyscall = 5,
    /// A scheduling context lent to the thread (a caller's, while it
    /// serves that call) ran out of budget: `msg[1]` = the context's
    /// budget, `msg[2]` = its period, in ticks. Sent to the thread's
    /// timeout handler ([`Syscall::ThreadSetTimeoutHandler`]). `Retry`
    /// leaves it to wait for the caller's next refill; `Stop` stops it,
    /// failing that caller with [`Error::PeerRestarted`].
    Timeout = 6,
}

impl FaultKind {
    pub const fn from_u64(n: u64) -> Option<FaultKind> {
        Some(match n {
            1 => FaultKind::PageFault,
            2 => FaultKind::GeneralProtection,
            3 => FaultKind::InvalidOpcode,
            4 => FaultKind::DivideError,
            5 => FaultKind::ForeignSyscall,
            6 => FaultKind::Timeout,
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
/// The largest device frame `DeviceFrame` makes: 1 GiB (a video card's
/// memory, mapped as a run of pages).
pub const DEVICE_FRAME_MAX_BITS: u64 = 30;
/// A CNode holds from 2^4 to 2^11 slots, each taking 2^5 bytes.
pub const CNODE_MIN_BITS: u64 = 4;
pub const CNODE_MAX_BITS: u64 = 20;
pub const CNODE_SLOT_BITS: u8 = 5;
/// An address space takes from 2^14 to 2^20 bytes: one page for its
/// top-level table, the rest a pool for the page tables under it.
pub const VSPACE_MIN_BITS: u64 = 14;
pub const VSPACE_MAX_BITS: u64 = 20;
/// PCI buses whose functions an I/O address space can be bound to and
/// whose MSIs can be routed: requester IDs below `PCI_BUSES << 8`. The
/// kernel's IOMMU and interrupt tables reach these, and the bus server
/// numbers no bus beyond them. On x86-64 that is every bus there can be
/// (VT-d's context tables are made as buses are first used); on AArch64
/// it is the 16 whose configuration space QEMU `virt`'s ECAM window
/// holds below 4 GiB.
pub const PCI_BUSES: u64 = if cfg!(target_arch = "aarch64") { 16 } else { 256 };

/// [`Syscall::ThreadRegisters`] operations.
/// The system call it made, Linux's way: number and arguments 0 to 2, in
/// message words 0 to 3 (`rax`, `rdi`, `rsi`, `rdx`; `x8`, `x0`-`x2`).
pub const REGS_SYSCALL: u64 = 0;
/// Arguments 3 to 5 and the stack pointer (`r10`, `r8`, `r9`, `rsp`;
/// `x3`-`x5`, `sp`).
pub const REGS_SYSCALL_MORE: u64 = 1;
/// Sets its thread-pointer register to `rdx` (the FS base on x86-64,
/// `TPIDR_EL0` on AArch64): a user address, or 0.
pub const REGS_SET_TLS: u64 = 2;
/// Its thread pointer, in message word 0.
pub const REGS_TLS: u64 = 3;
/// `rdx` = 1: its system calls go to its fault handler as
/// [`FaultKind::ForeignSyscall`] (and its registers are restored exactly
/// on return, but for the result); 0: they are Superior's again.
pub const REGS_FOREIGN: u64 = 4;
/// `fork`'s child: every register, the thread pointer and the FPU state of
/// the thread in slot `rdx` (Write right), but 0 in the result register
/// (`rax`, `x0`). The thread must be configured and not yet started; it
/// starts where the other will resume.
pub const REGS_FORK_FROM: u64 = 5;
/// Four of the thread's registers from index `rdx`, in Linux's
/// `sigcontext` order (x86-64: `r8`-`r15`, `rdi`, `rsi`, `rbp`, `rbx`,
/// `rdx`, `rax`, `rcx`, `rsp`, `rip`, `eflags`; AArch64: `x0`-`x30`, `sp`,
/// `pc`, `pstate`); past the last, 0. For a signal handler's frame.
pub const REGS_GET: u64 = 6;
/// Sets registers `rdx` and `rdx + 1` (in [`REGS_GET`]'s order) to `r8`
/// and `r9`, of a thread stopped in a fault (waiting for its handler) or
/// not started. The program counter and stack pointer must lie in user
/// space; of the flags only the arithmetic ones (and on x86-64 the
/// direction flag) are taken. An index past the last is ignored.
pub const REGS_SET: u64 = 7;
/// How many registers [`REGS_GET`] numbers.
pub const REGS_COUNT: u64 = if cfg!(target_arch = "x86_64") { 18 } else { 34 };
/// Four words of the thread's floating-point and SIMD state from word
/// `rdx`, as Linux's signal frame has it (x86-64: the 832-byte `xsave`
/// area, the `fxsave` area, header and AVX upper halves, which are 0 where
/// the CPU has no AVX; AArch64: `fpsimd_context`'s body, `fpsr` and `fpcr` in word 0's
/// low and high halves, then `v0`-`v31`); past the last, 0. For a signal
/// handler's frame.
pub const REGS_FP_GET: u64 = 8;
/// Sets words `rdx` and `rdx + 1` (in [`REGS_FP_GET`]'s order) to `r8`
/// and `r9`, of a thread as [`REGS_SET`] allows. On x86-64 MXCSR bits the
/// CPU does not have are dropped (and its mask word is kept), and of the
/// `xsave` header only `XSTATE_BV`'s x87, SSE and AVX bits are taken (with
/// AVX); on AArch64
/// `fpsr` and `fpcr` are 32 bits. An index past the last is ignored.
pub const REGS_FP_SET: u64 = 9;
/// How many words [`REGS_FP_GET`] numbers.
pub const REGS_FP_WORDS: u64 = if cfg!(target_arch = "x86_64") { 104 } else { 65 };
/// A memory barrier on every CPU running in the thread's address space:
/// returns once each has passed one (Linux's `membarrier`). The thread
/// may be running; it is only how the address space is named.
pub const REGS_BARRIER: u64 = 10;

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
    /// A scheduling context: CPU time threads bound to it share. It holds
    /// no budget until configured ([`Syscall::SchedControlConfigure`]),
    /// and deleting its last capability leaves its threads with none.
    SchedContext = 8,
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
            8 => ObjectType::SchedContext,
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
            ObjectType::SchedContext => Some(8),
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

    #[test]
    fn framebuffer_geometry_round_trips() {
        use framebuffer::{BGR, Geometry, RGB};
        for g in [
            Geometry { width: 1280, height: 720, stride: 1280, bytes_per_pixel: 4, format: BGR },
            Geometry { width: 1366, height: 768, stride: 1376, bytes_per_pixel: 3, format: RGB },
            Geometry { width: 3840, height: 2160, stride: 3840, bytes_per_pixel: 4, format: RGB },
        ] {
            assert_eq!(Geometry::unpack(g.pack()), Some(g));
            assert_ne!(g.pack()[0], 0);
        }
        assert_eq!(Geometry::unpack([0, 0]), None, "no screen");
        let bad = Geometry { width: 800, height: 600, stride: 640, bytes_per_pixel: 4, format: RGB };
        assert_eq!(Geometry::unpack(bad.pack()), None, "stride shorter than a row");
    }
}

/// What the kernel gives the root task, the Component Manager, at boot.
/// Its CSpace is a CNode of `1 << CNODE_BITS` slots; the boot bundle (see
/// [`crate::bundle`]) is mapped read-only at [`BUNDLE_VA`](root::BUNDLE_VA)
/// and its length is the root task's first argument.
pub mod root {
    pub const CNODE_BITS: u8 = 12;
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
    /// The state store: [`STATE_PAGES`] frames that keep their contents
    /// across a fast reboot ([`Syscall::Reboot`]), zeroed at power-on.
    pub const STATE_STORE: u64 = IOMMU + 1;
    pub const STATE_PAGES: u64 = 16;
    /// The legacy PCI interrupt lines (IRQ capabilities), up to
    /// [`INTX_COUNT`] of them in consecutive slots from the first, for
    /// functions with no MSI: one for each interrupt input the firmware
    /// routes PCI's pins to. [`Syscall::IntxLine`] says which a pin
    /// reaches. Empty where the kernel does not know the machine's
    /// routing.
    pub const INTX: u64 = STATE_STORE + STATE_PAGES;
    pub const INTX_COUNT: u64 = 8;
    /// I/O ports for PCI BARs: a range of ports on x86-64, on AArch64 the
    /// window of device memory that stands for them.
    pub const PCI_IO: u64 = INTX + INTX_COUNT;
    /// The PS/2 controller (the i8042, where a PC's built-in keyboard
    /// is): its data port 0x60 and its status/command port 0x64, two I/O
    /// port capabilities in consecutive slots. Empty on AArch64.
    pub const PS2: u64 = PCI_IO + 1;
    pub const PS2_COUNT: u64 = 2;
    /// The screen the firmware or bootloader set up (a VESA mode or UEFI's
    /// GOP), as device memory from its first byte, if there is one:
    /// [`Syscall::UntypedInfo`] on it also says its geometry (see
    /// [`framebuffer`](super::framebuffer)). Empty on AArch64.
    pub const FRAMEBUFFER: u64 = PS2 + PS2_COUNT;
    /// The rest of RAM, all the kernel does not keep for itself: up to
    /// [`SPARE_COUNT`] untyped blocks in consecutive slots, from the first
    /// (the rest empty). The Component Manager gives them to the Memory
    /// Server (`untyped spare` in the manifest).
    pub const SPARE: u64 = FRAMEBUFFER + 1;
    pub const SPARE_COUNT: u64 = 32;
    /// The sched-control capability: the right to give scheduling
    /// contexts budgets ([`Syscall::SchedControlConfigure`]).
    pub const SCHED_CONTROL: u64 = SPARE + SPARE_COUNT;
    /// The root task's own scheduling context (unlimited), which threads
    /// it makes share unless it binds them to another.
    pub const SCHED_CONTEXT: u64 = SCHED_CONTROL + 1;
    /// The first slot with nothing in it.
    pub const FIRST_FREE: u64 = SCHED_CONTEXT + 1;
    /// The root task's argument: the bundle's length, and in the bits from
    /// [`REBOOTS_SHIFT`] how many fast reboots came before this start.
    pub const REBOOTS_SHIFT: u32 = 32;
    /// Least size of [`UNTYPED`], in bits: 64 MiB, what every component's
    /// memory comes from. The kernel makes it larger for a bundle that
    /// needs it (room for twice the bundle: the Linux personality's files,
    /// gcc's among them, are copied into its memory).
    pub const UNTYPED_BITS: u8 = 26;
    /// Where the bundle is mapped, as an offset from the user window's base.
    pub const BUNDLE_OFFSET: u64 = 0x1_0000_0000;
    /// The root task's priority; a component can be given at most this.
    pub const PRIORITY: u8 = 60;
}

/// The boot framebuffer's geometry, as [`Syscall::UntypedInfo`] gives it
/// for the framebuffer's device memory ([`root::FRAMEBUFFER`]) in its
/// third and fourth words (both 0 for any other untyped memory).
pub mod framebuffer {
    /// Pixel formats: red, green and blue in that byte order, or blue,
    /// green and red.
    pub const RGB: u64 = 0;
    pub const BGR: u64 = 1;

    /// The screen: its size in pixels, the pixels from one row to the
    /// next, the bytes a pixel takes, and its format.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Geometry {
        pub width: u64,
        pub height: u64,
        pub stride: u64,
        pub bytes_per_pixel: u64,
        pub format: u64,
    }

    impl Geometry {
        /// Packs into two words: width | height << 16 | bytes per pixel <<
        /// 32 | format << 40, and the stride. The first word is never 0.
        pub fn pack(&self) -> [u64; 2] {
            [
                self.width & 0xffff
                    | (self.height & 0xffff) << 16
                    | (self.bytes_per_pixel & 0xff) << 32
                    | (self.format & 0xff) << 40,
                self.stride,
            ]
        }

        /// The geometry packed in `words`, if there is one.
        pub fn unpack(words: [u64; 2]) -> Option<Geometry> {
            let [a, stride] = words;
            let g = Geometry {
                width: a & 0xffff,
                height: a >> 16 & 0xffff,
                bytes_per_pixel: a >> 32 & 0xff,
                format: a >> 40 & 0xff,
                stride,
            };
            let ok = g.width > 0 && g.height > 0 && g.stride >= g.width && (3..=4).contains(&g.bytes_per_pixel);
            ok.then_some(g)
        }

        /// The bytes the screen's rows take.
        pub fn bytes(&self) -> u64 {
            self.stride * self.height * self.bytes_per_pixel
        }
    }
}
