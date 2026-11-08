# Superior

Superior is a capability-secure microkernel desktop operating system.

- **Microkernel:** about 15 kSLOC of Rust with machine-checked invariants and no kernel heap.
- **User-space everything:** drivers, filesystems, network stack, compositor and power management run as isolated, restartable components.
- **No ambient authority:** every right is an explicit, revocable capability; there is no root.
- **Compatibility as guests:** Linux and Windows personalities, Android/Linux/Windows micro-VMs, and x86-64 translation, all sandboxed above the trusted computing base.
- **Advisory AI:** on-device models emit bounded, expiring hints to a deterministic scheduler that works fully without them.
- **Immutable base:** verified and measured boot, A/B system updates, signed content-addressed app packages with rollback.

## Status

Phase 0 (foundations). Working today, under QEMU on x86-64:

- Boot, serial console, GDT/TSS, exception handlers, legacy PIC masked.
- All usable physical memory handed to the root CNode as untyped capabilities; every
  page table and user page is retyped from them. There is no kernel heap.
- `syscall`/`sysret` entry on a single kernel stack, with the seL4 model of saving user
  registers in the thread's TCB. System calls and interrupts share one register frame;
  threads that entered by system call leave by `sysret`, preempted threads by `iretq`.
- Local APIC timer, calibrated against the PIT, at 100 Hz; round-robin time slices within
  a priority level, never handing the CPU to a lower priority.
- Retype from user space: a thread holding untyped memory makes endpoints, notifications
  and smaller untyped blocks with `Retype`; each new capability is a child of the untyped
  one, so revoking the untyped destroys every object made from it (waking threads blocked
  on them with an error) and makes its memory reusable. `CapMint` copies a capability
  with fewer rights or a badge. Endpoint and notification state still lives in fixed
  kernel tables (8 of each) claimed at retype, not in the carved memory.
- Frames: retype makes 4 KiB frames, zeroed when made. `FrameMap` maps one into the
  caller's own address space (never executable; writable only with the Write right;
  needs the Map right), and `FrameUnmap` undoes it. Each frame capability maps once;
  mapping copies shares memory. Deleting or revoking a frame capability unmaps it first,
  so memory is never reused while still mapped. Intermediate page tables still come from
  kernel memory, not from the caller's untyped.
- Threads as objects: retype makes a thread; `ThreadConfigure` sets entry, stack,
  argument and priority (no higher than the creator's) to run in the creator's address
  space, inheriting its fault handler and budget; `ThreadCopyCap` fills its CSpace;
  `ThreadResume` and `ThreadSuspend` start and stop it (a blocked call is cancelled with
  `Interrupted`). Deleting the last capability destroys the thread and empties its CSpace.
  Threads live in the kernel's fixed thread table (8, 4 used at boot).
- CNodes as objects: retype makes a CNode of 16 to 256 slots. `CNodeCopy`, `CNodeDelete`
  and `CNodeRevoke` work on its slots, and `ThreadSetSpace` makes it a thread's CSpace.
  The thread holds its own copy of the CNode capability, so the CNode lives while any
  capability or thread refers to it; revoking the untyped it came from destroys it.
  CNode slots come from a fixed pool of 256 in the kernel's capability table.
- User faults as messages: a thread names a fault endpoint (`SetFaultHandler`); a page
  fault, general-protection fault, invalid opcode or divide error in user mode becomes a
  `Call` to it (kind, address, rip, error code). The handler's reply retries the
  instruction, resumes at a new rip with a value in `rax`, or stops the thread. A thread
  with no handler is stopped and logged; a kernel-mode fault still panics.
- Scheduling contexts (MCS): each thread owns one, unlimited unless given a budget per
  period. Budgets are charged per tick and refilled each period (periodic, not yet
  sporadic); a thread that runs dry is throttled until the refill. A passive server
  (`SchedPassive`) runs only on its caller's context, lent on `Call` and returned on
  reply, so serving a client is charged to that client.
- Idle: with every thread blocked the kernel halts the CPU until an interrupt makes one
  runnable. The timer signals a notification each tick, so threads sleep by waiting on it.
- IPC engine: `Send`, `Call`, `Recv`, `Reply`, `ReplyRecv`, `Signal`, `Wait`, `Yield`;
  direct switch on call/reply (fast path); 64 fixed priorities.
- Rights-checked capability lookup on every system call; badges delivered to servers.
- Capability transfer in IPC: a sender grants a slot, the receiver names an accept slot,
  and the receiver gets a copy derived from the sender's. Every CSpace is a window onto
  one capability table, so the derivation tree spans CSpaces and `CapRevoke` removes every
  copy handed out. Grant needs the Grant right on the endpoint; a reply may grant if the
  caller's capability had Grant or GrantReply.
- Static-pie user programs loaded into their own address spaces and relocated.
- Boot self-test: a server and a client in separate address spaces do 20,000
  call/reply round trips, and the kernel refuses four kinds of rights violations. A
  spinner at the client's priority, queued ahead of it, never makes a system call, so the
  client finishes only because the timer preempts it. The client also receives a
  capability in a reply, uses it, watches the server revoke it, and checks that ungranted
  or out-of-range transfers are refused. The client then sleeps on the timer
  notification with every other thread blocked, so the CPU idles and the timer wakes it.
  Self-test builds fail after 60 seconds instead of hanging. A hog at the top priority
  spins forever on a budget of 2 ticks in 10; without the budget nothing else runs and the
  test times out. The IPC server is passive, and the kernel checks that ticks were charged
  to its callers. The client gets 64 KiB of untyped memory and makes, uses, revokes and
  re-makes objects from it, down to filling the notification table. It maps frames,
  shares one through a read-only copy, and checks that revoking unmaps them and that
  reused memory comes back zeroed. The server doubles as the client's fault handler and
  emulates a faulting load, a store to a read-only page, `hlt` and `ud2`; the spinner
  ends by faulting with no handler and is stopped. The client creates a worker thread in
  its own address space, checks it ran with its copied capabilities and inherited fault
  handler, suspends and resumes it, then destroys it and refills the thread table. It makes a
  CNode, fills it with badged copies, runs a thread with it as its CSpace, and checks the
  CNode outlives the client's capability but not its last thread.

Not yet: page tables paid for from user untyped memory, mapping into other address
spaces, new address spaces as retypable objects, multi-level CSpaces, scheduling-context capabilities (budgets are set at boot), sporadic refills,
timeout faults, SMP, an IPC benchmark on real hardware.

The architectural specification lives in the Superior OS Architectural Specification doc:
https://claude.ai/artifact/QKJS8qH5Dfbjzn58RStq1j

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | The microkernel (`no_std`, target `x86_64-unknown-none`) |
| `crates/objects/` | Pure kernel logic, unit-tested on the host: capabilities and CNodes, untyped memory, the IPC and scheduling state machine, the syscall ABI, an ELF reader |
| `user/pingpong/` | Boot self-test program (IPC server, client and spinner) |
| `xtask/` | Build driver: user program, kernel, disk image, QEMU boot |

## Building

Needs Rust (the pinned nightly in `rust-toolchain.toml` installs itself) and QEMU.

```bash
cargo xtask test   # host unit tests, then boot self-tests in QEMU
cargo xtask run    # boot in QEMU with the serial console on this terminal
cargo xtask image  # just build target/superior.img
```

QEMU is found via `$QEMU`, then `C:\Program Files\qemu`, then `PATH`.

## Roadmap

| Phase | Months | Focus |
| --- | --- | --- |
| P0 | 0 to 6 | Foundations: bootloader, kernel core, QEMU bring-up |
| P1 | 5 to 15 | Core runtime, supervision, driver framework, class drivers |
| P2 | 12 to 24 | Graphics, UX, audio, Wi-Fi, verified boot, A/B updates |
| P3 | 18 to 30 | Compatibility: Linux and Windows personalities, micro-VMs, translation |
| P4 | 24 to 34 | Scheduling intelligence, Sentinel, proofs, hardening |
| P5 | 30 to 36 | Developer Preview readiness |
