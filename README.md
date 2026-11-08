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
- IPC engine: `Send`, `Call`, `Recv`, `Reply`, `ReplyRecv`, `Signal`, `Wait`, `Yield`;
  direct switch on call/reply (fast path); 64 fixed priorities.
- Rights-checked capability lookup on every system call; badges delivered to servers.
- Static-pie user programs loaded into their own address spaces and relocated.
- Boot self-test: a server and a client in separate address spaces do 20,000
  call/reply round trips, and the kernel refuses four kinds of rights violations. A
  spinner at the client's priority, queued ahead of it, never makes a system call, so the
  client finishes only because the timer preempts it.

Not yet: an idle thread, scheduling contexts (MCS budgets), capability transfer in
messages, retype into kernel objects from user space, SMP, an IPC benchmark on real hardware.

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
