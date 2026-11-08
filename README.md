# Superior

Superior is a capability-secure microkernel desktop operating system.

- **Microkernel:** about 15 kSLOC of Rust with machine-checked invariants and no kernel heap.
- **User-space everything:** drivers, filesystems, network stack, compositor and power management run as isolated, restartable components.
- **No ambient authority:** every right is an explicit, revocable capability; there is no root.
- **Compatibility as guests:** Linux and Windows personalities, Android/Linux/Windows micro-VMs, and x86-64 translation, all sandboxed above the trusted computing base.
- **Advisory AI:** on-device models emit bounded, expiring hints to a deterministic scheduler that works fully without them.
- **Immutable base:** verified and measured boot, A/B system updates, signed content-addressed app packages with rollback.

## Status

Phase 0 (foundations). The kernel boots on x86-64 under QEMU, loads its GDT/TSS and
exception handlers, and hands all usable physical memory to the root task as untyped
capabilities. There is no kernel heap.

The architectural specification lives in the Superior OS Architectural Specification doc:
https://claude.ai/artifact/QKJS8qH5Dfbjzn58RStq1j

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | The microkernel (`no_std`, target `x86_64-unknown-none`) |
| `crates/objects/` | Kernel object model: capabilities, CNodes, untyped memory. Pure logic, unit-tested on the host |
| `xtask/` | Build driver: kernel build, disk image, QEMU boot |

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
