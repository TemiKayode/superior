# Superior

Superior is a capability-secure microkernel desktop operating system.

- **Microkernel:** about 15 kSLOC of Rust with machine-checked invariants and no kernel heap.
- **User-space everything:** drivers, filesystems, network stack, compositor and power management run as isolated, restartable components.
- **No ambient authority:** every right is an explicit, revocable capability; there is no root.
- **Compatibility as guests:** Linux and Windows personalities, Android/Linux/Windows micro-VMs, and x86-64 translation, all sandboxed above the trusted computing base.
- **Advisory AI:** on-device models emit bounded, expiring hints to a deterministic scheduler that works fully without them.
- **Immutable base:** verified and measured boot, A/B system updates, signed content-addressed app packages with rollback.

## Status

Phase 0 (foundations) is complete; Phase 1 (core runtime and drivers) has begun with the
Component Manager. Working today, under QEMU on x86-64 and AArch64 (one kernel:
capabilities, threads, IPC, scheduling and the system calls are shared; `kernel/src/arch`
holds the rest):

- AArch64 on QEMU's `virt` machine: entered at EL1 from the kernel ELF, MMU and caches on
  before any Rust runs, an identity map of devices and RAM for EL1 only, 4-level page
  tables for user address spaces at the same user window as x86-64, the device tree read
  for RAM, a GICv3 with an ITS, the generic timer at 100 Hz, EL0/EL1 exception vectors (`svc`, aborts,
  undefined instructions, trapped `wfi`, interrupts, `brk`), and semihosting for the exit
  status. The same user programs (built as static PIE for `aarch64-unknown-none-softfloat`)
  pass the same boot self-tests and shell session; faults are reported in the same terms
  on both, so fault handlers are portable. The shell drives the PL011 through a device
  frame it maps, and `shutdown` uses the same exit-port capability, emulated.

- Boot, serial console, GDT/TSS, exception handlers; the legacy PIC remapped to vector
  0x20 with every line masked until a driver claims one.
- All usable physical memory handed to the root CNode as untyped capabilities; every
  page table and user page is retyped from them. There is no kernel heap.
- Several CPUs (SMP; QEMU runs every test with 2, `SUPERIOR_CPUS` sets up to 4): the
  other CPUs start through an INIT/start-up trampoline that climbs from real mode to long
  mode (x86-64) or PSCI `CPU_ON` (AArch64), each with its own kernel stack, GDT and TSS or
  redistributor, and timer. One kernel lock covers all kernel work, taken in turn (a
  ticket lock, so no CPU waits behind the others for ever); the IPC engine keeps
  a current thread per CPU and a shared set of ready queues, so any CPU runs the
  highest-priority thread it can. A thread another CPU stops (suspended, destroyed, its
  scheduling context gone) stays with its own CPU until that CPU next enters the kernel
  and saves its registers, and nobody else may run it before then; a system call it was
  making is made again, and every tick, interrupt signal or reschedule on a CPU lets go
  of such a thread first (an interrupt in the idle loop can hand a CPU a thread that
  another stops before the CPU runs it). A thread that crashes owing a reply fails its
  caller with `PeerRestarted` whichever CPU stops or destroys it first. CPUs kick each other with an interrupt when one's work leaves
  another something better to run, and only CPU 0's timer keeps the system's time
  (ticks, budget refills, sleeps). An unmapped page or a destroyed address space is
  flushed or unloaded on every CPU that has the space loaded before the kernel goes on:
  the CPU doing it asks each one by interrupt and waits, and a CPU waiting for the
  kernel lock answers such requests while it waits, so the wait cannot deadlock. Device
  interrupts go to CPU 0; code a CPU loads is made visible to every CPU's instruction
  cache. The boot self-test checks that every CPU ran user threads; the engine's
  simulation runs every seed on 2, 3 and 4 CPUs too, including interrupts that reach an
  idle CPU; and every QEMU test passes with 1, 2 and 4 CPUs. Test logs are checked in
  order per thread, since threads on different CPUs print in either order.
- `syscall`/`sysret` entry on each CPU's kernel stack (found through `swapgs`), with the
  seL4 model of saving user registers in the thread's TCB. System calls and interrupts share one register frame;
  threads that entered by system call leave by `sysret`, preempted threads by `iretq`.
- Local APIC timer, calibrated against the PIT, at 100 Hz; round-robin time slices within
  a priority level, never handing the CPU to a lower priority.
- Retype from user space: a thread holding untyped memory makes endpoints, notifications
  and smaller untyped blocks with `Retype`; each new capability is a child of the untyped
  one, so revoking the untyped destroys every object made from it (waking threads blocked
  on them with an error) and makes its memory reusable. `CapMint` copies a capability
  with fewer rights or a badge. Endpoint and notification state still lives in fixed
  kernel tables (32 of each) claimed at retype, not in the carved memory.
- Frames: retype makes 4 KiB frames, zeroed when made. `FrameMap` maps one into the
  caller's own address space (never executable; writable only with the Write right;
  needs the Map right), and `FrameUnmap` undoes it. Each frame capability maps once;
  mapping copies shares memory. Deleting or revoking a frame capability unmaps it first,
  so memory is never reused while still mapped. Page tables for a boot process's address
  space come from kernel memory; an address-space object pays for its own (below).
- Threads as objects: retype makes a thread; `ThreadConfigure` sets entry, stack,
  argument and priority (no higher than the creator's) to run in the creator's address
  space, inheriting its fault handler and budget; `ThreadCopyCap` fills its CSpace;
  `ThreadResume` and `ThreadSuspend` start and stop it (a blocked call is cancelled with
  `Interrupted`). Deleting the last capability destroys the thread and empties its CSpace.
  Threads live in the kernel's fixed thread table (32).
- CNodes as objects: retype makes a CNode of 16 to 2048 slots. `CNodeCopy`, `CNodeDelete`
  and `CNodeRevoke` work on its slots, and `ThreadSetSpace` makes it a thread's CSpace.
  The thread holds its own copy of the CNode capability, so the CNode lives while any
  capability or thread refers to it; revoking the untyped it came from destroys it.
  CNode slots come from a fixed pool of 4096 in the kernel's capability table.
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
- Idle: a CPU with no thread it can run halts until an interrupt (or a kick from another
  CPU) gives it one. The timer signals a notification each tick, so threads sleep by waiting on it.
- IPC engine: `Send`, `Call`, `Recv`, `Reply`, `ReplyRecv`, `Signal`, `Wait`, `Yield`;
  direct switch on call/reply (fast path); 64 fixed priorities. A server may set a
  caller aside (`ReplySave`, up to 16) and answer it later (`ReplyTo`), taking other
  calls meanwhile; if it dies they get `PeerRestarted`, if it is suspended
  `ReplyAbandoned` (the simulator checks every waiting caller is owed by exactly one).
- Bound notifications (as in seL4): `NotificationBind` ties a notification to the
  calling thread, whose `Recv` and `ReplyRecv` then also return when it is signalled
  (status `Notified`, the bits as the badge). Pending bits come before queued callers.
  One server loop waits for calls and for its rings' doorbells at once.
- Timers: `TimerSignal` signals a notification once, a number of ticks from now, with
  the capability's badge (a new deadline replaces the old; 0 cancels; 64 pending
  across the system, cleared when the notification is destroyed). A thread waits
  with a timeout by waiting on a notification it also set a timer on. `Sleep` blocks
  the caller for a number of ticks on a notification of its own that only the kernel
  signals, so no capability is needed; no program polls the clock in a loop (that
  costs a whole CPU on a multiprocessor), and one with nothing left to do parks on a
  sleep instead of yielding for ever.
- Rights-checked capability lookup on every system call; badges delivered to servers.
- Capability transfer in IPC: a sender grants a slot, the receiver names an accept slot,
  and the receiver gets a copy derived from the sender's. Every CSpace is a window onto
  one capability table, so the derivation tree spans CSpaces and `CapRevoke` removes every
  copy handed out. Grant needs the Grant right on the endpoint; a reply may grant if the
  caller's capability had Grant or GrantReply.
- Formal model of capability derivation (`crates/objects/src/model.rs`): an independent
  specification (a derivation forest with ghost provenance for every carve) that the
  real `CNode` must refine. A checker runs every operation (derive with masks and badges,
  retype of sub-blocks, whole blocks and frames, delete, revoke) from every reachable state
  of a 4-slot table until no new state appears: 2,756,509 states and 286,676,936
  transitions. After each step it checks refinement, no rights amplification, badge
  integrity, a well-formed tree, that no byte is handed out twice, and that a block with
  nothing made from it can always be carved again. Planting an allocator bug is caught
  in two steps. It is bounded model checking of an executable model, not a proof.
- Deterministic simulation (`crates/objects/src/sim.rs`): a seeded generator drives the
  IPC and scheduling engine with random system calls and outside events (ticks,
  interrupts, suspends, thread re-creation, budget changes, destroyed objects). After
  every step it checks the engine's structural invariants (queues, one running thread
  at the highest ready priority, budgets, reply links) and message integrity (every
  message received was sent once, with its badge, and never after its sender was
  stopped). Every seed runs twice and must replay identically; a failure prints the seed
  and the last steps (`SIM_SEED`, `SIM_STEPS` replay it). `cargo xtask test` runs
  10,000 seeds of 5,000 steps. It found six engine bugs, all fixed; three have their own regression tests.
- A shell in user space (`user/shell/`), booted by default. It is also its own serial
  driver: the kernel hands it COM1's I/O ports (`IoPortIn`, `IoPortOut` on an I/O-port
  capability) and the UART's interrupt line (`IrqSetNotification`, `IrqAck` on an IRQ
  capability). Each interrupt masks the line and signals a notification; the shell drains
  the UART and acknowledges, which unmasks it. Commands: `help`, `about`, `echo`,
  `sleep` (on the timer notification), `ipc` (times call/reply round trips to an echo
  thread it makes from its own untyped memory) and `shutdown`. `cargo xtask test` types
  a session into it over the serial port, byte by byte, checks every answer, and needs
  `shutdown` to power QEMU off.
- IPC benchmark (`cargo xtask bench`): the shell's `ipc` times call and reply one way
  each, as seL4's sel4bench does, under hardware virtualization (WHPX on Windows, KVM
  elsewhere), five runs of 100,000 round trips after a warm-up. On an i7-1165G7 under
  Hyper-V: median call 504 and reply 496 TSC cycles, against seL4's published MCS figures
  of 771 and 667 on Skylake (0.65x and 0.74x; the gate is 1.5x). The TSC runs at the
  nominal 2.8 GHz while the core may turbo to 4.7 GHz, so in core cycles the ratio could
  be up to 1.68x worse (1.10x and 1.25x), still inside the gate. Not measured on bare metal.
- The same shell on seL4 (`cargo xtask sel4-test`, also the last step of `cargo xtask
  test`): built with the `sel4` feature of `superior-sys`, it becomes seL4's root task
  (seL4 17.0.0, AArch64, QEMU virt), and a small runtime translates each Superior system
  call into seL4 system calls and invocations. Its UART frame, interrupt, notifications
  and untyped memory are made from seL4's boot capabilities; `sleep` waits on the EL1
  physical timer's interrupt; `ipc` calls an echo thread made through `TCB_Configure`
  and friends. The scripted session passes unchanged. seL4 is built in hypervisor mode,
  because rust-sel4's kernel loader enters the kernel at EL2; it and the loader are built
  once in Docker (`sel4/`), against a device tree dumped from the QEMU that boots it.
- Address spaces as objects: retype makes an address space of 16 KiB to 1 MiB; its
  top-level page table and every table under it come from that memory, so it can map
  only as much as it paid for and gives everything back when destroyed. `FrameMapInto`
  maps a frame into an address space the caller holds, writable or executable, never
  both; `ThreadSetVSpace` puts a thread in one (the thread holds its own reference).
  `ThreadSetFaultHandler` names another thread's fault handler, with a badge. `Retype`
  can place the new capability straight into a CNode the caller holds, so a parent can
  give a child original capabilities (untyped memory it can retype in turn).
- The Component Manager (`user/cm/`), the root task: the kernel starts only it, with
  every capability (memory, timer, console UART and interrupt, exit port) and the boot
  bundle mapped read-only. It reads the manifest in the bundle (`boot/*.manifest`,
  parsed by `crates/objects/src/manifest.rs`) and builds each component from its own
  untyped block: an address space, a 64-slot CNode, a thread, the frames it loads the
  executable into (relocated, mapped with each segment's permissions), a stack. Each
  component gets only the capabilities its manifest names: services it provides (the
  receive side) or uses (badged per client), devices, notifications, untyped memory, a
  control endpoint. The manager makes and keeps every service endpoint, and is every
  component's fault handler. A `start lazy` component starts on the first call to its
  service: a watcher thread takes the call, has it started, forwards the call under the
  client's badge and relays the reply. The shell now boots as a component.
  `cargo xtask cm-test` boots `boot/test.manifest` and checks the log: a probe reading
  the manager's memory faults and the manager is told; the lazy `echo` starts only on
  the client's first call, which is answered (forwarded under the client's badge 2);
  `spare`, which nothing calls, never starts.
- Supervision (spec section 4). A component that faults is restarted by its manifest's
  `restart` policy: `one-for-one` (the default) rebuilds just it, `rest-for-one` also
  rebuilds every running component after it, `never` leaves it stopped. The manager
  revokes the instance's untyped block and builds a new instance from the same block,
  attached to the same endpoints, so queued calls wait for it. The kernel fails a call
  the dead instance was serving with `PeerRestarted`; `superior_sys::call_retry`
  repeats such calls, for idempotent requests or ones carrying a request id. More than
  five restarts within sixty seconds (counted with the new `Ticks` call) and the
  manager gives up: a tombstone thread answers the component's services with
  `SERVICE_UNAVAILABLE`. A `state` capability is a page made once and handed to every
  instance, so state outlives instances. `shared <pages> <slot>` (up to 16) is the same
  for memory a component shares with a server: the manager holds the originals, so a
  restart of either side deletes only that side's copies and the other's mappings stay. `cargo xtask supervise-test` boots
  `boot/supervise.manifest`: a `counter` service keeps its value and a per-client
  request journal in its state page, is crashed under a call and finds its value
  again, and is crashed after applying a request but before replying, whose retry is
  answered from the journal instead of applied twice; a component that faults at every
  start is restarted five times, then given up on, and its client is told so; crashing
  a rest-for-one component restarts the one after it.
- Driver framework v1 (spec section 5). Drivers are ordinary components that reach
  exactly one device:
  - Kernel: device-memory capabilities (`DeviceUntyped`), which make only frames,
    never zeroed and never kernel objects; `DeviceFrame` picks the page.
  - Kernel: MSI vectors delivered as notification signals, with `IrqMsiMessage`
    saying what the device must write. MSIs are remapped, since an MSI is just a
    DMA write: `IrqMsiMessage` also names the I/O address space of the function
    that may raise the vector, and only that function's requester ID can. On
    x86-64 each vector has a VT-d interrupt remapping table entry that checks the
    requester ID (compatibility-format messages are blocked; invalidation goes
    through VT-d's invalidation queue). On AArch64 the GICv3 ITS keeps a
    translation table per device, so a device's message raises an LPI only if
    that device's table maps it. Unbinding a function's space takes its
    vectors away too.
  - Kernel: the IOMMU. Intel VT-d on x86-64 (QEMU q35 with `intel-iommu`) and Arm
    SMMUv3 on AArch64 (`virt,iommu=smmuv3`) share one I/O page-table walker
    (`kernel/src/iommu.rs`). Once the kernel turns the IOMMU on, no PCI function
    can reach any memory. An I/O address space (`IoSpace`, an IOMMU domain) is
    made from untyped memory like an address space, and bound to one function's
    requester ID with the IOMMU-control capability (`IoSpaceBind`). `IoMap` puts a
    page of RAM (never device memory) into it, and deleting or revoking that frame
    capability takes it out again. Destroying the space unbinds the function first,
    so its DMA stops before anything else happens. Blocked requests are reported:
    the IOMMU's fault interrupt (VT-d's fault event message, or the SMMU's event
    queue interrupt, the wired SPI its device-tree node names) has the kernel drain
    VT-d's fault recording registers or the SMMU's event queue at once (the timer
    tick drains them too), credit each fault to the space bound to its requester
    ID, and signal the notification the space's holder bound with `IoFaultNotify`;
    `IoFaults` tells the space's holder how many there were since it last
    asked, the first one's page and whether it was a write, and how many
    interrupt messages VT-d blocked (the ITS drops them without a report).
  - The root task gets PCI configuration space (ports 0xcf8-0xcff, or ECAM), a BAR
    window and eight MSI vectors, and gives them to the PCI bus server
    (`user/pcibus/`), the only component that touches configuration space. It finds
    the functions on bus 0 and behind bridges, assigns BARs, and serves the versioned `pci` interface
    (`crates/objects/src/interfaces.rs`). A bridge (a PCI Express root port, say)
    is configured, not handed out: the scan gives it the next bus number (first
    clearing the numbers firmware left, so no two bridges answer for one bus),
    and walks the bus behind it. Then each of a bridge's three windows (memory,
    prefetchable memory, I/O ports) is set to exactly what the BARs of that kind
    behind it take, side by side, a bridge's ranges lying inside those of the
    bridge above; a window with nothing behind it stays shut. I/O BARs get ports
    from a range the kernel hands the root task (0xd000 up on q35; on `virt` the
    window of device memory that stands for ports). A driver does not get the
    ports: it reads and writes its I/O BAR through the bus server (`pci::IO_READ`,
    `IO_WRITE`), which keeps every access inside the BAR. `pci::CLOSE` gives a
    function back. Hot-plug: a PCI Express port on bus 0 whose slot takes cards
    while the machine runs is looked at five times a second. A card that appears
    is powered, found and given addresses (the port's windows move to them) and
    is opened like any other; one whose attention button is pressed, or that is
    gone, first loses everything (its functions' domains, BAR pages and
    interrupts are revoked, whoever held them), then the slot is powered off,
    which lets it go. `cargo xtask hotplug-test` plugs a card in through QEMU's
    monitor, takes it out and plugs another in, on both ISAs: the client opens
    the first, finds its page and domain revoked when it goes, and opens the
    second. The NVMe test reads an RTL-8139's registers through its I/O
    BAR behind a root port and compares them with its memory BAR, and reaches a
    virtio device's prefetchable BAR through a bridge's prefetchable window. Every bus can be numbered on x86-64 (VT-d's
    context table for a bus is made when a function on it is first bound), and
    the 16 that `virt`'s configuration window holds on AArch64 (the SMMU stream
    table and ITS device table are sized for them, `abi::PCI_BUSES`), so a
    function on any of them gets a domain of its own and its MSIs are checked
    against its own requester ID. Behind a conventional bridge a
    function's DMA carries the bridge's ID instead, so it is opened with no
    domain and refused bus mastering. The NVMe tests put the controller behind the
    tenth root port (bus 10) and a virtio device behind a conventional bridge (bus 11). A driver opens one function and gets only
    its BAR pages and MSI vectors; configuration writes are limited to bus
    mastering, MSI-X and plain MSI (`pci::MSI`: the bus server writes the
    function's vector into its MSI capability, for devices without MSI-X). Each opened function gets a new, empty IOMMU domain with
    the `OPEN` reply; without an IOMMU, bus mastering is refused. Opening resets
    the function: the last owner's domain revoked first (every copy, so its DMA is
    blocked), then decoding and bus mastering off, the last owner's BAR pages and
    vectors revoked, MSI-X and MSI off, then a Function Level Reset where the device has
    one.
  - The Driver SDK (`crates/driver/`): the bus server client, MMIO registers, DMA
    pages mapped into the device's domain, split virtqueues, DMA buffer pools
    (`pool`: equal buffers that never cross a page, taken and given back in
    constant time, a buffer given back twice refused) and an executor (`exec`:
    `async` tasks on the driver's one thread, woken by events, with whatever the
    driver blocks in as the idle step; no allocation). The virtio-net driver is
    written with both: its buffers are two pools, and its loop is an interrupt
    task and a service task. Both are tested on the host as well (12 tests).
  - An IDL compiler (`crates/idl/`): an interface is described once, in a small
    text format (`interfaces/pci.idl`: a version, then each operation's number,
    arguments, results and documentation), and `cargo xtask idl` generates Rust from
    it (`crates/objects/src/idl/`): the operation numbers, a function building each
    call's message (the version filled in where the call carries it) and a reader
    for each reply that gives its results or the status it failed with. The Driver
    SDK makes every call to the bus server through it. `cargo xtask test` first
    checks the generated file matches its description (so neither drifts), tests the
    compiler (malformed descriptions are refused with their line) and checks the
    generated numbers against the hand-written interface the bus server answers.
  - Legacy PCI interrupts, for devices with no MSI: the kernel hands the root task
    an IRQ capability for each of the bus's four interrupt wires (on QEMU's q35 it
    steers the ICH9's PIRQ[E-H] to PIC lines 10, 11, 5 and 9 and marks them
    level-triggered; on `virt` they are shared interrupts 35 to 38), the bus server
    works out which wire a function's pin drives (rotating through bridges) and
    gives that line to its driver (`pci::INTX`), one function a line. The kernel
    masks the line as it signals; the driver unmasks it (`IrqAck`) once its device
    has let go.
  - The Linux Driver Environment (`crates/lde/`) hosts an unmodified Linux driver
    in a component. Linux's source file is compiled as it is (clang, in the build
    container) against the environment's own headers, which give it Linux's kernel
    API by name: PCI, `ioremap` and register access, `dma_alloc_coherent` and
    `dma_map_single`, DMA pools, `request_irq`, network devices, NAPI, socket
    buffers, MII, kernel timers, work, `request_firmware` (it finds none) and
    `printk`. `c/lde.c` implements that for one PCI device and one
    network interface, and a Rust host under it holds the component's
    capabilities: it finds the device from the driver's own ID table, gives the
    driver memory from a pool that is all the device's IOMMU domain holds, runs
    the driver's interrupt handler and receive poll from the component's one
    thread (so Linux's locks are empty), and serves the `nic` interface, frame
    rings included: what the driver delivers goes into the receive ring and what
    the server puts in the transmit ring goes to the driver's transmit routine. The
    driver gets no more than a native one does. Two drivers from Linux 6.6 run
    this way: RealTek's `8139cp` (`user/lde-8139cp/`, on QEMU's RTL-8139C+) and
    Intel's `e100` (`user/lde-e100/`, on QEMU's 82557), which brings a watchdog
    timer, a work item, a DMA pool and a firmware request with it. Linux is
    GPL-2.0, so its source is not in this repository; `cargo xtask` fetches each
    file from kernel.org and checks its SHA-256. A driver killed in the middle of
    something leaves its device there (these cards have no reset the bus server
    can give), so the host tries a failed probe once more. `cargo xtask lde-test`
    and `lde-e100-test` run the whole network test over each on both ISAs (pings, datagrams to 65,507 bytes, DNS, TCP,
    IPv6) while the injector kills the Linux driver, the network server and the
    resolver: each restart probes the device again from nothing.
  - A virtio-blk driver (`user/virtio-blk/`) serves the versioned `block`
    interface: reads land by DMA straight in a frame the client lends with the call.
    The device reaches that frame only while the read is in flight: the driver maps
    it into the domain, and deleting it before the reply unmaps it.
  - An NVMe driver (`user/nvme/`), the first class driver: it opens the first
    function of class 01:08:02 (`pci::OPEN_CLASS`), whoever made it, and serves the
    same `block` interface. It disables the controller, sets up the admin queues,
    identifies the controller (its write cache) and every active namespace (size and
    block size), and creates two I/O queue pairs (as many as the controller grants,
    up to two), each with its own MSI-X vector and its own thread: the main thread
    serves the first, and a thread the driver makes in its address space, with a
    small CSpace laid out like the main one, serves the second. Both receive on the
    one `block` endpoint, so two requests are in flight at once, one PRP entry each
    (a request is at most a page). Each namespace is a unit of the `block`
    interface: calls name a unit in their last word (0 for the first), and `INFO`
    says how many there are. Every command waits on a timer as well as its
    interrupt, so one that never completes times out.
  - An AHCI (SATA) driver (`user/ahci/`), opening the first function of class
    01:06:01. The bus server cannot reset such a controller (no Function Level
    Reset), so the driver resets the whole controller itself on every start, then
    brings up every port with a link and serves each one that reports an ATA disk
    (its signature arrives only once the port receives FISes) as a unit of `block`,
    in port order, with a command list, received-FIS area and command tables of its
    own. It identifies each disk (48-bit size, write cache, native command queuing).
    Two serving threads, each with a command slot of its own on every port, receive
    on the one endpoint; where the controller and disk do NCQ, reads and writes are
    READ/WRITE FPDMA QUEUED with the slot as the tag, so the disk holds both at once
    (otherwise READ/WRITE DMA EXT, one at a time per port). FLUSH CACHE EXT takes
    the port for itself. With one plain MSI for the whole controller, the main
    thread takes the interrupt, works out from each port's SACT and CI which slots
    finished (a task-file error restarts the port and fails what was on it) and
    wakes their threads; every command also waits on a timer.
  `cargo xtask drivers-test` boots `boot/drivers.manifest` with a test disk:
  - the client reads it and checks every word;
  - the bus server refuses the client the driver's device and its BARs;
  - (virtio-blk) the driver takes a second vector, routed to no device, and points
    its device's MSI-X entry at it: that vector must not be raised, and VT-d must
    report the blocked interrupt (with interrupt remapping turned off, the vector
    is raised and the test fails);
  - the driver points its device at a page of its own outside the domain, and the
    page must stay untouched (it does on both ISAs; with QEMU's virtio IOMMU
    bypass left on, the same test fails), and the IOMMU must report a blocked
    write to exactly that page, through its fault interrupt; virtio-blk's driver
    binds a notification to its domain's faults first and must be signalled;
  - the driver is crashed, restarted, its device reset and reopened, and reads work
    again;
  - two client threads read 40 times each at once, every word right; NVMe must
    report using both of its I/O queues, and AHCI both of its command slots (NCQ
    tags), with two commands in flight at once.
  With NVMe the controller has a second namespace, and with AHCI port 1 a second
  disk, a small disk of its own pattern: the client must see it as unit 1, of its
  own size, read its own data from it, and be refused past its end and for the
  unit after the last (on x86-64 the boot disk, on AHCI port 2, is unit 2).
  `cargo xtask nvme-test` and `cargo xtask ahci-test` run that test and the
  filesystem test with the disk on QEMU's NVMe controller or on an AHCI port (q35's
  own ICH9 controller on x86-64, with the boot disk moved to port 2; one added on
  AArch64), the manifests' `virtio-blk` swapped for the driver; `cargo xtask test`
  runs all three drivers on both ISAs. Through the IOMMU the stray read leaves the
  page untouched (both QEMU controllers then report the command a success); the
  bus server resets the NVMe controller with a Function Level Reset on every
  restart; under the filesystem test's fault injection a controller still writing
  for a killed driver is blocked by the IOMMU.
- The Memory Server, v1 (`user/memserver/`). It holds a pool of RAM and hands
  out pages under per-component quotas, which the Component Manager puts in the
  badge of each component's `mem` capability (manifest `quota`), so they cannot be
  forged. It keeps the original of every page it gives, so it can always take one
  back: revoking the original removes every copy and mapping. Pages that come back
  are zeroed and reused.
  - Demand-zero heaps (manifest `heap`): a page fault in a component's heap goes to
    the manager, which asks the Memory Server to map a zeroed page there (lending it
    the component's address space) and resumes the thread. Past the quota, the fault
    is a crash and supervision takes over.
  - `FRAME`, `FREE` and `INFO` for pages a component asks for directly.
  - Stopping or restarting a component gives every page it held back first.
  - Copy-on-write cloning (for `fork`): `SHARE` makes a component's heap pages
    read-only and shared, and `CLONE` maps them, read-only and at the same
    addresses, in another component (manifest `start clone`, the clone of the
    component before it with the same image and heap). Each mapping holds its own
    copy of the page's original capability, so revoking the original still takes
    every one. A write faults to the manager, and `FAULT` gives the writer a copy of
    the page, or the frame itself once no one else maps it; each mapping is charged
    to its holder, so breaking the sharing never needs more quota. The page logic
    (`crates/objects/src/pages.rs`) is host-tested against a model kernel with
    randomized requests (300 seeds of 400 steps each run; 20,000 on demand), checking
    every component's view of every page after each step; it found both bugs planted
    to test it.
  - Fast reboot (spec section 4): the Component Manager and the Memory Server are
    not restarted in place. If either fails (a fault, a panic, or the manager
    asking with the new `Reboot` call), the kernel revokes the manager's untyped
    memory, which takes every component, page and capability with it, tears the
    manager down and starts it again from the same memory. Its page tables come from
    an arena reset each time, so nothing leaks, and a state store of 16 pages,
    zeroed once at first boot, is handed to each new manager, which gives components
    their state pages from it, so they outlive the reboot. At most five reboots in
    60 s, then the system stops.
  - Components may have larger CSpaces (manifest `cspace`, up to 2^10 slots).
  `cargo xtask memory-test` boots `boot/memory.manifest`:
  - a client pages its heap in by touching it, and every page arrives zeroed;
  - it takes frames up to its quota and is refused one more;
  - it frees one, and the capability is gone;
  - a hog touches more heap than its quota and is restarted, with all 8 pages back
    in the pool; its next instance gets those same pages, zeroed;
  - a clone of the client starts sharing its heap pages; each side writes some,
    gets its own copies, and still sees the other's unwritten pages as they were.
  `cargo xtask reboot-test` boots `boot/reboot.manifest`: a client with a state
  page has the injector kill the Memory Server and then the manager itself; each
  time the system reboots fast, the client starts again, its heap pages zeroed,
  and finds its state page as it left it.
- The filesystem server, v2 (`user/fs/`), over the block interface (which has
  `WRITE` and `FLUSH`; the virtio-blk driver negotiates the device's write cache).
  - No global namespace: each component sees only its own tree, under a root
    picked by the badge on its capability, so the same component finds the same
    files after a restart.
  - POSIX-shaped: `/`-separated, case-sensitive paths (lent in a frame);
    directories; `OPEN` with create, exclusive and truncate flags; `MKDIR`,
    `UNLINK` (files and empty directories), `RENAME` (replacing a target of the
    same kind; a directory cannot move into itself), `READDIR`, `TRUNCATE`,
    `STAT`, `STATFS`. Files to the size of the disk (9 direct blocks, an
    indirect block of 1,024 and a double indirect block of 1,024 more indirect
    ones: a little over 4 GiB, past the 128 MiB a disk may have); a read or write of up to 4 KiB may span two blocks.
    Handles carry a generation, so a handle to a removed file never reaches the
    inode's next owner.
  - Symbolic links: `SYMLINK` and `READLINK`; relative or absolute targets (an
    absolute one starts at the component's own root, and `..` stops there, so no
    target leads out of the tree). Paths follow up to 8 links, then answer
    `TooManyLinks`, as does `OPEN` with `NOFOLLOW` on a link; creating through a
    dangling link makes its target; `UNLINK` and `RENAME` act on the link itself.
    Clients cannot write `..` in a path; targets can.
  - Crash-only, with a write-ahead journal of up to 48 blocks per commit. Changed
    blocks go to the journal, then a flush, then a header with their home
    addresses and a checksum, then a flush: only then is the change acknowledged.
    The blocks go home after the reply. Mount replays a committed transaction an
    instance (or the machine) left unfinished (a torn one fails its checksum and
    was never acknowledged), then checks that every block belongs to exactly one
    inode, every inode to exactly one directory, and the bitmap agrees.
  - Group commit: requests from several clients are served one after another but
    committed together. The server sets each caller aside (new kernel calls
    `ReplySave` and `ReplyTo`; up to 16 per thread, failed with `PeerRestarted` if
    the server dies) and takes the next call already waiting, or ring submission,
    until there is none or the group is full; then one commit (two flushes) answers
    them all. A request sees the uncommitted changes of those before it in its
    group, and a failing one changes nothing (every check comes first; one that may
    change something starts a group of its own when space runs low).
  - Clients retry calls cut off by a restart (a retried `UNLINK` or `RENAME`
    answering `NotFound` had already happened); the server retries block calls
    cut off by a driver restart.
  - Rings (spec section 3, Tier 2): besides calls, a client may submit requests
    through a ring of 16 entries and 15 data pages in its `shared` pages. Set-up
    calls attach the pages and hand the client a completion notification (the
    server's, so a server restart destroys it and wakes the client to set up again)
    and a doorbell (the server's bound notification). Requests are the words of a call
    plus a data offset; completions are posted once the change is durable. The server
    polls while it has work and asks for the doorbell only before it sleeps; the client
    sleeps until half of what it has in flight is done, and the server signals it once
    then, so signals coalesce. A client resubmits what had no completion after a
    restart.
  - Limits: 2,047 files and directories (32 blocks of inodes, all held in
    memory), 58-byte names, 16 requests per commit, four rings, disks of up to
    128 MiB (one bitmap block). The server is one thread: requests are not served
    in parallel, only committed together.
  - Fault injection: a manifest `fault-injector` component may ask the Component
    Manager to kill another (it is restarted as if it had crashed; such kills do
    not count towards the restart limit, which is there to stop crash loops).
  `cargo xtask fs-test` boots a fresh 16 MiB disk twice. The injector kills the
  filesystem server and the disk driver every 3 to 14 ticks until the power cut
  (about 50 to 90 kills a run):
  - a client appends 400 records and every acknowledged one reads back; then
    a 280,000-byte file written in unaligned pieces, truncated and extended;
    a removed file's blocks come back and its handle is dead; a sparse 9 MB
    file through the double indirect block, its holes read as zeros, cut back
    and removed with every block returned; nested
    directories, renames, refused operations (exclusive create, a path through
    a file, `..`, a directory into itself, removing a non-empty directory);
    600 files in one directory (more than the 511 inodes there once were),
    listed and removed; 9 symbolic links (relative,
    absolute, through a directory, with `..`, chained, climbing past the root, a
    loop, a dangling one created through), read back, renamed and removed;
  - through a ring, 15 in flight: a file opened, 300 1 KiB records written and read
    back, with the ring set up again after each server restart (about 15 a run);
  - one more record and a rename are acknowledged and the machine stops at once
    (a power cut);
  - the second boot finds all 401 records, the rename, the big file, the ring's
    file, the tree and its links (one left dangling by the first boot), and another component's tree does not have them. Every
    mount's check must pass. With no faults, 300 reads through a ring cost about
    40 system calls (a handful of doorbells, the rest sleeps), where calls cost at
    least one each.
- The network server, v3 (`user/net/`), and a virtio-net driver (`user/virtio-net/`).
  - The driver serves the versioned `nic` interface: whole Ethernet frames copied
    between its own receive and transmit buffers (the only memory the device reaches,
    through the IOMMU) and a page the caller lends with each call. Its interrupt is
    bound to its thread, so one `Recv` waits for calls and frames; when frames arrive
    it signals the notification its caller attached. A restarted driver has lost it,
    and says so in every `RECV` reply.
  - Frame rings between the two (`nic::ring`): 13 pages the manifest shares
    (`shared`, kept by the manager, so a restart of either side leaves the other's
    mapped) hold a receive ring of 16 frames and a transmit ring of 8. The driver
    puts received frames in one as its interrupt brings them and sends what the
    server puts in the other, so under load no frame takes a call, and neither side
    signals the other unless the other said it sleeps. Nothing in the shared pages
    is trusted: indices and lengths are bounded, a received frame is copied out
    before it is parsed, and the device never sees the pages. A full transmit ring
    makes the server wait for the driver rather than drop the frame; frames stuck
    behind a full device are the one time the driver asks for transmit interrupts.
    While there is no ring (just after the driver restarted, or none in the
    manifest) each frame takes a call as before, and the server's timer call finds
    a restarted driver and sets the ring up again.
  - The server speaks IPv4 over Ethernet: ARP (answering for itself, resolving next
    hops, holding frames that wait for an answer and asking again), ICMP echo (it
    answers pings) and UDP, with checksums, and IPv4 fragments: a datagram of up to
    65,507 bytes (UDP's largest) too big for one frame goes in 1,480-byte pieces, and
    fragments that arrive are put back together (`crates/inet`, up to four datagrams
    at once, each dropped if not whole within 5 s; malformed, overlapping past the
    end and oversized fragments are refused, which host unit tests check, the
    largest datagram arriving shuffled among them). It serves the `net`
    interface: UDP and ICMP-echo sockets, each owned by the client that bound it, send
    and receive with a lent page; a datagram longer than the page goes in pieces
    (`SEND_PART` stages it a page at a time, and `RECV_PART` fetches what `RECV`
    could not copy). Queued datagrams live in a pool of 160 pages, a page per 4 KiB,
    with at most 48 to a socket, so a flooded socket cannot starve the others;
    the loopback carries a big datagram to this host in fragments too; `STATS` counts datagrams reassembled, sent in
    fragments and dropped half reassembled, kept across restarts in the state page. Each socket comes with a notification of the server's, signalled when
    something arrives: a client waits on it, with a `TimerSignal` on it for a timeout,
    and a server restart deletes it, which wakes the client to bind again. The server's
    own notification, bound to its thread, carries the driver's signal and a 100 ms
    timer; on the timer it drains the driver and attaches again if the driver
    restarted, and resends ARP requests.
  - Its address, netmask, gateway and DNS server come from DHCP: DISCOVER, OFFER,
    REQUEST, ACK, each sent again every second until answered. Until it has a lease
    the server has no address (`INFO` and `SEND` answer `Unreachable`); `LEASE`
    gives the netmask, DNS server and seconds left. The lease is renewed halfway
    through (or every `arg` ticks from the manifest), and dropped, with DISCOVER
    again, if it runs out or the DHCP server refuses it. Everything else the server
    holds is lost on a restart, but the lease is kept in its `state` page, so a
    restarted server goes on with the same address at once.
  - IPv6 routes (`crates/inet/src/routes6.rs`, RFC 4861 and RFC 4191): every
    router that advertises itself is kept with its preference and lifetime, with
    the prefixes advertisements say are on the link and the more specific routes
    they carry. A packet goes to its destination if that is on the link, else to
    the router of the longest matching route, else to the best default router; a
    router that does not answer neighbour discovery is passed over for 30 s while
    another can be used. Managed addresses (`crates/inet/src/dhcp6.rs`, RFC 8415):
    when an advertisement's M flag is set, a DHCPv6 client asks for an address
    (Solicit, Advertise, Request, Reply), puts it through duplicate detection,
    uses it if autoconfiguration gave none, renews it at T1, rebinds at T2 and
    drops it when it runs out. Both are state machines with no I/O, tested on the
    host (23 tests: preferences, expiry, failover, longest match; the four
    messages, retransmission, renewal, rebinding, loss, messages that are not the
    client's).
  - Rings between clients and the network server (`net::ring`, laid out as the
    filesystem's): a client attaches 16 `shared` pages and submits the calls that
    lend a page (`SEND`, `RECV` and their IPv6 and by-parts forms, for datagrams
    and TCP bytes alike) through a submission queue, the page being one of the
    ring's; the server answers through a completion queue. It takes a ring's
    worth from each client before every wait, so calls keep their turn; a client
    rings the doorbell (the server's own notification, badged) only when the
    server said it sleeps, and the server signals a client only when it asked. A
    restarted server has lost the rings with the sockets: the client's completion
    notification is destroyed, and it sets both up again. The network test echoes
    thousands of datagrams this way under fault injection, with no call each.
  - A DNS resolver (`user/dns/`), a component of its own, serves the `dns`
    interface: a client lends a page holding a name and gets its IPv4 address
    (`RESOLVE`, an A record) or its IPv6 address (`RESOLVE6`, an AAAA record,
    written into the page). It answers from its cache while an answer's TTL lasts;
    otherwise it sends a recursive query for that record type to the DNS server the network server got from
    DHCP, through a UDP socket of the network server's, again every second for up
    to four tries, follows CNAMEs in the answer (with compression pointers) to the
    address, and caches what it learns, names that do not exist included (for
    10 s). `RECORDS` gives a name's records of any other type, as text in the
    page: TXT strings, mail exchangers (MX) as `preference host`, services (SRV)
    as `priority weight port target`, reverse names (PTR) and name servers (NS),
    found through CNAMEs the same way, the compressed names inside them expanded,
    and the last few short answers kept for their time to live. An answer the
    server cuts short to fit a datagram (the TC bit) is asked for again over TCP
    (RFC 7766), on a connection of the network server's: up to a page of it. It is crash-only too: a restart loses the cache and fails the call it
    was serving with `PeerRestarted`, and when the network server restarts it binds
    a new socket and asks again.
  - TCP (`crates/inet/src/tcp.rs`, a state machine with no I/O of its own, fed
    segments and the timer by the server): the three-way handshake (active,
    passive and simultaneous), the MSS option, sliding windows both ways, data
    arriving out of order kept (up to four ranges) and handed on in order,
    retransmission on a timeout estimated from round trips (RFC 6298, Karn's rule,
    backing off), fast retransmit after three duplicate ACKs, slow start and
    congestion avoidance, zero-window probes, half-close, `TIME-WAIT`, resets
    checked against blind ones (RFC 5961) and ignored in `TIME-WAIT` (RFC 1337),
    ICMP "unreachable" ending a connection attempt, and giving up after ten
    timeouts. Options, each used only when both SYNs carry it: window scaling
    (RFC 7323; a receive ring of up to 1 GiB offered whole), timestamps (RFC
    7323: every ACK times a round trip, retransmissions included, and old
    duplicates are dropped by PAWS), and SACK (RFC 2018: the receiver reports
    the ranges it holds past a gap, most recent first; the sender in fast
    recovery resends the holes one after another on each further duplicate or
    partial ACK, NewReno-style without SACK, and forgets what was reported on a
    timeout, since a receiver may renege). Host unit tests run two ends over a
    link that loses, reorders and repeats segments (up to 30% lost), with and
    without options on the far end: a 1 MiB window offered and filled, an old
    duplicate dropped by its timestamp, and SACK finishing ten lossy transfers
    in less time than the same transfers without it. The server holds up to
    sixteen connections (and sixteen sockets), each with 8 KiB rings each way; `TCP_CONNECT`, `TCP_LISTEN` (two connections
    held until accepted), `TCP_ACCEPT`, `SEND` and `RECV` (never blocking: `Empty`
    means wait for the connection's notification), `TCP_SHUTDOWN`, `TCP_STATE`,
    and `CLOSE`, after which the server finishes the connection (a FIN, up to
    30 s); `TIME-WAIT` connections give their slot to a new one when none is free.
    The server is crash-only here too: a restart forgets every connection (the
    peer is reset when it next sends; ports and initial sequence numbers differ
    per instance), and the client connects again. Packets to the server's own
    address go round a loopback queue. A port that closing connections still
    use can be listened on again (only another listener stands in the way).
  - IPv6 too, alongside IPv4 (`user/net/src/ip6.rs`; addresses are 128 bits
    throughout the server and `crates/inet`, IPv4 ones held as IPv4-mapped).
    The link-local address comes from the MAC (modified EUI-64) and must pass
    duplicate address detection (a neighbour solicitation from the unspecified
    address, then 1 s with no answer); router solicitations every 4 s until an
    advertisement gives the router and a /64 prefix with the autonomous flag
    (SLAAC), whose address is tried the same way. The DNS server comes from the
    advertisement's RDNSS option or, when it carries none (as QEMU's does not),
    from stateless DHCPv6 (an Information-Request to ff02::1:2). Neighbours are
    found with Neighbor Discovery (solicitations and advertisements, answered
    for its own addresses, on 33:33 multicast MACs), the address lives as long
    as the prefix's valid lifetime, and everything learned, detection's progress
    included, is kept in the state page so a restarted server goes on at once.
    ICMPv6 echo both ways, "unreachable" ending a connection attempt, UDP and
    TCP (MSS 1,440) over IPv6, extension headers skipped, and fragments both
    ways (1,448-byte pieces up to 65,507 bytes, put back together with the IPv4
    reassembler). The `net` interface's `SEND6`, `RECV6`, `TCP_CONNECT6`,
    `TCP_PEER` and `INFO6` take and give 16-byte addresses in the lent page;
    the IPv4 calls go on unchanged.
  `cargo xtask net-test` boots `boot/net.manifest` on QEMU's user-mode network, set
  to 10.0.3.0/24 rather than QEMU's default so nothing can assume an address, while
  xtask echoes UDP on the host. The server must lease 10.0.3.30/24 via 10.0.3.2
  with DNS server 10.0.3.3 exactly once, keep it across every one of its restarts,
  and renew it at least twice (every 2 s here); the client must see that address,
  gateway, netmask and DNS server. For at least 2 s the client pings the gateway, then for
  at least 5 s it sends UDP datagrams of 1 to 4,000 bytes that the host echoes back
  (those over 1,472 bytes go out in fragments, which QEMU puts back together, and
  come back in fragments, which the server must; it must have done both), then for
  at least 2 s datagrams of 4,097 to 65,507 bytes, staged and fetched in pieces;
  meanwhile the injector kills the driver, the server and the resolver in turn
  every 30 to 150 ms. Every ping and every datagram must come back with every byte
  right (the client sends again after 300 ms, or binds again when its socket is
  gone), and the components must have been killed at least 10 times, among the pings
  and among the echoes. Then the client resolves names through the resolver, which
  asks a DNS server xtask runs on the host (at the gateway's port 47053, as QEMU's
  own DNS server would ask the real internet): an A record, a CNAME, AAAA records
  (directly, through the CNAME and from the cache), a name with only an IPv4
  address asked for IPv6 and one with only IPv6 asked for IPv4, a name that
  does not exist and a malformed one; a name with a 300 s TTL 20 times, at least
  15 from the cache (the host must be asked at most 5 times); a name with a 1 s TTL
  twice, 1.5 s apart, the second asked of the host again; and for at least 3 s a
  new name each time, every address right, with the resolver killed at least 10
  times meanwhile. Last, for at least 5 s, TCP connections to an echo on the host
  (port 47002), each sending up to 8,000 bytes, reading them back and closing;
  a connection a restart cuts is made again, no byte may come back wrong, and
  the injector must have killed components at least 10 times meanwhile. A run
  does about 1,000 to 3,000 pings, 2,000 to 3,800 echoes, 1,500 to 2,000 names and
  some 300 TCP connections (about 1.3 MB, some 20 of them cut) through some 30 to
  60 kills of each. Then IPv6, under the same faults: the server must have its
  link-local address, fd00:3::5054:ff:fe12:3456/64 via the router and DNS
  server fd00:3::3, each address passing detection once and kept across every
  restart; pings to the host (fd00:3::2) for at least 2 s; UDP datagrams of 1 to
  1,452 bytes echoed by the host (on ::1); datagrams of 1,453 to 4,000 bytes sent
  to the client's own socket in fragments and put back together, and ones of
  4,097, 30,000 and 65,507 bytes and a 20,000-byte ping of this host (as over
  IPv4: 5,000, 40,000 and 65,507 bytes to itself and a 65,507-byte ping), QEMU
  not fragmenting IPv6; and TCP echoes
  for at least 5 s, every byte right.
  `cargo xtask tcp-test` boots `boot/tcp.manifest`, where the server drops one TCP
  segment in 20 at random each way (a test setting in its `arg`): a connection to
  a closed port of its own is refused (round the loopback: QEMU's user network
  does not answer a refused connection on a Windows host); 100,000 bytes are
  echoed by the host; the host makes three connections to the client's listening
  port through QEMU's forwarding, each sending 30,000 bytes (more than the
  window, which the client lets fill before reading) that the client checks and
  sends back; and two sockets of the client's own exchange 20,000 bytes each way
  through the loopback. Then over IPv6: a closed port of its own refused,
  50,000 bytes echoed by the host, and a pair of its own sockets exchanging
  20,000 bytes each way, the accepted end giving its peer's IPv6 address. (QEMU
  forwards only IPv4 connections in from the host.) Segments must have been sent
  again, dropped and kept out of order.
- USB: an xHCI host controller driver (`user/xhci/`) and a HID keyboard driver
  (`user/hid/`).
  - The xHCI driver opens the first function of class 0c:03:30, resets the controller,
    sets up the command ring, one event ring and the device context array, and on each
    root port with a device resets the port, enables a slot, addresses the device and
    reads its device descriptor. It serves the versioned `usb` interface: any client
    may read a device's descriptors to decide whether to claim it; one that claims it
    makes control transfers (data through a page it lends) and adds interrupt-IN
    endpoints, which the controller polls into the driver's buffers, signalling the
    client when reports arrive. The controller reaches only the driver's DMA pages,
    through the IOMMU domain; its MSI-X vector is bound to the driver's thread.
  - The HID driver finds the first boot-protocol keyboard (interface class 3, 1, 1),
    claims it, has its endpoint polled, selects the boot protocol and turns each
    8-byte report into presses and releases. It serves `input`: subscribers read
    events from a ring at their own pace and are signalled when there are more. A
    100 ms timer drains reports and sets the keyboard up again after the xHCI driver
    restarts.
  `cargo xtask keyboard-test` boots `boot/keyboard.manifest` with QEMU's xHCI
  controller and a USB keyboard, and xtask types "superior" followed by a space, over
  and over, through QEMU's monitor. Meanwhile the injector kills the xHCI and HID
  drivers every 30 to 150 ms, pausing 0.5 s after every eighth kill (a word takes
  about 0.2 s to type, longer than most gaps, and without the pauses AArch64 runs
  sometimes saw fewer than 10 whole words in 90 s). The client must see 10 words
  come through whole, and never a key that was not typed (a word cut by a restart
  counts as broken, not wrong); each driver must have been killed at least 10 times,
  20 of them while words came through. A run sees about 45 kills of each.
- Interrupt and exception entries clear the direction flag. User code may be
  interrupted mid-way through a backward copy, with the flag set; the kernel's own
  copies need it clear, and without the `cld` they ran backwards, wrecking saved
  registers. The Component Manager test checks it: the client and a spinner at the
  same priority both hold the flag set for 20 timer ticks, so every tick switches
  between them and each resumes from the registers the kernel saved.
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
  CNode outlives the client's capability but not its last thread. It makes an address
  space, checks the refusals (writable and executable, a read-only copy mapped writable),
  runs its page-table pool dry, and revokes its memory under a thread using it, which
  then cannot run. Self-test kernels keep small tables (8 threads, endpoints and
  notifications, a 256-slot CNode pool) so filling them stays quick; normal kernels have
  32 of each, 32 address spaces and a 4096-slot pool.

Not yet: in the Linux Driver Environment drivers of a class other than network,
ethtool and the MII ioctls, firmware files, more than one interrupt or one
device per component (QEMU's later 8255x models append stale bytes to some of
e100's frames, so its test uses the 82557); legacy
interrupt lines shared by two functions, and their routing on machines other
than QEMU's q35 and `virt`; more than 16 PCI buses on AArch64, port ranges handed to drivers themselves (an I/O BAR access is a call to the bus server), hot-plug of bridges or behind bridges below bus 0, a hot-plug interrupt (the slots are polled) and word of it to drivers (one whose card went finds its calls refused), and
DMA for devices behind conventional bridges (they share a requester ID); Function
Level Reset is exercised only by the NVMe controller (QEMU's virtio devices on
these buses have none); more than one command per queue in the NVMe driver,
more than two commands in flight per disk in the AHCI driver, ATAPI
and port multipliers; in the xHCI driver isochronous and bulk endpoints, USB 3 streams,
hubs and more than one interrupter, and HID devices other than boot keyboards; in the network server
a second IPv6 router or a DHCPv6 server to test against (QEMU's network has one router and hands out no addresses, so the IPv6 route table and the DHCPv6 address client are proved by host tests alone), DNSSEC, DNS answers over TCP of more than a page, IPv4 routes beyond one gateway; the SDK's power callbacks (with suspend and resume, Phase 2); the IDL describing interfaces other than the bus server's; escalating a component
given up on to a supervisor above it (today the
manager is the only one), memory budgets from a policy service, giving the Memory Server all spare
RAM (today it gets a fixed pool from its manifest), page tables for boot processes paid for from user memory,
multi-level CSpaces, the first call's capability forwarded by a lazy-start watcher, scheduling-context capabilities (budgets are set at boot), sporadic refills,
timeout faults, per-CPU ready queues and thread affinity (one lock and shared queues
today), device interrupts spread over CPUs, more than four CPUs, an IPC benchmark on bare
metal.

The architectural specification lives in the Superior OS Architectural Specification doc:
https://claude.ai/artifact/QKJS8qH5Dfbjzn58RStq1j

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | The microkernel (`no_std`, targets `x86_64-unknown-none` and `aarch64-unknown-none-softfloat`) |
| `kernel/src/arch/` | Per-ISA code: boot, starting the other CPUs, exceptions and system call entry, page tables, interrupts, timer, console (`x86_64/`, `aarch64/`) |
| `kernel/src/smp.rs` | What CPUs share outside the kernel lock: kicks and address-space shootdowns |
| `crates/sys/` | User-side system call wrappers for both ISAs (one ABI by register position), and the seL4 runtime (`src/sel4.rs`) |
| `crates/inet/` | Protocol pieces of the network server, unit-tested on the host: IP fragment reassembly, checksums over both families, and TCP |
| `crates/objects/` | Pure kernel logic, unit-tested on the host: capabilities and CNodes, untyped memory, the IPC and scheduling state machine, the syscall ABI, an ELF reader, the boot bundle and manifest formats |
| `user/pingpong/` | Boot self-test program (IPC server, client and spinner) |
| `user/cm/` | The Component Manager: the root task, which starts every component from the boot manifest |
| `user/shell/` | The boot shell and COM1 driver, started as a component |
| `crates/driver/` | The Driver SDK: PCI access through the bus server, MMIO, DMA pages, virtqueues, DMA buffer pools, an executor |
| `crates/idl/` | The IDL compiler: interface descriptions to Rust |
| `interfaces/` | Interface descriptions (`pci.idl`, the PCI bus server's) |
| `crates/lde/` | The Linux Driver Environment: Linux's kernel API for hosted drivers (`include/`, `c/lde.c`) and its host (`src/lib.rs`) |
| `user/lde-8139cp/` | Linux's 8139cp network driver, unmodified, in the Linux Driver Environment |
| `user/lde-e100/` | Linux's e100 network driver, likewise |
| `user/pcibus/` | The PCI bus server |
| `user/memserver/` | The Memory Server |
| `user/fs/` | The filesystem server |
| `user/virtio-blk/` | The virtio block driver |
| `user/nvme/` | The NVMe class driver |
| `user/ahci/` | The AHCI (SATA) class driver |
| `user/virtio-net/` | The virtio network driver |
| `user/net/` | The network server |
| `user/dns/` | The DNS resolver |
| `user/xhci/` | The xHCI (USB) host controller driver |
| `user/hid/` | The USB HID keyboard driver |
| `user/echo/`, `user/counter/`, `user/testclient/` | Test components for the Component Manager, supervision and drivers |
| `boot/` | Component manifests: `shell.manifest` (normal boot), `test.manifest` (`cm-test`), `supervise.manifest` (`supervise-test`) , `drivers.manifest` (`drivers-test`) , `memory.manifest` (`memory-test`), `reboot.manifest` (`reboot-test`), `fs.manifest` and `fs-verify.manifest` (`fs-test`), `net.manifest` (`net-test`), `tcp.manifest` (`tcp-test`), `keyboard.manifest` (`keyboard-test`) |
| `sel4/` | Docker build of seL4 and rust-sel4's kernel loader, for running the shell on seL4 |
| `xtask/` | Build driver: user program, kernel, disk image, QEMU boot |

## Building

Needs Rust (the pinned nightly in `rust-toolchain.toml` installs itself) and QEMU.

```bash
cargo xtask test           # host tests, model check, simulation; on both ISAs the boot self-tests, the Component Manager, supervision, driver, Memory Server and filesystem tests (the disk tests on all three disk drivers), the network, TCP and USB keyboard tests and a shell session; then the shell on seL4
cargo xtask cm-test        # just the Component Manager test (add aarch64 for that ISA)
cargo xtask supervise-test # just the supervision test (add aarch64 for that ISA)
cargo xtask drivers-test   # just the driver framework test (add aarch64 for that ISA)
cargo xtask memory-test    # just the Memory Server test (add aarch64 for that ISA)
cargo xtask reboot-test    # just the fast reboot test (add aarch64 for that ISA)
cargo xtask fs-test        # just the filesystem test, two boots (add aarch64 for that ISA)
cargo xtask nvme-test      # the driver and filesystem tests on an NVMe disk (add aarch64 for that ISA)
cargo xtask ahci-test      # the same on a SATA disk behind AHCI (add aarch64 for that ISA)
cargo xtask net-test       # just the network test (add aarch64 for that ISA)
cargo xtask lde-test       # the network test over Linux's 8139cp driver (needs Docker; fetches the driver from kernel.org the first time)
cargo xtask lde-e100-test  # the same over Linux's e100 driver
cargo xtask tcp-test       # just the TCP test (add aarch64 for that ISA)
cargo xtask keyboard-test  # just the USB keyboard test (add aarch64 for that ISA)
cargo xtask hotplug-test   # just the PCI hot-plug test (add aarch64 for that ISA)
cargo xtask run            # boot the shell in QEMU (x86-64), its console on this terminal
cargo xtask run aarch64    # the same on QEMU's AArch64 virt machine
cargo xtask idl    # generate Rust from the interface descriptions in interfaces/
cargo xtask image  # just build target/superior.img
cargo xtask bench  # IPC timing under WHPX or KVM, checked against seL4's figures
cargo xtask sel4-test      # the shell session on seL4 (needs Docker the first time)
```

QEMU is found via `$QEMU` (or `$QEMU_AARCH64`), then `C:\Program Files\qemu`, then `PATH`.

## Roadmap

| Phase | Months | Focus |
| --- | --- | --- |
| P0 | 0 to 6 | Foundations: bootloader, kernel core, QEMU bring-up |
| P1 | 5 to 15 | Core runtime, supervision, driver framework, class drivers |
| P2 | 12 to 24 | Graphics, UX, audio, Wi-Fi, verified boot, A/B updates |
| P3 | 18 to 30 | Compatibility: Linux and Windows personalities, micro-VMs, translation |
| P4 | 24 to 34 | Scheduling intelligence, Sentinel, proofs, hardening |
| P5 | 30 to 36 | Developer Preview readiness |
