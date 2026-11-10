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
- Idle: with every thread blocked the kernel halts the CPU until an interrupt makes one
  runnable. The timer signals a notification each tick, so threads sleep by waiting on it.
- IPC engine: `Send`, `Call`, `Recv`, `Reply`, `ReplyRecv`, `Signal`, `Wait`, `Yield`;
  direct switch on call/reply (fast path); 64 fixed priorities.
- Bound notifications (as in seL4): `NotificationBind` ties a notification to the
  calling thread, whose `Recv` and `ReplyRecv` then also return when it is signalled
  (status `Notified`, the bits as the badge). Pending bits come before queued callers.
  One server loop waits for calls and for its rings' doorbells at once.
- Timers: `TimerSignal` signals a notification once, a number of ticks from now, with
  the capability's badge (a new deadline replaces the old; 0 cancels; 64 pending
  across the system, cleared when the notification is destroyed). A thread waits
  with a timeout by waiting on a notification it also set a timer on.
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
    on every timer tick the kernel drains VT-d's fault recording registers or the
    SMMU's event queue and credits each fault to the space bound to its requester
    ID; `IoFaults` tells the space's holder how many there were since it last
    asked, the first one's page and whether it was a write, and how many
    interrupt messages VT-d blocked (the ITS drops them without a report).
  - The root task gets PCI configuration space (ports 0xcf8-0xcff, or ECAM), a BAR
    window and eight MSI vectors, and gives them to the PCI bus server
    (`user/pcibus/`), the only component that touches configuration space. It finds
    the functions on bus 0, assigns BARs, and serves the versioned `pci` interface
    (`crates/objects/src/interfaces.rs`). A driver opens one function and gets only
    its BAR pages and MSI vectors; configuration writes are limited to bus
    mastering, MSI-X and plain MSI (`pci::MSI`: the bus server writes the
    function's vector into its MSI capability, for devices without MSI-X). Each opened function gets a new, empty IOMMU domain with
    the `OPEN` reply; without an IOMMU, bus mastering is refused. Opening resets
    the function: the last owner's domain revoked first (every copy, so its DMA is
    blocked), then decoding and bus mastering off, the last owner's BAR pages and
    vectors revoked, MSI-X and MSI off, then a Function Level Reset where the device has
    one.
  - The Driver SDK (`crates/driver/`): the bus server client, MMIO registers, DMA
    pages mapped into the device's domain, split virtqueues.
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
    write to exactly that page;
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
  - The Memory Server cannot be restarted in place: if it fails, the system stops
    (spec section 4; the fast reboot that should follow is not built yet).
  - Components may have larger CSpaces (manifest `cspace`, up to 2^10 slots).
  `cargo xtask memory-test` boots `boot/memory.manifest`:
  - a client pages its heap in by touching it, and every page arrives zeroed;
  - it takes frames up to its quota and is refused one more;
  - it frees one, and the capability is gone;
  - a hog touches more heap than its quota and is restarted, with all 8 pages back
    in the pool; its next instance gets those same pages, zeroed.
- The filesystem server, v2 (`user/fs/`), over the block interface (which has
  `WRITE` and `FLUSH`; the virtio-blk driver negotiates the device's write cache).
  - No global namespace: each component sees only its own tree, under a root
    picked by the badge on its capability, so the same component finds the same
    files after a restart.
  - POSIX-shaped: `/`-separated, case-sensitive paths (lent in a frame);
    directories; `OPEN` with create, exclusive and truncate flags; `MKDIR`,
    `UNLINK` (files and empty directories), `RENAME` (replacing a target of the
    same kind; a directory cannot move into itself), `READDIR`, `TRUNCATE`,
    `STAT`, `STATFS`. Files to a little over 4 MiB (9 direct blocks and one
    indirect block); a read or write of up to 4 KiB may span two blocks.
    Handles carry a generation, so a handle to a removed file never reaches the
    inode's next owner.
  - Crash-only, with a write-ahead journal of up to 8 blocks per change. Changed
    blocks go to the journal, then a flush, then a header with their home
    addresses and a checksum, then a flush: only then is the change acknowledged.
    The blocks go home after the reply. Mount replays a committed transaction an
    instance (or the machine) left unfinished (a torn one fails its checksum and
    was never acknowledged), then checks that every block belongs to exactly one
    inode, every inode to exactly one directory, and the bitmap agrees.
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
  - Limits: 511 files and directories, 58-byte names, one request at a time, four
    rings.
  - Fault injection: a manifest `fault-injector` component may ask the Component
    Manager to kill another (it is restarted as if it had crashed; such kills do
    not count towards the restart limit, which is there to stop crash loops).
  `cargo xtask fs-test` boots a fresh 16 MiB disk twice. The injector kills the
  filesystem server and the disk driver every 3 to 14 ticks until the power cut
  (about 50 to 90 kills a run):
  - a client appends 400 records and every acknowledged one reads back; then
    a 280,000-byte file written in unaligned pieces, truncated and extended;
    a removed file's blocks come back and its handle is dead; nested
    directories, renames, refused operations (exclusive create, a path through
    a file, `..`, a directory into itself, removing a non-empty directory);
    70 files in one directory, listed and removed;
  - through a ring, 15 in flight: a file opened, 300 1 KiB records written and read
    back, with the ring set up again after each server restart (about 15 a run);
  - one more record and a rename are acknowledged and the machine stops at once
    (a power cut);
  - the second boot finds all 401 records, the rename, the big file, the ring's
    file and the tree, and another component's tree does not have them. Every
    mount's check must pass. With no faults, 300 reads through a ring cost about
    40 system calls (a handful of doorbells, the rest sleeps), where calls cost at
    least one each.
- The network server, v1 (`user/net/`), and a virtio-net driver (`user/virtio-net/`).
  - The driver serves the versioned `nic` interface: whole Ethernet frames copied
    between its own receive and transmit buffers (the only memory the device reaches,
    through the IOMMU) and a page the caller lends with each call. Its interrupt is
    bound to its thread, so one `Recv` waits for calls and frames; when frames arrive
    it signals the notification its caller attached. A restarted driver has lost it,
    and says so in every `RECV` reply.
  - The server speaks IPv4 over Ethernet: ARP (answering for itself, resolving next
    hops, holding frames that wait for an answer and asking again), ICMP echo (it
    answers pings) and UDP, with checksums; it serves the `net` interface: UDP and
    ICMP-echo sockets, each owned by the client that bound it, send and receive with
    a lent page. Each socket comes with a notification of the server's, signalled when
    something arrives: a client waits on it, with a `TimerSignal` on it for a timeout,
    and a server restart deletes it, which wakes the client to bind again. The server's
    own notification, bound to its thread, carries the driver's signal and a 100 ms
    timer; on the timer it drains the driver and attaches again if the driver
    restarted, and resends ARP requests. Fixed address for now: 10.0.2.15/24 via
    10.0.2.2.
  `cargo xtask net-test` boots `boot/net.manifest` on QEMU's user-mode network while
  xtask echoes UDP on the host. For at least 2 s the client pings the gateway, then for
  at least 5 s it sends UDP datagrams of 1 to 1,400 bytes that the host echoes back;
  meanwhile the injector kills the server and the driver every 30 to 150 ms. Every
  ping and every datagram must come back with every byte right (the client sends
  again after 300 ms, or binds again when its socket is gone), and both components
  must have been killed at least 10 times, among the pings and among the echoes. A
  run does about 1,000 to 3,000 pings and 2,000 to 3,600 echoes through some 35
  kills of each.
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
  drivers every 30 to 150 ms. The client must see 10 words come through whole, and
  never a key that was not typed (a word cut by a restart counts as broken, not
  wrong); each driver must have been killed at least 10 times, 20 of them while words
  came through. A run sees 80 to 260 kills of each.
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

Not yet: an interrupt for IOMMU faults (they are collected on
the timer tick), buses behind bridges in the IOMMU (requester IDs on bus 0 only); Function
Level Reset is exercised only by the NVMe controller (QEMU's virtio devices on
these buses have none); more than one command per queue in the NVMe driver,
more than two commands in flight per disk in the AHCI driver, ATAPI
and port multipliers; in the xHCI driver isochronous and bulk endpoints, USB 3 streams,
hubs and more than one interrupter, and HID devices other than boot keyboards; in the network server
DHCP, TCP, IPv6, fragments, DNS, routes beyond one gateway, and rings in place of a
call per frame; buses behind bridges; the async executor, buffer pools and
power callbacks of the SDK; an IDL compiler for the interfaces; escalating a component
given up on to a supervisor above it (today the
manager is the only one), restarting the Component Manager or Memory Server (spec: fast
reboot instead, not built yet), copy-on-write address-space cloning for `fork` in the
Memory Server, memory budgets from a policy service, giving the Memory Server all spare
RAM (today it gets a fixed pool from its manifest), page tables for boot processes paid for from user memory,
multi-level CSpaces, the first call's capability forwarded by a lazy-start watcher, scheduling-context capabilities (budgets are set at boot), sporadic refills,
timeout faults, SMP, an IPC benchmark on bare metal.

The architectural specification lives in the Superior OS Architectural Specification doc:
https://claude.ai/artifact/QKJS8qH5Dfbjzn58RStq1j

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | The microkernel (`no_std`, targets `x86_64-unknown-none` and `aarch64-unknown-none-softfloat`) |
| `kernel/src/arch/` | Per-ISA code: boot, exceptions and system call entry, page tables, interrupts, timer, console (`x86_64/`, `aarch64/`) |
| `crates/sys/` | User-side system call wrappers for both ISAs (one ABI by register position), and the seL4 runtime (`src/sel4.rs`) |
| `crates/objects/` | Pure kernel logic, unit-tested on the host: capabilities and CNodes, untyped memory, the IPC and scheduling state machine, the syscall ABI, an ELF reader, the boot bundle and manifest formats |
| `user/pingpong/` | Boot self-test program (IPC server, client and spinner) |
| `user/cm/` | The Component Manager: the root task, which starts every component from the boot manifest |
| `user/shell/` | The boot shell and COM1 driver, started as a component |
| `crates/driver/` | The Driver SDK: PCI access through the bus server, MMIO, DMA pages, virtqueues |
| `user/pcibus/` | The PCI bus server |
| `user/memserver/` | The Memory Server |
| `user/fs/` | The filesystem server |
| `user/virtio-blk/` | The virtio block driver |
| `user/nvme/` | The NVMe class driver |
| `user/ahci/` | The AHCI (SATA) class driver |
| `user/virtio-net/` | The virtio network driver |
| `user/net/` | The network server |
| `user/xhci/` | The xHCI (USB) host controller driver |
| `user/hid/` | The USB HID keyboard driver |
| `user/echo/`, `user/counter/`, `user/testclient/` | Test components for the Component Manager, supervision and drivers |
| `boot/` | Component manifests: `shell.manifest` (normal boot), `test.manifest` (`cm-test`), `supervise.manifest` (`supervise-test`) , `drivers.manifest` (`drivers-test`) , `memory.manifest` (`memory-test`), `fs.manifest` and `fs-verify.manifest` (`fs-test`), `net.manifest` (`net-test`), `keyboard.manifest` (`keyboard-test`) |
| `sel4/` | Docker build of seL4 and rust-sel4's kernel loader, for running the shell on seL4 |
| `xtask/` | Build driver: user program, kernel, disk image, QEMU boot |

## Building

Needs Rust (the pinned nightly in `rust-toolchain.toml` installs itself) and QEMU.

```bash
cargo xtask test           # host tests, model check, simulation; on both ISAs the boot self-tests, the Component Manager, supervision, driver, Memory Server and filesystem tests (the disk tests on all three disk drivers), the network and USB keyboard tests and a shell session; then the shell on seL4
cargo xtask cm-test        # just the Component Manager test (add aarch64 for that ISA)
cargo xtask supervise-test # just the supervision test (add aarch64 for that ISA)
cargo xtask drivers-test   # just the driver framework test (add aarch64 for that ISA)
cargo xtask memory-test    # just the Memory Server test (add aarch64 for that ISA)
cargo xtask fs-test        # just the filesystem test, two boots (add aarch64 for that ISA)
cargo xtask nvme-test      # the driver and filesystem tests on an NVMe disk (add aarch64 for that ISA)
cargo xtask ahci-test      # the same on a SATA disk behind AHCI (add aarch64 for that ISA)
cargo xtask net-test       # just the network test (add aarch64 for that ISA)
cargo xtask keyboard-test  # just the USB keyboard test (add aarch64 for that ISA)
cargo xtask run            # boot the shell in QEMU (x86-64), its console on this terminal
cargo xtask run aarch64    # the same on QEMU's AArch64 virt machine
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
