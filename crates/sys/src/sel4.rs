//! Superior's system calls on seL4 (17.0.0, AArch64, non-MCS, hypervisor
//! mode), so the same user programs run on both kernels.
//!
//! The program becomes seL4's root task. A small runtime gives it a stack,
//! builds from seL4's boot capabilities the ones a Superior program starts
//! with, then calls its main function. Every Superior system call is then
//! translated into seL4 system calls and object invocations.
//!
//! **Slots.** Superior gives each thread its own CSpace; here all threads
//! share the root task's CNode, and thread `t`'s slot `s` is CPtr
//! `window + 16t + s`, where `window` is the start of the free slots seL4
//! reports. A thread finds its number in `TPIDR_EL0` (seL4's TLS base): 0
//! for the root task, set by `ThreadConfigure` for the others.
//!
//! **The root task's capabilities**, as Superior's kernel gives its shell:
//!
//! | Slot | Superior | Here |
//! | --- | --- | --- |
//! | 0 | the UART | the PL011's page, a frame cut from seL4's device untyped |
//! | 1 | its interrupt | an IRQ handler for INTID 33 |
//! | 2 | a notification for it | a notification |
//! | 3 | the 100 Hz timer notification | a notification bound to the EL1 physical timer's interrupt (INTID 30); `Wait` on it arms that timer for 10 ms (seL4 lets user mode program it; the kernel ticks on the hypervisor timer) |
//! | 4 | 64 KiB of untyped memory | the same, from seL4's largest RAM untyped |
//! | 5 | QEMU's exit port | `IoPortOut` here ends QEMU through Arm semihosting |
//!
//! Message words 0-3 travel in seL4's message registers (`x2`-`x5`), so IPC
//! needs no IPC buffer; invocations use the root task's.

use core::arch::{asm, global_asm};
use superior_objects::abi::{CapTransfer, MSG_WORDS, ObjectType, Syscall};

use crate::Ret;

// seL4's system call numbers (non-MCS).
const SYS_CALL: i64 = -1;
const SYS_REPLY_RECV: i64 = -2;
const SYS_SEND: i64 = -3;
const SYS_NB_SEND: i64 = -4;
const SYS_RECV: i64 = -5;
const SYS_REPLY: i64 = -6;
const SYS_YIELD: i64 = -7;
const SYS_NB_RECV: i64 = -8;

// The root task's well-known capabilities.
const INIT_TCB: u64 = 1;
const INIT_CNODE: u64 = 2;
const INIT_VSPACE: u64 = 3;
const IRQ_CONTROL: u64 = 4;

// Invocation labels, from libsel4's generated invocation headers for this
// configuration (non-MCS, uniprocessor, no debug API, hypervisor mode; the
// labels used here are the same without it).
const UNTYPED_RETYPE: u64 = 1;
const TCB_WRITE_REGISTERS: u64 = 3;
const TCB_CONFIGURE: u64 = 5;
const TCB_SET_PRIORITY: u64 = 6;
const TCB_RESUME: u64 = 12;
const TCB_SET_TLS_BASE: u64 = 15;
const CNODE_COPY: u64 = 20;
const CNODE_MINT: u64 = 21;
const IRQ_ISSUE_IRQ_HANDLER: u64 = 26;
const IRQ_ACK_IRQ: u64 = 27;
const IRQ_SET_IRQ_HANDLER: u64 = 28;
const ARM_PAGE_TABLE_MAP: u64 = 38;
const ARM_PAGE_MAP: u64 = 40;

// Object types.
const SEL4_UNTYPED: u64 = 0;
const SEL4_TCB: u64 = 1;
const SEL4_ENDPOINT: u64 = 2;
const SEL4_NOTIFICATION: u64 = 3;
const SEL4_SMALL_PAGE: u64 = 7;
const SEL4_PAGE_TABLE: u64 = 9;

const FAILED_LOOKUP: u64 = 6;
/// Returned for Superior system calls with no seL4 translation.
const UNSUPPORTED: u64 = 0xffff;

// seL4_CapRights_t bits and VM attributes.
const RIGHT_WRITE: u64 = 1 << 0;
const RIGHT_READ: u64 = 1 << 1;
const RIGHT_GRANT_REPLY: u64 = 1 << 3;
const VM_CACHEABLE: u64 = 1;
const VM_EXECUTE_NEVER: u64 = 4;

// seL4_BootInfo field offsets.
const BI_IPC_BUFFER: u64 = 32;
const BI_EMPTY: u64 = 40;
const BI_UNTYPED: u64 = 152;
const BI_UNTYPED_LIST: u64 = 168;
/// Offset of `caps_or_badges` in the IPC buffer.
const IPCBUF_CAPS: u64 = 8 + 8 * 120 + 8;

const PAGE_BITS: u64 = 12;
const UART_PADDR: u64 = 0x0900_0000;
const UART_INTID: u64 = 33;
const PTIMER_INTID: u64 = 30;
const TICK_HZ: u64 = 100;

// Superior's slots in the root task's window.
const UART: u64 = 0;
const UART_IRQ: u64 = 1;
const UART_NTFN: u64 = 2;
const TIMER: u64 = 3;
const UNTYPED: u64 = 4;
const EXIT_PORT: u64 = 5;
const WINDOW_SLOTS: u64 = 16;
const MAX_THREADS: usize = 8;

struct State {
    ipc_buffer: u64,
    window: u64,
    next_free: u64,
    end_free: u64,
    /// The RAM untyped the runtime makes its own objects from.
    pool: u64,
    timer_irq: u64,
    threads: usize,
    /// Thread capabilities (CPtrs), by thread number - 1.
    tcbs: [u64; MAX_THREADS],
    /// The UART's frame, mapped uncached.
    device_frame: u64,
}

static mut STATE: State = State {
    ipc_buffer: 0,
    window: 0,
    next_free: 0,
    end_free: 0,
    pool: 0,
    timer_irq: 0,
    threads: 0,
    tcbs: [0; MAX_THREADS],
    device_frame: 0,
};

/// The state, which only the root task changes, and only before it starts
/// other threads or from its own system calls; other threads read
/// `window`, which never changes after start-up.
fn state() -> &'static mut State {
    // SAFETY: see above; there is one core.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

// ---- the runtime -------------------------------------------------------

const STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

static mut STACK: Stack = Stack([0; STACK_SIZE]);

// seL4 starts the root task with the boot information's address in x0
// and no stack.
global_asm!(
    ".section .text._start",
    ".global _start",
    "_start:",
    "adrp x9, {stack}",
    "add x9, x9, :lo12:{stack}",
    "mov x10, #{size}",
    "add sp, x9, x10",
    "bl {entry}",
    "b .",
    stack = sym STACK,
    size = const STACK_SIZE,
    entry = sym entry,
);

unsafe extern "C" {
    /// The program's own entry point, which the runtime calls once the
    /// Superior capabilities are in place.
    fn superior_main(arg: u64) -> !;
}

extern "C" fn entry(boot_info: u64) -> ! {
    if let Err((step, err)) = start(boot_info) {
        debug(step);
        debug_num(" failed: seL4 error ", err);
        exit(1);
    }
    // SAFETY: the program defines it, as a Superior entry point.
    unsafe { superior_main(0) }
}

fn read(addr: u64) -> u64 {
    // SAFETY: called only on the boot information, which seL4 maps.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

fn read_byte(addr: u64) -> u8 {
    // SAFETY: as in `read`.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

type Step = Result<(), (&'static str, u64)>;

fn check(step: &'static str, err: u64) -> Step {
    if err == 0 { Ok(()) } else { Err((step, err)) }
}

fn start(bi: u64) -> Step {
    let s = state();
    s.ipc_buffer = read(bi + BI_IPC_BUFFER);
    s.window = read(bi + BI_EMPTY);
    s.end_free = read(bi + BI_EMPTY + 8);
    s.next_free = s.window + WINDOW_SLOTS * MAX_THREADS as u64;
    if s.next_free + 256 > s.end_free {
        return Err(("finding free slots", 0));
    }

    // Find the device untyped holding the UART, and the largest RAM one.
    let (first, last) = (read(bi + BI_UNTYPED), read(bi + BI_UNTYPED + 8));
    let (mut uart_ut, mut pool_bits) = (None, 0);
    for (i, cptr) in (first..last).enumerate() {
        let desc = bi + BI_UNTYPED_LIST + 16 * i as u64;
        let (paddr, bits) = (read(desc), read_byte(desc + 8) as u64);
        let device = read_byte(desc + 9) != 0;
        if device && (paddr..paddr + (1 << bits)).contains(&UART_PADDR) {
            uart_ut = Some((cptr, paddr, bits));
        } else if !device && bits > pool_bits {
            (s.pool, pool_bits) = (cptr, bits);
        }
    }
    let Some((mut ut, mut base, mut bits)) = uart_ut else {
        return Err(("finding the UART's untyped", 0));
    };
    if pool_bits < 20 {
        return Err(("finding RAM", pool_bits));
    }

    // Halve the device untyped down to the UART's page, then make it a
    // frame in slot 0.
    while bits > PAGE_BITS {
        let halves = alloc(2);
        check(
            "splitting the device untyped",
            retype(ut, SEL4_UNTYPED, bits - 1, halves, 2),
        )?;
        bits -= 1;
        if UART_PADDR >= base + (1 << bits) {
            base += 1 << bits;
            ut = halves + 1;
        } else {
            ut = halves;
        }
    }
    let uart = s.window + UART;
    check(
        "making the UART frame",
        retype(ut, SEL4_SMALL_PAGE, 0, uart, 1),
    )?;
    s.device_frame = uart;

    let w = s.window;
    check(
        "getting the UART interrupt",
        irq_get(UART_INTID, w + UART_IRQ),
    )?;
    check(
        "making the UART notification",
        retype(s.pool, SEL4_NOTIFICATION, 0, w + UART_NTFN, 1),
    )?;
    check(
        "making the timer notification",
        retype(s.pool, SEL4_NOTIFICATION, 0, w + TIMER, 1),
    )?;
    s.timer_irq = alloc(1);
    check(
        "getting the timer interrupt",
        irq_get(PTIMER_INTID, s.timer_irq),
    )?;
    check(
        "binding the timer interrupt",
        invoke(s.timer_irq, IRQ_SET_IRQ_HANDLER, &[w + TIMER], &[]),
    )?;
    check(
        "making the untyped memory",
        retype(s.pool, SEL4_UNTYPED, 16, w + UNTYPED, 1),
    )
}

fn alloc(n: u64) -> u64 {
    let s = state();
    let at = s.next_free;
    s.next_free += n;
    at
}

// ---- seL4 system calls -------------------------------------------------

/// One seL4 system call: `x7` = number, `x0` = capability (badge out),
/// `x1` = message info, `x2`-`x5` = message registers 0-3.
#[inline(always)]
fn sel4(nr: i64, dest: u64, info: u64, mr: [u64; 4]) -> (u64, u64, [u64; 4]) {
    let (badge, info_out, m0, m1, m2, m3);
    // SAFETY: seL4 preserves every register but these.
    unsafe {
        asm!(
            "svc #0",
            in("x7") nr,
            inlateout("x0") dest => badge,
            inlateout("x1") info => info_out,
            inlateout("x2") mr[0] => m0,
            inlateout("x3") mr[1] => m1,
            inlateout("x4") mr[2] => m2,
            inlateout("x5") mr[3] => m3,
            lateout("x6") _,
            options(nostack),
        );
    }
    (badge, info_out, [m0, m1, m2, m3])
}

const fn info(label: u64, extra_caps: u64, length: u64) -> u64 {
    label << 12 | extra_caps << 7 | length
}

/// Invokes the object `service` refers to: `caps` go in the IPC buffer's
/// capability slots, `words` in the message registers. Returns seL4's
/// error number (0 = success).
fn invoke(service: u64, label: u64, caps: &[u64], words: &[u64]) -> u64 {
    let buf = state().ipc_buffer;
    let mut mr = [0; 4];
    for (i, &w) in words.iter().enumerate() {
        if i < 4 {
            mr[i] = w;
        } else {
            // SAFETY: the root task's IPC buffer, mapped by seL4; only the
            // root task invokes objects.
            unsafe { core::ptr::write_volatile((buf + 8 + 8 * i as u64) as *mut u64, w) };
        }
    }
    for (i, &c) in caps.iter().enumerate() {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((buf + IPCBUF_CAPS + 8 * i as u64) as *mut u64, c) };
    }
    let tag = info(label, caps.len() as u64, words.len() as u64);
    sel4(SYS_CALL, service, tag, mr).1 >> 12
}

fn retype(ut: u64, ty: u64, bits: u64, dest: u64, n: u64) -> u64 {
    invoke(
        ut,
        UNTYPED_RETYPE,
        &[INIT_CNODE],
        &[ty, bits, 0, 0, dest, n],
    )
}

fn irq_get(intid: u64, dest: u64) -> u64 {
    invoke(
        IRQ_CONTROL,
        IRQ_ISSUE_IRQ_HANDLER,
        &[INIT_CNODE],
        &[intid, dest, 64],
    )
}

/// Maps a frame, making the page tables it needs from the pool.
fn page_map(frame: u64, va: u64, writable: bool) -> u64 {
    let s = state();
    let rights = RIGHT_READ | if writable { RIGHT_WRITE } else { 0 };
    let attrs = VM_EXECUTE_NEVER
        | if frame == s.device_frame {
            0
        } else {
            VM_CACHEABLE
        };
    for _ in 0..4 {
        match invoke(frame, ARM_PAGE_MAP, &[INIT_VSPACE], &[va, rights, attrs]) {
            FAILED_LOOKUP => {
                let pt = alloc(1);
                let err = retype(s.pool, SEL4_PAGE_TABLE, 0, pt, 1);
                if err != 0 {
                    return err;
                }
                let err = invoke(pt, ARM_PAGE_TABLE_MAP, &[INIT_VSPACE], &[va, VM_CACHEABLE]);
                if err != 0 {
                    return err;
                }
            }
            err => return err,
        }
    }
    FAILED_LOOKUP
}

// ---- Superior system calls ---------------------------------------------

/// This thread's number: 0 for the root task.
fn thread() -> u64 {
    let t: u64;
    // SAFETY: reading this thread's TLS base.
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) t, options(nomem, nostack)) };
    t
}

/// The CPtr for this thread's slot.
fn slot(s: u64) -> u64 {
    state().window + WINDOW_SLOTS * thread() + s
}

/// The CPtr for another thread's slot, given its thread capability.
fn thread_slot(tcb: u64, s: u64) -> Option<u64> {
    let st = state();
    let t = st.tcbs[..st.threads].iter().position(|&c| c == tcb)?;
    Some(st.window + WINDOW_SLOTS * (t as u64 + 1) + s)
}

/// Superior rights (bit 0 read, bit 1 write) as seL4 rights; Grant Reply
/// always, so calls through any copy get a reply.
fn rights(sup: u64) -> u64 {
    RIGHT_GRANT_REPLY
        | if sup & 1 != 0 { RIGHT_READ } else { 0 }
        | if sup & 2 != 0 { RIGHT_WRITE } else { 0 }
}

fn status(err: u64) -> Ret {
    Ret {
        status: err,
        badge: 0,
        msg: [0; MSG_WORDS],
        cap: None,
    }
}

fn message(badge: u64, info: u64, msg: [u64; 4]) -> Ret {
    Ret {
        status: info >> 12,
        badge,
        msg,
        cap: None,
    }
}

/// Waits for one 10 ms tick of the physical timer.
fn timer_tick(ntfn: u64) -> Ret {
    // SAFETY: seL4 lets user mode program the EL1 physical timer
    // (KernelArmExportPTMRUser) and read the counter frequency.
    unsafe {
        let freq: u64;
        asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        asm!(
            "msr cntp_tval_el0, {}",
            "msr cntp_ctl_el0, {}",
            "isb",
            in(reg) freq / TICK_HZ,
            in(reg) 1u64,
            options(nostack)
        );
    }
    let (badge, _, msg) = sel4(SYS_RECV, ntfn, 0, [0; 4]);
    // SAFETY: as above; disabling the timer lowers its interrupt.
    unsafe { asm!("msr cntp_ctl_el0, xzr", "isb", options(nostack)) };
    invoke(state().timer_irq, IRQ_ACK_IRQ, &[], &[]);
    message(badge, 0, msg)
}

/// Ends QEMU with `status`, through Arm semihosting.
fn exit(status: u64) -> ! {
    let block = [0x20026u64, status];
    // SAFETY: QEMU runs with semihosting enabled for user mode.
    unsafe {
        asm!("hlt #0xf000", in("x0") 0x18u64, in("x1") block.as_ptr(), options(nostack));
    }
    loop {
        sel4(SYS_YIELD, 0, 0, [0; 4]);
    }
}

/// Prints through Arm semihosting, for start-up failures.
fn debug(s: &str) {
    let mut buf = [0u8; 96];
    let n = s.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    // SAFETY: SYS_WRITE0 reads the NUL-terminated string.
    unsafe {
        asm!("hlt #0xf000", in("x0") 0x04u64, in("x1") buf.as_ptr(), options(nostack));
    }
}

fn debug_num(prefix: &str, n: u64) {
    debug(prefix);
    let mut digits = [0u8; 21];
    let (mut i, mut n) = (20, n);
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    debug(core::str::from_utf8(&digits[i..20]).unwrap_or("?"));
    debug("\n");
}

/// The Superior system call `nr`, done with seL4.
pub fn syscall(nr: Syscall, a0: u64, m: [u64; MSG_WORDS], _x: CapTransfer) -> Ret {
    let s = state();
    match nr {
        Syscall::Send | Syscall::NBSend => {
            let sys = if nr == Syscall::Send {
                SYS_SEND
            } else {
                SYS_NB_SEND
            };
            sel4(sys, slot(a0), info(0, 0, 4), m);
            status(0)
        }
        Syscall::Call => {
            let (badge, info, msg) = sel4(SYS_CALL, slot(a0), info(0, 0, 4), m);
            message(badge, info, msg)
        }
        Syscall::Recv | Syscall::NBRecv => {
            let sys = if nr == Syscall::Recv {
                SYS_RECV
            } else {
                SYS_NB_RECV
            };
            let (badge, _, msg) = sel4(sys, slot(a0), 0, [0; 4]);
            message(badge, 0, msg)
        }
        Syscall::Reply => {
            sel4(SYS_REPLY, 0, info(0, 0, 4), m);
            status(0)
        }
        Syscall::ReplyRecv => {
            let (badge, _, msg) = sel4(SYS_REPLY_RECV, slot(a0), info(0, 0, 4), m);
            message(badge, 0, msg)
        }
        Syscall::Signal => {
            sel4(SYS_SEND, slot(a0), 0, [0; 4]);
            status(0)
        }
        Syscall::Wait if thread() == 0 && a0 == TIMER => timer_tick(slot(a0)),
        Syscall::Wait => {
            let (badge, _, msg) = sel4(SYS_RECV, slot(a0), 0, [0; 4]);
            message(badge, 0, msg)
        }
        Syscall::Yield => {
            sel4(SYS_YIELD, 0, 0, [0; 4]);
            status(0)
        }
        Syscall::Retype => {
            let (ty, bits) = match ObjectType::from_u64(m[0]) {
                Some(ObjectType::Untyped) => (SEL4_UNTYPED, m[1]),
                Some(ObjectType::Endpoint) => (SEL4_ENDPOINT, 0),
                Some(ObjectType::Notification) => (SEL4_NOTIFICATION, 0),
                Some(ObjectType::Frame) => (SEL4_SMALL_PAGE, 0),
                Some(ObjectType::Thread) if s.threads < MAX_THREADS - 1 => (SEL4_TCB, 0),
                _ => return status(UNSUPPORTED),
            };
            let dest = slot(m[2]);
            let err = retype(slot(a0), ty, bits, dest, 1);
            if err == 0 && ty == SEL4_TCB {
                s.tcbs[s.threads] = dest;
                s.threads += 1;
            }
            status(err)
        }
        Syscall::CapMint => status(invoke(
            INIT_CNODE,
            CNODE_MINT,
            &[INIT_CNODE],
            &[slot(m[0]), 64, slot(a0), 64, rights(m[1]), m[2]],
        )),
        Syscall::FrameMap => status(page_map(slot(a0), m[0], m[1] == 1)),
        Syscall::ThreadCopyCap => {
            let Some(dest) = thread_slot(slot(a0), m[1]) else {
                return status(UNSUPPORTED);
            };
            status(invoke(
                INIT_CNODE,
                CNODE_COPY,
                &[INIT_CNODE],
                &[dest, 64, slot(m[0]), 64, rights(m[2])],
            ))
        }
        Syscall::ThreadConfigure => {
            let tcb = slot(a0);
            let Some(n) = s.tcbs[..s.threads].iter().position(|&c| c == tcb) else {
                return status(UNSUPPORTED);
            };
            let (entry, stack, arg, priority) = (m[0], m[1], m[2], m[3]);
            // Same CSpace and VSpace as the root task; no IPC buffer, as
            // messages fit in registers.
            let steps: [&dyn Fn() -> u64; 4] = [
                &|| {
                    invoke(
                        tcb,
                        TCB_CONFIGURE,
                        &[INIT_CNODE, INIT_VSPACE, 0],
                        &[0, 0, 0, 0],
                    )
                },
                &|| invoke(tcb, TCB_SET_PRIORITY, &[INIT_TCB], &[priority]),
                // pc, sp, spsr, x0.
                &|| invoke(tcb, TCB_WRITE_REGISTERS, &[], &[0, 4, entry, stack, 0, arg]),
                &|| invoke(tcb, TCB_SET_TLS_BASE, &[], &[n as u64 + 1]),
            ];
            for step in steps {
                let err = step();
                if err != 0 {
                    return status(err);
                }
            }
            status(0)
        }
        Syscall::ThreadResume => status(invoke(slot(a0), TCB_RESUME, &[], &[])),
        Syscall::IrqSetNotification => {
            status(invoke(slot(a0), IRQ_SET_IRQ_HANDLER, &[slot(m[0])], &[]))
        }
        Syscall::IrqAck => status(invoke(slot(a0), IRQ_ACK_IRQ, &[], &[])),
        // QEMU's exit port: isa-debug-exit reports (value << 1) | 1.
        Syscall::IoPortOut if thread() == 0 && a0 == EXIT_PORT && m[0] == 0xf4 => {
            exit((m[2] << 1) | 1)
        }
        _ => status(UNSUPPORTED),
    }
}
