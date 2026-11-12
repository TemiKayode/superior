//! A network driver's host: serves the `nic` interface over the network
//! interface the driver registers (`lde-net.c`).
//!
//! The driver's NAPI poll runs from the loop, only while the receive
//! queue has room for what it may deliver. The component serves `nic` by
//! calls (`RECV`, `SEND`), and through frame rings (`nic::ring`) once its
//! caller has set them up. Then the frames the driver delivers go from
//! the host's receive queue into the receive ring, and the frames the
//! caller puts in the transmit ring go to the driver's transmit routine,
//! with no call for either; the caller's doorbell is a badged copy of the
//! component's notification, so it wakes the same loop the interrupt
//! does. In a CSpace of 2^8 slots.

use crate::{
    ALL, CLASS_SLOTS, CLASS_VA, LENT, LENT_VA, LISTENER, NOTIFY, PAGE, SERVICE, WRITE, lde_interrupt,
    lde_next_timer, say, start,
};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, Ordering, fence};
use superior_driver::{Failure, irq_ack};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::interfaces::nic::ring;
use superior_objects::interfaces::{Status, nic};
use superior_sys::{syscall, syscall_x};

/// The doorbell: this component's notification, to signal only, granted
/// to the ring's caller.
const DOORBELL: u64 = CLASS_SLOTS;
/// The caller's ring pages.
const RING: u64 = DOORBELL + 1;
const _: () = assert!(RING + ring::PAGES <= 256);
const RING_VA: u64 = CLASS_VA;

unsafe extern "C" {
    fn lde_open() -> c_int;
    fn lde_poll_pending() -> c_int;
    fn lde_poll_weight() -> c_int;
    fn lde_poll();
    fn lde_xmit(frame: *const c_void, len: usize) -> c_int;
    fn lde_tick();
    fn lde_mac(mac: *mut u8);
    fn lde_carrier() -> c_int;
}

/// Received frames waiting for the caller.
const RX_FRAMES: usize = 32;
const RX_BYTES: usize = 1536;
const _: () = assert!(nic::MAX_FRAME as usize <= RX_BYTES);

struct Net {
    /// The receive queue: frames `rx_head .. rx_tail`.
    rx: [[u8; RX_BYTES]; RX_FRAMES],
    rx_len: [u16; RX_FRAMES],
    rx_head: usize,
    rx_tail: usize,
    rx_dropped: u64,
    attached: bool,
    /// The caller's ring: pages attached so far, whether it is started,
    /// and this side's ends of the two rings.
    ring_pages: u64,
    ring: bool,
    ring_rx_tail: u32,
    ring_tx_head: u32,
    /// Frames sent and received, and how many of them through the rings.
    sent: u64,
    received: u64,
    by_ring: u64,
}

struct Cell(UnsafeCell<Net>);
// SAFETY: the component has one thread.
unsafe impl Sync for Cell {}
static NET: Cell = Cell(UnsafeCell::new(Net {
    rx: [[0; RX_BYTES]; RX_FRAMES],
    rx_len: [0; RX_FRAMES],
    rx_head: 0,
    rx_tail: 0,
    rx_dropped: 0,
    attached: false,
    ring_pages: 0,
    ring: false,
    ring_rx_tail: 0,
    ring_tx_head: 0,
    sent: 0,
    received: 0,
    by_ring: 0,
}));

/// The network host's state, taken afresh at each use (see [`host`]).
fn net() -> &'static mut Net {
    // SAFETY: one thread, and no caller keeps the reference across a call
    // that could take it again.
    unsafe { &mut *NET.0.get() }
}

impl Net {
    fn rx_waiting(&self) -> usize {
        self.rx_tail - self.rx_head
    }
}

/// Word `off` of the ring's header page.
fn hdr(off: usize) -> &'static AtomicU32 {
    // SAFETY: only used while the ring is started, its header mapped.
    unsafe { &*((RING_VA + off as u64) as *const AtomicU32) }
}

/// Where frame `i` of a ring whose slots start at page `page` lies.
fn ring_slot(page: u64, i: u32, slots: u32) -> u64 {
    RING_VA + page * PAGE as u64 + (i % slots) as u64 * ring::SLOT
}

#[unsafe(no_mangle)]
extern "C" fn lde_host_rx(frame: *const c_void, len: usize) {
    let n = net();
    if !(14..=nic::MAX_FRAME as usize).contains(&len) || n.rx_waiting() == RX_FRAMES {
        n.rx_dropped += 1;
        return;
    }
    let i = n.rx_tail % RX_FRAMES;
    // SAFETY: lde-net.c passes `len` bytes of a socket buffer; they fit.
    unsafe { core::ptr::copy_nonoverlapping(frame as *const u8, n.rx[i].as_mut_ptr(), len) };
    n.rx_len[i] = len as u16;
    n.rx_tail += 1;
}

fn bring_up(name: &'static str) -> Result<(), Failure> {
    start(name)?;
    // SAFETY: the interface the probe registered is brought up.
    let rc = unsafe { lde_open() };
    if rc != 0 {
        return Err(("the driver could not bring the interface up, errno", -rc as u64));
    }
    if syscall(Syscall::CapMint, NOTIFY, [DOORBELL, WRITE, 2, 0]).status != 0 {
        return Err(("making the doorbell", 0));
    }
    Ok(())
}

fn mac() -> u64 {
    let mut m = [0u8; 6];
    // SAFETY: six bytes.
    unsafe { lde_mac(m.as_mut_ptr()) };
    m.iter().fold(0, |a, &b| a << 8 | b as u64)
}

/// Runs the driver's receive poll while it has work and the queue has
/// room for all one poll may deliver, then tells the caller of frames.
fn pump() {
    let before = net().rx_waiting();
    // SAFETY: lde-net.c's, from the one thread.
    unsafe {
        let weight = lde_poll_weight() as usize;
        while lde_poll_pending() != 0 && net().rx_waiting() + weight <= RX_FRAMES {
            lde_poll();
        }
    }
    let n = net();
    if !n.ring && n.attached && n.rx_waiting() > before {
        syscall(Syscall::Signal, LISTENER, [0; 4]);
    }
}

fn count_frame(sent: bool, by_ring: bool) {
    let n = net();
    if sent {
        n.sent += 1;
    } else {
        n.received += 1;
    }
    n.by_ring += by_ring as u64;
    let (s, r, b) = (n.sent, n.received, n.by_ring);
    if sent && s.is_power_of_two() && s >= 64 {
        say!("{s} frames sent, {r} received ({b} of them through the rings)");
    }
}

/// `RING_ATTACH`: keeps and maps page `page` of the caller's ring.
fn ring_attach(page: u64, lent: bool) -> Status {
    if !lent || page >= ring::PAGES {
        return Status::Invalid;
    }
    if page == 0 {
        ring_drop();
    }
    if net().ring || page != net().ring_pages {
        return Status::Invalid;
    }
    // A copy of what was lent: the lent capability goes after the call.
    if syscall(Syscall::CapMint, LENT, [RING + page, ALL, 0, 0]).status != 0 {
        return Status::Invalid;
    }
    let va = RING_VA + page * PAGE as u64;
    if syscall(Syscall::FrameMap, RING + page, [va, 1, 0, 0]).status != 0 {
        syscall(Syscall::CapDelete, RING + page, [0; 4]);
        return Status::Invalid;
    }
    net().ring_pages += 1;
    Status::Ok
}

/// Lets go of the ring: its pages, and the caller's doorbell.
fn ring_drop() {
    let n = net();
    n.ring = false;
    for p in 0..n.ring_pages {
        // Deleting the capability unmaps the page.
        syscall(Syscall::CapDelete, RING + p, [0; 4]);
    }
    n.ring_pages = 0;
    syscall(Syscall::CapRevoke, DOORBELL, [0; 4]);
}

/// `RING_START`: the rings begin empty. The reply grants DOORBELL.
fn ring_start() -> Status {
    let n = net();
    if n.ring || n.ring_pages != ring::PAGES {
        return Status::Invalid;
    }
    for off in (0..PAGE).step_by(4) {
        hdr(off).store(0, Ordering::Relaxed);
    }
    fence(Ordering::SeqCst);
    (n.ring_rx_tail, n.ring_tx_head) = (0, 0);
    n.ring = true;
    say!("frame rings started");
    Status::Ok
}

/// Moves received frames from the host's queue into the receive ring, as
/// many as it has room for, and tells a sleeping caller.
fn ring_pump_rx() {
    let mut moved = false;
    while net().ring && net().rx_waiting() > 0 {
        let n = net();
        let head = hdr(ring::RX_HEAD).load(Ordering::Acquire);
        if ring::waiting(head, n.ring_rx_tail, ring::RX_SLOTS) == ring::RX_SLOTS {
            // Full: the rest wait in the queue (`before_sleep` tells the
            // caller).
            break;
        }
        let i = n.rx_head % RX_FRAMES;
        let len = n.rx_len[i] as usize;
        let at = n.ring_rx_tail % ring::RX_SLOTS;
        let to = ring_slot(ring::RX_PAGE, n.ring_rx_tail, ring::RX_SLOTS);
        // SAFETY: the ring's pages are mapped; a queued frame fits a slot.
        unsafe { core::ptr::copy_nonoverlapping(n.rx[i].as_ptr(), to as *mut u8, len) };
        hdr(ring::RX_LEN + 4 * at as usize).store(len as u32, Ordering::Relaxed);
        n.rx_head += 1;
        n.ring_rx_tail = n.ring_rx_tail.wrapping_add(1);
        hdr(ring::RX_TAIL).store(n.ring_rx_tail, Ordering::Release);
        count_frame(false, true);
        moved = true;
    }
    if moved {
        fence(Ordering::SeqCst);
        if hdr(ring::CALLER_SLEEPS).swap(0, Ordering::SeqCst) != 0 && net().attached {
            syscall(Syscall::Signal, LISTENER, [0; 4]);
        }
    }
}

/// Sends the frames waiting in the transmit ring. True if some are left
/// because the driver's transmit queue is full: its interrupt, when the
/// device has sent some, wakes the loop.
fn ring_pump_tx() -> bool {
    while net().ring {
        let head = net().ring_tx_head;
        let tail = hdr(ring::TX_TAIL).load(Ordering::Acquire);
        if ring::waiting(head, tail, ring::TX_SLOTS) == 0 {
            break;
        }
        let at = head % ring::TX_SLOTS;
        // Read once: the caller may change it at any time.
        let len = hdr(ring::TX_LEN + 4 * at as usize).load(Ordering::Relaxed) as u64;
        let from = ring_slot(ring::TX_PAGE, head, ring::TX_SLOTS);
        if (14..=nic::MAX_FRAME).contains(&len) {
            // SAFETY: the slot is mapped; lde-net.c copies the frame out
            // before it returns.
            match unsafe { lde_xmit(from as *const c_void, len as usize) } {
                0 => count_frame(true, true),
                1 => return true,
                _ => {} // the interface is down: the frame is lost
            }
        }
        // Only now is the slot the caller's again.
        let n = net();
        n.ring_tx_head = head.wrapping_add(1);
        hdr(ring::TX_HEAD).store(n.ring_tx_head, Ordering::Release);
    }
    false
}

/// Before the component waits: runs the driver's poll, empties the rings
/// as far as it can, says it sleeps, and looks once more, so that nothing
/// put in a ring meanwhile is left there with nobody to signal.
fn before_sleep() {
    loop {
        // SAFETY: lde-net.c's, from the one thread.
        unsafe { lde_tick() };
        pump();
        if !net().ring {
            return;
        }
        ring_pump_rx();
        let stuck = ring_pump_tx();
        hdr(ring::DRIVER_SLEEPS).store(1, Ordering::SeqCst);
        // Frames kept from a full ring wait in the queue, and behind it
        // in the driver: the caller rings the doorbell once it has taken
        // some.
        // SAFETY: lde-net.c's, from the one thread.
        let held = net().rx_waiting() > 0 || unsafe { lde_poll_pending() } != 0;
        hdr(ring::RX_STALLED).store(held as u32, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        let n = net();
        let tail = hdr(ring::TX_TAIL).load(Ordering::Acquire);
        let to_send = ring::waiting(n.ring_tx_head, tail, ring::TX_SLOTS) != 0;
        let head = hdr(ring::RX_HEAD).load(Ordering::Acquire);
        let room = ring::waiting(head, n.ring_rx_tail, ring::RX_SLOTS) < ring::RX_SLOTS;
        if !((to_send && !stuck) || (room && held)) {
            return;
        }
        hdr(ring::DRIVER_SLEEPS).store(0, Ordering::SeqCst);
    }
}

fn recv() -> [u64; 4] {
    let attached = net().attached as u64;
    if net().ring {
        // Frames go to the ring, in order.
        ring_pump_rx();
        return [Status::Empty as u64, 0, attached, 1];
    }
    let n = net();
    if n.rx_waiting() == 0 {
        return [Status::Empty as u64, 0, attached, 0];
    }
    if syscall(Syscall::FrameMap, LENT, [LENT_VA, 1, 0, 0]).status != 0 {
        return [Status::Invalid as u64, 0, attached, 0];
    }
    let i = n.rx_head % RX_FRAMES;
    let len = n.rx_len[i] as usize;
    // SAFETY: the lent page is mapped and a frame fits in it.
    unsafe { core::ptr::copy_nonoverlapping(n.rx[i].as_ptr(), LENT_VA as *mut u8, len) };
    n.rx_head += 1;
    count_frame(false, false);
    [Status::Ok as u64, len as u64, attached, 0]
}

fn send(len: u64) -> Status {
    if !(14..=nic::MAX_FRAME).contains(&len) {
        return Status::Invalid;
    }
    if syscall(Syscall::FrameMap, LENT, [LENT_VA, 0, 0, 0]).status != 0 {
        return Status::Invalid;
    }
    for attempt in 0..2 {
        // SAFETY: the lent page is mapped; lde-net.c copies the frame.
        match unsafe { lde_xmit(LENT_VA as *const c_void, len as usize) } {
            0 => {
                count_frame(true, false);
                return Status::Ok;
            }
            1 if attempt == 0 => {
                // The driver's queue is full: let it see what the device
                // has sent since its last interrupt, and try once more.
                // SAFETY: the driver's, from the one thread.
                unsafe {
                    lde_interrupt();
                    lde_tick();
                }
                pump();
            }
            1 => return Status::NoSpace,
            _ => return Status::DeviceError,
        }
    }
    Status::NoSpace
}

fn serve(m: [u64; 4], lent: bool, cap: Option<u16>) -> [u64; 4] {
    let status = |s: Status| [s as u64, 0, 0, 0];
    match m[0] {
        nic::INFO if m[1] == nic::VERSION => [Status::Ok as u64, mac(), nic::MAX_FRAME, 0],
        nic::ATTACH if cap == Some(LISTENER as u16) => {
            net().attached = true;
            // Frames may already be waiting.
            if net().rx_waiting() > 0 {
                syscall(Syscall::Signal, LISTENER, [0; 4]);
            }
            status(Status::Ok)
        }
        nic::RECV if lent => recv(),
        nic::SEND if lent => status(send(m[1])),
        nic::RING_ATTACH => status(ring_attach(m[1], lent)),
        nic::RING_START => status(ring_start()),
        _ => status(Status::Invalid),
    }
}

/// Runs the Linux network driver linked into this component, serving
/// `nic`. `name` is the driver's, for the log.
pub fn run(name: &'static str) -> ! {
    if let Err((what, code)) = bring_up(name) {
        say!("[fail] {what} ({code:#x})");
        superior_sys::park()
    }
    let m = mac();
    say!(
        "Linux's {name} driver runs the interface: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
        m >> 40 & 0xff,
        m >> 32 & 0xff,
        m >> 24 & 0xff,
        m >> 16 & 0xff,
        m >> 8 & 0xff,
        m & 0xff,
        // SAFETY: lde-net.c's, from the one thread.
        if unsafe { lde_carrier() } != 0 { "up" } else { "down" }
    );
    // The interrupt wakes the same `Recv` that waits for calls.
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the interrupt's notification");
    }
    // A call may lend a frame (RECV, SEND) or grant a notification
    // (ATTACH): either arrives in LENT.
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut reply: Option<([u64; 4], bool)> = None;
    loop {
        before_sleep();
        // The driver's next timer wakes the loop like an interrupt.
        // SAFETY: lde.c's, from the one thread.
        let wake = unsafe { lde_next_timer() } as u64;
        syscall(Syscall::TimerSignal, NOTIFY, [wake, 0, 0, 0]);
        let r = match reply.take() {
            Some((m, doorbell)) => {
                let x = CapTransfer {
                    grant: doorbell.then_some(DOORBELL as u16),
                    ..accept
                };
                syscall_x(Syscall::ReplyRecv, SERVICE, m, x)
            }
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            // The interrupt, or the doorbell (the handler then finds
            // nothing to do). The driver's handler quiets the device (it
            // masks what it leaves for the poll), so the line can be
            // unmasked after.
            // SAFETY: the driver's, from the one thread.
            unsafe { lde_interrupt() };
            irq_ack(crate::IRQ);
            if net().ring {
                hdr(ring::DRIVER_SLEEPS).store(0, Ordering::SeqCst);
            }
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let mut cap = r.cap;
        if r.msg[0] == nic::ATTACH && cap == Some(LENT as u16) {
            // Keep the notification (replacing an earlier one).
            syscall(Syscall::CapDelete, LISTENER, [0; 4]);
            let kept = syscall(Syscall::CapMint, LENT, [LISTENER, ALL, 0, 0]).status == 0;
            syscall(Syscall::CapDelete, LENT, [0; 4]);
            cap = kept.then_some(LISTENER as u16);
        }
        let lent = cap == Some(LENT as u16);
        let m = serve(r.msg, lent, cap);
        if lent {
            // The caller's frame goes back before the reply.
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some((m, r.msg[0] == nic::RING_START && m[0] == 0));
    }
}
