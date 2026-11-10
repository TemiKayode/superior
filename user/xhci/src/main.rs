//! An xHCI (USB 3) host controller driver, serving the `usb` interface
//! (`superior_objects::interfaces::usb`) to class drivers.
//!
//! A class driver: it opens the first PCI function of class 0c:03:30, whoever
//! made it. It resets the controller, sets up the command ring, one event
//! ring and the device context array, and on every root port with a device
//! resets the port, enables a slot and addresses the device, then reads its
//! device descriptor. Class drivers do the rest through control transfers;
//! interrupt-IN endpoints they add are polled by the controller into the
//! driver's buffers, and the class driver is signalled to read them.
//!
//! The controller reaches only the driver's DMA pages (rings, contexts and
//! report buffers) and, during a control transfer, the page the caller lent,
//! through the IOMMU domain that arrives with the open. Its interrupt (MSI-X
//! vector 0) is bound to the driver's thread, so one `Recv` waits for calls
//! and events.
//!
//! Slots: 0 the bus server, 1 the `usb` endpoint (receive), 2 a
//! notification, 3 untyped memory (128 KiB).

#![no_std]
#![no_main]

use superior_driver::{DmaPage, Failure, Mmio, Pci, dma_barrier};
use superior_objects::abi::{CapTransfer, Error, Syscall};
use superior_objects::interfaces::{Status, usb};
use superior_sys::{USER_BASE, print_line, syscall, syscall_x};

const PCI: u64 = 0;
const SERVICE: u64 = 1;
const NOTIFY: u64 = 2;
const UNTYPED: u64 = 3;
const MSI: u64 = 4;
const DOMAIN: u64 = 5;
/// The device context array (with the event ring segment table in its
/// second half), the command ring, the event ring, and a page for the
/// driver's own control transfers.
const DCBAA: u64 = 6;
const CMD_RING: u64 = 7;
const EVENT_RING: u64 = 8;
const SCRATCH: u64 = 9;
/// Where a caller's page (or notification) arrives.
const LENT: u64 = 10;
/// Device `i`'s listener.
const LISTENER: u64 = 11;
/// Device `i`'s pages: output context, input context, endpoint 0's ring,
/// the interrupt endpoint's ring and its report buffers.
const DEVICE_PAGES: u64 = LISTENER + MAX_DEVICES as u64;
const PAGES_PER_DEVICE: u64 = 5;
const BAR_SLOTS: u64 = DEVICE_PAGES + PAGES_PER_DEVICE * MAX_DEVICES as u64;
const MAX_BAR_PAGES: u64 = 8;

const BAR_VA: u64 = USER_BASE + 0x4000_0000;
const DMA_VA: u64 = USER_BASE + 0x5000_0000;
const LENT_VA: u64 = USER_BASE + 0x6000_0000;

const MAX_DEVICES: usize = 4;
/// Every right, for keeping a granted capability.
const ALL: u64 = 0x1f;

/// PCI class 0c (serial bus), subclass 03 (USB), interface 30 (xHCI).
const CLASS: u32 = 0x0c_03_30;
const CAP_MSIX: u8 = 0x11;

// Capability registers.
const HCSPARAMS1: u64 = 0x04;
const HCSPARAMS2: u64 = 0x08;
const HCCPARAMS1: u64 = 0x10;
const DBOFF: u64 = 0x14;
const RTSOFF: u64 = 0x18;
// Operational registers (from CAPLENGTH).
const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const CRCR: u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;
const PORTSC: u64 = 0x400;
const CMD_RUN: u32 = 1;
const CMD_RESET: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HALTED: u32 = 1;
const STS_EINT: u32 = 1 << 3;
const STS_CNR: u32 = 1 << 11;
// PORTSC bits.
const PORT_CCS: u32 = 1;
const PORT_PED: u32 = 1 << 1;
const PORT_PR: u32 = 1 << 4;
const PORT_PRC: u32 = 1 << 21;
/// The change bits (write 1 to clear), and PED (write 1 to disable).
const PORT_W1C: u32 = 0x7f << 17 | PORT_PED;
// Interrupter 0 (from RTSOFF).
const IMAN: u64 = 0x20;
const ERSTSZ: u64 = 0x28;
const ERSTBA: u64 = 0x30;
const ERDP: u64 = 0x38;
const IMAN_IP: u32 = 1;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;

// TRB types.
const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const EV_TRANSFER: u32 = 32;
const EV_COMMAND: u32 = 33;
// TRB control bits.
const CYCLE: u32 = 1;
const TOGGLE: u32 = 1 << 1;
const ISP: u32 = 1 << 2;
const IOC: u32 = 1 << 5;
const IDT: u32 = 1 << 6;
const DIR_IN: u32 = 1 << 16;
// Completion codes.
const SUCCESS: u32 = 1;
const SHORT_PACKET: u32 = 13;

/// TRBs in a ring (one page); the last is the link back.
const RING_TRBS: u16 = 256;
/// Report buffers of an interrupt endpoint, 64 bytes each.
const REPORTS: usize = 16;
const REPORT: u64 = 64;

/// Ticks a command or control transfer may take.
const TIMEOUT: u64 = 200;

macro_rules! say {
    ($($t:tt)*) => { print_line(format_args!("xhci: {}", format_args!($($t)*))) };
}

fn ticks() -> u64 {
    syscall(Syscall::Ticks, 0, [0; 4]).msg[0]
}

/// A producer ring of TRBs, in one DMA page, ending in a link TRB.
struct Ring {
    page: DmaPage,
    enqueue: u16,
    cycle: bool,
}

impl Ring {
    fn new(slot: u64) -> Result<Ring, Failure> {
        Ok(Ring {
            page: dma_page(slot)?,
            enqueue: 0,
            cycle: true,
        })
    }

    fn write(&self, i: u16, param: u64, status: u32, control: u32) {
        let at = self.page.va + 16 * i as u64;
        // SAFETY: TRB `i < RING_TRBS` lies in the ring's page. The control
        // word (with the cycle bit) goes last, so the controller never sees
        // a half-written TRB.
        unsafe {
            (at as *mut u64).write_volatile(param);
            ((at + 8) as *mut u32).write_volatile(status);
            dma_barrier();
            ((at + 12) as *mut u32).write_volatile(control);
        }
    }

    /// Adds a TRB of `kind`; returns its device address.
    fn push(&mut self, param: u64, status: u32, kind: u32, flags: u32) -> u64 {
        if self.enqueue == RING_TRBS - 1 {
            let c = self.cycle as u32;
            self.write(self.enqueue, self.page.dma, 0, TRB_LINK << 10 | TOGGLE | c);
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        let at = self.page.dma + 16 * self.enqueue as u64;
        self.write(
            self.enqueue,
            param,
            status,
            kind << 10 | flags | self.cycle as u32,
        );
        self.enqueue += 1;
        at
    }
}

/// A DMA page in `slot`, mapped at its own address.
fn dma_page(slot: u64) -> Result<DmaPage, Failure> {
    DmaPage::new(UNTYPED, slot, DMA_VA + (slot - DCBAA) * 0x1000, DOMAIN)
}

#[derive(Clone, Copy)]
struct Event {
    param: u64,
    status: u32,
    control: u32,
}

impl Event {
    fn kind(&self) -> u32 {
        self.control >> 10 & 0x3f
    }
    fn code(&self) -> u32 {
        self.status >> 24
    }
    fn slot(&self) -> u8 {
        (self.control >> 24) as u8
    }
}

struct Device {
    port: u8,
    speed: u8,
    slot: u8,
    ids: u32,
    class: u32,
    owner: Option<u64>,
    out_ctx: DmaPage,
    in_ctx: DmaPage,
    ep0: Ring,
    /// The interrupt-IN endpoint: its address and context index.
    int_ep: Option<(u8, u8)>,
    int_ring: Ring,
    reports: DmaPage,
    /// Which report buffer each ring TRB fills.
    trb_buffer: [u8; RING_TRBS as usize],
    /// Completed reports, oldest first: (buffer, length).
    done: [(u8, u8); REPORTS],
    done_head: usize,
    done_count: usize,
    max_packet: u32,
}

struct Hc {
    op: Mmio,
    rt: Mmio,
    db: Mmio,
    /// Context size: 32 or 64 bytes.
    csz: u64,
    dcbaa: DmaPage,
    cmd: Ring,
    events: DmaPage,
    ev_dequeue: u16,
    ev_cycle: bool,
    scratch: DmaPage,
    devices: [Option<Device>; MAX_DEVICES],
    /// The last command completion: (command TRB, code, slot).
    cmd_done: Option<(u64, u32, u8)>,
    /// The last endpoint 0 transfer events: (TRB, code, residual).
    ctl_done: [Option<(u64, u32, u32)>; 4],
}

/// Maps the BAR pages a range needs, one slot each.
struct Bars {
    pci: Pci,
    mapped: [u16; 6],
    next_slot: u64,
}

impl Bars {
    fn va(bar: u64, off: u64) -> u64 {
        BAR_VA + bar * 0x10_0000 + off
    }

    fn map(&mut self, bar: u64, off: u64, len: u64) -> Result<u64, Failure> {
        if bar >= 6 || off + len > MAX_BAR_PAGES * 4096 {
            return Err(("a register block outside what the driver maps", bar));
        }
        for page in off / 4096..=(off + len.max(1) - 1) / 4096 {
            if self.mapped[bar as usize] & 1 << page != 0 {
                continue;
            }
            if self.next_slot == BAR_SLOTS + MAX_BAR_PAGES {
                return Err(("too many BAR pages", 0));
            }
            self.pci
                .map_bar_page(bar, page, self.next_slot, Self::va(bar, page * 4096))?;
            self.next_slot += 1;
            self.mapped[bar as usize] |= 1 << page;
        }
        Ok(Self::va(bar, off))
    }
}

fn wait_for(what: &'static str, mut done: impl FnMut() -> bool) -> Result<(), Failure> {
    let start = ticks();
    while !done() {
        if ticks() > start + TIMEOUT {
            return Err((what, 0));
        }
        syscall(Syscall::Yield, 0, [0; 4]);
    }
    Ok(())
}

fn start() -> Result<Hc, Failure> {
    let pci = Pci { slot: PCI };
    let (bdf, _) = pci.open_class(CLASS, 0, DOMAIN)?;
    let mut bars = Bars {
        pci: Pci { slot: PCI },
        mapped: [0; 6],
        next_slot: BAR_SLOTS,
    };
    let cap = Mmio {
        base: bars.map(0, 0, 0x20)?,
    };
    let caplength = cap.read8(0) as u64;
    let hcs1 = cap.read32(HCSPARAMS1);
    let hcs2 = cap.read32(HCSPARAMS2);
    let hcc1 = cap.read32(HCCPARAMS1);
    let (max_slots, max_ports) = (hcs1 & 0xff, hcs1 >> 24);
    let scratchpads = (hcs2 >> 27 & 0x1f) | (hcs2 >> 21 & 0x1f) << 5;
    if scratchpads != 0 {
        return Err(("the controller wants scratchpad buffers", scratchpads as u64));
    }
    let csz = if hcc1 & 1 << 2 != 0 { 64 } else { 32 };
    let dboff = cap.read32(DBOFF) as u64 & !3;
    let rtsoff = cap.read32(RTSOFF) as u64 & !0x1f;
    let op = Mmio {
        base: bars.map(0, caplength, PORTSC + 0x10 * max_ports as u64)?,
    };
    let rt = Mmio {
        base: bars.map(0, rtsoff, 0x40)?,
    };
    let db = Mmio {
        base: bars.map(0, dboff, 4 * (max_slots as u64 + 1))?,
    };

    // Stop and reset the controller.
    op.write32(USBCMD, op.read32(USBCMD) & !CMD_RUN);
    wait_for("the controller did not halt", || {
        op.read32(USBSTS) & STS_HALTED != 0
    })?;
    op.write32(USBCMD, CMD_RESET);
    wait_for("the controller did not reset", || {
        op.read32(USBCMD) & CMD_RESET == 0 && op.read32(USBSTS) & STS_CNR == 0
    })?;

    // Bus mastering first: setting the event ring makes the controller
    // read its segment table.
    pci.bus_master(true)?;
    let dcbaa = dma_page(DCBAA)?;
    let cmd = Ring::new(CMD_RING)?;
    let events = dma_page(EVENT_RING)?;
    let scratch = dma_page(SCRATCH)?;
    let slots = max_slots.min(MAX_DEVICES as u32 * 2);
    op.write32(CONFIG, slots);
    op.write32(DCBAAP, dcbaa.dma as u32);
    op.write32(DCBAAP + 4, (dcbaa.dma >> 32) as u32);
    op.write32(CRCR, cmd.page.dma as u32 | 1);
    op.write32(CRCR + 4, (cmd.page.dma >> 32) as u32);
    // One event ring segment; its table entry in the second half of the
    // context array's page.
    let erst = dcbaa.va + 2048;
    // SAFETY: the context array's page is mapped; the entry is 16 bytes.
    unsafe {
        (erst as *mut u64).write_volatile(events.dma);
        ((erst + 8) as *mut u32).write_volatile(RING_TRBS as u32);
        ((erst + 12) as *mut u32).write_volatile(0);
    }
    dma_barrier();
    rt.write32(ERSTSZ, 1);
    rt.write32(ERDP, events.dma as u32);
    rt.write32(ERDP + 4, (events.dma >> 32) as u32);
    rt.write32(ERSTBA, (dcbaa.dma + 2048) as u32);
    rt.write32(ERSTBA + 4, ((dcbaa.dma + 2048) >> 32) as u32);

    // MSI-X vector 0, for interrupter 0.
    let msix = pci.find_capability(CAP_MSIX, 0)?.ok_or(("no MSI-X", 0))?;
    let table = pci.config_read(msix + 4)? as u64;
    let entry = Mmio {
        base: bars.map(table & 7, table & !7, 16)?,
    };
    let (address, data) = pci.msi_vector(0, MSI, NOTIFY, DOMAIN)?;
    entry.write32(0, address as u32);
    entry.write32(4, (address >> 32) as u32);
    entry.write32(8, data as u32);
    entry.write32(12, 0);
    pci.msix(true)?;
    rt.write32(IMAN, IMAN_IE | IMAN_IP);
    op.write32(USBCMD, CMD_RUN | CMD_INTE);
    wait_for("the controller did not start", || {
        op.read32(USBSTS) & STS_HALTED == 0
    })?;
    say!(
        "ready: {:02x}:{:02x}.{}, {max_ports} ports, {max_slots} slots, {csz}-byte contexts, interrupts on MSI-X vector 0 (message data {data:#x})",
        bdf >> 8,
        bdf >> 3 & 0x1f,
        bdf & 7
    );
    let mut hc = Hc {
        op,
        rt,
        db,
        csz,
        dcbaa,
        cmd,
        events,
        ev_dequeue: 0,
        ev_cycle: true,
        scratch,
        devices: [const { None }; MAX_DEVICES],
        cmd_done: None,
        ctl_done: [None; 4],
    };
    // The devices on the root ports.
    let mut n = 0;
    for port in 1..=max_ports as u8 {
        if n == MAX_DEVICES {
            break;
        }
        let sc = hc.op.read32(PORTSC + 0x10 * (port as u64 - 1));
        if sc & PORT_CCS == 0 {
            continue;
        }
        match hc.enumerate(port, n) {
            Ok(d) => {
                say!(
                    "port {port}: device {:04x}:{:04x} class {:06x}, {} speed, slot {}",
                    d.ids >> 16,
                    d.ids & 0xffff,
                    d.class,
                    ["?", "full", "low", "high", "super"].get(d.speed as usize).unwrap_or(&"?"),
                    d.slot
                );
                hc.devices[n] = Some(d);
                n += 1;
            }
            Err((what, code)) => say!("port {port}: {what} ({code:#x})"),
        }
    }
    Ok(hc)
}

impl Hc {
    fn portsc(&self, port: u8) -> u64 {
        PORTSC + 0x10 * (port as u64 - 1)
    }

    /// Takes the events the controller has posted, dispatching each.
    fn poll(&mut self) {
        let mut any = false;
        loop {
            let at = self.events.va + 16 * self.ev_dequeue as u64;
            dma_barrier();
            // SAFETY: the event ring's page is mapped; the TRB is inside.
            let control = unsafe { ((at + 12) as *const u32).read_volatile() };
            if (control & CYCLE != 0) != self.ev_cycle {
                break;
            }
            // SAFETY: as above.
            let e = unsafe {
                Event {
                    param: (at as *const u64).read_volatile(),
                    status: ((at + 8) as *const u32).read_volatile(),
                    control,
                }
            };
            self.ev_dequeue += 1;
            if self.ev_dequeue == RING_TRBS {
                self.ev_dequeue = 0;
                self.ev_cycle = !self.ev_cycle;
            }
            any = true;
            self.dispatch(e);
        }
        if any {
            let erdp = self.events.dma + 16 * self.ev_dequeue as u64 | ERDP_EHB;
            self.rt.write32(ERDP, erdp as u32);
            self.rt.write32(ERDP + 4, (erdp >> 32) as u32);
        }
        self.rt.write32(IMAN, IMAN_IE | IMAN_IP);
        self.op.write32(USBSTS, STS_EINT);
    }

    fn dispatch(&mut self, e: Event) {
        match e.kind() {
            EV_COMMAND => self.cmd_done = Some((e.param, e.code(), e.slot())),
            EV_TRANSFER => {
                let dci = (e.control >> 16 & 0x1f) as u8;
                let residual = e.status & 0xff_ffff;
                if dci == 1 {
                    self.ctl_done.rotate_right(1);
                    self.ctl_done[0] = Some((e.param, e.code(), residual));
                    return;
                }
                let Some(i) = self
                    .devices
                    .iter()
                    .position(|d| matches!(d, Some(d) if d.slot == e.slot()))
                else {
                    return;
                };
                let d = self.devices[i].as_mut().unwrap();
                if d.int_ep.map(|x| x.1) != Some(dci) || d.done_count == REPORTS {
                    return;
                }
                if e.code() != SUCCESS && e.code() != SHORT_PACKET {
                    return;
                }
                let trb = ((e.param - d.int_ring.page.dma) / 16) as usize % RING_TRBS as usize;
                let len = d.max_packet.saturating_sub(residual) as u8;
                d.done[(d.done_head + d.done_count) % REPORTS] = (d.trb_buffer[trb], len);
                d.done_count += 1;
                if d.owner.is_some() {
                    syscall(Syscall::Signal, LISTENER + i as u64, [0; 4]);
                }
            }
            _ => {}
        }
    }

    /// Runs a command; returns its completion's slot.
    fn command(&mut self, param: u64, kind: u32, flags: u32) -> Result<u8, Failure> {
        self.cmd_done = None;
        let at = self.cmd.push(param, 0, kind, flags);
        dma_barrier();
        self.db.write32(0, 0);
        let start = ticks();
        loop {
            self.poll();
            if let Some((trb, code, slot)) = self.cmd_done {
                if trb == at {
                    return match code {
                        SUCCESS => Ok(slot),
                        c => Err(("a command failed", (kind as u64) << 8 | c as u64)),
                    };
                }
            }
            if ticks() > start + TIMEOUT {
                return Err(("a command timed out", kind as u64));
            }
            syscall(Syscall::Yield, 0, [0; 4]);
        }
    }

    /// A control transfer on device `i`'s endpoint 0, its data stage at
    /// `buffer` (a device address). Returns the bytes moved.
    fn control(&mut self, i: usize, setup: u64, buffer: u64) -> Result<u32, Failure> {
        let len = (setup >> 48) as u32;
        let input = setup & 0x80 != 0;
        let d = self.devices[i].as_mut().ok_or(("no such device", i as u64))?;
        let trt = match (len, input) {
            (0, _) => 0,
            (_, false) => 2 << 16,
            (_, true) => 3 << 16,
        };
        d.ep0.push(setup, 8, TRB_SETUP, IDT | trt);
        let mut data_at = None;
        if len > 0 {
            let dir = if input { DIR_IN } else { 0 };
            data_at = Some(d.ep0.push(buffer, len, TRB_DATA, dir | ISP | IOC));
        }
        let status_dir = if len > 0 && input { 0 } else { DIR_IN };
        let status_at = d.ep0.push(0, 0, TRB_STATUS, status_dir | IOC);
        let slot = d.slot;
        self.ctl_done = [None; 4];
        dma_barrier();
        self.db.write32(4 * slot as u64, 1);
        let start = ticks();
        loop {
            self.poll();
            let find = |at: u64| self.ctl_done.iter().flatten().find(|e| e.0 == at).copied();
            if let Some((_, code, _)) = find(status_at) {
                if code != SUCCESS {
                    return Err(("a control transfer failed", code as u64));
                }
                let moved = match data_at.and_then(find) {
                    Some((_, _, residual)) => len.saturating_sub(residual),
                    None => len,
                };
                return Ok(moved);
            }
            // A stall or error ends the transfer at the data stage.
            if let Some((_, code, _)) = data_at.and_then(find) {
                if code != SUCCESS && code != SHORT_PACKET {
                    return Err(("a control transfer failed", code as u64));
                }
            }
            if ticks() > start + TIMEOUT {
                return Err(("a control transfer timed out", 0));
            }
            syscall(Syscall::Yield, 0, [0; 4]);
        }
    }

    fn ctx(&self, page: &DmaPage, index: u64) -> u64 {
        page.va + self.csz * index
    }

    fn put(at: u64, dword: u64, v: u32) {
        // SAFETY: `at` is a context inside a mapped DMA page.
        unsafe { ((at + 4 * dword) as *mut u32).write_volatile(v) }
    }

    fn get(at: u64, dword: u64) -> u32 {
        // SAFETY: as in `put`.
        unsafe { ((at + 4 * dword) as *const u32).read_volatile() }
    }

    /// Resets `port`, enables a slot and addresses its device, which
    /// becomes device `n`.
    fn enumerate(&mut self, port: u8, n: usize) -> Result<Device, Failure> {
        let reg = self.portsc(port);
        let sc = self.op.read32(reg);
        if sc & PORT_PED == 0 {
            // A USB 2 port: reset it to enable it.
            self.op.write32(reg, sc & !PORT_W1C | PORT_PR);
            wait_for("the port did not finish its reset", || {
                self.op.read32(reg) & PORT_PRC != 0
            })?;
        }
        let sc = self.op.read32(reg);
        self.op.write32(reg, sc & !PORT_PED); // clears the change bits
        if sc & PORT_PED == 0 {
            return Err(("the port stayed disabled", sc as u64));
        }
        let speed = (sc >> 10 & 0xf) as u8;
        let slot = self.command(0, TRB_ENABLE_SLOT, 0)?;
        let base = DEVICE_PAGES + PAGES_PER_DEVICE * n as u64;
        let d = Device {
            port,
            speed,
            slot,
            ids: 0,
            class: 0,
            owner: None,
            out_ctx: dma_page(base)?,
            in_ctx: dma_page(base + 1)?,
            ep0: Ring::new(base + 2)?,
            int_ep: None,
            int_ring: Ring::new(base + 3)?,
            reports: dma_page(base + 4)?,
            trb_buffer: [0; RING_TRBS as usize],
            done: [(0, 0); REPORTS],
            done_head: 0,
            done_count: 0,
            max_packet: 0,
        };
        // SAFETY: the array has an entry for every enabled slot.
        unsafe { ((self.dcbaa.va + 8 * slot as u64) as *mut u64).write_volatile(d.out_ctx.dma) };
        let mps = match speed {
            3 => 64,
            4 => 512,
            _ => 8,
        };
        // Address Device: the slot and endpoint 0.
        let input = self.ctx(&d.in_ctx, 0);
        Self::put(input, 1, 0b11);
        let slot_ctx = self.ctx(&d.in_ctx, 1);
        Self::put(slot_ctx, 0, (speed as u32) << 20 | 1 << 27);
        Self::put(slot_ctx, 1, (port as u32) << 16);
        let ep0 = self.ctx(&d.in_ctx, 2);
        Self::put(ep0, 1, 3 << 1 | 4 << 3 | mps << 16);
        Self::put(ep0, 2, d.ep0.page.dma as u32 | 1);
        Self::put(ep0, 3, (d.ep0.page.dma >> 32) as u32);
        Self::put(ep0, 4, 8);
        dma_barrier();
        let in_dma = d.in_ctx.dma;
        self.command(in_dma, TRB_ADDRESS_DEVICE, (slot as u32) << 24)?;
        self.devices[n] = Some(d);
        // Its device descriptor.
        let scratch = self.scratch;
        let got = self.control(n, get_descriptor(1, 0, 18), scratch.dma);
        let mut d = self.devices[n].take().unwrap();
        got?;
        // SAFETY: the scratch page is mapped and holds the descriptor.
        let desc = unsafe { core::slice::from_raw_parts(scratch.va as *const u8, 18) };
        d.class = (desc[4] as u32) << 16 | (desc[5] as u32) << 8 | desc[6] as u32;
        let le = |at: usize| u16::from_le_bytes([desc[at], desc[at + 1]]) as u32;
        d.ids = le(8) << 16 | le(10);
        let real_mps = if speed == 4 { 1 << desc[7] } else { desc[7] as u32 };
        if real_mps != mps && real_mps != 0 {
            // Evaluate Context with endpoint 0's real packet size.
            Self::put(input, 1, 0b10);
            Self::put(ep0, 1, 3 << 1 | 4 << 3 | real_mps << 16);
            dma_barrier();
            self.command(in_dma, TRB_EVALUATE_CONTEXT, (slot as u32) << 24)?;
        }
        Ok(d)
    }

    /// Adds device `i`'s interrupt-IN endpoint and starts polling it.
    fn endpoint(&mut self, i: usize, desc: u64) -> Status {
        let (addr, mps, interval) = (desc as u8, (desc >> 8 & 0x7ff) as u32, (desc >> 24) as u8);
        if addr & 0x80 == 0 || addr & 0xf == 0 || mps == 0 || mps as u64 > REPORT {
            return Status::Invalid;
        }
        let dci = 2 * (addr & 0xf) + 1;
        let csz = self.csz;
        let Some(d) = self.devices[i].as_mut() else {
            return Status::NotFound;
        };
        if d.int_ep.is_some() {
            return if d.int_ep.map(|x| x.0) == Some(addr) {
                Status::Ok
            } else {
                Status::InUse
            };
        }
        let speed = d.speed;
        // Interval in 2^n 125-microsecond frames.
        let exp = if speed == 1 || speed == 2 {
            (31 - ((interval.max(1) as u32) * 8).leading_zeros()).clamp(3, 10)
        } else {
            (interval.max(1) as u32 - 1).min(15)
        };
        let input = d.in_ctx.va;
        let out_slot = d.out_ctx.va;
        let ep = d.in_ctx.va + csz * (1 + dci as u64);
        for w in 0..(csz / 4) * 33 {
            Self::put(input, w, 0);
        }
        Self::put(input, 1, 1 | 1 << dci);
        // The slot context as the controller has it, with more entries.
        for w in 0..8 {
            Self::put(input + csz, w, Self::get(out_slot, w));
        }
        let entries = (Self::get(out_slot, 0) >> 27).max(dci as u32);
        Self::put(input + csz, 0, Self::get(out_slot, 0) & !(0x1f << 27) | entries << 27);
        Self::put(input + csz, 3, 0);
        Self::put(ep, 0, exp << 16);
        Self::put(ep, 1, 3 << 1 | 7 << 3 | mps << 16);
        Self::put(ep, 2, d.int_ring.page.dma as u32 | 1);
        Self::put(ep, 3, (d.int_ring.page.dma >> 32) as u32);
        Self::put(ep, 4, mps | mps << 16);
        dma_barrier();
        let (in_dma, slot) = (d.in_ctx.dma, d.slot);
        if self
            .command(in_dma, TRB_CONFIGURE_ENDPOINT, (slot as u32) << 24)
            .is_err()
        {
            return Status::DeviceError;
        }
        let d = self.devices[i].as_mut().unwrap();
        d.int_ep = Some((addr, dci));
        d.max_packet = mps;
        for b in 0..REPORTS as u8 {
            self.queue(i, b);
        }
        Status::Ok
    }

    /// Gives report buffer `b` of device `i` to its interrupt endpoint.
    fn queue(&mut self, i: usize, b: u8) {
        let d = self.devices[i].as_mut().unwrap();
        let Some((_, dci)) = d.int_ep else { return };
        let buf = d.reports.dma + REPORT * b as u64;
        let at = d.int_ring.push(buf, d.max_packet, TRB_NORMAL, ISP | IOC);
        let trb = ((at - d.int_ring.page.dma) / 16) as usize;
        d.trb_buffer[trb] = b;
        dma_barrier();
        self.db.write32(4 * d.slot as u64, dci as u32);
    }

    fn map_lent(&self, writable: bool) -> bool {
        syscall(Syscall::FrameMap, LENT, [LENT_VA, writable as u64, 0, 0]).status == 0
    }

    fn read(&mut self, i: usize, addr: u8) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        let d = self.devices[i].as_mut().unwrap();
        if d.int_ep.map(|x| x.0) != Some(addr) {
            return status(Status::NotFound);
        }
        if d.done_count == 0 {
            return status(Status::Empty);
        }
        let (b, len) = d.done[d.done_head];
        let src = d.reports.va + REPORT * b as u64;
        if !self.map_lent(true) {
            return status(Status::Invalid);
        }
        // SAFETY: the report buffer and the lent page are both mapped.
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, LENT_VA as *mut u8, len as usize)
        };
        let d = self.devices[i].as_mut().unwrap();
        d.done_head = (d.done_head + 1) % REPORTS;
        d.done_count -= 1;
        self.queue(i, b);
        [Status::Ok as u64, len as u64, 0, 0]
    }

    fn serve(&mut self, badge: u64, m: [u64; 4], cap: Option<u16>) -> [u64; 4] {
        let status = |s: Status| [s as u64, 0, 0, 0];
        let lent = cap == Some(LENT as u16);
        let count = self.devices.iter().flatten().count();
        if m[0] == usb::INFO {
            return if m[1] == usb::VERSION {
                [Status::Ok as u64, count as u64, 0, 0]
            } else {
                status(Status::Invalid)
            };
        }
        let i = m[1] as usize;
        let Some(d) = self.devices.get(i).and_then(|d| d.as_ref()) else {
            return status(Status::NotFound);
        };
        if m[0] == usb::DEVICE {
            return [
                Status::Ok as u64,
                d.port as u64 | (d.speed as u64) << 8,
                d.ids as u64,
                d.class as u64,
            ];
        }
        // Everything else needs the device, claimed by the caller, but for
        // reading descriptors (GET_DESCRIPTOR), which any client may do to
        // decide whether to claim it.
        let get_descriptor = m[0] == usb::CONTROL && matches!(m[2] & 0xffff, 0x0680 | 0x0681);
        match d.owner {
            Some(o) if o != badge && !get_descriptor => return status(Status::InUse),
            None if m[0] != usb::ATTACH && !get_descriptor => return status(Status::Denied),
            _ => {}
        }
        match m[0] {
            usb::ATTACH if lent => {
                syscall(Syscall::CapDelete, LISTENER + i as u64, [0; 4]);
                let kept = syscall(Syscall::CapMint, LENT, [LISTENER + i as u64, ALL, 0, 0]);
                if kept.status != 0 {
                    return status(Status::Invalid);
                }
                let d = self.devices[i].as_mut().unwrap();
                d.owner = Some(badge);
                if d.done_count > 0 {
                    syscall(Syscall::Signal, LISTENER + i as u64, [0; 4]);
                }
                status(Status::Ok)
            }
            usb::CONTROL if lent => {
                let setup = m[2];
                let input = setup & 0x80 != 0;
                let len = (setup >> 48) as usize;
                if len > 4096 || (len > 0 && !self.map_lent(input)) {
                    return status(Status::Invalid);
                }
                // The data stage goes through the driver's own page: the
                // controller never reaches the caller's.
                let scratch = self.scratch;
                if !input && len > 0 {
                    // SAFETY: both pages are mapped; `len` fits in a page.
                    unsafe {
                        core::ptr::copy_nonoverlapping(LENT_VA as *const u8, scratch.va as *mut u8, len)
                    };
                }
                match self.control(i, setup, scratch.dma) {
                    Ok(n) => {
                        if input && n > 0 {
                            // SAFETY: as above; `n <= len`.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    scratch.va as *const u8,
                                    LENT_VA as *mut u8,
                                    (n as usize).min(len),
                                )
                            };
                        }
                        [Status::Ok as u64, n as u64, 0, 0]
                    }
                    Err(_) => status(Status::DeviceError),
                }
            }
            usb::ENDPOINT => status(self.endpoint(i, m[2])),
            usb::READ if lent => self.read(i, m[2] as u8),
            _ => status(Status::Invalid),
        }
    }
}

/// A standard GET_DESCRIPTOR request's setup packet.
fn get_descriptor(kind: u8, index: u8, len: u16) -> u64 {
    0x80 | 6 << 8 | ((kind as u64) << 8 | index as u64) << 16 | (len as u64) << 48
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    let mut hc = match start() {
        Ok(h) => h,
        Err((what, code)) => {
            say!("[fail] {what} ({code:#x})");
            superior_sys::park()
        }
    };
    if syscall(Syscall::NotificationBind, NOTIFY, [0; 4]).status != 0 {
        say!("[fail] binding the interrupt's notification");
    }
    let accept = CapTransfer {
        grant: None,
        accept: Some(LENT as u16),
    };
    let mut reply: Option<[u64; 4]> = None;
    loop {
        let r = match reply.take() {
            Some(m) => syscall_x(Syscall::ReplyRecv, SERVICE, m, accept),
            None => syscall_x(Syscall::Recv, SERVICE, [0; 4], accept),
        };
        if r.status == Error::Notified.code() {
            syscall(Syscall::IrqAck, MSI, [0; 4]);
            hc.poll();
            continue;
        }
        if r.status != 0 {
            continue;
        }
        let m = hc.serve(r.badge, r.msg, r.cap);
        if r.cap.is_some() {
            // The caller's page or notification copy goes before the reply.
            syscall(Syscall::CapDelete, LENT, [0; 4]);
        }
        reply = Some(m);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("panic: {info}");
    superior_sys::park()
}
