//! The DbC against a simulated controller: it reads the context and
//! rings from the pages as a controller would, takes the OUT ring's TRBs
//! when the doorbell rings, collects their bytes as the debug host would
//! receive them, and writes transfer events back.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::boxed::Box;
use std::string::String;
use std::vec;
use std::vec::Vec;

/// Two pages, at made-up bus addresses.
struct Memory {
    pages: Vec<(u64, Box<[u8; PAGE]>)>,
}

impl Memory {
    fn new() -> Memory {
        Memory { pages: vec![(0x1_0000_0000, Box::new([0; PAGE])), (0x2000_0000, Box::new([0; PAGE]))] }
    }
    fn page(&mut self, i: usize) -> Page {
        let (pa, p) = &mut self.pages[i];
        Page { va: p.as_mut_ptr(), pa: *pa }
    }
    fn at(&self, pa: u64) -> *mut u8 {
        for (base, p) in &self.pages {
            if (*base..*base + PAGE as u64).contains(&pa) {
                return unsafe { (p.as_ptr() as *mut u8).add((pa - base) as usize) };
            }
        }
        panic!("the controller reached {pa:#x}, outside the DbC's pages");
    }
    fn r32(&self, pa: u64) -> u32 {
        unsafe { u32::from_le((self.at(pa) as *const u32).read_unaligned()) }
    }
    fn r64(&self, pa: u64) -> u64 {
        self.r32(pa) as u64 | (self.r32(pa + 4) as u64) << 32
    }
    fn w32(&self, pa: u64, v: u32) {
        unsafe { (self.at(pa) as *mut u32).write_unaligned(v.to_le()) }
    }
}

#[derive(Default)]
struct Controller {
    regs: HashMap<u64, u32>,
    /// The OUT ring as the controller walks it.
    out_deq: u64,
    out_cycle: bool,
    /// The event ring as the controller fills it.
    events: (u64, usize),
    event_at: usize,
    event_cycle: bool,
    received: Vec<u8>,
    transfers: usize,
    links: usize,
    /// Doorbells rung while the DbC was not running.
    stray_doorbells: usize,
}

#[derive(Clone)]
struct Sim(Rc<RefCell<Controller>>, Rc<RefCell<Memory>>);

impl Sim {
    fn reg(&self, off: u64) -> u32 {
        *self.0.borrow().regs.get(&off).unwrap_or(&0)
    }
    fn set(&self, off: u64, v: u32) {
        self.0.borrow_mut().regs.insert(off, v);
    }
    /// A debug host plugs in and configures the device.
    fn connect(&self) {
        self.set(reg::DCPORTSC, reg::CCS | 1 << 17);
        let c = self.reg(reg::DCCTRL);
        self.set(reg::DCCTRL, c | reg::RUN | reg::RUN_CHANGE);
        self.event(0, trb::PORT_STATUS_CHANGE, 0);
    }
    fn unplug(&self) {
        self.set(reg::DCPORTSC, 1 << 17);
        let c = self.reg(reg::DCCTRL);
        self.set(reg::DCCTRL, c & !reg::RUN | reg::RUN_CHANGE);
    }
    fn event(&self, param: u64, kind: u32, status: u32) {
        let mem = self.1.borrow();
        let mut c = self.0.borrow_mut();
        let (base, n) = c.events;
        assert!(n > 0, "an event before the event ring was set up");
        // The ring is full if the next slot is the one the DbC dequeues
        // from (as DCERDP says).
        let deq = (c.regs.get(&reg::DCERDP).copied().unwrap_or(0) as u64
            | (c.regs.get(&(reg::DCERDP + 4)).copied().unwrap_or(0) as u64) << 32)
            .wrapping_sub(base)
            / 16;
        assert_ne!((c.event_at + 1) % n, deq as usize, "the DbC let its event ring fill up");
        let slot = base + 16 * c.event_at as u64;
        mem.w32(slot, param as u32);
        mem.w32(slot + 4, (param >> 32) as u32);
        mem.w32(slot + 8, status);
        mem.w32(slot + 12, kind << 10 | c.event_cycle as u32);
        c.event_at += 1;
        if c.event_at == n {
            c.event_at = 0;
            c.event_cycle = !c.event_cycle;
        }
    }
    /// Takes the OUT ring's TRBs the DbC has handed over.
    fn doorbell(&self) {
        if self.reg(reg::DCCTRL) & reg::RUN == 0 {
            self.0.borrow_mut().stray_doorbells += 1;
            return;
        }
        loop {
            let (deq, cycle) = {
                let c = self.0.borrow();
                (c.out_deq, c.out_cycle)
            };
            let mem = self.1.borrow();
            let control = mem.r32(deq + 12);
            if (control & 1 != 0) != cycle {
                return;
            }
            let param = mem.r64(deq);
            match (control >> 10) & 0x3f {
                trb::LINK => {
                    let mut c = self.0.borrow_mut();
                    c.out_deq = param;
                    c.links += 1;
                    if control & trb::TOGGLE != 0 {
                        c.out_cycle = !c.out_cycle;
                    }
                }
                trb::NORMAL => {
                    let len = mem.r32(deq + 8) & 0x1_ffff;
                    let bytes: Vec<u8> = (0..len as u64).map(|i| unsafe { *mem.at(param + i) }).collect();
                    assert!(control & trb::IOC != 0, "a transfer that would raise no event");
                    drop(mem);
                    {
                        let mut c = self.0.borrow_mut();
                        c.received.extend(bytes);
                        c.transfers += 1;
                        c.out_deq += 16;
                    }
                    // Success (1), no residue.
                    self.event(deq, trb::TRANSFER_EVENT, 1 << 24);
                }
                t => panic!("TRB type {t} on the OUT ring"),
            }
        }
    }
}

impl Regs for Sim {
    fn read32(&self, off: u64) -> u32 {
        self.reg(off)
    }
    fn write32(&self, off: u64, v: u32) {
        match off {
            reg::DCCTRL => {
                let old = self.reg(off);
                // Run and Run Change are the controller's; Run Change is
                // written 1 to clear. Max burst (23:16) is read-only.
                let keep = old & (reg::RUN | reg::HALT_OUT | 0x00ff_0000);
                let change = if v & reg::RUN_CHANGE != 0 { 0 } else { old & reg::RUN_CHANGE };
                self.set(off, v & (reg::ENABLE | reg::LSE) | keep | change);
                if v & reg::ENABLE != 0 && old & reg::ENABLE == 0 {
                    self.enabled();
                }
            }
            reg::DCPORTSC => {
                let old = self.reg(off);
                self.set(off, old & !(v & reg::CHANGES));
            }
            reg::DCDB => self.doorbell(),
            _ => self.set(off, v),
        }
    }
}

impl Sim {
    /// DbC Enable set: the controller reads what it was given.
    fn enabled(&self) {
        let r64 = |o: u64| self.reg(o) as u64 | (self.reg(o + 4) as u64) << 32;
        let mem = self.1.borrow();
        assert_eq!(self.reg(reg::DCERSTSZ), 1);
        let erst = r64(reg::DCERSTBA);
        let (events, size) = (mem.r64(erst), mem.r32(erst + 8) as usize);
        assert_eq!(r64(reg::DCERDP), events, "the dequeue pointer starts at the ring");
        let ctx = r64(reg::DCCP);
        let out = mem.r64(ctx + 0x48);
        assert_eq!(out & 1, 1, "the OUT ring starts with cycle 1");
        let mut c = self.0.borrow_mut();
        c.events = (events, size);
        c.event_cycle = true;
        c.out_deq = out & !0xf;
        c.out_cycle = true;
        c.regs.insert(reg::DCST, 3 << 24);
    }
}

fn setup() -> (Sim, Dbc<Sim>) {
    let mut mem = Memory::new();
    let (page, data) = (mem.page(0), mem.page(1));
    let sim = Sim(Rc::new(RefCell::new(Controller::default())), Rc::new(RefCell::new(mem)));
    // Max burst 2, as some controllers say.
    sim.set(reg::DCCTRL, 2 << 16);
    let dbc = Dbc::new(sim.clone(), page, data);
    (sim, dbc)
}

/// Drives the DbC until all of `bytes` has gone out, as the kernel does:
/// poll, send what fits.
fn pump(dbc: &mut Dbc<Sim>, mut bytes: &[u8]) {
    let mut rounds = 0;
    while !bytes.is_empty() {
        dbc.poll();
        let n = dbc.send(bytes);
        bytes = &bytes[n..];
        rounds += 1;
        assert!(rounds < 10_000, "the DbC stopped taking bytes");
    }
    dbc.poll();
}

#[test]
fn walks_the_extended_capabilities() {
    // HCCPARAMS1's xECP: 0x500 / 4. Legacy support there, then (next 8
    // dwords on) a protocol capability, then the DbC, the last.
    let mut regs = HashMap::new();
    regs.insert(0x10u64, (0x500 / 4) << 16);
    regs.insert(0x500, 8 << 8 | CAP_LEGACY);
    regs.insert(0x520, 4 << 8 | 2);
    regs.insert(0x530, CAP_DBC);
    let caps: Vec<_> = capabilities(|o| *regs.get(&o).unwrap_or(&0), 0x1000).collect();
    assert_eq!(caps, [(0x500, CAP_LEGACY), (0x520, 2), (0x530, CAP_DBC)]);
    // None at all; and a list that runs off the registers stops there.
    assert_eq!(capabilities(|_| 0, 0x1000).count(), 0);
    regs.insert(0x530, 0x40 << 8 | CAP_DBC);
    assert_eq!(capabilities(|o| *regs.get(&o).unwrap_or(&0), 0x600).count(), 3);
}

#[test]
fn takes_the_controller_from_the_firmware() {
    let regs = RefCell::new(HashMap::from([(0x500u64, 1u32 << 16 | CAP_LEGACY), (0x504, 0xe000_0011)]));
    let reads = RefCell::new(0);
    let read = |o: u64| {
        let mut r = regs.borrow_mut();
        if o == 0x500 {
            *reads.borrow_mut() += 1;
            // The firmware lets go on the third look once asked.
            if *reads.borrow() == 3 && r[&0x500] & 1 << 24 != 0 {
                *r.get_mut(&0x500).unwrap() &= !(1 << 16);
            }
        }
        *r.get(&o).unwrap_or(&0)
    };
    let write = |o: u64, v: u32| {
        regs.borrow_mut().insert(o, v);
    };
    assert!(take_from_firmware(read, write, Some(0x500), 10));
    let r = regs.borrow();
    assert_eq!(r[&0x500] & (1 << 24 | 1 << 16), 1 << 24, "the OS owns it, the firmware does not");
    assert_eq!(r[&0x504] & 0x1f, 0, "the firmware's SMIs are off");
    drop(r);
    // A firmware that never lets go.
    let stuck = RefCell::new(1u32 << 16);
    assert!(!take_from_firmware(|_| *stuck.borrow(), |_, v| *stuck.borrow_mut() = v | 1 << 16, Some(0x500), 10));
    assert!(take_from_firmware(|_| 0, |_, _| {}, None, 10), "no legacy support: nothing to take");
}

#[test]
fn lays_out_what_the_debug_host_sees() {
    let (sim, dbc) = setup();
    assert_eq!(sim.reg(reg::DCDDI1), 0x1d6b_0001);
    assert_eq!(sim.reg(reg::DCDDI2), 0x0010);
    assert_eq!(sim.reg(reg::DCCTRL) & reg::ENABLE, reg::ENABLE);
    assert_eq!(dbc.port(), 3);
    assert_eq!(dbc.state, State::Waiting);
    let mem = sim.1.borrow();
    let ctx = sim.reg(reg::DCCP) as u64 | (sim.reg(reg::DCCP + 4) as u64) << 32;
    // The strings, as a USB host would read them.
    let lengths = mem.r32(ctx + 32);
    let string = |i: u64| -> String {
        let at = mem.r64(ctx + 8 * i);
        let len = unsafe { *mem.at(at) } as u64;
        assert_eq!(len, (lengths >> (8 * i)) as u64 & 0xff, "string {i}'s length");
        assert_eq!(unsafe { *mem.at(at + 1) }, 3, "a string descriptor");
        let units: Vec<u16> = (0..(len - 2) / 2).map(|k| mem.r32(at + 2 + 2 * k) as u16).collect();
        String::from_utf16(&units).unwrap()
    };
    assert_eq!(string(0), "\u{0409}");
    assert_eq!(string(1), "Superior");
    assert_eq!(string(2), "Superior kernel log");
    assert_eq!(string(3), "0");
    // Bulk OUT, then bulk IN: 1024-byte packets, burst 2, three retries.
    for (ep, kind) in [(0x40, 2), (0x80, 6)] {
        let info2 = mem.r32(ctx + ep + 4);
        assert_eq!(info2 >> 3 & 7, kind, "endpoint type");
        assert_eq!(info2 >> 16, 1024, "max packet size");
        assert_eq!(info2 >> 8 & 0xff, 2, "max burst");
        assert_eq!(info2 >> 1 & 3, 3, "error count");
        // Each ring ends in a link back to its start.
        let ring = mem.r64(ctx + ep + 8) & !0xf;
        let link = ring + 16 * (RING_TRBS as u64 - 1);
        assert_eq!(mem.r64(link), ring);
        assert_eq!(mem.r32(link + 12) >> 10 & 0x3f, trb::LINK);
    }
}

#[test]
fn sends_nothing_until_a_debug_host_configures_it() {
    let (sim, mut dbc) = setup();
    assert_eq!(dbc.poll(), State::Waiting);
    assert_eq!(dbc.send(b"early"), 0);
    assert_eq!(sim.0.borrow().stray_doorbells, 0);
    sim.connect();
    assert_eq!(dbc.poll(), State::Running);
    // The change bits were cleared, and the port event taken.
    assert_eq!(sim.reg(reg::DCCTRL) & reg::RUN_CHANGE, 0);
    assert_eq!(sim.reg(reg::DCPORTSC) & reg::CHANGES, 0);
    pump(&mut dbc, b"early");
    assert_eq!(sim.0.borrow().received, b"early");
    assert_eq!(dbc.sent, 5);
}

#[test]
fn a_long_log_goes_out_whole_round_both_rings() {
    let (sim, mut dbc) = setup();
    sim.connect();
    // Lines of every length, and some longer than the data page.
    let mut log = Vec::new();
    for i in 0..200u32 {
        let line = std::format!("[{i:3}] {}\n", "x".repeat((i as usize * 37) % 300));
        log.extend(line.bytes());
        if i % 50 == 49 {
            log.extend(std::iter::repeat_n(b'#', PAGE + 123));
        }
    }
    for chunk in log.chunks(97) {
        pump(&mut dbc, chunk);
    }
    let c = sim.0.borrow();
    assert_eq!(c.received, log, "the debug host received the log, in order, whole");
    assert!(c.transfers > 2 * RING_TRBS, "the OUT ring went round");
    assert!(c.links >= 2, "through its link, more than once");
    assert!(c.transfers > 2 * EVENT_TRBS, "the event ring went round");
    assert_eq!(dbc.sent, log.len() as u64);
}

#[test]
fn unplugging_drops_what_was_in_flight_and_waits_again() {
    let (sim, mut dbc) = setup();
    sim.connect();
    dbc.poll();
    // The controller sees the doorbell only once running: unplug first,
    // so the transfer never finishes.
    sim.unplug();
    assert_eq!(dbc.send(b"lost"), 4, "taken: the DbC had not looked yet");
    assert!(dbc.busy());
    assert_eq!(dbc.poll(), State::Waiting);
    assert!(!dbc.busy(), "nothing in flight once unplugged");
    assert_eq!(dbc.send(b"held"), 0);
    sim.connect();
    // The controller's ring position: the unplug lost a TRB the DbC
    // handed over, so a reconnected host restarts the ring in practice;
    // here the TRB is still there and is taken with the next.
    pump(&mut dbc, b"again");
    assert!(sim.0.borrow().received.ends_with(b"again"));
}

#[test]
fn a_halted_endpoint_stops_the_log() {
    let (sim, mut dbc) = setup();
    sim.connect();
    let c = sim.reg(reg::DCCTRL);
    sim.set(reg::DCCTRL, c | reg::HALT_OUT);
    assert_eq!(dbc.poll(), State::Halted);
    assert_eq!(dbc.send(b"x"), 0);
    dbc.disable();
    assert_eq!(sim.reg(reg::DCCTRL) & reg::ENABLE, 0);
    assert_eq!(dbc.poll(), State::Off);
}
