//! A test service for supervision (spec section 4): a counter that keeps
//! its state outside itself, so it survives being restarted.
//!
//! Its value and a request journal live in the component's `state` page,
//! which the Component Manager makes once and hands to every instance. A
//! new instance picks up where the last one stopped.
//!
//! Adding is not idempotent, so each `ADD` carries a request id. The
//! journal keeps, per client (badge), the last request id applied and the
//! value it produced. A request seen again (the client retrying after
//! `PeerRestarted`) is answered from the journal instead of applied twice.
//!
//! Operations (message word 0):
//!
//! | op | words 1, 2 | reply |
//! | --- | --- | --- |
//! | `GET` = 1 | - | value, instances started so far |
//! | `ADD` = 2 | request id, amount | value, 1 if answered from the journal |
//! | `CRASH` = 3 | - | none: faults on receipt |
//! | `ADD_CRASH` = 4 | request id, amount | as `ADD`, but faults after applying and journaling it and before replying |
//!
//! Slot 0: the receive side of its service endpoint. Slot 1: the state
//! page.

#![no_std]
#![no_main]

use superior_objects::abi::Syscall;
use superior_sys::{USER_BASE, print_line, syscall};

const SERVICE: u64 = 0;
const STATE: u64 = 1;

const GET: u64 = 1;
const ADD: u64 = 2;
const CRASH: u64 = 3;
const ADD_CRASH: u64 = 4;

/// Where the state page is mapped.
const STATE_VA: u64 = USER_BASE + 0x4000_0000;
/// Nothing is mapped here: reading it faults.
const HOLE: u64 = USER_BASE + 0x5000_0000;

/// Word offsets in the state page.
const VALUE: usize = 0;
const STARTS: usize = 1;
const JOURNAL: usize = 8;
const CLIENTS: usize = 64;

struct State(*mut u64);

impl State {
    fn get(&self, i: usize) -> u64 {
        // SAFETY: the page is mapped at STATE_VA for this program's life,
        // and every index used is under 512.
        unsafe { self.0.add(i).read_volatile() }
    }
    fn set(&self, i: usize, v: u64) {
        // SAFETY: as in `get`.
        unsafe { self.0.add(i).write_volatile(v) }
    }
}

fn crash() -> ! {
    // SAFETY: deliberately not: this faults, and the manager restarts us.
    let v = unsafe { core::ptr::read_volatile(HOLE as *const u64) };
    print_line(format_args!("[fail] counter: read {v:#x} from a hole"));
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_: u64) -> ! {
    if syscall(Syscall::FrameMap, STATE, [STATE_VA, 1, 0, 0]).status != 0 {
        print_line(format_args!("[fail] counter: could not map its state page"));
        crash();
    }
    let s = State(STATE_VA as *mut u64);
    s.set(STARTS, s.get(STARTS) + 1);
    print_line(format_args!(
        "counter: instance {} starting, value {}",
        s.get(STARTS),
        s.get(VALUE)
    ));
    let mut r = syscall(Syscall::Recv, SERVICE, [0; 4]);
    loop {
        let client = r.badge as usize % CLIENTS;
        let (id_at, result_at) = (JOURNAL + 2 * client, JOURNAL + 2 * client + 1);
        let reply = match r.msg[0] {
            GET => [s.get(VALUE), s.get(STARTS), 0, 0],
            ADD | ADD_CRASH => {
                let (id, amount) = (r.msg[1], r.msg[2]);
                if id != 0 && s.get(id_at) == id {
                    [s.get(result_at), 1, 0, 0]
                } else {
                    // The journal entry is written last: until it is, the
                    // request has not happened. (A crash between the two
                    // stores is not among the faults this service is
                    // tested with.)
                    let value = s.get(VALUE).wrapping_add(amount);
                    s.set(VALUE, value);
                    s.set(result_at, value);
                    s.set(id_at, id);
                    if r.msg[0] == ADD_CRASH {
                        crash();
                    }
                    [value, 0, 0, 0]
                }
            }
            CRASH => crash(),
            _ => [u64::MAX - 1, 0, 0, 0],
        };
        r = syscall(Syscall::ReplyRecv, SERVICE, reply);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        syscall(Syscall::Yield, 0, [0; 4]);
    }
}
