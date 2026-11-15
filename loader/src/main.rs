//! Superior's AArch64 UEFI loader: a UEFI application (`BOOTAA64.EFI` on
//! the EFI system partition) that carries the kernel and starts it the way
//! QEMU's `-kernel` does, so the kernel needs nothing new.
//!
//! - The kernel's ELF segments go where they are linked (its physical
//!   address, 0x4020_0000 on QEMU's `virt`), in pages asked of the
//!   firmware at exactly that address.
//! - The device tree is the one the firmware publishes in its
//!   configuration table, copied to pages of the loader's own (the
//!   firmware's copy is in memory the kernel will reuse). Firmware that
//!   offers only ACPI (QEMU's `virt` unless `acpi=off`) is refused, for
//!   now: the kernel reads its devices from a device tree.
//! - Then boot services end, interrupts are masked, what the loader wrote
//!   is cleaned from the caches to memory, the MMU and caches go off, and
//!   the kernel is entered at EL1 with the device tree's address in x0.
//!
//! Firmware that runs at EL2 is refused, for now: the kernel runs at EL1
//! and expects to be entered there.
//!
//! No crates: the few UEFI calls it makes are declared here.

#![no_std]
#![no_main]

use core::ffi::c_void;

type Handle = *mut c_void;
type Status = usize;

const SUCCESS: Status = 0;
/// Errors have the top bit set: LOAD_ERROR (1) and the like.
const LOAD_ERROR: Status = 1 << 63 | 1;

/// The parts of the system table the loader reads.
#[repr(C)]
struct SystemTable {
    header: [u8; 24],
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    con_in: *mut c_void,
    console_out_handle: Handle,
    con_out: *mut TextOutput,
    standard_error_handle: Handle,
    std_err: *mut TextOutput,
    runtime_services: *mut c_void,
    boot_services: *mut BootServices,
    number_of_table_entries: usize,
    configuration_table: *const ConfigurationTable,
}

#[repr(C)]
struct TextOutput {
    reset: usize,
    output_string: extern "efiapi" fn(*mut TextOutput, *const u16) -> Status,
}

#[repr(C)]
struct ConfigurationTable {
    guid: [u8; 16],
    table: *const c_void,
}

/// The boot services, as far as ExitBootServices: those the loader calls
/// typed, the others as placeholders.
#[repr(C)]
struct BootServices {
    header: [u8; 24],
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    free_pages: usize,
    get_memory_map: extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    // AllocatePool .. UnloadImage.
    other: [usize; 21],
    exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
}

/// AllocatePages: any address, or below one, or exactly at one; pages
/// the loader owns (EfiLoaderData), free once boot services end.
const ALLOCATE_MAX_ADDRESS: u32 = 1;
const ALLOCATE_ADDRESS: u32 = 2;
const LOADER_DATA: u32 = 2;

/// Configuration table GUIDs, as UEFI lays them out in memory: the device
/// tree's (b1b621d5-f19c-41a5-830b-d9152c69aae0) and ACPI 2.0's
/// (8868e871-e4f1-11d3-bc22-0080c73c8881).
const DTB_GUID: [u8; 16] = guid(0xb1b6_21d5, 0xf19c, 0x41a5, [0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0]);
const ACPI_GUID: [u8; 16] = guid(0x8868_e871, 0xe4f1, 0x11d3, [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81]);

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let (a, b, c) = (a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes());
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]
}

/// The kernel only maps RAM in the second GiB: the device tree's copy
/// must lie below its end.
const KERNEL_RAM_END: u64 = 0x8000_0000;

static KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kernel.elf"));

/// The memory map ExitBootServices needs the key of.
const MAP_SIZE: usize = 64 * 1024;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

struct Console(*mut TextOutput);

impl Console {
    /// Writes `s` (ASCII), each newline as CR LF.
    fn say(&self, s: &str) {
        let mut buf = [0u16; 128];
        let mut n = 0;
        let flush = |buf: &mut [u16; 128], n: &mut usize| {
            buf[*n] = 0;
            // SAFETY: the firmware's console, while boot services last;
            // `buf` is NUL-terminated UCS-2.
            unsafe { ((*self.0).output_string)(self.0, buf.as_ptr()) };
            *n = 0;
        };
        for b in s.bytes() {
            if n + 3 >= buf.len() {
                flush(&mut buf, &mut n);
            }
            if b == b'\n' {
                buf[n] = b'\r' as u16;
                n += 1;
            }
            buf[n] = b as u16;
            n += 1;
        }
        flush(&mut buf, &mut n);
    }

    fn hex(&self, v: u64) {
        let mut s = [0u8; 18];
        s[0] = b'0';
        s[1] = b'x';
        for (i, c) in s[2..].iter_mut().enumerate() {
            let d = (v >> (60 - 4 * i)) & 0xf;
            *c = if d < 10 { b'0' + d as u8 } else { b'a' + d as u8 - 10 };
        }
        // Leading zeros dropped, one digit kept.
        let first = s[2..].iter().position(|&c| c != b'0').unwrap_or(15) + 2;
        self.say("0x");
        self.say(core::str::from_utf8(&s[first..]).unwrap_or("?"));
    }
}

fn u16_at(b: &[u8], at: usize) -> u64 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u64
}

fn u32_at(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as u64
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The kernel's loadable segments: each one's file offset, physical
/// address, bytes in the file and bytes in memory.
fn segments(elf: &[u8]) -> impl Iterator<Item = (usize, u64, u64, u64)> + '_ {
    let ok = elf.len() >= 64 && elf[..4] == *b"\x7fELF" && elf[4] == 2 && u16_at(elf, 18) == 183;
    let (phoff, phentsize, phnum) = if ok { (u64_at(elf, 32) as usize, u16_at(elf, 54) as usize, u16_at(elf, 56) as usize) } else { (0, 56, 0) };
    (0..phnum).filter_map(move |i| {
        let p = phoff + i * phentsize;
        (p + 56 <= elf.len() && u32_at(elf, p) == 1)
            .then(|| (u64_at(elf, p + 8) as usize, u64_at(elf, p + 24), u64_at(elf, p + 32), u64_at(elf, p + 40)))
    })
}

/// Cleans and invalidates `[start, end)` to the point of coherency, so it
/// is in memory once the caches are off.
fn clean(start: u64, end: u64) {
    let ctr: u64;
    // SAFETY: reads the cache type register.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr) };
    let line = 4u64 << ((ctr >> 16) & 0xf);
    let mut a = start & !(line - 1);
    while a < end {
        // SAFETY: cache maintenance by address on memory the loader owns.
        unsafe { core::arch::asm!("dc civac, {}", in(reg) a) };
        a += line;
    }
    // SAFETY: a barrier.
    unsafe { core::arch::asm!("dsb sy") };
}

#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(image: Handle, st: *const SystemTable) -> Status {
    // SAFETY: the firmware hands over a valid system table.
    let st = unsafe { &*st };
    let con = Console(st.con_out);
    // SAFETY: as above.
    let bs = unsafe { &*st.boot_services };
    con.say("Superior UEFI loader (AArch64)\n");

    let el: u64;
    // SAFETY: reads the current exception level.
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    if (el >> 2) & 3 != 1 {
        con.say("loader: the firmware runs at EL2; the kernel must be entered at EL1, which this loader cannot do yet\n");
        return LOAD_ERROR;
    }

    // SAFETY: the firmware's configuration table, `number_of_table_entries`
    // long.
    let tables = unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) };
    let acpi = tables.iter().any(|t| t.guid == ACPI_GUID);
    let Some(dtb) = tables.iter().find(|t| t.guid == DTB_GUID).map(|t| t.table as u64) else {
        con.say(if acpi {
            "loader: the firmware offers ACPI and no device tree (QEMU: -machine virt,acpi=off); the kernel needs a device tree for now\n"
        } else {
            "loader: the firmware offers no device tree\n"
        });
        return LOAD_ERROR;
    };
    // SAFETY: the firmware's device tree: its header first.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, 8) };
    let dtb_size = u32::from_be_bytes(header[4..8].try_into().unwrap()) as u64;
    if header[..4] != [0xd0, 0x0d, 0xfe, 0xed] || dtb_size < 40 {
        con.say("loader: the firmware's device tree is not one\n");
        return LOAD_ERROR;
    }

    // The kernel: one block of pages from its lowest segment to its
    // highest end, at exactly that address.
    let (lo, hi) = segments(KERNEL).fold((u64::MAX, 0), |(lo, hi), (_, pa, _, mem)| (lo.min(pa), hi.max(pa + mem)));
    if lo >= hi {
        con.say("loader: no kernel in this loader\n");
        return LOAD_ERROR;
    }
    let (lo, hi) = (lo & !0xfff, (hi + 0xfff) & !0xfff);
    let mut at = lo;
    if (bs.allocate_pages)(ALLOCATE_ADDRESS, LOADER_DATA, ((hi - lo) / 4096) as usize, &mut at) != SUCCESS {
        con.say("loader: the firmware will not give up the kernel's place, ");
        con.hex(lo);
        con.say("\n");
        return LOAD_ERROR;
    }
    // SAFETY: the pages just allocated, `hi - lo` bytes.
    let place = unsafe { core::slice::from_raw_parts_mut(lo as *mut u8, (hi - lo) as usize) };
    place.fill(0);
    for (off, pa, file, _) in segments(KERNEL) {
        let at = (pa - lo) as usize;
        place[at..at + file as usize].copy_from_slice(&KERNEL[off..off + file as usize]);
    }
    let entry = u64_at(KERNEL, 24);

    // The device tree, copied below where the kernel maps RAM to.
    let mut copy = KERNEL_RAM_END - 1;
    let pages = dtb_size.div_ceil(4096) as usize;
    if (bs.allocate_pages)(ALLOCATE_MAX_ADDRESS, LOADER_DATA, pages, &mut copy) != SUCCESS {
        con.say("loader: no memory for the device tree\n");
        return LOAD_ERROR;
    }
    // SAFETY: the firmware's device tree, `dtb_size` bytes, into pages of
    // the loader's own that big.
    unsafe { core::ptr::copy_nonoverlapping(dtb as *const u8, copy as *mut u8, dtb_size as usize) };

    con.say("loader: kernel at ");
    con.hex(lo);
    con.say(" to ");
    con.hex(hi);
    con.say(", entry ");
    con.hex(entry);
    con.say("; device tree (");
    con.hex(dtb_size);
    con.say(" bytes) at ");
    con.hex(copy);
    con.say(if acpi { "; ACPI tables offered too, unused\n" } else { "\n" });
    con.say("loader: leaving boot services\n");

    // Boot services end with the key of the memory map as it is: a map
    // that changed meanwhile (the call itself can change it) is read again.
    let mut tries = 0;
    loop {
        let (mut size, mut key, mut desc_size, mut version) = (MAP_SIZE, 0, 0, 0);
        // SAFETY: the loader's map buffer, `size` bytes.
        let got = (bs.get_memory_map)(&mut size, core::ptr::addr_of_mut!(MAP) as *mut u8, &mut key, &mut desc_size, &mut version);
        if got == SUCCESS && (bs.exit_boot_services)(image, key) == SUCCESS {
            break;
        }
        tries += 1;
        if tries == 3 {
            // Boot services may be half gone: nothing more can be said.
            loop {
                // SAFETY: waits forever.
                unsafe { core::arch::asm!("wfe") };
            }
        }
    }
    // SAFETY: interrupts masked; the firmware's handlers are gone.
    unsafe { core::arch::asm!("msr daifset, #0xf") };
    clean(lo, hi);
    clean(copy, copy + dtb_size);
    // SAFETY: the kernel is in place and in memory: the MMU and caches go
    // off (the firmware's identity map means this code goes on where it
    // is), the instruction cache and TLBs are emptied, and the kernel is
    // entered as QEMU enters it.
    unsafe {
        core::arch::asm!(
            "mrs x2, sctlr_el1",
            "bic x2, x2, #1",       // M: the MMU
            "bic x2, x2, #4",       // C: data caches
            "bic x2, x2, #0x1000",  // I: instruction caches
            "msr sctlr_el1, x2",
            "isb",
            "ic iallu",
            "tlbi vmalle1",
            "dsb sy",
            "isb",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "br x4",
            in("x4") entry,
            in("x0") copy,
            options(noreturn),
        )
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        // SAFETY: waits forever.
        unsafe { core::arch::asm!("wfe") };
    }
}
