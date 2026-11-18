//! The TPM 2.0, for measured boot and a rollback counter.
//!
//! The kernel talks to it through the TIS interface (TCG's PC Client
//! Platform TPM Profile: a FIFO at locality 0), which QEMU's `tpm-tis` (x86,
//! at 0xFED40000) and `tpm-tis-device` (AArch64, found in the device tree)
//! both are. It sends a handful of commands, always with the empty
//! password session: `Startup`, `PCR_Extend` and `PCR_Read` (the boot
//! bundle's measurement goes into [`BUNDLE_PCR`]), and an NV counter
//! (`NV_DefineSpace`, `NV_Read`, `NV_Increment`) whose value is the oldest
//! bundle version the machine will boot again. A counter only goes up, and
//! the TPM keeps it whatever is written to the disk or the kernel's image:
//! a rollback floor that cannot be put back.
//!
//! Probed once (`get`); with no TPM it is `None` and the kernel's own
//! floor is the only one.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

/// The PCR the boot bundle is measured into (8 and 9 are for the OS
/// loader's measurements in TCG's PC Client profile).
pub const BUNDLE_PCR: u32 = 9;
/// The NV index of the rollback counter (owner-defined range).
pub const COUNTER_INDEX: u32 = 0x0180_0001;

const ACCESS: u64 = 0x00;
const STS: u64 = 0x18;
const FIFO: u64 = 0x24;
const DID_VID: u64 = 0xf00;

const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE: u8 = 0x20;
const ACCESS_REQUEST: u8 = 0x02;
const STS_VALID: u8 = 0x80;
const STS_READY: u8 = 0x40;
const STS_GO: u8 = 0x20;
const STS_DATA: u8 = 0x10;
const STS_EXPECT: u8 = 0x08;

/// How many register reads a wait may take before the TPM is given up on.
const PATIENCE: u64 = 50_000_000;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_STARTUP: u32 = 0x144;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_READ: u32 = 0x17e;
const CC_NV_DEFINE: u32 = 0x12a;
const CC_NV_INCREMENT: u32 = 0x134;
const CC_NV_READ: u32 = 0x14e;
const RH_OWNER: u32 = 0x4000_0001;
const RS_PW: u32 = 0x4000_0009;
const ALG_SHA256: u16 = 0x000b;

const RC_INITIALIZE: u32 = 0x100;
const RC_NV_UNINITIALIZED: u32 = 0x14a;

/// OWNERWRITE, AUTHWRITE, the counter type, OWNERREAD, AUTHREAD, NO_DA.
const COUNTER_ATTRIBUTES: u32 = 1 << 1 | 1 << 2 | 1 << 4 | 1 << 17 | 1 << 18 | 1 << 25;

/// The TPM's TIS registers, at a kernel address.
#[derive(Clone, Copy)]
pub struct Tpm {
    base: u64,
}

/// 0 not probed yet, 1 none, otherwise the registers' kernel address.
static BASE: AtomicU64 = AtomicU64::new(0);

/// The TPM, started, if the machine has one.
pub fn get() -> Option<Tpm> {
    match BASE.load(Ordering::SeqCst) {
        0 => {}
        1 => return None,
        base => return Some(Tpm { base }),
    }
    let tpm = crate::arch::tpm_base().map(|base| Tpm { base });
    let started = tpm.filter(|t| {
        let vid = t.r32(DID_VID);
        if t.r8(ACCESS) & ACCESS_VALID == 0 || vid == 0 || vid == u32::MAX {
            return false;
        }
        match t.startup() {
            Ok(()) => {
                crate::kprintln!("[ok] TPM 2.0 over TIS: vendor {:04x}, device {:04x}", vid & 0xffff, vid >> 16);
                true
            }
            Err(e) => {
                crate::kprintln!("[warn] TPM found but not started: {e}");
                false
            }
        }
    });
    BASE.store(started.map_or(1, |t| t.base), Ordering::SeqCst);
    started
}

/// A command being put together: big-endian fields after the 10-byte
/// header, whose size is filled in at the end.
struct Cmd {
    buf: [u8; 128],
    len: usize,
}

impl Cmd {
    fn new(tag: u16, code: u32) -> Self {
        let mut c = Cmd { buf: [0; 128], len: 0 };
        c.u16(tag).u32(0).u32(code);
        c
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        self
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    /// The empty password session: the authorization area of a command
    /// whose handle needs no secret.
    fn password(&mut self) -> &mut Self {
        self.u32(9).u32(RS_PW).u16(0).u8(0).u16(0)
    }
    fn done(&mut self) -> &[u8] {
        let len = (self.len as u32).to_be_bytes();
        self.buf[2..6].copy_from_slice(&len);
        &self.buf[..self.len]
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

impl Tpm {
    fn r8(&self, off: u64) -> u8 {
        // SAFETY: the TIS registers, mapped as device memory.
        unsafe { read_volatile((self.base + off) as *const u8) }
    }
    fn w8(&self, off: u64, v: u8) {
        // SAFETY: as for `r8`.
        unsafe { write_volatile((self.base + off) as *mut u8, v) }
    }
    fn r32(&self, off: u64) -> u32 {
        // SAFETY: as for `r8`.
        unsafe { read_volatile((self.base + off) as *const u32) }
    }
    fn burst(&self) -> usize {
        self.r8(STS + 1) as usize | (self.r8(STS + 2) as usize) << 8
    }
    fn wait(&self, what: &'static str, done: impl Fn(&Self) -> bool) -> Result<(), &'static str> {
        for _ in 0..PATIENCE {
            if done(self) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(what)
    }

    /// Sends `cmd` and reads the answer into `resp`: its response code
    /// and length.
    fn command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<(u32, usize), &'static str> {
        if self.r8(ACCESS) & ACCESS_ACTIVE == 0 {
            self.w8(ACCESS, ACCESS_REQUEST);
            self.wait("locality 0 not granted", |t| t.r8(ACCESS) & ACCESS_ACTIVE != 0)?;
        }
        self.w8(STS, STS_READY);
        self.wait("not ready for a command", |t| t.r8(STS) & STS_READY != 0)?;
        let mut sent = 0;
        while sent < cmd.len() {
            self.wait("no room in the FIFO", |t| t.burst() > 0)?;
            let n = self.burst().min(cmd.len() - sent);
            for &b in &cmd[sent..sent + n] {
                self.w8(FIFO, b);
            }
            sent += n;
        }
        self.wait("command not taken", |t| t.r8(STS) & STS_VALID != 0)?;
        if self.r8(STS) & STS_EXPECT != 0 {
            return Err("the TPM wanted more of the command");
        }
        self.w8(STS, STS_GO);
        let ready = |t: &Self| t.r8(STS) & (STS_VALID | STS_DATA) == STS_VALID | STS_DATA;
        self.wait("no answer", ready)?;
        let mut got = 0;
        let mut want = 10;
        while got < want {
            self.wait("answer cut short", ready)?;
            let n = self.burst().max(1).min(want - got);
            for _ in 0..n {
                let b = self.r8(FIFO);
                if got < resp.len() {
                    resp[got] = b;
                }
                got += 1;
            }
            if got >= 6 && want == 10 {
                want = (be32(&resp[2..6]) as usize).clamp(10, resp.len());
            }
        }
        self.w8(STS, STS_READY);
        Ok((be32(&resp[6..10]), got))
    }

    fn startup(&self) -> Result<(), &'static str> {
        let mut r = [0; 16];
        // SU_CLEAR. Firmware may have started it already.
        match self.command(Cmd::new(ST_NO_SESSIONS, CC_STARTUP).u16(0).done(), &mut r)? {
            (0 | RC_INITIALIZE, _) => Ok(()),
            _ => Err("TPM2_Startup refused"),
        }
    }

    /// Extends PCR `pcr`'s SHA-256 bank with `digest`.
    pub fn extend(&self, pcr: u32, digest: &[u8; 32]) -> Result<(), &'static str> {
        let mut c = Cmd::new(ST_SESSIONS, CC_PCR_EXTEND);
        c.u32(pcr).password().u32(1).u16(ALG_SHA256).bytes(digest);
        let mut r = [0; 32];
        match self.command(c.done(), &mut r)? {
            (0, _) => Ok(()),
            _ => Err("TPM2_PCR_Extend refused"),
        }
    }

    /// PCR `pcr`'s SHA-256 value.
    pub fn read_pcr(&self, pcr: u32) -> Result<[u8; 32], &'static str> {
        let mut select = [0u8; 3];
        select[(pcr / 8) as usize] = 1 << (pcr % 8);
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_PCR_READ);
        c.u32(1).u16(ALG_SHA256).u8(3).bytes(&select);
        let mut r = [0; 64];
        match self.command(c.done(), &mut r)? {
            // Header, update counter, the selection (10), one digest.
            (0, n) if n >= 62 && be32(&r[24..28]) == 1 => Ok(r[30..62].try_into().unwrap()),
            _ => Err("TPM2_PCR_Read refused"),
        }
    }

    /// The counter at `index`: `None` if it is not defined or was never
    /// incremented.
    pub fn counter(&self, index: u32) -> Result<Option<u64>, &'static str> {
        let mut c = Cmd::new(ST_SESSIONS, CC_NV_READ);
        c.u32(index).u32(index).password().u16(8).u16(0);
        let mut r = [0; 48];
        match self.command(c.done(), &mut r)? {
            (0, n) if n >= 24 => Ok(Some(u64::from_be_bytes(r[16..24].try_into().unwrap()))),
            (RC_NV_UNINITIALIZED, _) => Ok(None),
            // TPM_RC_HANDLE, for either handle: no such index.
            (rc, _) if rc & 0x80 != 0 && rc & 0x3f == 0x0b => Ok(None),
            _ => Err("TPM2_NV_Read refused"),
        }
    }

    /// Defines the counter at `index` (no secret needed to read or
    /// increment it; it can only go up).
    pub fn define_counter(&self, index: u32) -> Result<(), &'static str> {
        let mut c = Cmd::new(ST_SESSIONS, CC_NV_DEFINE);
        c.u32(RH_OWNER).password().u16(0);
        c.u16(14).u32(index).u16(ALG_SHA256).u32(COUNTER_ATTRIBUTES).u16(0).u16(8);
        let mut r = [0; 32];
        match self.command(c.done(), &mut r)? {
            // Defined already (TPM_RC_NV_DEFINED) is as good.
            (0 | 0x14c, _) => Ok(()),
            _ => Err("TPM2_NV_DefineSpace refused"),
        }
    }

    /// Adds one to the counter at `index`.
    pub fn increment(&self, index: u32) -> Result<(), &'static str> {
        let mut c = Cmd::new(ST_SESSIONS, CC_NV_INCREMENT);
        c.u32(index).u32(index).password();
        let mut r = [0; 32];
        match self.command(c.done(), &mut r)? {
            (0, _) => Ok(()),
            _ => Err("TPM2_NV_Increment refused"),
        }
    }

    /// Raises the counter at `index` to at least `floor` (defining it if
    /// need be); its value then.
    pub fn raise(&self, index: u32, floor: u64) -> Result<u64, &'static str> {
        if self.counter(index)?.is_none() {
            self.define_counter(index)?;
        }
        loop {
            match self.counter(index)? {
                Some(v) if v >= floor => return Ok(v),
                _ => self.increment(index)?,
            }
        }
    }
}
