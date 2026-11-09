//! The Superior Driver SDK (spec section 5).
//!
//! A driver is an ordinary component. It holds a capability to the PCI bus
//! server (`uses pci`), and through it gets exactly one device: that
//! function's BAR pages (device frames) and MSI vectors. It never touches
//! configuration space itself. This crate wraps that, plus what every
//! driver needs next:
//!
//! - [`Pci`]: open a function, map its BAR pages, enable bus mastering and
//!   MSI-X, take an MSI vector bound to a notification.
//! - [`Mmio`]: volatile register access through a mapping.
//! - [`DmaPage`], [`io_map`]: pages of RAM mapped into the device's IOMMU
//!   domain, the only memory it can reach, with the address to program
//!   into it.
//! - [`virtq`]: split virtqueue rings (virtio 1.x).
//!
//! Still to come, per the spec: an async executor, DMA buffer pools and
//! power-state callbacks.

#![no_std]

pub mod virtq;

use superior_objects::abi::{CapTransfer, ObjectType, Syscall};
use superior_objects::interfaces::{Status, pci};
use superior_sys::{Ret, syscall, syscall_x};

/// A failed step: what, and the status or kernel error code.
pub type Failure = (&'static str, u64);

fn sys(nr: Syscall, a0: u64, m: [u64; 4]) -> Result<Ret, u64> {
    let r = syscall(nr, a0, m);
    if r.status == 0 { Ok(r) } else { Err(r.status) }
}

/// Maps the frame in `slot` at `va` in the caller's own address space.
pub fn map(slot: u64, va: u64, writable: bool) -> Result<(), u64> {
    sys(Syscall::FrameMap, slot, [va, writable as u64, 0, 0]).map(drop)
}

/// The PCI bus server, through the endpoint in `slot`.
pub struct Pci {
    pub slot: u64,
}

impl Pci {
    fn call(&self, msg: [u64; 4], accept: Option<u64>) -> Result<Ret, Failure> {
        let x = CapTransfer {
            grant: None,
            accept: accept.map(|s| s as u16),
        };
        let r = syscall_x(Syscall::Call, self.slot, msg, x);
        if r.status != 0 {
            return Err(("calling the PCI bus server", r.status));
        }
        match Status::from_u64(r.msg[0]) {
            Status::Ok => Ok(r),
            s => Err(("the PCI bus server refused", s as u64)),
        }
    }

    /// Claims the `instance`th function with these IDs (and resets it).
    /// Its IOMMU domain, empty, arrives in `domain`. Returns its
    /// bus/device/function and the bitmask of memory BARs.
    pub fn open(
        &self,
        vendor: u16,
        device: u16,
        instance: u64,
        domain: u64,
    ) -> Result<(u64, u64), Failure> {
        let ids = (vendor as u64) << 16 | device as u64;
        self.open_with(pci::OPEN, ids, instance, domain)
    }

    /// As [`Pci::open`], for the `instance`th function of a class
    /// (`class << 16 | subclass << 8 | interface`), whoever made it.
    pub fn open_class(
        &self,
        class: u32,
        instance: u64,
        domain: u64,
    ) -> Result<(u64, u64), Failure> {
        self.open_with(pci::OPEN_CLASS, class as u64, instance, domain)
    }

    fn open_with(
        &self,
        op: u64,
        what: u64,
        instance: u64,
        domain: u64,
    ) -> Result<(u64, u64), Failure> {
        let r = self.call([op, pci::VERSION, what, instance], Some(domain))?;
        if r.cap != Some(domain as u16) {
            return Err(("no IOMMU domain arrived (no IOMMU?)", 0));
        }
        Ok((r.msg[1], r.msg[2]))
    }

    /// A dword of the function's configuration space.
    pub fn config_read(&self, offset: u64) -> Result<u32, Failure> {
        let r = self.call([pci::CONFIG_READ, offset, 0, 0], None)?;
        Ok(r.msg[1] as u32)
    }

    /// A byte of the function's configuration space.
    pub fn config_read8(&self, offset: u64) -> Result<u8, Failure> {
        Ok((self.config_read(offset & !3)? >> (8 * (offset & 3))) as u8)
    }

    /// Takes page `page` of BAR `bar` into `slot` and maps it at `va`.
    /// Returns the BAR's size.
    pub fn map_bar_page(&self, bar: u64, page: u64, slot: u64, va: u64) -> Result<u64, Failure> {
        let r = self.call([pci::BAR_PAGE, bar, page, 0], Some(slot))?;
        if r.cap != Some(slot as u16) {
            return Err(("no BAR page arrived", 0));
        }
        map(slot, va, true).map_err(|e| ("mapping a BAR page", e))?;
        Ok(r.msg[1])
    }

    pub fn bus_master(&self, on: bool) -> Result<(), Failure> {
        self.call([pci::BUS_MASTER, on as u64, 0, 0], None)
            .map(drop)
    }

    pub fn msix(&self, on: bool) -> Result<(), Failure> {
        self.call([pci::MSIX, on as u64, 0, 0], None).map(drop)
    }

    /// For a function with plain MSI: has the bus server program vector 0
    /// (take it first with [`Pci::msi_vector`]) and enable it.
    pub fn msi(&self, on: bool) -> Result<(), Failure> {
        self.call([pci::MSI, on as u64, 0, 0], None).map(drop)
    }

    /// Takes MSI vector `n` into `slot`, binds it to the notification in
    /// `notification`, and returns the message the device must write to
    /// raise it: (address, data).
    pub fn msi_vector(&self, n: u64, slot: u64, notification: u64) -> Result<(u64, u64), Failure> {
        let r = self.call([pci::MSI_VECTOR, n, 0, 0], Some(slot))?;
        if r.cap != Some(slot as u16) {
            return Err(("no MSI vector arrived", 0));
        }
        let m = sys(Syscall::IrqMsiMessage, slot, [0; 4]).map_err(|e| ("MSI message", e))?;
        sys(Syscall::IrqSetNotification, slot, [notification, 0, 0, 0])
            .map_err(|e| ("binding the MSI vector", e))?;
        Ok((m.msg[0], m.msg[1]))
    }

    /// Walks the function's capability list for capability `id`, starting
    /// after `from` (0 to start at the head). Returns its offset.
    pub fn find_capability(&self, id: u8, from: u64) -> Result<Option<u64>, Failure> {
        let mut at = if from == 0 {
            if self.config_read(0x04)? >> 16 & 0x10 == 0 {
                return Ok(None); // no capability list
            }
            self.config_read8(0x34)? as u64 & !3
        } else {
            self.config_read8(from + 1)? as u64 & !3
        };
        let mut steps = 0;
        while at != 0 && steps < 48 {
            if self.config_read8(at)? == id {
                return Ok(Some(at));
            }
            at = self.config_read8(at + 1)? as u64 & !3;
            steps += 1;
        }
        Ok(None)
    }
}

/// Registers mapped at `base`.
#[derive(Clone, Copy)]
pub struct Mmio {
    pub base: u64,
}

impl Mmio {
    pub fn read8(&self, off: u64) -> u8 {
        // SAFETY: the driver mapped device registers at `base`; the caller
        // keeps `off` inside the mapping.
        unsafe { ((self.base + off) as *const u8).read_volatile() }
    }
    pub fn read16(&self, off: u64) -> u16 {
        // SAFETY: as in `read8`.
        unsafe { ((self.base + off) as *const u16).read_volatile() }
    }
    pub fn read32(&self, off: u64) -> u32 {
        // SAFETY: as in `read8`.
        unsafe { ((self.base + off) as *const u32).read_volatile() }
    }
    /// Two 32-bit reads, low first (64-bit device registers need not
    /// support 64-bit accesses).
    pub fn read64(&self, off: u64) -> u64 {
        self.read32(off) as u64 | (self.read32(off + 4) as u64) << 32
    }
    pub fn write8(&self, off: u64, v: u8) {
        // SAFETY: as in `read8`.
        unsafe { ((self.base + off) as *mut u8).write_volatile(v) }
    }
    pub fn write16(&self, off: u64, v: u16) {
        // SAFETY: as in `read8`.
        unsafe { ((self.base + off) as *mut u16).write_volatile(v) }
    }
    pub fn write32(&self, off: u64, v: u32) {
        // SAFETY: as in `read8`.
        unsafe { ((self.base + off) as *mut u32).write_volatile(v) }
    }
    pub fn write64(&self, off: u64, v: u64) {
        self.write32(off, v as u32);
        self.write32(off + 4, (v >> 32) as u32);
    }
}

/// A page of RAM for DMA: mapped at `va` for the driver, and into the
/// device's domain at `dma`.
#[derive(Clone, Copy)]
pub struct DmaPage {
    pub va: u64,
    pub dma: u64,
}

impl DmaPage {
    /// Makes a frame from the untyped memory in `untyped` into `slot`, maps
    /// it at `va` and into the IOMMU domain in `domain`.
    pub fn new(untyped: u64, slot: u64, va: u64, domain: u64) -> Result<DmaPage, Failure> {
        sys(
            Syscall::Retype,
            untyped,
            [ObjectType::Frame as u64, 0, slot, 0],
        )
        .map_err(|e| ("no memory for a DMA page", e))?;
        map(slot, va, true).map_err(|e| ("mapping a DMA page", e))?;
        Ok(DmaPage {
            va,
            dma: io_map(slot, domain, true)?,
        })
    }
}

/// Maps the frame in `slot` into the IOMMU domain in `domain` (writable by
/// the device if `writable`), returning the address the device uses for
/// it. It stays reachable until unmapped ([`io_unmap`]) or until the
/// capability is deleted.
pub fn io_map(slot: u64, domain: u64, writable: bool) -> Result<u64, Failure> {
    sys(Syscall::IoMap, slot, [domain, writable as u64, 0, 0])
        .map(|r| r.msg[0])
        .map_err(|e| ("mapping a page for DMA", e))
}

/// Takes the frame in `slot` back out of its IOMMU domain.
pub fn io_unmap(slot: u64) -> Result<(), Failure> {
    sys(Syscall::IoUnmap, slot, [0; 4])
        .map(drop)
        .map_err(|e| ("unmapping a page from DMA", e))
}

/// The DMA requests the IOMMU blocked for the function bound to `domain`
/// since the last call: how many, and the first one's page address and
/// whether it was a write.
pub fn io_faults(domain: u64) -> Result<(u64, u64, bool), Failure> {
    sys(Syscall::IoFaults, domain, [0; 4])
        .map(|r| (r.msg[0], r.msg[1], r.msg[2] != 0))
        .map_err(|e| ("reading IOMMU faults", e))
}

/// How a test describes the IOMMU's report of a stray DMA write aimed at
/// `page`: whether it was reported, and a phrase saying so.
pub fn stray_reported(domain: u64, page: u64) -> (bool, &'static str) {
    match io_faults(domain) {
        Ok((n, at, true)) if n > 0 && at == page => (true, "the IOMMU reported a blocked write to it"),
        Ok((0, _, _)) => (false, "the IOMMU reported NOTHING"),
        Ok(_) => (false, "the IOMMU reported some OTHER fault"),
        Err(_) => (false, "reading the IOMMU's faults FAILED"),
    }
}

/// The physical address of the frame in `slot` (with an IOMMU, a device
/// reaches it only once it is mapped into the device's domain).
pub fn dma_address(slot: u64) -> Result<u64, Failure> {
    sys(Syscall::FrameDmaAddress, slot, [0; 4])
        .map(|r| r.msg[0])
        .map_err(|e| ("DMA address", e))
}

/// Orders the driver's memory writes (descriptors, rings) before the
/// register write that tells the device to look at them.
pub fn dma_barrier() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier has no other effect. `dsb sy` also orders normal
    // memory writes before device-memory ones, which `fence` may not.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags))
    };
}
