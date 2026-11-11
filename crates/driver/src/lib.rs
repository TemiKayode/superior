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
    /// raise it: (address, data). Where interrupts are remapped, only the
    /// function bound to the I/O address space in `domain` can raise it.
    pub fn msi_vector(
        &self,
        n: u64,
        slot: u64,
        notification: u64,
        domain: u64,
    ) -> Result<(u64, u64), Failure> {
        self.take_msi_vector(n, slot)?;
        let m = msi_message(slot, Some(domain))?;
        sys(Syscall::IrqSetNotification, slot, [notification, 0, 0, 0])
            .map_err(|e| ("binding the MSI vector", e))?;
        Ok(m)
    }

    /// Reads `width` bytes (1, 2 or 4) at `offset` in I/O BAR `bar`.
    pub fn io_read(&self, bar: u64, offset: u64, width: u64) -> Result<u64, Failure> {
        self.call([pci::IO_READ, bar, offset, width], None).map(|r| r.msg[1])
    }

    /// Writes `width` bytes of `value` at `offset` in I/O BAR `bar`.
    pub fn io_write(&self, bar: u64, offset: u64, width: u64, value: u64) -> Result<(), Failure> {
        self.call([pci::IO_WRITE, bar | width << 8, offset, value], None)
            .map(drop)
    }

    /// Gives the function back to the bus server.
    pub fn close(&self) -> Result<(), Failure> {
        self.call([pci::CLOSE, 0, 0, 0], None).map(drop)
    }

    /// For a function with no MSI: takes its legacy interrupt line into
    /// `slot` and binds it to the notification in `notification`. The
    /// line is masked each time it signals: [`irq_ack`] unmasks it, once
    /// the device no longer asserts it. Returns which of the bus's four
    /// interrupt wires it is.
    pub fn intx(&self, slot: u64, notification: u64) -> Result<u64, Failure> {
        let r = self.call([pci::INTX, 0, 0, 0], Some(slot))?;
        if r.cap != Some(slot as u16) {
            return Err(("no interrupt line arrived", 0));
        }
        sys(Syscall::IrqSetNotification, slot, [notification, 0, 0, 0])
            .map(|_| r.msg[1])
            .map_err(|e| ("binding the interrupt line", e))
    }

    /// Takes MSI vector `n` into `slot` and nothing more: the vector is
    /// routed for no device until [`msi_message`] says otherwise.
    pub fn take_msi_vector(&self, n: u64, slot: u64) -> Result<(), Failure> {
        let r = self.call([pci::MSI_VECTOR, n, 0, 0], Some(slot))?;
        if r.cap != Some(slot as u16) {
            return Err(("no MSI vector arrived", 0));
        }
        Ok(())
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

/// Unmasks the level-triggered interrupt line in `slot`, which the kernel
/// masked when it signalled.
pub fn irq_ack(slot: u64) {
    syscall(Syscall::IrqAck, slot, [0; 4]);
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
/// The message that raises the MSI vector in `slot`, which only the
/// function bound to the I/O address space in `source` may then send (or,
/// with `None`, no device at all).
pub fn msi_message(slot: u64, source: Option<u64>) -> Result<(u64, u64), Failure> {
    sys(Syscall::IrqMsiMessage, slot, [source.unwrap_or(u64::MAX), 0, 0, 0])
        .map(|m| (m.msg[0], m.msg[1]))
        .map_err(|e| ("MSI message", e))
}

/// What the IOMMU blocked for the function bound to `domain` since the
/// last call.
pub struct IoFaults {
    /// DMA requests, and the first one's page and whether it was a write.
    pub dma: u64,
    pub first_page: u64,
    pub first_write: bool,
    /// Interrupt messages it was not allowed to send.
    pub interrupts: u64,
}

pub fn io_faults(domain: u64) -> Result<IoFaults, Failure> {
    sys(Syscall::IoFaults, domain, [0; 4])
        .map(|r| IoFaults {
            dma: r.msg[0],
            first_page: r.msg[1],
            first_write: r.msg[2] != 0,
            interrupts: r.msg[3],
        })
        .map_err(|e| ("reading IOMMU faults", e))
}

/// Has the notification in `ntfn` signalled whenever the IOMMU blocks a
/// request from the function bound to `domain` (`None`: no longer).
pub fn io_fault_notify(domain: u64, ntfn: Option<u64>) -> Result<(), Failure> {
    sys(Syscall::IoFaultNotify, domain, [ntfn.unwrap_or(u64::MAX), 0, 0, 0])
        .map(|_| ())
        .map_err(|e| ("binding the IOMMU's fault notification", e))
}

/// How a test describes the IOMMU's report of a stray DMA write aimed at
/// `page`: whether it was reported, and a phrase saying so.
pub fn stray_reported(domain: u64, page: u64) -> (bool, &'static str) {
    match io_faults(domain) {
        Ok(f) if f.dma > 0 && f.first_write && f.first_page == page => {
            (true, "the IOMMU reported a blocked write to it")
        }
        Ok(f) if f.dma == 0 => (false, "the IOMMU reported NOTHING"),
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
