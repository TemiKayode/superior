//! Interfaces compiled from their descriptions (`interfaces/*.idl`) by
//! the IDL compiler (`crates/idl`, run by `cargo xtask idl`): each
//! operation's number, a function that builds its call's message, and
//! one that reads its reply. `cargo xtask test` fails if a file here is
//! not what its description gives.
//!
//! The first is the PCI bus server's, which the Driver SDK calls through
//! these; the display, window and audio interfaces were described this way from the start.
//! The hand-written modules in [`crate::interfaces`] describe the
//! rest (and what travels with each call) until they are moved over.

#[path = "pci.rs"]
mod pci_file;
pub use pci_file::pci;
#[path = "display.rs"]
mod display_file;
pub use display_file::display;
#[path = "window.rs"]
mod window_file;
pub use window_file::window;
#[path = "audio.rs"]
mod audio_file;
pub use audio_file::audio;

#[cfg(test)]
mod tests {
    use super::pci;
    use crate::interfaces::{Status, pci as by_hand};

    #[test]
    fn the_generated_numbers_are_the_ones_servers_use() {
        assert_eq!(pci::VERSION, by_hand::VERSION);
        let pairs = [
            (pci::OPEN, by_hand::OPEN),
            (pci::BAR_PAGE, by_hand::BAR_PAGE),
            (pci::CONFIG_READ, by_hand::CONFIG_READ),
            (pci::BUS_MASTER, by_hand::BUS_MASTER),
            (pci::MSIX, by_hand::MSIX),
            (pci::MSI_VECTOR, by_hand::MSI_VECTOR),
            (pci::OPEN_CLASS, by_hand::OPEN_CLASS),
            (pci::MSI, by_hand::MSI),
            (pci::INTX, by_hand::INTX),
            (pci::IO_READ, by_hand::IO_READ),
            (pci::IO_WRITE, by_hand::IO_WRITE),
            (pci::CLOSE, by_hand::CLOSE),
            (pci::BAR_FRAME, by_hand::BAR_FRAME),
        ];
        for (generated, written) in pairs {
            assert_eq!(generated, written);
        }
    }

    #[test]
    fn messages_and_replies() {
        // The version is filled in; unused words are zero.
        assert_eq!(pci::open(0x1af4_1041, 2), [pci::OPEN, pci::VERSION, 0x1af4_1041, 2]);
        assert_eq!(pci::io_read(0, 8, 2), [pci::IO_READ, 0, 8, 2]);
        assert_eq!(pci::bus_master(1), [pci::BUS_MASTER, 1, 0, 0]);
        assert_eq!(pci::close(), [pci::CLOSE, 0, 0, 0]);
        let ok = Status::Ok as u64;
        assert_eq!(
            pci::open_reply([ok, 0x0a00, 0b10, 0b01]),
            Ok(pci::OpenReply {
                location: 0x0a00,
                memory_bars: 0b10,
                io_bars: 0b01
            })
        );
        assert_eq!(pci::intx_reply([ok, 3, 9, 9]), Ok(pci::IntxReply { wire: 3 }));
        // A failed call's reply is its status.
        assert_eq!(pci::open_reply([Status::InUse as u64, 7, 7, 7]), Err(Status::InUse));
        assert_eq!(pci::bar_page_reply([Status::NotFound as u64, 0, 0, 0]), Err(Status::NotFound));
    }
}
