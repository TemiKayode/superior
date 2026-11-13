//! Wi-Fi security for Superior's station: WPA2-Personal, `no_std` and
//! allocation-free so a component can use it, and kept apart so host tests
//! can check it against the published test vectors.
//!
//! - [`sha1`]: SHA-1, HMAC-SHA1, PBKDF2, the passphrase's pairwise master
//!   key ([`sha1::psk`]) and 802.11's PRF.
//! - [`aes`]: AES-128, CCM and AES key wrap.
//! - [`handshake`]: the 4-way handshake, the station's side and the access
//!   point's.
//! - [`ccmp`]: data frames sealed and opened under the temporal key.
//! - [`frame`]: the 802.11 frames used, and Ethernet frames to and from
//!   data frames.
//! - [`station`]: a station finding a network, joining it and carrying
//!   Ethernet frames, with no I/O of its own (a radio driver hosts it).
//! - [`ap`]: an access point for one station, which the test harness plays
//!   at the far end of a simulated radio.

#![no_std]

pub mod aes;
pub mod ap;
pub mod ccmp;
pub mod frame;
pub mod handshake;
pub mod sha1;
pub mod station;

#[cfg(test)]
mod tests;
