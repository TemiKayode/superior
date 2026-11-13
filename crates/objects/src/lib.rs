//! Superior kernel object model.
//!
//! This crate holds the parts of the kernel that are pure logic: capability
//! storage and derivation, and carving physical memory into untyped blocks.
//! It is `no_std`, allocates nothing, and is unit-tested on the host so the
//! rules that guard authority are checked without booting anything.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod ab;
pub mod abi;
pub mod bundle;
pub mod cap;
pub mod crypto;
pub mod elf;
pub mod idl;
pub mod interfaces;
pub mod ipc;
pub mod manifest;
pub mod pages;
#[cfg(test)]
pub mod model;
#[cfg(test)]
pub mod sim;
pub mod untyped;
