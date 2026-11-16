//! Embeds the kernel: `cargo xtask` builds it for AArch64 and passes its
//! ELF's path in SUPERIOR_KERNEL_ELF. Without one, the loader carries
//! nothing and says so.
//!
//! And, if SUPERIOR_EXTRA_ACPI names a file, the ACPI tables in it (one
//! after another, each as long as its header says), which the loader
//! installs alongside the firmware's: what a machine's own tables leave
//! out, or what a test needs that QEMU's cannot say.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=SUPERIOR_KERNEL_ELF");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("kernel.elf");
    match env::var("SUPERIOR_KERNEL_ELF") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out).unwrap_or_else(|e| panic!("copying {path}: {e}"));
        }
        Err(_) => fs::write(&out, []).unwrap(),
    }
    println!("cargo:rerun-if-env-changed=SUPERIOR_EXTRA_ACPI");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("acpi.bin");
    match env::var("SUPERIOR_EXTRA_ACPI") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out).unwrap_or_else(|e| panic!("copying {path}: {e}"));
        }
        _ => fs::write(&out, []).unwrap(),
    }
}
