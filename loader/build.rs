//! Embeds the kernel: `cargo xtask` builds it for AArch64 and passes its
//! ELF's path in SUPERIOR_KERNEL_ELF. Without one, the loader carries
//! nothing and says so.

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
}
