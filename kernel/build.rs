//! Embeds the boot user program. `cargo xtask` builds it and passes its
//! path in SUPERIOR_USER_ELF; without one the kernel boots with no user
//! program and idles.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=SUPERIOR_USER_ELF");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("user.elf");
    match env::var("SUPERIOR_USER_ELF") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out).unwrap_or_else(|e| panic!("copying {path}: {e}"));
        }
        Err(_) => fs::write(&out, []).unwrap(),
    }
}
