//! Embeds the boot user programs. `cargo xtask` builds them and passes
//! their paths in SUPERIOR_USER_ELF (the self-test program) and
//! SUPERIOR_SHELL_ELF (the shell); a missing one is embedded empty.
//!
//! On AArch64 the kernel is linked at a fixed physical address by
//! `link-aarch64.ld`.

use std::{env, fs, path::PathBuf};

fn main() {
    embed("SUPERIOR_USER_ELF", "user.elf");
    embed("SUPERIOR_SHELL_ELF", "shell.elf");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64") {
        let script = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("link-aarch64.ld");
        println!("cargo:rerun-if-changed={}", script.display());
        println!("cargo:rustc-link-arg-bins=-T{}", script.display());
    }
}

fn embed(var: &str, name: &str) {
    println!("cargo:rerun-if-env-changed={var}");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(name);
    match env::var(var) {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            fs::copy(&path, &out).unwrap_or_else(|e| panic!("copying {path}: {e}"));
        }
        Err(_) => fs::write(&out, []).unwrap(),
    }
}
