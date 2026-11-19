//! Embeds the boot user programs. `cargo xtask` builds them and passes
//! their paths in SUPERIOR_USER_ELF (the self-test program),
//! SUPERIOR_SHELL_ELF (the shell), SUPERIOR_CM_ELF (the Component Manager)
//! and SUPERIOR_BUNDLE (the signed boot bundle it starts components from);
//! SUPERIOR_TRUST_KEY is the Ed25519 public key (32 bytes) that bundle must
//! be signed with. A missing one is embedded empty. SUPERIOR_MIN_VERSION is
//! the oldest bundle version the kernel boots (0 if unset).
//!
//! On AArch64 the kernel is linked in the high half, loaded at a fixed
//! physical address, by `link-aarch64.ld`.

use std::{env, fs, path::PathBuf};

fn main() {
    embed("SUPERIOR_USER_ELF", "user.elf");
    embed("SUPERIOR_SHELL_ELF", "shell.elf");
    embed("SUPERIOR_CM_ELF", "cm.elf");
    embed("SUPERIOR_BUNDLE", "bundle.bin");
    embed("SUPERIOR_TRUST_KEY", "trust.key");
    println!("cargo:rerun-if-env-changed=SUPERIOR_MIN_VERSION");
    let min = env::var("SUPERIOR_MIN_VERSION").unwrap_or_else(|_| "0".into());
    println!("cargo:rustc-env=SUPERIOR_MIN_VERSION={min}");
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
