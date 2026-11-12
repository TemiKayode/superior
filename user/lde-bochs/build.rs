//! Links the Linux driver and the environment's C half, which `cargo
//! xtask` compiled (crates/lde/cc.sh) into the directory it names in
//! `SUPERIOR_LDE_OBJECTS`. Without it (a plain `cargo check`) nothing is
//! linked, and only a real link fails.

fn main() {
    println!("cargo:rerun-if-env-changed=SUPERIOR_LDE_OBJECTS");
    let Ok(dir) = std::env::var("SUPERIOR_LDE_OBJECTS") else {
        println!("cargo:warning=SUPERIOR_LDE_OBJECTS is not set: build this with cargo xtask");
        return;
    };
    for object in ["bochs.o", "lde.o", "lde-net.o", "lde-drm.o"] {
        let path = std::path::Path::new(&dir).join(object);
        println!("cargo:rerun-if-changed={}", path.display());
        println!("cargo:rustc-link-arg={}", path.display());
    }
}
