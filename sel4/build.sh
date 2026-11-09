#!/bin/sh
# Builds, inside the sel4/Dockerfile container (repository mounted at
# /work), everything needed to boot Superior's shell on seL4:
#   1. the seL4 kernel for qemu-arm-virt (AArch64), for the device tree
#      that `cargo xtask sel4-test` dumps from the host's QEMU into
#      target/sel4/virt.dtb (the machine the kernel will boot on), installed
#      to /work/target/sel4/prefix with libsel4's headers. It is built in
#      hypervisor mode (kernel at EL2, threads at EL0), since rust-sel4's
#      loader enters the kernel at EL2. Kernel printing is off so the UART
#      is left to user space (the shell is its driver), and user mode may
#      use the EL1 physical timer (the kernel ticks on the hypervisor
#      timer) and read both counters;
#   2. rust-sel4's kernel loader, which boots the kernel with a payload.
# The root task itself is built by `cargo xtask sel4-test`.
set -eu
SEL4_VERSION=17.0.0
# rust-sel4 at a fixed commit, built with the nightly it pins.
RUST_SEL4_REV=f631577eb7def6fe6fb57fcaf7b8fd61bf144fcc
NIGHTLY=nightly-2026-10-28
OUT=/work/target/sel4
mkdir -p "$OUT"
cd "$OUT"

if [ ! -f prefix/bin/kernel.elf ]; then
    # Cloned and built inside the container: seL4's tree has symbolic
    # links, which a checkout on a Windows host turns into plain files.
    SRC=/tmp/sel4-build
    rm -rf "$SRC" && mkdir -p "$SRC"
    git clone --depth 1 --branch "$SEL4_VERSION" https://github.com/seL4/seL4.git "$SRC/seL4"
    cmake -G Ninja -S "$SRC/seL4" -B "$SRC/build" \
        -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
        -DCMAKE_TOOLCHAIN_FILE="$SRC/seL4/gcc.cmake" \
        -DCMAKE_INSTALL_PREFIX="$SRC/prefix" \
        -DKernelPlatform=qemu-arm-virt \
        -DKernelSel4Arch=aarch64 \
        -DKernelArmHypervisorSupport=ON \
        -DARM_CPU=cortex-a72 \
        -DQEMU_DTB="$OUT/virt.dtb" \
        -DKernelVerificationBuild=OFF \
        -DKernelDebugBuild=OFF \
        -DKernelPrinting=OFF \
        -DKernelArmExportPTMRUser=ON \
        -DKernelArmExportPCNTUser=ON \
        -DKernelArmExportVCNTUser=ON
    ninja -C "$SRC/build" all
    cmake --install "$SRC/build"
    rm -rf prefix && cp -rL "$SRC/prefix" prefix
fi

if [ ! -x loader/bin/sel4-kernel-loader-add-payload ]; then
    rustup toolchain install "$NIGHTLY" --profile minimal -c rust-src
    CC_aarch64_unknown_none=aarch64-linux-gnu-gcc \
    SEL4_PREFIX="$OUT/prefix" \
        cargo +"$NIGHTLY" install --locked --root "$OUT/loader" \
            --git https://github.com/seL4/rust-sel4 --rev "$RUST_SEL4_REV" \
            -Z build-std=core,alloc,compiler_builtins \
            -Z build-std-features=compiler-builtins-mem \
            --target aarch64-unknown-none \
            sel4-kernel-loader
    cargo +"$NIGHTLY" install --locked --root "$OUT/loader" \
        --git https://github.com/seL4/rust-sel4 --rev "$RUST_SEL4_REV" \
        sel4-kernel-loader-add-payload
fi
echo "seL4 $SEL4_VERSION and its loader are in $OUT"
