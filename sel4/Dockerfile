# Build environment for running Superior's user space on seL4 (AArch64,
# QEMU virt): the seL4 kernel (CMake/Ninja, cross gcc), rust-sel4's kernel
# loader, and Rust for the root task. QEMU runs on the host.
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake ninja-build git curl \
        gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
        python3 python3-pip python3-venv libxml2-utils device-tree-compiler \
        pkg-config libclang-dev clang \
    && rm -rf /var/lib/apt/lists/*

# The seL4 kernel build's Python dependencies.
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir sel4-deps
ENV PATH=/opt/venv/bin:/root/.cargo/bin:$PATH

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none

WORKDIR /work
