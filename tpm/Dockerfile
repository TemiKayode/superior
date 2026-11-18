# QEMU with a software TPM (swtpm), for `cargo xtask tpm-test`: QEMU's
# Windows build has no TPM backend, so the test boots the kernel here, in
# Linux, with swtpm's TPM 2.0 on QEMU's TIS interface.
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 qemu-system-arm swtpm swtpm-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Secure Boot for `cargo xtask secure-boot-test`: keys (openssl), signing
# the UEFI loader (sbsign), and firmware variables with those keys
# enrolled (virt-fw-vars, from virt-firmware).
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl sbsigntool python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir virt-firmware
ENV PATH=/opt/venv/bin:$PATH

# Debian's AArch64 edk2 (AAVMF), built with Secure Boot (QEMU's own
# edk2-aarch64-code.fd is not): the Secure Boot test copies it out and
# boots it on the host's QEMU.
RUN apt-get update && apt-get install -y --no-install-recommends qemu-efi-aarch64 \
    && rm -rf /var/lib/apt/lists/*
