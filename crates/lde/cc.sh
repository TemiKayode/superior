#!/bin/sh
# Compiles the Linux Driver Environment's C half (its core, network and DRM
# parts; every driver links all three) and one Linux driver for
# an architecture, in the build container (cargo xtask runs this):
#   cc.sh <x86_64|aarch64> <driver.c> <module name> <output directory>
# Linux's own warnings policy: char signedness in pointers is not checked.
set -e
arch=$1; driver=$2; name=$3; out=$4
case $arch in
x86_64)  target="--target=x86_64-unknown-none-elf -mno-sse -mno-mmx -mno-80387 -msoft-float -mno-red-zone" ;;
aarch64) target="--target=aarch64-unknown-none-elf -mgeneral-regs-only -mno-outline-atomics" ;;
*) echo "unknown architecture $arch"; exit 1 ;;
esac
# No floating point (threads have no FP state), position-independent like
# every component, and nothing from the container's own headers.
flags="-std=gnu11 -O2 -ffreestanding -fno-stack-protector -fno-common -fPIE -fvisibility=hidden
  -nostdinc -I/work/crates/lde/include -Wall -Werror -Wno-unused-function -Wno-pointer-sign
  -Wno-shift-count-overflow"
mkdir -p "$out"
clang $target $flags -DKBUILD_MODNAME="\"$name\"" -c "$driver" -o "$out/$name.o"
for half in lde lde-net lde-drm; do
  clang $target $flags -c /work/crates/lde/c/$half.c -o "$out/$half.o"
done
