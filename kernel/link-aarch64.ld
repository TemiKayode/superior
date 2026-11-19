/* The AArch64 kernel, loaded by QEMU (or the UEFI loader) at its physical
   address on the virt machine. RAM starts at 0x40000000, where QEMU places
   the device tree for a bare-metal image; the kernel goes 2 MiB above it.
   It runs in the high half, KERNEL_OFFSET above that (TTBR1), so the low
   half is all user space: linked there, loaded at the physical address,
   and entered there (_start_phys) with the MMU off. */
KERNEL_OFFSET = 0xffff000000000000;
ENTRY(_start_phys)

SECTIONS
{
    . = KERNEL_OFFSET + 0x40200000;
    __kernel_start = .;
    .text : AT(ADDR(.text) - KERNEL_OFFSET) { KEEP(*(.text.boot)) *(.text .text.*) }
    .rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) ALIGN(4096) { *(.rodata .rodata.*) }
    .data : AT(ADDR(.data) - KERNEL_OFFSET) ALIGN(4096) { *(.data .data.*) }
    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_OFFSET) ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(4096);
    __kernel_end = .;
}
_start_phys = _start - KERNEL_OFFSET;
