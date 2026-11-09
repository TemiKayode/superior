/* The AArch64 kernel, loaded by QEMU at its link address on the virt
   machine. RAM starts at 0x40000000, where QEMU places the device tree for
   a bare-metal image; the kernel goes 2 MiB above it. */
ENTRY(_start)

SECTIONS
{
    . = 0x40200000;
    __kernel_start = .;
    .text : { KEEP(*(.text.boot)) *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data : ALIGN(4096) { *(.data .data.*) }
    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(4096);
    __kernel_end = .;
}
