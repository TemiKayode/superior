//! A Linux program, for the Linux personality's test (it is not one of
//! Superior's): Linux's system calls made directly, no C library.
//!
//! 400 times over it maps 64 KiB of anonymous memory, checks every page
//! reads as zeros, writes to every page, and unmaps it: 25 MiB in all, far
//! more than a process's memory, so it runs only if what `munmap` gives
//! back is used again. Each map must be at the same address as the first
//! (the space is used again too), and afterwards `write` from there must
//! fail with `EFAULT` (nothing is mapped there). Then it says so and exits
//! 0; else it exits 1.
//!
//! All code addresses it takes are relative to the program counter, so as
//! a static PIE it has nothing to relocate.

#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    // r12: maps made; r13: the first one's address.
    "xor r12d, r12d",
    "xor r13d, r13d",
    "2:",
    // mmap(0, 64 KiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    "xor edi, edi",
    "mov esi, 0x10000",
    "mov edx, 3",
    "mov r10d, 0x22",
    "mov r8, -1",
    "xor r9d, r9d",
    "mov eax, 9",
    "syscall",
    "cmp rax, -4095",
    "jae mm_fail",
    "test r12, r12",
    "jnz 3f",
    "mov r13, rax",
    "3:",
    "cmp rax, r13",
    "jne mm_fail",
    // Every page zeros, then written.
    "lea r14, [r12 + 1]",
    "mov rbx, rax",
    "mov r15d, 16",
    "4:",
    "cmp qword ptr [rbx], 0",
    "jne mm_fail",
    "cmp qword ptr [rbx + 4088], 0",
    "jne mm_fail",
    "mov [rbx], r14",
    "mov [rbx + 4088], r14",
    "add rbx, 4096",
    "dec r15d",
    "jnz 4b",
    // munmap
    "mov rdi, r13",
    "mov esi, 0x10000",
    "mov eax, 11",
    "syscall",
    "test rax, rax",
    "jnz mm_fail",
    "inc r12",
    "cmp r12, 400",
    "jne 2b",
    // write(1, the first address, 1): EFAULT.
    "mov edi, 1",
    "mov rsi, r13",
    "mov edx, 1",
    "mov eax, 1",
    "syscall",
    "cmp rax, -14",
    "jne mm_fail",
    "mov edi, 1",
    "lea rsi, [rip + mm_msg]",
    "mov edx, 27",
    "mov eax, 1",
    "syscall",
    "xor edi, edi",
    "jmp mm_exit",
    "mm_fail:",
    "mov edi, 1",
    "mm_exit:",
    "mov eax, 231",
    "syscall",
    ".section .rodata",
    "mm_msg: .ascii \"mapped and unmapped 25 MiB\\n\"",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    // x19: maps made; x20: the first one's address.
    "mov x19, #0",
    "mov x20, #0",
    "2:",
    // mmap(0, 64 KiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    "mov x0, #0",
    "mov x1, #0x10000",
    "mov x2, #3",
    "mov x3, #0x22",
    "mov x4, #-1",
    "mov x5, #0",
    "mov x8, #222",
    "svc #0",
    "cmn x0, #4095",
    "b.hs mm_fail",
    "cbnz x19, 3f",
    "mov x20, x0",
    "3:",
    "cmp x0, x20",
    "b.ne mm_fail",
    // Every page zeros, then written.
    "add x23, x19, #1",
    "mov x21, x0",
    "mov x22, #16",
    "4:",
    "ldr x9, [x21]",
    "cbnz x9, mm_fail",
    "ldr x9, [x21, #4088]",
    "cbnz x9, mm_fail",
    "str x23, [x21]",
    "str x23, [x21, #4088]",
    "add x21, x21, #4096",
    "subs x22, x22, #1",
    "b.ne 4b",
    // munmap
    "mov x0, x20",
    "mov x1, #0x10000",
    "mov x8, #215",
    "svc #0",
    "cbnz x0, mm_fail",
    "add x19, x19, #1",
    "cmp x19, #400",
    "b.ne 2b",
    // write(1, the first address, 1): EFAULT.
    "mov x0, #1",
    "mov x1, x20",
    "mov x2, #1",
    "mov x8, #64",
    "svc #0",
    "cmn x0, #14",
    "b.ne mm_fail",
    "mov x0, #1",
    "adrp x1, mm_msg",
    "add x1, x1, :lo12:mm_msg",
    "mov x2, #27",
    "mov x8, #64",
    "svc #0",
    "mov x0, #0",
    "b mm_exit",
    "mm_fail:",
    "mov x0, #1",
    "mm_exit:",
    "mov x8, #93",
    "svc #0",
    ".section .rodata",
    "mm_msg: .ascii \"mapped and unmapped 25 MiB\\n\"",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
