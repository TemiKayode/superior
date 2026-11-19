//! A Linux program, for the Linux personality's test (it is not one of
//! Superior's): Linux's system calls made directly, no C library.
//!
//! It sets a handler for `SIGUSR1`, puts a value in the first SIMD
//! register (`xmm0`, `d0`) and rounds toward zero (MXCSR, FPCR), then sends
//! itself the signal. The handler clears that register, sets rounding back
//! to nearest and notes that it ran. Once the handler returns
//! (`rt_sigreturn`, through the restorer given with `SA_RESTORER`), the
//! register and the rounding mode must be as they were: they went in the
//! signal frame. If they are, and the handler ran, it says so and exits 0;
//! else it exits 1.
//!
//! On x86-64 with AVX (CPUID's OSXSAVE and AVX bits) it also puts a value
//! in `ymm0`'s upper half, which the handler clears (`vzeroall`), and says
//! so too if that is as it was (the `xsave` state in the frame).
//!
//! All code addresses it takes are relative to the program counter, so as
//! a static PIE it has nothing to relocate.

#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    // rt_sigaction(SIGUSR1, {handler, SA_RESTORER, restorer, 0}, 0, 8)
    "sub rsp, 40",
    "lea rax, [rip + fp_handler]",
    "mov [rsp], rax",
    "mov qword ptr [rsp + 8], 0x04000000",
    "lea rax, [rip + fp_restorer]",
    "mov [rsp + 16], rax",
    "mov qword ptr [rsp + 24], 0",
    "mov edi, 10",
    "mov rsi, rsp",
    "xor edx, edx",
    "mov r10d, 8",
    "mov eax, 13",
    "syscall",
    "test rax, rax",
    "jnz fp_fail",
    // AVX? (rbx is not needed by anyone above us.)
    "mov eax, 1",
    "cpuid",
    "and ecx, 0x18000000",
    "cmp ecx, 0x18000000",
    "sete byte ptr [rip + fp_avx]",
    // The value, and rounding toward zero; with AVX, another in ymm0's
    // upper half.
    "mov rax, 0x0123456789abcdef",
    "movq xmm0, rax",
    "cmp byte ptr [rip + fp_avx], 1",
    "jne 2f",
    "mov rax, 0x0fedcba987654321",
    "movq xmm1, rax",
    "vinsertf128 ymm0, ymm0, xmm1, 1",
    "2:",
    "mov dword ptr [rsp + 32], 0x7f80",
    "ldmxcsr [rsp + 32]",
    // kill(getpid(), SIGUSR1)
    "mov eax, 39",
    "syscall",
    "mov edi, eax",
    "mov esi, 10",
    "mov eax, 62",
    "syscall",
    // As they were, and the handler ran?
    "movq rax, xmm0",
    "mov rcx, 0x0123456789abcdef",
    "cmp rax, rcx",
    "jne fp_fail",
    "stmxcsr [rsp + 32]",
    "cmp dword ptr [rsp + 32], 0x7f80",
    "jne fp_fail",
    "cmp qword ptr [rip + fp_ran], 1",
    "jne fp_fail",
    "cmp byte ptr [rip + fp_avx], 1",
    "jne 3f",
    "vextractf128 xmm1, ymm0, 1",
    "movq rax, xmm1",
    "mov rcx, 0x0fedcba987654321",
    "cmp rax, rcx",
    "jne fp_fail",
    "3:",
    "mov edi, 1",
    "lea rsi, [rip + fp_msg]",
    "mov edx, 35",
    "mov eax, 1",
    "syscall",
    "cmp byte ptr [rip + fp_avx], 1",
    "jne 4f",
    "mov edi, 1",
    "lea rsi, [rip + fp_ymm_msg]",
    "mov edx, 36",
    "mov eax, 1",
    "syscall",
    "4:",
    "xor edi, edi",
    "jmp fp_exit",
    "fp_fail:",
    "mov edi, 1",
    "fp_exit:",
    "mov eax, 231",
    "syscall",
    "fp_handler:",
    "pxor xmm0, xmm0",
    "cmp byte ptr [rip + fp_avx], 1",
    "jne 5f",
    "vzeroall",
    "5:",
    "mov dword ptr [rsp - 8], 0x1f80",
    "ldmxcsr [rsp - 8]",
    "mov qword ptr [rip + fp_ran], 1",
    "ret",
    "fp_restorer:",
    "mov eax, 15",
    "syscall",
    ".section .rodata",
    "fp_msg: .ascii \"fp registers kept across a handler\\n\"",
    "fp_ymm_msg: .ascii \"ymm registers kept across a handler\\n\"",
    ".section .bss",
    ".balign 8",
    "fp_ran: .quad 0",
    "fp_avx: .byte 0",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".arch_extension fp",
    ".arch_extension simd",
    ".globl _start",
    "_start:",
    // rt_sigaction(SIGUSR1, {handler, SA_RESTORER, restorer, 0}, 0, 8)
    "sub sp, sp, #48",
    "adr x0, fp_handler",
    "str x0, [sp]",
    "mov x0, #0x04000000",
    "str x0, [sp, #8]",
    "adr x0, fp_restorer",
    "str x0, [sp, #16]",
    "str xzr, [sp, #24]",
    "mov x0, #10",
    "mov x1, sp",
    "mov x2, #0",
    "mov x3, #8",
    "mov x8, #134",
    "svc #0",
    "cbnz x0, fp_fail",
    // The value, and rounding toward zero (FPCR.RMode = 0b11).
    "movz x0, #0xcdef",
    "movk x0, #0x89ab, lsl #16",
    "movk x0, #0x4567, lsl #32",
    "movk x0, #0x0123, lsl #48",
    "fmov d0, x0",
    "mov x0, #0xc00000",
    "msr fpcr, x0",
    // kill(getpid(), SIGUSR1)
    "mov x8, #172",
    "svc #0",
    "mov x1, #10",
    "mov x8, #129",
    "svc #0",
    // As they were, and the handler ran?
    "fmov x0, d0",
    "movz x1, #0xcdef",
    "movk x1, #0x89ab, lsl #16",
    "movk x1, #0x4567, lsl #32",
    "movk x1, #0x0123, lsl #48",
    "cmp x0, x1",
    "b.ne fp_fail",
    "mrs x0, fpcr",
    "mov x1, #0xc00000",
    "cmp x0, x1",
    "b.ne fp_fail",
    "adrp x0, fp_ran",
    "add x0, x0, :lo12:fp_ran",
    "ldr x0, [x0]",
    "cmp x0, #1",
    "b.ne fp_fail",
    "mov x0, #1",
    "adrp x1, fp_msg",
    "add x1, x1, :lo12:fp_msg",
    "mov x2, #35",
    "mov x8, #64",
    "svc #0",
    "mov x0, #0",
    "b fp_exit",
    "fp_fail:",
    "mov x0, #1",
    "fp_exit:",
    "mov x8, #94",
    "svc #0",
    "fp_handler:",
    "fmov d0, xzr",
    "msr fpcr, xzr",
    "adrp x1, fp_ran",
    "add x1, x1, :lo12:fp_ran",
    "mov x2, #1",
    "str x2, [x1]",
    "ret",
    "fp_restorer:",
    "mov x8, #139",
    "svc #0",
    ".section .rodata",
    "fp_msg: .ascii \"fp registers kept across a handler\\n\"",
    ".section .bss",
    ".balign 8",
    "fp_ran: .quad 0",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
