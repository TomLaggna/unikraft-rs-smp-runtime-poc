// src/user_code.rs - User space code that runs at ring 3
//
// This code is copied to user space and executed after iretq transitions to ring 3.
// It triggers INT 32 to return to kernel.
// NOTE: Cannot use I/O instructions (out) at ring 3 - they're privileged.
//
// This is designed to roughly match the characteristics of the Dandelion basic.c example:
// - ~8KB total mapped size (code + data padding)
// - Small computation loop to simulate actual work
// Reference: https://github.com/eth-easl/dandelionFunctionExamples/blob/main/c_functions/basic/basic.c

use core::arch::global_asm;

// User code assembly - position independent
// Sized to match Dandelion basic example: ~7.5KB code, ~500 bytes data/bss
// Total: ~8KB mapped region
global_asm!(
    r#"
.section .text.user_code
.align 16

.globl user_code_start
user_code_start:

// Entry point - we arrive here from iretq at ring 3
.globl user_code_entry
user_code_entry:
    // We're now in user mode (ring 3)!
    // Cannot do I/O (out instruction) - that's privileged
    
    // Set marker values to verify user code execution
    mov rbx, 0xDEADBEEFCAFEBABE
    mov r12, 0x1234567890ABCDEF
    
    // Simulate work similar to Dandelion basic example:
    // Analysis of basic.c -> dandelion_init -> dandelion_add_output -> dandelion_exit:
    // - dandelion_init: ~500-1000 dynamic instructions (loops over input/output sets, allocs)
    // - dandelion_alloc: ~200-400 per call (called 2-3 times)
    // - dandelion_exit: ~300-500 (loops to serialize outputs, memcpy)
    // - memcpy: ~50-100 per call
    // Total estimate: ~2000-5000 dynamic instructions for minimal workload
    //
    // We use 3000 iterations with mixed operations to approximate this
    mov rcx, 3000
    xor rax, rax          // accumulator
.Lwork_loop:
    // Mix of operations similar to Dandelion runtime:
    // - arithmetic (comparisons, increments)
    // - memory simulation (register moves acting as loads/stores)
    mov rdx, rcx
    imul rdx, rdx         // square (like size calculations)
    add rax, rdx          // accumulate
    mov r8, rax           // simulate store
    mov r9, r8            // simulate load
    xor r9, rcx           // xor mixing
    add rax, r9
    dec rcx
    jnz .Lwork_loop
    
    // Store result marker
    mov rbx, rax
    mov r12, rbx
    
    // Trigger INT 32 to return to kernel
    int 32
    
    // Should never reach here - loop forever as safety
.Luser_loop:
    jmp .Luser_loop

// Padding functions to reach ~7.5KB code size (matching Dandelion .text)
// Each function is ~256 bytes of NOPs with some structure

.align 64
dummy_func_1:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_2:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_3:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_4:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_5:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_6:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_7:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_8:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_9:
    .rept 60
    nop
    .endr
    ret

.align 64
dummy_func_10:
    .rept 60
    nop
    .endr
    ret

// More padding - larger blocks
.align 256
.Lpadding_block_1:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_2:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_3:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_4:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_5:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_6:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_7:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_8:
    .rept 512
    nop
    .endr

.align 256
.Lpadding_block_9:
    .rept 512
    nop
    .endr

.align 256  
.Lpadding_block_10:
    .rept 512
    nop
    .endr

// Data section padding (~500 bytes to match Dandelion .data + .bss)
.align 64
user_data_section:
    .rept 64
    .quad 0xDEADBEEF00000000
    .endr

.globl user_code_end
user_code_end:
"#
);

extern "C" {
    static user_code_start: u8;
    static user_code_end: u8;
    fn user_code_entry();
}

/// Get user code as a byte slice
pub unsafe fn get_user_code() -> &'static [u8] {
    let start = &user_code_start as *const u8;
    let end = &user_code_end as *const u8;
    let size = end.offset_from(start) as usize;
    core::slice::from_raw_parts(start, size)
}

/// Get the entry point offset within the user code
pub unsafe fn get_entry_offset() -> usize {
    let start = &user_code_start as *const u8 as usize;
    let entry = user_code_entry as usize;
    entry - start
}

/// Get the size of user code
pub unsafe fn get_user_code_size() -> usize {
    let start = &user_code_start as *const u8;
    let end = &user_code_end as *const u8;
    end.offset_from(start) as usize
}
