// src/user_code.rs - User space code that runs at ring 3
//
// This code is copied to user space and executed after iretq transitions to ring 3.
// It triggers INT 32 to return to kernel.
// NOTE: Cannot use I/O instructions (out) at ring 3 - they're privileged.

use core::arch::global_asm;

// User code assembly - position independent
// NOTE: We cannot use OUT instructions at ring 3 (causes GPF)
// Instead, we just trigger INT 32 to return to kernel
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
    
    // Set a marker value in RBX before INT 32
    // If we see this value in the fault handler, we know user code ran
    // Using 0xDEADBEEFCAFEBABE as marker
    mov rbx, 0xDEADBEEFCAFEBABE
    
    // Also set R12 as backup marker (another callee-saved register)
    mov r12, 0x1234567890ABCDEF
    
    // Trigger INT 32 to return to kernel
    // This will invoke user_exception_handler_32 which jumps to U->K trampoline
    int 32
    
    // Should never reach here
    // But if we do, loop forever
.Luser_loop:
    jmp .Luser_loop

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
