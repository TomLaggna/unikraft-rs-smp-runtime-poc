// src/user_handlers.rs - Interrupt handlers for user space execution
//
// These handlers run at ring 0 but with user CR3 loaded.
// They are copied into guest_mem and invoked via the user space IDT.

use core::arch::global_asm;

/// COM1 port for debug output
const COM1: u16 = 0x3F8;

// Assembly interrupt handlers
// These are position-independent and will be copied to guest_mem
global_asm!(
    r#"
.section .text.user_handlers
.align 16

.globl user_handlers_start
user_handlers_start:
    // Marker for start of handler code

// Helper macro to define exception handlers 0-31 (except 32)
.macro EXCEPTION_HANDLER num, char
.globl user_exception_handler_\num
user_exception_handler_\num:
    // Save minimal context
    push rax
    push rdx
    
    // Output character to COM1 for debugging
    mov al, \char
    mov dx, {COM1}
    out dx, al
    
    // Restore and return
    pop rdx
    pop rax
    iretq
.endm

// Define handlers for exceptions 0-31
EXCEPTION_HANDLER 0, '0'   // Divide by zero
EXCEPTION_HANDLER 1, '1'   // Debug
EXCEPTION_HANDLER 2, '2'   // NMI
EXCEPTION_HANDLER 3, '3'   // Breakpoint
EXCEPTION_HANDLER 4, '4'   // Overflow
EXCEPTION_HANDLER 5, '5'   // Bound range
EXCEPTION_HANDLER 6, '6'   // Invalid opcode
EXCEPTION_HANDLER 7, '7'   // Device not available
EXCEPTION_HANDLER 8, '8'   // Double fault (uses IST)
EXCEPTION_HANDLER 9, '9'   // Coprocessor segment overrun
EXCEPTION_HANDLER 10, 'A'  // Invalid TSS
EXCEPTION_HANDLER 11, 'B'  // Segment not present
EXCEPTION_HANDLER 12, 'C'  // Stack fault
EXCEPTION_HANDLER 13, 'D'  // General protection fault
EXCEPTION_HANDLER 14, 'E'  // Page fault
EXCEPTION_HANDLER 15, 'F'  // Reserved
EXCEPTION_HANDLER 16, 'G'  // x87 FPU error
EXCEPTION_HANDLER 17, 'H'  // Alignment check
EXCEPTION_HANDLER 18, 'I'  // Machine check
EXCEPTION_HANDLER 19, 'J'  // SIMD exception
EXCEPTION_HANDLER 20, 'K'  // Virtualization exception
EXCEPTION_HANDLER 21, 'L'  // Control protection exception
EXCEPTION_HANDLER 22, 'M'  // Reserved
EXCEPTION_HANDLER 23, 'N'  // Reserved
EXCEPTION_HANDLER 24, 'O'  // Reserved
EXCEPTION_HANDLER 25, 'P'  // Reserved
EXCEPTION_HANDLER 26, 'Q'  // Reserved
EXCEPTION_HANDLER 27, 'R'  // Reserved
EXCEPTION_HANDLER 28, 'S'  // Reserved
EXCEPTION_HANDLER 29, 'T'  // Reserved
EXCEPTION_HANDLER 30, 'U'  // Reserved
EXCEPTION_HANDLER 31, 'V'  // Reserved

// Handler for INT 32 - User exit syscall
// This handler switches CR3 back to kernel and returns to kernel loop
.globl user_exception_handler_32
user_exception_handler_32:
    // Save all general-purpose registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    // Output 'X' to signal user exit
    mov al, 'X'
    mov dx, {COM1}
    out dx, al
    
    // Call Rust function to handle user exit
    // It will switch CR3 and set up return to kernel
    call user_exit_handler_rust
    
    // Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    iretq

.globl user_handlers_end
user_handlers_end:
    // Marker for end of handler code

"#,
    COM1 = const COM1
);

// External symbols from assembly
extern "C" {
    fn user_exception_handler_0();
    fn user_exception_handler_1();
    fn user_exception_handler_2();
    fn user_exception_handler_3();
    fn user_exception_handler_4();
    fn user_exception_handler_5();
    fn user_exception_handler_6();
    fn user_exception_handler_7();
    fn user_exception_handler_8();
    fn user_exception_handler_9();
    fn user_exception_handler_10();
    fn user_exception_handler_11();
    fn user_exception_handler_12();
    fn user_exception_handler_13();
    fn user_exception_handler_14();
    fn user_exception_handler_15();
    fn user_exception_handler_16();
    fn user_exception_handler_17();
    fn user_exception_handler_18();
    fn user_exception_handler_19();
    fn user_exception_handler_20();
    fn user_exception_handler_21();
    fn user_exception_handler_22();
    fn user_exception_handler_23();
    fn user_exception_handler_24();
    fn user_exception_handler_25();
    fn user_exception_handler_26();
    fn user_exception_handler_27();
    fn user_exception_handler_28();
    fn user_exception_handler_29();
    fn user_exception_handler_30();
    fn user_exception_handler_31();
    fn user_exception_handler_32();
    
    static user_handlers_start: u8;
    static user_handlers_end: u8;
}

/// Get the handler function addresses as an array
///
/// # Safety
/// Returns raw function pointers from assembly
pub unsafe fn get_handler_addresses() -> [u64; 33] {
    [
        user_exception_handler_0 as u64,
        user_exception_handler_1 as u64,
        user_exception_handler_2 as u64,
        user_exception_handler_3 as u64,
        user_exception_handler_4 as u64,
        user_exception_handler_5 as u64,
        user_exception_handler_6 as u64,
        user_exception_handler_7 as u64,
        user_exception_handler_8 as u64,
        user_exception_handler_9 as u64,
        user_exception_handler_10 as u64,
        user_exception_handler_11 as u64,
        user_exception_handler_12 as u64,
        user_exception_handler_13 as u64,
        user_exception_handler_14 as u64,
        user_exception_handler_15 as u64,
        user_exception_handler_16 as u64,
        user_exception_handler_17 as u64,
        user_exception_handler_18 as u64,
        user_exception_handler_19 as u64,
        user_exception_handler_20 as u64,
        user_exception_handler_21 as u64,
        user_exception_handler_22 as u64,
        user_exception_handler_23 as u64,
        user_exception_handler_24 as u64,
        user_exception_handler_25 as u64,
        user_exception_handler_26 as u64,
        user_exception_handler_27 as u64,
        user_exception_handler_28 as u64,
        user_exception_handler_29 as u64,
        user_exception_handler_30 as u64,
        user_exception_handler_31 as u64,
        user_exception_handler_32 as u64,
    ]
}

/// Get the handler code as a byte slice for copying to guest_mem
///
/// # Safety
/// Returns a slice of executable code from .text section
pub unsafe fn get_handler_code() -> &'static [u8] {
    let start = &user_handlers_start as *const u8;
    let end = &user_handlers_end as *const u8;
    let size = end.offset_from(start) as usize;
    core::slice::from_raw_parts(start, size)
}

/// Rust handler called from assembly when INT 32 is invoked
/// This runs at ring 0 with user CR3 loaded
///
/// # Safety
/// Called from assembly interrupt handler context
#[no_mangle]
extern "C" fn user_exit_handler_rust() {
    // TODO: Get kernel CR3 from somewhere (ApTaskInfo?)
    // TODO: Switch CR3 back to kernel
    // TODO: Signal task completion
    // For now, just a marker that we got here
    unsafe {
        use core::arch::asm;
        // Output '!' to indicate we're in Rust handler
        asm!(
            "mov al, '!'",
            "mov dx, 0x3F8",
            "out dx, al",
            options(nostack, preserves_flags)
        );
    }
}
