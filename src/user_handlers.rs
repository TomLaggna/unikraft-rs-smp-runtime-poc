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

// Helper macro for exceptions WITHOUT error code
.macro EXCEPTION_HANDLER_NO_ERR num, char
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

// Helper macro for exceptions WITH error code (must pop it before iretq!)
// Exceptions with error code: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30
.macro EXCEPTION_HANDLER_WITH_ERR num, char
.globl user_exception_handler_\num
user_exception_handler_\num:
    // Error code is on stack - save it first, then print, then handle
    push rax
    push rdx
    
    // Output character to COM1 for debugging
    mov al, \char
    mov dx, {COM1}
    out dx, al
    
    // Print CR2 (faulting address) for page faults - useful for debugging
    // Read CR2 and print as 16 hex digits
    .if \num == 14
        mov al, '@'
        out dx, al
        mov rax, cr2
        mov rcx, 16
    1:
        rol rax, 4
        push rax
        and al, 0xF
        add al, '0'
        cmp al, '9'
        jle 2f
        add al, 7
    2:
        out dx, al
        pop rax
        dec rcx
        jnz 1b
        mov al, '@'
        out dx, al
    .endif
    
    // Restore regs
    pop rdx
    pop rax
    
    // Pop the error code that was pushed by the CPU
    add rsp, 8
    
    iretq
.endm

// Define handlers for exceptions 0-31
// Exceptions WITHOUT error code: 0-7, 9, 15, 16, 18-20, 22-28, 31
EXCEPTION_HANDLER_NO_ERR 0, '0'   // Divide by zero
EXCEPTION_HANDLER_NO_ERR 1, '1'   // Debug
EXCEPTION_HANDLER_NO_ERR 2, '2'   // NMI
EXCEPTION_HANDLER_NO_ERR 3, '3'   // Breakpoint
EXCEPTION_HANDLER_NO_ERR 4, '4'   // Overflow
EXCEPTION_HANDLER_NO_ERR 5, '5'   // Bound range
EXCEPTION_HANDLER_NO_ERR 6, '6'   // Invalid opcode
EXCEPTION_HANDLER_NO_ERR 7, '7'   // Device not available
// Double fault (8) - special handler that halts instead of returning
// EXCEPTION_HANDLER_WITH_ERR 8, '8' - replaced with halt version below
EXCEPTION_HANDLER_NO_ERR 9, '9'   // Coprocessor segment overrun

// Special double fault handler (exception 8) that halts the system
// Double fault means unrecoverable state - halt to prevent infinite loop
.globl user_exception_handler_8
user_exception_handler_8:
    push rax
    push rdx
    
    // Output '8' for double fault then '!' repeatedly
    mov dx, {COM1}
    mov al, '8'
    out dx, al
    mov al, '!'
    out dx, al
    mov al, 'D'
    out dx, al
    mov al, 'F'
    out dx, al
    mov al, '!'
    out dx, al
    
    // Halt loop - system is in unrecoverable state
1:
    cli
    hlt
    jmp 1b

EXCEPTION_HANDLER_WITH_ERR 10, 'A'  // Invalid TSS
EXCEPTION_HANDLER_WITH_ERR 11, 'B'  // Segment not present
EXCEPTION_HANDLER_WITH_ERR 12, 'C'  // Stack fault
EXCEPTION_HANDLER_WITH_ERR 13, 'D'  // General protection fault
// Page fault (14) - special handler that halts after printing info
// EXCEPTION_HANDLER_WITH_ERR 14, 'E' - replaced with halt version below
EXCEPTION_HANDLER_NO_ERR 15, 'F'  // Reserved

// Special page fault handler (exception 14) that halts after printing CR2
// This prevents infinite fault loops and makes debugging clearer
.globl user_exception_handler_14
user_exception_handler_14:
    // Save RBX first - it contains our marker value from user code!
    push rbx
    push rax
    push rdx
    push rcx
    
    mov dx, {COM1}
    
    // Output 'E' for page fault
    mov al, 'E'
    out dx, al
    
    // Print 'B' then RBX value (marker from user code: should be 0xDEADBEEFCAFEBABE)
    mov al, 'B'
    out dx, al
    mov rax, [rsp + 24]  // RBX is at offset 24 (after rcx, rdx, rax pushes)
    mov rcx, 16
.Lprint_rbx:
    rol rax, 4
    push rax
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lrbx_ok
    add al, 7
.Lrbx_ok:
    out dx, al
    pop rax
    dec rcx
    jnz .Lprint_rbx
    mov al, ':'
    out dx, al
    
    // Print 'S' then RSP value to show what stack we're on
    mov al, 'S'
    out dx, al
    mov rax, rsp
    add rax, 32          // Adjust for our 4 pushes (rbx, rax, rdx, rcx)
    mov rcx, 16
.Lprint_rsp:
    rol rax, 4
    push rax
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lrsp_ok
    add al, 7
.Lrsp_ok:
    out dx, al
    pop rax
    dec rcx
    jnz .Lprint_rsp
    mov al, ':'
    out dx, al
    
    // Print CR2 (faulting address) as 16 hex digits between @ markers
    mov al, '@'
    out dx, al
    mov rax, cr2
    mov rcx, 16
1:
    rol rax, 4
    push rax
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle 2f
    add al, 7
2:
    out dx, al
    pop rax
    dec rcx
    jnz 1b
    mov al, '@'
    out dx, al
    
    // Print error code from stack (at [rsp + 32] due to our 4 pushes)
    mov al, '['
    out dx, al
    mov rax, [rsp + 32]   // error code
    mov rcx, 16
3:
    rol rax, 4
    push rax
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle 4f
    add al, 7
4:
    out dx, al
    pop rax
    dec rcx
    jnz 3b
    mov al, ']'
    out dx, al
    
    // Print "PF!" marker
    mov al, 'P'
    out dx, al
    mov al, 'F'
    out dx, al
    mov al, '!'
    out dx, al
    
    // Halt loop
5:
    cli
    hlt
    jmp 5b

EXCEPTION_HANDLER_NO_ERR 16, 'G'  // x87 FPU error
EXCEPTION_HANDLER_WITH_ERR 17, 'H'  // Alignment check
EXCEPTION_HANDLER_NO_ERR 18, 'I'  // Machine check
EXCEPTION_HANDLER_NO_ERR 19, 'J'  // SIMD exception
EXCEPTION_HANDLER_NO_ERR 20, 'K'  // Virtualization exception
EXCEPTION_HANDLER_WITH_ERR 21, 'L'  // Control protection exception
EXCEPTION_HANDLER_NO_ERR 22, 'M'  // Reserved
EXCEPTION_HANDLER_NO_ERR 23, 'N'  // Reserved
EXCEPTION_HANDLER_NO_ERR 24, 'O'  // Reserved
EXCEPTION_HANDLER_NO_ERR 25, 'P'  // Reserved
EXCEPTION_HANDLER_NO_ERR 26, 'Q'  // Reserved
EXCEPTION_HANDLER_NO_ERR 27, 'R'  // Reserved
EXCEPTION_HANDLER_NO_ERR 28, 'S'  // Reserved
EXCEPTION_HANDLER_WITH_ERR 29, 'T'  // Reserved (some sources say error code)
EXCEPTION_HANDLER_WITH_ERR 30, 'U'  // Reserved (security exception has error code)
EXCEPTION_HANDLER_NO_ERR 31, 'V'  // Reserved

// Handler for INT 32 - User exit syscall
// This handler jumps to the User->Kernel trampoline
// The trampoline address will be patched in at runtime (see TRAMPOLINE_ADDR_OFFSET)
.globl user_exception_handler_32
user_exception_handler_32:
    // Output 'X' to signal user exit attempt
    push rax
    push rdx
    
    mov al, 'X'
    mov dx, {COM1}
    out dx, al
    
    pop rdx
    pop rax
    
    // Jump to User->Kernel trampoline
    // This address will be patched at runtime
    // mov rax, <trampoline_address>
    .byte 0x48, 0xB8  // REX.W + MOV RAX, imm64
.globl user_handler_32_trampoline_addr
user_handler_32_trampoline_addr:
    .quad 0xDEADBEEFDEADBEEF  // Placeholder - will be patched
    
    // jmp rax
    jmp rax

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
    static user_handler_32_trampoline_addr: u64;
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

/// Get the offset of the trampoline address field in handler 32
/// This is where we need to patch the User->Kernel trampoline address
///
/// # Safety
/// Returns offset based on assembly layout
pub unsafe fn get_handler_32_trampoline_offset() -> usize {
    let handler_start = &user_handlers_start as *const u8 as usize;
    let trampoline_field = &user_handler_32_trampoline_addr as *const u64 as usize;
    trampoline_field - handler_start
}
