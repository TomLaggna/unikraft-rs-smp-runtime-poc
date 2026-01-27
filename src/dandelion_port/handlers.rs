//! Interrupt Handlers for Unikraft Engine
//!
//! This module provides interrupt handlers for vectors 0-32.
//! Vector 32 (INT 32) is used as the "return to kernel" syscall,
//! which jumps to the U2K trampoline.
//!
//! Handler structure:
//! - Vectors 0-7: No error code, push dummy + vector, jump to common
//! - Vector 8 (Double Fault): Has error code, push vector, jump to common
//! - Vectors 9, 15, 16, 18, 19, 20, 21+: No error code
//! - Vectors 10-14, 17: Have error code
//! - Vector 32: INT 32 handler - jumps to U2K trampoline

use super::{UnikraftResult, UnikraftError};

// ============================================================================
// Handler Code
// ============================================================================

/// Get the compiled handler code as a byte slice
///
/// The handlers are position-independent and can be copied to any
/// page-aligned address. The U2K trampoline address must be patched
/// into the INT 32 handler after copying.
pub fn get_handler_code() -> &'static [u8] {
    HANDLER_CODE
}

/// Get the offset of each handler within the handler code block
///
/// Returns an array of 33 offsets (vectors 0-32)
pub fn get_handler_offsets() -> [usize; 33] {
    HANDLER_OFFSETS
}

/// Get the offset where the U2K trampoline address needs to be patched
/// (within the INT 32 handler)
pub fn get_u2k_patch_offset() -> usize {
    U2K_PATCH_OFFSET
}

// ============================================================================
// Handler Implementation
// ============================================================================

/// Size of each handler stub (must be consistent)
const HANDLER_STUB_SIZE: usize = 16;

/// Offset within handler code where U2K address is stored (for patching)
const U2K_PATCH_OFFSET: usize = 33 * HANDLER_STUB_SIZE;

/// Handler offsets (vector N is at offset HANDLER_OFFSETS[N])
static HANDLER_OFFSETS: [usize; 33] = [
    0 * HANDLER_STUB_SIZE,   // Vector 0: Divide Error
    1 * HANDLER_STUB_SIZE,   // Vector 1: Debug
    2 * HANDLER_STUB_SIZE,   // Vector 2: NMI
    3 * HANDLER_STUB_SIZE,   // Vector 3: Breakpoint
    4 * HANDLER_STUB_SIZE,   // Vector 4: Overflow
    5 * HANDLER_STUB_SIZE,   // Vector 5: Bound Range
    6 * HANDLER_STUB_SIZE,   // Vector 6: Invalid Opcode
    7 * HANDLER_STUB_SIZE,   // Vector 7: Device Not Available
    8 * HANDLER_STUB_SIZE,   // Vector 8: Double Fault (has error code)
    9 * HANDLER_STUB_SIZE,   // Vector 9: Coprocessor Segment
    10 * HANDLER_STUB_SIZE,  // Vector 10: Invalid TSS (has error code)
    11 * HANDLER_STUB_SIZE,  // Vector 11: Segment Not Present (has error code)
    12 * HANDLER_STUB_SIZE,  // Vector 12: Stack Fault (has error code)
    13 * HANDLER_STUB_SIZE,  // Vector 13: General Protection (has error code)
    14 * HANDLER_STUB_SIZE,  // Vector 14: Page Fault (has error code)
    15 * HANDLER_STUB_SIZE,  // Vector 15: Reserved
    16 * HANDLER_STUB_SIZE,  // Vector 16: x87 FPU Error
    17 * HANDLER_STUB_SIZE,  // Vector 17: Alignment Check (has error code)
    18 * HANDLER_STUB_SIZE,  // Vector 18: Machine Check
    19 * HANDLER_STUB_SIZE,  // Vector 19: SIMD Exception
    20 * HANDLER_STUB_SIZE,  // Vector 20: Virtualization
    21 * HANDLER_STUB_SIZE,  // Vector 21: Control Protection (has error code)
    22 * HANDLER_STUB_SIZE,  // Vector 22-28: Reserved
    23 * HANDLER_STUB_SIZE,
    24 * HANDLER_STUB_SIZE,
    25 * HANDLER_STUB_SIZE,
    26 * HANDLER_STUB_SIZE,
    27 * HANDLER_STUB_SIZE,
    28 * HANDLER_STUB_SIZE,
    29 * HANDLER_STUB_SIZE,  // Vector 29: VMM Communication
    30 * HANDLER_STUB_SIZE,  // Vector 30: Security Exception (has error code)
    31 * HANDLER_STUB_SIZE,  // Vector 31: Reserved
    32 * HANDLER_STUB_SIZE,  // Vector 32: INT 32 - Return to kernel
];

/// Vectors that push an error code automatically
const VECTORS_WITH_ERROR_CODE: [u8; 9] = [8, 10, 11, 12, 13, 14, 17, 21, 30];

/// Handler machine code
///
/// Structure of each 16-byte handler stub:
/// - No error code: push 0; push vector; jmp common_handler
/// - With error code: nop; nop; push vector; jmp common_handler
///
/// The common handler then jumps to U2K trampoline.
///
/// For INT 32 specifically, we directly jump to U2K since it's the
/// "return to kernel" syscall.
static HANDLER_CODE: &[u8] = &[
    // === Vector 0: Divide Error (no error code) ===
    0x6A, 0x00,              // push 0 (dummy error code)
    0x6A, 0x00,              // push 0 (vector number)
    0xE9, 0x00, 0x00, 0x00, 0x00,  // jmp common_handler (offset patched)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // padding
    
    // === Vector 1: Debug (no error code) ===
    0x6A, 0x00,              // push 0
    0x6A, 0x01,              // push 1
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 2: NMI (no error code) ===
    0x6A, 0x00,
    0x6A, 0x02,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 3: Breakpoint (no error code) ===
    0x6A, 0x00,
    0x6A, 0x03,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 4: Overflow (no error code) ===
    0x6A, 0x00,
    0x6A, 0x04,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 5: Bound Range (no error code) ===
    0x6A, 0x00,
    0x6A, 0x05,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 6: Invalid Opcode (no error code) ===
    0x6A, 0x00,
    0x6A, 0x06,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 7: Device Not Available (no error code) ===
    0x6A, 0x00,
    0x6A, 0x07,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 8: Double Fault (HAS error code) ===
    0x90, 0x90,              // nop; nop (CPU pushed error code)
    0x6A, 0x08,              // push 8
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 9: Coprocessor Segment (no error code) ===
    0x6A, 0x00,
    0x6A, 0x09,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 10: Invalid TSS (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x0A,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 11: Segment Not Present (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x0B,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 12: Stack Fault (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x0C,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 13: General Protection (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x0D,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 14: Page Fault (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x0E,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 15: Reserved (no error code) ===
    0x6A, 0x00,
    0x6A, 0x0F,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 16: x87 FPU Error (no error code) ===
    0x6A, 0x00,
    0x6A, 0x10,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 17: Alignment Check (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x11,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 18: Machine Check (no error code) ===
    0x6A, 0x00,
    0x6A, 0x12,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 19: SIMD Exception (no error code) ===
    0x6A, 0x00,
    0x6A, 0x13,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 20: Virtualization (no error code) ===
    0x6A, 0x00,
    0x6A, 0x14,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 21: Control Protection (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x15,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vectors 22-28: Reserved (no error code) ===
    0x6A, 0x00, 0x6A, 0x16, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x17, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x18, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x19, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x1A, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x1B, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x6A, 0x00, 0x6A, 0x1C, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 29: VMM Communication (no error code) ===
    0x6A, 0x00,
    0x6A, 0x1D,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 30: Security Exception (HAS error code) ===
    0x90, 0x90,
    0x6A, 0x1E,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 31: Reserved (no error code) ===
    0x6A, 0x00,
    0x6A, 0x1F,
    0xE9, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === Vector 32: INT 32 - Return to kernel (no error code) ===
    // This jumps directly to U2K trampoline
    // jmp [rip + u2k_addr]  -- 6 bytes: FF 25 00 00 00 00
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // === U2K trampoline address (patched at setup time) ===
    // This is at offset U2K_PATCH_OFFSET (33 * 16 = 528)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    
    // === Common handler (jumps to U2K after saving state) ===
    // Stack at this point: [error_code] [vector] [RIP] [CS] [RFLAGS] [RSP] [SS]
    // For faults, we need to jump to U2K to return to kernel
    // jmp [rip + u2k_addr]
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // offset to u2k_addr filled by patcher
];

/// Patch handler code with U2K trampoline address and jump offsets
///
/// # Arguments
/// * `storage` - Guest memory buffer
/// * `handler_offset` - Offset of handler code in storage
/// * `u2k_va` - Virtual address of U2K trampoline
pub fn patch_handlers(
    storage: &mut [u8],
    handler_offset: usize,
    u2k_va: u64,
) -> UnikraftResult<()> {
    // Patch the U2K address at the end of handler code
    let u2k_addr_offset = handler_offset + U2K_PATCH_OFFSET;
    storage[u2k_addr_offset..u2k_addr_offset + 8].copy_from_slice(&u2k_va.to_le_bytes());
    
    // Patch INT 32 handler to use the U2K address
    // The jmp [rip+0] at vector 32 needs to point to the U2K address
    // jmp [rip+X] where X is the distance from end of instruction to u2k_addr
    let int32_jmp_offset = handler_offset + 32 * HANDLER_STUB_SIZE + 2; // after FF 25
    let distance = U2K_PATCH_OFFSET as i32 - (32 * HANDLER_STUB_SIZE + 6) as i32;
    storage[int32_jmp_offset..int32_jmp_offset + 4].copy_from_slice(&distance.to_le_bytes());
    
    // Patch common handler's jmp to U2K
    let common_handler_offset = handler_offset + U2K_PATCH_OFFSET + 8;
    let common_jmp_rel_offset = common_handler_offset + 2;
    let distance = (u2k_addr_offset as i32) - (common_handler_offset as i32 + 6);
    storage[common_jmp_rel_offset..common_jmp_rel_offset + 4].copy_from_slice(&distance.to_le_bytes());
    
    // Patch each handler stub's jmp to common_handler
    for vector in 0..32 {
        let stub_offset = handler_offset + vector * HANDLER_STUB_SIZE;
        let jmp_offset = if VECTORS_WITH_ERROR_CODE.contains(&(vector as u8)) {
            stub_offset + 4  // After nop; nop; push vector
        } else {
            stub_offset + 4  // After push 0; push vector
        };
        let jmp_rel_offset = jmp_offset + 1;  // After E9
        let distance = (common_handler_offset as i32) - (jmp_offset as i32 + 5);
        storage[jmp_rel_offset..jmp_rel_offset + 4].copy_from_slice(&distance.to_le_bytes());
    }
    
    Ok(())
}
