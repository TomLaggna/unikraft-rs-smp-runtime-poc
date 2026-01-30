// src/trampolines.rs - CR3-switching trampolines using global_asm
//
// These trampolines handle the transition between kernel and user contexts
// by switching CR3 (page tables), loading appropriate GDT/IDT/TSS, and
// managing the stack pointer.

use core::arch::global_asm;

// Kernel-to-User Trampoline
// This runs in kernel context and switches to user context
global_asm!(
    r#"
.section .text.trampoline_k2u, "ax"
.align 16

.globl trampoline_k2u_start
trampoline_k2u_start:

.globl trampoline_kernel_to_user
trampoline_kernel_to_user:
    /* Now save registers we'll use */
    push rax
    push rdx

    /* ================================================================
     * SAVE KERNEL GDT/IDT ON STACK
     * Push them before saving RSP - U2K will pop them after restore.
     * SGDT/SIDT store 10 bytes, but we use 16-byte aligned slots.
     * ================================================================ */
    
    /* Save kernel IDT descriptor on stack (push first, pop last) */
    sub rsp, 16
    sidt [rsp]
    
    /* Save kernel GDT descriptor on stack */
    sub rsp, 16
    sgdt [rsp]

    /* Save current (kernel) RSP to U2K data section.
     * U2K will restore this after switching back to kernel CR3.
     * Both trampoline pages are mapped in both address spaces.
     * u2k_rsp_save_addr contains the address of kernel_rsp_restore in U2K. */
    lea rax, [rip + u2k_rsp_save_addr]
    mov rax, [rax]      /* rax = address of kernel_rsp_restore in U2K */
    mov [rax], rsp      /* write RSP to that address */

    /* Also save to local kernel_rsp_save for debugging */
    lea rax, [rip + kernel_rsp_save]
    mov [rax], rsp


    /* Load user CR3 - CRITICAL: After this, kernel stack is unmapped! */
    lea rax, [rip + user_cr3_value]
    mov rax, [rax]
    mov cr3, rax


    /* NOW switch to user stack (mapped in user page tables) */
    /* This requires memory access via new page tables */
    lea rax, [rip + user_stack_top]
    mov rsp, [rax]   /* CRITICAL: This loads from user page tables! */

    /* Load GDT */
    lea rax, [rip + gdt_desc]
    lgdt [rax]

    /* Load IDT */
    lea rax, [rip + idt_desc]
    lidt [rax]

    /* Load TSS */
    lea rax, [rip + tss_selector]
    movzx eax, word ptr [rax]
    ltr ax

    /* ================================================================
     * RING TRANSITION: Switch from ring 0 to ring 3 using iretq
     * 
     * iretq expects this stack layout (from bottom to top):
     *   SS     - User data segment selector (0x23 = index 4, RPL=3)
     *   RSP    - User stack pointer
     *   RFLAGS - Flags (we'll use IF=1 to enable interrupts)
     *   CS     - User code segment selector (0x1B = index 3, RPL=3)
     *   RIP    - User entry point
     * ================================================================ */
    
    /* Build iretq stack frame - order is reversed (last push = first pop by iretq) */
    
    /* SS: User data segment selector (GDT index 4, RPL=3) = 0x23 */
    push 0x23
    
    /* RSP: User stack (already loaded earlier) */
    lea rax, [rip + user_stack_top]
    mov rax, [rax]
    push rax
    
    /* RFLAGS: Enable interrupts (IF=1), reserved bit 1 always set = 0x202 */
    pushfq
    pop rax
    or rax, 0x200        /* Set IF (interrupt enable flag) */
    and rax, 0xFFFFFFFFFFFFFEFF /* Clear TF (trap flag) just in case */
    push rax
    
    /* CS: User code segment selector (GDT index 3, RPL=3) = 0x1B */
    push 0x1B
    
    /* RIP: User entry point */
    lea rax, [rip + user_entry_point]
    mov rax, [rax]
    push rax
    
    /* Perform the ring transition! */
    iretq

/* Data section for K->U (patched at runtime) */
/* ALL fields are 8-byte aligned and 8 bytes in size for proper Rust access */
.align 8
.globl k2u_data_start
k2u_data_start:

.align 8
.globl kernel_rsp_save
kernel_rsp_save:
    .quad   0

/* Address of kernel_rsp_restore in U2K data section (patched at runtime) */
.align 8
.globl u2k_rsp_save_addr
u2k_rsp_save_addr:
    .quad   0

.align 8
.globl user_cr3_value
user_cr3_value:
    .quad   0xDEADBEEFDEADBEEF

/* GDT descriptor: Packed 10 bytes for lgdt */
/* Explicitly defined to ensure Limit follows Base immediately */
.align 8
.globl gdt_desc
gdt_desc:
    .space 10       /* limit (2) + base (8) */
    .space 6        /* padding to 16 bytes */

/* IDT descriptor: Packed 10 bytes for lidt */
.align 8
.globl idt_desc
idt_desc:
    .space 10       /* limit (2) + base (8) */
    .space 6        /* padding to 16 bytes */

.align 8
.globl tss_selector
tss_selector:
    .quad   0       /* selector in low 16 bits, rest padding */

.align 8
.globl user_stack_top
user_stack_top:
    .quad   0

.align 8
.globl user_entry_point
user_entry_point:
    .quad   0

.align 8
.globl k2u_data_end
k2u_data_end:

trampoline_k2u_end:
"#
);

// User-to-Kernel Trampoline
// This runs in user context (but at ring 0) and switches back to kernel
global_asm!(
    r#"
.section .text.trampoline_u2k, "ax"
.align 16

.globl trampoline_u2k_start
trampoline_u2k_start:

.globl trampoline_user_to_kernel
trampoline_user_to_kernel:

    /* ================================================================
     * SWITCH CR3 TO KERNEL
     * Both trampoline pages are mapped at the same high VA in both
     * kernel and user address spaces, so we can still access
     * the data section after switching CR3.
     * ================================================================ */
    
    lea rax, [rip + kernel_cr3_value]
    mov rax, [rax]
    mov cr3, rax

    /* Data section is still accessible (mapped in kernel too) */
    
    /* Restore kernel RSP from data section */
    lea rax, [rip + kernel_rsp_restore]
    mov rsp, [rax]
    /* ================================================================
     * RESTORE KERNEL GDT/IDT
     * K2U pushed these on the stack before saving RSP.
     * Stack layout: [GDT desc 16 bytes][IDT desc 16 bytes][rdx][rax][ret addr]
     * ================================================================ */

    
    /* Pop and restore kernel GDT */
    lgdt [rsp]
    add rsp, 16
    
    /* Pop and restore kernel IDT */
    lidt [rsp]
    add rsp, 16    

    pop rdx
    pop rax
    /* Return to caller (K2U's caller - the AP loop) */
    ret

/* Data section for U->K (patched at runtime) */
.align 8
.globl u2k_data_start
u2k_data_start:

.globl kernel_cr3_value
kernel_cr3_value:
    .quad   0xDEADBEEFDEADBEEF

.globl kernel_rsp_restore
kernel_rsp_restore:
    .quad   0

.align 8
.globl u2k_data_end
u2k_data_end:

trampoline_u2k_end:
"#
);

// External symbols from assembly
extern "C" {
    static trampoline_k2u_start: u8;
    static trampoline_k2u_end: u8;
    static k2u_data_start: u8;
    static k2u_data_end: u8;

    static trampoline_u2k_start: u8;
    static trampoline_u2k_end: u8;
    static u2k_data_start: u8;
    static u2k_data_end: u8;

    // Data fields in K->U trampoline
    static mut kernel_rsp_save: u64;
    static mut u2k_rsp_save_addr: u64;
    static mut user_cr3_value: u64;
    static mut gdt_desc: [u8; 16]; // Packed: Limit (2) + Base (8) + Padding (6)
    static mut idt_desc: [u8; 16]; // Packed: Limit (2) + Base (8) + Padding (6)
    static mut tss_selector: u64; // selector in low 16 bits
    static mut user_stack_top: u64;
    static mut user_entry_point: u64;

    // Data fields in U->K trampoline
    static mut kernel_cr3_value: u64;
    static mut kernel_rsp_restore: u64;

    // Entry points
    fn trampoline_kernel_to_user() -> !;
    fn trampoline_user_to_kernel() -> !;
}

/// Get K->U trampoline code as byte slice
pub unsafe fn get_k2u_code() -> &'static [u8] {
    let start = &trampoline_k2u_start as *const u8;
    let end = &trampoline_k2u_end as *const u8;
    let size = end as usize - start as usize;
    core::slice::from_raw_parts(start, size)
}

/// Get U->K trampoline code as byte slice
pub unsafe fn get_u2k_code() -> &'static [u8] {
    let start = &trampoline_u2k_start as *const u8;
    let end = &trampoline_u2k_end as *const u8;
    let size = end as usize - start as usize;
    core::slice::from_raw_parts(start, size)
}

/// Get offset of data section in K->U trampoline
pub unsafe fn get_k2u_data_offset() -> usize {
    let code_start = &trampoline_k2u_start as *const u8 as usize;
    let data_start = &k2u_data_start as *const u8 as usize;
    data_start - code_start
}

/// Get offset of data section in U->K trampoline
pub unsafe fn get_u2k_data_offset() -> usize {
    let code_start = &trampoline_u2k_start as *const u8 as usize;
    let data_start = &u2k_data_start as *const u8 as usize;
    data_start - code_start
}

/// Offsets of specific fields in K->U trampoline (from start of code)
/// These are calculated at runtime from symbol addresses
pub mod k2u_offsets {
    use super::*;

    pub unsafe fn kernel_rsp_save() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::kernel_rsp_save as *const u64 as usize;
        field - start
    }

    pub unsafe fn u2k_rsp_save_addr() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::u2k_rsp_save_addr as *const u64 as usize;
        field - start
    }

    pub unsafe fn user_cr3_value() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::user_cr3_value as *const u64 as usize;
        field - start
    }

    pub unsafe fn gdt_desc() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::gdt_desc as *const [u8; 16] as usize;
        field - start
    }

    pub unsafe fn idt_desc() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::idt_desc as *const [u8; 16] as usize;
        field - start
    }

    pub unsafe fn tss_selector() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::tss_selector as *const u64 as usize;
        field - start
    }

    pub unsafe fn user_stack_top() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::user_stack_top as *const u64 as usize;
        field - start
    }

    pub unsafe fn user_entry_point() -> usize {
        let start = &trampoline_k2u_start as *const u8 as usize;
        let field = &super::user_entry_point as *const u64 as usize;
        field - start
    }
}

/// Offsets of specific fields in U->K trampoline (from start of code)
pub mod u2k_offsets {
    use super::*;

    pub unsafe fn kernel_cr3_value() -> usize {
        let start = &trampoline_u2k_start as *const u8 as usize;
        let field = &super::kernel_cr3_value as *const u64 as usize;
        field - start
    }

    pub unsafe fn kernel_rsp_restore() -> usize {
        let start = &trampoline_u2k_start as *const u8 as usize;
        let field = &super::kernel_rsp_restore as *const u64 as usize;
        field - start
    }
}

/// Get entry point address for K->U trampoline
pub unsafe fn get_k2u_entry() -> u64 {
    trampoline_kernel_to_user as u64
}

/// Get entry point address for U->K trampoline
pub unsafe fn get_u2k_entry() -> u64 {
    trampoline_user_to_kernel as u64
}
