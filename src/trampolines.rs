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
    /* VERY FIRST THING: Output '@' to show we entered */
    /* Use only RAX and DX - no stack, no memory */
    mov al, '@'
    mov dx, 0x3F8
    out dx, al
    /* Removed infinite loop here */

    /* Debug: Output 'K' before any processing */
    mov al, 'K'
    out dx, al
    
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

    /* Pre-load values for debug output BEFORE CR3 switch */
    /* We'll use these after CR3 when stack isn't safe yet */
    mov dl, '>'      /* Character to output */
    mov bx, 0x3F8    /* UART port */

    /* Load user CR3 - CRITICAL: After this, kernel stack is unmapped! */
    lea rax, [rip + user_cr3_value]
    mov rax, [rax]
    
    /* DEBUG: Print CR3 value BEFORE switching (16 hex digits) */
    mov rcx, rax     /* Save CR3 in RCX */
    mov r8, 16       /* Loop counter */
    
print_cr3_loop:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle 2f
    add al, 7
2:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz print_cr3_loop
    
    /* Output 'C' marker after CR3 value */
    mov al, 'C'
    mov dx, 0x3F8
    out dx, al
    
    /* Restore CR3 value from saved position and switch */
    lea rax, [rip + user_cr3_value]
    mov rax, [rax]
    mov cr3, rax

    /* IMMEDIATELY output to show CR3 switch worked */
    /* This uses pre-loaded registers, no memory or stack access */
    mov al, dl       /* Get the '>' character */
    mov dx, bx       /* Get the port */
    out dx, al       /* Output! */

    /* Explicitly flush TLB for GDT page to ensure we see fresh data */
    /* This is critical because AP may have stale TLB entries */
    lea rax, [rip + gdt_desc]
    mov rax, [rax + 2]    /* Get GDT base from descriptor */
    invlpg [rax]          /* Flush TLB for GDT base page */

    /* DEBUG: Dump entire data section AFTER CR3 switch (reading via USER page tables) */
    mov al, 'D'
    mov dx, 0x3F8
    out dx, al
    mov al, '['
    out dx, al
    
    /* Dump 9 quads: kernel_rsp, user_cr3, gdt_desc[2], idt_desc[2], tss, user_stack, user_entry */
    lea rsi, [rip + k2u_data_start]  /* Start of data section */
    mov r10, 9                        /* Loop counter: 9 quads */
    
dump_quad_loop:
    /* Load quad (8 bytes) from [rsi] - READING VIA USER PAGE TABLES NOW */
    mov rcx, [rsi]                    /* Load 8-byte value */
    mov r8, 16                        /* 16 hex digits per quad */
    
dump_nibble_loop:
    /* Get top nibble of RCX */
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    
    /* Convert to ASCII hex */
    add al, '0'
    cmp al, '9'
    jle 1f
    add al, 7
1:
    mov dx, 0x3F8
    out dx, al
    
    /* Shift left for next nibble */
    shl rcx, 4
    dec r8
    jnz dump_nibble_loop
    
    /* Move to next quad */
    add rsi, 8
    
    /* Print delimiter between quads */
    dec r10
    jz dump_data_done
    mov al, '|'
    mov dx, 0x3F8
    out dx, al
    jmp dump_quad_loop
    
dump_data_done:
    mov al, ']'
    mov dx, 0x3F8
    out dx, al

    /* Set up GDT after switching CR3, before setting RSP */
    lea rax, [rip + gdt_desc]
    lgdt [rax]

    /* NOW switch to user stack (mapped in user page tables) */
    /* This requires memory access via new page tables */
    /* CRITICAL: Cannot use stack here - it's unmapped! */
    lea rax, [rip + user_stack_top]

    /* Debug: Print the ADDRESS we computed (value in RAX) */
    mov rcx, rax     /* Save address in RCX */
    mov r8, 16       /* Loop counter */

print_addr_loop:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle 1f
    add al, 7
1:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz print_addr_loop

    /* Output ':' separator */
    mov al, ':'
    out dx, al

    /* Now restore RAX and do the actual load */
    lea rax, [rip + user_stack_top]

    /* Debug: Output 'L' to show LEA worked */
    /* CRITICAL: Can't use push/AL here - stack unmapped and would corrupt RAX! */
    mov r15, rax     /* Save RAX in R15 (no stack needed) */
    mov al, 'L'
    mov dx, 0x3F8
    out dx, al
    mov rax, r15     /* Restore RAX */

    mov rsp, [rax]   /* CRITICAL: This loads from user page tables! */
    
    /* Debug: Output full RSP value as 16 hex digits */
    mov rcx, rsp     /* Save RSP in RCX */
    mov r8, 16       /* Loop counter: 16 nibbles */
    
output_rsp_loop:
    /* Get top nibble of RCX */
    mov rax, rcx
    shr rax, 60      /* Shift right by 60 bits to get top nibble */
    and eax, 0xF     /* Mask to 4 bits */
    
    /* Convert to ASCII hex */
    add al, '0'
    cmp al, '9'
    jle output_digit
    add al, 7        /* 'A' - '9' - 1 = 7 */
    
output_digit:
    mov dx, 0x3F8
    out dx, al
    
    /* Shift RCX left by 4 bits for next nibble */
    shl rcx, 4
    
    /* Decrement counter and loop */
    dec r8
    jnz output_rsp_loop
    
    /* Output space after the hex value */
    mov al, 0x20
    out dx, al
    
    /* Restore RSP from original value (it's still in RSP register) */

    /* NOW we can use the stack again */
    /* Debug: Output '+' to show stack switch worked */
    push rax
    push rdx
    mov al, '+'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax

    /* Load GDT - segment registers don't need updating since
       both kernel and user GDTs have identical layout */
    lea rax, [rip + gdt_desc]
    lgdt [rax]

    /* Debug: Output 'G' */
    push rax
    push rdx
    mov al, 'G'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax

    /* Load IDT */
    lea rax, [rip + idt_desc]
    lidt [rax]

    /* Debug: Output 'I' */
    push rax
    push rdx
    mov al, 'I'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax

    /* Debug: Try to read from GDT to verify it's accessible */
    /* Read GDTR to get base address */
    sub rsp, 16
    sgdt [rsp]
    mov rax, [rsp + 2]            /* GDT base (starts at offset 2) */
    add rsp, 16
    
    /* Debug: Print the GDT base address we got from SGDT */
    mov rcx, rax     /* Save GDT base in RCX */
    push rcx         /* Save it on stack too */
    mov r8, 16       /* 16 hex digits */
print_gdt_base:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle 1f
    add al, 7
1:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz print_gdt_base
    
    mov al, 'g'      /* lowercase g = about to read from GDT */
    out dx, al
    
    pop rax          /* Restore GDT base */
    
    /* Read first byte of GDT entry 5 (TSS descriptor at offset 0x28) */
    mov rbx, rax
    add rbx, 0x28                 /* TSS descriptor offset */
    mov cl, [rbx]                 /* Read first byte - should be 0x67 (limit low) */
    
    /* Print the byte we read */
    push rax
    push rdx
    /* High nibble */
    mov al, cl
    shr al, 4
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lgdt_byte_hi_ok
    add al, 7
.Lgdt_byte_hi_ok:
    mov dx, 0x3F8
    out dx, al
    /* Low nibble */
    mov al, cl
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lgdt_byte_lo_ok
    add al, 7
.Lgdt_byte_lo_ok:
    out dx, al
    mov al, ':'
    out dx, al
    pop rdx
    pop rax

    /* Load TSS */
    lea rax, [rip + tss_selector]
    movzx eax, word ptr [rax]
    
    ltr ax

    /* Debug: Output 'T' */
    push rax
    push rdx
    mov al, 'T'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax
    
    /* Debug: Read TSS RSP0 and IST1 to verify they're correct */
    /* First get GDT base to find TSS descriptor, then TSS base */
    sub rsp, 16
    sgdt [rsp]
    mov rax, [rsp + 2]   /* GDT base */
    add rsp, 16
    
    /* TSS descriptor is at GDT+0x28, base is at bytes 2-4, 7, and 8-11 */
    /* For simplicity, just read TSS.IST1 which should be at TSS+0x24 */
    add rax, 0x28        /* Point to TSS descriptor */
    
    /* Extract TSS base from descriptor (complex format, skip for now) */
    /* Instead, use the gdt_desc base + TSS offset we know */
    /* TSS is 80 bytes after GDT start in our layout */
    lea rax, [rip + gdt_desc]
    mov rax, [rax + 2]   /* Get GDT base from descriptor */
    add rax, 80          /* TSS is at GDT+80 in our layout */
    
    /* Now RAX points to TSS. Read IST1 at offset 0x24 */
    mov rcx, [rax + 0x24]
    
    /* Output 'S' then IST1 value */
    push rcx
    mov al, 'S'
    mov dx, 0x3F8
    out dx, al
    pop rcx
    
    /* Print IST1 value (16 hex digits) */
    mov r8, 16
print_ist1:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle 1f
    add al, 7
1:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz print_ist1
    
    mov al, ':'
    out dx, al

    /* User stack is already set (we did it right after CR3 switch) */

    /* Debug: Output 'U' before jumping to user code */
    push rax
    push rdx
    mov al, 'U'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax

    /* ================================================================
     * FLUSH TLB for critical interrupt handling pages
     * These pages are set up by BSP but we're running on AP with
     * potentially stale TLB entries after CR3 switch
     * ================================================================ */
    
    /* Flush page 0 (null page - should not be present) */
    xor rax, rax
    invlpg [rax]
    
    /* Flush handler code page (0x3df4000) */
    mov rax, 0x3df4000
    invlpg [rax]
    
    /* Flush GDT/TSS/IDT page (0x3df5000) */
    mov rax, 0x3df5000
    invlpg [rax]
    
    /* Flush interrupt stack pages (0x3df6000 - 0x3dfc000) */
    mov rax, 0x3df6000
    invlpg [rax]
    mov rax, 0x3df7000
    invlpg [rax]
    mov rax, 0x3df8000
    invlpg [rax]
    mov rax, 0x3df9000
    invlpg [rax]
    mov rax, 0x3dfa000
    invlpg [rax]
    mov rax, 0x3dfb000
    invlpg [rax]
    mov rax, 0x3dfc000
    invlpg [rax]
    
    /* Flush user code page (0x400000) */
    mov rax, 0x400000
    invlpg [rax]

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
    
    /* Debug: Print first 8 bytes at user entry point (0x400000) */
    mov rax, [rsp]       /* Get RIP from stack (user entry point) */
    mov rbx, [rax]       /* Read first 8 bytes at that address */
    
    /* Print 'C' for Code, then 8 bytes as hex */
    mov al, 'C'
    mov dx, 0x3F8
    out dx, al
    
    mov rax, rbx
    mov rcx, 16
.Lprint_code:
    rol rax, 4
    push rax
    and al, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lcode_digit_ok
    add al, 7
.Lcode_digit_ok:
    mov dx, 0x3F8
    out dx, al
    pop rax
    dec rcx
    jnz .Lprint_code
    
    mov al, ':'
    mov dx, 0x3F8
    out dx, al
    
    /* Debug: Output 'R' (Ring transition) before iretq */
    mov al, 'R'
    mov dx, 0x3F8
    out dx, al
    
    /* Debug: Read and print IDT entry 32 handler address */
    /* First get IDT base from SIDT */
    sub rsp, 16
    sidt [rsp]
    mov rax, [rsp + 2]   /* IDT base at offset 2 */
    add rsp, 16
    
    /* IDT entry 32 is at base + 32*16 = base + 0x200 */
    add rax, 0x200
    
    /* Read low qword of IDT entry (contains offset_low, selector, IST, type, offset_mid) */
    mov rbx, [rax]
    
    /* Extract handler address:
     * offset_low  = bits 0-15  of rbx
     * offset_mid  = bits 48-63 of rbx
     * offset_high = [rax + 8] bits 0-31
     */
    mov rcx, rbx
    and rcx, 0xFFFF           /* offset_low */
    mov r9, rbx
    shr r9, 48                /* offset_mid */
    shl r9, 16
    or rcx, r9                /* combine low and mid */
    mov r9, [rax + 8]         /* high qword */
    mov r10, 0xFFFFFFFF
    and r9, r10               /* offset_high (mask with reg) */
    shl r9, 32
    or rcx, r9                /* full 64-bit handler address in RCX */
    
    /* Print 'H' then handler address */
    push rcx
    mov al, 'H'
    mov dx, 0x3F8
    out dx, al
    pop rcx
    
    /* Print handler address (16 hex digits) */
    mov r8, 16
.Lprint_handler:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle 1f
    add al, 7
1:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lprint_handler
    
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
    /* Debug: Output 'X' before CR3 switch */
    push rax
    push rdx
    mov al, 'X'
    mov dx, 0x3F8
    out dx, al
    pop rdx
    pop rax

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

    /* Debug: Print 'S' for Stack restored, then RSP value */
    mov al, 'S'
    mov dx, 0x3F8
    out dx, al
    mov rcx, rsp
    mov r8, 16
.Lu2k_print_rsp:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lu2k_rsp_ok
    add al, 7
.Lu2k_rsp_ok:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lu2k_print_rsp
    mov al, 0x20    /* space */
    out dx, al

    /* ================================================================
     * RESTORE KERNEL GDT/IDT
     * K2U pushed these on the stack before saving RSP.
     * Stack layout: [GDT desc 16 bytes][IDT desc 16 bytes][rdx][rax][ret addr]
     * ================================================================ */

    /* Debug: Print GDT descriptor we're about to load */
    mov al, 'G'
    mov dx, 0x3F8
    out dx, al
    mov rcx, [rsp]      /* First 8 bytes of GDT desc (limit + base low) */
    mov r8, 16
.Lu2k_print_gdt:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lu2k_gdt_ok
    add al, 7
.Lu2k_gdt_ok:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lu2k_print_gdt
    mov al, 0x20    /* space */
    out dx, al
    
    /* Pop and restore kernel GDT */
    lgdt [rsp]
    add rsp, 16

    /* Debug: Print IDT descriptor we're about to load */
    mov al, 'I'
    mov dx, 0x3F8
    out dx, al
    mov rcx, [rsp]      /* First 8 bytes of IDT desc (limit + base low) */
    mov r8, 16
.Lu2k_print_idt:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lu2k_idt_ok
    add al, 7
.Lu2k_idt_ok:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lu2k_print_idt
    mov al, 0x20    /* space */
    out dx, al
    
    /* Pop and restore kernel IDT */
    lidt [rsp]
    add rsp, 16

    /* Debug: Verify IDT was loaded correctly using SIDT */
    sub rsp, 16
    sidt [rsp]
    mov al, 'V'     /* V for Verify */
    mov dx, 0x3F8
    out dx, al
    mov rcx, [rsp]
    mov r8, 16
.Lu2k_print_verify:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lu2k_verify_ok
    add al, 7
.Lu2k_verify_ok:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lu2k_print_verify
    add rsp, 16
    mov al, 0x20    /* space */
    mov dx, 0x3F8
    out dx, al

    /* Debug: Output 'K' back in kernel */
    mov al, 'K'
    mov dx, 0x3F8
    out dx, al

    /* Pop the registers K2U saved at the start */
    pop rdx
    pop rax

    /* Debug: Print return address before ret */
    mov rcx, [rsp]    /* Return address is at top of stack */
    push rax
    push rdx
    
    mov al, 0x20    /* space */
    mov dx, 0x3F8
    out dx, al
    mov al, 'R'
    out dx, al
    mov al, 'A'
    out dx, al
    mov al, ':'
    out dx, al
    
    /* Print return address (16 hex digits) */
    mov r8, 16
.Lu2k_print_ret_addr:
    mov rax, rcx
    shr rax, 60
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jle .Lu2k_ret_ok
    add al, 7
.Lu2k_ret_ok:
    mov dx, 0x3F8
    out dx, al
    shl rcx, 4
    dec r8
    jnz .Lu2k_print_ret_addr
    
    mov al, '!'
    mov dx, 0x3F8
    out dx, al
    mov al, 0x0A    /* newline */
    out dx, al
    
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
