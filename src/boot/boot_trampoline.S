/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Extracted and adapted from Unikraft's plat/kvm/x86/lcpu_start.S
 * for standalone use in Rust applications.
 *
 * This is the complete x86_64 multi-core boot trampoline that brings
 * Application Processors (APs) from 16-bit real mode to 64-bit long mode.
 *
 * IMPORTANT: This code must be copied to a page-aligned address in the
 * first 1 MiB of physical memory (e.g., 0x8000) before sending SIPIs.
 */

#include "boot_defs.h"

/* Section markers for runtime relocation */
.section .data
.globl x86_start16_addr
x86_start16_addr:
	.quad	0x8000		/* Target address in first 1MB */

/* ========================================================================== */
/* 16-BIT REAL MODE SECTION - Entry point from SIPI                          */
/* ========================================================================== */

.section .text.boot.16, "ax"
.globl x86_start16_begin
x86_start16_begin:

.code16  /* GCC's 16-bit mode - handles 32-bit operands properly */
.globl lcpu_start16_ap
ENTRY(lcpu_start16_ap)
	/* Debug: Send 'A' to COM1 (0x3F8) to signal AP started */
	/* movb	$'A', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Clear pointers to startup and platform boot parameters */
	xorl	%edi, %edi
	xorl	%esi, %esi

	/* Debug: Send 'B' before address calculation */
	/* movb	$'B', %al */
	/* outb	%al, %dx */

	/* Load address of lcpu_start16 */
	movw	$lcpu_start16, %ax
	/* On start-up a core's %cs is set depending on the value of the vector
	 * inside the SIPI message, so make sure we are jumping to the
	 * proper address w.r.t. segmentation.
	 */
	movl	%cs, %ebx
	shll	$4, %ebx
	subl	%ebx, %eax
	jmp	*%eax
END(lcpu_start16_ap)

/*
 * 16-bit boot entry function
 */
.align 16
.globl gdt32
gdt32:
/* Repurpose null segment to encode the GDT pointer */
gdt32_null:
	.word	0x0000
.globl gdt32_ptr
gdt32_ptr:
	.word	(gdt32_end - gdt32 - 1)	/* size - 1	*/
	.long	gdt32			/* GDT address - linker calculates */
gdt32_cs:
	.quad	GDT_DESC_CODE32_VAL	/* 32-bit CS	*/
gdt32_ds:
	.quad	GDT_DESC_DATA32_VAL	/* DS		*/
gdt32_end:

#define CR0_BOOT16_SETTINGS	X86_CR0_PE	/* Protected mode */

.code16
ENTRY(lcpu_start16)
	/* Debug: Send 'C' - reached lcpu_start16 */
	/* movb	$'C', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Disable interrupts */
	cli

	/* Setup protected mode */
	movl	$CR0_BOOT16_SETTINGS, %eax
	movl	%eax, %cr0

	/* Load 32-bit GDT and jump into 32-bit code segment */
	movw	$gdt32_ptr, %ax
	lgdt	(%eax)

	/* ljmp to 32-bit code */
	movw	$jump_to32, %ax
	movw	%ax, -4(%eax)
	ljmp	$(gdt32_cs - gdt32), $jump_to32

.code32
.globl jump_to32
jump_to32:
	/* Debug: Send 'D' - in 32-bit mode */
	/* movb	$'D', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Set up remaining segment registers */
	movl	$(gdt32_ds - gdt32), %eax
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %ds

	xorl	%eax, %eax
	movl	%eax, %fs
	movl	%eax, %gs

	/* Jump to 32-bit entry - use full 32-bit address in 32-bit mode */
	movl	$lcpu_start32, %eax
	jmp	*%eax
END(lcpu_start16)

.globl x86_start16_end
x86_start16_end:

/* ========================================================================== */
/* 32-BIT PROTECTED MODE SECTION                                              */
/* ========================================================================== */

.section .data.boot.32
.align 16
gdt64:
gdt64_null:
	.quad	0x0000000000000000	/* null segment */
gdt64_cs:
	.quad	GDT_DESC_CODE64_VAL	/* 64-bit CS	*/
gdt64_ds:
	.quad	GDT_DESC_DATA64_VAL	/* DS		*/
gdt64_end:
gdt64_ptr:
	.word	gdt64_end - gdt64 - 1
	.quad	gdt64			/* Will be relocated */

#define CR4_BOOT32_SETTINGS	X86_CR4_PAE	/* Physical Address Extension */
#define EFER_BOOT32_SETTINGS	X86_EFER_LME	/* IA-32e Mode */
#define CR0_BOOT32_SETTINGS	(X86_CR0_PE | X86_CR0_WP | X86_CR0_PG)

.code32
.section .text.boot.32
.globl lcpu_start32
ENTRY(lcpu_start32)
	/* Debug: Send 'E' - in lcpu_start32 */
	/* movb	$'E', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Enable physical address extension (PAE) */
	movl	$CR4_BOOT32_SETTINGS, %eax
	movl	%eax, %cr4

	/* Debug: Send '1' - PAE enabled */
	/* movb	$'1', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Switch to IA-32e mode (long mode) */
	xorl	%edx, %edx
	movl	$EFER_BOOT32_SETTINGS, %eax
	movl	$X86_MSR_EFER, %ecx
	wrmsr

	/* Debug: Send '2' - long mode enabled in EFER */
	/* movb	$'2', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Set boot page table and enable paging
	 * NOTE: x86_bpt_pml4 must be set by the BSP before starting APs
	 */
	movl	x86_bpt_pml4_addr, %eax
	movl	%eax, %cr3

	/* Flush TLB by reloading CR3 */
	movl	%cr3, %eax
	movl	%eax, %cr3

	/* Debug: Send '3' - CR3 loaded */
	/* movb	$'3', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	movl	$CR0_BOOT32_SETTINGS, %eax
	movl	%eax, %cr0

	/* Debug: Send '4' - paging enabled */
	/* movb	$'4', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Load 64-bit GDT and jump to 64-bit code segment */
	movl	$gdt64_ptr, %eax
	lgdt	(%eax)

	/* Setup far jump address */
	movl	$jump_to64, %eax
	movl	%eax, -6(%eax)
	ljmp	$(gdt64_cs - gdt64), $0x1532	/* 0x1532 = IS32 placeholder */

.code64
jump_to64:
	/* Debug: Send 'F' - in 64-bit mode! */
	/* movb	$'F', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Set up remaining segment registers */
	movl	$(gdt64_ds - gdt64), %eax
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %ds

	xorl	%eax, %eax
	movl	%eax, %fs
	movl	%eax, %gs

	leaq	lcpu_start64(%rip), %rcx
	jmp	*%rcx
END(lcpu_start32)

/* ========================================================================== */
/* 64-BIT LONG MODE SECTION                                                   */
/* ========================================================================== */

.code64
.section .text.boot.64
.globl lcpu_start64
ENTRY(lcpu_start64)
	/* Debug: Send 'G' - in lcpu_start64 */
	/* movb	$'G', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */
	
	/* Save the startup args pointer (if any) */
	movq	%rdi, %r8

	/* Request basic CPU features and APIC ID */
	movl	$1, %eax
	cpuid
	shrl	$24, %ebx		/* APIC ID now in EBX */

	/* Debug: Send 'H' - got APIC ID */
	/* movb	$'H', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Use APIC_ID * LCPU_SIZE for indexing the cpu structure */
	movl	$LCPU_SIZE, %eax
	imul	%ebx, %eax

	/* Compute pointer into CPU struct array and store it in RBP */
	leaq	lcpus(%rip), %rbp
	addq	%rax, %rbp

	/* Debug: Send 'I' - computed CPU struct pointer */
	/* movb	$'I', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Debug: Send nibble of %rbp byte 6 to check address range */
	/* movq	%rbp, %rax */
	/* shrq	$48, %rax */
	/* andb	$0x0F, %al */
	/* cmpb	$10, %al */
	/* jl	1f */
	/* addb	$('A' - 10), %al */
	/* jmp	2f */
/* 1:	addb	$'0', %al */
/* 2:	movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Put CPU into init state */
	movl	$LCPU_STATE_INIT, LCPU_STATE_OFFSET(%rbp)

	/* Debug: Send 'J' - set state to INIT */
	/* movb	$'J', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* ====================================================================
	 * Enable FPU and SSE
	 * ==================================================================== */
	movq	%cr0, %rdi
	orl	$(X86_CR0_NE | X86_CR0_MP), %edi
	movq	%rdi, %cr0

	fninit

	/* Debug: Send 'K' - FPU initialized */
	/* movb	$'K', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	jmp	ldmxcsr_rval_addr + 0x4

ldmxcsr_rval_addr:
	.long	0x1f80		/* Power-on default */

	/* Debug: Send 'L' - after jump over data */
	/* movb	$'L', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	movq	%cr4, %rdi
	orl	$(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT), %edi
	movq	%rdi, %cr4

	/* Debug: Send 'M' - CR4 SSE flags set */
	/* movb	$'M', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Debug: Send 'N' - about to leaq */
	/* movb	$'N', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	leaq	ldmxcsr_rval_addr(%rip), %rbx
	
	/* Debug: Send 'O' - about to ldmxcsr */
	/* movb	$'O', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	ldmxcsr	(%rbx)

	/* Debug: Send 'P' - ldmxcsr done */
	/* movb	$'P', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* ====================================================================
	 * Enable XSAVE (if available)
	 * ==================================================================== */
	/* Debug: Send 'Q' - checking XSAVE */
	/* movb	$'Q', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	testl	$(X86_CPUID1_ECX_XSAVE), %ecx
	jz	no_xsave

	movq	%cr4, %rdi
	orl	$(X86_CR4_OSXSAVE), %edi
	movq	%rdi, %cr4

no_xsave:

	/* ====================================================================
	 * Enable AVX (if available)
	 * ==================================================================== */
	/* Debug: Send 'R' - checking AVX */
	/* movb	$'R', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	testl	$(X86_CPUID1_ECX_AVX), %ecx
	jz	no_avx

	movq	%rcx, %rdi
	xorl	%ecx, %ecx
	xgetbv
	orl	$(X86_XCR0_SSE | X86_XCR0_AVX), %eax
	xsetbv
	movq	%rdi, %rcx

no_avx:

	/* ====================================================================
	 * Request extended CPU features
	 * ==================================================================== */
	/* Debug: Send 'S' - about to CPUID(7) */
	/* movb	$'S', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	movl	$7, %eax
	xorl	%ecx, %ecx
	cpuid

	/* ====================================================================
	 * Enable FS and GS base (if available)
	 * ==================================================================== */
	/* Debug: Send 'T' - checking FSGSBASE */
	/* movb	$'T', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	testl	$(X86_CPUID7_EBX_FSGSBASE), %ebx
	jz	no_fsgsbase

	movq	%cr4, %rdi
	orl	$(X86_CR4_FSGSBASE), %edi
	movq	%rdi, %cr4

no_fsgsbase:

	/* ====================================================================
	 * Check if we have startup arguments supplied
	 * ==================================================================== */
	/* Debug: Send 'U' - about to check args */
	/* movb	$'U', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	test	%r8, %r8
	jz	no_args

	/* Initialize the CPU configuration with the supplied startup args */
	movq	LCPU_SARGS_ENTRY_OFFSET(%r8), %rax
	movq	LCPU_SARGS_STACKP_OFFSET(%r8), %rsp

	jmp	jump_to_entry

no_args:
	/* Debug: Send 'V' - loading from CPU struct */
	/* movb	$'V', %al */
	/* movw	$0x3F8, %dx */
	/* outb	%al, %dx */

	/* Load the stack pointer and the entry address from the CPU struct */
	movq	LCPU_ENTRY_OFFSET(%rbp), %rax
	movq	LCPU_STACKP_OFFSET(%rbp), %rsp

jump_to_entry:
	/* Save entry address before any operations that might corrupt %rax */
	movq	%rax, %r15
	
	/* Copy CPU struct pointer from %rbp to %rdi (first argument for Rust) */
	movq	%rbp, %rdi

	/* Set up minimal IDT with page fault handler */
	subq	$4096, %rsp
	movq	%rsp, %rbx
	
	/* Clear IDT (256 entries * 16 bytes = 4096 bytes) */
	movq	%rbx, %rcx
	movq	$512, %r8
.Lclear_idt:
	movq	$0, (%rcx)
	addq	$8, %rcx
	decq	%r8
	jnz	.Lclear_idt
	
	/* Set up page fault handler (vector 14) */
	leaq	page_fault_handler(%rip), %rax
	leaq	0xE0(%rbx), %rcx	/* Entry 14 * 16 bytes */
	
	movw	%ax, 0(%rcx)		/* offset_low */
	movw	$0x08, 2(%rcx)		/* selector */
	movb	$0, 4(%rcx)		/* IST */
	movb	$0x8E, 5(%rcx)		/* type_attr: present, DPL=0, interrupt gate */
	shrq	$16, %rax
	movw	%ax, 6(%rcx)		/* offset_mid */
	shrq	$16, %rax
	movl	%eax, 8(%rcx)		/* offset_high */
	
	/* Load IDT */
	subq	$16, %rsp
	movw	$4095, (%rsp)		/* limit */
	movq	%rbx, 2(%rsp)		/* base */
	lidt	(%rsp)
	addq	$16, %rsp
	addq	$4096, %rsp

	/* Align stack to 16-byte boundary (System V AMD64 ABI requirement) */
	andq	$~0xf, %rsp

	/* Clear all registers except %rdi (arg) and %r15 (entry address) */
	xorq	%rax, %rax
	xorq	%rbx, %rbx
	xorq	%rcx, %rcx
	xorq	%rdx, %rdx
	xorq	%rsi, %rsi
	xorq	%rbp, %rbp
	xorq	%r8, %r8
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14

	/* Jump to Rust entry point */
	jmp	*%r15
	
	/* If we get here, something went wrong */
	movb	$'?', %al
	movw	$0x3F8, %dx
	outb	%al, %dx
	jmp	fail_loop

/* Minimal page fault handler - outputs 'F' and halts */
page_fault_handler:
	pushq	%rax
	pushq	%rdx
	
	/* Output 'F' for page fault */
	movb	$'F', %al
	movw	$0x3F8, %dx
	outb	%al, %dx
	
	popq	%rdx
	popq	%rax
	
	/* Halt */
	cli
1:	hlt
	jmp	1b

fail:
	movl	$LCPU_STATE_HALTED, LCPU_STATE_OFFSET(%rbp)

fail_loop:
	cli
1:
	hlt
	jmp	1b
END(lcpu_start64)

/* ========================================================================== */
/* DATA SECTION - Must be initialized by BSP                                  */
/* ========================================================================== */

.section .data
.align 4096

/* Page table address - set this before starting APs */
.globl x86_bpt_pml4_addr
x86_bpt_pml4_addr:
	.long	0x10a000		/* Default from Unikraft kernel */

/* Per-CPU structures - must match Rust CpuData layout */
.globl lcpus
.align 64
lcpus:
	.fill	(LCPU_SIZE * LCPU_MAXCOUNT), 1, 0




/* Helper macros */
.macro ENTRY name
.globl \name
.type \name, @function
\name:
.endm

.macro END name
.size \name, . - \name
.endm
