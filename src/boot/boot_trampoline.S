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
	.quad	0x8000		/* Default target address in first 1MB */

/*
 * Macros for position-independent code in 16-bit section
 * These create relocation entries that must be patched at runtime
 */
.macro mov_start16 sym:req, reg:req, bytes:req
	mov	$0x1516, \reg	/* Placeholder: IS16 */
.globl	\sym\()_imm\bytes\()_start16
.set	\sym\()_imm\bytes\()_start16, (. - \bytes)
	nop
.endm

.macro data_start16 type:req, sym:req, bytes:req
.globl	\sym\()_data\bytes\()_start16
.set	\sym\()_data\bytes\()_start16, .
	.\type	0x1516		/* Placeholder: IS16 */
.endm

/* ========================================================================== */
/* 16-BIT REAL MODE SECTION - Entry point from SIPI                          */
/* ========================================================================== */

.section .text.boot.16, "ax"
.globl x86_start16_begin
x86_start16_begin:

.code16
.globl lcpu_start16_ap
ENTRY(lcpu_start16_ap)
	/* Clear pointers to startup and platform boot parameters */
	xorl	%edi, %edi
	xorl	%esi, %esi

	mov_start16	lcpu_start16, %ax, 2
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
	data_start16	long, gdt32, 4	/* GDT address	*/
gdt32_cs:
	.quad	GDT_DESC_CODE32_VAL	/* 32-bit CS	*/
gdt32_ds:
	.quad	GDT_DESC_DATA32_VAL	/* DS		*/
gdt32_end:

#define CR0_BOOT16_SETTINGS	X86_CR0_PE	/* Protected mode */

.code16
ENTRY(lcpu_start16)
	/* Disable interrupts */
	cli

	/* Setup protected mode */
	movl	$CR0_BOOT16_SETTINGS, %eax
	movl	%eax, %cr0

	/* Load 32-bit GDT and jump into 32-bit code segment */
	mov_start16	gdt32_ptr, %ax, 2
	lgdt	(%eax)

	/* ljmp encoding: 0xEA <offset:32> <segment:16>
	 * We patch the offset at runtime
	 */
	mov_start16	jump_to32, %ax, 2
	movw	%ax, -4(%eax)
	ljmp	$(gdt32_cs - gdt32), $0x1532	/* 0x1532 = IS32 placeholder */

.code32
.globl jump_to32
jump_to32:
	/* Set up remaining segment registers */
	movl	$(gdt32_ds - gdt32), %eax
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %ds

	xorl	%eax, %eax
	movl	%eax, %fs
	movl	%eax, %gs

	mov_start16	lcpu_start32, %eax, 4

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
	/* Enable physical address extension (PAE) */
	movl	$CR4_BOOT32_SETTINGS, %eax
	movl	%eax, %cr4

	/* Switch to IA-32e mode (long mode) */
	xorl	%edx, %edx
	movl	$EFER_BOOT32_SETTINGS, %eax
	movl	$X86_MSR_EFER, %ecx
	wrmsr

	/* Set boot page table and enable paging
	 * NOTE: x86_bpt_pml4 must be set by the BSP before starting APs
	 */
	movl	x86_bpt_pml4_addr, %eax
	movl	%eax, %cr3

	movl	$CR0_BOOT32_SETTINGS, %eax
	movl	%eax, %cr0

	/* Load 64-bit GDT and jump to 64-bit code segment */
	movl	$gdt64_ptr, %eax
	lgdt	(%eax)

	/* Setup far jump address */
	movl	$jump_to64, %eax
	movl	%eax, -6(%eax)
	ljmp	$(gdt64_cs - gdt64), $0x1532	/* 0x1532 = IS32 placeholder */

.code64
jump_to64:
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
	/* Save the startup args pointer (if any) */
	movq	%rdi, %r8

	/* Request basic CPU features and APIC ID */
	movl	$1, %eax
	cpuid
	shrl	$24, %ebx		/* APIC ID now in EBX */

	/* Use APIC_ID * LCPU_SIZE for indexing the cpu structure */
	movl	$LCPU_SIZE, %eax
	imul	%ebx, %eax

	/* Compute pointer into CPU struct array and store it in RBP */
	leaq	lcpus(%rip), %rbp
	addq	%rax, %rbp

	/* Put CPU into init state */
	movl	$LCPU_STATE_INIT, LCPU_STATE_OFFSET(%rbp)

	/* ====================================================================
	 * Enable FPU and SSE
	 * ==================================================================== */
	movq	%cr0, %rdi
	orl	$(X86_CR0_NE | X86_CR0_MP), %edi
	movq	%rdi, %cr0

	fninit

	jmp	ldmxcsr_rval_addr + 0x4

ldmxcsr_rval_addr:
	.long	0x1f80		/* Power-on default */

	movq	%cr4, %rdi
	orl	$(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT), %edi
	movq	%rdi, %cr4

	leaq	ldmxcsr_rval_addr(%rip), %rbx
	ldmxcsr	(%rbx)

	/* ====================================================================
	 * Enable XSAVE (if available)
	 * ==================================================================== */
	testl	$(X86_CPUID1_ECX_XSAVE), %ecx
	jz	no_xsave

	movq	%cr4, %rdi
	orl	$(X86_CR4_OSXSAVE), %edi
	movq	%rdi, %cr4

no_xsave:

	/* ====================================================================
	 * Enable AVX (if available)
	 * ==================================================================== */
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
	movl	$7, %eax
	xorl	%ecx, %ecx
	cpuid

	/* ====================================================================
	 * Enable FS and GS base (if available)
	 * ==================================================================== */
	testl	$(X86_CPUID7_EBX_FSGSBASE), %ebx
	jz	no_fsgsbase

	movq	%cr4, %rdi
	orl	$(X86_CR4_FSGSBASE), %edi
	movq	%rdi, %cr4

no_fsgsbase:

	/* ====================================================================
	 * Check if we have startup arguments supplied
	 * ==================================================================== */
	test	%r8, %r8
	jz	no_args

	/* Initialize the CPU configuration with the supplied startup args */
	movq	LCPU_SARGS_ENTRY_OFFSET(%r8), %rax
	movq	LCPU_SARGS_STACKP_OFFSET(%r8), %rsp

	jmp	jump_to_entry

no_args:
	/* Load the stack pointer and the entry address from the CPU struct */
	movq	LCPU_ENTRY_OFFSET(%rbp), %rax
	movq	LCPU_STACKP_OFFSET(%rbp), %rsp

jump_to_entry:
	/* Align stack to 16-byte boundary (System V AMD64 ABI requirement) */
	andq	$~0xf, %rsp
	subq	$0x8, %rsp

	movq	%rbp, %rdi
	xorq	%rbp, %rbp		/* Reset frame pointer */

	/* Jump to entry function
	 * Arguments:
	 * RDI = struct lcpu* (or APIC ID for Rust)
	 */
	jmp	*%rax

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
