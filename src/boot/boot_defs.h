/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Definitions extracted from Unikraft for boot trampoline
 */

#ifndef __BOOT_DEFS_H__
#define __BOOT_DEFS_H__

/* ========================================================================== */
/* x86 Control Register Bits                                                  */
/* ========================================================================== */

/* CR0 */
#define X86_CR0_PE	(1 << 0)	/* Protection Enable */
#define X86_CR0_MP	(1 << 1)	/* Monitor Coprocessor */
#define X86_CR0_EM	(1 << 2)	/* Emulation */
#define X86_CR0_TS	(1 << 3)	/* Task Switched */
#define X86_CR0_ET	(1 << 4)	/* Extension Type */
#define X86_CR0_NE	(1 << 5)	/* Numeric Error */
#define X86_CR0_WP	(1 << 16)	/* Write Protect */
#define X86_CR0_AM	(1 << 18)	/* Alignment Mask */
#define X86_CR0_NW	(1 << 29)	/* Not Write-through */
#define X86_CR0_CD	(1 << 30)	/* Cache Disable */
#define X86_CR0_PG	(1 << 31)	/* Paging */

/* CR4 */
#define X86_CR4_VME		(1 << 0)	/* Virtual-8086 Mode Extensions */
#define X86_CR4_PVI		(1 << 1)	/* Protected-Mode Virtual Interrupts */
#define X86_CR4_TSD		(1 << 2)	/* Time Stamp Disable */
#define X86_CR4_DE		(1 << 3)	/* Debugging Extensions */
#define X86_CR4_PSE		(1 << 4)	/* Page Size Extensions */
#define X86_CR4_PAE		(1 << 5)	/* Physical Address Extension */
#define X86_CR4_MCE		(1 << 6)	/* Machine-Check Enable */
#define X86_CR4_PGE		(1 << 7)	/* Page Global Enable */
#define X86_CR4_PCE		(1 << 8)	/* Performance-Monitoring Counter Enable */
#define X86_CR4_OSFXSR		(1 << 9)	/* OS Support for FXSAVE/FXRSTOR */
#define X86_CR4_OSXMMEXCPT	(1 << 10)	/* OS Support for Unmasked SIMD FP Exceptions */
#define X86_CR4_UMIP		(1 << 11)	/* User-Mode Instruction Prevention */
#define X86_CR4_LA57		(1 << 12)	/* 57-bit Linear Addresses */
#define X86_CR4_VMXE		(1 << 13)	/* VMX Enable */
#define X86_CR4_SMXE		(1 << 14)	/* SMX Enable */
#define X86_CR4_FSGSBASE	(1 << 16)	/* FSGSBASE Enable */
#define X86_CR4_PCIDE		(1 << 17)	/* PCID Enable */
#define X86_CR4_OSXSAVE		(1 << 18)	/* XSAVE and Processor Extended States Enable */
#define X86_CR4_SMEP		(1 << 20)	/* Supervisor Mode Execution Protection */
#define X86_CR4_SMAP		(1 << 21)	/* Supervisor Mode Access Prevention */
#define X86_CR4_PKE		(1 << 22)	/* Protection Key Enable */

/* ========================================================================== */
/* MSR Numbers                                                                */
/* ========================================================================== */

#define X86_MSR_EFER		0xc0000080	/* Extended Feature Enable Register */
#define X86_MSR_STAR		0xc0000081	/* Syscall Target Address */
#define X86_MSR_LSTAR		0xc0000082	/* Long Mode Syscall Target Address */

/* EFER bits */
#define X86_EFER_SCE	(1 << 0)	/* Syscall Enable */
#define X86_EFER_LME	(1 << 8)	/* Long Mode Enable */
#define X86_EFER_LMA	(1 << 10)	/* Long Mode Active */
#define X86_EFER_NXE	(1 << 11)	/* No-Execute Enable */

/* ========================================================================== */
/* CPUID Feature Bits                                                         */
/* ========================================================================== */

/* CPUID.1:ECX */
#define X86_CPUID1_ECX_SSE3	(1 << 0)	/* SSE3 */
#define X86_CPUID1_ECX_PCLMUL	(1 << 1)	/* PCLMULQDQ */
#define X86_CPUID1_ECX_DTES64	(1 << 2)	/* 64-bit DS Area */
#define X86_CPUID1_ECX_MONITOR	(1 << 3)	/* MONITOR/MWAIT */
#define X86_CPUID1_ECX_DSCPL	(1 << 4)	/* CPL Qualified Debug Store */
#define X86_CPUID1_ECX_VMX	(1 << 5)	/* Virtual Machine Extensions */
#define X86_CPUID1_ECX_SMX	(1 << 6)	/* Safer Mode Extensions */
#define X86_CPUID1_ECX_EST	(1 << 7)	/* Enhanced SpeedStep */
#define X86_CPUID1_ECX_TM2	(1 << 8)	/* Thermal Monitor 2 */
#define X86_CPUID1_ECX_SSSE3	(1 << 9)	/* SSSE3 */
#define X86_CPUID1_ECX_CNXTID	(1 << 10)	/* L1 Context ID */
#define X86_CPUID1_ECX_FMA	(1 << 12)	/* Fused Multiply Add */
#define X86_CPUID1_ECX_CX16	(1 << 13)	/* CMPXCHG16B */
#define X86_CPUID1_ECX_XTPR	(1 << 14)	/* xTPR Update Control */
#define X86_CPUID1_ECX_PDCM	(1 << 15)	/* Perfmon and Debug Capability */
#define X86_CPUID1_ECX_PCID	(1 << 17)	/* Process-context identifiers */
#define X86_CPUID1_ECX_DCA	(1 << 18)	/* Direct Cache Access */
#define X86_CPUID1_ECX_SSE4_1	(1 << 19)	/* SSE4.1 */
#define X86_CPUID1_ECX_SSE4_2	(1 << 20)	/* SSE4.2 */
#define X86_CPUID1_ECX_x2APIC	(1 << 21)	/* x2APIC */
#define X86_CPUID1_ECX_MOVBE	(1 << 22)	/* MOVBE */
#define X86_CPUID1_ECX_POPCNT	(1 << 23)	/* POPCNT */
#define X86_CPUID1_ECX_TSC	(1 << 24)	/* TSC-Deadline */
#define X86_CPUID1_ECX_AES	(1 << 25)	/* AES */
#define X86_CPUID1_ECX_XSAVE	(1 << 26)	/* XSAVE */
#define X86_CPUID1_ECX_OSXSAVE	(1 << 27)	/* OSXSAVE */
#define X86_CPUID1_ECX_AVX	(1 << 28)	/* AVX */
#define X86_CPUID1_ECX_F16C	(1 << 29)	/* F16C */
#define X86_CPUID1_ECX_RDRAND	(1 << 30)	/* RDRAND */

/* CPUID.7.0:EBX */
#define X86_CPUID7_EBX_FSGSBASE	(1 << 0)	/* FSGSBASE */
#define X86_CPUID7_EBX_TSC_ADJ	(1 << 1)	/* IA32_TSC_ADJUST */
#define X86_CPUID7_EBX_SGX	(1 << 2)	/* SGX */
#define X86_CPUID7_EBX_BMI1	(1 << 3)	/* BMI1 */
#define X86_CPUID7_EBX_HLE	(1 << 4)	/* HLE */
#define X86_CPUID7_EBX_AVX2	(1 << 5)	/* AVX2 */
#define X86_CPUID7_EBX_SMEP	(1 << 7)	/* SMEP */
#define X86_CPUID7_EBX_BMI2	(1 << 8)	/* BMI2 */
#define X86_CPUID7_EBX_ERMS	(1 << 9)	/* Enhanced REP MOVSB/STOSB */
#define X86_CPUID7_EBX_INVPCID	(1 << 10)	/* INVPCID */
#define X86_CPUID7_EBX_RTM	(1 << 11)	/* RTM */
#define X86_CPUID7_EBX_PQM	(1 << 12)	/* PQM */
#define X86_CPUID7_EBX_MPX	(1 << 14)	/* MPX */
#define X86_CPUID7_EBX_PQE	(1 << 15)	/* PQE */
#define X86_CPUID7_EBX_AVX512F	(1 << 16)	/* AVX512F */

/* CPUID.7.0:ECX */
#define X86_CPUID7_ECX_PKU	(1 << 3)	/* Protection Keys for Userspace */
#define X86_CPUID7_ECX_OSPKE	(1 << 4)	/* OS Support for Protection Keys */

/* ========================================================================== */
/* XCR0 (XSAVE Control Register)                                              */
/* ========================================================================== */

#define X86_XCR0_FPU	(1 << 0)	/* x87 FPU */
#define X86_XCR0_SSE	(1 << 1)	/* SSE */
#define X86_XCR0_AVX	(1 << 2)	/* AVX */
#define X86_XCR0_BNDREG	(1 << 3)	/* MPX BND0-3 */
#define X86_XCR0_BNDCSR	(1 << 4)	/* MPX BNDCFGU, BNDSTATUS */
#define X86_XCR0_OPMASK	(1 << 5)	/* AVX-512 opmask */
#define X86_XCR0_ZMM_HI	(1 << 6)	/* AVX-512 ZMM_Hi256 */
#define X86_XCR0_HI16	(1 << 7)	/* AVX-512 Hi16_ZMM */
#define X86_XCR0_PKRU	(1 << 9)	/* Protection Key */

/* ========================================================================== */
/* GDT Descriptor Values                                                      */
/* ========================================================================== */

/* 32-bit GDT descriptors */
#define GDT_DESC_CODE32_VAL	0x00cf9a000000ffff	/* 32-bit code, readable, 4GB */
#define GDT_DESC_DATA32_VAL	0x00cf92000000ffff	/* 32-bit data, writable, 4GB */

/* 64-bit GDT descriptors - Ring 0 (kernel) */
#define GDT_DESC_CODE64_VAL	0x00af9a000000ffff	/* 64-bit code, readable, DPL=0 */
#define GDT_DESC_DATA64_VAL	0x00af92000000ffff	/* 64-bit data, writable, DPL=0 */

/* 64-bit GDT descriptors - Ring 3 (user space) */
#define GDT_DESC_CODE64_USER_VAL	0x00affa000000ffff	/* 64-bit code, readable, DPL=3 */
#define GDT_DESC_DATA64_USER_VAL	0x00aff2000000ffff	/* 64-bit data, writable, DPL=3 */

/* GDT Selector constants (index << 3 | RPL) */
#define GDT_SEL_KERN_CODE\t0x08\t/* Kernel code segment (index 1, RPL=0) */
#define GDT_SEL_KERN_DATA\t0x10\t/* Kernel data segment (index 2, RPL=0) */
#define GDT_SEL_USER_CODE\t0x1B\t/* User code segment (index 3, RPL=3) */
#define GDT_SEL_USER_DATA\t0x23\t/* User data segment (index 4, RPL=3) */

/* ========================================================================== */
/* LCPU Structure Offsets (must match Rust CpuData)                           */
/* ========================================================================== */

#define LCPU_STATE_OFFSET	0x00
#define LCPU_IDX_OFFSET		0x04
#define LCPU_ID_OFFSET		0x08

#define LCPU_SARGS_ENTRY_OFFSET	0x10
#define LCPU_SARGS_STACKP_OFFSET 0x18

#define LCPU_ENTRY_OFFSET	0x10
#define LCPU_STACKP_OFFSET	0x18

#define LCPU_SIZE		0x40	/* 64 bytes per CPU */
#define LCPU_MAXCOUNT		16	/* Max CPUs supported */

/* LCPU States */
#define LCPU_STATE_OFFLINE	0
#define LCPU_STATE_INIT		1
#define LCPU_STATE_IDLE		2
#define LCPU_STATE_BUSY0	3
#define LCPU_STATE_HALTED	-2147483648	/* INT_MIN */

/* ========================================================================== */
/* Assembly Entry/Exit Macros                                                 */
/* ========================================================================== */

#define ENTRY(name) \
	.globl name; \
	.type name, @function; \
name:

#define END(name) \
	.size name, . - name

#endif /* __BOOT_DEFS_H__ */
