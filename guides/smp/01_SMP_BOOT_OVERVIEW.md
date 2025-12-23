# SMP Boot Process Overview

## Goal
Get an Application Processor (AP) to execute Rust code and print "Hello World" to the console, without using Unikraft's built-in SMP support (which is not available in the prebuilt kernel).

## Context
- **Prebuilt Unikraft kernel**: Does NOT have SMP functionality linked
- **Target platform**: x86-64 on QEMU/KVM with 4 CPUs
- **Starting point**: BSP (Bootstrap Processor, CPU 0) is already running our Rust main() function
- **Challenge**: Manually implement the AP startup sequence that Unikraft normally provides

## x86-64 Multi-Core Boot Process

### CPU States at Boot
1. **BSP (CPU 0)**: Boots normally, goes through BIOS/bootloader, enters kernel, runs our code
2. **APs (CPU 1-3)**: Start in a halted state, waiting for SIPI (Startup Inter-Processor Interrupt)

### The Boot Sequence

```
BSP:                              AP (e.g., CPU 1):
====                              =================
1. Boot normally                  1. [HALTED - waiting]
2. Initialize system              
3. Setup boot trampoline          
4. Send INIT IPI ----------------> 2. Reset CPU state
5. Wait 10ms                      3. [Wait for SIPI]
6. Send SIPI with vector --------> 4. **WAKE UP** at vector*4096 in real mode
7. Wait 200us                        (e.g., vector=0x8 → start at 0x8000)
8. Send SIPI again --------------> 5. Execute trampoline code:
9. Wait for AP to signal ready       - Real mode (16-bit)
                                     - Switch to protected mode (32-bit)
                                     - Switch to long mode (64-bit)
                                     - Jump to our Rust entry point
                                  6. Execute Rust code (ap_entry)
                                  7. Print "Hello World"
```

## The Boot Trampoline

The **boot trampoline** is a small piece of assembly code that:
- Starts execution in **16-bit real mode** (because that's what the CPU starts in after SIPI)
- Sets up a minimal GDT (Global Descriptor Table)
- Switches to **32-bit protected mode**
- Enables PAE (Physical Address Extension) and long mode
- Loads page tables (from CR3)
- Switches to **64-bit long mode**
- Jumps to a 64-bit Rust entry point

### Trampoline Location
- **Must be in the first 1 MiB** of physical memory (real mode addressing limitation)
- **Must be page-aligned** (4096-byte boundary)
- Common address: `0x8000` (32 KiB into physical memory)
- Unikraft kernel **might** already have trampoline code at a low address, OR we need to copy it there

## Critical Requirements

### 1. Boot Trampoline Code
- Location: First 1 MiB, page-aligned (e.g., 0x8000)
- Contains: 16-bit → 32-bit → 64-bit transition code
- Status: We have extracted it from Unikraft (boot_trampoline.S)
- Question: Does kernel already have it in memory, or do we copy it?

### 2. Page Tables (CR3)
- APs need the **same page table** as the BSP
- BSP's CR3 register points to the page table root (PML4)
- Trampoline loads this into the AP's CR3
- Source: Read from BSP's CR3, write to trampoline's data structure

### 3. Per-CPU Data Structures
- Each AP needs configuration:
  - **Entry point**: Address of `ap_entry` function
  - **Stack pointer**: Unique stack for this AP
  - **APIC ID**: To identify which CPU this is
- Structure: `CpuData` in boot_trampoline_bindings.rs
- Populated by BSP before sending SIPI

### 4. Stack for AP
- Each AP needs its own stack (no sharing!)
- Size: 16 KiB per CPU (reasonable minimum)
- Allocation: BSP allocates before starting AP
- Stack pointer: Top of stack (grows downward)

### 5. Entry Point Function
- Function: `ap_entry(cpu_data: *const CpuData)`
- Called from trampoline in 64-bit long mode
- Receives pointer to its CpuData structure
- Must not return (loop forever after printing)

## Current Implementation Status

### ✅ What We Have
1. Boot trampoline assembly code (boot_trampoline.S)
2. Rust bindings structure (boot_trampoline_bindings.rs)
3. x2APIC functions for sending IPIs
4. AP entry point function in main.rs
5. CpuData structure definition
6. Serial console printing (println! via std)

### ❌ What's Currently Broken (PIE Conversion)
1. **Boot trampoline is NOT being copied** to low memory
   - boot_trampoline_bindings.rs just has placeholder stubs
   - Methods print "Info: handled by kernel" but do nothing
2. **Per-CPU data structures NOT initialized**
3. **Page table address NOT set in trampoline**
4. **Stack NOT allocated for APs**
5. **Entry point NOT configured in CpuData**

### Why APs Aren't Running Our Code
The kernel might be starting the CPUs (it reports success), but:
- APs don't know WHERE to jump after booting
- They have no stack to use
- They might be running kernel's default idle loop
- Our `ap_entry` function is never called

## Next Steps Overview

To fix this, we need to:

1. **Restore boot trampoline functionality** while keeping PIE compatibility
2. **Copy trampoline to low memory** (0x8000)
3. **Read BSP's CR3** and store in trampoline data
4. **Allocate stacks** for each AP
5. **Initialize CpuData** for each AP with entry point and stack
6. **Send proper SIPI sequence** with correct vector

The next documents will detail each step.
