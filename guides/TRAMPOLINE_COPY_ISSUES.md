# Boot Trampoline Copying Issues - Analysis

## Your Questions

### Q1: "We're only copying 112 bytes (16-bit section). Don't we need the entire trampoline?"

**YES! You're absolutely correct.**

Currently copying:
```
x86_start16_begin → x86_start16_end = 112 bytes (.text.boot.16 only)
```

But the trampoline has 4 sections:
```
.text.boot.16  →  0x70 bytes  (112 bytes) - 16-bit real mode code
.data.boot.32  →  0x22 bytes  ( 34 bytes) - GDT64 tables for 64-bit
.text.boot.32  →  0x57 bytes  ( 87 bytes) - 32-bit protected mode code
.text.boot.64  →  0xc9 bytes  (201 bytes) - 64-bit long mode code
-----------------------------------------------------------
TOTAL          →  434 bytes minimum
```

**The 32-bit and 64-bit sections aren't even being linked!** The Rust linker only pulled in symbols we reference (x86_start16_begin, x86_start16_end, etc.) but not the unreferenced 32/64-bit code.

### Q2: "What are the 0x1516 placeholders for? Shouldn't we just use relative jumps?"

**The placeholders are for INTERNAL addresses within the trampoline**, not for CR3!

Example from the code:
```asm
mov_start16 lcpu_start16, %ax, 2
```

This expands to:
```asm
mov $0x1516, %ax    ; Placeholder - needs patching
nop
```

At runtime, we need to patch `0x1516` with:
```
0x8000 + offset_of(lcpu_start16 relative to x86_start16_begin)
```

**Why not relative jumps?** Because in 16-bit real mode:
- Segmentation is active (CS:IP addressing)
- Can't use RIP-relative addressing (that's 64-bit only)
- Absolute addresses are required for segment calculations

## The Two Separate Address Types

### Type 1: Trampoline Internal Addresses (0x1516 placeholders)
**What:** Addresses of code/data WITHIN the copied trampoline  
**When patched:** At runtime after copying to 0x8000  
**Examples:**
- `lcpu_start16` → 0x8000 + 0x38
- `lcpu_start32` → 0x8000 + 0x70 + 0x34 (after 16-bit + data sections)
- `gdt32_ptr` → 0x8000 + 0x48

### Type 2: Runtime System State (actual variables)
**What:** Dynamic values read from the running system  
**When set:** At runtime before sending SIPI  
**Examples:**
- `x86_bpt_pml4_addr` ← Read CR3 value
- `lcpus[i].entry` ← Address of `ap_entry` function
- `lcpus[i].stack_ptr` ← Allocated stack pointer

## Why The Current Code Crashes

When the AP reaches 32-bit mode:
```asm
movl x86_bpt_pml4_addr, %eax  ; Load CR3 address
movl %eax, %cr3               ; Set page table
```

But `x86_bpt_pml4_addr` is at a **high address** in the PIE binary (0x62000), not in the copied low memory at 0x8000!

The 16-bit code can't access high memory, so it crashes.

## Solutions

### Option 1: Copy Everything Contiguously (HARD)
1. Reference all sections to force linker to include them
2. Create a custom linker script to lay them out contiguously
3. Copy the entire blob to 0x8000
4. Patch all internal addresses

**Problem:** The sections are scattered in the ELF, hard to extract contiguously.

### Option 2: Separate Memory Regions (EASIER)
1. Keep 32/64-bit code in high memory (they can run anywhere)
2. Only copy 16-bit code to 0x8000 (required for SIPI)
3. Have 16-bit code jump to high memory for 32-bit transition

**Problem:** 16-bit code can't directly address high memory.

### Option 3: Use Kernel's Existing Trampoline (EASIEST)
The Unikraft kernel **must already have a working trampoline** for its own use!

1. Find where kernel placed its trampoline (probably 0x8000 or 0x9000)
2. Patch the kernel's `lcpus[]` array
3. Don't copy our own code at all

**Advantage:** Kernel already solved all these problems.

### Option 4: Embed as Binary Blob (MEDIUM)
1. Compile trampoline as standalone binary with custom linker script
2. Use `objcopy` to extract raw binary
3. Use `include_bytes!()` to embed in Rust
4. Copy the blob which is already contiguous

**Advantage:** All sections guaranteed contiguous, simple to copy.

## Recommended Approach

**Start with Option 3** - Find and use the kernel's trampoline:

```rust
// Don't copy our own trampoline
// Just find where kernel put its trampoline
let kernel_trampoline_addr = find_kernel_trampoline()?; // 0x8000 or 0x9000

// Patch the kernel's lcpus array
let kernel_lcpus = (kernel_trampoline_addr + offset_to_lcpus) as *mut [CpuData; 256];
unsafe {
    (*kernel_lcpus)[1] = CpuData::init(...);
}
```

If that doesn't work, fall back to **Option 4** - proper binary blob.

## What To Do Next

1. **First, verify kernel's trampoline exists:**
   ```bash
   # Dump first 1MB of memory when kernel boots
   # Look for tell-tale patterns
   ```

2. **Check if kernel populated x86_bpt_pml4_addr:**
   ```rust
   unsafe {
       let kernel_cr3 = ptr::read_volatile(&x86_bpt_pml4_addr);
       println!("Kernel set CR3 to: 0x{:x}", kernel_cr3);
   }
   ```

3. **If kernel has working trampoline, just patch its lcpus array**

4. **If not, implement Option 4 (binary blob approach)**

## Why Your Questions Were Spot-On

You identified the exact two problems:
1. ✅ Not copying enough code (missing 32/64-bit sections)
2. ✅ Confused about what relocations are for (internal vs runtime addresses)

Both are critical issues that would prevent the trampoline from working!
