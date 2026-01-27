# Dandelion ELF Integration Guide

This document analyzes how Dandelion's KVM execution engine loads and runs ELF files, and compares it to our proof-of-concept (PoC) implementation. The goal is to identify what we already have and what needs to be added to support Dandelion SDK ELF files.

## Overview

Dandelion SDK creates ELF executables with a standardized interface for I/O through a special symbol `__dandelion_system_data`. The runtime is responsible for:
1. Parsing the ELF to extract code, entry point, and the system data symbol
2. Setting up an isolated address space with page tables, GDT, TSS, and IDT
3. Writing input data and metadata to the `DandelionSystemData` struct
4. Executing the user code
5. Reading output data from the context after execution

## 1. ELF Parsing

### Dandelion Approach

Dandelion parses ELF files to extract:
- **Entry point** (`e_entry`) - where execution begins
- **Loadable segments** (PT_LOAD, `p_type == 0x1`) - code and data to copy to memory
- **Symbol table** - to find `__dandelion_system_data` offset
- **Memory protection flags** - to set page permissions (R/W/X)

```rust
// From Dandelion's kvm.rs parse_function()
let parsed_elf = ParsedElf::new(&function)?;
let entry_point = parsed_elf.get_entry_point();
let (layout, source) = parsed_elf.get_layout_pair();
let (system_data_offset, _) = parsed_elf.get_symbol_by_name(&function, "__dandelion_system_data")?;
```

### What We Have (PoC)

✅ **Already implemented in `src/elfloader/elf_parser.rs`:**
- `ParsedElf::new()` - parses ELF header, program headers, section headers, symbol table
- `get_entry_point()` - returns `e_entry`
- `get_layout_pair()` - returns (requirements, items) pairs for PT_LOAD segments
- `get_symbol_by_name()` - looks up symbols like `__dandelion_system_data`
- `get_memory_protection_layout()` - returns protection flags per segment

### What's Missing

❌ **We haven't integrated the ELF parser with our execution flow:**
- Currently using hardcoded assembly in `user_code.rs`
- Need to load ELF segments into `guest_mem` at their virtual addresses
- Need to pass entry point to trampoline setup

## 2. Memory Layout Comparison

### Dandelion KVM Layout

Dandelion allocates a `guest_mem` buffer (64MB-128MB typical) and lays out:

```
Low addresses:
┌─────────────────────────────┐ 0x0
│ ELF Code/Data (loaded at   │
│ p_vaddr from ELF segments) │
├─────────────────────────────┤ (grows up)
│ Input Data                  │
│ (DataSets with buffers)    │
├─────────────────────────────┤
│ DandelionSystemData struct │ ← __dandelion_system_data offset
│ Input/Output set metadata  │
├─────────────────────────────┤
│ Heap                       │
│ (heap_begin to heap_end)   │
├─────────────────────────────┤
│ (gap)                      │
├─────────────────────────────┤ stack_start (calculated)
│ Interrupt handlers (1 page)│
│ GDT (80 bytes)             │
│ TSS (104 bytes)            │
│ IDT (33 entries × 16 bytes)│
├─────────────────────────────┤
│ Stack (grows down)         │
├─────────────────────────────┤
│ Page Tables                │
│ PT → PD → PDPT → PML4     │
└─────────────────────────────┘ guest_mem.len()
High addresses
```

### Our PoC Layout

```
Low addresses:
┌─────────────────────────────┐ 0x0
│ User Code (hardcoded ASM)  │
│ User Stack                 │
├─────────────────────────────┤ END_OF_USER_SPACE (~0x10_0000)
│ (gap)                      │
├─────────────────────────────┤ interrupt_config.base_offset
│ GDT (10 entries × 8 bytes) │
│ TSS (104 bytes)            │
│ IDT (33 entries × 16 bytes)│
│ Interrupt Handlers         │
├─────────────────────────────┤ TRAMPOLINE_TABLES
│ K2U Table (2KB)            │
│ U2K Table (2KB)            │
├─────────────────────────────┤ PAGE_TABLE_OFFSET
│ PT (512 × 8 bytes)         │
│ PD (512 × 8 bytes)         │
│ PDPT (512 × 8 bytes)       │
│ PML4 (512 × 8 bytes)       │
└─────────────────────────────┘ 64MB (GUEST_MEM_SIZE)
High addresses
```

### Comparison

| Aspect | Dandelion KVM | Our PoC | Status |
|--------|---------------|---------|--------|
| guest_mem allocation | mmap ANONYMOUS | `Vec<u8>` 64MB | ✅ Same concept |
| ELF loading | Copy segments to p_vaddr | Hardcoded at 0x0 | ❌ Need integration |
| Page tables at top | Yes (high addresses) | Yes | ✅ Same |
| GDT/TSS/IDT | Before page tables | Middle of buffer | ⚠️ Different location |
| Interrupt handlers | Same page as GDT | Separate section | ⚠️ Could consolidate |
| Stack | Between heap and tables | At low addresses | ⚠️ Different strategy |
| Trampolines | Not needed (KVM runs at ring 3) | Required (kernel runs at ring 0) | N/A |

## 3. DandelionSystemData Interface

### The Critical Structure

```rust
#[repr(C)]
pub struct DandelionSystemData<PtrT, SizeT> {
    exit_code: c_int,           // Set by user code on exit
    heap_begin: PtrT,           // Start of usable heap
    heap_end: PtrT,             // End of usable heap
    input_sets_len: SizeT,      // Number of input sets
    input_sets: PtrT,           // Pointer to IoSetInfo array
    output_sets_len: SizeT,     // Number of output sets  
    output_sets: PtrT,          // Pointer to IoSetInfo array
    input_bufs: PtrT,           // Pointer to input IoBufferDescriptor array
    output_bufs: PtrT,          // Pointer to output IoBufferDescriptor array (set by user)
}

#[repr(C)]
struct IoSetInfo<PtrT, SizeT> {
    ident: PtrT,      // Pointer to name string
    ident_len: SizeT, // Length of name
    offset: SizeT,    // Index into buffer array where this set's buffers start
}

#[repr(C)]
struct IoBufferDescriptor<PtrT, SizeT> {
    ident: PtrT,      // Pointer to buffer name string
    ident_len: SizeT, // Length of name
    data: PtrT,       // Pointer to actual data
    data_len: SizeT,  // Size of data
    key: SizeT,       // Key for sharding/grouping
}
```

### Dandelion Flow

**Before execution (`setup_input_structs`):**
1. Write input data to context memory
2. Build `IoSetInfo` and `IoBufferDescriptor` arrays in memory
3. Fill in `DandelionSystemData` struct at the symbol offset
4. Set `heap_begin` after all data, `heap_end` before stack

**After execution (`read_output_structs`):**
1. Read `DandelionSystemData` from symbol offset
2. Check `exit_code` for success/failure
3. Follow `output_sets` and `output_bufs` pointers to read output data
4. Parse output `IoSetInfo` and `IoBufferDescriptor` arrays

### What We Have (PoC)

❌ **Not implemented.** Our current PoC:
- Uses hardcoded user code that doesn't follow Dandelion interface
- No input/output data passing mechanism
- No `DandelionSystemData` setup

### What's Missing

We need to implement:
1. `setup_input_structs()` - write input metadata before execution
2. `read_output_structs()` - parse output metadata after execution
3. DataSet/DataItem structures for organizing I/O data
4. Memory allocation tracking within guest_mem

## 4. GDT/TSS/IDT Setup

### Dandelion KVM Approach

Dandelion runs user code in KVM's ring 3 directly. The setup is simpler:

```rust
// GDT: 5 entries (80 bytes)
// Entry 0: Null
// Entry 1: Code segment (DPL=0)
// Entry 2: Data segment (DPL=0)  
// Entry 3: User code (DPL=3)
// Entry 4: User data (DPL=3)
// Entry 5-6: TSS (16 bytes for 64-bit TSS descriptor)

// TSS: 104 bytes
// - IST entries for interrupt stacks
// - I/O permission bitmap

// IDT: 33 entries (vectors 0-32)
// Each 16 bytes, points to fault handler
// All set to privilege level 3 (accessible from user mode)
```

### Our PoC Approach

We run inside Unikraft (already in ring 0) and transition to ring 3:

```rust
// GDT: 10 entries (80 bytes)
// Entry 0: Null
// Entry 1: Kernel Code 64-bit
// Entry 2: Kernel Data
// Entry 3: Kernel Code 32-bit (for AP bootstrap)
// Entry 4: User Code 64-bit (DPL=3)
// Entry 5: User Data (DPL=3)
// Entry 6-7: TSS (16 bytes)
// Entries 8-9: Reserved

// TSS: 104 bytes (similar to Dandelion)
// IDT: 33 entries (similar to Dandelion)
```

### Comparison

| Aspect | Dandelion KVM | Our PoC | Status |
|--------|---------------|---------|--------|
| GDT entries | 5 + TSS | 8 + TSS | ⚠️ We have extra entries |
| TSS structure | 104 bytes | 104 bytes | ✅ Same |
| IDT entries | 33 (vectors 0-32) | 33 (vectors 0-32) | ✅ Same |
| Handler privilege | DPL=3 | DPL=3 | ✅ Same |

## 5. Page Table Setup

### Dandelion Approach

```rust
// 4-level paging: PML4 → PDPT → PD → PT
// Allocate from high addresses working backwards
// Identity-map all of guest_mem
// Use 2MB huge pages where possible, 4KB for fine-grained control
```

### Our PoC Approach

```rust
// 4-level paging: PML4 → PDPT → PD → PT
// Tables at high end of guest_mem
// Map user space at low addresses
// Map trampolines at high VA (~2TB)
// Use 4KB pages for user space
```

### Comparison

| Aspect | Dandelion KVM | Our PoC | Status |
|--------|---------------|---------|--------|
| 4-level paging | Yes | Yes | ✅ Same |
| Tables at high addresses | Yes | Yes | ✅ Same |
| Huge page support | 2MB pages | 2MB for kernel | ⚠️ Not for user |
| Trampoline mapping | Not needed | Required | N/A |

## 6. Execution Flow Comparison

### Dandelion KVM Flow

```
1. parse_function()
   └─ Parse ELF, get entry_point and system_data_offset
   
2. load_static()
   └─ Copy ELF segments to static context
   
3. KvmLoop::run()
   ├─ setup_input_structs() - write input data and metadata
   ├─ Create memory region for KVM
   ├─ init_vcpu()
   │   ├─ set_page_table() - build 4-level page tables
   │   ├─ set_interrupt_table() - setup GDT/TSS/IDT
   │   └─ Set initial registers (RIP=entry, RSP=stack_start)
   ├─ KVM run loop until HLT instruction
   └─ read_output_structs() - parse output data
```

### Our PoC Flow

```
1. Create UserSpaceManager
   └─ Allocate 64MB guest_mem
   
2. Map user code (hardcoded)
   └─ Copy assembly to guest_mem at VA 0x0
   
3. Setup interrupt infrastructure
   ├─ setup_gdt() - create GDT entries
   ├─ setup_tss() - create TSS with IST
   └─ setup_idt() - create 33 interrupt gates
   
4. Install handlers and trampolines
   ├─ install_handlers() - copy fault handlers
   ├─ Copy K2U and U2K trampolines
   └─ Patch data sections with addresses
   
5. Execute via trampoline
   ├─ save_kernel_state_and_call_k2u()
   │   └─ K2U loads user CR3, GDT, IDT, TSS
   │   └─ IRETQ to user code
   └─ User code runs until INT 32 (or fault)
   └─ U2K restores kernel context
```

## 7. Gap Analysis: What We Need

### Critical Missing Features

1. **ELF Loading Integration**
   - Read ELF file from disk/memory
   - Copy PT_LOAD segments to guest_mem at p_vaddr
   - Extract entry point for trampoline
   - Get `__dandelion_system_data` symbol offset

2. **DandelionSystemData Interface**
   - Implement `setup_input_structs<u64, u64>()`
   - Implement `read_output_structs<u64, u64>()`
   - Memory management for input/output data
   - Heap bounds tracking

3. **Context Structure**
   - Create a `Context` type to track:
     - Content (DataSets with DataItems)
     - Free space pointer
     - Size bounds
   - Methods: `write()`, `read()`, `get_free_space_and_write_slice()`

4. **DataSet/DataItem Structures**
   ```rust
   pub struct DataSet {
       pub ident: String,
       pub buffers: Vec<DataItem>,
   }
   
   pub struct DataItem {
       pub ident: String,
       pub data: Position,  // offset + size
       pub key: u32,
   }
   ```

### Secondary Improvements

1. **Memory Layout Optimization**
   - Consider matching Dandelion's layout more closely
   - Put stack at higher addresses (before page tables)
   - Consolidate interrupt handlers with GDT/TSS/IDT

2. **Protection Flags**
   - Use ELF p_flags to set page permissions (R/W/X)
   - Currently we make all user pages RWX

3. **Error Handling**
   - Map exception vectors to DandelionError types
   - Return meaningful exit codes

## 8. Implementation Plan

### Phase 1: ELF Loading (Minimal)

```rust
// In main.rs or new module
fn load_dandelion_elf(elf_path: &str, usm: &mut UserSpaceManager) -> Result<ElfConfig, Error> {
    let elf_bytes = std::fs::read(elf_path)?;
    let parsed = ParsedElf::new(&elf_bytes)?;
    
    let entry_point = parsed.get_entry_point();
    let (requirements, sources) = parsed.get_layout_pair();
    let (system_data_offset, _) = parsed.get_symbol_by_name(&elf_bytes, "__dandelion_system_data")?;
    
    // Copy segments to guest_mem
    for (req, src) in requirements.iter().zip(sources.iter()) {
        usm.guest_mem[req.offset..req.offset + src.size]
            .copy_from_slice(&elf_bytes[src.offset..src.offset + src.size]);
        // Zero-fill remainder if memsz > filesz
        if req.size > src.size {
            usm.guest_mem[req.offset + src.size..req.offset + req.size].fill(0);
        }
    }
    
    Ok(ElfConfig {
        entry_point,
        system_data_offset,
    })
}
```

### Phase 2: Context and I/O Structures

```rust
pub struct Context {
    pub content: Vec<Option<DataSet>>,
    free_pointer: usize,
    size: usize,
}

impl Context {
    pub fn write<T>(&mut self, offset: usize, data: &[T]) -> Result<()> { ... }
    pub fn read<T>(&self, offset: usize, buf: &mut [T]) -> Result<()> { ... }
    pub fn get_free_space_and_write_slice<T>(&mut self, data: &[T]) -> Result<usize> { ... }
}
```

### Phase 3: setup_input_structs / read_output_structs

Implement simplified versions of Dandelion's interface functions, adapted for our guest_mem model.

## 9. Test ELF Analysis

The workspace contains `elf/test_elf_unikernel_x86_64_basic`. We should:
1. Parse it with our ELF parser
2. Verify we can find `__dandelion_system_data`
3. Load it into guest_mem
4. Execute it (with minimal I/O first)

## Conclusion

Our PoC has a solid foundation for user space isolation:
- ✅ Page table management
- ✅ GDT/TSS/IDT setup
- ✅ Interrupt handlers
- ✅ CR3-switching trampolines
- ✅ ELF parser (not yet integrated)

To support Dandelion ELF files, we need to:
- ❌ Integrate ELF loading into execution flow
- ❌ Implement DandelionSystemData interface
- ❌ Create Context and I/O data structures
- ❌ Adapt memory layout for input/output data

The most significant gap is the **I/O interface**. Dandelion's structured input/output mechanism through `DandelionSystemData` is what makes the SDK usable for real workloads.
