# Dandelion ELF Integration Guide

This document analyzes how Dandelion's KVM execution engine loads and runs ELF files, and compares it to our proof-of-concept (PoC) implementation. The goal is to identify what we already have and what needs to be added to support Dandelion SDK ELF files.

## Overview

Dandelion SDK creates ELF executables with a standardized interface for I/O through a special symbol `__dandelion_system_data`. The runtime is responsible for:
1. Parsing the ELF to extract code, entry point, and the system data symbol
2. Setting up an isolated address space with page tables, GDT, TSS, and IDT
3. Writing input data and metadata to the `DandelionSystemData` struct
4. Executing the user code
5. Reading output data from the context after execution

## The Dandelion Port Module

The `src/dandelion_port/` directory contains a portable implementation ready to be integrated into Dandelion's engine architecture. The module structure:

```
dandelion_port/
├── mod.rs              # Core types: UnikraftContext, UnikraftLayout, errors
├── x86_64.rs           # Page table and interrupt table setup (dynamic allocation)
├── handlers.rs         # Interrupt handlers 0-32 using global_asm!
├── trampolines.rs      # K2U/U2K trampolines using global_asm!
├── ap_startup.rs       # AP management: CpuData, CorePool, task distribution
└── boot_trampoline.rs  # Boot trampoline: 16-bit → 32-bit → 64-bit transitions
```

---

## Boot Trampoline Setup (AP Startup)

The boot trampoline is required to bring Application Processors (APs) from reset state to 64-bit long mode. This section explains the setup process.

### Why Fixed Physical Address?

The SIPI (Startup Inter-Processor Interrupt) mechanism requires:

1. **Physical Address < 1MB**: The SIPI vector is a physical page number (0x00-0xFF), so the trampoline must be at address `vector << 12` (e.g., vector 0x08 → address 0x8000).

2. **No RIP-Relative Addressing**: In 16-bit real mode and early 32-bit protected mode, we cannot use RIP-relative addressing. The code must use absolute addresses that are known at assembly time.

3. **Identity Mapping Required**: After setting CR3 with the kernel page tables, instruction fetching continues from the same physical address. If this address isn't identity-mapped (VA == PA), the CPU will fetch garbage and crash.

### Using Directmap to Access Low Memory

Unikraft provides a directmap region at `0xffffff8000000000` that maps all physical memory:

```
Virtual Address = DIRECTMAP_BASE + Physical Address
                = 0xffffff8000000000 + 0x8000
                = 0xffffff8000008000
```

This allows the BSP (Boot Strap Processor) to copy the trampoline code to low physical memory without special setup:

```rust
use dandelion_port::boot_trampoline::{
    setup_boot_trampoline, BootTrampolineConfig, DIRECTMAP_BASE
};

unsafe {
    let config = BootTrampolineConfig {
        target_phys_addr: 0x8000,    // Physical address for trampoline
        kernel_pml4_phys: cr3_value,  // Kernel's page table
        directmap_base: DIRECTMAP_BASE,
    };
    
    let sipi_vector = setup_boot_trampoline(&config);
    // sipi_vector = 0x08 (for address 0x8000)
}
```

### Boot Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ BSP sends INIT IPI to AP                                                     │
│     ↓                                                                       │
│ BSP sends SIPI with vector (e.g., 0x08 → address 0x8000)                    │
│     ↓                                                                       │
│ AP starts at 0x8000 in 16-bit Real Mode                                     │
│     ↓                                                                       │
│ port_lcpu_start16_ap:                                                       │
│   - Clear segment registers                                                 │
│   - Jump to lcpu_start16 (CS-relative)                                      │
│     ↓                                                                       │
│ port_lcpu_start16:                                                          │
│   - Set CR0.PE (Protected Mode Enable)                                      │
│   - Load 32-bit GDT                                                         │
│   - Far jump to 32-bit code segment                                         │
│     ↓                                                                       │
│ port_lcpu_start32:                                                          │
│   - Set CR4.PAE (Physical Address Extension)                                │
│   - Set EFER.LME (Long Mode Enable)                                         │
│   - Load CR3 with kernel page tables (from patched port_x86_bpt_pml4_addr)  │
│   - Set CR0.PG (Paging Enable)                                              │
│   - Load 64-bit GDT                                                         │
│   - Far jump to 64-bit code segment                                         │
│     ↓                                                                       │
│ port_lcpu_start64:                                                          │
│   - Get APIC ID via CPUID                                                   │
│   - Calculate CpuData pointer: &port_lcpus[apic_id]                         │
│   - Enable FPU, SSE, XSAVE, AVX, FSGSBASE                                   │
│   - Load entry point and stack from CpuData                                 │
│   - Jump to Rust entry point with CpuData as argument                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Page Table Requirements for AP Boot

The kernel page tables (passed via CR3) must include:

1. **Identity mapping of low memory** (0x0000 - 0x100000): Required for instruction fetching during and immediately after the CR3 switch in `port_lcpu_start32`.

2. **Kernel code mapping**: So the AP can execute the Rust entry point.

3. **Directmap region**: So the AP can access physical memory.

### CpuData Structure

Each AP reads its configuration from the `port_lcpus` array, indexed by APIC ID:

```rust
#[repr(C, align(64))]
pub struct CpuData {
    pub state: i32,           // CPU state (OFFLINE, INIT, IDLE, BUSY, HALTED)
    pub idx: u32,             // CPU index (0, 1, 2, ...)
    pub id: u32,              // APIC ID
    _pad0: u32,
    pub entry: u64,           // Entry point address (Rust function)
    pub stackp: u64,          // Stack pointer
    pub task_info_ptr: u64,   // Pointer to work queue / task info
    _reserved: [u64; 4],
}
```

BSP must initialize CpuData before sending SIPI:

```rust
use dandelion_port::boot_trampoline::init_cpu_data;

unsafe {
    init_cpu_data(
        0x8000,                    // Trampoline physical address
        DIRECTMAP_BASE,            // Directmap base
        cpu_index,                 // CPU index (for lcpus array)
        ap_rust_entry as u64,      // Rust function to call
        stack_top,                 // AP's stack pointer
    );
}
```

### Complete AP Boot Example

```rust
use dandelion_port::boot_trampoline::{
    setup_boot_trampoline, init_cpu_data, get_cpu_data,
    BootTrampolineConfig, DIRECTMAP_BASE, cpu_state,
};

/// BSP function to start an AP
pub unsafe fn start_ap(cpu_index: usize, stack_top: u64) {
    let trampoline_addr = 0x8000u64;
    
    // 1. Setup boot trampoline (only once for all APs)
    static TRAMPOLINE_SETUP: core::sync::atomic::AtomicBool = 
        core::sync::atomic::AtomicBool::new(false);
    
    if !TRAMPOLINE_SETUP.swap(true, core::sync::atomic::Ordering::SeqCst) {
        let config = BootTrampolineConfig {
            target_phys_addr: trampoline_addr,
            kernel_pml4_phys: get_kernel_cr3(),
            directmap_base: DIRECTMAP_BASE,
        };
        setup_boot_trampoline(&config);
    }
    
    // 2. Initialize this AP's CpuData
    init_cpu_data(
        trampoline_addr,
        DIRECTMAP_BASE,
        cpu_index,
        ap_entry as u64,
        stack_top,
    );
    
    // 3. Send INIT IPI
    send_init_ipi(cpu_index);
    delay_10ms();
    
    // 4. Send SIPI (twice, as per Intel spec)
    let sipi_vector = (trampoline_addr >> 12) as u8;
    send_sipi(cpu_index, sipi_vector);
    delay_200us();
    send_sipi(cpu_index, sipi_vector);
    
    // 5. Wait for AP to reach INIT state
    let cpu_data = get_cpu_data(trampoline_addr, DIRECTMAP_BASE, cpu_index);
    while (*cpu_data).state == cpu_state::OFFLINE {
        core::hint::spin_loop();
    }
}

/// AP entry point (called from boot trampoline)
extern "C" fn ap_entry(cpu_data: *mut CpuData) {
    // AP is now in 64-bit mode with stack set up
    // cpu_data contains our configuration
    
    unsafe {
        (*cpu_data).state = cpu_state::IDLE;
    }
    
    // Enter work loop...
}
```

---

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

---

## Appendix: dandelion_port Module Reference

### mod.rs - Core Types

Core types and module exports for the Unikraft execution engine.

**Key Types:**
- `UnikraftContext` - Analogous to `KvmContext`, holds guest memory and layout
- `UnikraftLayout` - Pre-computed offsets for page tables, GDT, TSS, IDT, handlers
- `DandelionSystemData` - The I/O interface structure (must match SDK)
- `UnikraftError` - Error types matching Dandelion's error conventions

### x86_64.rs - Page Tables and Interrupt Tables

Dynamic page table and interrupt table setup, plus architecture utilities.

**Key Functions:**
- `calculate_page_table_pages(context_size)` - Calculates pages needed for PML4+PDPT+PD+PT
- `set_page_table(buffer, context_size)` - Creates 4-level page tables dynamically
- `set_interrupt_table(buffer, layout)` - Sets up GDT, TSS, IDT with assembly handlers
- `virt_to_phys(cr3, va)` - Walk page tables to translate virtual to physical
- `map_page(cr3, va, pa, flags, allocator)` - Add a mapping to existing page tables
- `init_ap_tls()` - Initialize Thread-Local Storage for an AP

**Design Notes:**
- Page tables scale with context size (up to 512 GB with full PDPT)
- Uses assembly (`global_asm!`) for handlers, avoiding bytecode arrays
- All user pages marked as USER | PRESENT | WRITABLE (can be refined per-segment)
- `DIRECTMAP_BASE` (0xffffff8000000000) used for physical memory access

### handlers.rs - Interrupt Handlers

Interrupt handlers for vectors 0-32 using `global_asm!` macros.

**Handler Types:**
- Vectors without error code: 0-7, 9, 15-16, 18-20, 28-31
- Vectors with error code: 8, 10-14, 17, 21, 29-30

**Key Functions:**
- `patch_handlers(buffer, layout)` - Writes handler addresses and patches code
- `port_common_handler` - Common interrupt path, jumps to U2K trampoline

### trampolines.rs - K2U/U2K Context Switches

CR3-switching trampolines using `global_asm!`.

**Trampolines:**
- `port_trampoline_k2u` - Kernel to User: loads user GDT/CR3/IDT/TSS, `IRETQ` to user
- `port_trampoline_u2k` - User to Kernel: restores kernel context, returns to caller

**Key Functions:**
- `patch_k2u(buffer, layout)` - Patches K2U with user descriptor addresses
- `patch_u2k(buffer, layout)` - Patches U2K with kernel state locations

### ap_startup.rs - AP Management

Application Processor lifecycle and work distribution.

**Key Types:**
- `CpuData` - Per-CPU state (replicated in boot_trampoline.rs for assembly access)
- `ApTaskInfo` - Work item for APs (context pointer, function pointer)
- `CorePool` - Manages available cores and work assignment

**x2APIC Functions (for sending IPIs):**
- `x2apic_supported()` - Check CPUID for x2APIC support
- `x2apic_enable()` - Enable x2APIC mode on current CPU
- `send_init_ipi(apic_id)` - Send INIT IPI to target
- `send_startup_ipi(apic_id, vector)` - Send SIPI to target

**Key Functions:**
- `setup_ap(idx, apic_id, stack)` - Prepare CpuData for an AP
- `wake_ap(apic_id, sipi_vector)` - Complete INIT-SIPI-SIPI sequence
- `ap_work_loop(cpu_data)` - AP's main loop: wait for work, execute, signal done
- `delay_us(us)`, `delay_ms(ms)` - Busy-wait delays for IPI timing

### boot_trampoline.rs - Real Mode to Long Mode

16-bit → 32-bit → 64-bit boot trampoline for AP startup.

**Key Constants:**
- `DIRECTMAP_BASE` = 0xffffff8000000000 - Unikraft's physical memory mapping
- `DEFAULT_TRAMPOLINE_ADDR` = 0x8000 - Default physical address for trampoline
- `LCPU_SIZE` = 64 - Size of CpuData structure

**Key Functions:**
- `setup_boot_trampoline(config)` - Copy trampoline to low memory via directmap
- `init_cpu_data(...)` - Initialize CpuData for an AP before SIPI
- `get_trampoline_code()` - Get raw trampoline bytes for inspection

**Assembly Sections:**
- `.text.port_boot16` - 16-bit real mode entry and GDT32
- `.text.port_boot32` - Protected mode, enables long mode and paging
- `.text.port_boot64` - Long mode, enables FPU/SSE/AVX, jumps to Rust
- `.data.port_boot` - Patchable data: `port_x86_bpt_pml4_addr`, `port_lcpus`

---

## Integration Checklist

When porting to Dandelion, verify:

### Boot Trampoline Setup
- [ ] Low physical memory (0x8000) is reserved and not used by kernel
- [ ] Page tables include identity mapping of trampoline address (< 1MB)
- [ ] `BootTrampolineConfig.kernel_pml4_phys` is the physical address of PML4
- [ ] Directmap region is accessible for copying trampoline

### Per-AP Setup
- [ ] Each AP has a unique stack allocation (≥ 16KB recommended)
- [ ] CpuData is initialized with entry point and stack before SIPI
- [ ] APIC IDs are correctly enumerated (ACPI MADT or CPUID)
- [ ] TLS is initialized for each AP after boot (`init_ap_tls()`)

### IPI Sequence
- [ ] x2APIC is enabled on BSP before sending IPIs
- [ ] INIT-SIPI-SIPI follows Intel timing (10ms after INIT, 200μs between SIPIs)
- [ ] Destination APIC IDs match the target APs

### User Space Setup
- [ ] K2U/U2K trampolines are patched with correct addresses
- [ ] IDT handlers point to patched handler code
- [ ] GDT has user code/data segments with DPL=3
- [ ] TSS has IST entry for interrupt stack
- [ ] User CR3 has identity mapping of trampolines (high VA)

### Code Quality
- [ ] All assembly uses `global_asm!` (no bytecode arrays)
- [ ] No debug prints in production trampolines/handlers
- [ ] Atomic operations use correct memory ordering
- [ ] Volatile reads/writes for cross-core communication

---

## What's NOT in the Port (Must Be Provided by Dandelion)

The following components are **not** included in `dandelion_port/` and must come from the Dandelion framework:

1. **Memory Allocator** - For allocating AP stacks, TLS areas, and page table pages
2. **ACPI/MADT Parsing** - To enumerate available CPUs and their APIC IDs
3. **ELF Loader Integration** - `elfloader/` exists but integration with engine loop is external
4. **I/O Interface** - `setup_input_structs()` / `read_output_structs()` implementations
5. **Engine Loop Trait** - The `EngineLoop` trait implementation wrapping these primitives
6. **Error Propagation** - Mapping `UnikraftError` to `DandelionError`

---

## Quick Start Integration Sketch

```rust
// Pseudocode for Dandelion integration

use dandelion_port::{
    ap_startup::{wake_ap, ApTaskInfo, CorePool, x2apic_enable},
    boot_trampoline::{setup_boot_trampoline, init_cpu_data, BootTrampolineConfig},
    x86_64::{set_page_table, set_interrupt_table, virt_to_phys, init_ap_tls},
    trampolines::{patch_k2u, patch_u2k},
    handlers::patch_handlers,
    UnikraftContext, UnikraftLayout,
};

impl EngineLoop for UnikraftLoop {
    fn run(&mut self, context: &mut Context) -> DandelionResult<()> {
        // 1. Get a free core from pool
        let core_id = self.core_pool.acquire_core()?;
        
        // 2. Set up task info
        let task_info = self.core_pool.get_task_info(core_id);
        task_info.setup_task(
            context.entry_point,
            context.user_cr3,
            self.kernel_cr3,
            context.layout.k2u_entry_va,
            context.layout.u2k_entry_va,
            // ... GDT/IDT/TSS info
        );
        
        // 3. Wake the AP (it will execute and signal completion)
        unsafe { wake_ap(self.apic_ids[core_id], self.sipi_vector); }
        
        // 4. Wait for completion
        let status = task_info.wait_for_completion();
        
        // 5. Release core
        self.core_pool.release_core(core_id);
        
        match status {
            2 => Ok(()),  // Done
            3 => Err(DandelionError::EngineError),
            _ => Err(DandelionError::EngineError),
        }
    }
}
```
