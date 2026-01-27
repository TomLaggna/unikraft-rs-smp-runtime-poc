# Unikraft Engine Integration Guide for Dandelion

This document describes how to integrate the Unikraft-based execution engine into
Dandelion as a new `ContextType::Unikraft` variant, alongside existing KVM, MMU,
and CHERI engines.

## Overview

The Unikraft engine provides **Ring 3 isolation on shared address space hardware**
using x86-64 paging and privilege separation. Unlike KVM (which uses hardware
virtualization) or MMU (which uses MMAP), Unikraft shares the host kernel's
physical memory but isolates user code via:

1. **Separate page tables** - User code runs with its own CR3
2. **Ring 3 execution** - User code runs at CPL=3 (unprivileged)
3. **CR3-switching trampolines** - Assembly sequences that atomically switch
   between kernel and user address spaces

## File Structure

```
src/
└── dandelion_port/
    ├── mod.rs           # Core types: UnikraftContext, UnikraftLayout, etc.
    ├── x86_64.rs        # Page table and interrupt table setup
    ├── trampolines.rs   # K2U/U2K machine code and patching
    └── handlers.rs      # Interrupt handlers (vectors 0-32)
```

### Target Integration Path in Dandelion

```
src/engines/
├── kvm/
│   ├── kvm.rs           # KvmDriver, KvmLoop, KvmContext
│   └── x86_64.rs        # KVM-specific x86_64 setup
├── mmu/
│   └── mmu.rs
└── unikraft/            # NEW: Add these files
    ├── mod.rs           # UnikraftDriver, UnikraftLoop
    ├── x86_64.rs        # Unikraft-specific x86_64 setup
    ├── trampolines.rs   # CR3-switching trampolines
    └── handlers.rs      # Interrupt handlers
```

## Key Components

### 1. UnikraftContext (mod.rs)

```rust
pub struct UnikraftContext {
    /// Guest memory storage
    pub storage: Vec<u8, PageAlignedAllocator>,
    /// Host virtual address of storage start
    pub host_base_va: u64,
    /// Memory layout within storage
    pub layout: UnikraftLayout,
}
```

**Comparison with KVM:**
- `KvmContext` wraps a VM file descriptor and uses KVM ioctls
- `UnikraftContext` directly owns the memory buffer (no hypervisor)

### 2. UnikraftLayout (mod.rs)

```rust
pub struct UnikraftLayout {
    pub page_tables_offset: usize,     // 4-level x86_64 page tables
    pub gdt_offset: usize,             // Global Descriptor Table (80 bytes)
    pub tss_offset: usize,             // Task State Segment (104 bytes)
    pub idt_offset: usize,             // Interrupt Descriptor Table (33 entries)
    pub k2u_trampoline_offset: usize,  // Kernel-to-user trampoline
    pub u2k_trampoline_offset: usize,  // User-to-kernel trampoline
    pub handlers_offset: usize,        // Interrupt handler stubs
    pub interrupt_stack_offset: usize, // Ring 0 stack for interrupts
    pub user_code_offset: usize,       // User ELF loaded here
    pub user_stack_offset: usize,      // User stack (Ring 3)
    pub data_region_offset: usize,     // Dandelion I/O data region
}
```

### 3. x86_64.rs - Architecture Setup

This mirrors `kvm/x86_64.rs` closely:

| Function | Purpose |
|----------|---------|
| `set_page_table()` | Build 4-level page tables mapping guest memory |
| `set_interrupt_table()` | Setup GDT, TSS, and IDT |
| `setup_gdt()` | Create GDT with kernel/user segments |
| `setup_tss()` | Configure TSS with Ring 0 stack pointer |
| `setup_idt()` | Install interrupt gate descriptors |

**GDT Layout (10 entries, 80 bytes):**
```
Index 0: Null descriptor
Index 1: Kernel Code (Ring 0, 64-bit)
Index 2: Kernel Data (Ring 0)
Index 3: User Code (Ring 3, 64-bit)
Index 4: User Data (Ring 3)
Index 5-6: TSS descriptor (16 bytes, spans 2 entries)
Index 7-9: Reserved
```

### 4. trampolines.rs - CR3 Switching

**K2U Trampoline (Kernel → User):**
1. Save kernel RSP to data section
2. Load new CR3 (user page tables)
3. Load GDT from data section
4. Load IDT from data section
5. Push IRET frame (SS, RSP, RFLAGS, CS, RIP)
6. IRET to Ring 3

**U2K Trampoline (User → Kernel):**
1. Save user registers to data section
2. Load kernel CR3 (restore kernel page tables)
3. Restore kernel RSP
4. Return to kernel

**Data Section Layout:**
```rust
pub mod k2u_offsets {
    pub const KERNEL_RSP_SAVE: usize = 0;     // 8 bytes
    pub const USER_CR3_VALUE: usize = 8;      // 8 bytes
    pub const GDT_DESC: usize = 16;           // 10 bytes (2 + 8)
    pub const IDT_DESC: usize = 32;           // 10 bytes (2 + 8)
    pub const USER_ENTRY: usize = 48;         // 8 bytes
    pub const USER_RSP: usize = 56;           // 8 bytes
    pub const USER_RFLAGS: usize = 64;        // 8 bytes
    pub const DATA_SECTION_START: usize = 1024;
}
```

### 5. handlers.rs - Interrupt Handlers

33 handlers for vectors 0-32:
- Vectors 0-31: Standard x86 exceptions
- Vector 32: `INT 32` - User code "syscall" to return to kernel

Each handler pushes vector number and jumps to U2K trampoline.

## Integration Steps

### Step 1: Add ContextType Variant

In `src/engines/mod.rs` or equivalent:

```rust
pub enum ContextType {
    Kvm(KvmContext),
    Mmu(MmuContext),
    Cheri(CheriContext),
    Unikraft(UnikraftContext),  // NEW
}
```

### Step 2: Implement EngineLoop Trait

```rust
pub struct UnikraftLoop;

impl EngineLoop for UnikraftLoop {
    fn run_engine<S: DataStore>(
        domain: &UnikraftMemoryDomain,
        config: &ElfConfig,
        system_data: &DandelionSystemData,
    ) -> EngineResult<(...)> {
        // 1. Copy input data to data region
        // 2. Patch K2U trampoline with entry point and stack
        // 3. Call K2U trampoline (switches to Ring 3)
        // 4. On return (via U2K), check exit reason
        // 5. Copy output data from data region
    }
}
```

### Step 3: Memory Domain Setup

```rust
pub struct UnikraftMemoryDomain {
    pub context: UnikraftContext,
}

impl UnikraftMemoryDomain {
    pub fn new(size: usize) -> Result<Self> {
        let mut context = UnikraftContext::allocate(size)?;
        
        // Setup page tables
        x86_64::set_page_table(&mut context)?;
        
        // Setup interrupt infrastructure
        x86_64::set_interrupt_table(&mut context)?;
        
        // Copy trampolines
        trampolines::setup_trampolines(&mut context)?;
        
        // Setup handlers
        handlers::patch_handlers(
            &mut context.storage,
            context.layout.handlers_offset,
            context.layout.u2k_trampoline_offset as u64,
        )?;
        
        Ok(Self { context })
    }
}
```

### Step 4: Execute User Code

The execution flow differs from KVM:

**KVM Flow:**
```
Rust → KVM_RUN ioctl → VM Entry → User code → VM Exit → Rust
```

**Unikraft Flow:**
```
Rust → K2U trampoline (ASM) → IRET → User code → INT 32 → U2K trampoline → Rust
```

To call the trampoline from Rust:

```rust
pub unsafe fn execute_user_code(k2u_va: u64) {
    // The K2U trampoline is at a known virtual address
    // Call it as a function pointer - it will IRET to user code
    // and return when user code executes INT 32
    let trampoline: extern "C" fn() = core::mem::transmute(k2u_va);
    trampoline();
}
```

### Step 5: Integrate with Dandelion Data Interface

The `DandelionSystemData` struct in `mod.rs` matches Dandelion's `interface.rs`:

```rust
#[repr(C)]
pub struct DandelionSystemData {
    pub module_input_offset: u64,
    pub input_size: u64,
    pub module_output_offset: u64,
    pub output_size: u64,
    // ... other fields
}
```

Copy this struct to the guest's data region before execution, and read it
back after execution to get output data locations.

## Memory Map

```
Virtual Address Space (User CR3):
┌─────────────────────────────┐ 0xFFFF_FFFF_FFFF_FFFF
│ (Not mapped)                │
├─────────────────────────────┤ 0x0000_0200_0000_0000 (2TB)
│ K2U Trampoline              │ ← Also mapped in kernel CR3
│ U2K Trampoline              │
│ Interrupt Handlers          │
├─────────────────────────────┤
│ Page Tables (identity)      │ ← For CR3 switch consistency
├─────────────────────────────┤
│ GDT, TSS, IDT               │
├─────────────────────────────┤
│ (Gap)                       │
├─────────────────────────────┤ ~0x0000_0001_0000_0000 (high user)
│ User Stack ↓                │
├─────────────────────────────┤
│ Data Region                 │ ← Dandelion I/O
├─────────────────────────────┤
│ User Code (ELF)             │
├─────────────────────────────┤
│ (Low memory gap)            │
└─────────────────────────────┘ 0x0000_0000_0000_0000
```

## Critical Alignment Requirements

| Structure | Alignment | Size | Notes |
|-----------|-----------|------|-------|
| PML4 | 4096 | 4096 | Page-aligned |
| PDPT | 4096 | 4096 | Page-aligned |
| PD | 4096 | 4096 | Page-aligned |
| PT | 4096 | 4096 | Page-aligned |
| GDT | 8 | 80 | 8-byte aligned |
| TSS | 4 | 104 | 4-byte aligned |
| IDT | 8 | 528 | 8-byte aligned |
| K2U Code | 16 | ~1024 | 16-byte aligned |
| U2K Code | 16 | ~1024 | 16-byte aligned |
| Trampoline Data | 8 | ~128 | 8-byte aligned |

## Page Table Entry Flags

```rust
pub mod pte_flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
}
```

**User code pages:** `PRESENT | WRITABLE | USER`
**Kernel code pages:** `PRESENT | WRITABLE` (no USER bit)
**Trampoline pages:** `PRESENT | WRITABLE | USER` (accessible from both rings)

## Differences from KVM Engine

| Aspect | KVM | Unikraft |
|--------|-----|----------|
| Isolation | Hardware VM | Ring 3 + Page Tables |
| Memory | Guest Physical | Shared Virtual |
| Execution | KVM_RUN ioctl | Assembly trampoline |
| Interrupts | VMCS injection | IDT + IST |
| Exit handling | VM-Exit reasons | Interrupt vector |
| Page tables | EPT/NPT | Standard x86-64 |

## Testing Checklist

- [ ] Page tables map user code correctly
- [ ] GDT/TSS/IDT installed without triple fault
- [ ] K2U trampoline reaches user code entry point
- [ ] User code can execute basic instructions
- [ ] INT 32 triggers U2K trampoline correctly
- [ ] Return to kernel preserves registers
- [ ] Page faults captured with correct CR2
- [ ] DandelionSystemData read/write works
- [ ] Multiple invocations reuse context

## Debugging Tips

1. **Triple Fault on K2U**: Check GDT descriptor format and segment selectors
2. **Page Fault Loop**: Verify trampoline pages have USER bit set
3. **GPF on IRET**: Ensure RPL in segment selectors matches DPL
4. **Wrong CR2**: Check page table entry addresses are physical, not virtual
5. **Stack Corruption**: Verify TSS.RSP0 points to valid kernel stack

## References

- Intel SDM Vol. 3A, Chapter 4: Paging
- Intel SDM Vol. 3A, Chapter 6: Interrupt and Exception Handling
- Intel SDM Vol. 3A, Chapter 7: Task Management
- AMD APM Vol. 2, Chapter 5: Page Translation and Protection
