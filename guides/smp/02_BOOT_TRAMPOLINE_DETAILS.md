# Boot Trampoline: Deep Dive

## What Is The Boot Trampoline?

The boot trampoline is a **bridge** between the hardware's initial state (16-bit real mode) and modern operating system code (64-bit long mode).

## Why Do We Need It?

When an x86-64 CPU receives a SIPI (Startup IPI), it:
1. Starts executing at physical address `vector * 4096` (where vector is an 8-bit value)
2. Starts in **16-bit real mode** (ancient 8086 compatibility mode)
3. Has no GDT, no page tables, minimal setup

But our Rust code needs:
- 64-bit long mode
- Paging enabled
- Valid stack pointer
- Proper segment descriptors

The trampoline does this transition.

## Trampoline Code Flow

### Stage 1: 16-bit Real Mode
```assembly
lcpu_start16_ap:
    cli                    ; Disable interrupts
    xor %edi, %edi        ; Clear registers
    xor %esi, %esi
    ; Calculate actual position (CS segment * 16)
    mov %cs, %ebx
    shl $4, %ebx
    ; Jump to normalized address
    jmp *%eax
```

**Purpose**: Normalize address, prepare for protected mode

### Stage 2: Enter 32-bit Protected Mode
```assembly
lcpu_start16:
    cli
    mov $X86_CR0_PE, %eax     ; Enable protected mode bit
    mov %eax, %cr0
    lgdt (gdt32_ptr)          ; Load 32-bit GDT
    ljmp $CS32, $jump_to32    ; Far jump to 32-bit code
```

**Purpose**: Enable protected mode, load GDT, switch to 32-bit

### Stage 3: 32-bit Protected Mode Setup
```assembly
lcpu_start32:
    ; Enable PAE (Physical Address Extension)
    mov $X86_CR4_PAE, %eax
    mov %eax, %cr4
    
    ; Enable long mode in EFER MSR
    mov $0xC0000080, %ecx    ; EFER MSR
    rdmsr
    or $X86_EFER_LME, %eax   ; Set LME bit
    wrmsr
    
    ; Load page table root
    mov x86_bpt_pml4_addr, %eax
    mov %eax, %cr3
    
    ; Enable paging (enters long mode)
    mov $CR0_SETTINGS, %eax  ; PE | WP | PG
    mov %eax, %cr0
    
    ; Load 64-bit GDT
    lgdt (gdt64_ptr)
    ljmp $CS64, $jump_to64   ; Far jump to 64-bit code
```

**Purpose**: Enable long mode, load page tables, enable paging

### Stage 4: 64-bit Long Mode
```assembly
lcpu_start64:
    ; Get APIC ID from CPUID
    mov $1, %eax
    cpuid
    shr $24, %ebx           ; APIC ID in high byte
    
    ; Calculate CpuData structure address
    ; Address = lcpus + (APIC_ID * LCPU_SIZE)
    mov $LCPU_SIZE, %eax
    imul %ebx, %eax
    lea lcpus(%rip), %rbp
    add %rax, %rbp
    
    ; Mark CPU as initialized
    mov $LCPU_STATE_INIT, LCPU_STATE_OFFSET(%rbp)
    
    ; Enable FPU, SSE, AVX, etc.
    ; ... (see boot_trampoline.S for full sequence)
    
    ; Load entry point and stack from CpuData
    mov LCPU_ENTRY_OFFSET(%rbp), %rax    ; Entry function
    mov LCPU_STACKP_OFFSET(%rbp), %rsp   ; Stack pointer
    
    ; Align stack (required by ABI)
    and $~0xf, %rsp
    sub $0x8, %rsp
    
    ; Call entry function with CpuData pointer as argument
    mov %rbp, %rdi          ; First argument: pointer to CpuData
    xor %rbp, %rbp          ; Clear frame pointer
    jmp *%rax               ; Jump to ap_entry
```

**Purpose**: Initialize CPU features, load stack and entry point, jump to Rust code

## Critical Data Structures

### x86_bpt_pml4_addr (Global Variable)
```assembly
.globl x86_bpt_pml4_addr
x86_bpt_pml4_addr:
    .long 0x10a000    ; Default - MUST be set by BSP!
```
- **Type**: 32-bit physical address
- **Purpose**: Points to the page table root (PML4)
- **Set by**: BSP reads its CR3 and writes here before starting APs
- **Used by**: Stage 3 to load into AP's CR3

### lcpus[] Array (Global)
```assembly
.globl lcpus
.align 64
lcpus:
    .fill (LCPU_SIZE * LCPU_MAXCOUNT), 1, 0
```
- **Type**: Array of CpuData structures (64 bytes each, 16 CPUs max)
- **Purpose**: Per-CPU configuration and state
- **Set by**: BSP before starting each AP
- **Used by**: Stage 4 to load entry point and stack

### CpuData Structure Layout
```rust
#[repr(C, align(64))]
pub struct CpuData {
    pub state: i32,         // Offset 0x00: CPU state
    pub idx: u32,           // Offset 0x04: CPU index (0, 1, 2, ...)
    pub id: u64,            // Offset 0x08: APIC ID
    pub entry: u64,         // Offset 0x10: Entry function pointer
    pub stack_ptr: u64,     // Offset 0x18: Stack top pointer
    _padding: [u8; 32],     // Offset 0x20-0x3F: Padding to 64 bytes
}
```

## Trampoline Placement

### Address Requirements
1. **Below 1 MiB**: Real mode can only address 1 MiB (20-bit addressing)
2. **Page-aligned**: Address must be multiple of 4096 (0x1000)
3. **Accessible**: Must be in a writable memory region
4. **Known**: BSP must know the exact address to copy code there

### Common Addresses
- `0x7000`: Sometimes used, might conflict with BIOS
- `0x8000` (32 KiB): **Recommended** - usually safe
- `0x9000`: Near 0x8000, also commonly used

### SIPI Vector Calculation
If trampoline is at address `0x8000`:
```
Vector = 0x8000 / 0x1000 = 0x8
```
The SIPI message includes this 8-bit vector.

## PIE (Position Independent Executable) Problem

### The Conflict
- **Trampoline needs absolute addresses**: Must run at fixed physical address in low memory
- **PIE requires relative addresses**: All code/data referenced with offsets

### The Solution
1. **Don't embed trampoline in PIE executable**: Trampoline is pure data, copied at runtime
2. **Compile trampoline separately**: As a separate non-PIE object file
3. **Link as library**: Static library (libboot_trampoline.a)
4. **Copy bytes at runtime**: BSP copies the bytes to 0x8000

### Implementation Approach
```rust
// Trampoline as external static data
extern "C" {
    static x86_start16_begin: u8;
    static x86_start16_end: u8;
}

// Copy to low memory
unsafe {
    let trampoline_code = core::slice::from_raw_parts(
        &x86_start16_begin as *const u8,
        (&x86_start16_end as *const u8 as usize) - 
        (&x86_start16_begin as *const u8 as usize)
    );
    
    let dest = 0x8000 as *mut u8;
    core::ptr::copy_nonoverlapping(
        trampoline_code.as_ptr(),
        dest,
        trampoline_code.len()
    );
}
```

## Relocation Fixups

The trampoline has self-referential addresses that need patching after copying:

### Relocation Points
1. **gdt32_ptr**: Pointer to GDT in 16-bit code
2. **gdt32_data**: GDT base address
3. **lcpu_start16**: Jump target in 16-bit code
4. **jump_to32**: Jump target to 32-bit code
5. **lcpu_start32**: Address of 32-bit entry point

### Relocation Process
```rust
// After copying to 0x8000, patch addresses
let base = 0x8000u64;

// Patch GDT pointer (2-byte immediate)
patch_u16(base + offset_of_gdt32_ptr, (base + gdt32_offset) as u16);

// Patch 32-bit entry address (4-byte immediate)
patch_u32(base + offset_of_lcpu_start32_imm, lcpu_start32_addr as u32);

// ... (see boot_trampoline.S for full relocation table)
```

## Testing the Trampoline

### Can We Test It?
Yes, even the BSP went through a similar process (or the kernel's version of it).

### Debug Strategies
1. **GDB at 0x8000**: Set breakpoint, check if AP reaches there
2. **Port 0x80 writes**: Add `outb $0x80, %al` with different values at each stage
3. **Serial output**: If we reach 64-bit mode, print from trampoline
4. **State variable**: Check `lcpus[N].state` - does it change?

### Failure Points
- **Not reaching 0x8000**: SIPI vector wrong, or memory not accessible
- **Hang in 16-bit code**: GDT not set up correctly
- **Hang in 32-bit code**: Page tables not set, or CR3 wrong
- **Hang in 64-bit code**: Stack not set, or entry point wrong
- **Reach 64-bit but no output**: Entry function not called, or stack corrupt

## Next Steps

With this understanding, the next document will detail:
1. How to restore the trampoline copy functionality
2. How to compile trampoline as a separate object for PIE builds
3. How to properly initialize all the data structures
