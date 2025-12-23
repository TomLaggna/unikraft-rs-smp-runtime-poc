# SMP Implementation Checklist

## Goal
Get AP to print "Hello World" by implementing complete SMP boot sequence.

## Prerequisites Check

### ✓ Already Have
- [x] Boot trampoline assembly code (boot_trampoline.S)
- [x] x2APIC IPI sending functions (cpu_startup.rs)
- [x] AP entry point function (main.rs::ap_entry)
- [x] Serial console working (println!)
- [x] PIE executable building successfully

### ✗ Currently Missing
- [ ] Trampoline compilation and linkage
- [ ] Trampoline copy to low memory
- [ ] Page table address setup
- [ ] Per-CPU data initialization
- [ ] Stack allocation
- [ ] Relocation fixups

## Step-by-Step Implementation Plan

### Phase 1: Restore Trampoline Compilation

**Goal**: Get boot_trampoline.S compiled and linked without breaking PIE.

#### Step 1.1: Compile Trampoline as Separate Object
```bash
# This should already work from Makefile
make asm
# Creates: build/boot_trampoline.o
# Creates: build/libboot_trampoline.a
```

**Verify**:
```bash
nm build/libboot_trampoline.a | grep x86_start16
# Should show: x86_start16_begin, x86_start16_end, etc.
```

#### Step 1.2: Link Library But Keep PIE
The trampoline library should be linked, but its code is just data to copy, not executed in place.

**Modify**: .cargo/config.toml
```toml
[target.x86_64-unknown-linux-musl]
rustflags = [
    "-C", "link-arg=-Lbuild",
    "-C", "link-arg=-lboot_trampoline",
]
```

**Issue**: PIE linker will complain about absolute relocations in trampoline.

**Solution**: Mark trampoline sections as data, not code:
- In boot_trampoline.S: Use `.section .rodata` for the code
- Or: Don't link directly, load as binary blob

#### Step 1.3: Alternative - Load Trampoline as Binary Blob
Better approach for PIE:

```rust
// In boot_trampoline_bindings.rs
pub const BOOT_TRAMPOLINE_BINARY: &[u8] = 
    include_bytes!("../../build/boot_trampoline.bin");
```

Generate .bin file:
```bash
objcopy -O binary build/boot_trampoline.o build/boot_trampoline.bin
```

**Advantages**:
- No linker conflicts with PIE
- Trampoline is pure data
- Easy to copy to low memory

---

### Phase 2: Copy Trampoline to Low Memory

**Goal**: Copy trampoline code to 0x8000 at runtime.

#### Step 2.1: Implement copy_to_target()
```rust
impl BootTrampoline {
    pub unsafe fn copy_to_target(&self) {
        let trampoline_data = BOOT_TRAMPOLINE_BINARY;
        let dest = self.target_addr as *mut u8;
        
        // Copy bytes to low memory
        core::ptr::copy_nonoverlapping(
            trampoline_data.as_ptr(),
            dest,
            trampoline_data.len()
        );
        
        println!("Copied {} bytes to 0x{:x}", 
                 trampoline_data.len(), self.target_addr);
    }
}
```

#### Step 2.2: Verify Memory is Writable
The prebuilt Unikraft kernel might not give us access to low memory.

**Test**:
```rust
unsafe {
    let test_addr = 0x8000 as *mut u8;
    *test_addr = 0x42;  // Try to write
    let read_back = *test_addr;
    println!("Memory test at 0x8000: wrote 0x42, read 0x{:x}", read_back);
}
```

**If this crashes**: Kernel doesn't allow access to low memory.
**Solution**: Use kernel's existing trampoline address instead.

#### Step 2.3: Find Kernel's Trampoline (If Needed)
If we can't write to low memory, kernel might have trampoline already.

**Strategy**:
1. Use GDB to examine memory around 0x8000, 0x7000, etc.
2. Look for known patterns (GDT magic bytes, specific instructions)
3. Use kernel's trampoline address instead of our own

**GDB Commands**:
```gdb
# Connect to QEMU
target remote :1234

# Examine memory
x/128bx 0x8000
x/128bx 0x7000

# Look for GDT pattern (null descriptor + code/data)
find 0x0, 0x100000, 0x0000000000000000, 0x00cf9a000000ffff
```

---

### Phase 3: Setup Page Tables

**Goal**: Make APs use same page tables as BSP.

#### Step 3.1: Read BSP's CR3
```rust
// In main(), before starting APs
let cr3: u64;
unsafe {
    asm!("mov {}, cr3", out(reg) cr3);
}
println!("BSP CR3 (page table root): 0x{:x}", cr3);
```

#### Step 3.2: Write to Trampoline's x86_bpt_pml4_addr
```rust
impl BootTrampoline {
    pub unsafe fn set_page_table(&self, pml4_addr: u32) {
        // Find x86_bpt_pml4_addr in copied trampoline
        let offset_in_trampoline = /* need to calculate from .S file */;
        let addr = (self.target_addr + offset_in_trampoline) as *mut u32;
        *addr = pml4_addr;
        
        println!("Set page table addr in trampoline: 0x{:x}", pml4_addr);
    }
}
```

**Critical**: We need the exact offset of `x86_bpt_pml4_addr` within the trampoline binary.

**How to find**:
```bash
# After compiling
nm build/boot_trampoline.o | grep x86_bpt_pml4_addr
# Shows address, e.g.: 0000000000001000 D x86_bpt_pml4_addr

# Get offset within .data section
objdump -h build/boot_trampoline.o | grep .data
```

---

### Phase 4: Allocate Stacks

**Goal**: Each AP gets its own stack.

#### Step 4.1: Allocate Stack Memory
```rust
// In main()
const STACK_SIZE: usize = 16384; // 16 KiB
static mut AP_STACKS: [[u8; STACK_SIZE]; 4] = [[0; STACK_SIZE]; 4];

fn alloc_stack(cpu_idx: usize) -> u64 {
    unsafe {
        let stack_base = AP_STACKS[cpu_idx].as_ptr() as u64;
        let stack_top = stack_base + STACK_SIZE as u64;
        stack_top // Stack grows downward
    }
}
```

**Important**: Stack pointer points to the **top** (high address), not bottom.

#### Step 4.2: Verify Stack Alignment
```rust
let stack = alloc_stack(1);
assert_eq!(stack & 0xF, 0, "Stack must be 16-byte aligned");
```

---

### Phase 5: Initialize Per-CPU Data

**Goal**: Fill in `lcpus[]` array in trampoline for each AP.

#### Step 5.1: Calculate lcpus[] Address
```rust
impl BootTrampoline {
    pub unsafe fn init_cpu(&self, idx: usize, id: u64, entry: u64, stack: u64) {
        // Find lcpus array in copied trampoline
        let lcpus_offset = /* calculate from symbols */;
        let lcpus_addr = (self.target_addr + lcpus_offset) as *mut CpuData;
        
        // Write CpuData for this CPU
        let cpu_data = CpuData {
            state: 0, // LCPU_STATE_OFFLINE
            idx: idx as u32,
            id,
            entry,
            stack_ptr: stack,
            _padding: [0; 32],
        };
        
        core::ptr::write(lcpus_addr.add(idx), cpu_data);
        
        println!("Initialized CPU {}: entry=0x{:x}, stack=0x{:x}", 
                 idx, entry, stack);
    }
}
```

#### Step 5.2: Set Entry Point
```rust
// In main(), for each AP
let entry_fn = ap_entry as *const () as u64;
trampoline.init_cpu(cpu_idx, apic_id, entry_fn, stack_ptr);
```

**Critical**: `ap_entry` must be `extern "C"` and take correct argument:
```rust
#[no_mangle]
pub extern "C" fn ap_entry(cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    unsafe {
        let cpu = &*cpu_data;
        println!("Hello from CPU {}! APIC ID: {}", cpu.idx, cpu.id);
        
        loop {
            core::arch::asm!("hlt");
        }
    }
}
```

---

### Phase 6: Apply Relocations

**Goal**: Fix self-referential addresses in trampoline after copying.

#### Step 6.1: Identify Relocation Points
From boot_trampoline.S:
- `gdt32_ptr_imm2_start16`: Offset of 2-byte immediate
- `gdt32_data4_start16`: Offset of 4-byte immediate
- `lcpu_start16_imm2_start16`: Offset of 2-byte immediate
- `jump_to32_imm2_start16`: Offset of 2-byte immediate
- `lcpu_start32_imm4_start16`: Offset of 4-byte immediate

#### Step 6.2: Calculate Symbol Offsets
```bash
nm build/boot_trampoline.o | grep _start16
# Extract offsets, store in constants
```

#### Step 6.3: Implement Patching
```rust
impl BootTrampoline {
    pub unsafe fn apply_relocations(&self) {
        let base = self.target_addr;
        
        // Example: Patch GDT pointer
        let gdt32_ptr_offset = 0x43; // From nm output
        let gdt32_offset = 0x22;      // From nm output
        
        let patch_addr = (base + gdt32_ptr_offset) as *mut u16;
        let patch_value = (base + gdt32_offset) as u16;
        *patch_addr = patch_value;
        
        // ... repeat for all relocation points
        
        println!("Applied relocations to trampoline at 0x{:x}", base);
    }
}
```

---

### Phase 7: Send IPIs

**Goal**: Wake up APs with proper sequence.

#### Step 7.1: Enable x2APIC on BSP
```rust
unsafe {
    x2apic_enable()?;
    println!("x2APIC enabled on BSP");
}
```

#### Step 7.2: Send INIT-SIPI-SIPI Sequence
```rust
for ap_id in 1..4 {
    let apic_id = ap_id as u32; // Assuming APIC ID == CPU index
    
    println!("Starting CPU {}...", ap_id);
    
    // 1. Send INIT IPI
    unsafe {
        x2apic_send_iipi(apic_id);
    }
    delay_ms(10);
    
    // 2. Send SIPI twice
    let sipi_vector = trampoline.get_sipi_vector(); // 0x8 for 0x8000
    for attempt in 0..2 {
        unsafe {
            x2apic_send_sipi(0x8000, apic_id);
        }
        delay_us(200);
    }
    
    // 3. Wait for AP to signal ready
    delay_ms(10);
    
    // 4. Check if AP started
    unsafe {
        let cpu_state = /* read lcpus[ap_id].state */;
        if cpu_state != 0 {
            println!("  ✓ CPU {} reported state: {}", ap_id, cpu_state);
        } else {
            println!("  ✗ CPU {} did not respond", ap_id);
        }
    }
}
```

---

## Testing & Debugging

### Test 1: Memory Write
```rust
unsafe {
    let addr = 0x8000 as *mut u8;
    *addr = 0x42;
    assert_eq!(*addr, 0x42, "Can't write to low memory");
}
```

### Test 2: Trampoline Copy
```rust
trampoline.copy_to_target();
// Verify with GDB: x/128bx 0x8000
```

### Test 3: Page Table
```rust
unsafe {
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3);
    println!("CR3: 0x{:x}", cr3);
    
    // Should be non-zero and page-aligned
    assert_ne!(cr3, 0);
    assert_eq!(cr3 & 0xFFF, 0);
}
```

### Test 4: State Change
```rust
// After sending SIPI, check if AP updated its state
delay_ms(100);
unsafe {
    let state = /* read lcpus[1].state from trampoline memory */;
    println!("CPU 1 state: {}", state);
    // Should be > 0 if AP reached 64-bit code
}
```

### GDB Breakpoints
```gdb
# Break at trampoline entry
break *0x8000

# Break at 64-bit entry
break lcpu_start64

# Break at ap_entry
break ap_entry

# Continue and check which is hit
continue
```

---

## Expected Behavior

### Success Signs
1. "Copied N bytes to 0x8000"
2. "Set page table addr: 0x..."
3. "Initialized CPU 1: entry=0x..., stack=0x..."
4. "Starting CPU 1..."
5. **"Hello from CPU 1! APIC ID: 1"** ← This is the goal!

### Failure Modes & Solutions

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Crash on memory write | Low memory not accessible | Use kernel's existing trampoline |
| SIPI sent but no response | Wrong vector or memory not executable | Check trampoline address, verify copy |
| AP hangs before 64-bit | Page tables wrong | Verify CR3 is correct |
| AP hangs in 64-bit | Stack or entry point wrong | Check CpuData initialization |
| AP executes but no output | Entry function not called | Verify lcpus[].entry points to ap_entry |
| Output garbled | Stack too small or corrupt | Increase stack size, check alignment |

---

## Next Step: Implementation

With this checklist, we can now:
1. Fix boot_trampoline_bindings.rs to restore real functionality
2. Compile trampoline as binary blob for PIE compatibility
3. Implement each phase systematically
4. Test at each step with GDB

The key insight: **The trampoline is copied data, not linked code**, which solves the PIE conflict.
