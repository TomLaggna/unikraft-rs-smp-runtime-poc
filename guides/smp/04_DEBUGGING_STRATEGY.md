# SMP Boot Debugging Strategy

## The Challenge

When an AP (Application Processor) fails to boot, it typically **fails silently**:
- No kernel panic
- No error message
- CPU just halts somewhere in the boot process

We need systematic ways to determine **where** and **why** the AP is failing.

## Debug Tools Available

### 1. GDB with QEMU
- Attach to QEMU's GDB stub
- Set breakpoints at specific addresses
- Examine registers and memory
- Step through assembly code

### 2. Serial Port Output
- BSP can print diagnostic info
- APs can print once they reach 64-bit mode (if stack is set up)
- Use for state checks and progress markers

### 3. I/O Port Writes
- Write to port 0x80 (POST code port) or 0xe9 (QEMU debug console)
- Visible in QEMU monitor
- Works in any CPU mode (real, protected, long)
- Useful for trampoline debugging

### 4. Memory-Mapped State Variables
- lcpus[].state field
- Custom debug flags in trampoline
- BSP can poll these after sending SIPI

## Debug Strategy: Binary Search

Use a **progressive verification** approach:

1. Verify trampoline is in memory
2. Verify AP reaches 16-bit code
3. Verify AP reaches 32-bit code
4. Verify AP reaches 64-bit code
5. Verify AP has valid stack
6. Verify AP reaches entry function

Stop when you find the first failure point.

---

## Phase 1: Verify Trampoline Copy

### Check 1: BSP Can Write to 0x8000
```rust
unsafe {
    let test_addr = 0x8000 as *mut [u8; 16];
    let test_pattern = [0x42; 16];
    core::ptr::write(test_addr, test_pattern);
    let read_back = core::ptr::read(test_addr);
    
    if read_back == test_pattern {
        println!("✓ Can write to low memory at 0x8000");
    } else {
        println!("✗ FAILED: Cannot write to 0x8000");
        println!("  Wrote: {:?}", test_pattern);
        println!("  Read:  {:?}", read_back);
    }
}
```

**If this fails**: Unikraft kernel doesn't give us access to low memory.
**Solution**: Find where kernel placed its trampoline (see below).

### Check 2: Trampoline Copy Succeeded
```rust
let trampoline_size = BootTrampoline::get_16bit_section_size();
println!("Trampoline size: {} bytes", trampoline_size);

unsafe {
    trampoline.copy_to_target();
    
    // Verify first few bytes match source
    let dest = 0x8000 as *const [u8; 16];
    let copied = core::ptr::read(dest);
    println!("First 16 bytes at 0x8000: {:02x?}", copied);
}
```

**GDB Verification**:
```gdb
# In GDB (after BSP copies trampoline)
x/128bx 0x8000
# Should show non-zero bytes (assembly code)
```

### Check 3: Find Kernel's Existing Trampoline
If we can't write to low memory, kernel has a trampoline already.

**Strategy**: Look for characteristic patterns:
- GDT null descriptor: `00 00 00 00 00 00 00 00`
- Followed by code descriptor: `ff ff 00 00 00 9a cf 00`
- Followed by data descriptor: `ff ff 00 00 00 92 cf 00`

**GDB Search**:
```gdb
# Search for GDT pattern
find 0x0, 0x100000, 0x0000000000000000, 0x00cf9a000000ffff

# If found, examine that area
x/256bx <address>
```

**Look for**:
- `cli` instruction (0xFA)
- `lgdt` instruction (0x0F 0x01 /2)
- `mov %cr0` instructions
- `lcpus` array (64-byte aligned, multiple of 64 bytes)

---

## Phase 2: Verify AP Reaches Trampoline

### Method 1: State Variable
Add to trampoline (in lcpu_start16_ap):
```assembly
lcpu_start16_ap:
    # Write marker to show we reached here
    movl    $0xDEAD0001, (0x9000)  # Use a scratch memory location
    
    xorl    %edi, %edi
    xorl    %esi, %esi
    # ... rest of code
```

Check from BSP:
```rust
unsafe {
    let marker_addr = 0x9000 as *const u32;
    delay_ms(100); // Give AP time to write
    let marker = core::ptr::read(marker_addr);
    
    if marker == 0xDEAD0001 {
        println!("✓ AP reached 16-bit entry point");
    } else {
        println!("✗ AP did not reach trampoline (marker: 0x{:08x})", marker);
    }
}
```

### Method 2: I/O Port Write
Add to trampoline:
```assembly
lcpu_start16_ap:
    # Write to port 0xe9 (QEMU debug console)
    movb    $'1', %al
    outb    %al, $0xe9
    # ... rest of code
```

**QEMU will output**: Character '1' to console if AP reaches here.

**Enable in QEMU**:
```bash
# Add to QEMU flags:
-debugcon file:debug.log -global isa-debugcon.iobase=0xe9
```

### Method 3: GDB Breakpoint
```gdb
# Set breakpoint at trampoline entry
break *0x8000

# Continue from BSP's main()
continue

# If breakpoint hits, check CPU ID
info registers
# Look at CS, EIP to confirm we're in 16-bit mode
```

---

## Phase 3: Track Progress Through Boot Stages

Add markers at each stage transition:

### 16-bit Entry
```assembly
lcpu_start16_ap:
    movb    $'A', %al       # 'A' = 16-bit entry
    outb    %al, $0xe9
    # ...
```

### 16-bit to 32-bit Transition
```assembly
lcpu_start16:
    movb    $'B', %al       # 'B' = entering protected mode
    outb    %al, $0xe9
    # ...
    ljmp    $CS32, $jump_to32
```

### 32-bit Entry
```assembly
jump_to32:
    movb    $'C', %al       # 'C' = 32-bit mode
    outb    %al, $0xe9
    # ...
```

### 32-bit Setup Page Tables
```assembly
lcpu_start32:
    movb    $'D', %al       # 'D' = loading page tables
    outb    %al, $0xe9
    
    movl    x86_bpt_pml4_addr, %eax
    movl    %eax, %cr3
    
    movb    $'E', %al       # 'E' = page tables loaded
    outb    %al, $0xe9
    # ...
```

### 64-bit Entry
```assembly
lcpu_start64:
    movb    $'F', %al       # 'F' = 64-bit mode!
    outb    %al, $0xe9
    # ...
```

### Reading the Output
Run QEMU and watch for characters:
- `A`: AP woke up, reached 16-bit code
- `AB`: Transitioned to protected mode
- `ABC`: Entered 32-bit code
- `ABCD`: Loading page tables
- `ABCDE`: Page tables loaded, entering long mode
- `ABCDEF`: Made it to 64-bit!

If output stops at a certain letter, you know where the failure is.

---

## Phase 4: Verify Critical Data

### Check: Page Table Address
```rust
// BSP prints its CR3
let cr3: u64;
unsafe {
    asm!("mov {}, cr3", out(reg) cr3);
    println!("BSP CR3: 0x{:x}", cr3);
}

// Verify it's written to trampoline
unsafe {
    let trampoline_cr3_addr = (0x8000 + /* offset of x86_bpt_pml4_addr */) as *const u32;
    let trampoline_cr3 = core::ptr::read(trampoline_cr3_addr);
    println!("Trampoline x86_bpt_pml4_addr: 0x{:x}", trampoline_cr3);
    
    if trampoline_cr3 == (cr3 as u32) {
        println!("✓ Page table address matches");
    } else {
        println!("✗ Page table address mismatch!");
    }
}
```

### Check: CpuData Structure
```rust
// For each AP, verify CpuData was written correctly
unsafe {
    let lcpus_addr = (0x8000 + /* offset of lcpus */) as *const CpuData;
    let cpu1_data = core::ptr::read(lcpus_addr.add(1));
    
    println!("CPU 1 CpuData:");
    println!("  state: {}", cpu1_data.state);
    println!("  idx: {}", cpu1_data.idx);
    println!("  id: {}", cpu1_data.id);
    println!("  entry: 0x{:x}", cpu1_data.entry);
    println!("  stack_ptr: 0x{:x}", cpu1_data.stack_ptr);
    
    // Verify entry points to ap_entry
    let expected_entry = ap_entry as *const () as u64;
    if cpu1_data.entry == expected_entry {
        println!("  ✓ Entry point correct");
    } else {
        println!("  ✗ Entry point wrong (expected 0x{:x})", expected_entry);
    }
    
    // Verify stack is non-zero and aligned
    if cpu1_data.stack_ptr != 0 && cpu1_data.stack_ptr & 0xF == 0 {
        println!("  ✓ Stack pointer valid");
    } else {
        println!("  ✗ Stack pointer invalid");
    }
}
```

---

## Phase 5: Verify AP Reaches 64-bit Code

### Check: State Variable Update
```rust
// AP should update its state to LCPU_STATE_INIT (1) when it reaches 64-bit code
unsafe {
    let lcpus_addr = (0x8000 + /* offset of lcpus */) as *const CpuData;
    
    for cpu_idx in 1..4 {
        delay_ms(100); // Give AP time
        
        let cpu_data = core::ptr::read(lcpus_addr.add(cpu_idx));
        match cpu_data.state {
            0 => println!("CPU {}: OFFLINE (never started)", cpu_idx),
            1 => println!("CPU {}: INIT (reached 64-bit!)", cpu_idx),
            2 => println!("CPU {}: IDLE (reached entry point!)", cpu_idx),
            _ => println!("CPU {}: Unknown state {}", cpu_idx, cpu_data.state),
        }
    }
}
```

### Check: GDB Breakpoint
```gdb
# Set breakpoint at 64-bit entry
break lcpu_start64

# Continue
continue

# If hit, examine state
info registers
# RIP should be at lcpu_start64
# RSP should be 0 (not set yet)

# Step through until stack and entry are loaded
stepi
# ...
# Eventually RDI should have CpuData pointer
# RAX should have ap_entry address
# RSP should have stack pointer
```

---

## Phase 6: Verify AP Reaches Entry Function

### Check: Println from ap_entry
This is the ultimate test:
```rust
#[no_mangle]
pub extern "C" fn ap_entry(cpu_data: *const CpuData) -> ! {
    // Try to print ASAP
    println!("!!! AP ENTRY REACHED !!!");
    
    unsafe {
        let cpu = &*cpu_data;
        println!("CPU {}: idx={}, id={}, entry=0x{:x}, stack=0x{:x}",
                 cpu.idx, cpu.idx, cpu.id, cpu.entry, cpu.stack_ptr);
    }
    
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
```

**If this doesn't print**: Stack is wrong, or function never called.

### Debug: Stack Corruption
```rust
pub extern "C" fn ap_entry(cpu_data: *const CpuData) -> ! {
    // Test stack is writable
    let stack_test: u64 = 0xCAFEBABE;
    
    unsafe {
        // Try to use stack
        let stack_var = &stack_test as *const u64;
        println!("Stack test variable at: {:p}, value: 0x{:x}", 
                 stack_var, *stack_var);
    }
    
    // Continue...
}
```

### Debug: GDB at ap_entry
```gdb
break ap_entry

continue

# If breakpoint hits:
info registers
# RSP should be valid stack address
# RDI should point to CpuData

# Check stack
x/16gx $rsp
# Should show valid memory

# Check CpuData
x/4gx $rdi
# Should show state, idx, id, etc.
```

---

## Common Failure Scenarios

### Scenario 1: AP Never Wakes Up
**Symptoms**: No markers, no state changes, nothing in GDB.

**Possible Causes**:
1. APIC not enabled or configured wrong
2. SIPI vector calculation wrong
3. Memory at trampoline address not executable
4. CPU is actually halted by kernel

**Debug**:
```rust
// Verify APIC is working
let apic_id = get_apic_id();
println!("BSP APIC ID: {}", apic_id);

// Try sending IPI to self (should work)
unsafe {
    x2apic_send_iipi(apic_id);
}
// If this causes problem, APIC setup is wrong
```

### Scenario 2: AP Hangs in 16-bit Mode
**Symptoms**: Marker 'A' appears, but not 'B'.

**Possible Causes**:
1. GDT not set up correctly
2. Relocations not applied (jumps to wrong address)
3. Segment calculation wrong

**Debug**: Check GDT in memory, verify relocations were patched.

### Scenario 3: AP Hangs in 32-bit Mode
**Symptoms**: Markers 'ABC' appear, then nothing.

**Possible Causes**:
1. Page table address wrong (CR3 points to invalid memory)
2. Page tables not set up for APs
3. Long mode enable sequence wrong

**Debug**: Verify `x86_bpt_pml4_addr` matches BSP's CR3, check page table is valid.

### Scenario 4: AP Reaches 64-bit But No Output
**Symptoms**: Markers up to 'F', state changes to INIT, but no println.

**Possible Causes**:
1. Stack pointer wrong (0 or unaligned)
2. Entry point wrong (doesn't point to ap_entry)
3. Function signature mismatch (wrong calling convention)
4. Serial console not working from AP (rare)

**Debug**: GDB breakpoint at ap_entry, examine RSP and function pointer.

---

## Recovery Strategies

### If Low Memory Not Writable
→ Find kernel's existing trampoline with GDB, use that address

### If SIPI Doesn't Wake AP
→ Check kernel boot logs, verify kernel started all CPUs itself
→ Look for kernel's per-CPU structures, hook into those

### If Page Tables Don't Work
→ Verify BSP's page tables are identity-mapped for low memory
→ Check kernel's page table setup

### If Stack Doesn't Work
→ Try larger stack (64 KiB)
→ Verify stack region is in valid memory (check page tables)
→ Use static array instead of heap allocation

### If Entry Point Not Called
→ Verify function pointer is correct (use `nm` to check symbol address)
→ Check calling convention (extern "C")
→ Try inline assembly stub that just does infinite loop with HLT

---

## Minimal Test Case

To isolate issues, try this minimal AP entry:

```rust
#[no_mangle]
pub extern "C" fn ap_entry_minimal(cpu_data: *const CpuData) -> ! {
    // Don't use stack, don't print
    // Just write to a known memory location
    unsafe {
        let marker = 0x9000 as *mut u32;
        *marker = 0xABCD1234; // "I made it!"
    }
    
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
```

Then check from BSP:
```rust
unsafe {
    let marker = core::ptr::read(0x9000 as *const u32);
    if marker == 0xABCD1234 {
        println!("✓✓✓ AP reached entry function!");
    }
}
```

If this works, gradually add back stack, println, etc.

---

## Summary: Debugging Workflow

1. **Test memory access** to 0x8000
2. **Copy trampoline**, verify with GDB
3. **Add I/O port markers** throughout trampoline
4. **Send SIPI**, watch for marker sequence
5. **Check state variable** after delay
6. **GDB breakpoint** at failure point
7. **Examine registers** and memory
8. **Try minimal entry** function
9. **Add complexity** gradually

With this strategy, you can **pinpoint exactly where the boot process fails** and fix it systematically.
