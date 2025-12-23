# Why This Approach Works Better Than global_asm! with Parameters

## The Challenge You Identified

You correctly identified that we need **runtime variable substitution** in the assembly:
- Page table address (CR3) - can only be read at runtime
- AP entry points - addresses not known until binary is loaded
- Stack pointers - allocated at runtime
- APIC IDs - discovered from ACPI tables

## Why global_asm! Doesn't Work Here

`global_asm!` is a **compile-time macro**. Consider this example:

```rust
// ❌ This doesn't work - cr3 is not a constant!
unsafe {
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3);
    
    // ERROR: cr3 is not a const, can't use in global_asm!
    global_asm!(
        ".section .data",
        ".globl x86_bpt_pml4_addr",
        "x86_bpt_pml4_addr:",
        ".long {}", const cr3  // ❌ COMPILE ERROR
    );
}
```

The assembly is baked into the binary at **compile time**. You can't inject runtime values.

## What About Format Strings?

You might think of using format!() macro:

```rust
// ❌ Still doesn't work - global_asm! needs const
let cr3 = read_cr3();
global_asm!(
    ".long {}",
    const cr3  // ❌ ERROR: cr3 is not const
);
```

Even with procedural macros, you can't make runtime values appear at compile time.

## The Solution: Separate Compilation + Runtime Patching

Instead of trying to parameterize the assembly at compile time, we:

1. **Compile with placeholders** - assembly has `.long 0x0` for runtime values
2. **Link as data** - symbols become references in the binary
3. **Patch at runtime** - write actual values with `ptr::write_volatile()`

### How Runtime Patching Works

```rust
// External symbols from linked assembly
extern "C" {
    static mut x86_bpt_pml4_addr: u32;
    static mut lcpus: [CpuData; 256];
}

// At runtime, we can modify these!
unsafe {
    // Read CR3 at runtime
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3);
    
    // Write it to the symbol ✅ THIS WORKS!
    ptr::write_volatile(&raw mut x86_bpt_pml4_addr, cr3 as u32);
}
```

## Why This Is Actually Better

### 1. True Runtime Flexibility

```rust
// Can read system state FIRST, then configure
let cr3 = read_cr3();
let apic_ids = discover_cpus_from_acpi();
let stacks = allocate_stacks(cpu_count);

// Then patch all values
for (idx, apic_id) in apic_ids.iter().enumerate() {
    trampoline.init_cpu(
        idx as u32,
        *apic_id,
        ap_entry as u64,
        stacks[idx]
    )?;
}
```

### 2. PIE Compatible

```rust
// The trampoline in the PIE binary is just DATA
// (never executed in place)
let trampoline_data = unsafe {
    core::slice::from_raw_parts(
        &x86_start16_begin as *const u8,
        size
    )
};

// Copy to low memory where APs can execute it
unsafe {
    ptr::copy_nonoverlapping(
        trampoline_data.as_ptr(),
        0x8000 as *mut u8,
        size
    );
}
```

### 3. Can Patch Both Locations

Since we copy the trampoline, we need to patch **two places**:
- The symbol in the linked binary (for reference)
- The copied code at 0x8000 (where APs execute)

```rust
pub unsafe fn set_page_table(&self, pml4_addr: u64) {
    // Patch the symbol in the binary
    ptr::write_volatile(&raw mut x86_bpt_pml4_addr, pml4_addr as u32);
    
    // Patch the copied code at 0x8000
    let offset = &raw const x86_bpt_pml4_addr as usize
        - &x86_start16_begin as *const u8 as usize;
    let target = (self.target_addr as usize + offset) as *mut u32;
    ptr::write_volatile(target, pml4_addr as u32);
}
```

This would be **impossible** with `global_asm!` parameterization.

## Comparison Table

| Approach | Runtime Variables | PIE Compatible | Copy to 0x8000 | Patch Multiple Locations |
|----------|------------------|----------------|----------------|-------------------------|
| `global_asm!` with `const` | ❌ No | ✅ Yes | ❌ No | ❌ No |
| Precompiled binary blob | ✅ Yes | ✅ Yes | ✅ Yes | ⚠️ Complex |
| **Link + Runtime Patch** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |

## Real-World Example: Reading CR3

This is **impossible** with compile-time substitution:

```rust
// ❌ IMPOSSIBLE with global_asm!
fn main() {
    // CR3 value is only known at runtime!
    let cr3: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3);
    }
    
    // How do you put this in global_asm!? YOU CAN'T!
    // global_asm!(".long {}", const cr3);  // ❌ ERROR
}
```

With our approach:

```rust
// ✅ WORKS with runtime patching
fn main() {
    let trampoline = BootTrampoline::new(0x8000);
    
    unsafe {
        // Read at runtime
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3);
        
        // Patch at runtime - trivial!
        trampoline.set_page_table(cr3);
    }
}
```

## What About Assembly Macros?

You might think: "Can't I use assembly macros?"

```asm
.macro SET_CR3 value
    .long \value
.endm

SET_CR3 0x12345  # Still compile-time!
```

Assembly macros are also **compile-time**. They're expanded when the assembler runs, not when the program runs.

## The Key Insight

**The compiler can't predict runtime values.**

Your intuition was correct that we need runtime substitution. But the solution isn't compile-time parameterization - it's **runtime memory patching**.

By treating the trampoline as:
- **Data in the PIE binary** (compile time)
- **Copied and patched memory** (runtime)

We get full flexibility without fighting the compiler.

## Summary

- ❌ `global_asm!` parameters must be `const` (compile-time only)
- ❌ Format strings/macros don't help (still compile-time)
- ✅ Link assembly as static library
- ✅ Reference symbols with `extern "C"`
- ✅ Patch values at runtime with `ptr::write_volatile()`
- ✅ Copy to 0x8000 and patch again

This is the standard approach used by:
- Linux kernel (boot trampoline at 0x0)
- Xen hypervisor
- UEFI firmware
- Other bare-metal multicore systems

Your instinct about needing runtime variables was **100% correct**. The solution is just different from what you initially imagined!
