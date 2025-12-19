# Unikraft Rust Multicore - Complete Guide

## Overview

This project enables **multi-core CPU initialization from Rust** on KVM/QEMU x86_64, using boot code extracted directly from Unikraft's [`plat/kvm/x86/lcpu_start.S`](https://github.com/unikraft/unikraft).

**Target Platform:** KVM/QEMU x86_64 (specifically, not generic bare metal)

## What's Here

### Core Implementation Files

```
rust_multicore/
├── Cargo.toml                  # Rust package configuration
├── Makefile                    # Build orchestration (recommended)
├── build.sh                    # Alternative: shell script build
├── src/
│   ├── main.rs                 # Complete working example
│   ├── cpu_startup.rs          # x2APIC/SIPI functions
│   └── boot/
│       ├── boot_trampoline.S   # 16→32→64 bit AP boot code
│       ├── boot_defs.h         # Constants and offsets
│       └── boot_trampoline_bindings.rs  # Rust FFI layer
└── guides/
    └── README.md               # This file
```

## Quick Start

### Option 1: Using Makefile (Recommended)

```bash
make all        # Build everything
make run        # Build and run in QEMU with 4 CPUs
make clean      # Clean build artifacts
```

### Option 2: Using build.sh

```bash
./build.sh      # Compile assembly + Rust
./run.sh        # Run in QEMU
```

### Option 3: Manual Cargo (assembly must be pre-compiled)

```bash
# First compile assembly
cd src/boot
gcc -c -m64 -nostdlib -fno-pic boot_trampoline.S -o ../../boot_trampoline.o
cd ../..

# Then build Rust
cargo build --release --target x86_64-unknown-none
```

## Architecture

### Boot Sequence

```
BSP (Bootstrap Processor - your main Rust code):
  1. Enable x2APIC
  2. Copy boot_trampoline to 0x8000 (low memory)
  3. Apply runtime relocations
  4. Setup per-CPU data structures
  5. Send INIT IPI to target CPU
  6. Wait 10ms
  7. Send SIPI (twice with 200μs delay)

AP (Application Processor - secondary CPUs):
  → Receive SIPI at physical address
  → 16-bit real mode (lcpu_start16_ap)
     ↓ Load GDT, enable protected mode
  → 32-bit protected mode (lcpu_start32)
     ↓ Enable PAE, long mode, paging
  → 64-bit long mode (lcpu_start64)
     ↓ Enable FPU/SSE/AVX, get APIC ID
  → Jump to Rust ap_entry() function
```

### Memory Layout

```
Physical Memory:
0x0000_0000 - 0x0000_7FFF: BIOS/reserved
0x0000_8000 - 0x0000_8FFF: Boot trampoline (4KB)
0x0000_9000 - 0x000F_FFFF: Available
0x0010_0000 - ...        : Kernel/application code
```

## KVM/QEMU Specifics

### Why KVM/QEMU vs Bare Metal?

**KVM/QEMU provides:**
- ✅ Consistent APIC behavior (x2APIC always available)
- ✅ Predictable memory layout
- ✅ Simplified device initialization
- ✅ Known-good page tables from bootloader
- ✅ No ACPI complexity (CPU count from `-smp` flag)

**Bare metal requires:**
- ❌ ACPI parsing for CPU discovery
- ❌ APIC detection and configuration
- ❌ BIOS memory map parsing
- ❌ Custom page table setup
- ❌ Firmware quirks handling

### KVM-Specific Boot Code Simplifications

The boot trampoline makes these assumptions valid for KVM:

1. **x2APIC is available** - Don't need xAPIC fallback
2. **Page tables exist** - Use bootloader's PML4 from CR3
3. **Low memory is available** - 0x8000 is always free
4. **SIPI vector works** - No BIOS SMM interference
5. **APIC IDs sequential** - Often match CPU indices

## What Was Extracted from Unikraft

### From `plat/kvm/x86/lcpu_start.S`:

✅ **16-bit real mode entry** (`lcpu_start16_ap`, `lcpu_start16`)
  - Segmentation adjustment for SIPI vector
  - GDT setup and protected mode switch

✅ **32-bit protected mode transition** (`lcpu_start32`)
  - PAE (Physical Address Extension) enable
  - EFER.LME (Long Mode Enable)
  - Page table loading from existing CR3
  - Paging enable + long mode activation

✅ **64-bit long mode setup** (`lcpu_start64`)
  - APIC ID extraction via CPUID
  - FPU/SSE/AVX/XSAVE feature detection & enablement
  - Per-CPU structure indexing
  - Jump to Rust entry function

### From `plat/common/include/x86/cpu.h`:

✅ CR0/CR4 control register bits
✅ MSR numbers (EFER, APIC registers)
✅ CPUID feature flags
✅ GDT descriptor formats

### From `drivers/ukintctlr/xpic/include/uk/intctlr/apic.h`:

✅ x2APIC MSR addresses
✅ IPI/SIPI/INIT message formats
✅ APIC enable sequence

## Code Flow Example

```rust
// BSP initializes multicore
fn main() {
    // 1. Setup
    let trampoline = BootTrampoline::new(0x8000);
    trampoline.copy_to_target();
    trampoline.apply_relocations();
    
    // 2. Configure per-CPU data
    for cpu in 1..cpu_count {
        let stack = alloc_stack(16384);
        trampoline.init_cpu(cpu, apic_id, ap_entry as u64, stack);
    }
    
    // 3. Start CPUs
    for cpu in 1..cpu_count {
        x2apic_send_iipi(apic_id);      // INIT
        delay_ms(10);
        x2apic_send_sipi(0x8000, apic_id);  // SIPI
        delay_us(200);
        x2apic_send_sipi(0x8000, apic_id);  // SIPI again
    }
}

// AP entry point (called from assembly)
#[no_mangle]
pub extern "C" fn ap_entry(cpu_data: *const CpuData) -> ! {
    let cpu_id = unsafe { (*cpu_data).idx };
    println!("CPU {} online!", cpu_id);
    
    // Your per-CPU work here
    loop { /* ... */ }
}
```

## Testing

### QEMU Command

```bash
qemu-system-x86_64 \
    -kernel target/x86_64-unknown-none/release/rust_multicore \
    -cpu host \
    -enable-kvm \
    -smp 4 \
    -m 128M \
    -serial stdio \
    -display none
```

### Expected Output

```
Rust Multicore Boot Starting...
x2APIC enabled on BSP
Found 4 CPUs
Boot trampoline copied to 0x8000
Relocations applied
Page table set: 0x10a000
Initialized CPU 1 (APIC ID 1)
...
Starting CPU 1...
SIPI sent to CPU 1
CPU 1 online! APIC ID: 1
...
All CPUs started!
```

## Troubleshooting

### Problem: Assembly doesn't compile

```bash
# Check GCC is installed
gcc --version

# Try compiling manually
cd src/boot
gcc -c -m64 -nostdlib boot_trampoline.S -o test.o
objdump -d test.o  # Verify output
```

### Problem: APs don't start

**Debug steps:**
1. Check CR3 value is valid (page table exists)
2. Verify low memory (0x8000) is accessible
3. Try with `-smp 1` first (BSP only)
4. Add `-d int` to QEMU to trace interrupts
5. Check serial output for SIPI messages

### Problem: Page fault in AP

**Likely causes:**
- Page tables don't map low memory (0x0-0x100000)
- CR3 not set correctly before starting APs
- Boot code not copied to 0x8000

**Solution:**
```rust
// Verify CR3 before starting APs
let cr3: u64;
unsafe { asm!("mov {}, cr3", out(reg) cr3); }
println!("CR3 = 0x{:x}", cr3);  // Should be valid PML4 address
```

### Problem: Rust linker errors

**Check:**
- `boot_trampoline.o` exists in project root
- Linker script includes it properly
- All symbols are exported with `.globl`

## Limitations

### Current Implementation

- ✅ Boots multiple CPUs successfully
- ✅ Each CPU gets own stack
- ✅ x2APIC working on all CPUs
- ❌ No per-CPU GS base setup (yet)
- ❌ No IPI communication between CPUs (yet)
- ❌ No scheduler/work queue (yet)
- ❌ No ACPI parsing (hardcoded CPU count)

### For Production Use, Add:

1. **ACPI MADT parsing** - Discover real CPU count and APIC IDs
2. **Per-CPU variables** - Use GS segment base register
3. **IPI handlers** - Implement IRQ handling for cross-CPU calls
4. **Memory allocator** - Dynamic stack allocation
5. **Synchronization** - Mutexes, atomic operations
6. **Exception handlers** - Per-CPU trap frames

## Build System Details

### Why Multiple Build Options?

**Makefile (recommended):**
- Most flexible
- Clear separation of concerns
- Easy to customize per-architecture flags
- Standard for system-level code

**build.rs:**
- Integrates with `cargo build`
- Automatic dependency tracking
- Works on all platforms Cargo supports
- More complex for assembly compilation

**Shell script:**
- Simplest for quick iteration
- Good for CI/CD
- Easy to understand
- Manual dependency tracking

### Makefile Targets

```makefile
all:        Build assembly + Rust
asm:        Compile boot_trampoline.S only
rust:       Cargo build (requires pre-compiled assembly)
run:        Build and run in QEMU
debug:      Run with GDB attached
clean:      Remove all build artifacts
```

## What This Gives You

This project provides a **working foundation** for multi-core Rust applications on KVM/QEMU. You get:

1. ✅ **Complete boot infrastructure** - 16/32/64-bit transitions
2. ✅ **x2APIC initialization** - IPI/SIPI sending
3. ✅ **Per-CPU management** - Stack allocation, entry functions
4. ✅ **Rust-friendly interface** - Safe wrappers over assembly
5. ✅ **Working example** - Boots 4 CPUs successfully

## Next Steps

To build a real application:

1. **Add synchronization primitives** (spinlocks, atomics)
2. **Implement work stealing scheduler** (per-CPU run queues)
3. **Setup IPI handlers** (wake up sleeping CPUs)
4. **Add memory management** (per-CPU heaps)
5. **Implement panic handler** (halt all CPUs on error)

## References

- [Unikraft Source](https://github.com/unikraft/unikraft)
- [Intel SDM Vol 3: System Programming](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)
- [x2APIC Specification](https://software.intel.com/content/www/us/en/develop/download/intel-64-architecture-x2apic-specification.html)
- [Multiprocessor Specification](https://pdos.csail.mit.edu/6.828/2008/readings/ia32/MPspec.pdf)

## License

Code extracted from Unikraft is BSD-3-Clause (see headers).
