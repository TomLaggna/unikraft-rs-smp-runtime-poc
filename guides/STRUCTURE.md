# Project Structure

```
rust_multicore/
│
├── README.md                    # MAIN DOCUMENTATION - START HERE
├── Cargo.toml                   # Rust package configuration
├── Makefile                     # Recommended build system
├── build.sh                     # Alternative: shell script build
├── run.sh                       # Run in QEMU
├── build.rs                     # Alternative: Cargo-integrated build (not recommended)
│
├── src/
│   ├── main.rs                  # Main entry point with BSP initialization
│   ├── cpu_startup.rs           # x2APIC, IPI, SIPI functions
│   │
│   ├── boot/                    # Boot trampoline (extracted from Unikraft)
│   │   ├── boot_trampoline.S    # 16→32→64 bit AP boot assembly
│   │   ├── boot_defs.h          # Constants, CR0/CR4 bits, CPUID flags
│   │   └── boot_trampoline_bindings.rs  # Rust FFI to assembly
│   │
│   └── complete_minimal_implementation.rs  # Alternative standalone impl (DEPRECATED)
│
├── build/                       # Build artifacts (gitignored)
│   ├── boot_trampoline.o        # Compiled assembly object
│   └── libboot_trampoline.a     # Static library linked with Rust
│
├── target/                      # Cargo build output (gitignored)
│   └── x86_64-unknown-none/
│       └── release/
│           └── rust_multicore   # Final kernel binary
│
├── guides/                      # Historical documentation
│   ├── README.md                # Guide index (points to main README)
│   └── *.md                     # Various guides (may be outdated)
│
└── runtime_dump.txt             # Assembly dump of Unikraft kernel (reference)
```

## Key Files

### Essential Files (Don't Delete!)

1. **[src/boot/boot_trampoline.S](src/boot/boot_trampoline.S)**
   - Complete x86_64 boot sequence extracted from Unikraft
   - Handles 16-bit → 32-bit → 64-bit transitions
   - Enables CPU features (PAE, long mode, FPU, SSE, AVX)
   - **Source:** Unikraft `plat/kvm/x86/lcpu_start.S`

2. **[src/boot/boot_defs.h](src/boot/boot_defs.h)**
   - All constants and bit definitions
   - CR0/CR4 control register bits
   - MSR numbers, CPUID flags
   - **Source:** Unikraft `plat/common/include/x86/cpu.h`

3. **[src/boot/boot_trampoline_bindings.rs](src/boot/boot_trampoline_bindings.rs)**
   - Rust FFI bindings to assembly
   - Safe wrappers for boot code management
   - Runtime relocation support

4. **[src/cpu_startup.rs](src/cpu_startup.rs)**
   - x2APIC initialization
   - IPI/SIPI/INIT sending functions
   - Delay/timing utilities
   - **Source:** Unikraft `drivers/ukintctlr/xpic/`

5. **[src/main.rs](src/main.rs)**
   - Main application entry point
   - Demonstrates multi-core initialization
   - BSP and AP entry functions

### Build System Files

**Option 1: Makefile (Recommended)**
- **[Makefile](Makefile)** - Full-featured build orchestration
- Targets: `all`, `asm`, `rust`, `run`, `debug`, `clean`
- Clear separation between assembly and Rust compilation

**Option 2: Shell Scripts**
- **[build.sh](build.sh)** - Simple linear build script
- **[run.sh](run.sh)** - Run compiled kernel in QEMU
- Good for CI/CD pipelines

**Option 3: Cargo Integration**
- **[build.rs](build.rs)** - Integrates assembly into `cargo build`
- Works but more complex, Makefile recommended

### Configuration Files

- **[Cargo.toml](Cargo.toml)** - Rust package manifest
  - Target: `x86_64-unknown-none` (KVM/QEMU, not bare metal)
  - Linker flags for assembly integration

### Documentation

- **[README.md](README.md)** - **PRIMARY DOCUMENTATION**
- **[guides/](guides/)** - Historical docs (may be outdated, see guides/README.md)

### Reference Files

- **[runtime_dump.txt](runtime_dump.txt)** - Unikraft kernel objdump
  - Shows what's in prebuilt Unikraft runtime
  - Proves we need custom build for SMP

## Build Artifacts (Gitignored)

```
build/
├── boot_trampoline.o            # Compiled from boot_trampoline.S
└── libboot_trampoline.a         # Static library for linking

target/
└── x86_64-unknown-none/
    └── release/
        └── rust_multicore       # Final executable kernel
```

## Deprecated Files

### complete_minimal_implementation.rs

This file was an early attempt at a standalone implementation. It's kept for reference but **DO NOT USE**. The modular approach (main.rs + boot/) is correct.

**Why it's deprecated:**
- ❌ Incomplete boot code
- ❌ Missing relocations
- ❌ Embedded boot bytes instead of proper assembly
- ❌ Harder to maintain

**Use instead:**
- ✅ `src/main.rs` + `src/boot/` modular structure

## Build Flow

### Using Makefile (Recommended)

```
make all
  ├─> make asm
  │    └─> gcc -c boot_trampoline.S → boot_trampoline.o
  │    └─> ar crs libboot_trampoline.a boot_trampoline.o
  │
  └─> cargo build --release
       └─> Links with libboot_trampoline.a
       └─> Produces target/.../rust_multicore
```

### Using Shell Scripts

```
./build.sh
  ├─> gcc -c boot_trampoline.S → build/boot_trampoline.o
  ├─> ar crs libboot_trampoline.a build/boot_trampoline.o
  └─> cargo build --release

./run.sh
  └─> qemu-system-x86_64 -kernel ... -smp 4
```

### Using Cargo Only

```
cargo build --release
  └─> build.rs runs first
       ├─> gcc -c boot_trampoline.S
       ├─> ar crs libboot_trampoline.a
       └─> Continue with Rust compilation
```

## Linker Requirements

The assembly code MUST be linked with the Rust binary. This is achieved via:

1. **Makefile approach:** Pre-build `libboot_trampoline.a`, tell rustc where to find it
2. **Cargo approach:** `build.rs` compiles it, outputs to `$OUT_DIR`, Cargo links automatically
3. **Manual approach:** Compile assembly, place in `build/`, add `-Lbuild -lboot_trampoline` to RUSTFLAGS

## Directory Conventions

- `src/` - All Rust source code
- `src/boot/` - Assembly and FFI bindings (boot infrastructure)
- `build/` - Assembly build artifacts
- `target/` - Cargo build output
- `guides/` - Documentation (use main README as primary)

## Adding New Files

### Adding Rust modules:
```rust
// In src/my_module.rs
pub fn my_function() { }

// In src/main.rs or lib.rs
mod my_module;
use my_module::my_function;
```

### Adding assembly code:
1. Create `.S` file in `src/boot/`
2. Add to Makefile `ASM_SRC` variable
3. Create Rust bindings in `src/boot/`
4. Export symbols with `.globl` directive

### Adding documentation:
1. Update main [README.md](README.md)
2. For detailed technical docs, add to `guides/` with clear date/version

## Testing Structure

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_boot_trampoline_size() {
        // Unit tests go here
    }
}
```

## Cleaning Up

```bash
make clean          # Remove all build artifacts
cargo clean         # Remove Cargo cache
rm -rf build target # Nuclear option
```

## Summary

**Start here:** [README.md](README.md)

**Build:** `make all` or `./build.sh`

**Run:** `make run` or `./run.sh`

**Core code:**
- `src/main.rs` - Entry point
- `src/boot/` - Boot infrastructure
- `src/cpu_startup.rs` - APIC functions
