# Solution: Force All Trampoline Sections To Link

## Problem
The Rust linker only includes referenced symbols. Currently:
- ✅ x86_start16_begin, x86_start16_end (referenced) → .text.boot.16 linked
- ❌ lcpu_start32 (unreferenced) → .text.boot.32 NOT linked
- ❌ lcpu_start64 (unreferenced) → .text.boot.64 NOT linked
- ❌ gdt64 (unreferenced) → .data.boot.32 NOT linked

## Solution 1: Reference All Symbols

Add to boot_trampoline_bindings.rs:

```rust
extern "C" {
    // Code section boundaries (MUST reference all sections)
    static x86_start16_begin: u8;
    static x86_start16_end: u8;
    
    // Force 32-bit section to link
    static lcpu_start32: u8;
    static gdt64: u8;
    static gdt64_ptr: u8;
    
    // Force 64-bit section to link
    static lcpu_start64: u8;
    
    // Data structures
    static mut x86_bpt_pml4_addr: u32;
    static mut lcpus: [CpuData; 256];
}
```

Then in BootTrampoline::new(), reference them to prevent dead code elimination:

```rust
pub fn new(target_addr: u64) -> Self {
    // ... assertions ...
    
    // Prevent linker from eliminating unreferenced sections
    unsafe {
        let _ = &lcpu_start32;
        let _ = &lcpu_start64;
        let _ = &gdt64;
    }
    
    Self { target_addr }
}
```

## Solution 2: Custom Linker Script

Create a linker script that forces inclusion and makes sections contiguous:

```ld
/* boot_trampoline.ld */
SECTIONS {
    .boot_blob : {
        PROVIDE(__boot_blob_start = .);
        *(.text.boot.16)
        *(.data.boot.32)
        *(.text.boot.32)
        *(.text.boot.64)
        PROVIDE(__boot_blob_end = .);
    }
    
    .boot_data : {
        *(.data)  /* x86_bpt_pml4_addr, lcpus */
    }
}
```

Then use `__boot_blob_start` and `__boot_blob_end` as copy boundaries.

## Solution 3: Build Separate Binary (BEST)

Create a separate build step that produces a raw binary blob:

### Makefile addition:
```makefile
TRAMPOLINE_BIN := $(BUILD_DIR)/boot_trampoline.bin
TRAMPOLINE_SCRIPT := src/boot/boot_trampoline.ld

$(TRAMPOLINE_BIN): $(ASM_OBJ)
	$(CC) -nostdlib -T$(TRAMPOLINE_SCRIPT) -o $(BUILD_DIR)/boot_trampoline.elf $(ASM_OBJ)
	objcopy -O binary $(BUILD_DIR)/boot_trampoline.elf $@
	@echo "✓ Boot trampoline binary: $@ ($$(stat -f%z $@) bytes)"
```

### Linker script (boot_trampoline.ld):
```ld
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(lcpu_start16_ap)

SECTIONS {
    . = 0x8000;  /* Target load address */
    
    .text : {
        *(.text.boot.16)
        *(.data.boot.32)
        *(.text.boot.32)
        *(.text.boot.64)
    }
    
    .data : {
        x86_bpt_pml4_addr = .;
        . += 4;
        
        . = ALIGN(64);
        lcpus = .;
        . += (64 * 256);  /* 256 CPUs * 64 bytes */
    }
}
```

### Rust code:
```rust
static TRAMPOLINE_BLOB: &[u8] = include_bytes!("../../build/boot_trampoline.bin");

pub unsafe fn copy_to_target(&self) -> Result<(), &'static str> {
    let dst = self.target_addr as *mut u8;
    ptr::copy_nonoverlapping(
        TRAMPOLINE_BLOB.as_ptr(),
        dst,
        TRAMPOLINE_BLOB.len()
    );
    Ok(())
}
```

## Which Solution?

1. **Try Solution 1 first** - Quick, might work
2. **If linker still doesn't include sections, use Solution 3** - Most robust
3. **Solution 2 is middle ground** - Complex but flexible

## Next Steps

1. Implement Solution 1 (reference all symbols)
2. Rebuild and check: `nm target/.../smp-poc | grep lcpu_start`
3. If lcpu_start32/64 appear, verify sizes and proceed
4. If not, fall back to Solution 3 (separate binary)
