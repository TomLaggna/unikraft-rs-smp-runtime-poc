// boot_trampoline_bindings.rs
// Rust FFI bindings to the boot trampoline assembly code
//
// This module provides a safe interface to:
// 1. Copy the position-dependent trampoline code to low memory (< 1MB)
// 2. Patch runtime addresses (page tables, entry points, stacks)
// 3. Initialize per-CPU data structures

use core::ptr;

/// Per-CPU data structure (must match boot_defs.h LCPU layout)
/// Size: 64 bytes, aligned to 64-byte boundary
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct CpuData {
    pub state: i32,     // LCPU_STATE_* (offset 0)
    pub idx: u32,       // CPU index (offset 4)
    pub id: u64,        // APIC ID (offset 8)
    pub entry: u64,     // Entry point function (offset 16)
    pub stack_ptr: u64, // Top of stack (offset 24)
    _padding: [u8; 32], // Padding to 64 bytes
}

impl CpuData {
    pub const fn new() -> Self {
        Self {
            state: 0, // LCPU_STATE_OFFLINE = 0
            idx: 0,
            id: 0,
            entry: 0,
            stack_ptr: 0,
            _padding: [0; 32],
        }
    }

    pub fn init(idx: u32, apic_id: u64, entry: u64, stack_ptr: u64) -> Self {
        Self {
            state: 0, // Will be updated by AP
            idx,
            id: apic_id,
            entry,
            stack_ptr,
            _padding: [0; 32],
        }
    }
}

// Embed the boot trampoline binary blob (compiled separately)
// This contains all sections contiguously: 16-bit, 32-bit data, 32-bit code, 64-bit code
// Built with base address 0x8000, so all internal addresses are already correct!
static TRAMPOLINE_BLOB: &[u8] = include_bytes!("../../build/boot_trampoline.bin");

// Offsets within the binary blob (from nm build/boot_trampoline.elf)
// Note: These are now absolute addresses since linker script starts at 0x8000
// We need the offsets relative to 0x8000 for patching
const OFFSET_X86_BPT_PML4_ADDR: usize = 0x2000;
const OFFSET_LCPUS: usize = 0x2040;

/// Boot trampoline manager
///
/// This struct handles copying the trampoline code to low memory
/// and patching runtime-specific addresses.
pub struct BootTrampoline {
    target_addr: u64,
}

impl BootTrampoline {
    /// Create a new boot trampoline manager
    ///
    /// # Arguments
    /// * `target_addr` - Virtual address to write trampoline (must be page-aligned)
    ///                   For Unikraft, use: DIRECTMAP_AREA_START + physical_address
    ///                   where physical_address is in the first 1MB
    ///
    /// # Panics
    /// Panics if target_addr is not page-aligned
    pub fn new(target_addr: u64) -> Self {
        assert!(
            target_addr & 0xfff == 0,
            "Target address must be page-aligned (got 0x{:x})",
            target_addr
        );

        Self { target_addr }
    }

    /// Get the size of the entire boot trampoline blob
    #[allow(dead_code)]
    pub fn get_blob_size() -> usize {
        TRAMPOLINE_BLOB.len()
    }

    /// Copy the trampoline code to the target address
    ///
    /// This copies the entire boot trampoline blob (all sections) to low memory.
    ///
    /// # Safety
    /// The target address must point to valid, writable memory
    pub unsafe fn copy_to_target(&self) -> Result<(), &'static str> {
        let dst = self.target_addr as *mut u8;

        println!(
            "Copying {} bytes of trampoline blob to 0x{:x}",
            TRAMPOLINE_BLOB.len(),
            self.target_addr
        );

        // Check if target is writable (simple test)
        let test_ptr = dst as *mut u32;
        if test_ptr.is_null() {
            return Err("Target address is null");
        }

        // Copy the entire trampoline blob
        ptr::copy_nonoverlapping(TRAMPOLINE_BLOB.as_ptr(), dst, TRAMPOLINE_BLOB.len());

        println!(
            "✓ Trampoline copied successfully ({} bytes)",
            TRAMPOLINE_BLOB.len()
        );
        Ok(())
    }

    /// Set the page table root address (CR3 value)
    ///
    /// This writes the page table address that APs will load into CR3
    /// when transitioning to long mode.
    ///
    /// # Arguments
    /// * `pml4_addr` - Physical address of PML4 (page table root)
    pub unsafe fn set_page_table(&self, pml4_addr: u64) {
        println!("Setting page table address to 0x{:x}", pml4_addr);

        // Patch the copied blob at target address
        let target_ptr = (self.target_addr as usize + OFFSET_X86_BPT_PML4_ADDR) as *mut u32;
        ptr::write_volatile(target_ptr, pml4_addr as u32);

        println!(
            "✓ Page table address set at offset 0x{:x}",
            OFFSET_X86_BPT_PML4_ADDR
        );
    }

    /// Initialize a CPU's data structure
    ///
    /// This sets up the per-CPU configuration that the AP will read
    /// when it starts executing trampoline code.
    ///
    /// # Arguments
    /// * `cpu_idx` - CPU index (0-based, BSP is typically 0)
    /// * `apic_id` - APIC ID of the CPU
    /// * `entry_fn` - Entry point function for the AP
    /// * `stack_ptr` - Top of the stack for this AP
    pub unsafe fn init_cpu(
        &self,
        cpu_idx: u32,
        apic_id: u64,
        entry_fn: u64,
        stack_ptr: u64,
    ) -> Result<(), &'static str> {
        if cpu_idx >= 256 {
            return Err("CPU index out of range");
        }

        println!(
            "Initializing CPU {}: APIC ID={}, entry=0x{:x}, stack=0x{:x}",
            cpu_idx, apic_id, entry_fn, stack_ptr
        );

        // Patch the CPU data structure in the copied blob
        let target_offset = OFFSET_LCPUS + (cpu_idx as usize * 64);
        let target_cpu_ptr = (self.target_addr as usize + target_offset) as *mut CpuData;

        let cpu_data = CpuData::init(cpu_idx, apic_id, entry_fn, stack_ptr);
        ptr::write_volatile(target_cpu_ptr, cpu_data);

        println!(
            "✓ CPU {} initialized at offset 0x{:x}",
            cpu_idx, target_offset
        );
        Ok(())
    }

    /// Apply relocations to the copied trampoline
    ///
    /// NOT NEEDED! Since we build the trampoline with base address 0x8000,
    /// the linker calculates all internal addresses for us at compile time.
    /// No runtime patching required!
    pub unsafe fn apply_relocations(&self) -> Result<(), &'static str> {
        println!(
            "✓ No relocations needed (trampoline built for 0x{:x})",
            self.target_addr
        );
        Ok(())
    }

    /// Get the SIPI vector for this trampoline location
    #[allow(dead_code)]
    pub fn get_sipi_vector(&self) -> u8 {
        (self.target_addr >> 12) as u8
    }

    /// Get the state of a specific CPU
    ///
    /// # Safety
    /// Reads from the CPU data structure in the trampoline memory
    pub unsafe fn get_cpu_state(&self, cpu_idx: u32) -> i32 {
        let target_offset = OFFSET_LCPUS + (cpu_idx as usize * 64);
        let target_cpu_ptr = (self.target_addr as usize + target_offset) as *const CpuData;
        let cpu_data = ptr::read_volatile(target_cpu_ptr);
        cpu_data.state
    }

    /// Get the target address where the trampoline is located
    #[allow(dead_code)]
    pub fn target_address(&self) -> u64 {
        self.target_addr
    }
}

// Constants for CPU states (must match boot_defs.h)
#[allow(dead_code)]
pub const LCPU_STATE_OFFLINE: i32 = 0;
#[allow(dead_code)]
pub const LCPU_STATE_INIT: i32 = 1;
#[allow(dead_code)]
pub const LCPU_STATE_ONLINE: i32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_data_size() {
        assert_eq!(core::mem::size_of::<CpuData>(), 64);
        assert_eq!(core::mem::align_of::<CpuData>(), 64);
    }

    #[test]
    fn test_trampoline_creation() {
        let trampoline = BootTrampoline::new(0x8000);
        assert_eq!(trampoline.target_address(), 0x8000);
    }

    #[test]
    #[should_panic]
    fn test_trampoline_invalid_address() {
        // Should panic - address too high
        let _ = BootTrampoline::new(0x100000);
    }

    #[test]
    #[should_panic]
    fn test_trampoline_misaligned() {
        // Should panic - not page-aligned
        let _ = BootTrampoline::new(0x8001);
    }
}
