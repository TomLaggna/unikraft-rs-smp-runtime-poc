// boot_trampoline_bindings.rs
// Rust FFI bindings to the boot trampoline assembly code
// For PIE builds on Unikraft, we provide placeholder implementations

/// Per-CPU data structure (must match boot_defs.h LCPU layout)
#[repr(C, align(64))]
pub struct CpuData {
    pub state: i32,
    pub idx: u32,
    pub id: u64,
    pub entry: u64,
    pub stack_ptr: u64,
    _padding: [u8; 32],
}

impl CpuData {
    pub const fn new() -> Self {
        Self {
            state: 0, // LCPU_STATE_OFFLINE
            idx: 0,
            id: 0,
            entry: 0,
            stack_ptr: 0,
            _padding: [0; 32],
        }
    }
}

pub struct BootTrampoline {
    target_addr: u64,
}

impl BootTrampoline {
    pub fn new(target_addr: u64) -> Self {
        assert!(
            target_addr < 0x100000,
            "Target address must be in first 1MB"
        );
        assert!(
            target_addr & 0xfff == 0,
            "Target address must be page-aligned"
        );

        Self { target_addr }
    }

    /// Get the size of the 16-bit boot code section
    #[allow(dead_code)]
    pub fn get_16bit_section_size() -> usize {
        // Placeholder - in real Unikraft integration, would get from kernel
        4096
    }

    /// Copy the boot trampoline to the target address
    /// Note: In PIE builds on Unikraft, this would use kernel APIs
    pub unsafe fn copy_to_target(&self) {
        // Placeholder - would be implemented via Unikraft kernel APIs
        println!("Info: Boot trampoline handled by Unikraft kernel");
    }

    /// Apply runtime relocations to the copied boot code
    pub unsafe fn apply_relocations(&self) {
        // Placeholder
        println!("Info: Relocations handled by Unikraft kernel");
    }

    /// Set the page table address for APs
    pub unsafe fn set_page_table(&self, _pml4_addr: u32) {
        // Placeholder
        println!("Info: Page table setup handled by Unikraft kernel");
    }

    /// Initialize a CPU data structure
    pub unsafe fn init_cpu(&self, _idx: usize, _id: u64, _entry: u64, _stack: u64) {
        // Placeholder
        println!("Info: CPU init handled by Unikraft kernel");
    }

    /// Get the SIPI vector for this trampoline location
    pub fn get_sipi_vector(&self) -> u8 {
        (self.target_addr >> 12) as u8
    }
}
