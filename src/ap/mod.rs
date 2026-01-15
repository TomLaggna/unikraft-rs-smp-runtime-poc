// ap/mod.rs - Application Processor module
use core::ptr;

pub mod ap;
pub mod ap_print;

// Re-export commonly used items
pub use ap::ap_entry;

/// Shared memory structure for BSP-AP communication
/// Uses primitive values with explicit memory fences for cross-core visibility
/// Access pattern:
/// - BSP writes before AP starts (initialization)
/// - After AP starts, BSP only reads (polling), AP only writes
/// - No concurrent writes, so no locking needed
#[repr(C, align(64))]
pub struct ApTaskInfo {
    pub entry_point: u64, // Entry point address for AP to execute
    pub user_cr3: u64,    // Physical address of user space PML4 (for CR3)
    pub kernel_cr3: u64,  // Physical address of kernel PML4 (for returning from user space)
    pub status: u8,       // 0=idle, 1=running, 2=done
    _padding1: [u8; 7],   // Padding before interrupt config
    // Interrupt configuration for user space
    pub gdt_base: u64,     // Virtual address of GDT in guest_mem
    pub gdt_limit: u16,    // GDT size - 1
    _padding2: [u8; 6],    // Padding after gdt_limit
    pub idt_base: u64,     // Virtual address of IDT in guest_mem
    pub idt_limit: u16,    // IDT size - 1
    _padding3: [u8; 6],    // Padding after idt_limit
    pub tss_base: u64,     // Virtual address of TSS in guest_mem
    pub tss_selector: u16, // TSS selector in GDT (0x28)
    _padding4: [u8; 6],    // Padding to maintain alignment
}

impl ApTaskInfo {
    pub const fn new() -> Self {
        Self {
            entry_point: 0,
            user_cr3: 0,
            kernel_cr3: 0,
            status: 0,
            _padding1: [0; 7],
            gdt_base: 0,
            gdt_limit: 0,
            _padding2: [0; 6],
            idt_base: 0,
            idt_limit: 0,
            _padding3: [0; 6],
            tss_base: 0,
            tss_selector: 0,
            _padding4: [0; 6],
        }
    }

    /// BSP writes entry point before starting AP
    /// Inserts Release fence to ensure visibility on AP
    pub fn write_entry_point(&self, value: u64) {
        unsafe {
            let ptr = &raw const self.entry_point as *mut u64;
            ptr::write_volatile(ptr, value);
        }
    }

    /// BSP writes user space CR3 before starting AP
    pub fn write_user_cr3(&self, value: u64) {
        unsafe {
            let ptr = &raw const self.user_cr3 as *mut u64;
            ptr::write_volatile(ptr, value);
        }
    }

    /// AP reads entry point after starting
    /// Inserts Acquire fence to ensure it sees BSP's writes
    pub fn read_entry_point(&self) -> u64 {
        unsafe {
            let ptr = &raw const self.entry_point as *const u64;
            ptr::read_volatile(ptr)
        }
    }

    /// AP reads user space CR3 after starting
    pub fn read_user_cr3(&self) -> u64 {
        unsafe {
            let ptr = &raw const self.user_cr3 as *const u64;
            ptr::read_volatile(ptr)
        }
    }

    /// AP writes status as it executes
    pub fn write_status(&self, value: u8) {
        unsafe {
            let ptr = &raw const self.status as *mut u8;
            ptr::write_volatile(ptr, value);
        }
    }

    /// BSP reads status to poll AP progress
    pub fn read_status(&self) -> u8 {
        unsafe {
            let ptr = &raw const self.status as *const u8;
            ptr::read_volatile(ptr)
        }
    }

    /// BSP writes kernel CR3 before starting AP
    pub fn write_kernel_cr3(&self, value: u64) {
        unsafe {
            let ptr = &raw const self.kernel_cr3 as *mut u64;
            ptr::write_volatile(ptr, value);
        }
    }

    /// AP reads kernel CR3 (for returning from user space)
    pub fn read_kernel_cr3(&self) -> u64 {
        unsafe {
            let ptr = &raw const self.kernel_cr3 as *const u64;
            ptr::read_volatile(ptr)
        }
    }

    /// BSP writes interrupt configuration from InterruptConfig
    pub fn write_interrupt_config(
        &self,
        gdt_base: u64,
        gdt_limit: u16,
        idt_base: u64,
        idt_limit: u16,
        tss_base: u64,
        tss_selector: u16,
    ) {
        unsafe {
            ptr::write_volatile(&raw const self.gdt_base as *mut u64, gdt_base);
            ptr::write_volatile(&raw const self.gdt_limit as *mut u16, gdt_limit);
            ptr::write_volatile(&raw const self.idt_base as *mut u64, idt_base);
            ptr::write_volatile(&raw const self.idt_limit as *mut u16, idt_limit);
            ptr::write_volatile(&raw const self.tss_base as *mut u64, tss_base);
            ptr::write_volatile(&raw const self.tss_selector as *mut u16, tss_selector);
        }
    }

    /// AP reads GDT configuration
    pub fn read_gdt_config(&self) -> (u64, u16) {
        unsafe {
            let base = ptr::read_volatile(&raw const self.gdt_base as *const u64);
            let limit = ptr::read_volatile(&raw const self.gdt_limit as *const u16);
            (base, limit)
        }
    }

    /// AP reads IDT configuration
    pub fn read_idt_config(&self) -> (u64, u16) {
        unsafe {
            let base = ptr::read_volatile(&raw const self.idt_base as *const u64);
            let limit = ptr::read_volatile(&raw const self.idt_limit as *const u16);
            (base, limit)
        }
    }

    /// AP reads TSS configuration
    pub fn read_tss_config(&self) -> (u64, u16) {
        unsafe {
            let base = ptr::read_volatile(&raw const self.tss_base as *const u64);
            let selector = ptr::read_volatile(&raw const self.tss_selector as *const u16);
            (base, selector)
        }
    }
}
