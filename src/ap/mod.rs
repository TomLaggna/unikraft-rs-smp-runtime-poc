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
    pub status: u8,       // 0=idle, 1=running, 2=done
    _padding: [u8; 47],   // Padding to 64 bytes (cache line)
}

impl ApTaskInfo {
    pub const fn new() -> Self {
        Self {
            entry_point: 0,
            user_cr3: 0,
            status: 0,
            _padding: [0; 47],
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
}
