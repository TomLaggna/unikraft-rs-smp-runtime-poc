// ap/mod.rs - Application Processor module
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

pub mod ap;
pub mod ap_print;

// Re-export commonly used items
pub use ap::{alloc_aligned, ap_entry, ap_runtime_init};
pub use ap_print::{ap_print, ap_print_hex, ap_print_u32};

/// Shared memory structure for BSP-AP communication
#[repr(C, align(64))]
pub struct ApTaskInfo {
    pub entry_point: AtomicU64, // Entry point address for AP to execute
    pub status: AtomicU8,       // 0=idle, 1=running, 2=done
    _padding: [u8; 55],         // Padding to 64 bytes
}

impl ApTaskInfo {
    pub const fn new() -> Self {
        Self {
            entry_point: AtomicU64::new(0),
            status: AtomicU8::new(0),
            _padding: [0; 55],
        }
    }
}
