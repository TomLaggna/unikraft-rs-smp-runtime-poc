// ap/mod.rs - Application Processor module

pub mod ap;
pub mod ap_print;

// Re-export commonly used items
pub use ap::{alloc_aligned, ap_entry, ap_runtime_init};
pub use ap_print::{ap_print, ap_print_hex, ap_print_u32};
