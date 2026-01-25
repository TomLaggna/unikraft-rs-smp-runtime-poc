// src/debug_utils.rs

// Re-export common types needed for debug routines
pub use crate::user_pagetable::{walk_pt, walk_pt_with_flags};

#[macro_export]
macro_rules! debug_ap_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-ap-boot")]
        {
            // We use standard println! here because in this Unikraft/linkage setup,
            // standard print macros are often wired to the console.
            // If they aren't available in specific contexts (like early AP),
            // this might need to change to a serial output function.
            println!($($arg)*);
        }
    }
}

#[macro_export]
macro_rules! debug_mem_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-user-mem")]
        {
            println!($($arg)*);
        }
    }
}

#[macro_export]
macro_rules! debug_trampoline_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-trampoline")]
        {
            println!($($arg)*);
        }
    }
}

/// Helper to hex dump a memory region if debug-user-mem is enabled
#[cfg(feature = "debug-user-mem")]
pub unsafe fn dump_memory(start: *const u8, len: usize) {
    use core::slice;
    let data = slice::from_raw_parts(start, len);
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        println!();
    }
}

#[cfg(not(feature = "debug-user-mem"))]
pub unsafe fn dump_memory(_start: *const u8, _len: usize) {}

/// Helper to walk page tables and print details if feature enabled
#[cfg(feature = "debug-user-mem")]
pub unsafe fn inspect_address(cr3: u64, va: u64, name: &str) {
    println!("INSPECT: {}", name);
    println!("  VA: 0x{:016x}", va);
    match crate::user_pagetable::walk_pt_with_flags(cr3, va) {
        Ok((pa, flags)) => {
            println!("  -> PA: 0x{:016x}", pa);
            println!("  -> Flags: 0x{:x} (P={}, RW={}, U={}, NX={})", 
                flags,
                (flags & 1),
                (flags >> 1) & 1,
                (flags >> 2) & 1,
                (flags >> 63) & 1
            );
        }
        Err(e) => {
            println!("  -> WALK FAILED: {}", e);
        }
    }
}

#[cfg(not(feature = "debug-user-mem"))]
pub unsafe fn inspect_address(_cr3: u64, _va: u64, _name: &str) {}
