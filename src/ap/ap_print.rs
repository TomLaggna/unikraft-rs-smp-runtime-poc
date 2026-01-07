// ap_print.rs - AP-safe serial output functions
// Simple serial I/O that doesn't require Rust runtime initialization

use core::arch::asm;

/// Simple serial output function safe for APs (no runtime dependencies)
pub fn ap_print(msg: &str) {
    unsafe {
        for byte in msg.bytes() {
            // Wait for transmitter to be ready
            loop {
                let mut status: u8;
                asm!("in al, dx", out("al") status, in("dx") 0x3FDu16, options(nomem, nostack));
                if status & 0x20 != 0 {
                    break;
                }
            }
            // Send the byte
            asm!("out dx, al", in("al") byte, in("dx") 0x3F8u16, options(nomem, nostack));
        }
    }
}

/// Simple println-like macro for APs (no allocator/locks needed)
#[macro_export]
macro_rules! ap_println {
    () => {
        $crate::ap::ap_print::ap_print("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct SerialWriter;
        impl core::fmt::Write for SerialWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::ap::ap_print::ap_print(s);
                Ok(())
            }
        }
        let _ = core::write!(SerialWriter, $($arg)*);
        $crate::ap::ap_print::ap_print("\n");
    }};
}
