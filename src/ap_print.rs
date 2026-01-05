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
        $crate::ap_print::ap_print("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct SerialWriter;
        impl core::fmt::Write for SerialWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::ap_print::ap_print(s);
                Ok(())
            }
        }
        let _ = core::write!(SerialWriter, $($arg)*);
        $crate::ap_print::ap_print("\n");
    }};
}

/// Print a decimal number (for AP output)
pub fn ap_print_u32(n: u32) {
    if n == 0 {
        unsafe {
            asm!("out dx, al", in("al") b'0' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
        }
        return;
    }

    let mut num = n;
    let mut digits = [0u8; 10];
    let mut i = 0;

    while num > 0 {
        digits[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }

    unsafe {
        while i > 0 {
            i -= 1;
            asm!("out dx, al", in("al") digits[i], in("dx") 0x3F8u16, options(nomem, nostack));
        }
    }
}

/// Print hex number (helper for debugging)
pub fn ap_print_hex(n: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    // Print leading zeros for full 64-bit hex
    for shift in (0..64).rev().step_by(4) {
        let nibble = ((n >> shift) & 0xF) as usize;
        let ch = HEX_CHARS[nibble];

        // Wait for UART ready and send byte
        unsafe {
            loop {
                let mut status: u8;
                asm!(
                    "in al, dx",
                    out("al") status,
                    in("dx") 0x3FDu16,
                    options(nomem, nostack)
                );
                if (status & 0x20) != 0 {
                    break;
                }
            }
            asm!(
                "out dx, al",
                in("al") ch,
                in("dx") 0x3F8u16,
                options(nomem, nostack)
            );
        }
    }
}
