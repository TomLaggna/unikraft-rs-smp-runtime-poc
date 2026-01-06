// ap.rs - Application Processor entry point and runtime initialization

use super::ap_print::{ap_print, ap_print_hex, ap_print_u32};
use crate::ap_println; // Macro is exported to crate root
use crate::boot_trampoline_bindings;
use crate::cpu_startup::x2apic_enable;
use core::arch::asm;
use core::ptr;

/// Entry point for Application Processors (APs)
#[no_mangle]
pub extern "C" fn ap_entry(cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    unsafe {
        // Debug: Send 'Z' to show we made it to ap_entry_real
        // asm!("out dx, al", in("al") b'Z' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        let cpu = &*cpu_data;
        let cpu_id = cpu.idx;

        // Debug: Send '!' after reading cpu_id
        // asm!("out dx, al", in("al") b'!' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        // Enable x2APIC on this CPU
        if let Err(_) = x2apic_enable() {
            loop {
                asm!("hlt");
            }
        }

        // Debug: Send '@' after x2APIC enabled
        asm!("out dx, al", in("al") b'@' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        // Mark CPU as IDLE
        let state_ptr = &raw const cpu.state as *mut i32;
        ptr::write_volatile(state_ptr, 2); // LCPU_STATE_IDLE

        // Debug: Send '#' after state set
        asm!("out dx, al", in("al") b'#' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        // Initialize Rust runtime for this AP (TLS, etc.)
        let tlsp = match ap_runtime_init() {
            Ok(tls_ptr) => tls_ptr,
            Err(e) => {
                ap_print("Failed to initialize runtime: ");
                ap_print_u32(e as u32);
                ap_print("\n");
                loop {
                    asm!("hlt");
                }
            }
        };

        ap_print("Runtime init complete\n");

        // Test 1: Basic arithmetic
        ap_print("Test 1: Arithmetic... ");
        let result = 5u32 + 7u32;
        if result == 12 {
            ap_print("PASS (5+7=12)\n");
        } else {
            ap_print("FAIL\n");
        }

        // Test 2: Stack usage - local variables
        ap_print("Test 2: Stack arrays... ");
        let mut stack_test: [u64; 4] = [1, 2, 3, 4];
        stack_test[0] = stack_test[1] + stack_test[2];
        if stack_test[0] == 5 {
            ap_print("PASS (1+2+3+4, arr[0]=5)\n");
        } else {
            ap_print("FAIL\n");
        }

        // Test 3: Function calls (stack frame test)
        ap_print("Test 3: Function calls... ");
        fn test_multiply(x: u32, y: u32) -> u32 {
            x * y
        }
        let mult_result = test_multiply(3, 4);
        if mult_result == 12 {
            ap_print("PASS (3*4=12)\n");
        } else {
            ap_print("FAIL\n");
        }

        // Use ap_println! macro which works without full runtime
        ap_println!("CPU {} online! APIC ID: {}", cpu_id, cpu.id);
        ap_println!("TLS base: 0x{:016x}", tlsp);

        // Wait for work (simplified - just halt)
        loop {
            asm!("hlt");
        }
    }
}

/// Initialize Rust runtime for AP (mainly TLS setup)
pub fn ap_runtime_init() -> Result<usize, i32> {
    // TLS symbols from linker
    extern "C" {
        static _tls_start: u8;
        static _etdata: u8;
        static _tls_end: u8;
    }

    unsafe {
        let tls_start = &_tls_start as *const u8 as usize;
        let etdata = &_etdata as *const u8 as usize;
        let tls_end = &_tls_end as *const u8 as usize;

        let tdata_len = etdata - tls_start;
        let tbss_len = tls_end - etdata;

        // Calculate TLS area size (same as Unikraft's ukarch_tls_area_size)
        // x86_64: TLS data + padding + TCB (8 bytes for self-pointer)
        let tls_data_size = tdata_len + tbss_len;
        let tls_data_aligned = (tls_data_size + 7) & !7; // align to 8
        let tcb_size = 8; // Just the self-pointer for minimal TCB
        let tls_total_size = tls_data_aligned + tcb_size;

        // Allocate TLS area (32-byte aligned for x86_64)
        let tls_area = alloc_aligned(tls_total_size, 32)?;

        // Calculate TLS pointer (points to TCB, which is at the end)
        let tlsp = tls_area + tls_total_size - tcb_size;

        // Initialize TLS area:
        // 1. Copy .tdata section
        core::ptr::copy_nonoverlapping(tls_start as *const u8, tls_area as *mut u8, tdata_len);

        // 2. Zero .tbss section
        core::ptr::write_bytes((tls_area + tdata_len) as *mut u8, 0, tbss_len);

        // 3. Zero padding
        if tls_data_aligned > tls_data_size {
            core::ptr::write_bytes(
                (tls_area + tdata_len + tbss_len) as *mut u8,
                0,
                tls_data_aligned - tls_data_size,
            );
        }

        // 4. Set up TCB self-pointer (required by x86_64 TLS ABI)
        *(tlsp as *mut usize) = tlsp;

        // 5. Set FS base register to point to TLS
        core::arch::asm!(
            "wrfsbase {0}",
            in(reg) tlsp,
            options(nostack, preserves_flags)
        );

        ap_print("TLS initialized at 0x");
        ap_print_hex(tlsp as u64);
        ap_print("\n");

        Ok(tlsp)
    }
}

/// Allocate aligned memory (simplified - use static pool)
pub fn alloc_aligned(size: usize, align: usize) -> Result<usize, i32> {
    static mut TLS_MEMORY: [u8; 8192] = [0; 8192]; // 8KB should be enough
    static mut TLS_OFFSET: usize = 0;

    unsafe {
        // Align current offset
        let base = core::ptr::addr_of!(TLS_MEMORY) as usize;
        let current = base + TLS_OFFSET;
        let aligned = (current + align - 1) & !(align - 1);
        let offset_aligned = aligned - base;

        // Check bounds without creating reference
        if offset_aligned + size > 8192 {
            return Err(-12); // ENOMEM
        }

        TLS_OFFSET = offset_aligned + size;
        Ok(aligned)
    }
}
