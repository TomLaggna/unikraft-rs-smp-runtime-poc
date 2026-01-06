// ap.rs - Application Processor entry point and runtime initialization

use super::ap_print::{ap_print, ap_print_hex, ap_print_u32};
use crate::ap_println; // Macro is exported to crate root
use crate::boot_trampoline_bindings;
use crate::cpu_startup::x2apic_enable;
use crate::ApTaskInfo;
use core::arch::asm;
use core::ptr;
use core::sync::atomic::Ordering;

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

        // Use ap_println! macro which works without full runtime
        ap_println!("CPU {} online! APIC ID: {}", cpu_id, cpu.id);
        ap_println!("TLS base: 0x{:016x}", tlsp);

        // Get task info from cpu_data
        let task_info_ptr = cpu.task_info_ptr as *const ApTaskInfo;
        if task_info_ptr.is_null() {
            ap_print("ERROR: No task info provided\n");
            loop {
                asm!("hlt");
            }
        }

        let task_info = &*task_info_ptr;
        let elf_entry = task_info.entry_point.load(Ordering::SeqCst);

        if elf_entry == 0 {
            ap_print("ERROR: No ELF entry point set\n");
            loop {
                asm!("hlt");
            }
        }

        ap_println!("Executing ELF at entry point: 0x{:016x}", elf_entry);

        // Set status to running
        task_info.status.store(1, Ordering::SeqCst);

        // Execute the ELF entry point
        // Cast to function pointer and call it
        let elf_fn: extern "C" fn() -> () = core::mem::transmute(elf_entry as usize);
        elf_fn();

        // Mark task as done
        task_info.status.store(2, Ordering::SeqCst);
        ap_println!("CPU {} completed ELF execution", cpu_id);

        // Wait for more work (simplified - just halt)
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
