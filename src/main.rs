// main.rs - Complete example of multi-core initialization for KVM/QEMU x86_64

mod cpu_startup;

// Boot trampoline is in src/boot/ directory
#[path = "boot/boot_trampoline_bindings.rs"]
mod boot_trampoline_bindings;

#[macro_use]
mod ap_print;

use ap_print::{ap_print, ap_print_hex, ap_print_u32};
use boot_trampoline_bindings::BootTrampoline;
use core::arch::asm;
use core::ptr;
use cpu_startup::*;

// Unikraft direct-map region (physical memory mapped at high virtual addresses)
const DIRECTMAP_AREA_START: u64 = 0xffffff8000000000; // -512 GiB

const TRAMPOLINE_PHYS_ADDR: u64 = 0x8000; // Physical location in first 1MB
const TRAMPOLINE_VIRT_ADDR: u64 = DIRECTMAP_AREA_START + TRAMPOLINE_PHYS_ADDR; // Direct-map virtual address
const STACK_SIZE: usize = 1 << 14; // 16KB stack per CPU

fn main() {
    // Initialize serial console for debugging (for custom output)
    // Note: On Unikraft with std, regular println! should work
    println!("Rust Multicore Boot Starting...");

    // Check where we (BSP) are running from
    let main_addr = main as *const () as u64;
    println!("BSP running from: main() at 0x{:x}", main_addr);
    let ap_entry_addr = ap_entry as *const () as u64;
    println!("AP entry point: ap_entry() at 0x{:x}", ap_entry_addr);

    // Step 1: Enable x2APIC on BSP
    unsafe {
        if let Err(e) = x2apic_enable() {
            panic!("Failed to enable x2APIC: {:?}", e);
        }
    }
    println!("x2APIC enabled on BSP");

    // Step 2: Get number of CPUs from ACPI (simplified - assumes 2 CPUs)
    // For debugging, only start 1 AP
    let cpu_count = 2; // BSP + 1 AP
    println!("Testing with {} CPUs (1 BSP + 1 AP)", cpu_count);

    // Step 3: Setup boot trampoline
    // Use Unikraft's direct-map region to access physical memory
    println!("Setting up trampoline:");
    println!("  Physical address: 0x{:x}", TRAMPOLINE_PHYS_ADDR);
    println!("  Direct-map virtual address: 0x{:x}", TRAMPOLINE_VIRT_ADDR);
    let trampoline = BootTrampoline::new(TRAMPOLINE_VIRT_ADDR);

    unsafe {
        // Copy boot code to low memory
        if let Err(e) = trampoline.copy_to_target() {
            panic!("Failed to copy trampoline: {}", e);
        }
        println!(
            "Boot trampoline copied via direct-map to physical 0x{:x}",
            TRAMPOLINE_PHYS_ADDR
        );

        // Verify the copy by reading back the first few bytes from direct-map
        let verify_ptr = TRAMPOLINE_VIRT_ADDR as *const u8;
        let first_bytes = core::slice::from_raw_parts(verify_ptr, 16);
        println!(
            "First 16 bytes at direct-map 0x{:x}: {:02x?}",
            TRAMPOLINE_VIRT_ADDR, first_bytes
        );

        // Verify it starts with our 'out' instruction: mov al, 'A' (b0 41)
        if first_bytes[0] == 0xb0 && first_bytes[1] == 0x41 {
            println!("✓ Trampoline verified - starts with mov al, 'A'");
        } else {
            println!("⚠ WARNING: Unexpected bytes (expected b0 41...)");
        }

        // Apply runtime relocations
        if let Err(e) = trampoline.apply_relocations() {
            panic!("Failed to apply relocations: {}", e);
        }
        println!("Relocations applied");

        // Set page table address (get from CR3)
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3);

        println!("BSP's current CR3: 0x{:x}", cr3);

        // CRITICAL: Add identity mapping for trampoline (0x0-0x200000 covers first 2MB)
        // The AP needs this when it enables paging in 32-bit mode
        println!("Adding identity mapping for trampoline in page tables...");
        add_identity_mapping(cr3, 0x0, 0x200000); // Map first 2MB identity
        println!("✓ Identity mapping added: 0x0-0x200000 -> 0x0-0x200000");

        trampoline.set_page_table(cr3);
        println!("Page table set: 0x{:x}", cr3);

        // Step 4: Initialize per-CPU data structures
        for i in 1..cpu_count {
            // EXPERIMENT: Use stack in low memory (identity-mapped region)
            // Allocate at 0x7000 (just before our trampoline at 0x8000)
            let stack_base = 0x7000 - (i as u64 * STACK_SIZE as u64);
            let stack = stack_base;
            println!("  CPU {} stack in low memory: 0x{:x}", i, stack);

            // Get APIC ID (for simplicity, assume APIC ID == CPU index)
            let apic_id = i as u64;

            // Set entry point to our AP entry function
            let entry = ap_entry as *const () as u64;
            println!("  Entry address for CPU {}: 0x{:x}", i, entry);

            if let Err(e) = trampoline.init_cpu(i as u32, apic_id, entry, stack) {
                panic!("Failed to initialize CPU {}: {}", i, e);
            }
            println!("Initialized CPU {} (APIC ID {})", i, apic_id);
        }

        // Step 5: Start all secondary CPUs
        for i in 1..cpu_count {
            let apic_id = i as u32;

            println!("Starting CPU {}...", i);

            // Send INIT IPI (assert)
            x2apic_send_iipi(apic_id);
            delay_ms(10);

            // De-assert INIT before sending SIPI (required by Intel spec)
            cpu_startup::deassert_init_ipi(apic_id);
            delay_ms(1); // Give it a bit more time

            println!("  About to send SIPI...");

            // Send SIPI (twice as per Intel specification)
            // SIPI uses PHYSICAL address, so use TRAMPOLINE_PHYS_ADDR
            let vector = (TRAMPOLINE_PHYS_ADDR >> 12) as u8;
            println!(
                "  SIPI vector: 0x{:x} (physical addr=0x{:x})",
                vector, TRAMPOLINE_PHYS_ADDR
            );
            x2apic_send_sipi(TRAMPOLINE_PHYS_ADDR, apic_id);
            delay_us(200);
            x2apic_send_sipi(TRAMPOLINE_PHYS_ADDR, apic_id);
            delay_us(200);
            // Wait up to 1 second for CPU to come online
            for retry in 0..100 {
                delay_ms(10);
                let state = trampoline.get_cpu_state(i);
                if state != 0 {
                    delay_ms(100);
                    println!("  CPU {} came online! State: {}", i, state);
                    break;
                }
                if retry == 99 {
                    println!(
                        "  WARNING: CPU {} did not respond after 1 second (state={})",
                        i, state
                    );
                }
            }
        }

        println!("All CPUs started!");
    }

    // Main completes - the kernel will take over
    println!("Main boot sequence complete!");
}

/// Add identity mapping for low memory in page tables
/// Maps virtual address range to the same physical addresses (identity map)
unsafe fn add_identity_mapping(cr3: u64, _virt_start: u64, _size: u64) {
    // Use direct-map to access page table physical memory
    let pml4_phys = cr3 & !0xFFF;
    let pml4_virt = DIRECTMAP_AREA_START + pml4_phys;
    let pml4 = pml4_virt as *mut u64;

    // For 0x0-0x200000 (first 2MB), we need PML4[0] -> PDPT[0] -> PD[0]
    // Use a 2MB huge page for simplicity

    let pml4_entry = ptr::read_volatile(pml4.add(0));
    let pdpt_phys = if pml4_entry & 1 == 0 {
        // PML4[0] not present, this shouldn't happen but handle it
        panic!("PML4[0] not present - cannot add identity mapping");
    } else {
        pml4_entry & !0xFFF
    };

    let pdpt_virt = DIRECTMAP_AREA_START + pdpt_phys;
    let pdpt = pdpt_virt as *mut u64;

    let pdpt_entry = ptr::read_volatile(pdpt.add(0));
    let pd_phys = if pdpt_entry & 1 == 0 {
        // PDPT[0] not present, shouldn't happen
        panic!("PDPT[0] not present - cannot add identity mapping");
    } else {
        pdpt_entry & !0xFFF
    };

    let pd_virt = DIRECTMAP_AREA_START + pd_phys;
    let pd = pd_virt as *mut u64;

    // Map first 2MB as identity using a 2MB huge page
    // PD[0] = 0x0 | Present | Write | PageSize(2MB)
    let pd_entry = 0x0 | 0x1 | 0x2 | 0x80; // phys=0, P=1, RW=1, PS=1
    ptr::write_volatile(pd.add(0), pd_entry);

    // Flush TLB for this mapping
    asm!("invlpg [{}]", in(reg) 0x0usize, options(nostack, preserves_flags));
}

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
fn ap_runtime_init() -> Result<usize, i32> {
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
fn alloc_aligned(size: usize, align: usize) -> Result<usize, i32> {
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
