// main.rs - Complete example of multi-core initialization for KVM/QEMU x86_64

mod cpu_startup;

// Boot trampoline is in src/boot/ directory
#[path = "boot/boot_trampoline_bindings.rs"]
mod boot_trampoline_bindings;

use boot_trampoline_bindings::BootTrampoline;
use core::arch::asm;
use core::ptr;
use cpu_startup::*;

const TRAMPOLINE_ADDR: u64 = 0x8000; // Standard location in first 1MB
const STACK_SIZE: usize = 16384; // 16KB stack per CPU

fn main() {
    // Initialize serial console for debugging (for custom output)
    // Note: On Unikraft with std, regular println! should work
    println!("Rust Multicore Boot Starting...");

    // Test: Send a character directly to COM1 (0x3F8) to verify `out` works
    unsafe {
        asm!("out dx, al", in("al") b'T' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
        asm!("out dx, al", in("al") b'E' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
        asm!("out dx, al", in("al") b'S' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
        asm!("out dx, al", in("al") b'T' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
        asm!("out dx, al", in("al") b'\n' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    }
    println!("Direct serial output test complete (should see TEST above)");

    // Step 1: Enable x2APIC on BSP
    unsafe {
        if let Err(e) = x2apic_enable() {
            panic!("Failed to enable x2APIC: {:?}", e);
        }
    }
    println!("x2APIC enabled on BSP");

    // Step 2: Get number of CPUs from ACPI (simplified - assumes 4 CPUs)
    let cpu_count = 4;
    println!("Found {} CPUs", cpu_count);

    // Step 3: Setup boot trampoline
    let trampoline = BootTrampoline::new(TRAMPOLINE_ADDR);

    unsafe {
        // Copy boot code to low memory
        if let Err(e) = trampoline.copy_to_target() {
            panic!("Failed to copy trampoline: {}", e);
        }
        println!("Boot trampoline copied to 0x{:x}", TRAMPOLINE_ADDR);

        // Verify the copy by reading back the first few bytes
        let verify_ptr = TRAMPOLINE_ADDR as *const u8;
        let first_bytes = core::slice::from_raw_parts(verify_ptr, 16);
        println!(
            "First 16 bytes at 0x{:x}: {:02x?}",
            TRAMPOLINE_ADDR, first_bytes
        );

        // Apply runtime relocations
        if let Err(e) = trampoline.apply_relocations() {
            panic!("Failed to apply relocations: {}", e);
        }
        println!("Relocations applied");

        // Set page table address (get from CR3)
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3);
        trampoline.set_page_table(cr3);
        println!("Page table set: 0x{:x}", cr3);

        // CRITICAL CHECK: Is low memory identity mapped or do we need address translation?
        // The bytes at virtual 0x8000 match our trampoline, BUT this doesn't tell us if
        // physical 0x8000 has the same content (which is what SIPI will execute from).

        // Try to determine the virtual->physical mapping by checking if we can access
        // the page table itself. CR3 points to physical 0x12000.
        // If there's a direct map (e.g., at 0xffff888000000000 + phys like Linux),
        // we might be able to read it there.

        // println!("Checking memory layout:");
        // println!("  CR3 (page table) is at physical: 0x{:x}", cr3);

        // // Try reading from virtual 0x8000 (where we think we copied the trampoline)
        // let virt_ptr = TRAMPOLINE_ADDR as *const u8;
        // let virt_bytes = core::slice::from_raw_parts(virt_ptr, 8);
        // println!(
        //     "  Virtual 0x{:x} contains: {:02x?}",
        //     TRAMPOLINE_ADDR, virt_bytes
        // );

        // // The first instruction in our trampoline is: mov al, 'A' (b0 41)
        // if virt_bytes[0] == 0xb0 && virt_bytes[1] == 0x41 {
        //     println!("  ✓ Virtual 0x8000 contains our trampoline code");
        //     println!("  ⚠  BUT: SIPI will jump to PHYSICAL 0x8000!");
        //     println!("  ⚠  If virtual 0x8000 != physical 0x8000, the AP will crash!");
        // }

        // // Check if CR3 is readable as a virtual address (would indicate identity mapping)
        // let can_read_cr3 = {
        //     let mut readable = false;
        //     // Try to read one byte - if this doesn't crash, it's mapped
        //     let test_ptr = cr3 as *const u8;
        //     // We can't actually test this safely without catching the page fault...
        //     // For now, assume we CANNOT directly access physical memory
        //     println!("  ✗ Cannot directly access physical addresses (CR3 test would crash)");
        //     readable
        // };

        // // Check common direct-map regions:
        // // Linux: 0xffff888000000000 + physical
        // // Some kernels: identity map in low memory
        // println!("Checking if low memory might be identity mapped:");
        // let low_mem_works = virt_bytes[0] == 0xb0; // We already read this successfully
        // if low_mem_works {
        //     println!("  → Virtual 0x8000 is readable and contains expected code");
        //     println!("  → ASSUMING low memory is identity mapped (Unikraft common pattern)");
        //     println!("  → If SIPI fails, virtual 0x8000 ≠ physical 0x8000");
        // }

        // Step 4: Initialize per-CPU data structures
        for i in 1..cpu_count {
            // Allocate stack for this CPU
            let stack = alloc_stack(STACK_SIZE);

            // Get APIC ID (for simplicity, assume APIC ID == CPU index)
            let apic_id = i as u64;

            // Set entry point to our AP entry function
            let entry = ap_entry as *const () as u64;

            if let Err(e) = trampoline.init_cpu(i, apic_id, entry, stack) {
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
            let vector = trampoline.get_sipi_vector();
            println!(
                "  SIPI vector: 0x{:x} (addr=0x{:x})",
                vector, TRAMPOLINE_ADDR
            );
            x2apic_send_sipi(TRAMPOLINE_ADDR, apic_id);
            delay_us(200);
            x2apic_send_sipi(TRAMPOLINE_ADDR, apic_id);
            delay_us(200);

            // Wait up to 1 second for CPU to come online
            for retry in 0..100 {
                delay_ms(10);
                let state = trampoline.get_cpu_state(i);
                if state != 0 {
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

/// Entry point for Application Processors (APs)
/// Called from boot_trampoline.S after CPU is in 64-bit mode
#[no_mangle]
pub extern "C" fn ap_entry(cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    unsafe {
        let cpu = &*cpu_data;
        let cpu_id = cpu.idx;

        // Enable x2APIC on this CPU
        if let Err(_) = x2apic_enable() {
            loop {
                asm!("hlt");
            }
        }

        // Simple output to show we're alive
        println!("CPU {} online! APIC ID: {}", cpu_id, cpu.id);

        // Mark CPU as IDLE
        let state_ptr = &raw const cpu.state as *mut i32;
        ptr::write_volatile(state_ptr, 2); // LCPU_STATE_IDLE

        // Wait for work (simplified - just halt)
        loop {
            asm!("hlt");
        }
    }
}

/// Allocate a stack (simplified - in real code use proper allocator)
fn alloc_stack(size: usize) -> u64 {
    static mut STACK_MEMORY: [u8; 4 * 16384] = [0; 4 * 16384];
    static mut STACK_OFFSET: usize = 0;

    unsafe {
        let stack_base =
            core::ptr::addr_of!(STACK_MEMORY) as *const u8 as u64 + STACK_OFFSET as u64;
        STACK_OFFSET += size;
        stack_base + size as u64 // Return top of stack
    }
}
