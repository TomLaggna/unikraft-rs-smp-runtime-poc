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
        trampoline.copy_to_target();
        println!("Boot trampoline copied to 0x{:x}", TRAMPOLINE_ADDR);

        // Apply runtime relocations
        trampoline.apply_relocations();
        println!("Relocations applied");

        // Set page table address (get from CR3)
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3);
        trampoline.set_page_table(cr3 as u32);
        println!("Page table set: 0x{:x}", cr3);

        // Step 4: Initialize per-CPU data structures
        for i in 1..cpu_count {
            // Allocate stack for this CPU
            let stack = alloc_stack(STACK_SIZE);

            // Get APIC ID (for simplicity, assume APIC ID == CPU index)
            let apic_id = i as u64;

            // Set entry point to our AP entry function
            let entry = ap_entry as *const () as u64;

            trampoline.init_cpu(i, apic_id, entry, stack);
            println!("Initialized CPU {} (APIC ID {})", i, apic_id);
        }

        // Step 5: Start all secondary CPUs
        for i in 1..cpu_count {
            let apic_id = i as u32;

            println!("Starting CPU {}...", i);

            // Send INIT IPI
            x2apic_send_iipi(apic_id);
            delay_ms(10);

            // Send SIPI (twice as per Intel specification)
            #[allow(unused_variables)]
            let vector = trampoline.get_sipi_vector();
            for _ in 0..2 {
                x2apic_send_sipi(TRAMPOLINE_ADDR, apic_id);
                delay_us(200);
            }

            println!("SIPI sent to CPU {}", i);
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
