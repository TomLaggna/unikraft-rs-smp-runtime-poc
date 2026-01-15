// main.rs - Complete example of multi-core initialization for KVM/QEMU x86_64
//
// ELF Execution Architecture:
// 1. BSP reads ELF from ramfs and parses it to get entry point
// 2. BSP creates shared ApTaskInfo structure with entry point address
// 3. BSP passes pointer to ApTaskInfo via CpuData.task_info_ptr
// 4. AP reads entry point from ApTaskInfo and executes it
// 5. AP sets status field to signal execution progress:
//    - 0 = idle
//    - 1 = running
//    - 2 = done
// 6. BSP monitors status field to detect completion

mod cpu_startup;
mod dandelion_commons;
mod elfloader;
mod user_handlers;
mod user_pagetable;

// Boot trampoline is in src/boot/ directory
#[path = "boot/boot_trampoline_bindings.rs"]
mod boot_trampoline_bindings;

// AP module with entry point and runtime initialization
#[macro_use]
mod ap;

use ap::ap_entry;
use ap::ApTaskInfo;
use boot_trampoline_bindings::BootTrampoline;
use core::arch::asm;
use core::ptr;
use cpu_startup::*;
use elfloader::elf_parser::ParsedElf;
use std::fs;

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

    // Step 2: Load and parse ELF file
    println!("\n=== Loading ELF file ===");
    let elf_path = "/elf/test_elf_unikernel_x86_64_basic";
    let elf_bytes = match fs::read(elf_path) {
        Ok(bytes) => {
            println!("✓ Read ELF file: {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            println!("✗ Failed to read ELF file '{}': {}", elf_path, e);
            panic!("Cannot proceed without ELF file");
        }
    };

    // Parse ELF to get entry point
    let parsed_elf = match ParsedElf::new(&elf_bytes) {
        Ok(elf) => {
            println!("✓ ELF parsed successfully");
            elf
        }
        Err(e) => {
            println!("✗ Failed to parse ELF: {:?}", e);
            panic!("Malformed ELF file");
        }
    };

    let elf_entry_point = parsed_elf.get_entry_point();
    println!("✓ ELF entry point: 0x{:x}", elf_entry_point);

    // ========================================================================
    // TEST: User Space Manager (Dandelion Pattern)
    // ========================================================================
    println!("\n=== Testing User Space Manager (Dandelion Pattern) ===");

    // Create a 64 MB user address space (reduced for 1GB RAM system)
    const USER_SPACE_SIZE: usize = 64 * 1024 * 1024; // 64 MB
    let mut user_space = unsafe {
        match user_pagetable::UserSpaceManager::new(USER_SPACE_SIZE) {
            Ok(us) => us,
            Err(e) => panic!("Failed to create user space: {}", e),
        }
    };

    user_space.print_stats();
    println!();

    // Example: Map a small code region
    // Allocate 64KB for user code in kernel space
    let user_code_size = 64 * 1024;
    let mut user_code_buf = vec![0u8; user_code_size];

    // Write simple code pattern (NOP instructions)
    for i in 0..user_code_size {
        user_code_buf[i] = 0x90; // NOP
    }

    // Map it at virtual address 0x400000 (typical ELF base) in user space
    let user_code_virt = 0x400000;
    let user_code_kernel_virt = user_code_buf.as_ptr() as usize;

    if let Err(e) = unsafe {
        user_space.map_user_range(user_code_virt, user_code_kernel_virt, user_code_size, false)
    } {
        panic!("Failed to map user code: {}", e);
    }

    println!("✓ Mapped user code region:");
    println!(
        "  User virtual:   0x{:x} - 0x{:x}",
        user_code_virt,
        user_code_virt + user_code_size
    );
    println!(
        "  Kernel virtual: 0x{:x} - 0x{:x}",
        user_code_kernel_virt,
        user_code_kernel_virt + user_code_size
    );
    println!();

    // Example: Map user stack
    // Stack must end BEFORE interrupt structures to avoid overlap
    let user_stack_size = 16 * 4096; // 64KB
    let mut user_stack_buf = vec![0u8; user_stack_size];
    // Place stack just below interrupt structures
    let interrupt_virt_base = user_space.get_interrupt_virt_base();
    let user_stack_virt = interrupt_virt_base - user_stack_size;
    let user_stack_kernel_virt = user_stack_buf.as_ptr() as usize;

    if let Err(e) = unsafe {
        user_space.map_user_range(
            user_stack_virt,
            user_stack_kernel_virt,
            user_stack_size,
            true,
        )
    } {
        panic!("Failed to map user stack: {}", e);
    }

    println!("✓ Mapped user stack:");
    println!(
        "  User virtual:   0x{:x} - 0x{:x}",
        user_stack_virt,
        user_stack_virt + user_stack_size
    );
    println!(
        "  Kernel virtual: 0x{:x} - 0x{:x}",
        user_stack_kernel_virt,
        user_stack_kernel_virt + user_stack_size
    );
    println!();

    println!(
        "✓ User space ready! CR3 = 0x{:016x}\n",
        user_space.get_cr3()
    );

    // Setup interrupt handlers for user space
    println!("=== Setting up user space interrupt handlers ===");

    // Get handler code and addresses from assembly
    let handler_code = unsafe { user_handlers::get_handler_code() };
    let handler_addresses = unsafe { user_handlers::get_handler_addresses() };
    let handler_base = handler_addresses[0]; // Use first handler as base

    println!("Handler code size: {} bytes", handler_code.len());
    println!("Original handler base: 0x{:016x}", handler_base);

    // Get current kernel stack for TSS.RSP0
    let kernel_stack: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) kernel_stack);
    }
    println!("Kernel stack (for TSS.RSP0): 0x{:016x}", kernel_stack);

    // Setup all interrupt infrastructure
    let _interrupt_config = unsafe {
        match user_space.setup_all_interrupt_infrastructure(
            handler_code,
            &handler_addresses,
            handler_base,
            kernel_stack,
        ) {
            Ok(config) => config,
            Err(e) => panic!("Failed to setup interrupt infrastructure: {}", e),
        }
    };

    // Allocate shared memory for AP task info in static storage (not heap)
    // Static variables are in the data segment and accessible by APs
    static mut AP_TASK_INFO: ApTaskInfo = ApTaskInfo::new();
    unsafe {
        // Write user space CR3 to AP task info so AP can load user page tables
        AP_TASK_INFO.write_user_cr3(user_space.get_cr3());
        println!(
            "✓ User CR3 written to AP task info: 0x{:016x}",
            user_space.get_cr3()
        );
    }
    unsafe {
        AP_TASK_INFO.write_entry_point(elf_entry_point as u64);
    }

    let task_info_ptr = unsafe { &AP_TASK_INFO as *const ApTaskInfo as u64 };
    println!("✓ AP task info at: 0x{:x}", task_info_ptr);
    println!();

    // Step 3: Get number of CPUs from ACPI (simplified - assumes 2 CPUs)
    // For debugging, only start 1 AP
    let cpu_count = 2; // BSP + 1 AP
    println!("Testing with {} CPUs (1 BSP + 1 AP)", cpu_count);

    // Step 4: Setup boot trampoline
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

            if let Err(e) = trampoline.init_cpu(i as u32, apic_id, entry, stack, task_info_ptr) {
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
                    delay_ms(1000);
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

        // Monitor AP task execution
        println!("\n=== Monitoring AP Task Execution ===");
        for retry in 0..200 {
            delay_ms(10);
            let status = AP_TASK_INFO.read_status();
            match status {
                0 => {
                    if retry % 10 == 0 {
                        println!("Waiting for AP to start ELF execution...");
                    }
                }
                1 => {
                    println!("✓ AP is executing ELF...");
                }
                2 => {
                    println!("✓ AP completed ELF execution!");
                    break;
                }
                _ => {
                    println!("⚠ Unknown status: {}", status);
                }
            }
            if retry == 199 {
                println!("⚠ Timeout waiting for AP task completion");
            }
        }
    }

    // Main completes - the kernel will take over
    println!("\n=== Main boot sequence complete! ===");
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
