// main.rs - Complete example of multi-core initialization for KVM/QEMU x86_64

mod cpu_startup;

// Boot trampoline is in src/boot/ directory
#[path = "boot/boot_trampoline_bindings.rs"]
mod boot_trampoline_bindings;

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

    // Test: Send a character directly to COM1 (0x3F8) to verify `out` works
    // unsafe {
    //     asm!("out dx, al", in("al") b'T' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    //     asm!("out dx, al", in("al") b'E' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    //     asm!("out dx, al", in("al") b'S' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    //     asm!("out dx, al", in("al") b'T' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    //     asm!("out dx, al", in("al") b'\n' as u8, in("dx") 0x3F8u16, options(nomem, nostack));
    // }
    // println!("Direct serial output test complete (should see TEST above)");

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
unsafe fn add_identity_mapping(cr3: u64, virt_start: u64, size: u64) {
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

/// Check if a virtual address is mapped and get its attributes
unsafe fn check_mapping(cr3: u64, virt_addr: u64) -> bool {
    // 953MB physical memory limit from QEMU config
    const PHYS_MEM_LIMIT: u64 = 953 * 1024 * 1024; // 0x3B900000

    let pml4_phys = cr3 & !0xFFF;
    let pml4_virt = DIRECTMAP_AREA_START + pml4_phys;
    let pml4 = pml4_virt as *const u64;

    let pml4_idx = (virt_addr >> 39) & 0x1FF;
    let pml4_entry = ptr::read_volatile(pml4.add(pml4_idx as usize));

    if pml4_entry & 1 == 0 {
        println!("  PML4[{}] not present", pml4_idx);
        return false;
    }

    let pdpt_phys = pml4_entry & 0x000FFFFFFFFFF000;
    println!(
        "  PML4[{}] = 0x{:016x} → PDPT @ 0x{:x}",
        pml4_idx, pml4_entry, pdpt_phys
    );
    if pdpt_phys >= PHYS_MEM_LIMIT {
        println!(
            "    ERROR: PDPT address 0x{:x} exceeds {}MB limit!",
            pdpt_phys, 953
        );
        return false;
    }

    let pdpt_virt = DIRECTMAP_AREA_START + pdpt_phys;
    let pdpt = pdpt_virt as *const u64;

    let pdpt_idx = (virt_addr >> 30) & 0x1FF;
    let pdpt_entry = ptr::read_volatile(pdpt.add(pdpt_idx as usize));

    if pdpt_entry & 1 == 0 {
        println!("  PDPT[{}] not present", pdpt_idx);
        return false;
    }

    if pdpt_entry & 0x80 != 0 {
        let final_phys = (pdpt_entry & 0x000FFFFFC0000000) | (virt_addr & 0x3FFFFFFF);
        println!(
            "  PDPT[{}] = 0x{:016x} → 1GB page @ 0x{:x}",
            pdpt_idx, pdpt_entry, final_phys
        );
        if final_phys >= PHYS_MEM_LIMIT {
            println!(
                "    ERROR: Final address 0x{:x} exceeds {}MB limit!",
                final_phys, 953
            );
            return false;
        }
        return true;
    }

    let pd_phys = pdpt_entry & 0x000FFFFFFFFFF000;
    println!(
        "  PDPT[{}] = 0x{:016x} → PD @ 0x{:x}",
        pdpt_idx, pdpt_entry, pd_phys
    );
    if pd_phys >= PHYS_MEM_LIMIT {
        println!(
            "    ERROR: PD address 0x{:x} exceeds {}MB limit!",
            pd_phys, 953
        );
        return false;
    }

    let pd_virt = DIRECTMAP_AREA_START + pd_phys;
    let pd = pd_virt as *const u64;

    let pd_idx = (virt_addr >> 21) & 0x1FF;
    let pd_entry = ptr::read_volatile(pd.add(pd_idx as usize));

    if pd_entry & 1 == 0 {
        println!("  PD[{}] not present", pd_idx);
        return false;
    }

    if pd_entry & 0x80 != 0 {
        let final_phys = (pd_entry & 0x000FFFFFFFE00000) | (virt_addr & 0x1FFFFF);
        println!(
            "  PD[{}] = 0x{:016x} → 2MB page @ 0x{:x}",
            pd_idx, pd_entry, final_phys
        );
        if final_phys >= PHYS_MEM_LIMIT {
            println!(
                "    ERROR: Final address 0x{:x} exceeds {}MB limit!",
                final_phys, 953
            );
            return false;
        }
        return true;
    }

    let pt_phys = pd_entry & 0x000FFFFFFFFFF000;
    println!(
        "  PD[{}] = 0x{:016x} → PT @ 0x{:x}",
        pd_idx, pd_entry, pt_phys
    );
    if pt_phys >= PHYS_MEM_LIMIT {
        println!(
            "    ERROR: PT address 0x{:x} exceeds {}MB limit!",
            pt_phys, 953
        );
        return false;
    }

    let pt_virt = DIRECTMAP_AREA_START + pt_phys;
    let pt = pt_virt as *const u64;

    let pt_idx = (virt_addr >> 12) & 0x1FF;
    let pt_entry = ptr::read_volatile(pt.add(pt_idx as usize));

    if pt_entry & 1 == 0 {
        println!("  PT[{}] not present", pt_idx);
        return false;
    }

    let final_phys = (pt_entry & 0x000FFFFFFFFFF000) | (virt_addr & 0xFFF);
    println!(
        "  PT[{}] = 0x{:016x} → FINAL @ 0x{:x}",
        pt_idx, pt_entry, final_phys
    );
    if final_phys >= PHYS_MEM_LIMIT {
        println!(
            "    ERROR: Final address 0x{:x} exceeds {}MB limit!",
            final_phys, 953
        );
        return false;
    }

    println!("  ✓ All addresses within 953MB limit");
    true
}

/// Simplest possible AP entry for testing
#[no_mangle]
pub extern "C" fn ap_entry_simple(_cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    // Ultra minimal - just output Y and halt
    unsafe {
        core::arch::asm!(
            "mov al, 0x59",
            "mov dx, 0x3F8",
            "out dx, al",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn)
        );
    }
}

/// Entry point for Application Processors (APs)
/// Called from boot_trampoline.S after CPU is in 64-bit mode
#[no_mangle]
#[unsafe(naked)]
pub extern "C" fn ap_entry(cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    unsafe {
        core::arch::naked_asm!(
            // Very first thing: send 'Y'
            "mov al, 'Y'",
            "mov dx, 0x3F8",
            "out dx, al",
            // Now jump to the real function
            "jmp {real_entry}",
            real_entry = sym ap_entry_real,
        );
    }
}

#[no_mangle]
pub extern "C" fn ap_entry_real(cpu_data: *const boot_trampoline_bindings::CpuData) -> ! {
    unsafe {
        // Debug: Send 'Z' to show we made it to ap_entry_real
        asm!("out dx, al", in("al") b'Z' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        let cpu = &*cpu_data;
        let cpu_id = cpu.idx;

        // Debug: Send '!' after reading cpu_id
        asm!("out dx, al", in("al") b'!' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

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
        let stack_top = stack_base + size as u64;

        // Debug: Print stack address range
        if STACK_OFFSET == size {
            println!(
                "STACK_MEMORY is at: 0x{:x}",
                core::ptr::addr_of!(STACK_MEMORY) as u64
            );
        }

        stack_top // Return top of stack
    }
}
