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

// Page table constants
const PAGE_SIZE: usize = 4096;
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Walk kernel page tables to get physical address of a virtual address
unsafe fn get_physical_address(cr3: u64, va: u64) -> u64 {
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4_phys = cr3 & PTE_ADDR_MASK;
    let pml4_virt = (pml4_phys + DIRECTMAP_AREA_START) as *const u64;
    let pml4e = ptr::read_volatile(pml4_virt.add(pml4_idx as usize));

    if (pml4e & PTE_PRESENT) == 0 {
        panic!("PML4 entry not present");
    }

    let pdpt_phys = pml4e & PTE_ADDR_MASK;
    let pdpt_virt = (pdpt_phys + DIRECTMAP_AREA_START) as *const u64;
    let pdpte = ptr::read_volatile(pdpt_virt.add(pdpt_idx as usize));

    if (pdpte & PTE_PRESENT) == 0 {
        panic!("PDPT entry not present");
    }

    let pd_phys = pdpte & PTE_ADDR_MASK;
    let pd_virt = (pd_phys + DIRECTMAP_AREA_START) as *const u64;
    let pde = ptr::read_volatile(pd_virt.add(pd_idx as usize));

    if (pde & PTE_PRESENT) == 0 {
        panic!("PD entry not present");
    }

    let pt_phys = pde & PTE_ADDR_MASK;
    let pt_virt = (pt_phys + DIRECTMAP_AREA_START) as *const u64;
    let pte = ptr::read_volatile(pt_virt.add(pt_idx as usize));

    if (pte & PTE_PRESENT) == 0 {
        panic!("PT entry not present");
    }

    let page_phys = pte & PTE_ADDR_MASK;
    page_phys + offset
}

/// Map a physical address at a virtual address in kernel page tables
unsafe fn map_page_in_kernel_pt(cr3: u64, va: u64, pa: u64) -> Result<(), &'static str> {
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;

    let pml4_phys = cr3 & PTE_ADDR_MASK;
    let pml4_virt = (pml4_phys + DIRECTMAP_AREA_START) as *mut u64;

    // Get or create PDPT
    let pml4e_ptr = pml4_virt.add(pml4_idx as usize);
    let mut pml4e = ptr::read_volatile(pml4e_ptr);
    let pdpt_phys = if (pml4e & PTE_PRESENT) == 0 {
        // Allocate new PDPT
        let layout = std::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let new_pdpt_ptr = std::alloc::alloc_zeroed(layout);
        if new_pdpt_ptr.is_null() {
            return Err("Failed to allocate PDPT");
        }
        // Touch the page to ensure it's present in direct map
        ptr::write_volatile(new_pdpt_ptr, 0);
        let pdpt_va = new_pdpt_ptr as u64;
        let pdpt_pa = get_physical_address(cr3, pdpt_va);
        pml4e = pdpt_pa | PTE_PRESENT | PTE_WRITE;
        ptr::write_volatile(pml4e_ptr, pml4e);
        pdpt_pa
    } else {
        pml4e & PTE_ADDR_MASK
    };

    // Get or create PD
    let pdpt_virt = (pdpt_phys + DIRECTMAP_AREA_START) as *mut u64;
    let pdpte_ptr = pdpt_virt.add(pdpt_idx as usize);
    let mut pdpte = ptr::read_volatile(pdpte_ptr);
    let pd_phys = if (pdpte & PTE_PRESENT) == 0 {
        let layout = std::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let new_pd_ptr = std::alloc::alloc_zeroed(layout);
        if new_pd_ptr.is_null() {
            return Err("Failed to allocate PD");
        }
        // Touch the page to ensure it's present in direct map
        ptr::write_volatile(new_pd_ptr, 0);
        let pd_va = new_pd_ptr as u64;
        let pd_pa = get_physical_address(cr3, pd_va);
        pdpte = pd_pa | PTE_PRESENT | PTE_WRITE;
        ptr::write_volatile(pdpte_ptr, pdpte);
        pd_pa
    } else {
        pdpte & PTE_ADDR_MASK
    };

    // Get or create PT
    let pd_virt = (pd_phys + DIRECTMAP_AREA_START) as *mut u64;
    let pde_ptr = pd_virt.add(pd_idx as usize);
    let mut pde = ptr::read_volatile(pde_ptr);
    let pt_phys = if (pde & PTE_PRESENT) == 0 {
        let layout = std::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let new_pt_ptr = std::alloc::alloc_zeroed(layout);
        if new_pt_ptr.is_null() {
            return Err("Failed to allocate PT");
        }
        // Touch the page to ensure it's present in direct map
        ptr::write_volatile(new_pt_ptr, 0);
        let pt_va = new_pt_ptr as u64;
        let pt_pa = get_physical_address(cr3, pt_va);
        pde = pt_pa | PTE_PRESENT | PTE_WRITE;
        ptr::write_volatile(pde_ptr, pde);
        pt_pa
    } else {
        pde & PTE_ADDR_MASK
    };

    // Set PT entry
    let pt_virt = (pt_phys + DIRECTMAP_AREA_START) as *mut u64;
    let pte_ptr = pt_virt.add(pt_idx as usize);
    let pte = pa | PTE_PRESENT | PTE_WRITE;
    ptr::write_volatile(pte_ptr, pte);

    // Flush TLB
    asm!("invlpg [{}]", in(reg) va, options(nostack));

    Ok(())
}

fn main() {
    // Initialize serial console for debugging (for custom output)
    // Note: On Unikraft with std, regular println! should work
    println!("Rust Multicore Boot Starting...");

    // Check where we (BSP) are running from
    let main_addr = main as *const () as u64;
    println!("BSP running from: main() at 0x{:x}", main_addr);
    let ap_entry_addr = ap_entry as *const () as u64;
    println!("AP entry point: ap_entry() at 0x{:x}", ap_entry_addr);

    // ========================================================================
    // Helper function to walk page tables
    // ========================================================================
    unsafe fn walk_and_get_pa(cr3: u64, va: u64) -> u64 {
        const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        const DIRECTMAP_START: u64 = 0xffffff8000000000;

        let pml4_idx = (va >> 39) & 0x1FF;
        let pdpt_idx = (va >> 30) & 0x1FF;
        let pd_idx = (va >> 21) & 0x1FF;
        let pt_idx = (va >> 12) & 0x1FF;

        let pml4_phys = cr3 & PTE_ADDR_MASK;
        let pml4_virt = (pml4_phys + DIRECTMAP_START) as *const u64;
        let pml4e = ptr::read_volatile(pml4_virt.add(pml4_idx as usize));

        let pdpt_phys = pml4e & PTE_ADDR_MASK;
        let pdpt_virt = (pdpt_phys + DIRECTMAP_START) as *const u64;
        let pdpte = ptr::read_volatile(pdpt_virt.add(pdpt_idx as usize));

        let pd_phys = pdpte & PTE_ADDR_MASK;
        let pd_virt = (pd_phys + DIRECTMAP_START) as *const u64;
        let pde = ptr::read_volatile(pd_virt.add(pd_idx as usize));

        let pt_phys = pde & PTE_ADDR_MASK;
        let pt_virt = (pt_phys + DIRECTMAP_START) as *const u64;
        let pte = ptr::read_volatile(pt_virt.add(pt_idx as usize));

        (pte & PTE_ADDR_MASK) | (va & 0xFFF)
    }

    // ========================================================================
    // TEST: Allocate memory and map at high address
    // ========================================================================
    println!("\n=== TEST: Trampoline Allocation and High Address Mapping ===");

    // Step 1: Allocate buffer and find page-aligned addresses
    const TRAMPOLINE_SIZE: usize = 3 * PAGE_SIZE;
    let trampoline_buffer = vec![0u8; TRAMPOLINE_SIZE];
    let buffer_va = trampoline_buffer.as_ptr() as u64;

    println!("Step 1: Allocated {} bytes (3 pages)", TRAMPOLINE_SIZE);
    println!("  Buffer VA: 0x{:016x}", buffer_va);

    // Get CR3
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    println!("  CR3: 0x{:016x}", cr3);

    // Find page-aligned addresses within the buffer
    let page1_va = if (buffer_va & 0xFFF) == 0 {
        buffer_va // Already page-aligned
    } else {
        (buffer_va & !0xFFF) + PAGE_SIZE as u64 // Round up to next page
    };
    let page2_va = page1_va + PAGE_SIZE as u64;

    println!("  Page-aligned addresses found:");
    println!("    Page 1 VA: 0x{:016x}", page1_va);
    println!("    Page 2 VA: 0x{:016x}", page2_va);

    // Walk page tables to get actual physical addresses for these VAs
    let (page1_pa, page2_pa) = unsafe {
        (
            walk_and_get_pa(cr3, page1_va),
            walk_and_get_pa(cr3, page2_va),
        )
    };

    println!("  Physical addresses (from page table walk):");
    println!("    Page 1 PA: 0x{:016x}", page1_pa);
    println!("    Page 2 PA: 0x{:016x}", page2_pa);

    // Step 2: Map the pages at high address (but BELOW VMA management region)
    // Unikraft's VMA system manages addresses starting from CONFIG_LIBUKVMEM_DEFAULT_BASE
    // (likely ~0x200000000000 = 2TB based on Xen memory layout). We'll use an address
    // just below that limit to maximize separation from user space while avoiding VMA checks.
    const HIGH_VA_BASE: u64 = 0x0000_1FFF_FFFF_E000; // Just below 2TB (below VMA management)
    let high_va_page1 = HIGH_VA_BASE;
    let high_va_page2 = HIGH_VA_BASE + PAGE_SIZE as u64;

    println!("\nStep 2: Mapping at high addresses (~2TB, below VMA region)");
    println!(
        "  High VA page 1: 0x{:016x} -> PA: 0x{:016x}",
        high_va_page1, page1_pa
    );
    println!(
        "  High VA page 2: 0x{:016x} -> PA: 0x{:016x}",
        high_va_page2, page2_pa
    );

    // Step 4: Map both pages at high addresses
    unsafe {
        if let Err(e) = map_page_in_kernel_pt(cr3, high_va_page1, page1_pa) {
            panic!("Failed to map page 1: {}", e);
        }
        if let Err(e) = map_page_in_kernel_pt(cr3, high_va_page2, page2_pa) {
            panic!("Failed to map page 2: {}", e);
        }
    }
    println!("  ✓ Pages mapped successfully");

    // Explicit TLB flush for both addresses
    unsafe {
        asm!("invlpg [{}]", in(reg) high_va_page1, options(nostack));
        asm!("invlpg [{}]", in(reg) high_va_page2, options(nostack));
    }
    println!("  ✓ TLB flushed");

    // Step 3: Verify page table setup by walking them
    println!("\nStep 3: Verifying page table mappings");
    for (i, high_va) in [high_va_page1, high_va_page2].iter().enumerate() {
        println!(
            "  Verifying mapping for page {} at 0x{:016x}",
            i + 1,
            high_va
        );

        let pml4_idx = (high_va >> 39) & 0x1FF;
        let pdpt_idx = (high_va >> 30) & 0x1FF;
        let pd_idx = (high_va >> 21) & 0x1FF;
        let pt_idx = (high_va >> 12) & 0x1FF;

        println!(
            "    Indices: PML4[{}] PDPT[{}] PD[{}] PT[{}]",
            pml4_idx, pdpt_idx, pd_idx, pt_idx
        );

        unsafe {
            // Walk PML4
            let cr3_phys = cr3 & PTE_ADDR_MASK;
            let pml4_virt = (cr3_phys + DIRECTMAP_AREA_START) as *const u64;
            let pml4e = ptr::read_volatile(pml4_virt.add(pml4_idx as usize));
            println!(
                "    PML4[{}] = 0x{:016x} (P={}, W={}, U={})",
                pml4_idx,
                pml4e,
                pml4e & 1,
                (pml4e >> 1) & 1,
                (pml4e >> 2) & 1
            );

            if (pml4e & 1) == 0 {
                println!("    ✗ ERROR: PML4 entry not present!");
                continue;
            }

            // Walk PDPT
            let pdpt_phys = pml4e & PTE_ADDR_MASK;
            let pdpt_virt = (pdpt_phys + DIRECTMAP_AREA_START) as *const u64;
            let pdpte = ptr::read_volatile(pdpt_virt.add(pdpt_idx as usize));
            println!(
                "    PDPT[{}] = 0x{:016x} (P={}, W={}, U={})",
                pdpt_idx,
                pdpte,
                pdpte & 1,
                (pdpte >> 1) & 1,
                (pdpte >> 2) & 1
            );

            if (pdpte & 1) == 0 {
                println!("    ✗ ERROR: PDPT entry not present!");
                continue;
            }

            // Walk PD
            let pd_phys = pdpte & PTE_ADDR_MASK;
            let pd_virt = (pd_phys + DIRECTMAP_AREA_START) as *const u64;
            let pde = ptr::read_volatile(pd_virt.add(pd_idx as usize));
            println!(
                "    PD[{}] = 0x{:016x} (P={}, W={}, U={})",
                pd_idx,
                pde,
                pde & 1,
                (pde >> 1) & 1,
                (pde >> 2) & 1
            );

            if (pde & 1) == 0 {
                println!("    ✗ ERROR: PD entry not present!");
                continue;
            }

            // Walk PT
            let pt_phys = pde & PTE_ADDR_MASK;
            let pt_virt = (pt_phys + DIRECTMAP_AREA_START) as *const u64;
            let pte = ptr::read_volatile(pt_virt.add(pt_idx as usize));
            println!(
                "    PT[{}] = 0x{:016x} (P={}, W={}, U={})",
                pt_idx,
                pte,
                pte & 1,
                (pte >> 1) & 1,
                (pte >> 2) & 1
            );

            if (pte & 1) == 0 {
                println!("    ✗ ERROR: PT entry not present!");
                continue;
            }

            // Extract final physical address
            let mapped_phys = pte & PTE_ADDR_MASK;
            let expected_phys = if i == 0 { page1_pa } else { page2_pa };
            println!("    Final physical address: 0x{:016x}", mapped_phys);
            println!("    Expected physical:      0x{:016x}", expected_phys);

            if mapped_phys == expected_phys {
                println!("    ✓ Physical address matches!");
            } else {
                println!("    ✗ ERROR: Physical address mismatch!");
            }
        }
    }

    // Step 4: TEST - Verify mappings work correctly
    println!("\nStep 4: Testing trampoline access patterns");

    println!("\n  Note: High addresses (~2TB) are below VMA management region.");
    println!("        This avoids VMA checks while providing separation from user space.");
    println!("        Both kernel and user mode can access these addresses.");

    // Write test pattern via low (original) VAs
    unsafe {
        core::ptr::write_volatile(page1_va as *mut u8, 0xDE);
        core::ptr::write_volatile((page1_va + 1) as *mut u8, 0xAD);
        core::ptr::write_volatile((page1_va + 2) as *mut u8, 0xBE);
        core::ptr::write_volatile((page1_va + 3) as *mut u8, 0xEF);

        core::ptr::write_volatile(page2_va as *mut u8, 0xCA);
        core::ptr::write_volatile((page2_va + 1) as *mut u8, 0xFE);
        core::ptr::write_volatile((page2_va + 2) as *mut u8, 0xBA);
        core::ptr::write_volatile((page2_va + 3) as *mut u8, 0xBE);
    }
    println!("\n  Test 1: Kernel access via LOW addresses (original allocation)");
    println!("    Written via low VA: DE AD BE EF at 0x{:x}", page1_va);

    // Read back via low addresses
    unsafe {
        let val1 = core::ptr::read_volatile(page1_va as *const u32);
        let val2 = core::ptr::read_volatile(page2_va as *const u32);
        println!("    Read back: 0x{:08x} and 0x{:08x}", val1, val2);
        if val1 == 0xEFBEADDE && val2 == 0xBEBAFECA {
            println!("    ✓ Low address access works!");
        }
    }

    // Test access via DIRECT MAP (alternative kernel access method)
    const DIRECTMAP_START: u64 = 0xffffff8000000000;
    println!("\n  Test 2: Kernel access via DIRECT MAP");
    let directmap_page1 = DIRECTMAP_START + page1_pa;
    let directmap_page2 = DIRECTMAP_START + page2_pa;
    println!("    Direct map VA page 1: 0x{:016x}", directmap_page1);
    println!("    Direct map VA page 2: 0x{:016x}", directmap_page2);

    unsafe {
        // Read what we wrote earlier
        let val1 = core::ptr::read_volatile(directmap_page1 as *const u32);
        let val2 = core::ptr::read_volatile(directmap_page2 as *const u32);
        println!("    Read via direct map: 0x{:08x} and 0x{:08x}", val1, val2);
        if val1 == 0xEFBEADDE && val2 == 0xBEBAFECA {
            println!("    ✓ Direct map access works!");
        }

        // Write new values via direct map
        core::ptr::write_volatile(directmap_page1 as *mut u32, 0x12345678);
        core::ptr::write_volatile(directmap_page2 as *mut u32, 0x9ABCDEF0);

        // Read back via low VA to confirm they point to same physical memory
        let val1_low = core::ptr::read_volatile(page1_va as *const u32);
        let val2_low = core::ptr::read_volatile(page2_va as *const u32);
        println!(
            "    Wrote via direct map, read via low VA: 0x{:08x} and 0x{:08x}",
            val1_low, val2_low
        );
        if val1_low == 0x12345678 && val2_low == 0x9ABCDEF0 {
            println!("    ✓ Direct map and low VA point to same physical memory!");
        }
    }

    println!("\n  ✓ SUCCESS: Trampoline memory is correctly allocated and accessible");
    println!(
        "    - Low addresses: 0x{:x} (original allocation)",
        page1_va
    );
    println!(
        "    - High addresses: 0x{:x} (~2TB, below VMA region)",
        high_va_page1
    );
    println!(
        "    - Direct map: 0x{:x} (physical memory mapping)",
        directmap_page1
    );
    println!(
        "    - All addresses point to same physical pages: 0x{:x}, 0x{:x}",
        page1_pa, page2_pa
    );

    println!("=== TEST COMPLETE ===\n");

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
    let interrupt_config = unsafe {
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

    // Get current kernel CR3 for returning from user space
    let kernel_cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) kernel_cr3);
    }

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

        // Write kernel CR3 for returning from user space
        AP_TASK_INFO.write_kernel_cr3(kernel_cr3);
        println!(
            "✓ Kernel CR3 written to AP task info: 0x{:016x}",
            kernel_cr3
        );

        // Write interrupt configuration
        AP_TASK_INFO.write_interrupt_config(
            interrupt_config.gdt_base,
            interrupt_config.gdt_limit,
            interrupt_config.idt_base,
            interrupt_config.idt_limit,
            interrupt_config.tss_base,
            interrupt_config.tss_selector,
        );
        println!("✓ Interrupt config written to AP task info");
        println!(
            "  GDT: base=0x{:x}, limit={}",
            interrupt_config.gdt_base, interrupt_config.gdt_limit
        );
        println!(
            "  IDT: base=0x{:x}, limit={}",
            interrupt_config.idt_base, interrupt_config.idt_limit
        );
        println!(
            "  TSS: base=0x{:x}, selector=0x{:x}",
            interrupt_config.tss_base, interrupt_config.tss_selector
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
