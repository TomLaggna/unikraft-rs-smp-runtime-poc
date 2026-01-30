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
mod timing;
mod trampolines;
mod user_code;
mod user_handlers;
mod user_pagetable;

// Debug utilities module
#[macro_use]
mod debug_utils;
use debug_utils::*;

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
use timing::{init_timer, record_and_print, TimePoint};
use user_pagetable::{virt_to_phys, walk_pt, walk_pt_with_flags};

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
const PTE_NX: u64 = 1 << 63;
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
        // ...
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
        // Ensure new entry is Writable and NOT NX (Supervisor)
        pml4e = pdpt_pa | PTE_PRESENT | PTE_WRITE;
        ptr::write_volatile(pml4e_ptr, pml4e);
        pdpt_pa
    } else {
        // LOG EXISTING ENTRY
        // debug_mem_println!("DEBUG MAP: PML4[{}] existing: 0x{:016x}", pml4_idx, pml4e);
        // Force clear NX bit if present
        if (pml4e & PTE_NX) != 0 {
            debug_mem_println!(
                "DEBUG MAP: Clearing NX on PML4[{}] (was 0x{:016x})",
                pml4_idx,
                pml4e
            );
            pml4e &= !PTE_NX;
            ptr::write_volatile(pml4e_ptr, pml4e);
        }
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
        // Force clear NX bit if present
        if (pdpte & PTE_NX) != 0 {
            pdpte &= !PTE_NX;
            ptr::write_volatile(pdpte_ptr, pdpte);
        }
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
        // Force clear NX bit if present
        if (pde & PTE_NX) != 0 {
            pde &= !PTE_NX;
            ptr::write_volatile(pde_ptr, pde);
        }
        pde & PTE_ADDR_MASK
    };

    // Set PT entry
    let pt_virt = (pt_phys + DIRECTMAP_AREA_START) as *mut u64;
    let pte_ptr = pt_virt.add(pt_idx as usize);
    let pte = pa | PTE_PRESENT | PTE_WRITE; // Ensure NX bit 63 is 0
    ptr::write_volatile(pte_ptr, pte);

    // Flush TLB
    asm!("invlpg [{}]", in(reg) va, options(nostack));

    Ok(())
}

fn main() {
    // Initialize timing as first thing
    init_timer();

    // Initialize serial console for debugging (for custom output)
    // Note: On Unikraft with std, regular println! should work
    // Check where we (BSP) are running from
    let main_addr = main as *const () as u64;
    let ap_entry_addr = ap_entry as *const () as u64;

    // ========================================================================
    // TEST: Allocate memory and map at high address
    // ========================================================================

    // Step 1: Allocate buffer and find page-aligned addresses
    const TRAMPOLINE_SIZE: usize = 3 * PAGE_SIZE;
    let trampoline_buffer = vec![0u8; TRAMPOLINE_SIZE];
    let buffer_va = trampoline_buffer.as_ptr() as u64;

    // Get CR3
    let kernel_cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) kernel_cr3);
    }
    let kernel_cr3_pa = kernel_cr3 & 0x0000_FFFF_FFFF_F000;

    // Find page-aligned addresses within the buffer
    let page1_va = if (buffer_va & 0xFFF) == 0 {
        buffer_va // Already page-aligned
    } else {
        (buffer_va & !0xFFF) + PAGE_SIZE as u64 // Round up to next page
    };
    let page2_va = page1_va + PAGE_SIZE as u64;

    // Walk page tables to get actual physical addresses for these VAs
    let (page1_pa, page2_pa) = unsafe {
        (
            get_physical_address(kernel_cr3, page1_va),
            get_physical_address(kernel_cr3, page2_va),
        )
    };

    // Step 2: Map the pages at high address (but BELOW VMA management region)
    // Unikraft's VMA system manages addresses starting from CONFIG_LIBUKVMEM_DEFAULT_BASE
    // (likely ~0x200000000000 = 2TB based on Xen memory layout). We'll use an address
    // just below that limit to maximize separation from user space while avoiding VMA checks.
    const HIGH_VA_BASE: u64 = 0x0000_1FFF_FFFF_E000; // Just below 2TB (below VMA management)
    let high_va_page1 = HIGH_VA_BASE;
    let high_va_page2 = HIGH_VA_BASE + PAGE_SIZE as u64;

    // Step 4: Map both pages at high addresses
    unsafe {
        if let Err(e) = map_page_in_kernel_pt(kernel_cr3, high_va_page1, page1_pa) {
            panic!("Failed to map page 1: {}", e);
        }
        if let Err(e) = map_page_in_kernel_pt(kernel_cr3, high_va_page2, page2_pa) {
            panic!("Failed to map page 2: {}", e);
        }
    }
    debug_trampoline_println!("  ✓ Pages mapped successfully");

    // Explicit TLB flush for both addresses
    unsafe {
        asm!("invlpg [{}]", in(reg) high_va_page1, options(nostack));
        asm!("invlpg [{}]", in(reg) high_va_page2, options(nostack));
    }

    // ========================================================================
    // TEST: User Space Manager (Dandelion Pattern)
    // ========================================================================

    // Create a 32 MB user address space (reduced for 1GB RAM system)
    const USER_SPACE_SIZE: usize = 32 * 1024 * 1024; // 32 MB
    let mut user_space = unsafe {
        match user_pagetable::UserSpaceManager::new(USER_SPACE_SIZE) {
            Ok(us) => us,
            Err(e) => panic!("Failed to create user space: {}", e),
        }
    };

    // Get user code from assembly module
    let user_code_asm = unsafe { user_code::get_user_code() };
    let user_code_entry_offset = unsafe { user_code::get_entry_offset() };

    // Allocate 64KB + 4KB for user code in kernel space (extra for alignment)
    let user_code_size = 64 * 1024;
    let user_code_buf_raw = vec![0u8; user_code_size + 4096];

    // Page-align the buffer pointer
    let user_code_buf_ptr = user_code_buf_raw.as_ptr() as usize;
    let user_code_buf_aligned = (user_code_buf_ptr + 4095) & !4095;
    let user_code_buf_slice = unsafe {
        core::slice::from_raw_parts_mut(user_code_buf_aligned as *mut u8, user_code_size)
    };

    // Copy the assembly user code to the aligned buffer
    user_code_buf_slice[..user_code_asm.len()].copy_from_slice(user_code_asm);

    // Force kernel to map all pages in the user code buffer
    for offset in (0..user_code_size).step_by(4096) {
        // Touch each page to ensure it's mapped, but don't overwrite our code
        if offset >= user_code_asm.len() {
            user_code_buf_slice[offset] = 0;
        }
    }

    // Map it at virtual address 0x400000 (typical ELF base) in user space
    let user_code_virt = 0x400000;
    let user_code_kernel_virt = user_code_buf_aligned;

    if let Err(e) = unsafe {
        user_space.map_user_range(
            user_code_virt,
            user_code_kernel_virt,
            user_code_size,
            false,
            false,
        )
    } {
        panic!("Failed to map user code: {}", e);
    }

    // Example: Map user stack
    // Stack must end BEFORE interrupt structures to avoid overlap
    let user_stack_size = 16 * 4096; // 64KB
    let user_stack_buf = vec![0u8; user_stack_size];

    // Force kernel to map all pages in the stack buffer
    {
        let buf_ptr = user_stack_buf.as_ptr() as *mut u8;
        unsafe {
            for page in 0..(user_stack_size / 4096) {
                core::ptr::write_volatile(buf_ptr.add(page * 4096), 0);
            }
        }
    }

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
            false, // kernel_accessible=false, U=1 for trampoline stack
        )
    } {
        panic!("Failed to map user stack: {}", e);
    }

    // Map trampolines in user page tables
    if let Err(e) = user_space.map_trampolines(high_va_page1, page1_pa, page2_pa) {
        panic!("Failed to map trampolines in user space: {}", e);
    }
    debug_trampoline_println!("");

    // User code entry point
    let user_entry_va = user_code_virt;
    // User stack top must be INSIDE the mapped region (U=1), not at the boundary
    // The stack grows down, so we need RSP to point to a valid user address.
    // user_stack_virt + user_stack_size is the first byte AFTER the stack mapping,
    // which borders the interrupt structures (U=0). Subtract 16 for alignment.
    let user_stack_top = user_stack_virt + user_stack_size - 16;

    // Trampoline page 1: Kernel->User
    // Data section layout at end of page:
    //   Offset 0x100: saved kernel RSP (8 bytes)
    //   Offset 0x108: user CR3 (8 bytes)
    //   Offset 0x110: user RSP (8 bytes)
    //   Offset 0x118: user entry (8 bytes)
    //   Offset 0x120: GDT base (8 bytes)
    //   Offset 0x128: GDT limit (2 bytes) + padding (6 bytes)
    //   Offset 0x130: IDT base (8 bytes)
    //   Offset 0x138: IDT limit (2 bytes) + padding (6 bytes)
    //   Offset 0x140: TSS selector (2 bytes) + padding (6 bytes)

    // Copy K->U trampoline code to page 1
    unsafe {
        let k2u_code = trampolines::get_k2u_code();
        // Copy code
        let dst = high_va_page1 as *mut u8;
        core::ptr::copy_nonoverlapping(k2u_code.as_ptr(), dst, k2u_code.len());
    }

    // Copy U->K trampoline code to page 2
    unsafe {
        let u2k_code = trampolines::get_u2k_code();
        // Copy code
        let dst = high_va_page2 as *mut u8;
        core::ptr::copy_nonoverlapping(u2k_code.as_ptr(), dst, u2k_code.len());
    }

    // Setup interrupt handlers for user space
    // Get handler code and addresses from assembly
    let handler_code = unsafe { user_handlers::get_handler_code() };
    let handler_addresses = unsafe { user_handlers::get_handler_addresses() };
    let handler_base = handler_addresses[0]; // Use first handler as base

    // Get current kernel stack for TSS.RSP0
    let kernel_stack: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) kernel_stack);
    }
    debug_trampoline_println!("Kernel stack (for TSS.RSP0): 0x{:016x}", kernel_stack);

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

    // Patch the trampoline address into INT 32 handler
    unsafe {
        let trampoline_offset = user_handlers::get_handler_32_trampoline_offset();
        debug_trampoline_println!(
            "  Trampoline field offset in handler code: 0x{:x}",
            trampoline_offset
        );

        let handler_code_offset = user_space.get_interrupt_handler_code_address();
        let guest_mem = user_space.get_guest_mem_mut();
        let trampoline_field_offset = handler_code_offset + trampoline_offset;
        // Write the trampoline address
        let ptr = guest_mem.as_mut_ptr().add(trampoline_field_offset) as *mut u64;
        core::ptr::write_volatile(ptr, high_va_page2);
    }

    // Patch the trampoline data sections with runtime values
    unsafe {
        // Patch K->U trampoline data fields
        debug_trampoline_println!("\n  K->U trampoline data:");

        // user_cr3_value
        let user_cr3 = user_space.get_cr3();
        let user_cr3_pa = user_cr3 & 0x0000_FFFF_FFFF_F000;
        let offset = trampolines::k2u_offsets::user_cr3_value() as u64;
        let ptr = (high_va_page1 + offset) as *mut u64;
        core::ptr::write_volatile(ptr, user_cr3_pa);
        // user_stack_top
        let offset = trampolines::k2u_offsets::user_stack_top() as u64;
        let ptr = (high_va_page1 + offset) as *mut u64;
        core::ptr::write_volatile(ptr, user_stack_top as u64);

        // Flush TLB for this address in case it was cached
        core::arch::asm!("invlpg [{}]", in(reg) ptr as u64, options(nostack));

        // user_entry_point
        let offset = trampolines::k2u_offsets::user_entry_point() as u64;
        let ptr = (high_va_page1 + offset) as *mut u64;
        core::ptr::write_volatile(ptr, user_entry_va as u64);

        // gdt_desc (limit + base)
        let offset = trampolines::k2u_offsets::gdt_desc() as u64;
        let ptr = (high_va_page1 + offset) as *mut u16;
        core::ptr::write_volatile(ptr, interrupt_config.gdt_limit);
        let ptr = (high_va_page1 + offset + 2) as *mut u64;
        // Use User Virtual Address for GDT base (mapped in user space)
        let gdt_base_uva = user_space.get_gdt_uva() as u64;
        core::ptr::write_volatile(ptr, gdt_base_uva);

        // idt_desc (limit + base)
        let offset = trampolines::k2u_offsets::idt_desc() as u64;
        let ptr = (high_va_page1 + offset) as *mut u16;
        core::ptr::write_volatile(ptr, interrupt_config.idt_limit);
        let ptr = (high_va_page1 + offset + 2) as *mut u64;
        // Use User Virtual Address for IDT base
        let idt_base_uva = user_space.get_idt_uva() as u64;
        core::ptr::write_volatile(ptr, idt_base_uva);

        // tss_selector
        let offset = trampolines::k2u_offsets::tss_selector() as u64;
        let ptr = (high_va_page1 + offset) as *mut u16;
        core::ptr::write_volatile(ptr, interrupt_config.tss_selector);

        // Patch U->K trampoline data fields
        // kernel_cr3_value
        let offset = trampolines::u2k_offsets::kernel_cr3_value() as u64;
        let ptr = (high_va_page2 + offset) as *mut u64;
        core::ptr::write_volatile(ptr, kernel_cr3_pa);

        // u2k_rsp_save_addr in K2U: address where K2U should save kernel RSP
        // This points to kernel_rsp_restore in U2K data section
        let u2k_rsp_restore_offset = trampolines::u2k_offsets::kernel_rsp_restore() as u64;
        let kernel_rsp_restore_addr = high_va_page2 + u2k_rsp_restore_offset;
        let offset = trampolines::k2u_offsets::u2k_rsp_save_addr() as u64;
        let ptr = (high_va_page1 + offset) as *mut u64;
        core::ptr::write_volatile(ptr, kernel_rsp_restore_addr);
        // Memory barrier to ensure all writes are visible
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Flush TLB for trampoline pages to ensure no stale cached values
        core::arch::asm!("invlpg [{}]", in(reg) high_va_page1, options(nostack));
        core::arch::asm!("invlpg [{}]", in(reg) high_va_page2, options(nostack));
    }

    // Allocate shared memory for AP task info in static storage (not heap)
    // Static variables are in the data segment and accessible by APs
    static mut AP_TASK_INFO: ApTaskInfo = ApTaskInfo::new();
    unsafe {
        // Write user space CR3 to AP task info so AP can load user page tables
        AP_TASK_INFO.write_user_cr3(user_space.get_cr3());
        // Write kernel CR3 for returning from user space
        AP_TASK_INFO.write_kernel_cr3(kernel_cr3);
        // Write interrupt configuration
        AP_TASK_INFO.write_interrupt_config(
            interrupt_config.gdt_base,
            interrupt_config.gdt_limit,
            interrupt_config.idt_base,
            interrupt_config.idt_limit,
            interrupt_config.tss_base,
            interrupt_config.tss_selector,
        );
        // Write trampoline addresses
        // Using High VA for execution (needed for safe CR3 switching)
        AP_TASK_INFO.write_k2u_trampoline(high_va_page1);
        AP_TASK_INFO.write_u2k_trampoline(high_va_page2);
    }

    let task_info_ptr = unsafe { &raw const AP_TASK_INFO as *const ApTaskInfo as u64 };

    // Record timestamp: User space memory setup complete
    record_and_print(TimePoint::UserSpaceSetupComplete);

    // Step 3: Get number of CPUs from ACPI (simplified - assumes 2 CPUs)
    // For debugging, only start 1 AP
    let cpu_count = 2; // BSP + 1 AP

    // Step 4: Setup boot trampoline
    // Use Unikraft's direct-map region to access physical memory
    let trampoline = BootTrampoline::new(TRAMPOLINE_VIRT_ADDR);

    unsafe {
        // Copy boot code to low memory
        if let Err(e) = trampoline.copy_to_target() {
            panic!("Failed to copy trampoline: {}", e);
        }

        // CRITICAL: Add identity mapping for trampoline (0x0-0x200000 covers first 2MB)
        // The AP needs this when it enables paging in 32-bit mode
        add_identity_mapping(kernel_cr3, 0x0, 0x200000); // Map first 2MB identity

        trampoline.set_page_table(kernel_cr3);

        // Step 4: Initialize per-CPU data structures
        for i in 1..cpu_count {
            // EXPERIMENT: Use stack in low memory (identity-mapped region)
            // Use 0x90000 (below EBDA) for stack to ensure enough space
            // Stack grows DOWN.
            // CPU 1 stack top at 0x90000. Grows to 0x8C000.
            let stack_top = 0x90000 - ((i - 1) as u64 * STACK_SIZE as u64);
            let stack = stack_top;
            // Get APIC ID (for simplicity, assume APIC ID == CPU index)
            let apic_id = i as u64;
            // Set entry point to our AP entry function
            let entry = ap_entry as *const () as u64;

            if let Err(e) = trampoline.init_cpu(i as u32, apic_id, entry, stack, task_info_ptr) {
                panic!("Failed to initialize CPU {}: {}", i, e);
            }
        }

        // Step 1: Enable x2APIC on BSP
        unsafe {
            if let Err(e) = x2apic_enable() {
                panic!("Failed to enable x2APIC: {:?}", e);
            }
        }

        // Step 5: Start all secondary CPUs
        for i in 1..cpu_count {
            let apic_id = i as u32;
            // Send INIT IPI (assert)
            x2apic_send_iipi(apic_id);
            delay_ms(10);
            // De-assert INIT before sending SIPI (required by Intel spec)
            cpu_startup::deassert_init_ipi(apic_id);
            delay_ms(1); // Give it a bit more time
                         // Send SIPI (twice as per Intel specification)
                         // SIPI uses PHYSICAL address, so use TRAMPOLINE_PHYS_ADDR
            let vector = (TRAMPOLINE_PHYS_ADDR >> 12) as u8;
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

        // Monitor AP task execution
        debug_ap_println!("\n=== Monitoring AP Task Execution ===");
        for retry in 0..200 {
            delay_ms(10);
            let status = AP_TASK_INFO.read_status();
            match status {
                0 => {
                    if retry % 10 == 0 {
                        debug_ap_println!("Waiting for AP to start ELF execution...");
                    }
                }
                1 => {
                    // debug_ap_println!("✓ AP is executing ELF...");
                }
                2 => {
                    debug_ap_println!("✓ AP completed ELF execution!");
                    break;
                }
                _ => {
                    debug_ap_println!("⚠ Unknown status: {}", status);
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
