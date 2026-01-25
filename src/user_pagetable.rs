// src/user_pagetable_v2.rs - User space page table management following Dandelion pattern
//
// This implementation closely follows the Dandelion approach from:
// https://github.com/eth-easl/dandelion/blob/main/machine_interface/src/function_driver/compute_driver/kvm/x86_64.rs
//
// Key concepts:
// 1. Allocate a large "guest_mem" buffer in kernel space
// 2. Build page tables at HIGH addresses of this buffer
// 3. User code/data goes at LOW addresses
// 4. Use the kernel virtual addresses as "physical" addresses in PTEs
//    (we translate via kernel page table walk)

use core::arch::asm;
use core::ptr;
use core::slice;

// Import debug macros
use crate::{debug_ap_println, debug_mem_println, debug_trampoline_println};

/// Page table entry flags
const PDE64_PRESENT: u64 = 1 << 0;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const PDE64_ACCESSED: u64 = 1 << 5;
const PDE64_DIRTY: u64 = 1 << 6;
const PDE64_IS_PAGE: u64 = 1 << 7; // Indicates 2MB/1GB page mapping, not another table

/// All common flags for user-accessible read-write pages
const PDE64_ALL_ALLOWED: u64 = PDE64_PRESENT | PDE64_RW | PDE64_USER;

/// Page sizes
const PAGE_SHIFT: usize = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT; // 4KB
const PAGE_MASK: u64 = (PAGE_SIZE - 1) as u64;

const LARGE_PAGE_SHIFT: usize = 21;
const LARGE_PAGE: usize = 1 << LARGE_PAGE_SHIFT; // 2MB

const HUGE_PAGE_SHIFT: usize = 30;
const HUGE_PAGE: usize = 1 << HUGE_PAGE_SHIFT; // 1GB

const PML4_SHIFT: usize = 39;
const TABLE_SIZE: usize = 512; // Each table has 512 entries

/// Interrupt infrastructure configuration
/// Shared between AP kernel setup and user space setup
#[repr(C)]
pub struct InterruptConfig {
    /// Physical/virtual address of GDT
    pub gdt_base: u64,
    /// GDT limit (size - 1)
    pub gdt_limit: u16,
    /// Physical/virtual address of IDT
    pub idt_base: u64,
    /// IDT limit (size - 1)
    pub idt_limit: u16,
    /// Physical/virtual address of TSS
    pub tss_base: u64,
    /// TSS selector in GDT
    pub tss_selector: u16,
    /// Kernel stack for ring 0 (RSP0 in TSS)
    pub kernel_stack: u64,
    /// Interrupt handler stack (for IST entries)
    pub interrupt_stack: u64,
}

impl InterruptConfig {
    /// Create configuration from user space manager
    pub fn from_user_space(manager: &UserSpaceManager, kernel_stack: u64) -> Self {
        // Get the aligned base address (raw allocation + alignment offset)
        let aligned_base =
            (manager.guest_mem.as_ptr() as u64) + manager.guest_mem_aligned_offset as u64;
        Self {
            gdt_base: aligned_base + manager.gdt_offset as u64,
            gdt_limit: 80 - 1, // 10 entries × 8 bytes - 1
            idt_base: aligned_base + manager.idt_offset as u64,
            idt_limit: (33 * 16) - 1, // 33 entries × 16 bytes - 1
            tss_base: aligned_base + manager.tss_offset as u64,
            tss_selector: 0x28, // GDT offset for TSS
            kernel_stack,
            interrupt_stack: aligned_base + manager.get_interrupt_stack_top() as u64,
        }
    }

    /// Load this configuration into CPU registers
    ///
    /// # Safety
    /// Must be called with valid addresses that are mapped in current page tables
    pub unsafe fn load_into_cpu(&self) {
        use core::arch::asm;

        // Load GDT
        let gdt_desc = [
            self.gdt_limit,
            (self.gdt_base & 0xFFFF) as u16,
            ((self.gdt_base >> 16) & 0xFFFF) as u16,
            ((self.gdt_base >> 32) & 0xFFFF) as u16,
            ((self.gdt_base >> 48) & 0xFFFF) as u16,
        ];
        asm!("lgdt [{}]", in(reg) &gdt_desc, options(readonly, nostack, preserves_flags));

        // Load IDT
        let idt_desc = [
            self.idt_limit,
            (self.idt_base & 0xFFFF) as u16,
            ((self.idt_base >> 16) & 0xFFFF) as u16,
            ((self.idt_base >> 32) & 0xFFFF) as u16,
            ((self.idt_base >> 48) & 0xFFFF) as u16,
        ];
        asm!("lidt [{}]", in(reg) &idt_desc, options(readonly, nostack, preserves_flags));

        // Load TSS
        asm!("ltr {0:x}", in(reg) self.tss_selector, options(nostack, preserves_flags));
    }
}

/// Walk page tables to translate virtual address to physical address
/// Returns (physical_address, pte_entry) so caller can check flags
pub unsafe fn walk_pt_with_flags(cr3: u64, va: u64) -> Result<(u64, u64), &'static str> {
    const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const DIRECTMAP_START: u64 = 0xffffff8000000000;

    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;
    let offset = va & 0xFFF;

    let pml4_phys = cr3 & PTE_ADDR_MASK;
    let pml4_virt = (pml4_phys + DIRECTMAP_START) as *const u64;
    let pml4e = core::ptr::read_volatile(pml4_virt.add(pml4_idx as usize));

    if (pml4e & 1) == 0 {
        return Err("PML4 entry not present");
    }

    let pdpt_phys = pml4e & PTE_ADDR_MASK;
    let pdpt_virt = (pdpt_phys + DIRECTMAP_START) as *const u64;
    let pdpte = core::ptr::read_volatile(pdpt_virt.add(pdpt_idx as usize));

    if (pdpte & 1) == 0 {
        return Err("PDPT entry not present");
    }

    let pd_phys = pdpte & PTE_ADDR_MASK;
    let pd_virt = (pd_phys + DIRECTMAP_START) as *const u64;
    let pde = core::ptr::read_volatile(pd_virt.add(pd_idx as usize));

    if (pde & 1) == 0 {
        return Err("PD entry not present");
    }

    // Check if it's a 2MB huge page
    if (pde & 0x80) != 0 {
        let page_pa = pde & PTE_ADDR_MASK;
        let offset_2mb = va & 0x1F_FFFF; // 2MB offset
        return Ok((page_pa | offset_2mb, pde));
    }

    let pt_phys = pde & PTE_ADDR_MASK;
    let pt_virt = (pt_phys + DIRECTMAP_START) as *const u64;
    let pte = core::ptr::read_volatile(pt_virt.add(pt_idx as usize));

    if (pte & 1) == 0 {
        return Err("PT entry not present");
    }

    let page_phys = pte & PTE_ADDR_MASK;
    Ok((page_phys | offset, pte))
}

/// Walk page tables to translate virtual address to physical address
/// Panics if any level is not present, returns PA if successfully walked
pub unsafe fn walk_pt(cr3: u64, va: u64) -> Result<u64, &'static str> {
    walk_pt_with_flags(cr3, va).map(|(pa, _)| pa)
}

/// Walk kernel page tables to translate virtual → physical
/// Unikraft uses a direct-map region starting at 0xffffff8000000000
pub unsafe fn virt_to_phys(virt_addr: u64) -> Option<u64> {
    const DIRECTMAP_START: u64 = 0xffffff8000000000;

    // Get CR3
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    let pml4_phys = cr3 & !0xFFF;

    // Debug output
    // println!("  virt_to_phys: virt=0x{:016x}, CR3=0x{:016x}", virt_addr, cr3);

    // Extract indices
    let pml4_idx = (virt_addr >> 39) & 0x1FF;
    let pdpt_idx = (virt_addr >> 30) & 0x1FF;
    let pd_idx = (virt_addr >> 21) & 0x1FF;
    let pt_idx = (virt_addr >> 12) & 0x1FF;
    let offset = virt_addr & 0xFFF;

    // println!("  Indices: PML4[{}] PDPT[{}] PD[{}] PT[{}]", pml4_idx, pdpt_idx, pd_idx, pt_idx);

    // Walk PML4
    let pml4 = (DIRECTMAP_START + pml4_phys) as *const u64;
    let pml4_entry = ptr::read_volatile(pml4.add(pml4_idx as usize));
    // debug_mem_println!("  PML4[{}] = 0x{:016x}", pml4_idx, pml4_entry);
    if pml4_entry & 1 == 0 {
        debug_mem_println!("  PML4 entry not present! virt_addr 0x{:016x}", virt_addr);
        return None;
    }

    // Walk PDPT
    let pdpt = (DIRECTMAP_START + (pml4_entry & !0xFFF)) as *const u64;
    let pdpt_entry = ptr::read_volatile(pdpt.add(pdpt_idx as usize));
    // debug_mem_println!("  PDPT[{}] = 0x{:016x}", pdpt_idx, pdpt_entry);
    if pdpt_entry & 1 == 0 {
        debug_mem_println!("  PDPT entry not present! virt_addr 0x{:016x}", virt_addr);
        return None;
    }
    if pdpt_entry & (1 << 7) != 0 {
        // 1GB page
        let phys = (pdpt_entry & !0x3FFFFFFF) + (virt_addr & 0x3FFFFFFF);
        return Some(phys & 0x000F_FFFF_FFFF_F000);
    }

    // Walk PD
    let pd = (DIRECTMAP_START + (pdpt_entry & !0xFFF)) as *const u64;
    let pd_entry = ptr::read_volatile(pd.add(pd_idx as usize));
    // debug_mem_println!("  PD[{}] = 0x{:016x}", pd_idx, pd_entry);
    if pd_entry & 1 == 0 {
        debug_mem_println!("  PD entry not present! virt_addr 0x{:016x}", virt_addr);
        return None;
    }
    if pd_entry & (1 << 7) != 0 {
        // 2MB page - frame address plus offset within 2MB page
        let phys_frame = pd_entry & 0x000F_FFFF_FFE0_0000; // 2MB aligned physical frame
        let offset = virt_addr & 0x1FFFFF; // 21-bit offset within 2MB page
        return Some(phys_frame + offset);
    }

    // Walk PT
    let pt = (DIRECTMAP_START + (pd_entry & !0xFFF)) as *const u64;
    let pt_entry = ptr::read_volatile(pt.add(pt_idx as usize));
    // debug_mem_println!("  PT[{}] = 0x{:016x}", pt_idx, pt_entry);
    if pt_entry & 1 == 0 {
        debug_mem_println!("  PT entry not present! virt_addr 0x{:016x}", virt_addr);
        return None;
    }

    // Return page frame + offset (full physical address)
    let phys_frame = pt_entry & 0x000F_FFFF_FFFF_F000; // Extract page frame, mask out flags
    let result = phys_frame + offset;
    // debug_mem_println!("  Result: phys=0x{:016x}", result);
    Some(result)
}

/// Helper to convert u8 slice to u64 slice (for page table manipulation)
fn u8_slice_to_u64_slice(input: &mut [u8]) -> &mut [u64] {
    assert!(input.len() % 8 == 0);
    let u64_len = input.len() / 8;
    unsafe { slice::from_raw_parts_mut(input.as_mut_ptr() as *mut u64, u64_len) }
}

/// Get p2 (page directory) base and entry for a given page entry index
fn get_p2(current_page_entry: usize) -> (usize, usize) {
    let p2_base = (current_page_entry / (TABLE_SIZE * TABLE_SIZE)) * (TABLE_SIZE + 1) * TABLE_SIZE;
    let p2_entry = (current_page_entry / TABLE_SIZE) % TABLE_SIZE;
    (p2_base, p2_entry)
}

/// Map a range of virtual addresses to physical addresses in the user page tables
/// This follows the Dandelion set_range() implementation but translates each page individually
///
/// # Arguments
/// * `table_array` - The combined p2+p1 tables array
/// * `table_base` - Base address (in guest_mem) where table_array starts
/// * `virtual_start` - Start of virtual address range (guest virtual)
/// * `virtual_end` - End of virtual address range (exclusive)
/// * `protection_flags` - Page protection flags (PDE64_*)
/// * `kernel_virt_start` - Starting kernel virtual address of the memory to map
/// * `previous_past_last_page` - Last page index from previous call (for continuity)
///
/// # Returns
/// The past-last-page index for this range (for next call)
fn set_range(
    table_array: &mut [u64],
    table_base_virt: u64,
    virtual_start: usize,
    virtual_end: usize,
    protection_flags: u64,
    kernel_virt_start: usize,
    previous_past_last_page: usize,
) -> Result<usize, &'static str> {
    let mut current_page_entry = virtual_start >> PAGE_SHIFT;
    let past_last_page = virtual_end >> PAGE_SHIFT;

    // Ensure no overlap with previous range
    debug_assert!(previous_past_last_page <= current_page_entry);

    // If p2 table for first page hasn't been set up and we need it, set it up now
    if previous_past_last_page.next_multiple_of(TABLE_SIZE) <= current_page_entry
        && current_page_entry % TABLE_SIZE != 0
    {
        let (p2_base, p2_entry) = get_p2(current_page_entry);
        let p1_offset = p2_base + (1 + p2_entry) * TABLE_SIZE;

        // Translate P1 table's virtual address to physical
        let p1_virt = table_base_virt + (p1_offset * core::mem::size_of::<u64>()) as u64;
        let p1_phys = unsafe {
            virt_to_phys(p1_virt)
                .ok_or("Failed to translate P1 table virtual address to physical")?
        };

        table_array[p2_base + p2_entry] = PDE64_ALL_ALLOWED | p1_phys;
        // table_array[p1_offset..p1_offset + (current_page_entry % TABLE_SIZE)].fill(0);
    }

    while current_page_entry < past_last_page {
        let (p2_base, p2_entry) = get_p2(current_page_entry);
        let p1_offset = current_page_entry % TABLE_SIZE;

        // If starting a new p2 entry (aligned to 2MB boundary)
        if p1_offset == 0 {
            // If we can map the whole 2MB with a large page, do it
            if current_page_entry + TABLE_SIZE <= past_last_page {
                // Translate the virtual address for this 2MB page
                let user_va = current_page_entry << PAGE_SHIFT;
                let offset_in_range = user_va - virtual_start;
                let kernel_virt = kernel_virt_start + offset_in_range;
                let phys = unsafe {
                    virt_to_phys(kernel_virt as u64)
                        .ok_or("Failed to translate kernel virtual address to physical")?
                };

                table_array[p2_base + p2_entry] = protection_flags | PDE64_IS_PAGE | phys;
                current_page_entry += TABLE_SIZE;
                continue;
            } else {
                // Need a p1 table for partial 2MB region - translate its virtual address
                let p1_offset_idx = p2_base + (1 + p2_entry) * TABLE_SIZE;
                let p1_virt =
                    table_base_virt + (p1_offset_idx * core::mem::size_of::<u64>()) as u64;
                let p1_phys = unsafe {
                    virt_to_phys(p1_virt)
                        .ok_or("Failed to translate P1 table virtual address to physical")?
                };
                table_array[p2_base + p2_entry] = PDE64_ALL_ALLOWED | p1_phys;
            }
        }

        // Map individual 4KB page in p1 table - translate each page
        let user_va = current_page_entry << PAGE_SHIFT;
        let offset_in_range = user_va - virtual_start;
        let kernel_virt = kernel_virt_start + offset_in_range;
        let phys = unsafe {
            virt_to_phys(kernel_virt as u64)
                .ok_or("Failed to translate kernel virtual address to physical")?
        };

        let p1_base = p2_base + (1 + p2_entry) * TABLE_SIZE;
        table_array[p1_base + p1_offset] = protection_flags | phys;

        current_page_entry += 1;
    }

    // Fill rest of last p1 table with zeros
    if current_page_entry % TABLE_SIZE != 0 {
        // let last_index =
        //     current_page_entry + TABLE_SIZE * (1 + current_page_entry / (TABLE_SIZE * TABLE_SIZE));
        // table_array[last_index..last_index.next_multiple_of(TABLE_SIZE)].fill(0);
    }

    Ok(past_last_page)
}

/// User space manager following Dandelion pattern
///
/// Memory layout:
/// ```
/// High addresses (buffer end)
/// ├─ P4 table (PML4) - 1 page
/// ├─ P3 table (PDPT) - 1 page  
/// ├─ P2+P1 tables - multiple pages
/// ├─ Interrupt handler stack - N pages (RSP0 points here)
/// ├─ IDT - 1 page (33 entries × 16 bytes)
/// ├─ TSS - 104 bytes
/// ├─ GDT - 80 bytes  
/// ├─ Interrupt handlers - 1 page (assembly fault handler code)
/// ↓
/// Low addresses (0)
/// └─ User code/data region
/// ```
pub struct UserSpaceManager {
    /// The entire "guest memory" buffer (owned) - may have padding at start for alignment
    guest_mem: Vec<u8>,
    /// Offset to page-aligned region within guest_mem
    guest_mem_aligned_offset: usize,
    /// Size of the user-addressable space (excluding reserved interrupt structures)
    last_address: usize,
    /// Physical address of PML4 (for CR3) - validated page-aligned
    p4_pa: u64,
    /// BUFFER OFFSET: P4 (PML4) table location in guest_mem
    p4_offset: usize,
    /// Address where stack starts (points below reserved memory structures)
    stack_start: usize,
    /// Address where interrupt structures start (end of user-addressable space)
    interrupt_start: usize,
    /// BUFFER OFFSET: where interrupt handler code page starts in guest_mem
    interrupt_handler_code_offset: usize,
    /// BUFFER OFFSET: GDT location in guest_mem
    gdt_offset: usize,
    /// BUFFER OFFSET: TSS location in guest_mem
    tss_offset: usize,
    /// BUFFER OFFSET: IDT location in guest_mem
    idt_offset: usize,
    /// BUFFER OFFSET: interrupt handler stack location in guest_mem
    interrupt_stack_offset: usize,
    /// USER VIRTUAL ADDRESS: where interrupt structures are mapped in user space
    interrupt_virt_base: usize,
    /// BUFFER OFFSET: P3 table for trampoline mappings (~2TB region)
    trampoline_p3_offset: usize,
    /// BUFFER OFFSET: P2 table for trampoline mappings
    trampoline_p2_offset: usize,
    /// BUFFER OFFSET: P1 table for trampoline mappings
    trampoline_p1_offset: usize,
    /// Physical addresses of trampoline page tables (validated page-aligned at init)
    trampoline_p3_pa: u64,
    trampoline_p2_pa: u64,
    trampoline_p1_pa: u64,
    /// BUFFER OFFSET: where P2+P1 tables start (for map_user_range)
    table_base: usize,
    /// SIZE: total size of P2+P1 table region in bytes
    table_size: usize,
}

impl UserSpaceManager {
    /// Create a new user space with the given size
    ///
    /// # Arguments
    /// * `user_space_size` - Maximum address userspace can access (e.g., 512MB = 1<<29)
    ///
    /// # Safety
    /// Must be called in context where allocation is safe
    pub unsafe fn new(user_space_size: usize) -> Result<Self, &'static str> {
        if user_space_size >= (1 << 39) {
            return Err("User space size must be < 512GB");
        }

        // Page tables must cover the FULL user_space_size range
        let total_size = user_space_size; // Everything fits in 64MB

        // Constants for interrupt infrastructure (following Dandelion)
        const GDT_SIZE: usize = 80; // 10 entries × 8 bytes (null + 2 kernel + 2 user + TSS)
        const TSS_SIZE: usize = 104; // Standard TSS size
        const IDT_ENTRIES: usize = 33; // Entries 0-32
        const IDT_ENTRY_SIZE: usize = 16; // 16 bytes per entry in 64-bit mode
        const INTERRUPT_STACK_PAGES: usize = 4; // 16KB stack for interrupt handlers

        // Calculate page table space needed for FULL user_space_size
        let p2_table_number = total_size.next_multiple_of(HUGE_PAGE) >> HUGE_PAGE_SHIFT;
        let p1_table_number = p2_table_number * TABLE_SIZE;
        // Increase p1p2 size to cover total_size (64MB)
        let page_table_pages = 1 + 1 + p2_table_number + p1_table_number; // p4 + p3 + p2s + p1s
        let page_table_bytes = page_table_pages << PAGE_SHIFT;

        // Calculate sizes for interrupt infrastructure
        let interrupt_handler_code_bytes = PAGE_SIZE; // 1 page for handler assembly
        let gdt_bytes = GDT_SIZE;
        let tss_bytes = TSS_SIZE;
        let idt_bytes = IDT_ENTRIES * IDT_ENTRY_SIZE;
        let interrupt_stack_bytes = INTERRUPT_STACK_PAGES << PAGE_SHIFT;

        // Total space for interrupt infrastructure
        let interrupt_total = interrupt_handler_code_bytes
            + gdt_bytes
            + tss_bytes
            + idt_bytes
            + interrupt_stack_bytes;

        // Allocate buffer: 64MB + 1 page to ensure we can find a page-aligned region
        let allocation_size = total_size + PAGE_SIZE;
        let mut raw_allocation = vec![0u8; allocation_size];

        // Find the first page-aligned address within the allocation
        let raw_ptr = raw_allocation.as_ptr() as usize;
        let alignment_offset = if raw_ptr & (PAGE_SIZE - 1) == 0 {
            0 // Already aligned
        } else {
            PAGE_SIZE - (raw_ptr & (PAGE_SIZE - 1)) // Offset to next page boundary
        };

        debug_mem_println!(
            "  Raw allocation at 0x{:016x}, alignment offset: 0x{:x}",
            raw_ptr,
            alignment_offset
        );

        // Create a slice starting at the aligned offset
        let guest_mem = &mut raw_allocation[alignment_offset..alignment_offset + total_size];
        let guest_mem_kva = guest_mem.as_ptr() as u64;

        // Verify virtual alignment
        if guest_mem_kva & (PAGE_SIZE as u64 - 1) != 0 {
            return Err("guest_mem is not page-aligned in virtual address space!");
        }
        debug_mem_println!(
            "  guest_mem at KVA 0x{:016x} (page-aligned ✓)",
            guest_mem_kva
        );

        // Force kernel to map all pages FIRST (one write per page is sufficient)
        // This ensures virt_to_phys() will work on all addresses
        debug_mem_println!(
            "  Forcing kernel to map {} pages...",
            total_size / PAGE_SIZE
        );
        for page in 0..(total_size / PAGE_SIZE) {
            guest_mem[page * PAGE_SIZE] = 0; // Touch first byte of each page
        }
        debug_mem_println!("  All pages now mapped in kernel page tables ✓");

        // NOW check physical alignment (after pages are mapped)
        let guest_mem_pa_check = virt_to_phys(guest_mem_kva)
            .ok_or("Failed to translate guest_mem base to physical address")?;
        if guest_mem_pa_check & (PAGE_SIZE as u64 - 1) != 0 {
            return Err("guest_mem is not page-aligned in PHYSICAL address space!");
        }
        debug_mem_println!(
            "  guest_mem at PA  0x{:016x} (page-aligned ✓)",
            guest_mem_pa_check
        );

        // ==================================================================
        // ALLOCATION STRATEGY: Work backwards from end of 64MB buffer
        // Layout: [User Space | Interrupt Structures | Page Tables]
        // Buffer offset = Virtual address (everything in first 64MB)
        // ==================================================================

        let mut addr = total_size; // Start from end (64MB)

        // 1. Allocate page tables (from end, working backwards)
        addr -= PAGE_SIZE;
        let p4_offset = addr;

        // Validate p4_offset is page-aligned and within bounds
        assert_eq!(
            p4_offset & (PAGE_SIZE - 1),
            0,
            "P4 offset must be page-aligned"
        );
        assert!(
            p4_offset + PAGE_SIZE <= total_size,
            "P4 extends beyond guest_mem"
        );

        addr -= PAGE_SIZE;
        let p3_offset = addr;

        let p2p1_size = (p2_table_number + p1_table_number) << PAGE_SHIFT;
        addr -= p2p1_size;
        let p2p1_offset = addr;

        let page_tables_start = addr; // Where main page tables begin

        // 1.5. Allocate trampoline page tables (P3/P2/P1 for ~2TB mapping)
        // These are separate from main page tables to avoid complexity
        addr -= PAGE_SIZE;
        let trampoline_p1_offset = addr;

        addr -= PAGE_SIZE;
        let trampoline_p2_offset = addr;

        addr -= PAGE_SIZE;
        let trampoline_p3_offset = addr;

        let trampoline_tables_start = addr;

        // 2. Allocate interrupt structures (before trampoline tables)
        // IMPORTANT: Page-align each major section for proper mapping with different permissions

        // Round down to page boundary for interrupt structures
        addr = (addr / PAGE_SIZE) * PAGE_SIZE;

        // Region 1: Interrupt Stack (RW)
        addr -= interrupt_stack_bytes;
        let interrupt_stack_offset = addr;

        // Region 2: GDT + TSS + IDT (RO)
        // Pack these into one page (or multiple if needed, but they fit in one)
        // Ensure we start at a page boundary below the stack
        addr = (addr / PAGE_SIZE) * PAGE_SIZE; // Should already be aligned

        // Allocate space for packed structures (1 page is enough for < 1KB)
        // We'll put them at the END of this page/region
        let misc_structures_end = addr;
        addr -= PAGE_SIZE; // Allocate 1 page
        let misc_structures_start = addr;

        // Calculate offsets within this page (working backwards from end)
        let mut struct_ptr = misc_structures_end;

        struct_ptr -= idt_bytes;
        let idt_offset = struct_ptr;

        struct_ptr -= tss_bytes;
        let tss_offset = struct_ptr;

        struct_ptr -= gdt_bytes;
        let gdt_offset = struct_ptr;

        // Ensure we didn't overflow the page
        assert!(
            gdt_offset >= misc_structures_start,
            "Interrupt structures exceed 1 page!"
        );

        // Region 3: Handler Code (RX)
        addr -= interrupt_handler_code_bytes;
        let handler_code_offset = addr;

        let interrupt_start = addr; // Where interrupt structures begin

        // Round down to page boundary - this is where user space ends
        let user_space_end = (interrupt_start / PAGE_SIZE) * PAGE_SIZE;

        debug_mem_println!("\n=== BUFFER LAYOUT (64MB total) ===");
        debug_mem_println!("  Buffer size: {} bytes (0x{:x})", total_size, total_size);
        debug_mem_println!("  Memory regions:");
        debug_mem_println!(
            "    [0x0 - 0x{:x}] User space ({:.2} MB) ✓ PAGE-ALIGNED",
            user_space_end,
            user_space_end as f64 / (1024.0 * 1024.0)
        );
        if user_space_end != interrupt_start {
            debug_mem_println!(
                "    [0x{:x} - 0x{:x}] Gap for alignment ({} bytes)",
                user_space_end,
                interrupt_start,
                interrupt_start - user_space_end
            );
        }
        debug_mem_println!(
            "    [0x{:x} - 0x{:x}] Interrupt structures ({} bytes)",
            interrupt_start,
            trampoline_tables_start,
            trampoline_tables_start - interrupt_start
        );
        debug_mem_println!(
            "      Handler code:  0x{:x} ({} bytes)",
            handler_code_offset,
            interrupt_handler_code_bytes
        );
        debug_mem_println!(
            "      GDT:           0x{:x} ({} bytes)",
            gdt_offset,
            gdt_bytes
        );
        debug_mem_println!(
            "      TSS:           0x{:x} ({} bytes)",
            tss_offset,
            tss_bytes
        );
        debug_mem_println!(
            "      IDT:           0x{:x} ({} bytes)",
            idt_offset,
            idt_bytes
        );
        debug_mem_println!(
            "      Int stack:     0x{:x} ({} bytes)",
            interrupt_stack_offset,
            interrupt_stack_bytes
        );
        debug_mem_println!(
            "    [0x{:x} - 0x{:x}] Trampoline page tables (3 pages)",
            trampoline_tables_start,
            page_tables_start
        );
        debug_mem_println!("      Tramp P3:      0x{:x}", trampoline_p3_offset);
        debug_mem_println!("      Tramp P2:      0x{:x}", trampoline_p2_offset);
        debug_mem_println!("      Tramp P1:      0x{:x}", trampoline_p1_offset);
        debug_mem_println!(
            "    [0x{:x} - 0x{:x}] Main page tables ({} bytes)",
            page_tables_start,
            total_size,
            page_table_bytes
        );
        debug_mem_println!("      P2+P1:         0x{:x}", p2p1_offset);
        debug_mem_println!("      P3:            0x{:x}", p3_offset);
        debug_mem_println!("      P4:            0x{:x}\n", p4_offset);

        // Get physical addresses by translating each page table's virtual address
        // All addresses must be page-aligned for page table entries
        const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        const PAGE_MASK: u64 = PAGE_SIZE as u64 - 1;

        let guest_mem_base_kva = guest_mem.as_ptr() as u64;

        let p4_kva = guest_mem_base_kva + p4_offset as u64;
        let p4_pa_raw = virt_to_phys(p4_kva).ok_or("Failed to translate P4 KVA to physical")?;

        // Validate P4 physical address is page-aligned
        if p4_pa_raw & PAGE_MASK != 0 {
            debug_mem_println!("  ERROR: P4 PA 0x{:016x} is NOT page-aligned!", p4_pa_raw);
            return Err("P4 table is not page-aligned in physical memory! This will break CR3.");
        }
        let p4_pa = p4_pa_raw & PTE_ADDR_MASK;

        debug_mem_println!("  P4 setup:");
        debug_mem_println!("    p4_offset in guest_mem: 0x{:x}", p4_offset);
        debug_mem_println!("    p4_kva: 0x{:016x}", p4_kva);
        debug_mem_println!("    p4_pa:  0x{:016x} (validated page-aligned ✓)", p4_pa);

        let p3_kva = guest_mem_base_kva + p3_offset as u64;
        let p3_pa_raw = virt_to_phys(p3_kva).ok_or("Failed to translate P3 KVA to physical")?;
        if p3_pa_raw & PAGE_MASK != 0 {
            debug_mem_println!("  ERROR: P3 PA 0x{:016x} is NOT page-aligned!", p3_pa_raw);
            return Err("P3 table is not page-aligned in physical memory!");
        }
        let p3_pa = p3_pa_raw & PTE_ADDR_MASK;

        let p2p1_kva = guest_mem_base_kva + p2p1_offset as u64;

        // Get and validate trampoline page table physical addresses
        let tramp_p3_kva = guest_mem_base_kva + trampoline_p3_offset as u64;
        let tramp_p3_pa_raw = virt_to_phys(tramp_p3_kva)
            .ok_or("Failed to translate trampoline P3 KVA to physical")?;
        if tramp_p3_pa_raw & PAGE_MASK != 0 {
            debug_mem_println!(
                "  ERROR: Trampoline P3 PA 0x{:016x} is NOT page-aligned!",
                tramp_p3_pa_raw
            );
            return Err("Trampoline P3 is not page-aligned in physical memory!");
        }
        let trampoline_p3_pa = tramp_p3_pa_raw & PTE_ADDR_MASK;

        let tramp_p2_kva = guest_mem_base_kva + trampoline_p2_offset as u64;
        let tramp_p2_pa_raw = virt_to_phys(tramp_p2_kva)
            .ok_or("Failed to translate trampoline P2 KVA to physical")?;
        if tramp_p2_pa_raw & PAGE_MASK != 0 {
            debug_mem_println!(
                "  ERROR: Trampoline P2 PA 0x{:016x} is NOT page-aligned!",
                tramp_p2_pa_raw
            );
            return Err("Trampoline P2 is not page-aligned in physical memory!");
        }
        let trampoline_p2_pa = tramp_p2_pa_raw & PTE_ADDR_MASK;

        let tramp_p1_kva = guest_mem_base_kva + trampoline_p1_offset as u64;
        let tramp_p1_pa_raw = virt_to_phys(tramp_p1_kva)
            .ok_or("Failed to translate trampoline P1 KVA to physical")?;
        if tramp_p1_pa_raw & PAGE_MASK != 0 {
            debug_mem_println!(
                "  ERROR: Trampoline P1 PA 0x{:016x} is NOT page-aligned!",
                tramp_p1_pa_raw
            );
            return Err("Trampoline P1 is not page-aligned in physical memory!");
        }
        let trampoline_p1_pa = tramp_p1_pa_raw & PTE_ADDR_MASK;

        // Initialize trampoline page tables (will be set up when trampolines are mapped)
        {
            let (_, tramp_p3_raw) = guest_mem.split_at_mut(trampoline_p3_offset);
            let tramp_p3 = u8_slice_to_u64_slice(&mut tramp_p3_raw[0..PAGE_SIZE]);
            tramp_p3.fill(0);

            let (_, tramp_p2_raw) = guest_mem.split_at_mut(trampoline_p2_offset);
            let tramp_p2 = u8_slice_to_u64_slice(&mut tramp_p2_raw[0..PAGE_SIZE]);
            tramp_p2.fill(0);

            let (_, tramp_p1_raw) = guest_mem.split_at_mut(trampoline_p1_offset);
            let tramp_p1 = u8_slice_to_u64_slice(&mut tramp_p1_raw[0..PAGE_SIZE]);
            tramp_p1.fill(0);
        }

        // Set up P4 table
        {
            let (_, p4_raw) = guest_mem.split_at_mut(p4_offset);
            let p4_table = u8_slice_to_u64_slice(&mut p4_raw[0..PAGE_SIZE]);
            p4_table.fill(0);

            // P4[0] points to P3
            p4_table[0] = PDE64_ALL_ALLOWED | p3_pa;

            // Verify P4 is properly initialized
            assert_ne!(
                p4_table[0], 0,
                "P4[0] must be non-zero after initialization"
            );
        }

        // Set up P3 table
        {
            let (_, p3_raw) = guest_mem.split_at_mut(p3_offset);
            let p3_table = u8_slice_to_u64_slice(&mut p3_raw[0..PAGE_SIZE]);
            p3_table.fill(0);

            // P3 entries point to P2 tables - translate each P2 table's address
            for p3_entry in 0..p2_table_number {
                let p2_offset_in_tables = p3_entry * (TABLE_SIZE + 1) * PAGE_SIZE;
                let p2_kva = p2p1_kva + p2_offset_in_tables as u64;
                let p2_pa_raw =
                    virt_to_phys(p2_kva).ok_or("Failed to translate P2 table KVA to physical")?;
                if p2_pa_raw & PAGE_MASK != 0 {
                    return Err("P2 table is not page-aligned in physical memory!");
                }
                let p2_pa = p2_pa_raw & PTE_ADDR_MASK;
                p3_table[p3_entry] = PDE64_ALL_ALLOWED | p2_pa;
            }
        }

        // Initialize P2 and P1 tables
        {
            let (_, table_raw) = guest_mem.split_at_mut(p2p1_offset);
            let table_array_len = p2p1_size;
            let table_array = u8_slice_to_u64_slice(&mut table_raw[0..table_array_len]);

            // Zero out all P2 tables (P1 tables will be set up as needed by set_range)
            for p3_entry in 0..p2_table_number {
                let start_index = p3_entry * (TABLE_SIZE + 1) * TABLE_SIZE;
                table_array[start_index..start_index + TABLE_SIZE].fill(0);
            }
        }

        // Use p2p1_offset directly - it's already calculated correctly
        let table_base = p2p1_offset;
        let table_size = p2p1_size;

        // NOTE: We do NOT map the page tables into the user space anymore.
        // This avoids self-referential mapping bugs.
        // If we need to modify page tables, we use the kernel direct map (buffer offsets).

        // Calculate indices for the user stack virtual address (needed for debugging/info)
        // The user stack is located just below the interrupt block at user_space_end
        let user_stack_size = 16 * 4096; // 64KB, must match main.rs
        let user_stack_virt = user_space_end - user_stack_size;

        let pml4_idx = (user_stack_virt >> 39) & 0x1FF;
        let pdpt_idx = (user_stack_virt >> 30) & 0x1FF;
        let pd_idx = (user_stack_virt >> 21) & 0x1FF;
        let pt_idx = ((user_stack_virt >> 12) & 0x1FF); // First page of stack

        Ok(Self {
            guest_mem: raw_allocation,
            guest_mem_aligned_offset: alignment_offset,
            last_address: total_size, // Full size that page tables cover
            p4_pa,
            p4_offset,
            stack_start: page_tables_start, // Where page tables start
            interrupt_start, // Where interrupt structures actually start (may not be page-aligned)
            interrupt_handler_code_offset: handler_code_offset,
            gdt_offset,
            tss_offset,
            idt_offset,
            interrupt_stack_offset,
            interrupt_virt_base: user_space_end, // User space ends at page-aligned boundary
            trampoline_p3_offset,
            trampoline_p2_offset,
            trampoline_p1_offset,
            trampoline_p3_pa,
            trampoline_p2_pa,
            trampoline_p1_pa,
            table_base,
            table_size,
        })
    }

    /// Map a range of memory at a specific user virtual address
    ///
    /// This assumes the memory at `kernel_virt_start` is already mapped in kernel space
    /// and we want to make it accessible in user space at `user_virt_start`.
    ///
    /// # Arguments
    /// * `user_virt_start` - Virtual address in user space
    /// * `kernel_virt_start` - Kernel virtual address of the memory
    /// * `size` - Size in bytes
    /// * `writable` - Whether user can write to these pages
    pub unsafe fn map_user_range(
        &mut self,
        user_virt_start: usize,
        kernel_virt_start: usize,
        size: usize,
        writable: bool,
        kernel_accessible: bool,
    ) -> Result<(), &'static str> {
        if user_virt_start + size > self.last_address {
            return Err("Mapping extends beyond user address space");
        }

        println!("\n=== map_user_range ===");
        println!(
            "  Mapping: user VA 0x{:x} - 0x{:x}",
            user_virt_start,
            user_virt_start + size
        );
        println!("  From:    kernel VA 0x{:x}", kernel_virt_start);
        println!("  Size:    0x{:x} ({} KB)", size, size / 1024);
        println!("  Writable: {}", writable);
        println!("  Kernel-accessible (no U bit): {}", kernel_accessible);

        // Calculate protection flags
        // If kernel_accessible=true, omit U bit so CPL=0 code can access
        let protection_flags = match (writable, kernel_accessible) {
            (true, true) => PDE64_PRESENT | PDE64_RW, // Kernel RW (no U bit)
            (true, false) => PDE64_ALL_ALLOWED,       // User RW
            (false, true) => PDE64_PRESENT,           // Kernel RO (no U bit)
            (false, false) => PDE64_PRESENT | PDE64_USER, // User RO
        };

        // Use stored fields instead of recalculating
        let table_base = self.table_base;
        let table_size = self.table_size;

        let guest_mem = self.get_aligned_mem_mut();
        let guest_mem_base_kva = guest_mem.as_ptr() as u64;
        let table_base_kva = guest_mem_base_kva + table_base as u64;

        println!("  table_base offset: 0x{:x}", table_base);
        println!("  table_base KVA: 0x{:x}", table_base_kva);

        let (_, table_raw) = guest_mem.split_at_mut(table_base);
        let table_array = u8_slice_to_u64_slice(&mut table_raw[0..table_size]);

        // Use set_range to map the pages
        set_range(
            table_array,
            table_base_kva,
            user_virt_start,
            user_virt_start + size,
            protection_flags,
            kernel_virt_start,
            0, // TODO: Track previous_past_last_page for multiple calls
        )?;

        println!("  ✓ set_range completed");

        // VERIFICATION: Walk page tables to verify mapping
        let user_cr3 = self.p4_pa;
        println!("\n  Verifying mappings...");

        // Check first page
        let first_va = user_virt_start as u64;
        let first_kva = kernel_virt_start as u64;
        let first_expected_pa = virt_to_phys(first_kva).ok_or("Failed to get PA for first page")?
            & 0x000F_FFFF_FFFF_F000;

        match walk_pt(user_cr3, first_va) {
            Ok(mapped_pa) => {
                let mapped_pa_clean = mapped_pa & 0x000F_FFFF_FFFF_F000;
                if mapped_pa_clean != first_expected_pa {
                    println!(
                        "  ✗ First page VA 0x{:x}: mapped to PA 0x{:x}, expected 0x{:x}",
                        first_va, mapped_pa_clean, first_expected_pa
                    );
                    return Err("First page mapped to wrong physical address");
                }
                println!(
                    "  ✓ First page VA 0x{:x} -> PA 0x{:x}",
                    first_va, mapped_pa_clean
                );
            }
            Err(e) => {
                println!("  ✗ First page VA 0x{:x}: {}", first_va, e);
                return Err(e);
            }
        }

        // Check last page AND the exact byte that will be accessed
        let last_page_va = ((user_virt_start + size - 1) & !0xFFF) as u64;
        let last_page_offset = ((last_page_va - user_virt_start as u64) as usize) as u64;
        let last_kva = (kernel_virt_start as u64) + last_page_offset;
        let last_expected_pa =
            virt_to_phys(last_kva).ok_or("Failed to get PA for last page")? & 0x000F_FFFF_FFFF_F000;

        match walk_pt_with_flags(user_cr3, last_page_va) {
            Ok((mapped_pa, pte)) => {
                let mapped_pa_clean = mapped_pa & 0x000F_FFFF_FFFF_F000;
                if mapped_pa_clean != last_expected_pa {
                    println!(
                        "  ✗ Last page VA 0x{:x}: mapped to PA 0x{:x}, expected 0x{:x}",
                        last_page_va, mapped_pa_clean, last_expected_pa
                    );
                    return Err("Last page mapped to wrong physical address");
                }
                let writable = (pte >> 1) & 0x1;
                let user = (pte >> 2) & 0x1;
                println!(
                    "  ✓ Last page VA 0x{:x} -> PA 0x{:x} (W={} U={})",
                    last_page_va, mapped_pa_clean, writable, user
                );
            }
            Err(e) => {
                println!("  ✗ Last page VA 0x{:x}: {}", last_page_va, e);
                return Err(e);
            }
        }

        // If this is a writable stack mapping (growing down), verify the address that push will access
        // Stack top points to first byte AFTER mapped region, push decrements by 8 first
        let range_end = user_virt_start + size;
        if writable && range_end & 0xFFF == 0 {
            // Page-aligned end on a writable region - likely a stack top
            let first_push_addr = (range_end - 8) as u64;
            println!(
                "  Checking stack-like mapping: will verify first push address 0x{:x}",
                first_push_addr
            );

            match walk_pt_with_flags(user_cr3, first_push_addr) {
                Ok((mapped_pa, pte)) => {
                    let pa_clean = mapped_pa & 0x000F_FFFF_FFFF_F000;
                    let present = pte & 0x1;
                    let writable_flag = (pte >> 1) & 0x1;
                    let user = (pte >> 2) & 0x1;
                    println!(
                        "  ✓ First push address 0x{:x} -> PA 0x{:x}",
                        first_push_addr, pa_clean
                    );
                    println!(
                        "    PTE flags: P={} W={} U={}",
                        present, writable_flag, user
                    );

                    if writable_flag == 0 {
                        println!("  ✗ ERROR: Page is NOT WRITABLE! Push will fault!");
                        return Err("Stack page is read-only");
                    }
                }
                Err(e) => {
                    println!("  ✗ First push address 0x{:x}: {}", first_push_addr, e);
                    println!("  This means stack push will page fault!");
                    return Err("First push address not mapped");
                }
            }
        }

        // Sample other pages
        for page_offset in (0..size).step_by(4096) {
            let va = (user_virt_start + page_offset) as u64;

            // Skip first and last page since we already checked them
            if va == first_va || (va & !0xFFF) == last_page_va {
                continue;
            }

            let expected_kva = (kernel_virt_start + page_offset) as u64;
            let expected_pa = virt_to_phys(expected_kva)
                .ok_or("Failed to get PA for kernel page")?
                & 0x000F_FFFF_FFFF_F000;

            match walk_pt(user_cr3, va) {
                Ok(mapped_pa) => {
                    let mapped_pa_clean = mapped_pa & 0x000F_FFFF_FFFF_F000;
                    if mapped_pa_clean != expected_pa {
                        println!(
                            "  ✗ VA 0x{:x}: mapped to PA 0x{:x}, expected 0x{:x}",
                            va, mapped_pa_clean, expected_pa
                        );
                        return Err("Page mapped to wrong physical address");
                    }
                    if page_offset % (16 * 4096) == 0 {
                        println!("  ✓ VA 0x{:x} -> PA 0x{:x}", va, mapped_pa_clean);
                    }
                }
                Err(e) => {
                    println!("  ✗ VA 0x{:x}: {}", va, e);
                    return Err(e);
                }
            }
        }
        println!("  ✓ All pages verified!");

        Ok(())
    }

    /// Get the PML4 physical address (for loading into CR3)
    pub fn get_cr3(&self) -> u64 {
        self.p4_pa
    }

    /// Get the aligned portion of guest memory (internal helper)
    fn get_aligned_mem(&self) -> &[u8] {
        let start = self.guest_mem_aligned_offset;
        &self.guest_mem[start..]
    }

    /// Get the aligned portion of guest memory as mutable (internal helper)
    fn get_aligned_mem_mut(&mut self) -> &mut [u8] {
        let start = self.guest_mem_aligned_offset;
        &mut self.guest_mem[start..]
    }

    /// Get a pointer to the guest memory (for copying user code/data)
    pub fn get_guest_mem_mut(&mut self) -> &mut [u8] {
        self.get_aligned_mem_mut()
    }

    /// Get the address where interrupt handler code should be copied
    pub fn get_interrupt_handler_code_address(&self) -> usize {
        self.interrupt_handler_code_offset
    }

    /// Get the GDT address in guest memory
    pub fn get_gdt_address(&self) -> usize {
        self.gdt_offset
    }

    /// Get the TSS address in guest memory
    pub fn get_tss_address(&self) -> usize {
        self.tss_offset
    }

    /// Get the IDT address in guest memory
    pub fn get_idt_address(&self) -> usize {
        self.idt_offset
    }

    /// Get the interrupt stack top address (for TSS RSP0)
    /// NOTE: This is in guest_mem, but for user→kernel transitions,
    /// TSS.RSP0 should point to kernel stack instead!
    pub fn get_interrupt_stack_top(&self) -> usize {
        self.interrupt_stack_offset + (4 << PAGE_SHIFT) // Top of 4-page stack
    }

    /// Get the User Virtual Address of the GDT
    pub fn get_gdt_uva(&self) -> usize {
        let aligned_start = self.interrupt_start & !(PAGE_SIZE - 1);
        self.interrupt_virt_base + (self.gdt_offset - aligned_start)
    }

    /// Get the User Virtual Address of the IDT
    pub fn get_idt_uva(&self) -> usize {
        let aligned_start = self.interrupt_start & !(PAGE_SIZE - 1);
        self.interrupt_virt_base + (self.idt_offset - aligned_start)
    }

    /// Get the User Virtual Address of the TSS
    pub fn get_tss_uva(&self) -> usize {
        let aligned_start = self.interrupt_start & !(PAGE_SIZE - 1);
        self.interrupt_virt_base + (self.tss_offset - aligned_start)
    }

    /// Get the user virtual address where interrupt structures are mapped
    /// User code/stack must stay below this address
    pub fn get_interrupt_virt_base(&self) -> usize {
        self.interrupt_virt_base
    }

    /// Convert buffer offset to user virtual address for interrupt structures
    /// Since interrupt structures are in first 64MB: buffer offset = virtual address!
    fn offset_to_user_virt(&self, offset: usize) -> usize {
        // For first 64MB of buffer, offset IS the virtual address
        offset
    }

    /// Map interrupt infrastructure into user page tables
    /// This makes GDT/TSS/IDT/handlers accessible when user CR3 is loaded
    ///
    /// Maps only interrupt structures (NOT page tables for security)
    /// Split into executable (handler code) and non-executable (rest)
    pub unsafe fn map_interrupt_infrastructure(&mut self) -> Result<(), &'static str> {
        println!("\n=== Mapping Interrupt Infrastructure ===");

        // Calculate layout variables
        let interrupt_handler_code_offset = self.interrupt_handler_code_offset;
        let handler_code_end = interrupt_handler_code_offset + PAGE_SIZE;
        let interrupt_stack_offset = self.interrupt_stack_offset;

        // Interrupt structures end where page tables begin
        // In 'new': stack_start = page_tables_start
        let interrupt_structures_end = self.stack_start;

        // Get the base address of guest memory to calculate kernel virtual addresses
        // We use unsafe to get the pointer without holding a mutable borrow, allowing us to call methods
        let guest_mem_base_kva =
            unsafe { self.guest_mem.as_ptr().add(self.guest_mem_aligned_offset) as usize };

        println!("  Guest Mem Base KVA: 0x{:x}", guest_mem_base_kva);

        // Map 1: Handler Code (EXECUTABLE/READ/KERNEL)
        // map_user_range(writable=false, kernel_accessible=true) -> PDE64_PRESENT (Ring 0 RX)
        println!(
            "  Mapping handler code: 0x{:x} - 0x{:x} (EXECUTABLE/READ/KERNEL)",
            interrupt_handler_code_offset, handler_code_end
        );
        self.map_user_range(
            interrupt_handler_code_offset,                      // User Virt
            guest_mem_base_kva + interrupt_handler_code_offset, // Kernel Virt (Source)
            PAGE_SIZE,                                          // Size
            false,                                              // Writable? No
            true, // Kernel accessible (no User bit)? Yes
        )?;

        // Map 2: GDT/TSS/IDT (READ-ONLY/KERNEL)
        // Range: from handler code end (start of RO page) to interrupt stack start
        if handler_code_end < interrupt_stack_offset {
            println!(
                "  Mapping GDT/TSS/IDT: 0x{:x} - 0x{:x} (READ/WRITE/KERNEL)",
                handler_code_end, interrupt_stack_offset
            );
            self.map_user_range(
                handler_code_end,
                guest_mem_base_kva + handler_code_end,
                interrupt_stack_offset - handler_code_end,
                true, // Writable? Yes (Required for ltr to set Busy bit in GDT)
                true, // Kernel only? Yes
            )?;
        }

        // Map 3: Interrupt Stack (READ-WRITE/KERNEL)
        // Range: from interrupt stack start to end of interrupt structures
        if interrupt_stack_offset < interrupt_structures_end {
            println!(
                "  Mapping Interrupt Stack: 0x{:x} - 0x{:x} (READ/WRITE/KERNEL)",
                interrupt_stack_offset, interrupt_structures_end
            );
            self.map_user_range(
                interrupt_stack_offset,
                guest_mem_base_kva + interrupt_stack_offset,
                interrupt_structures_end - interrupt_stack_offset,
                true, // Writable? Yes
                true, // Kernel only? Yes
            )?;
        }

        println!("✓ Interrupt infrastructure mapped (via map_user_range)");
        Ok(())
    }

    /// Map trampolines into user page tables at high address (~2TB, below VMA region)
    ///
    /// Maps 2 pages at a high virtual address (same as kernel mapping) to allow
    /// CR3 switching without breaking instruction fetching.
    ///
    /// # Arguments
    /// * `trampoline_va_base` - Virtual address where trampolines should be mapped (e.g., 0x1FFF_FFFF_E000)
    /// * `trampoline_pa1` - Physical address of first trampoline page
    /// * `trampoline_pa2` - Physical address of second trampoline page
    pub fn map_trampolines(
        &mut self,
        trampoline_va_base: u64,
        trampoline_pa1: u64,
        trampoline_pa2: u64,
    ) -> Result<(), &'static str> {
        println!("\n=== Mapping Trampolines in User Page Tables ===");
        println!("  VA base:  0x{:016x}", trampoline_va_base);
        println!("  PA page1: 0x{:016x}", trampoline_pa1);
        println!("  PA page2: 0x{:016x}", trampoline_pa2);

        // Calculate page table indices for trampoline VA
        // VA structure: [PML4:9][PDPT:9][PD:9][PT:9][offset:12]
        let pml4_idx = (trampoline_va_base >> 39) & 0x1FF;
        let pdpt_idx = (trampoline_va_base >> 30) & 0x1FF;
        let pd_idx = (trampoline_va_base >> 21) & 0x1FF;
        let pt_idx = (trampoline_va_base >> 12) & 0x1FF;

        println!(
            "  Indices: PML4[{}] -> PDPT[{}] -> PD[{}] -> PT[{}]",
            pml4_idx, pdpt_idx, pd_idx, pt_idx
        );

        // Use pre-validated physical addresses from struct (calculated during init)
        let tramp_p3_pa = self.trampoline_p3_pa;
        let tramp_p2_pa = self.trampoline_p2_pa;
        let tramp_p1_pa = self.trampoline_p1_pa;

        println!("  Trampoline page table physical addresses (pre-validated):");
        println!("    P3 PA: 0x{:016x}", tramp_p3_pa);
        println!("    P2 PA: 0x{:016x}", tramp_p2_pa);
        println!("    P1 PA: 0x{:016x}", tramp_p1_pa);

        // Extract offsets before mut borrow
        let p4_offset = self.p4_offset;
        let p4_pa = self.p4_pa;
        let trampoline_p3_offset = self.trampoline_p3_offset;
        let trampoline_p2_offset = self.trampoline_p2_offset;
        let trampoline_p1_offset = self.trampoline_p1_offset;

        // Get aligned memory for modifications
        let guest_mem = self.get_aligned_mem_mut();
        let guest_mem_base_kva = guest_mem.as_ptr() as u64;

        // Step 1: Update P4 to point to trampoline P3
        // NOTE: Use kernel-accessible flags (no U bit) since we access trampolines at CPL=0
        let kernel_accessible_flags = PDE64_PRESENT | PDE64_RW; // No PDE64_USER bit
        {
            let (_, p4_raw) = guest_mem.split_at_mut(p4_offset);
            let p4_table = u8_slice_to_u64_slice(&mut p4_raw[0..PAGE_SIZE]);

            p4_table[pml4_idx as usize] = kernel_accessible_flags | tramp_p3_pa;
            println!(
                "  Set P4[{}] = 0x{:016x}",
                pml4_idx, p4_table[pml4_idx as usize]
            );

            // Debug: Read back directly from guest_mem to verify
            let p4_entry_offset = p4_offset + (pml4_idx as usize * 8);
            let readback = u64::from_le_bytes([
                guest_mem[p4_entry_offset],
                guest_mem[p4_entry_offset + 1],
                guest_mem[p4_entry_offset + 2],
                guest_mem[p4_entry_offset + 3],
                guest_mem[p4_entry_offset + 4],
                guest_mem[p4_entry_offset + 5],
                guest_mem[p4_entry_offset + 6],
                guest_mem[p4_entry_offset + 7],
            ]);
            println!(
                "  DEBUG: Read back from guest_mem[0x{:x}] = 0x{:016x}",
                p4_entry_offset, readback
            );

            // Extra debug: What physical address does this guest_mem location map to?
            let entry_kva = guest_mem_base_kva + p4_entry_offset as u64;
            if let Some(entry_pa) = unsafe { virt_to_phys(entry_kva) } {
                let entry_pa_clean = entry_pa & 0x000F_FFFF_FFFF_F000;
                let offset_in_page = (p4_entry_offset & 0xFFF) as u64;
                println!(
                    "  DEBUG: guest_mem[0x{:x}] KVA: 0x{:016x}",
                    p4_entry_offset, entry_kva
                );
                println!(
                    "  DEBUG: Maps to PA: 0x{:016x} + 0x{:x} = 0x{:016x}",
                    entry_pa_clean,
                    offset_in_page,
                    entry_pa_clean + offset_in_page
                );
                println!(
                    "  DEBUG: CR3 expects P4[63] at: 0x{:016x} + 0x1f8 = 0x{:016x}",
                    p4_pa,
                    p4_pa + 0x1f8
                );
            }
        }

        // Step 2: Set P3 to point to P2
        {
            let (_, tramp_p3_raw) = guest_mem.split_at_mut(trampoline_p3_offset);
            let tramp_p3 = u8_slice_to_u64_slice(&mut tramp_p3_raw[0..PAGE_SIZE]);

            tramp_p3[pdpt_idx as usize] = PDE64_ALL_ALLOWED | tramp_p2_pa;
            println!(
                "  Set P3[{}] = 0x{:016x}",
                pdpt_idx, tramp_p3[pdpt_idx as usize]
            );

            // Debug: Read back directly from guest_mem
            let p3_entry_offset = trampoline_p3_offset + (pdpt_idx as usize * 8);
            let readback = u64::from_le_bytes([
                guest_mem[p3_entry_offset],
                guest_mem[p3_entry_offset + 1],
                guest_mem[p3_entry_offset + 2],
                guest_mem[p3_entry_offset + 3],
                guest_mem[p3_entry_offset + 4],
                guest_mem[p3_entry_offset + 5],
                guest_mem[p3_entry_offset + 6],
                guest_mem[p3_entry_offset + 7],
            ]);
            println!(
                "  DEBUG: Read back from guest_mem[0x{:x}] = 0x{:016x}",
                p3_entry_offset, readback
            );
        }

        // Step 3: Set P2 to point to P1
        {
            let (_, tramp_p2_raw) = guest_mem.split_at_mut(trampoline_p2_offset);
            let tramp_p2 = u8_slice_to_u64_slice(&mut tramp_p2_raw[0..PAGE_SIZE]);

            tramp_p2[pd_idx as usize] = PDE64_ALL_ALLOWED | tramp_p1_pa;
            println!(
                "  Set P2[{}] = 0x{:016x}",
                pd_idx, tramp_p2[pd_idx as usize]
            );

            // Debug: Read back directly from guest_mem
            let p2_entry_offset = trampoline_p2_offset + (pd_idx as usize * 8);
            let readback = u64::from_le_bytes([
                guest_mem[p2_entry_offset],
                guest_mem[p2_entry_offset + 1],
                guest_mem[p2_entry_offset + 2],
                guest_mem[p2_entry_offset + 3],
                guest_mem[p2_entry_offset + 4],
                guest_mem[p2_entry_offset + 5],
                guest_mem[p2_entry_offset + 6],
                guest_mem[p2_entry_offset + 7],
            ]);
            println!(
                "  DEBUG: Read back from guest_mem[0x{:x}] = 0x{:016x}",
                p2_entry_offset, readback
            );
        }

        // Step 4: Set P1 entries to point to actual trampoline physical pages
        {
            let (_, tramp_p1_raw) = guest_mem.split_at_mut(trampoline_p1_offset);
            let tramp_p1 = u8_slice_to_u64_slice(&mut tramp_p1_raw[0..PAGE_SIZE]);

            // Validate input physical addresses are page-aligned
            const PAGE_MASK: u64 = (PAGE_SIZE - 1) as u64;
            if trampoline_pa1 & PAGE_MASK != 0 {
                return Err("trampoline_pa1 is not page-aligned!");
            }
            if trampoline_pa2 & PAGE_MASK != 0 {
                return Err("trampoline_pa2 is not page-aligned!");
            }

            // Map first trampoline page
            // Use kernel-mode flags (no USER bit) since trampoline runs at CPL=0
            tramp_p1[pt_idx as usize] = (PDE64_PRESENT | PDE64_RW) | trampoline_pa1;
            println!(
                "  Set P1[{}] = 0x{:016x} (trampoline page 1)",
                pt_idx, tramp_p1[pt_idx as usize]
            );

            // Map second trampoline page (next PT entry)
            tramp_p1[(pt_idx + 1) as usize] = (PDE64_PRESENT | PDE64_RW) | trampoline_pa2;
            println!(
                "  Set P1[{}] = 0x{:016x} (trampoline page 2)",
                pt_idx + 1,
                tramp_p1[(pt_idx + 1) as usize]
            );

            // Debug: Read back both entries directly from guest_mem
            let p1_entry1_offset = trampoline_p1_offset + (pt_idx as usize * 8);
            let readback1 = u64::from_le_bytes([
                guest_mem[p1_entry1_offset],
                guest_mem[p1_entry1_offset + 1],
                guest_mem[p1_entry1_offset + 2],
                guest_mem[p1_entry1_offset + 3],
                guest_mem[p1_entry1_offset + 4],
                guest_mem[p1_entry1_offset + 5],
                guest_mem[p1_entry1_offset + 6],
                guest_mem[p1_entry1_offset + 7],
            ]);
            println!(
                "  DEBUG: Read back P1[{}] from guest_mem[0x{:x}] = 0x{:016x}",
                pt_idx, p1_entry1_offset, readback1
            );

            let p1_entry2_offset = trampoline_p1_offset + ((pt_idx + 1) as usize * 8);
            let readback2 = u64::from_le_bytes([
                guest_mem[p1_entry2_offset],
                guest_mem[p1_entry2_offset + 1],
                guest_mem[p1_entry2_offset + 2],
                guest_mem[p1_entry2_offset + 3],
                guest_mem[p1_entry2_offset + 4],
                guest_mem[p1_entry2_offset + 5],
                guest_mem[p1_entry2_offset + 6],
                guest_mem[p1_entry2_offset + 7],
            ]);
            println!(
                "  DEBUG: Read back P1[{}] from guest_mem[0x{:x}] = 0x{:016x}",
                pt_idx + 1,
                p1_entry2_offset,
                readback2
            );
        }

        // Ensure all writes are visible to other cores/reads via direct map
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        println!("✓ Trampolines mapped in user page tables");
        Ok(())
    }

    /// Setup GDT in guest memory
    /// Returns the virtual address where GDT was placed
    pub fn setup_gdt(&mut self) -> Result<usize, &'static str> {
        println!("Setting up GDT at 0x{:x}", self.gdt_offset);

        let gdt_offset = self.gdt_offset;
        let aligned_mem = self.get_aligned_mem_mut();
        let gdt_slice = &mut aligned_mem[gdt_offset..gdt_offset + 80];

        // Helper to write a segment descriptor (8 bytes)
        let write_segment = |dest: &mut [u8], privilege_level: u8, segment_type: u8| {
            // segment_type: 10 (0xA) = code, 2 = data
            // Code segment: executable, readable
            // Data segment: writable
            let descriptor_type = 1; // 1 for code/data
            let code_64_bit = 1; // 64-bit mode

            dest[0] = 0xFF; // Limit low
            dest[1] = 0xFF; // Limit high
            dest[2..4].fill(0); // Base low (unused in 64-bit)
            dest[4] = 0; // Base mid
            dest[5] = (1 << 7) | (privilege_level << 5) | (descriptor_type << 4) | segment_type;
            dest[6] = (1 << 7) | ((code_64_bit as u8) << 5) | 0xF; // Granularity + 64-bit + limit high
            dest[7] = 0; // Base high
        };

        // Entry 0: Null descriptor
        gdt_slice[0..8].fill(0);

        // Entry 1 (0x08): Kernel code segment (ring 0, executable)
        write_segment(&mut gdt_slice[8..16], 0, 0xA);

        // Entry 2 (0x10): Kernel data segment (ring 0, writable)
        write_segment(&mut gdt_slice[16..24], 0, 0x2);

        // Entry 3 (0x18): User code segment (ring 3, executable)
        write_segment(&mut gdt_slice[24..32], 3, 0xA);

        // Entry 4 (0x20): User data segment (ring 3, writable)
        write_segment(&mut gdt_slice[32..40], 3, 0x2);

        // Entry 5/6 (0x28-0x2F): TSS descriptor (16 bytes, filled by setup_tss)
        gdt_slice[40..56].fill(0);

        println!("✓ GDT configured (80 bytes)");
        Ok(self.gdt_offset)
    }

    /// Setup TSS in guest memory
    ///
    /// # Arguments
    /// * `kernel_stack_top` - Physical/kernel virtual address for RSP0 (used for ring 3→0 transition)
    ///
    /// Returns the virtual address where TSS was placed
    pub fn setup_tss(&mut self, kernel_stack_top: u64) -> Result<usize, &'static str> {
        println!(
            "Setting up TSS at 0x{:x}, RSP0=0x{:x}",
            self.tss_offset, kernel_stack_top
        );
        // Calculate IST1 value before borrowing guest_mem
        let ist1 = self.get_interrupt_stack_top() as u64;
        // Clear TSS area (104 bytes)
        let tss_offset = self.tss_offset;
        let aligned_mem = self.get_aligned_mem_mut();
        let tss_slice = &mut aligned_mem[tss_offset..tss_offset + 104];
        tss_slice.fill(0);

        // TSS structure layout (x86_64):
        // 0x00: reserved (4 bytes)
        // 0x04: RSP0 (8 bytes) - stack for ring 0
        // 0x0C: RSP1 (8 bytes)
        // 0x14: RSP2 (8 bytes)
        // 0x1C: reserved (8 bytes)
        // 0x24: IST1-7 (7 × 8 bytes)
        // 0x5C: reserved (8 bytes)
        // 0x64: reserved (2 bytes)
        // 0x66: I/O map base (2 bytes)

        // Set RSP0 for privilege level transitions (ring 3 → ring 0)
        // We MUST use the interrupt stack (which is mapped in User Space) to avoid
        // a double fault when the CPU tries to push the interrupt frame.
        // The original kernel stack (kernel_stack_top) is likely not mapped in User CR3.
        tss_slice[4..12].copy_from_slice(&ist1.to_le_bytes());

        // Also set RSP1 and RSP2 to the same stack as a safety measure
        tss_slice[0x0C..0x14].copy_from_slice(&ist1.to_le_bytes()); // RSP1
        tss_slice[0x14..0x1C].copy_from_slice(&ist1.to_le_bytes()); // RSP2

        // Set ALL IST entries (IST1-IST7) to the same stack address as a safety measure.
        // IST entries are at offsets 0x24, 0x2C, 0x34, 0x3C, 0x44, 0x4C, 0x54
        // This ensures any interrupt using any IST will have a valid stack.
        for i in 0..7 {
            let offset = 0x24 + i * 8;
            tss_slice[offset..offset + 8].copy_from_slice(&ist1.to_le_bytes());
        }

        // Set I/O map base to TSS size (no I/O permission bitmap)
        tss_slice[0x66..0x68].copy_from_slice(&104u16.to_le_bytes());

        // Now update the TSS descriptor in the GDT
        // TSS descriptor is at GDT offset 0x28 (entry 5), 16 bytes
        let tss_limit = 103u64; // TSS size - 1

        // Get virtual address of TSS for the descriptor (User Virtual Address)
        // The GDT is loaded in User CR3, so the base address must be valid in that context
        let tss_base_addr = self.get_tss_uva() as u64;

        let gdt_offset = self.gdt_offset;
        let aligned_mem = self.get_aligned_mem_mut();
        let gdt_tss_desc = &mut aligned_mem[gdt_offset + 40..gdt_offset + 56];

        // Build TSS descriptor (16 bytes in 64-bit mode)
        // Low qword: limit[15:0] | base[15:0] | base[23:16] | type=0x89 | limit[19:16] | base[31:24]
        let low = (tss_limit & 0xFFFF)
            | ((tss_base_addr & 0xFFFF) << 16)
            | ((tss_base_addr & 0xFF0000) << 16)  // Base[16:23] at 32-39
            | (0x89u64 << 40)  // Type: Available 64-bit TSS (0x9), Present (0x8)
            | (((tss_limit >> 16) & 0xF) << 48)
            | ((tss_base_addr & 0xFF000000) << 32);

        // High qword: base[63:32] | reserved
        let high = tss_base_addr >> 32;

        gdt_tss_desc[0..8].copy_from_slice(&low.to_le_bytes());
        gdt_tss_desc[8..16].copy_from_slice(&high.to_le_bytes());

        println!("✓ TSS configured, descriptor updated in GDT");
        Ok(self.tss_offset)
    }

    /// Setup IDT in guest memory
    ///
    /// # Arguments
    /// * `handler_addresses` - Array of handler virtual addresses in guest_mem
    ///
    /// Returns the virtual address where IDT was placed
    pub fn setup_idt(&mut self, handler_addresses: &[u64; 33]) -> Result<usize, &'static str> {
        println!("Setting up IDT at 0x{:x}", self.idt_offset);

        let idt_offset = self.idt_offset;
        let aligned_mem = self.get_aligned_mem_mut();
        let idt_slice = &mut aligned_mem[idt_offset..idt_offset + 33 * 16];

        // Helper to write an IDT entry (16 bytes)
        let write_idt_entry = |dest: &mut [u8], handler_addr: u64, dpl: u8, ist: u8| {
            let addr_bytes = handler_addr.to_le_bytes();

            // Offset low (bits 0-15)
            dest[0] = addr_bytes[0];
            dest[1] = addr_bytes[1];

            // Segment selector (0x08 = kernel code segment)
            dest[2] = 0x08;
            dest[3] = 0x00;

            // IST (Interrupt Stack Table) - bits 0-2
            dest[4] = ist & 0x7;

            // Type and attributes:
            // Present (bit 7) | DPL (bits 5-6) | Type (bits 0-4)
            // Type: 0xE = interrupt gate (disables interrupts), 0xF = trap gate
            let gate_type = 0xE; // Interrupt gate
            dest[5] = 0x80 | ((dpl & 0x3) << 5) | gate_type;

            // Offset middle (bits 16-31)
            dest[6] = addr_bytes[2];
            dest[7] = addr_bytes[3];

            // Offset high (bits 32-63)
            dest[8] = addr_bytes[4];
            dest[9] = addr_bytes[5];
            dest[10] = addr_bytes[6];
            dest[11] = addr_bytes[7];

            // Reserved
            dest[12..16].fill(0);
        };

        // Setup all 33 IDT entries
        for i in 0..33 {
            let offset = i * 16;
            let handler_addr = handler_addresses[i];

            // DPL = 3 for INT 32 (user accessible), DPL = 0 for all others
            let dpl = if i == 32 { 3 } else { 0 };

            // Use IST 1 (Interrupt Stack) for ALL interrupts.
            // This allows us to use the specific interrupt stack set up in the TSS
            // and avoids the need for RSP0 (matching Dandelion's approach).
            let ist = 1;

            write_idt_entry(&mut idt_slice[offset..offset + 16], handler_addr, dpl, ist);

            // Print INT 32 entry details
            if i == 32 {
                println!(
                    "  IDT[32]: handler=0x{:x}, dpl={}, ist={}",
                    handler_addr, dpl, ist
                );
                println!(
                    "    Entry bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    idt_slice[offset],
                    idt_slice[offset + 1],
                    idt_slice[offset + 2],
                    idt_slice[offset + 3],
                    idt_slice[offset + 4],
                    idt_slice[offset + 5],
                    idt_slice[offset + 6],
                    idt_slice[offset + 7]
                );
                println!(
                    "                 {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    idt_slice[offset + 8],
                    idt_slice[offset + 9],
                    idt_slice[offset + 10],
                    idt_slice[offset + 11],
                    idt_slice[offset + 12],
                    idt_slice[offset + 13],
                    idt_slice[offset + 14],
                    idt_slice[offset + 15]
                );
            }
        }

        println!("✓ IDT configured (33 entries)");
        Ok(self.idt_offset)
    }

    /// Copy interrupt handler code to guest memory
    ///
    /// # Arguments
    /// * `handler_code` - Assembly code for fault handlers
    ///
    /// Returns the starting buffer offset of handlers
    pub fn install_handlers(&mut self, handler_code: &[u8]) -> Result<usize, &'static str> {
        if handler_code.len() > PAGE_SIZE {
            return Err("Handler code exceeds one page");
        }

        let handler_offset = self.interrupt_handler_code_offset;
        let aligned_mem = self.get_aligned_mem_mut();
        let dest = &mut aligned_mem[handler_offset..handler_offset + handler_code.len()];
        dest.copy_from_slice(handler_code);

        println!(
            "✓ Installed {} bytes of handler code at buffer offset 0x{:x}",
            handler_code.len(),
            self.interrupt_handler_code_offset
        );

        Ok(self.interrupt_handler_code_offset)
    }

    /// Calculate handler addresses as USER VIRTUAL ADDRESSES
    ///
    /// Takes the original handler addresses (from linking) and adjusts them
    /// to USER VIRTUAL ADDRESSES where they will be mapped in user space.
    ///
    /// # Arguments
    /// * `original_addresses` - Handler addresses as linked in kernel
    /// * `original_base` - Base address of handlers in original location
    ///
    /// Returns adjusted addresses as USER VIRTUAL ADDRESSES for IDT entries
    pub fn calculate_handler_addresses(
        &self,
        original_addresses: &[u64; 33],
        original_base: u64,
    ) -> [u64; 33] {
        // Calculate where handlers will be mapped in user space
        let handler_user_virt_base = self.offset_to_user_virt(self.interrupt_handler_code_offset);

        let mut adjusted = [0u64; 33];
        for i in 0..33 {
            // Calculate offset from original base
            let offset = original_addresses[i] - original_base;
            // Add offset to user virtual base (where they're mapped in user space)
            adjusted[i] = handler_user_virt_base as u64 + offset;
        }

        adjusted
    }

    /// Get interrupt configuration for loading into CPU
    ///
    /// # Arguments
    /// * `kernel_stack` - Kernel stack address for RSP0 (ring 3→0 transitions)
    pub fn get_interrupt_config(&self, kernel_stack: u64) -> InterruptConfig {
        InterruptConfig::from_user_space(self, kernel_stack)
    }

    /// Switch CR3 from user page tables back to kernel page tables
    ///
    /// # Safety
    /// Must be called from interrupt handler running at ring 0 with user CR3 loaded
    pub unsafe fn switch_to_kernel_cr3(kernel_cr3: u64) {
        use core::arch::asm;
        asm!("mov cr3, {}", in(reg) kernel_cr3, options(nostack, preserves_flags));
    }

    /// Setup all interrupt infrastructure in one call
    ///
    /// This is a convenience method that:
    /// 1. Installs handler code in guest_mem
    /// 2. Calculates adjusted handler addresses
    /// 3. Sets up GDT
    /// 4. Sets up TSS with kernel stack
    /// 5. Sets up IDT with handlers
    /// 6. Maps interrupt infrastructure in user page tables
    ///
    /// # Arguments
    /// * `handler_code` - Raw handler code bytes
    /// * `handler_addresses` - Original handler addresses (as linked)
    /// * `handler_base` - Base address of handlers in original location
    /// * `kernel_stack` - Kernel stack for TSS.RSP0
    ///
    /// # Returns
    /// InterruptConfig for loading into CPU
    pub unsafe fn setup_all_interrupt_infrastructure(
        &mut self,
        handler_code: &[u8],
        handler_addresses: &[u64; 33],
        handler_base: u64,
        kernel_stack: u64,
    ) -> Result<InterruptConfig, &'static str> {
        println!("\n=== Setting up interrupt infrastructure ===");

        // 1. Install handlers
        self.install_handlers(handler_code)?;

        // 2. Calculate adjusted addresses
        let adjusted_addresses = self.calculate_handler_addresses(handler_addresses, handler_base);
        println!("✓ Handler addresses adjusted for guest_mem");

        // 3. Setup GDT
        self.setup_gdt()?;

        // 4. Setup TSS
        self.setup_tss(kernel_stack)?;

        // 5. Setup IDT
        self.setup_idt(&adjusted_addresses)?;

        // 6. Map interrupt infrastructure
        self.map_interrupt_infrastructure()?;

        println!("=== Interrupt infrastructure ready ===\n");

        Ok(self.get_interrupt_config(kernel_stack))
    }

    /// Print statistics
    pub fn print_stats(&self) {
        println!("\n=== User Space Manager Summary ===");
        println!(
            "  Virtual address space:  0x0 - 0x{:x} ({} MB)",
            self.last_address,
            self.last_address >> 20
        );
        println!(
            "  Buffer size:            {} bytes ({} MB)",
            self.guest_mem.len(),
            self.guest_mem.len() >> 20
        );
        println!("  PML4 (CR3):             0x{:016x}", self.p4_pa);
        println!("\n  Memory layout:");
        println!(
            "    User space:           0x0 - 0x{:x} ({:.2} MB)",
            self.interrupt_start,
            self.interrupt_start as f64 / (1024.0 * 1024.0)
        );
        println!(
            "    Interrupt structures: 0x{:x} - 0x{:x}",
            self.interrupt_start, self.stack_start
        );
        println!(
            "      Handler code:       0x{:x}",
            self.interrupt_handler_code_offset
        );
        println!("      GDT:                0x{:x}", self.gdt_offset);
        println!("      TSS:                0x{:x}", self.tss_offset);
        println!("      IDT:                0x{:x}", self.idt_offset);
        println!(
            "      Int stack:          0x{:x} (top: 0x{:x})",
            self.interrupt_stack_offset,
            self.get_interrupt_stack_top()
        );
        println!(
            "    Page tables:          0x{:x} - 0x{:x}",
            self.stack_start, self.last_address
        );
    }
}
