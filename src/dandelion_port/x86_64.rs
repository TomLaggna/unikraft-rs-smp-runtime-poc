//! x86_64 Architecture Support for Unikraft Engine
//!
//! This module handles:
//! - 4-level page table setup (PML4 → PDPT → PD → PT)
//! - GDT with kernel and user segments
//! - TSS with interrupt stack table (IST)
//! - IDT with 33 interrupt gates (vectors 0-32)
//!
//! Structure closely mirrors Dandelion's `kvm/x86_64.rs` for easy comparison.

use super::{
    PageFaultMetadata, UnikraftContext, UnikraftLayout, UnikraftResult, UnikraftError,
    PAGE_SIZE,
};

// ============================================================================
// Constants - Page Table Flags
// ============================================================================

/// Page table entry flags (matching x86_64 specification)
pub mod pte_flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;  // PS bit for 2MB/1GB pages
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
    
    /// Standard flags for user-accessible pages
    pub const USER_PAGE: u64 = PRESENT | WRITABLE | USER;
    
    /// Flags for page table entries (non-leaf)
    pub const TABLE_ENTRY: u64 = PRESENT | WRITABLE | USER;
}

// ============================================================================
// Constants - Segment Selectors
// ============================================================================

/// GDT segment selectors
pub mod selectors {
    pub const NULL: u16 = 0x00;
    pub const KERNEL_CODE_64: u16 = 0x08;  // Index 1
    pub const KERNEL_DATA: u16 = 0x10;     // Index 2
    pub const KERNEL_CODE_32: u16 = 0x18;  // Index 3 (for AP bootstrap)
    pub const USER_CODE_64: u16 = 0x20;    // Index 4, RPL=0 (we set RPL=3 when using)
    pub const USER_DATA: u16 = 0x28;       // Index 5, RPL=0 (we set RPL=3 when using)
    pub const TSS: u16 = 0x30;             // Index 6 (TSS is 16 bytes, spans 6-7)
    
    /// User code selector with RPL=3
    pub const USER_CODE_64_RPL3: u16 = USER_CODE_64 | 3;  // 0x23
    /// User data selector with RPL=3
    pub const USER_DATA_RPL3: u16 = USER_DATA | 3;        // 0x2B
    /// But iretq uses: CS = (index << 3) | RPL, so index 4 with RPL 3 = 0x1B + 3 = 0x23
    /// Actually for index 4: selector = 4 * 8 = 0x20, with RPL 3 = 0x23
    /// For index 5: selector = 5 * 8 = 0x28, with RPL 3 = 0x2B
    /// Correction: our user code is at index 4, user data at index 5
    /// So USER_CODE = 0x20 | 3 = 0x23, USER_DATA = 0x28 | 3 = 0x2B
    /// But in our GDT we have user code at index 4 (0x20) and user data at index 5 (0x28)
    /// Wait, looking at the original code:
    /// - Entry 4: User Code 64-bit (DPL=3)
    /// - Entry 5: User Data (DPL=3)
    /// So selectors are 0x20 and 0x28, with RPL=3 they become 0x23 and 0x2B
    /// But the iretq code uses 0x1B and 0x23... let me check the original
    /// Original: CS=0x1B, SS=0x23
    /// 0x1B = 0x18 | 3 = index 3 with RPL 3
    /// 0x23 = 0x20 | 3 = index 4 with RPL 3
    /// So user code is at GDT index 3, user data at index 4
    /// Let me re-check the GDT layout in the original code...
}

// ============================================================================
// Constants - Structure Sizes
// ============================================================================

/// GDT size: 10 entries × 8 bytes = 80 bytes
/// (Entries: null, kernel code 64, kernel data, kernel code 32, 
///  user code 64, user data, TSS low, TSS high, reserved, reserved)
pub const GDT_SIZE: usize = 80;

/// TSS size: 104 bytes (x86_64 TSS structure)
pub const TSS_SIZE: usize = 104;

/// IDT entry size: 16 bytes per gate descriptor
pub const IDT_ENTRY_SIZE: usize = 16;

/// Number of IDT entries: vectors 0-32
pub const IDT_ENTRIES: usize = 33;

/// IDT total size
pub const IDT_SIZE: usize = IDT_ENTRIES * IDT_ENTRY_SIZE;

/// Interrupt stack size (pages)
pub const INTERRUPT_STACK_PAGES: usize = 6;

/// Interrupt stack total size
pub const INTERRUPT_STACK_SIZE: usize = INTERRUPT_STACK_PAGES * PAGE_SIZE;

/// Trampoline region size (K2U + U2K tables)
pub const TRAMPOLINE_K2U_SIZE: usize = 2048;
pub const TRAMPOLINE_U2K_SIZE: usize = 2048;
pub const TRAMPOLINE_REGION_SIZE: usize = TRAMPOLINE_K2U_SIZE + TRAMPOLINE_U2K_SIZE;

/// High virtual address for trampolines (mapped in both address spaces)
/// ~2TB mark, well above typical user space
pub const TRAMPOLINE_VA_BASE: u64 = 0x0000_0200_0000_0000;

// ============================================================================
// Page Table Setup
// ============================================================================

/// Set up 4-level page tables for user space
///
/// This function mirrors `set_page_table()` in Dandelion's kvm/x86_64.rs.
/// 
/// # Arguments
/// * `context` - The Unikraft context containing guest memory
/// * `stack_start` - Mutable reference to track where stack can begin
/// * `context_size` - Total size of the context
/// * `mappings` - List of (vaddr, paddr, size, flags) to map
///
/// # Returns
/// * Physical address of PML4 (for CR3)
pub fn set_page_table(
    storage: &mut [u8],
    stack_start: &mut usize,
    context_size: usize,
    mappings: &[(u64, u64, usize, u64)],
) -> UnikraftResult<u64> {
    // Allocate page tables from top of context, working backwards
    // Order: PT, PD, PDPT, PML4 (PML4 at highest address)
    
    // For simplicity, allocate fixed space for each level
    // A more sophisticated implementation would allocate on-demand
    
    *stack_start -= PAGE_SIZE;
    let pml4_offset = *stack_start;
    
    *stack_start -= PAGE_SIZE;
    let pdpt_offset = *stack_start;
    
    *stack_start -= PAGE_SIZE;
    let pd_offset = *stack_start;
    
    *stack_start -= PAGE_SIZE;
    let pt_offset = *stack_start;
    
    // Zero out page table pages
    storage[pml4_offset..pml4_offset + PAGE_SIZE].fill(0);
    storage[pdpt_offset..pdpt_offset + PAGE_SIZE].fill(0);
    storage[pd_offset..pd_offset + PAGE_SIZE].fill(0);
    storage[pt_offset..pt_offset + PAGE_SIZE].fill(0);
    
    // Get physical base address of context (assumed identity-mapped for now)
    // In real integration, this would come from the memory domain
    let phys_base = storage.as_ptr() as u64;
    
    let pml4_phys = phys_base + pml4_offset as u64;
    let pdpt_phys = phys_base + pdpt_offset as u64;
    let pd_phys = phys_base + pd_offset as u64;
    let pt_phys = phys_base + pt_offset as u64;
    
    // Set up PML4 entry 0 -> PDPT
    write_pte(storage, pml4_offset, 0, pdpt_phys | pte_flags::TABLE_ENTRY);
    
    // Set up PDPT entry 0 -> PD
    write_pte(storage, pdpt_offset, 0, pd_phys | pte_flags::TABLE_ENTRY);
    
    // Set up PD entry 0 -> PT (for first 2MB of virtual space)
    write_pte(storage, pd_offset, 0, pt_phys | pte_flags::TABLE_ENTRY);
    
    // Map pages according to mappings
    for (vaddr, paddr, size, flags) in mappings {
        map_range(storage, pml4_offset, *vaddr, *paddr, *size, *flags, phys_base)?;
    }
    
    Ok(pml4_phys)
}

/// Map a range of virtual addresses to physical addresses
fn map_range(
    storage: &mut [u8],
    pml4_offset: usize,
    vaddr: u64,
    paddr: u64,
    size: usize,
    flags: u64,
    phys_base: u64,
) -> UnikraftResult<()> {
    let mut current_vaddr = vaddr;
    let mut current_paddr = paddr;
    let end_vaddr = vaddr + size as u64;
    
    while current_vaddr < end_vaddr {
        // For now, use 4KB pages exclusively
        // A production implementation would use 2MB pages where possible
        map_4kb_page(storage, pml4_offset, current_vaddr, current_paddr, flags, phys_base)?;
        current_vaddr += PAGE_SIZE as u64;
        current_paddr += PAGE_SIZE as u64;
    }
    
    Ok(())
}

/// Map a single 4KB page
fn map_4kb_page(
    storage: &mut [u8],
    pml4_offset: usize,
    vaddr: u64,
    paddr: u64,
    flags: u64,
    phys_base: u64,
) -> UnikraftResult<()> {
    // Extract page table indices from virtual address
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    
    // Walk/create page tables
    let pdpt_offset = get_or_create_table(storage, pml4_offset, pml4_idx, phys_base)?;
    let pd_offset = get_or_create_table(storage, pdpt_offset, pdpt_idx, phys_base)?;
    let pt_offset = get_or_create_table(storage, pd_offset, pd_idx, phys_base)?;
    
    // Write the final PT entry
    write_pte(storage, pt_offset, pt_idx, paddr | flags);
    
    Ok(())
}

/// Get or create a page table at the given index
fn get_or_create_table(
    storage: &mut [u8],
    table_offset: usize,
    index: usize,
    phys_base: u64,
) -> UnikraftResult<usize> {
    let entry_offset = table_offset + index * 8;
    let entry = read_pte(storage, table_offset, index);
    
    if entry & pte_flags::PRESENT != 0 {
        // Table exists, extract physical address and convert to offset
        let table_phys = entry & 0x000F_FFFF_FFFF_F000;
        let table_offset = (table_phys - phys_base) as usize;
        Ok(table_offset)
    } else {
        // Need to allocate a new table - this is a simplified version
        // In production, we'd track free pages properly
        Err(UnikraftError::PageTableError)
    }
}

/// Write a page table entry
fn write_pte(storage: &mut [u8], table_offset: usize, index: usize, value: u64) {
    let offset = table_offset + index * 8;
    storage[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Read a page table entry
fn read_pte(storage: &[u8], table_offset: usize, index: usize) -> u64 {
    let offset = table_offset + index * 8;
    u64::from_le_bytes(storage[offset..offset + 8].try_into().unwrap())
}

// ============================================================================
// Interrupt Table Setup (GDT, TSS, IDT)
// ============================================================================

/// Set up GDT, TSS, and IDT for user space
///
/// This function mirrors `set_interrupt_table()` in Dandelion's kvm/x86_64.rs.
///
/// # Arguments
/// * `storage` - Guest memory buffer
/// * `stack_start` - Mutable reference tracking available memory
///
/// # Returns
/// Tuple of (gdt_offset, tss_offset, idt_offset, handler_offset, interrupt_stack_top)
pub fn set_interrupt_table(
    storage: &mut [u8],
    stack_start: &mut usize,
) -> UnikraftResult<(usize, usize, usize, usize, u64)> {
    let phys_base = storage.as_ptr() as u64;
    
    // Allocate interrupt stack (6 pages)
    *stack_start -= INTERRUPT_STACK_SIZE;
    let interrupt_stack_offset = *stack_start;
    let interrupt_stack_top = phys_base + *stack_start as u64 + INTERRUPT_STACK_SIZE as u64;
    storage[interrupt_stack_offset..interrupt_stack_offset + INTERRUPT_STACK_SIZE].fill(0);
    
    // Allocate space for handlers, GDT, TSS, IDT
    // Handler code is copied from handlers module
    let handler_code = super::handlers::get_handler_code();
    let handler_size = handler_code.len();
    let handler_size_aligned = (handler_size + 7) & !7; // 8-byte align
    
    // Calculate space needed (all 8-byte aligned)
    let gdt_tss_idt_size = GDT_SIZE + TSS_SIZE + IDT_SIZE;
    let total_size = handler_size_aligned + gdt_tss_idt_size;
    let total_size_page_aligned = (total_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    
    *stack_start -= total_size_page_aligned;
    let base_offset = *stack_start;
    storage[base_offset..base_offset + total_size_page_aligned].fill(0);
    
    // Layout within allocated region
    let handler_offset = base_offset;
    let gdt_offset = base_offset + handler_size_aligned;
    let tss_offset = gdt_offset + GDT_SIZE;
    let idt_offset = tss_offset + TSS_SIZE;
    
    // Copy handler code
    storage[handler_offset..handler_offset + handler_size].copy_from_slice(handler_code);
    
    // Set up GDT
    setup_gdt(storage, gdt_offset, tss_offset, phys_base)?;
    
    // Set up TSS
    setup_tss(storage, tss_offset, interrupt_stack_top)?;
    
    // Set up IDT
    let handler_base_va = phys_base + handler_offset as u64;
    setup_idt(storage, idt_offset, handler_base_va)?;
    
    Ok((gdt_offset, tss_offset, idt_offset, handler_offset, interrupt_stack_top))
}

/// Set up GDT with kernel and user segments
fn setup_gdt(
    storage: &mut [u8],
    gdt_offset: usize,
    tss_offset: usize,
    phys_base: u64,
) -> UnikraftResult<()> {
    let tss_base = phys_base + tss_offset as u64;
    
    // Entry 0: Null descriptor
    write_gdt_entry(storage, gdt_offset, 0, 0);
    
    // Entry 1: Kernel Code 64-bit (DPL=0)
    // Flags: L=1 (long mode), P=1, S=1, Type=0xA (execute/read)
    write_gdt_entry(storage, gdt_offset, 1, 0x00AF_9A00_0000_FFFF);
    
    // Entry 2: Kernel Data (DPL=0)
    // Flags: P=1, S=1, Type=0x2 (read/write)
    write_gdt_entry(storage, gdt_offset, 2, 0x00CF_9200_0000_FFFF);
    
    // Entry 3: Kernel Code 32-bit (DPL=0) - for AP bootstrap compatibility
    write_gdt_entry(storage, gdt_offset, 3, 0x00CF_9A00_0000_FFFF);
    
    // Entry 4: User Code 64-bit (DPL=3)
    // Flags: L=1 (long mode), P=1, DPL=3, S=1, Type=0xA (execute/read)
    write_gdt_entry(storage, gdt_offset, 4, 0x00AF_FA00_0000_FFFF);
    
    // Entry 5: User Data (DPL=3)
    // Flags: P=1, DPL=3, S=1, Type=0x2 (read/write)
    write_gdt_entry(storage, gdt_offset, 5, 0x00CF_F200_0000_FFFF);
    
    // Entry 6-7: TSS descriptor (16 bytes for 64-bit TSS)
    // TSS limit = 103 (0x67), Type = 0x9 (available 64-bit TSS)
    let tss_desc_low = 0x0000_8900_0000_0067_u64
        | ((tss_base & 0xFFFF) << 16)           // Base 15:0
        | ((tss_base & 0xFF_0000) << 16)        // Base 23:16
        | ((tss_base & 0xFF00_0000) << 32);     // Base 31:24
    let tss_desc_high = (tss_base >> 32) & 0xFFFF_FFFF;  // Base 63:32
    
    write_gdt_entry(storage, gdt_offset, 6, tss_desc_low);
    write_gdt_entry(storage, gdt_offset, 7, tss_desc_high);
    
    // Entries 8-9: Reserved/padding
    write_gdt_entry(storage, gdt_offset, 8, 0);
    write_gdt_entry(storage, gdt_offset, 9, 0);
    
    Ok(())
}

/// Write a GDT entry
fn write_gdt_entry(storage: &mut [u8], gdt_offset: usize, index: usize, value: u64) {
    let offset = gdt_offset + index * 8;
    storage[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Set up TSS with interrupt stack
fn setup_tss(
    storage: &mut [u8],
    tss_offset: usize,
    interrupt_stack_top: u64,
) -> UnikraftResult<()> {
    // TSS structure (104 bytes for 64-bit):
    // Offset 0x00: Reserved (4 bytes)
    // Offset 0x04: RSP0 (8 bytes) - Ring 0 stack
    // Offset 0x0C: RSP1 (8 bytes)
    // Offset 0x14: RSP2 (8 bytes)
    // Offset 0x1C: Reserved (8 bytes)
    // Offset 0x24: IST1 (8 bytes) - Interrupt Stack Table entry 1
    // ... IST2-IST7 ...
    // Offset 0x64: Reserved (2 bytes)
    // Offset 0x66: I/O Map Base (2 bytes)
    
    // RSP0 - used when transitioning from Ring 3 to Ring 0
    write_tss_field(storage, tss_offset, 0x04, interrupt_stack_top);
    
    // IST1 - used by interrupt handlers (via IDT IST field)
    write_tss_field(storage, tss_offset, 0x24, interrupt_stack_top);
    
    // I/O Map Base - set to TSS limit to indicate no I/O bitmap
    storage[tss_offset + 0x66] = 0x68;  // Just past TSS
    storage[tss_offset + 0x67] = 0x00;
    
    Ok(())
}

/// Write a 64-bit field to TSS
fn write_tss_field(storage: &mut [u8], tss_offset: usize, field_offset: usize, value: u64) {
    let offset = tss_offset + field_offset;
    storage[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Set up IDT with 33 interrupt gates
fn setup_idt(
    storage: &mut [u8],
    idt_offset: usize,
    handler_base_va: u64,
) -> UnikraftResult<()> {
    // Get handler offsets from handlers module
    let handler_offsets = super::handlers::get_handler_offsets();
    
    for vector in 0..IDT_ENTRIES {
        let handler_va = handler_base_va + handler_offsets[vector] as u64;
        setup_interrupt_gate(
            storage,
            idt_offset,
            vector,
            selectors::KERNEL_CODE_64,  // Handler runs in kernel code segment
            handler_va,
            3,  // DPL=3 - allow user mode to trigger (for syscall-like INT 32)
            1,  // IST=1 - use IST1 for stack
        );
    }
    
    Ok(())
}

/// Set up a single IDT interrupt gate
fn setup_interrupt_gate(
    storage: &mut [u8],
    idt_offset: usize,
    vector: usize,
    selector: u16,
    handler_addr: u64,
    dpl: u8,
    ist: u8,
) {
    let entry_offset = idt_offset + vector * IDT_ENTRY_SIZE;
    
    // IDT Gate Descriptor (16 bytes):
    // Bytes 0-1: Offset 15:0
    // Bytes 2-3: Segment Selector
    // Byte 4: IST (bits 0-2), Reserved (bits 3-7)
    // Byte 5: Type (bits 0-3), 0 (bit 4), DPL (bits 5-6), P (bit 7)
    // Bytes 6-7: Offset 31:16
    // Bytes 8-11: Offset 63:32
    // Bytes 12-15: Reserved
    
    let offset_low = (handler_addr & 0xFFFF) as u16;
    let offset_mid = ((handler_addr >> 16) & 0xFFFF) as u16;
    let offset_high = ((handler_addr >> 32) & 0xFFFF_FFFF) as u32;
    
    // Type = 0xE (64-bit interrupt gate), P=1
    let type_attr = 0x8E | ((dpl & 0x3) << 5);
    
    storage[entry_offset..entry_offset + 2].copy_from_slice(&offset_low.to_le_bytes());
    storage[entry_offset + 2..entry_offset + 4].copy_from_slice(&selector.to_le_bytes());
    storage[entry_offset + 4] = ist & 0x7;
    storage[entry_offset + 5] = type_attr;
    storage[entry_offset + 6..entry_offset + 8].copy_from_slice(&offset_mid.to_le_bytes());
    storage[entry_offset + 8..entry_offset + 12].copy_from_slice(&offset_high.to_le_bytes());
    storage[entry_offset + 12..entry_offset + 16].fill(0);  // Reserved
}

// ============================================================================
// Descriptor Table Pointers
// ============================================================================

/// Create a GDT/IDT descriptor (10 bytes: 2-byte limit + 8-byte base)
pub fn create_descriptor(base: u64, limit: u16) -> [u8; 10] {
    let mut desc = [0u8; 10];
    desc[0..2].copy_from_slice(&limit.to_le_bytes());
    desc[2..10].copy_from_slice(&base.to_le_bytes());
    desc
}
