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

/// Walk kernel page tables to translate virtual → physical
/// Unikraft uses a direct-map region starting at 0xffffff8000000000
unsafe fn virt_to_phys(virt_addr: u64) -> Option<u64> {
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
    // println!("  PML4[{}] = 0x{:016x}", pml4_idx, pml4_entry);
    if pml4_entry & 1 == 0 {
        println!("  PML4 entry not present!");
        return None;
    }

    // Walk PDPT
    let pdpt = (DIRECTMAP_START + (pml4_entry & !0xFFF)) as *const u64;
    let pdpt_entry = ptr::read_volatile(pdpt.add(pdpt_idx as usize));
    // println!("  PDPT[{}] = 0x{:016x}", pdpt_idx, pdpt_entry);
    if pdpt_entry & 1 == 0 {
        println!("  PDPT entry not present!");
        return None;
    }
    if pdpt_entry & (1 << 7) != 0 {
        // 1GB page
        return Some((pdpt_entry & !0x3FFFFFFF) + (virt_addr & 0x3FFFFFFF));
    }

    // Walk PD
    let pd = (DIRECTMAP_START + (pdpt_entry & !0xFFF)) as *const u64;
    let pd_entry = ptr::read_volatile(pd.add(pd_idx as usize));
    // println!("  PD[{}] = 0x{:016x}", pd_idx, pd_entry);
    if pd_entry & 1 == 0 {
        println!("  PD entry not present!");
        return None;
    }
    if pd_entry & (1 << 7) != 0 {
        // 2MB page
        return Some((pd_entry & !0x1FFFFF) + (virt_addr & 0x1FFFFF));
    }

    // Walk PT
    let pt = (DIRECTMAP_START + (pd_entry & !0xFFF)) as *const u64;
    let pt_entry = ptr::read_volatile(pt.add(pt_idx as usize));
    // println!("  PT[{}] = 0x{:016x}", pt_idx, pt_entry);
    if pt_entry & 1 == 0 {
        println!("  PT entry not present!");
        return None;
    }

    let result = (pt_entry & !0xFFF) + offset;
    // println!("  Result: phys=0x{:016x}", result);
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
        table_array[p1_offset..p1_offset + (current_page_entry % TABLE_SIZE)].fill(0);
    }

    while current_page_entry < past_last_page {
        let (p2_base, p2_entry) = get_p2(current_page_entry);
        let p1_offset = current_page_entry % TABLE_SIZE;

        // If starting a new p2 entry (aligned to 2MB boundary)
        if p1_offset == 0 {
            // If we can map the whole 2MB with a large page, do it
            if current_page_entry + TABLE_SIZE <= past_last_page {
                // Translate the virtual address for this 2MB page
                let page_offset = current_page_entry << PAGE_SHIFT;
                let kernel_virt = kernel_virt_start + page_offset;
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
        let page_offset = current_page_entry << PAGE_SHIFT;
        let kernel_virt = kernel_virt_start + page_offset;
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
        let last_index =
            current_page_entry + TABLE_SIZE * (1 + current_page_entry / (TABLE_SIZE * TABLE_SIZE));
        table_array[last_index..last_index.next_multiple_of(TABLE_SIZE)].fill(0);
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
    /// The entire "guest memory" buffer (owned)
    guest_mem: Vec<u8>,
    /// Size of the user-addressable space
    last_address: usize,
    /// Physical address of PML4 (for CR3)
    p4_phys: u64,
    /// Address where stack starts (points below reserved memory structures)
    stack_start: usize,
    /// Address where interrupt structures start (end of user-addressable space)
    interrupt_start: usize,
    /// Address where interrupt handler code page starts
    interrupt_handler_code: usize,
    /// Address of GDT in guest memory
    gdt_address: usize,
    /// Address of TSS in guest memory
    tss_address: usize,
    /// Address of IDT in guest memory
    idt_address: usize,
    /// Address where interrupt handler stack starts (for RSP0)
    interrupt_stack: usize,
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

        let last_address = user_space_size;

        // Constants for interrupt infrastructure (following Dandelion)
        const GDT_SIZE: usize = 80; // 10 entries × 8 bytes (null + 2 kernel + 2 user + TSS)
        const TSS_SIZE: usize = 104; // Standard TSS size
        const IDT_ENTRIES: usize = 33; // Entries 0-32
        const IDT_ENTRY_SIZE: usize = 16; // 16 bytes per entry in 64-bit mode
        const INTERRUPT_STACK_PAGES: usize = 4; // 16KB stack for interrupt handlers

        // Calculate page table space needed
        let p2_table_number = last_address.next_multiple_of(HUGE_PAGE) >> HUGE_PAGE_SHIFT;
        let p1_table_number = p2_table_number * TABLE_SIZE;
        let page_table_pages = 1 + 1 + p2_table_number + p1_table_number; // p4 + p3 + p2s + p1s
        let page_table_bytes = page_table_pages << PAGE_SHIFT;

        // Calculate interrupt infrastructure space (allocated from high addresses downward)
        let interrupt_handler_code_bytes = PAGE_SIZE; // 1 page for handler assembly
        let gdt_bytes = GDT_SIZE;
        let tss_bytes = TSS_SIZE;
        let idt_bytes = IDT_ENTRIES * IDT_ENTRY_SIZE;
        let interrupt_stack_bytes = INTERRUPT_STACK_PAGES << PAGE_SHIFT;

        // Total space for interrupt infrastructure (before page tables)
        let interrupt_total = interrupt_handler_code_bytes
            + gdt_bytes
            + tss_bytes
            + idt_bytes
            + interrupt_stack_bytes;

        // Allocate buffer: user space + interrupt infra + page tables + headroom
        let total_size = last_address + interrupt_total + page_table_bytes + (16 << PAGE_SHIFT);
        let mut guest_mem = vec![0u8; total_size];

        // CRITICAL: Force kernel to map all pages by touching each one
        // Vec allocation uses lazy/demand paging - pages aren't mapped until first access
        println!("Forcing kernel to map {} pages...", total_size / PAGE_SIZE);
        for page in 0..(total_size / PAGE_SIZE) {
            guest_mem[page * PAGE_SIZE] = 0;
        }
        println!("All pages now mapped in kernel page tables");

        // Allocate structures from high addresses working backwards
        let mut stack_start = total_size;

        // P4 table (PML4)
        stack_start -= PAGE_SIZE;
        let p4_address = stack_start;

        // P3 table (PDPT)
        stack_start -= PAGE_SIZE;
        let p3_address = stack_start;

        // P2+P1 tables
        stack_start -= (p2_table_number + p1_table_number) << PAGE_SHIFT;
        let table_base = stack_start;

        // Interrupt handler stack (RSP0 will point to top of this)
        stack_start -= interrupt_stack_bytes;
        let interrupt_stack = stack_start;

        // IDT (aligned to 8-byte boundary for cache efficiency)
        stack_start -= idt_bytes;
        let idt_address = stack_start;

        // TSS
        stack_start -= tss_bytes;
        let tss_address = stack_start;

        // GDT
        stack_start -= gdt_bytes;
        let gdt_address = stack_start;

        // Interrupt handler code page
        stack_start -= interrupt_handler_code_bytes;
        let interrupt_handler_code = stack_start;
        let interrupt_start = interrupt_handler_code;

        println!("\nUser space memory layout:");
        println!(
            "  User address space:      0x{:x} - 0x{:x}",
            0, last_address
        );
        println!(
            "  Interrupt structures:    0x{:x} - 0x{:x}",
            interrupt_start,
            interrupt_start + interrupt_total
        );
        println!(
            "    Handler code:          0x{:x} (1 page)",
            interrupt_handler_code
        );
        println!(
            "    GDT:                   0x{:x} ({} bytes)",
            gdt_address, gdt_bytes
        );
        println!(
            "    TSS:                   0x{:x} ({} bytes)",
            tss_address, tss_bytes
        );
        println!(
            "    IDT:                   0x{:x} ({} bytes)",
            idt_address, idt_bytes
        );
        println!(
            "    Interrupt stack:       0x{:x} ({} pages)",
            interrupt_stack, INTERRUPT_STACK_PAGES
        );
        println!(
            "  Page tables:             0x{:x} - 0x{:x}",
            table_base, stack_start
        );
        println!("  Buffer end:              0x{:x}\n", total_size);

        // Get physical addresses by translating each page table's virtual address
        let guest_mem_base_virt = guest_mem.as_ptr() as u64;

        println!("Guest mem base virt: 0x{:016x}", guest_mem_base_virt);
        println!("P4 offset in buffer: 0x{:x}", p4_address);

        let p4_virt = guest_mem_base_virt + p4_address as u64;
        println!("P4 virt: 0x{:016x}", p4_virt);

        let p4_phys =
            virt_to_phys(p4_virt).ok_or("Failed to translate P4 virtual address to physical")?;

        let p3_virt = guest_mem_base_virt + p3_address as u64;
        let p3_phys =
            virt_to_phys(p3_virt).ok_or("Failed to translate P3 virtual address to physical")?;

        let table_base_virt = guest_mem_base_virt + table_base as u64;

        // Set up P4 table
        {
            let (_, p4_raw) = guest_mem.split_at_mut(p4_address);
            let p4_table = u8_slice_to_u64_slice(&mut p4_raw[0..PAGE_SIZE]);
            p4_table.fill(0);

            // P4[0] points to P3
            p4_table[0] = PDE64_ALL_ALLOWED | p3_phys;
        }

        // Set up P3 table
        {
            let (_, p3_raw) = guest_mem.split_at_mut(p3_address);
            let p3_table = u8_slice_to_u64_slice(&mut p3_raw[0..PAGE_SIZE]);
            p3_table.fill(0);

            // P3 entries point to P2 tables - translate each P2 table's address
            for p3_entry in 0..p2_table_number {
                let p2_offset = p3_entry * (TABLE_SIZE + 1) * PAGE_SIZE;
                let p2_virt = table_base_virt + p2_offset as u64;
                let p2_phys = virt_to_phys(p2_virt)
                    .ok_or("Failed to translate P2 table virtual address to physical")?;
                p3_table[p3_entry] = PDE64_ALL_ALLOWED | p2_phys;
            }
        }

        // Initialize P2 and P1 tables
        {
            let (_, table_raw) = guest_mem.split_at_mut(table_base);
            let table_array_len = (p2_table_number + p1_table_number) << PAGE_SHIFT;
            let table_array = u8_slice_to_u64_slice(&mut table_raw[0..table_array_len]);

            // Zero out all P2 tables (P1 tables will be set up as needed by set_range)
            for p3_entry in 0..p2_table_number {
                let start_index = p3_entry * (TABLE_SIZE + 1) * TABLE_SIZE;
                table_array[start_index..start_index + TABLE_SIZE].fill(0);
            }
        }

        Ok(Self {
            guest_mem,
            last_address,
            p4_phys,
            stack_start: interrupt_start, // Points to start of reserved memory
            interrupt_start,
            interrupt_handler_code,
            gdt_address,
            tss_address,
            idt_address,
            interrupt_stack,
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
    ) -> Result<(), &'static str> {
        if user_virt_start + size > self.last_address {
            return Err("Mapping extends beyond user address space");
        }

        // Calculate protection flags
        let protection_flags = if writable {
            PDE64_ALL_ALLOWED
        } else {
            PDE64_PRESENT | PDE64_USER // Read-only
        };

        // Get access to page tables
        let guest_mem_base_virt = self.guest_mem.as_ptr() as u64;

        let p2_table_number = self.last_address.next_multiple_of(HUGE_PAGE) >> HUGE_PAGE_SHIFT;
        let p1_table_number = p2_table_number * TABLE_SIZE;
        let table_base = self.stack_start - ((p2_table_number + p1_table_number) << PAGE_SHIFT);
        let table_base_virt = guest_mem_base_virt + table_base as u64;

        let (_, table_raw) = self.guest_mem.split_at_mut(table_base);
        let table_array_len = (p2_table_number + p1_table_number) << PAGE_SHIFT;
        let table_array = u8_slice_to_u64_slice(&mut table_raw[0..table_array_len]);

        // Use set_range to map the pages - pass table_base_virt for translation
        set_range(
            table_array,
            table_base_virt,
            user_virt_start,
            user_virt_start + size,
            protection_flags,
            kernel_virt_start,
            0, // TODO: Track previous_past_last_page for multiple calls
        )?;

        Ok(())
    }

    /// Get the PML4 physical address (for loading into CR3)
    pub fn get_cr3(&self) -> u64 {
        self.p4_phys
    }

    /// Get a pointer to the guest memory (for copying user code/data)
    pub fn get_guest_mem_mut(&mut self) -> &mut [u8] {
        &mut self.guest_mem
    }

    /// Get the address where interrupt handler code should be copied
    pub fn get_interrupt_handler_code_address(&self) -> usize {
        self.interrupt_handler_code
    }

    /// Get the GDT address in guest memory
    pub fn get_gdt_address(&self) -> usize {
        self.gdt_address
    }

    /// Get the TSS address in guest memory
    pub fn get_tss_address(&self) -> usize {
        self.tss_address
    }

    /// Get the IDT address in guest memory
    pub fn get_idt_address(&self) -> usize {
        self.idt_address
    }

    /// Get the interrupt stack top address (for TSS RSP0)
    pub fn get_interrupt_stack_top(&self) -> usize {
        self.interrupt_stack + (4 << PAGE_SHIFT) // Top of 4-page stack
    }

    /// Print statistics
    pub fn print_stats(&self) {
        println!("User Space Manager:");
        println!("  User address space: 0x0 - 0x{:x}", self.last_address);
        println!("  Guest mem buffer: {} bytes", self.guest_mem.len());
        println!("  PML4 (CR3): 0x{:016x}", self.p4_phys);
        println!("  Stack start (reserved memory): 0x{:x}", self.stack_start);
        println!("  Interrupt structures start: 0x{:x}", self.interrupt_start);
        println!("    Handler code:   0x{:x}", self.interrupt_handler_code);
        println!("    GDT:            0x{:x}", self.gdt_address);
        println!("    TSS:            0x{:x}", self.tss_address);
        println!("    IDT:            0x{:x}", self.idt_address);
        println!("    Int stack top:  0x{:x}", self.get_interrupt_stack_top());
    }
}
