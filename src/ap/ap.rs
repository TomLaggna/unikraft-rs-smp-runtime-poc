// ap.rs - Application Processor entry point and runtime initialization
use crate::ap_println; // Macro is exported to crate root
use crate::boot_trampoline_bindings;
use crate::cpu_startup::x2apic_enable;
use crate::ApTaskInfo;
use core::arch::asm;
use core::ptr;

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
        // asm!("out dx, al", in("al") b'@' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        // Mark CPU as IDLE
        let state_ptr = &raw const cpu.state as *mut i32;
        ptr::write_volatile(state_ptr, 2); // LCPU_STATE_IDLE

        // Debug: Send '#' after state set
        // asm!("out dx, al", in("al") b'#' as u8, in("dx") 0x3F8u16, options(nomem, nostack));

        // Initialize Rust runtime for this AP (TLS, etc.)
        let tlsp = match ap_runtime_init() {
            Ok(tls_ptr) => tls_ptr,
            Err(e) => {
                ap_println!("Failed to initialize runtime: {}", e);
                loop {
                    asm!("hlt");
                }
            }
        };

        ap_println!("Runtime init complete");

        // Use ap_println! macro which works without full runtime
        ap_println!("CPU {} online! APIC ID: {}", cpu_id, cpu.id);
        ap_println!("TLS base: 0x{:016x}", tlsp);

        // Set up minimal exception handlers to catch ELF crashes
        setup_exception_handlers();
        ap_println!("Exception handlers installed");

        // Read task info from shared memory
        let task_info_ptr = cpu.task_info_ptr as *const ApTaskInfo;
        if task_info_ptr.is_null() {
            ap_println!("ERROR: Task info pointer is null");
            loop {
                asm!("hlt");
            }
        }
        ap_println!("reading entry point from shared memory...");
        let task_info = &*task_info_ptr;
        let elf_entry = task_info.read_entry_point();
        ap_println!(
            "Read ELF entry point from shared memory: 0x{:016x}",
            elf_entry
        );

        if elf_entry == 0 {
            ap_println!("ERROR: No ELF entry point set");
            loop {
                asm!("hlt");
            }
        }

        // Mark task as running
        task_info.write_status(1);
        ap_println!("Task status set to RUNNING");

        // Execute the ELF entry point
        // Cast to function pointer and call it
        // let elf_fn: extern "C" fn() -> () = core::mem::transmute(elf_entry as usize);
        // ap_println!("executing elf...");
        // TODO elf is not PIE and needs to be loaded at specific address
        // elf_fn();

        // Mark task as done
        task_info.write_status(2);
        ap_println!("CPU {} completed ELF execution", cpu_id);

        // Wait for more work (simplified - just halt)
        loop {
            asm!("hlt");
        }
    }
}

/// Initialize Rust runtime for AP (mainly TLS setup)
pub fn ap_runtime_init() -> Result<usize, i32> {
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

        ap_println!("TLS initialized at 0x{:016x}", tlsp);

        Ok(tlsp)
    }
}

/// Allocate aligned memory (simplified - use static pool)
pub fn alloc_aligned(size: usize, align: usize) -> Result<usize, i32> {
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

/// IDT entry for exception handlers
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn new() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: unsafe extern "C" fn(), dpl: u8) {
        let addr = handler as usize as u64;
        self.offset_low = (addr & 0xFFFF) as u16;
        self.offset_mid = ((addr >> 16) & 0xFFFF) as u16;
        self.offset_high = ((addr >> 32) & 0xFFFFFFFF) as u32;
        self.selector = 0x08; // Code segment selector
        self.ist = 0;
        // Flags: Present (0x80) | DPL (dpl << 5) | Type (0x0E for interrupt gate)
        self.flags = 0x80 | ((dpl & 0x3) << 5) | 0x0E;
    }
}

#[repr(C, packed)]
struct IdtDescriptor {
    limit: u16,
    base: u64,
}

/// Task State Segment (TSS) for x86_64
/// Used for stack switching when transitioning privilege levels (ring 3 -> ring 0)
#[repr(C, packed)]
struct Tss {
    _reserved1: u32,
    rsp0: u64, // Stack pointer for ring 0 (kernel)
    rsp1: u64, // Stack pointer for ring 1 (unused)
    rsp2: u64, // Stack pointer for ring 2 (unused)
    _reserved2: u64,
    ist: [u64; 7], // Interrupt Stack Table
    _reserved3: u64,
    _reserved4: u16,
    iomap_base: u16, // I/O Map Base Address
}

static mut AP_IDT: [IdtEntry; 33] = [IdtEntry::new(); 33];

// Static TSS for stack switching during ring transitions
static mut AP_TSS: Tss = Tss {
    _reserved1: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    _reserved2: 0,
    ist: [0; 7],
    _reserved3: 0,
    _reserved4: 0,
    iomap_base: 104, // Size of TSS
};

unsafe fn setup_exception_handlers() {
    // Get current stack pointer for kernel stack (RSP0)
    let kernel_stack: u64;
    asm!("mov {}, rsp", out(reg) kernel_stack);

    // Initialize TSS with kernel stack
    AP_TSS.rsp0 = kernel_stack;
    ap_println!("TSS RSP0 set to: 0x{:016x}", kernel_stack);

    // Setup TSS descriptor in GDT
    setup_tss_descriptor();

    // Set up handlers for common exceptions (DPL=0, kernel only)
    AP_IDT[0].set_handler(exception_handler_0, 0); // Divide by zero
    AP_IDT[6].set_handler(exception_handler_6, 0); // Invalid opcode
    AP_IDT[8].set_handler(exception_handler_8, 0); // Double fault
    AP_IDT[13].set_handler(exception_handler_13, 0); // General protection fault
    AP_IDT[14].set_handler(exception_handler_14, 0); // Page fault

    // User exit handler (interrupt 32) - DPL=3 (user accessible)
    AP_IDT[32].set_handler(user_exit_handler, 3);

    let idt_desc = IdtDescriptor {
        limit: (core::mem::size_of::<[IdtEntry; 33]>() - 1) as u16,
        base: AP_IDT.as_ptr() as u64,
    };

    asm!("lidt [{}]", in(reg) &idt_desc, options(readonly, nostack, preserves_flags));

    // Verify IDT was loaded
    let mut loaded_desc = IdtDescriptor { limit: 0, base: 0 };
    asm!("sidt [{}]", in(reg) &mut loaded_desc, options(nostack, preserves_flags));

    // Copy packed struct fields to avoid unaligned reference
    let base = loaded_desc.base;
    let limit = loaded_desc.limit;
    ap_println!("IDT loaded at: 0x{:016x} limit: {}", base, limit);

    // Load TSS using LTR instruction
    let tss_selector = boot_trampoline_bindings::GDT_SEL_TSS;
    asm!("ltr {0:x}", in(reg) tss_selector, options(nostack, preserves_flags));
    ap_println!("TSS loaded with selector: 0x{:04x}", tss_selector);
}

/// Setup TSS descriptor in the GDT
/// TSS descriptor is 16 bytes in 64-bit mode (occupies 2 GDT entries)
unsafe fn setup_tss_descriptor() {
    let tss_base = &AP_TSS as *const Tss as u64;
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;

    // Get GDT base address
    let mut gdt_desc = IdtDescriptor { limit: 0, base: 0 };
    asm!("sgdt [{}]", in(reg) &mut gdt_desc, options(nostack, preserves_flags));

    // TSS descriptor is at index 5 (offset 0x28)
    let tss_desc_ptr = (gdt_desc.base + 0x28) as *mut u64;

    // Build TSS descriptor (16 bytes = 2 u64 entries)
    // Low qword: limit[15:0] | base[15:0] | base[23:16] | type=0x89 | limit[19:16] | base[31:24]
    let low = (tss_limit & 0xFFFF)
        | ((tss_base & 0xFFFF) << 16)
        | ((tss_base & 0xFF0000) << 32)
        | (0x89u64 << 40)  // Type: Available 64-bit TSS, Present
        | (((tss_limit >> 16) & 0xF) << 48)
        | ((tss_base & 0xFF000000) << 32);

    // High qword: base[63:32] | reserved
    let high = tss_base >> 32;

    ptr::write_volatile(tss_desc_ptr, low);
    ptr::write_volatile(tss_desc_ptr.offset(1), high);

    ap_println!(
        "TSS descriptor set at GDT+0x28, TSS base: 0x{:016x}",
        tss_base
    );
}

#[no_mangle]
unsafe extern "C" fn exception_handler_0() {
    ap_println!("\n!!! EXCEPTION #0: Divide by Zero !!!\n");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_6() {
    ap_println!("\n!!! EXCEPTION #6: Invalid Opcode !!!\n");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_8() {
    ap_println!("\n!!! EXCEPTION #8: Double Fault !!!");
    ap_println!("This means an exception occurred while handling another exception.");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_13() {
    ap_println!("\n!!! EXCEPTION #13: General Protection Fault !!!");
    // Read error code from stack
    let error_code: u64;
    asm!("mov {}, [rsp]", out(reg) error_code);
    ap_println!("Error code: 0x{:016x}", error_code);
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_14() {
    ap_println!("\n!!! EXCEPTION #14: Page Fault !!!");
    // Read CR2 (faulting address)
    let fault_addr: u64;
    asm!("mov {}, cr2", out(reg) fault_addr);
    ap_println!("Fault address: 0x{:016x}", fault_addr);
    // Read error code from stack
    let error_code: u64;
    asm!("mov {}, [rsp]", out(reg) error_code);
    ap_println!(
        "Error code: 0x{:016x} (P={}, W={}, U={})",
        error_code,
        error_code & 1,
        (error_code >> 1) & 1,
        (error_code >> 2) & 1
    );
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

/// User exit handler (interrupt 32)
/// Called when user space program executes INT 32 to exit
/// This handler has DPL=3, allowing ring 3 (user space) to invoke it
#[no_mangle]
unsafe extern "C" fn user_exit_handler() {
    ap_println!("\n=== USER EXIT (INT 32) ===");
    ap_println!("User program requested exit");

    // TODO: Mark task as completed in AP_TASK_INFO when implementing ELF execution
    // extern { static mut AP_TASK_INFO: ApTaskInfo; }
    // AP_TASK_INFO.write_status(2); // Status: done

    // For now, just halt
    loop {
        asm!("cli");
        asm!("hlt");
    }
}
