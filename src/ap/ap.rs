// ap.rs - Application Processor entry point and runtime initialization
use crate::ap_println; // Macro is exported to crate root
use crate::boot_trampoline_bindings;
use crate::cpu_startup::x2apic_enable;
use crate::timing::{print_ap_timestamps, record_ap, TimePoint};
use crate::ApTaskInfo;
use core::arch::asm;
use core::ptr;

/// Entry point for Application Processors (APs)
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

        // Mark CPU as IDLE
        let state_ptr = &raw const cpu.state as *mut i32;
        ptr::write_volatile(state_ptr, 2); // LCPU_STATE_IDLE

        // Set up minimal exception handlers to catch ELF crashes
        setup_exception_handlers();

        // Record timestamp: AP boot complete
        record_ap(TimePoint::ApBootComplete);

        // Read task info from shared memory
        let task_info_ptr = cpu.task_info_ptr as *const ApTaskInfo;
        if task_info_ptr.is_null() {
            ap_println!("ERROR: Task info pointer is null");
            loop {
                asm!("hlt");
            }
        }
        let task_info = &*task_info_ptr;

        // Read trampoline addresses
        let k2u_trampoline = task_info.read_k2u_trampoline();

        if k2u_trampoline == 0 {
            ap_println!("ERROR: K->U trampoline address not set");
            loop {
                asm!("hlt");
            }
        }

        // Mark task as running
        task_info.write_status(1);
        // Record timestamp: Before user execution

        // Execute user code via K->U trampoline
        // NOTE: GDT/IDT/TSS are NOT loaded here - the trampoline will load them
        // The trampoline will:
        // 1. Save kernel RSP
        // 2. Load user CR3
        // 3. Load GDT/IDT/TSS (now accessible in user CR3)
        // 4. Set up user stack
        // 5. Jump to user code entry point
        // User code will trigger INT 32, which will call U->K trampoline to return here

        // Call the K->U trampoline
        // NOTE: This looks like it returns, but it actually jumps to user code.
        // The "return" comes from U->K trampoline after INT 32.

        // Ensure TLB is flushed for the trampoline mapping
        unsafe {
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3);
            asm!("mov cr3, {}", in(reg) cr3);
        }

        // Verify code at trampoline address
        let trampoline_fn: extern "C" fn() = core::mem::transmute(k2u_trampoline);
        trampoline_fn();

        // Record timestamp: After user execution
        record_ap(TimePoint::AfterUserExecution);

        // Mark task as done
        // TODO removing the debugging code seems to have caused some bug
        // setting the status causes a GPF
        // comment it out for now
        // GPF is the fallback fault, so maybe an unmapped interrupt is actually happening?

        // task_info.write_status(2);
        loop {
            asm!("hlt");
        }
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

static mut AP_IDT: [IdtEntry; 33] = [IdtEntry::new(); 33];

unsafe fn setup_exception_handlers() {
    // Get current stack pointer for kernel stack (RSP0)
    let kernel_stack: u64;
    asm!("mov {}, rsp", out(reg) kernel_stack);

    // Set up handlers for common exceptions (DPL=0, kernel only)
    AP_IDT[0].set_handler(exception_handler_0, 0); // Divide by zero
    AP_IDT[1].set_handler(exception_handler_1, 0); // Debug
    AP_IDT[2].set_handler(exception_handler_2, 0); // NMI
    AP_IDT[3].set_handler(exception_handler_3, 0); // Breakpoint
    AP_IDT[4].set_handler(exception_handler_4, 0); // Overflow
    AP_IDT[5].set_handler(exception_handler_5, 0); // Bound range exceeded
    AP_IDT[6].set_handler(exception_handler_6, 0); // Invalid opcode
    AP_IDT[7].set_handler(exception_handler_7, 0); // Device not available
    AP_IDT[8].set_handler(exception_handler_8, 0); // Double fault
    AP_IDT[10].set_handler(exception_handler_10, 0); // Invalid TSS
    AP_IDT[11].set_handler(exception_handler_11, 0); // Segment not present
    AP_IDT[12].set_handler(exception_handler_12, 0); // Stack-segment fault
    AP_IDT[13].set_handler(exception_handler_13, 0); // General protection fault
    AP_IDT[14].set_handler(exception_handler_14, 0); // Page fault
    AP_IDT[16].set_handler(exception_handler_16, 0); // x87 FPU error
    AP_IDT[17].set_handler(exception_handler_17, 0); // Alignment check
    AP_IDT[18].set_handler(exception_handler_18, 0); // Machine check
    AP_IDT[19].set_handler(exception_handler_19, 0); // SIMD exception

    let idt_desc = IdtDescriptor {
        limit: (core::mem::size_of::<[IdtEntry; 33]>() - 1) as u16,
        base: AP_IDT.as_ptr() as u64,
    };

    asm!("lidt [{}]", in(reg) &idt_desc, options(readonly, nostack, preserves_flags));
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
unsafe extern "C" fn exception_handler_1() {
    ap_println!("\n!!! EXCEPTION #1: Debug !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_2() {
    ap_println!("\n!!! EXCEPTION #2: NMI !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_3() {
    ap_println!("\n!!! EXCEPTION #3: Breakpoint !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_4() {
    ap_println!("\n!!! EXCEPTION #4: Overflow !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_5() {
    ap_println!("\n!!! EXCEPTION #5: Bound Range Exceeded !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_7() {
    ap_println!("\n!!! EXCEPTION #7: Device Not Available !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_10() {
    ap_println!("\n!!! EXCEPTION #10: Invalid TSS !!!");
    let error_code: u64;
    asm!("mov {}, [rsp]", out(reg) error_code);
    ap_println!("Error code: 0x{:016x}", error_code);
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_11() {
    ap_println!("\n!!! EXCEPTION #11: Segment Not Present !!!");
    let error_code: u64;
    asm!("mov {}, [rsp]", out(reg) error_code);
    ap_println!("Error code: 0x{:016x}", error_code);
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_12() {
    ap_println!("\n!!! EXCEPTION #12: Stack-Segment Fault !!!");
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

#[no_mangle]
unsafe extern "C" fn exception_handler_16() {
    ap_println!("\n!!! EXCEPTION #16: x87 FPU Error !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_17() {
    ap_println!("\n!!! EXCEPTION #17: Alignment Check !!!");
    let error_code: u64;
    asm!("mov {}, [rsp]", out(reg) error_code);
    ap_println!("Error code: 0x{:016x}", error_code);
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_18() {
    ap_println!("\n!!! EXCEPTION #18: Machine Check !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}

#[no_mangle]
unsafe extern "C" fn exception_handler_19() {
    ap_println!("\n!!! EXCEPTION #19: SIMD Exception !!!");
    loop {
        asm!("cli");
        asm!("hlt");
    }
}
