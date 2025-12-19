// cpu_startup.rs - Minimal x86_64 Multi-core Startup
// For use in Rust applications on KVM x86_64

// ============================================================================
// MSR and APIC Definitions
// ============================================================================

#[allow(dead_code)]
const MSR_APIC_BASE: u32 = 0x1b;
const MSR_APIC_SVR: u32 = 0x80f;
const MSR_APIC_ICR: u32 = 0x830;
#[allow(dead_code)]
const MSR_APIC_EOI: u32 = 0x80b;

const APIC_BASE_EN: u32 = 0x800;
const APIC_BASE_EXTD: u32 = 0x400;
const APIC_SVR_EN: u32 = 0x100;

// ICR control bits
const APIC_ICR_TRIGGER_LEVEL: u32 = 1 << 15;
const APIC_ICR_LEVEL_ASSERT: u32 = 1 << 14;
const APIC_ICR_DESTMODE_PHYSICAL: u32 = 0;
#[allow(dead_code)]
const APIC_ICR_DMODE_FIXED: u32 = 0;
const APIC_ICR_DMODE_INIT: u32 = 5 << 8;
const APIC_ICR_DMODE_SUP: u32 = 6 << 8; // Startup

#[allow(dead_code)]
const CPUID_X2_APIC_SUPPORT: u32 = 1 << 21;

// ============================================================================
// Low-level MSR Operations
// ============================================================================

#[inline]
unsafe fn rdmsr(msr: u32) -> (u32, u32) {
    let value = x86::msr::rdmsr(msr);
    ((value & 0xFFFFFFFF) as u32, (value >> 32) as u32)
}

#[inline]
unsafe fn wrmsr(msr: u32, low: u32, high: u32) {
    let value = ((high as u64) << 32) | (low as u64);
    x86::msr::wrmsr(msr, value);
}

// ============================================================================
// x2APIC Functions
// ============================================================================

/// Check if x2APIC is supported and enable it
pub unsafe fn enable_x2apic() -> Result<(), &'static str> {
    // Check CPUID for x2APIC support (CPUID.1:ECX[21])
    let cpuid_result = x86::cpuid::CpuId::new();
    let feature_info = cpuid_result
        .get_feature_info()
        .ok_or("Failed to get CPUID feature info")?;

    if !feature_info.has_x2apic() {
        return Err("CPU does not support x2APIC");
    }

    // Check APIC base MSR
    let (base_low, base_high) = rdmsr(MSR_APIC_BASE);
    if (base_low & APIC_BASE_EN) == 0 {
        return Err("APIC is not enabled in firmware");
    }

    // Switch to x2APIC mode
    wrmsr(MSR_APIC_BASE, base_low | APIC_BASE_EXTD, base_high);

    // Enable APIC software
    let (svr_low, svr_high) = rdmsr(MSR_APIC_SVR);
    if (svr_low & APIC_SVR_EN) == 0 {
        wrmsr(MSR_APIC_SVR, svr_low | APIC_SVR_EN, svr_high);
    }

    Ok(())
}

/// Get the current CPU's APIC ID
#[allow(dead_code)]
pub fn get_apic_id() -> u32 {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(feature_info) = cpuid.get_feature_info() {
        feature_info.initial_local_apic_id() as u32
    } else {
        // Fallback: read from CPUID manually without ebx
        unsafe {
            let mut ebx: u32;
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "cpuid",
                "xchg {tmp:r}, rbx",
                tmp = out(reg) ebx,
                inout("eax") 1u32 => _,
                out("ecx") _,
                out("edx") _,
            );
            ebx >> 24
        }
    }
}

/// Send INIT IPI to target CPU
pub unsafe fn send_init_ipi(dest: u32) {
    let icr = APIC_ICR_TRIGGER_LEVEL
        | APIC_ICR_LEVEL_ASSERT
        | APIC_ICR_DESTMODE_PHYSICAL
        | APIC_ICR_DMODE_INIT;
    wrmsr(MSR_APIC_ICR, icr, dest);
}

/// Send Start-up IPI (SIPI) to target CPU
///
/// # Arguments
/// * `addr` - Physical address of boot code (must be page-aligned, i.e., multiple of 4096)
/// * `dest` - APIC ID of destination CPU
pub unsafe fn send_startup_ipi(addr: u64, dest: u32) {
    assert!(
        (addr & 0xfff) == 0,
        "Boot code address must be page-aligned (multiple of 4096)"
    );

    let vector = (addr >> 12) as u32;
    let icr = APIC_ICR_TRIGGER_LEVEL
        | APIC_ICR_LEVEL_ASSERT
        | APIC_ICR_DESTMODE_PHYSICAL
        | APIC_ICR_DMODE_SUP
        | vector;

    wrmsr(MSR_APIC_ICR, icr, dest);
}

// ============================================================================
// Delay Functions
// ============================================================================

/// Busy-wait delay in microseconds (approximate)
pub fn delay_us(us: u32) {
    // Approximate: 1000 CPU cycles ≈ 1 microsecond at ~1 GHz
    // This is a rough estimate; for real code use TSC or a timer
    let iterations = us.saturating_mul(1000 / 4);
    for _ in 0..iterations {
        unsafe {
            core::arch::asm!("nop");
        }
    }
}

/// Busy-wait delay in milliseconds
pub fn delay_ms(ms: u32) {
    delay_us(ms.saturating_mul(1000));
}

// ============================================================================
// High-level x2APIC Functions (referenced by main.rs)
// ============================================================================

/// Public wrapper for enable_x2apic
pub unsafe fn x2apic_enable() -> Result<(), &'static str> {
    enable_x2apic()
}

/// Send INIT IPI to target CPU (public wrapper)
pub unsafe fn x2apic_send_iipi(dest: u32) {
    send_init_ipi(dest);
}

/// Send SIPI to target CPU (public wrapper)
pub unsafe fn x2apic_send_sipi(addr: u64, dest: u32) {
    send_startup_ipi(addr, dest);
}

// ============================================================================
// CPU Startup Configuration and Execution
// ============================================================================

/// Configuration for starting an Application Processor (AP)
#[allow(dead_code)]
pub struct ApStartupConfig {
    /// Target CPU's APIC ID
    pub apic_id: u32,

    /// Physical address of boot trampoline code (must be page-aligned in first 1 MiB)
    pub boot_code_addr: u64,

    /// Entry function called when AP boots (64-bit, called with APIC ID as argument)
    pub entry_fn: unsafe extern "C" fn(u32) -> !,

    /// Stack pointer for the AP (should point to end of allocated stack)
    pub stack_ptr: u64,
}

/// Start an Application Processor (AP)
///
/// This performs the standard Intel MP startup sequence:
/// 1. Enable x2APIC
/// 2. Send INIT IPI
/// 3. Wait 10ms
/// 4. Send SIPI (twice, 200us apart)
#[allow(dead_code)]
pub unsafe fn start_ap(config: &ApStartupConfig) -> Result<(), &'static str> {
    // Enable x2APIC if not already enabled
    let _ = enable_x2apic(); // Ignore error if already enabled

    // Verify boot code address is page-aligned and in first 1 MiB
    if (config.boot_code_addr & 0xfff) != 0 {
        return Err("Boot code address must be page-aligned");
    }
    if config.boot_code_addr >= 0x100000 {
        return Err("Boot code must be in first 1 MiB of physical memory");
    }

    // Verify AP is not ourselves
    if config.apic_id == get_apic_id() {
        return Err("Cannot start AP: target is current CPU");
    }

    // Send INIT IPI
    send_init_ipi(config.apic_id);

    // Wait per Intel manual (10ms minimum)
    delay_ms(10);

    // Send SIPI twice per Intel manual
    for _ in 0..2 {
        send_startup_ipi(config.boot_code_addr, config.apic_id);
        delay_us(200);
    }

    // At this point, the AP is starting up
    // You may want to add verification here (poll CPU state, etc.)

    Ok(())
}

// ============================================================================
// Memory Copy for Boot Code
// ============================================================================

/// Copy boot trampoline code to physical memory location
///
/// # Safety
/// - Must be called with valid physical addresses
/// - Destination address must be writable
/// - Typically called early during boot
#[allow(dead_code)]
pub unsafe fn copy_boot_code(boot_code: &[u8], dest_addr: u64) -> Result<(), &'static str> {
    if boot_code.is_empty() {
        return Err("Boot code is empty");
    }

    if boot_code.len() > 0x1000 {
        return Err("Boot code too large (> 4KiB)");
    }

    if (dest_addr & 0xfff) != 0 {
        return Err("Destination address must be page-aligned");
    }

    // Copy memory
    let src = boot_code.as_ptr() as *const u8;
    let dst = dest_addr as *mut u8;

    core::ptr::copy_nonoverlapping(src, dst, boot_code.len());

    // Clear remaining page
    let remaining = 0x1000 - boot_code.len();
    if remaining > 0 {
        core::ptr::write_bytes(dst.add(boot_code.len()), 0, remaining);
    }

    Ok(())
}

// ============================================================================
// Minimal Boot Trampoline (Assembly)
// ============================================================================

/// Minimal x86_64 16-bit boot trampoline
///
/// This must be copied to a page-aligned address in the first 1 MiB.
/// The trampoline brings the CPU from 16-bit real mode to 64-bit long mode.
///
/// This is a placeholder; you should extract the actual trampoline from
/// the Unikraft source (plat/kvm/x86/lcpu_start.S)
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub const BOOT_TRAMPOLINE: &[u8] = &[
    // This is a placeholder - must be replaced with actual assembly
    // from Unikraft's lcpu_start16_ap through lcpu_start64
    0x00, // Placeholder bytes
];

// ============================================================================
// Example Usage
// ============================================================================

#[cfg(test)]
mod example {
    use super::*;

    /// Example: Start a secondary CPU
    ///
    /// In real code, you would:
    /// 1. Extract the boot trampoline from Unikraft
    /// 2. Allocate memory in the first 1 MiB for it
    /// 3. Create an entry point function
    /// 4. Call start_ap with the configuration

    #[allow(dead_code)]
    unsafe extern "C" fn example_entry_point(apic_id: u32) -> ! {
        // Entry point code for the new CPU
        // This runs in 64-bit long mode on the AP
        println!("AP {} started!", apic_id);
        loop {
            core::arch::asm!("hlt");
        }
    }

    #[test]
    fn example_start_ap() {
        unsafe {
            // These values are examples
            let config = ApStartupConfig {
                apic_id: 1,                    // CPU to start
                boot_code_addr: 0x8000,        // Must be page-aligned in first 1 MiB
                entry_fn: example_entry_point, // Called when AP boots
                stack_ptr: 0x10000 + 4096,     // Top of allocated stack
            };

            match start_ap(&config) {
                Ok(()) => println!("AP startup sequence completed"),
                Err(e) => println!("Failed to start AP: {}", e),
            }
        }
    }
}
