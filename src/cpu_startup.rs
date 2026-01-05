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

/// Send INIT IPI to target CPU
pub unsafe fn send_init_ipi(dest: u32) {
    let icr = APIC_ICR_TRIGGER_LEVEL
        | APIC_ICR_LEVEL_ASSERT
        | APIC_ICR_DESTMODE_PHYSICAL
        | APIC_ICR_DMODE_INIT;
    wrmsr(MSR_APIC_ICR, icr, dest);
}

/// De-assert INIT IPI (required before SIPI)
pub unsafe fn deassert_init_ipi(dest: u32) {
    let icr = APIC_ICR_TRIGGER_LEVEL | APIC_ICR_DESTMODE_PHYSICAL | APIC_ICR_DMODE_INIT;
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
    // SIPI uses edge-triggered, not level-triggered!
    let icr = APIC_ICR_DESTMODE_PHYSICAL | APIC_ICR_DMODE_SUP | vector;

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
