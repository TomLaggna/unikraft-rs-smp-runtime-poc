// timing.rs - Simple timing utilities for benchmarking
//
// Uses RDTSC (Read Time-Stamp Counter) to measure execution times.
// Timestamps are stored in arrays and can be printed after execution completes
// to avoid I/O overhead during time-critical sections.

use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Global start time (initialized when first timer is created)
static START_TIME: AtomicU64 = AtomicU64::new(0);
const CPU_MHZ: f64 = 2304.009; // We read the TSC at 2304.009 MHz from outside QEMU

/// Maximum number of timestamps we can store
const MAX_TIMESTAMPS: usize = 16;

/// Storage for BSP timestamps
static BSP_TIMESTAMPS: [AtomicU64; MAX_TIMESTAMPS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_TIMESTAMPS]
};
static BSP_TIMEPOINTS: [AtomicU64; MAX_TIMESTAMPS] = {
    const INIT: AtomicU64 = AtomicU64::new(u64::MAX);
    [INIT; MAX_TIMESTAMPS]
};
static BSP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Storage for AP timestamps
static AP_TIMESTAMPS: [AtomicU64; MAX_TIMESTAMPS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_TIMESTAMPS]
};
static AP_TIMEPOINTS: [AtomicU64; MAX_TIMESTAMPS] = {
    const INIT: AtomicU64 = AtomicU64::new(u64::MAX);
    [INIT; MAX_TIMESTAMPS]
};
static AP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Record points for timing
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u64)]
pub enum TimePoint {
    /// BSP: After user space memory setup complete
    UserSpaceSetupComplete = 0,
    /// BSP: After user (u2k/k2u) initial trampoline setup complete
    UserTrampolineSetupComplete = 1,
    /// BSP: After user (u2k/k2u) trampolines were patched and APTaskInfo updated
    PatchingUserSpaceComplete = 2,
    /// BSP: After boot trampoline setup complete
    BootTrampolineSetupComplete = 3,
    /// AP: After AP has booted and initialized
    ApBootComplete = 4,
    /// AP: After AP executes user function
    AfterUserExecution = 5,
}

impl TimePoint {
    fn name(&self) -> &'static str {
        match self {
            TimePoint::UserSpaceSetupComplete => "USER_SPACE_SETUP_COMPLETE",
            TimePoint::UserTrampolineSetupComplete => "USER_TRAMPOLINE_SETUP_COMPLETE",
            TimePoint::PatchingUserSpaceComplete => "PATCHING_USER_SPACE_COMPLETE",
            TimePoint::BootTrampolineSetupComplete => "BOOT_TRAMPOLINE_SETUP_COMPLETE",
            TimePoint::ApBootComplete => "AP_BOOT_COMPLETE",
            TimePoint::AfterUserExecution => "AFTER_USER_EXECUTION",
        }
    }

    fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(TimePoint::UserSpaceSetupComplete),
            1 => Some(TimePoint::UserTrampolineSetupComplete),
            2 => Some(TimePoint::PatchingUserSpaceComplete),
            3 => Some(TimePoint::BootTrampolineSetupComplete),
            4 => Some(TimePoint::ApBootComplete),
            5 => Some(TimePoint::AfterUserExecution),
            _ => None,
        }
    }
}

/// Read the CPU timestamp counter
#[inline]
fn read_tsc() -> u64 {
    unsafe { _rdtsc() }
}

/// Initialize the global timer (call once at start)
pub fn init_timer() {
    let now = read_tsc();
    START_TIME.store(now, Ordering::Relaxed);
}

/// Get time elapsed since start in TSC cycles
#[inline]
pub fn elapsed_cycles() -> u64 {
    let start = START_TIME.load(Ordering::Relaxed);
    if start == 0 {
        // Auto-initialize on first use
        init_timer();
        0
    } else {
        let now = read_tsc();
        now.saturating_sub(start)
    }
}

/// Record a timestamp for BSP (no printing, just store)
#[inline]
pub fn record(point: TimePoint) {
    let cycles = elapsed_cycles();
    let idx = BSP_COUNT.fetch_add(1, Ordering::Relaxed);
    if idx < MAX_TIMESTAMPS {
        BSP_TIMESTAMPS[idx].store(cycles, Ordering::Relaxed);
        BSP_TIMEPOINTS[idx].store(point as u64, Ordering::Relaxed);
    }
}

/// Record a timestamp for AP (no printing, just store)
#[inline]
pub fn record_ap(point: TimePoint) {
    let cycles = elapsed_cycles();
    let idx = AP_COUNT.fetch_add(1, Ordering::Relaxed);
    if idx < MAX_TIMESTAMPS {
        AP_TIMESTAMPS[idx].store(cycles, Ordering::Relaxed);
        AP_TIMEPOINTS[idx].store(point as u64, Ordering::Relaxed);
    }
}

/// Print all BSP timestamps (call after execution is complete)
pub fn print_bsp_timestamps() {
    let count = BSP_COUNT.load(Ordering::Relaxed).min(MAX_TIMESTAMPS);
    for i in 0..count {
        let cycles = BSP_TIMESTAMPS[i].load(Ordering::Relaxed);
        let point_val = BSP_TIMEPOINTS[i].load(Ordering::Relaxed);
        let micros = ((cycles as f64) / CPU_MHZ) as u64;

        if let Some(point) = TimePoint::from_u64(point_val) {
            println!(
                "[TIMESTAMP] {} at {} cycles ({} μs)",
                point.name(),
                cycles,
                micros
            );
        }
    }
}

/// Print all AP timestamps (call after execution is complete)
/// Uses ap_println for AP-safe output
pub fn print_ap_timestamps() {
    let count = AP_COUNT.load(Ordering::Relaxed).min(MAX_TIMESTAMPS);
    for i in 0..count {
        let cycles = AP_TIMESTAMPS[i].load(Ordering::Relaxed);
        let point_val = AP_TIMEPOINTS[i].load(Ordering::Relaxed);
        let micros = ((cycles as f64) / CPU_MHZ) as u64;

        if let Some(point) = TimePoint::from_u64(point_val) {
            crate::ap_println!(
                "[TIMESTAMP] {} at {} cycles ({} μs)",
                point.name(),
                cycles,
                micros
            );
        }
    }
}

/// Print all timestamps (BSP first, then AP)
pub fn print_all_timestamps() {
    print_bsp_timestamps();
    print_ap_timestamps();
}

/// Reset all timestamp storage (for multiple benchmark runs)
pub fn reset_timestamps() {
    BSP_COUNT.store(0, Ordering::Relaxed);
    AP_COUNT.store(0, Ordering::Relaxed);
    for i in 0..MAX_TIMESTAMPS {
        BSP_TIMESTAMPS[i].store(0, Ordering::Relaxed);
        BSP_TIMEPOINTS[i].store(u64::MAX, Ordering::Relaxed);
        AP_TIMESTAMPS[i].store(0, Ordering::Relaxed);
        AP_TIMEPOINTS[i].store(u64::MAX, Ordering::Relaxed);
    }
}

// Legacy API for compatibility - these now just call record/record_ap

/// Record a timestamp (legacy API - now stores without printing)
#[inline]
pub fn record_and_print(point: TimePoint) {
    record(point);
}

/// Record a timestamp for AP (legacy API - now stores without printing)
#[inline]
pub fn record_and_print_ap(point: TimePoint) {
    record_ap(point);
}
