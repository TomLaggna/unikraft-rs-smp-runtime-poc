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

/// Accumulated cycles spent in virt_to_phys (BSP only)
static VIRT_TO_PHYS_CYCLES: AtomicU64 = AtomicU64::new(0);
static VIRT_TO_PHYS_CALLS: AtomicU64 = AtomicU64::new(0);

/// Accumulated cycles for buffer allocation stages
static VEC_ALLOC_CYCLES: AtomicU64 = AtomicU64::new(0);
static PAGE_TOUCH_CYCLES: AtomicU64 = AtomicU64::new(0);
static PAGE_TOUCH_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_TABLE_INIT_CYCLES: AtomicU64 = AtomicU64::new(0);

/// Record points for timing
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u64)]
pub enum TimePoint {
    /// BSP: After buffer allocation and page touching in UserSpaceManager::new
    BufferAllocationComplete = 0,
    /// BSP: After user code buffer allocation and mapping
    UserCodeMappingComplete = 1,
    /// BSP: After user stack buffer allocation and mapping
    UserStackMappingComplete = 2,
    /// BSP: After interrupt infrastructure setup (GDT, TSS, IDT, handlers)
    InterruptSetupComplete = 3,
    /// BSP: After user space memory setup complete (legacy, same as InterruptSetupComplete)
    UserSpaceSetupComplete = 4,
    /// BSP: After user (u2k/k2u) initial trampoline setup complete
    UserTrampolineSetupComplete = 5,
    /// BSP: After user (u2k/k2u) trampolines were patched and APTaskInfo updated
    PatchingUserSpaceComplete = 6,
    /// BSP: After boot trampoline setup complete
    BootTrampolineSetupComplete = 7,
    /// AP: After AP has booted and initialized
    ApBootComplete = 8,
    /// AP: After AP executes user function
    AfterUserExecution = 9,
}

impl TimePoint {
    fn name(&self) -> &'static str {
        match self {
            TimePoint::BufferAllocationComplete => "BUFFER_ALLOCATION_COMPLETE",
            TimePoint::UserCodeMappingComplete => "USER_CODE_MAPPING_COMPLETE",
            TimePoint::UserStackMappingComplete => "USER_STACK_MAPPING_COMPLETE",
            TimePoint::InterruptSetupComplete => "INTERRUPT_SETUP_COMPLETE",
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
            0 => Some(TimePoint::BufferAllocationComplete),
            1 => Some(TimePoint::UserCodeMappingComplete),
            2 => Some(TimePoint::UserStackMappingComplete),
            3 => Some(TimePoint::InterruptSetupComplete),
            4 => Some(TimePoint::UserSpaceSetupComplete),
            5 => Some(TimePoint::UserTrampolineSetupComplete),
            6 => Some(TimePoint::PatchingUserSpaceComplete),
            7 => Some(TimePoint::BootTrampolineSetupComplete),
            8 => Some(TimePoint::ApBootComplete),
            9 => Some(TimePoint::AfterUserExecution),
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

/// Add cycles to virt_to_phys accumulator (call from virt_to_phys)
#[inline]
pub fn add_virt_to_phys_cycles(cycles: u64) {
    VIRT_TO_PHYS_CYCLES.fetch_add(cycles, Ordering::Relaxed);
    VIRT_TO_PHYS_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Get total cycles spent in virt_to_phys
#[inline]
pub fn get_virt_to_phys_cycles() -> (u64, u64) {
    (
        VIRT_TO_PHYS_CYCLES.load(Ordering::Relaxed),
        VIRT_TO_PHYS_CALLS.load(Ordering::Relaxed),
    )
}

/// Add cycles for vec allocation
#[inline]
pub fn add_vec_alloc_cycles(cycles: u64) {
    VEC_ALLOC_CYCLES.fetch_add(cycles, Ordering::Relaxed);
}

/// Add cycles for page touching
#[inline]
pub fn add_page_touch_cycles(cycles: u64) {
    PAGE_TOUCH_CYCLES.fetch_add(cycles, Ordering::Relaxed);
    PAGE_TOUCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Add cycles for page table initialization
#[inline]
pub fn add_page_table_init_cycles(cycles: u64) {
    PAGE_TABLE_INIT_CYCLES.fetch_add(cycles, Ordering::Relaxed);
}

/// Get buffer allocation timing stats
pub fn get_buffer_alloc_stats() -> (u64, u64, u64, u64) {
    (
        VEC_ALLOC_CYCLES.load(Ordering::Relaxed),
        PAGE_TOUCH_CYCLES.load(Ordering::Relaxed),
        PAGE_TOUCH_COUNT.load(Ordering::Relaxed),
        PAGE_TABLE_INIT_CYCLES.load(Ordering::Relaxed),
    )
}

/// Read TSC directly (for timing small code sections)
#[inline]
pub fn rdtsc() -> u64 {
    read_tsc()
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

    // Print virt_to_phys aggregate timing
    let (cycles, calls) = get_virt_to_phys_cycles();
    if calls > 0 {
        let micros = ((cycles as f64) / CPU_MHZ) as u64;
        let avg_cycles = cycles / calls;
        println!(
            "[TIMING] virt_to_phys: {} calls, {} total cycles ({} μs), {} avg cycles/call",
            calls, cycles, micros, avg_cycles
        );
    }

    // Print buffer allocation timing breakdown
    let (vec_cycles, touch_cycles, touch_count, pt_init_cycles) = get_buffer_alloc_stats();
    if vec_cycles > 0 || touch_cycles > 0 {
        let vec_micros = ((vec_cycles as f64) / CPU_MHZ) as u64;
        let touch_micros = ((touch_cycles as f64) / CPU_MHZ) as u64;
        let pt_init_micros = ((pt_init_cycles as f64) / CPU_MHZ) as u64;
        println!("[TIMING] Buffer allocation breakdown:");
        println!(
            "  - vec allocation: {} cycles ({} μs)",
            vec_cycles, vec_micros
        );
        println!(
            "  - page touching: {} pages, {} total cycles ({} μs), {} avg cycles/page",
            touch_count,
            touch_cycles,
            touch_micros,
            if touch_count > 0 {
                touch_cycles / touch_count
            } else {
                0
            }
        );
        println!(
            "  - page table init: {} cycles ({} μs)",
            pt_init_cycles, pt_init_micros
        );
    }
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
