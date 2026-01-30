// timing.rs - Simple timing utilities for benchmarking
//
// Uses RDTSC (Read Time-Stamp Counter) to measure execution times.
// Similar to Dandelion's approach but simplified for bare-metal environment.

use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU64, Ordering};

/// Global start time (initialized when first timer is created)
static START_TIME: AtomicU64 = AtomicU64::new(0);
const CPU_MHZ: u64 = 2100; // Assume 2.1 GHz for conversion (adjust as needed)

/// Record points for timing
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimePoint {
    /// BSP: After user space memory setup complete
    UserSpaceSetupComplete,
    /// AP: After AP has booted and initialized
    ApBootComplete,
    /// AP: Before AP executes user function
    BeforeUserExecution,
    /// AP: After AP executes user function
    AfterUserExecution,
}

impl TimePoint {
    fn name(&self) -> &'static str {
        match self {
            TimePoint::UserSpaceSetupComplete => "USER_SPACE_SETUP_COMPLETE",
            TimePoint::ApBootComplete => "AP_BOOT_COMPLETE",
            TimePoint::BeforeUserExecution => "BEFORE_USER_EXECUTION",
            TimePoint::AfterUserExecution => "AFTER_USER_EXECUTION",
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

/// Record a timestamp and print it
pub fn record_and_print(point: TimePoint) {
    let cycles = elapsed_cycles();

    // Convert cycles to microseconds (assuming 2.1 GHz CPU)
    // This is approximate - actual TSC frequency varies by CPU
    let micros = cycles / CPU_MHZ;

    println!(
        "[TIMESTAMP] {} at {} cycles ({} μs)",
        point.name(),
        cycles,
        micros
    );
}

/// Record a timestamp and print it (AP-safe version using ap_println)
pub fn record_and_print_ap(point: TimePoint) {
    let cycles = elapsed_cycles();

    // Convert cycles to microseconds (assuming ~3 GHz CPU)
    let micros = cycles / 3000;

    // Use the ap_println macro which is safe for AP use
    crate::ap_println!(
        "[TIMESTAMP] {} at {} cycles ({} μs)",
        point.name(),
        cycles,
        micros
    );
}
