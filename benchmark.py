#!/usr/bin/env python3
"""
Benchmark script comparing Dandelion vs PoC timing.

Usage: python3 benchmark.py [--runs N]
"""

import subprocess
import re
import os
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import statistics

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


@dataclass
class PoCTimestamps:
    """Timestamps from the PoC benchmark (in microseconds)"""
    user_space_setup_complete: int = 0
    user_trampoline_setup_complete: int = 0
    boot_trampoline_setup_complete: int = 0
    ap_boot_complete: int = 0
    before_user_execution: int = 0
    after_user_execution: int = 0


@dataclass
class DandelionTimestamps:
    """Timestamps from Dandelion benchmark (in microseconds)"""
    engine_start: int = 0
    engine_setup_end: int = 0
    engine_exec_end: int = 0


@dataclass
class BenchmarkResults:
    """Collection of benchmark results"""
    poc_runs: List[PoCTimestamps] = field(default_factory=list)
    dandelion_runs: List[DandelionTimestamps] = field(default_factory=list)


def run_poc_benchmark() -> Optional[PoCTimestamps]:
    """Run the PoC benchmark and parse timestamps"""
    print("  Running PoC benchmark...")
    
    poc_dir = Path("/home/user/unikraft-rs-smp-runtime-poc")
    
    try:
        result = subprocess.run(
            ["make", "run-bench"],
            cwd=poc_dir,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print("    PoC benchmark timed out!")
        return None
    except Exception as e:
        print(f"    PoC benchmark failed: {e}")
        return None
    
    timestamps = PoCTimestamps()
    
    # Parse timestamps from output
    # Format: [TIMESTAMP] NAME at CYCLES cycles (MICROS μs)
    pattern = r'\[TIMESTAMP\]\s+(\w+)\s+at\s+\d+\s+cycles\s+\((\d+)\s*μs\)'
    
    for match in re.finditer(pattern, output):
        name, micros = match.groups()
        micros = int(micros)
        
        if name == "USER_SPACE_SETUP_COMPLETE":
            timestamps.user_space_setup_complete = micros
        elif name == "USER_TRAMPOLINE_SETUP_COMPLETE":
            timestamps.user_trampoline_setup_complete = micros
        elif name == "BOOT_TRAMPOLINE_SETUP_COMPLETE":
            timestamps.boot_trampoline_setup_complete = micros
        elif name == "AP_BOOT_COMPLETE":
            timestamps.ap_boot_complete = micros
        elif name == "BEFORE_USER_EXECUTION":
            timestamps.before_user_execution = micros
        elif name == "AFTER_USER_EXECUTION":
            timestamps.after_user_execution = micros
    
    if timestamps.after_user_execution == 0:
        print("    Warning: Could not parse all PoC timestamps")
        return None
    
    return timestamps


def run_dandelion_benchmark() -> Optional[DandelionTimestamps]:
    """Run the Dandelion benchmark and parse timestamps"""
    print("  Running Dandelion benchmark...")
    
    dandelion_dir = Path("/home/user/dandelion")
    stats_file = dandelion_dir / "server" / "stats_basic.log"
    # Remove old stats file if exists
    if stats_file.exists():
        stats_file.unlink()
    
    try:
        result = subprocess.run(
            [
                "cargo", "test",
                "--bin", "dandelion_server",
                "--test", "timing_tests",
                "--features", "kvm,reqwest_io,timestamp,archive",
                "--release",
                "--",
                "timing_tests::timing_basic",
                "--exact",
                "--nocapture"
            ],
            cwd=dandelion_dir,
            capture_output=True,
            text=True,
            timeout=180
        )
    except subprocess.TimeoutExpired:
        print("    Dandelion benchmark timed out!")
        return None
    except Exception as e:
        print(f"    Dandelion benchmark failed: {e}")
        return None
    
    # Parse timestamps from stats file
    # Check both possible locations
    if not stats_file.exists():
        print(f"    Stats file not found: {stats_file}")
        return None
    
    timestamps = DandelionTimestamps()
    
    try:
        with open(stats_file, 'r') as f:
            content = f.read()
        
        # Parse the stats file format
        # Format: EngineStart: CYCLES cycles (MICROS μs)
        # We want the microseconds value, look for the "basic" function section
        
        # Find the section for function "basic" (not basic_composition)
        # Look for lines like: EngineStart: 1856650 cycles (884 μs)
        patterns = [
            (r'EngineStart:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'engine_start'),
            (r'EngineSetupEnd:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'engine_setup_end'),
            (r'EngineExecEnd:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'engine_exec_end'),
        ]
        
        # Find the "basic" function block (not basic_composition which has 0s)
        # Look for non-zero EngineStart
        for pattern, attr in patterns:
            matches = list(re.finditer(pattern, content))
            # Take the last non-zero match (basic function, not basic_composition)
            for match in reversed(matches):
                value = int(match.group(1))
                if value > 0:
                    setattr(timestamps, attr, value)
                    break
        
        if timestamps.engine_exec_end == 0:
            print(f"    Warning: Could not parse Dandelion timestamps from {stats_file}")
            print(f"    File contents (first 500 chars): {content[:500]}")
            return None
            
    except Exception as e:
        print(f"    Error reading stats file: {e}")
        return None
    
    return timestamps


def collect_data(num_runs: int) -> BenchmarkResults:
    """Collect benchmark data from multiple runs"""
    results = BenchmarkResults()
    
    print(f"\nCollecting data from {num_runs} runs...\n")
    
    for i in range(num_runs):
        print(f"Run {i+1}/{num_runs}:")
        
        # Run PoC
        poc_ts = run_poc_benchmark()
        if poc_ts:
            results.poc_runs.append(poc_ts)
            print(f"    PoC: setup={poc_ts.user_space_setup_complete}μs, "
                  f"exec={poc_ts.after_user_execution - poc_ts.before_user_execution}μs, "
                  f"total={poc_ts.after_user_execution}μs")
        
        # Run Dandelion
        dandelion_ts = run_dandelion_benchmark()
        if dandelion_ts:
            results.dandelion_runs.append(dandelion_ts)
            setup_time = dandelion_ts.engine_setup_end - dandelion_ts.engine_start
            exec_time = dandelion_ts.engine_exec_end - dandelion_ts.engine_setup_end
            print(f"    Dandelion: setup={setup_time}μs, exec={exec_time}μs, "
                  f"total={dandelion_ts.engine_exec_end - dandelion_ts.engine_start}μs")
        
        print()
    
    return results


def compute_boxplot_stats(data: List[float]) -> Dict:
    """Compute statistics for boxplot"""
    if not data:
        return {'min': 0, 'max': 0, 'mean': 0, 'q25': 0, 'q75': 0, 'median': 0}
    
    sorted_data = sorted(data)
    n = len(sorted_data)
    
    return {
        'min': min(data),
        'max': max(data),
        'mean': statistics.mean(data),
        'median': statistics.median(data),
        'q25': sorted_data[n // 4] if n >= 4 else sorted_data[0],
        'q75': sorted_data[3 * n // 4] if n >= 4 else sorted_data[-1],
        'data': data
    }


def create_comparison_plot(results: BenchmarkResults, output_path: str):
    """Create the first plot: Total runtime and setup/exec comparison"""
    
    fig, axes = plt.subplots(1, 3, figsize=(14, 6))
    fig.suptitle('KVM vs Unikraft: Runtime Comparison', fontsize=14, fontweight='bold')
    
    # Prepare data
    # Dandelion
    dandelion_setup = [ts.engine_setup_end - ts.engine_start for ts in results.dandelion_runs]
    dandelion_exec = [ts.engine_exec_end - ts.engine_setup_end for ts in results.dandelion_runs]
    dandelion_total = [ts.engine_exec_end - ts.engine_start for ts in results.dandelion_runs]
    
    # PoC
    poc_setup = [ts.user_space_setup_complete for ts in results.poc_runs]
    poc_exec = [ts.after_user_execution - ts.before_user_execution for ts in results.poc_runs]
    poc_total = [ts.after_user_execution for ts in results.poc_runs]
    
    colors = {'dandelion': '#2ecc71', 'poc': '#3498db'}
    
    # Plot 1: Total Runtime
    ax1 = axes[0]
    bp1 = ax1.boxplot([dandelion_total, poc_total], 
                       labels=['KVM', 'Unikraft'],
                       patch_artist=True)
    bp1['boxes'][0].set_facecolor(colors['dandelion'])
    bp1['boxes'][1].set_facecolor(colors['poc'])
    ax1.set_ylabel('Time (μs)')
    ax1.set_title('Total Runtime')
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Setup Time
    ax2 = axes[1]
    bp2 = ax2.boxplot([dandelion_setup, poc_setup],
                       labels=['KVM', 'Unikraft'],
                       patch_artist=True)
    bp2['boxes'][0].set_facecolor(colors['dandelion'])
    bp2['boxes'][1].set_facecolor(colors['poc'])
    ax2.set_ylabel('Time (μs)')
    ax2.set_title('Setup Time')
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Execution Time
    ax3 = axes[2]
    bp3 = ax3.boxplot([dandelion_exec, poc_exec],
                       labels=['KVM', 'Unikraft'],
                       patch_artist=True)
    bp3['boxes'][0].set_facecolor(colors['dandelion'])
    bp3['boxes'][1].set_facecolor(colors['poc'])
    ax3.set_ylabel('Time (μs)')
    ax3.set_title('Execution Time')
    ax3.grid(True, alpha=0.3)
    
    # Add statistics annotations
    def add_stats_annotation(ax, data_list, positions):
        for data, pos in zip(data_list, positions):
            if data:
                mean = statistics.mean(data)
                ax.annotate(f'μ={mean:.0f}', 
                           xy=(pos, mean), 
                           xytext=(pos + 0.3, mean),
                           fontsize=8, color='red')
    
    add_stats_annotation(ax1, [dandelion_total, poc_total], [1, 2])
    add_stats_annotation(ax2, [dandelion_setup, poc_setup], [1, 2])
    add_stats_annotation(ax3, [dandelion_exec, poc_exec], [1, 2])
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved comparison plot to: {output_path}")
    plt.close()


def create_detailed_plot(results: BenchmarkResults, output_path: str):
    """Create the second plot: PoC detailed timing breakdown"""
    
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle('Unikraft PoC Stage Timings', fontsize=14, fontweight='bold')
    
    # Prepare data - compute deltas between stages
    user_space_setup = [ts.user_space_setup_complete for ts in results.poc_runs]
    
    trampoline_setup = [
        ts.user_trampoline_setup_complete - ts.user_space_setup_complete 
        for ts in results.poc_runs
    ]
    
    boot_trampoline_setup = [
        ts.boot_trampoline_setup_complete - ts.user_trampoline_setup_complete
        for ts in results.poc_runs
    ]
    
    ap_boot = [
        ts.ap_boot_complete - ts.boot_trampoline_setup_complete
        for ts in results.poc_runs
    ]
    
    exec_setup = [
        ts.before_user_execution - ts.ap_boot_complete
        for ts in results.poc_runs
    ]
    
    user_execution = [
        ts.after_user_execution - ts.before_user_execution
        for ts in results.poc_runs
    ]
    
    # All data for boxplot
    all_data = [
        user_space_setup,
        trampoline_setup,
        boot_trampoline_setup,
        ap_boot,
        exec_setup,
        user_execution
    ]
    
    labels = [
        'User Space\nSetup',
        'User Trampoline\nSetup',
        'Boot Trampoline\nSetup',
        'AP Boot',
        'AP Setup',
        'User Execution'
    ]
    
    colors = ['#e74c3c', '#e67e22', '#f39c12', '#27ae60', '#3498db', '#9b59b6']
    
    bp = ax.boxplot(all_data, labels=labels, patch_artist=True)
    
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax.set_ylabel('Time (μs)')
    ax.set_xlabel('Stage')
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add mean annotations
    for i, data in enumerate(all_data):
        if data:
            mean = statistics.mean(data)
            ax.annotate(f'{mean:.0f}μs', 
                       xy=(i + 1, mean), 
                       xytext=(i + 1, mean + max(data) * 0.1),
                       ha='center',
                       fontsize=9,
                       fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved detailed plot to: {output_path}")
    plt.close()


def print_summary(results: BenchmarkResults):
    """Print a summary of the benchmark results"""
    print("\n" + "="*60)
    print("BENCHMARK SUMMARY")
    print("="*60)
    
    print(f"\nPoC runs collected: {len(results.poc_runs)}")
    print(f"Dandelion runs collected: {len(results.dandelion_runs)}")
    
    if results.poc_runs:
        print("\n--- PoC Statistics (μs) ---")
        poc_total = [ts.after_user_execution for ts in results.poc_runs]
        poc_setup = [ts.user_space_setup_complete for ts in results.poc_runs]
        poc_exec = [ts.after_user_execution - ts.before_user_execution for ts in results.poc_runs]
        
        print(f"  Total runtime:  mean={statistics.mean(poc_total):.0f}, "
              f"min={min(poc_total)}, max={max(poc_total)}")
        print(f"  Setup time:     mean={statistics.mean(poc_setup):.0f}, "
              f"min={min(poc_setup)}, max={max(poc_setup)}")
        print(f"  Execution time: mean={statistics.mean(poc_exec):.0f}, "
              f"min={min(poc_exec)}, max={max(poc_exec)}")
    
    if results.dandelion_runs:
        print("\n--- Dandelion Statistics (μs) ---")
        d_total = [ts.engine_exec_end - ts.engine_start for ts in results.dandelion_runs]
        d_setup = [ts.engine_setup_end - ts.engine_start for ts in results.dandelion_runs]
        d_exec = [ts.engine_exec_end - ts.engine_setup_end for ts in results.dandelion_runs]
        
        print(f"  Total runtime:  mean={statistics.mean(d_total):.0f}, "
              f"min={min(d_total)}, max={max(d_total)}")
        print(f"  Setup time:     mean={statistics.mean(d_setup):.0f}, "
              f"min={min(d_setup)}, max={max(d_setup)}")
        print(f"  Execution time: mean={statistics.mean(d_exec):.0f}, "
              f"min={min(d_exec)}, max={max(d_exec)}")
    
    print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(description='Benchmark Dandelion vs PoC')
    parser.add_argument('--runs', '-n', type=int, default=10,
                        help='Number of benchmark runs (default: 10)')
    parser.add_argument('--output-dir', '-o', type=str, 
                        default='/home/user/unikraft-rs-smp-runtime-poc',
                        help='Output directory for plots')
    parser.add_argument('--poc-only', action='store_true',
                        help='Only run PoC benchmarks')
    parser.add_argument('--dandelion-only', action='store_true',
                        help='Only run Dandelion benchmarks')
    
    args = parser.parse_args()
    
    results = BenchmarkResults()
    
    print(f"\n{'='*60}")
    print(f"  BENCHMARK: Dandelion vs PoC")
    print(f"  Runs: {args.runs}")
    print(f"{'='*60}")
    
    # Collect data
    for i in range(args.runs):
        print(f"\nRun {i+1}/{args.runs}:")
        
        if not args.dandelion_only:
            poc_ts = run_poc_benchmark()
            if poc_ts:
                results.poc_runs.append(poc_ts)
                print(f"    PoC: setup={poc_ts.user_space_setup_complete}μs, "
                      f"exec={poc_ts.after_user_execution - poc_ts.before_user_execution}μs")
        
        if not args.poc_only:
            dandelion_ts = run_dandelion_benchmark()
            if dandelion_ts:
                results.dandelion_runs.append(dandelion_ts)
                setup = dandelion_ts.engine_setup_end - dandelion_ts.engine_start
                exec_t = dandelion_ts.engine_exec_end - dandelion_ts.engine_setup_end
                print(f"    Dandelion: setup={setup}μs, exec={exec_t}μs")
    
    # Print summary
    print_summary(results)
    
    # Generate plots
    output_dir = Path(args.output_dir)
    
    if results.poc_runs and results.dandelion_runs:
        create_comparison_plot(results, str(output_dir / "benchmark_comparison.png"))
    
    if results.poc_runs:
        create_detailed_plot(results, str(output_dir / "benchmark_detailed.png"))
    
    print(f"\nBenchmark complete!")


if __name__ == "__main__":
    main()
