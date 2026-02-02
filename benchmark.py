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
    buffer_allocation_complete: int = 0
    user_code_mapping_complete: int = 0
    user_stack_mapping_complete: int = 0
    interrupt_setup_complete: int = 0
    user_space_setup_complete: int = 0
    user_trampoline_setup_complete: int = 0
    patching_user_space_complete: int = 0
    boot_trampoline_setup_complete: int = 0
    ap_boot_complete: int = 0
    after_user_execution: int = 0


@dataclass
class DandelionTimestamps:
    """Timestamps from Dandelion benchmark (in microseconds)"""
    engine_start: int = 0
    buffer_allocation_complete: int = 0
    user_code_mapping_complete: int = 0
    user_stack_mapping_complete: int = 0
    interrupt_setup_complete: int = 0
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
        
        if name == "BUFFER_ALLOCATION_COMPLETE":
            timestamps.buffer_allocation_complete = micros
        elif name == "USER_CODE_MAPPING_COMPLETE":
            timestamps.user_code_mapping_complete = micros
        elif name == "USER_STACK_MAPPING_COMPLETE":
            timestamps.user_stack_mapping_complete = micros
        elif name == "INTERRUPT_SETUP_COMPLETE":
            timestamps.interrupt_setup_complete = micros
        elif name == "USER_SPACE_SETUP_COMPLETE":
            timestamps.user_space_setup_complete = micros
        elif name == "USER_TRAMPOLINE_SETUP_COMPLETE":
            timestamps.user_trampoline_setup_complete = micros
        elif name == "PATCHING_USER_SPACE_COMPLETE":
            timestamps.patching_user_space_complete = micros
        elif name == "BOOT_TRAMPOLINE_SETUP_COMPLETE":
            timestamps.boot_trampoline_setup_complete = micros
        elif name == "AP_BOOT_COMPLETE":
            timestamps.ap_boot_complete = micros
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
            (r'BufferAllocationComplete:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'buffer_allocation_complete'),
            (r'UserCodeMappingComplete:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'user_code_mapping_complete'),
            (r'UserStackMappingComplete:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'user_stack_mapping_complete'),
            (r'InterruptSetupComplete:\s*\d+\s*cycles\s*\((\d+)\s*μs\)', 'interrupt_setup_complete'),
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
                  f"exec={poc_ts.after_user_execution - poc_ts.ap_boot_complete}μs, "
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
    dandelion_critical_path = [dandelion_setup[i] + dandelion_exec[i] for i in range(len(dandelion_setup))]
    
    # PoC - Setup Critical Path = UserSpaceSetup + (PatchingUserSpace - UserTrampolineSetupComplete)
    poc_setup = [
        ts.user_space_setup_complete + (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
        for ts in results.poc_runs
    ]
    # Execution time = AfterUserExecution - ApBootComplete
    poc_exec = [ts.after_user_execution - ts.ap_boot_complete for ts in results.poc_runs]
    poc_critical_path = [poc_setup[i] + poc_exec[i] for i in range(len(poc_setup))]
    
    colors = {'dandelion': '#2ecc71', 'poc': '#3498db'}
    
    # Plot 1: Critical Path (Setup + Execution)
    ax1 = axes[0]
    bp1 = ax1.boxplot([dandelion_critical_path, poc_critical_path], 
                       labels=['KVM', 'Unikraft'],
                       patch_artist=True)
    bp1['boxes'][0].set_facecolor(colors['dandelion'])
    bp1['boxes'][1].set_facecolor(colors['poc'])
    ax1.set_ylabel('Time (μs)')
    ax1.set_title('Critical Path (Setup + Execution)')
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Setup Time
    ax2 = axes[1]
    bp2 = ax2.boxplot([dandelion_setup, poc_setup],
                       labels=['KVM', 'Unikraft'],
                       patch_artist=True)
    bp2['boxes'][0].set_facecolor(colors['dandelion'])
    bp2['boxes'][1].set_facecolor(colors['poc'])
    ax2.set_ylabel('Time (μs)')
    ax2.set_title('Setup Critical Path')
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
    
    add_stats_annotation(ax1, [dandelion_critical_path, poc_critical_path], [1, 2])
    add_stats_annotation(ax2, [dandelion_setup, poc_setup], [1, 2])
    add_stats_annotation(ax3, [dandelion_exec, poc_exec], [1, 2])
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved comparison plot to: {output_path}")
    plt.close()


def create_detailed_plot(results: BenchmarkResults, output_path: str):
    """Create the second plot: PoC detailed timing breakdown"""
    
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.suptitle('Unikraft PoC One Time Setup Timings', fontsize=14, fontweight='bold')
    
    # Prepare data - compute deltas between stages
    # User Trampoline Setup = UserTrampolineSetupComplete - UserSpaceSetupComplete
    user_trampoline_setup = [
        ts.user_trampoline_setup_complete - ts.user_space_setup_complete 
        for ts in results.poc_runs
    ]
    
    # Boot Trampoline Setup = BootTrampolineSetupComplete - PatchingUserSpaceComplete
    boot_trampoline_setup = [
        ts.boot_trampoline_setup_complete - ts.patching_user_space_complete
        for ts in results.poc_runs
    ]
    
    # AP Boot = ApBootComplete - BootTrampolineSetupComplete
    ap_boot = [
        ts.ap_boot_complete - ts.boot_trampoline_setup_complete
        for ts in results.poc_runs
    ]
    
    # All data for boxplot
    all_data = [
        user_trampoline_setup,
        boot_trampoline_setup,
        ap_boot,
    ]
    
    labels = [
        'User Trampoline\nSetup',
        'Boot Trampoline\nSetup',
        'AP Boot',
    ]
    
    colors = ['#e67e22', '#f39c12', '#27ae60']
    
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
    
    # Add total one-time setup annotation
    total_one_time = [
        (ts.user_trampoline_setup_complete - ts.user_space_setup_complete) +
        (ts.boot_trampoline_setup_complete - ts.patching_user_space_complete) +
        (ts.ap_boot_complete - ts.boot_trampoline_setup_complete)
        for ts in results.poc_runs
    ]
    total_mean = statistics.mean(total_one_time)
    ax.text(0.02, 0.98, f'Total One-Time Setup: {total_mean:.0f}μs',
            transform=ax.transAxes,
            fontsize=11,
            fontweight='bold',
            verticalalignment='top',
            horizontalalignment='left',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved detailed plot to: {output_path}")
    plt.close()


def create_setup_breakdown_plot(results: BenchmarkResults, output_path: str):
    """Create the third plot: Setup critical path breakdown showing stages up to and including PatchingUserSpaceComplete"""
    
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle('Unikraft PoC Setup Critical Path Breakdown', fontsize=14, fontweight='bold')
    
    # Compute stage durations (deltas between consecutive timestamps)
    # Stage 1: Buffer Allocation (0 -> BufferAllocationComplete)
    buffer_alloc = [ts.buffer_allocation_complete for ts in results.poc_runs]
    
    # Stage 2: User Code Mapping (BufferAllocationComplete -> UserCodeMappingComplete)
    user_code_mapping = [
        ts.user_code_mapping_complete - ts.buffer_allocation_complete
        for ts in results.poc_runs
    ]
    
    # Stage 3: User Stack Mapping (UserCodeMappingComplete -> UserStackMappingComplete)
    user_stack_mapping = [
        ts.user_stack_mapping_complete - ts.user_code_mapping_complete
        for ts in results.poc_runs
    ]
    
    # Stage 4: Interrupt Setup (UserStackMappingComplete -> InterruptSetupComplete)
    interrupt_setup = [
        ts.interrupt_setup_complete - ts.user_stack_mapping_complete
        for ts in results.poc_runs
    ]
    
    # Stage 5: Remaining Setup + Patching
    # This is: (InterruptSetupComplete -> UserSpaceSetupComplete) + (UserTrampolineSetupComplete -> PatchingUserSpaceComplete)
    # Together with stages 1-4, this sums to the critical path from Plot 1
    remaining_and_patching = [
        (ts.user_space_setup_complete - ts.interrupt_setup_complete) +
        (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
        for ts in results.poc_runs
    ]
    
    # All data for boxplot
    all_data = [
        buffer_alloc,
        user_code_mapping,
        user_stack_mapping,
        interrupt_setup,
        remaining_and_patching,
    ]
    
    labels = [
        'Buffer Mapping\n& Paging Setup',
        'User Code\nMapping',
        'User Stack\nMapping',
        'Interrupt\nSetup',
        'Remaining Setup\n& Patching',
    ]
    
    # Use a colorful palette
    colors = ['#3498db', '#2ecc71', '#9b59b6', '#e74c3c', '#f39c12']
    
    bp = ax.boxplot(all_data, labels=labels, patch_artist=True)
    
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax.set_ylabel('Time (μs)')
    ax.set_xlabel('Setup Stage')
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add mean annotations
    for i, data in enumerate(all_data):
        if data:
            mean = statistics.mean(data)
            # Position annotation above the box
            max_val = max(data) if max(data) > 0 else 1
            ax.annotate(f'{mean:.0f}μs', 
                       xy=(i + 1, mean), 
                       xytext=(i + 1, max_val + max_val * 0.15),
                       ha='center',
                       fontsize=9,
                       fontweight='bold')
    
    # Add total setup time annotation
    total_setup = [ts.user_space_setup_complete + (ts.patching_user_space_complete - ts.user_trampoline_setup_complete) for ts in results.poc_runs]
    total_mean = statistics.mean(total_setup)
    ax.text(0.98, 0.98, f'Total Setup: {total_mean:.0f}μs',
            transform=ax.transAxes,
            fontsize=11,
            fontweight='bold',
            verticalalignment='top',
            horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved setup breakdown plot to: {output_path}")
    plt.close()


def create_setup_comparison_plot(results: BenchmarkResults, output_path: str):
    """Create the fourth plot: Side-by-side comparison of setup stages between KVM and Unikraft"""
    
    fig, ax = plt.subplots(figsize=(14, 7))
    fig.suptitle('KVM vs Unikraft: Setup Stage Comparison', fontsize=14, fontweight='bold')
    
    # Compute Dandelion stage durations (relative to EngineStart)
    # These must sum to: engine_setup_end - engine_start (the critical path from Plot 1)
    
    # Stage 1: Buffer Allocation (EngineStart -> BufferAllocationComplete)
    dandelion_buffer_alloc = [
        max(0, ts.buffer_allocation_complete - ts.engine_start)
        for ts in results.dandelion_runs
    ]
    
    # Stage 2: User Code Mapping (BufferAllocationComplete -> UserCodeMappingComplete)
    dandelion_user_code_mapping = [
        max(0, ts.user_code_mapping_complete - ts.buffer_allocation_complete)
        for ts in results.dandelion_runs
    ]
    
    # Stage 3: User Stack Mapping (UserCodeMappingComplete -> UserStackMappingComplete)
    dandelion_user_stack_mapping = [
        max(0, ts.user_stack_mapping_complete - ts.user_code_mapping_complete)
        for ts in results.dandelion_runs
    ]
    
    # Stage 4: Final Setup (UserStackMappingComplete -> EngineSetupEnd)
    dandelion_final_setup = [
        max(0, ts.engine_setup_end - ts.user_stack_mapping_complete)
        for ts in results.dandelion_runs
    ]
    
    # Compute PoC stage durations
    # These must sum to: user_space_setup_complete + (patching_user_space_complete - user_trampoline_setup_complete)
    # which is the critical path from Plot 1
    
    # Stage 1: Buffer Allocation (0 -> BufferAllocationComplete)
    poc_buffer_alloc = [max(0, ts.buffer_allocation_complete) for ts in results.poc_runs]
    
    # Stage 2: User Code Mapping (BufferAllocationComplete -> UserCodeMappingComplete)
    poc_user_code_mapping = [
        max(0, ts.user_code_mapping_complete - ts.buffer_allocation_complete)
        for ts in results.poc_runs
    ]
    
    # Stage 3: User Stack Mapping (UserCodeMappingComplete -> UserStackMappingComplete)
    poc_user_stack_mapping = [
        max(0, ts.user_stack_mapping_complete - ts.user_code_mapping_complete)
        for ts in results.poc_runs
    ]
    
    # Stage 4: Final Setup = (UserStackMappingComplete -> UserSpaceSetupComplete) + (UserTrampolineSetupComplete -> PatchingUserSpaceComplete)
    # This includes: interrupt setup + any remaining user space setup + patching
    poc_final_setup = [
        max(0, (ts.user_space_setup_complete - ts.user_stack_mapping_complete) + 
            (ts.patching_user_space_complete - ts.user_trampoline_setup_complete))
        for ts in results.poc_runs
    ]
    
    # Setup grouped bar chart
    stages = ['Buffer Alloc\n& Page Setup', 'User Code\nMapping', 'User Stack\nMapping', 'Final Setup\n& Patching']
    x = np.arange(len(stages))
    width = 0.35
    
    # Calculate means for bar heights
    dandelion_means = [
        statistics.mean(dandelion_buffer_alloc) if dandelion_buffer_alloc else 0,
        statistics.mean(dandelion_user_code_mapping) if dandelion_user_code_mapping else 0,
        statistics.mean(dandelion_user_stack_mapping) if dandelion_user_stack_mapping else 0,
        statistics.mean(dandelion_final_setup) if dandelion_final_setup else 0,
    ]
    
    poc_means = [
        statistics.mean(poc_buffer_alloc) if poc_buffer_alloc else 0,
        statistics.mean(poc_user_code_mapping) if poc_user_code_mapping else 0,
        statistics.mean(poc_user_stack_mapping) if poc_user_stack_mapping else 0,
        statistics.mean(poc_final_setup) if poc_final_setup else 0,
    ]
    
    # Calculate standard deviations for error bars
    dandelion_stds = [
        statistics.stdev(dandelion_buffer_alloc) if len(dandelion_buffer_alloc) > 1 else 0,
        statistics.stdev(dandelion_user_code_mapping) if len(dandelion_user_code_mapping) > 1 else 0,
        statistics.stdev(dandelion_user_stack_mapping) if len(dandelion_user_stack_mapping) > 1 else 0,
        statistics.stdev(dandelion_final_setup) if len(dandelion_final_setup) > 1 else 0,
    ]
    
    poc_stds = [
        statistics.stdev(poc_buffer_alloc) if len(poc_buffer_alloc) > 1 else 0,
        statistics.stdev(poc_user_code_mapping) if len(poc_user_code_mapping) > 1 else 0,
        statistics.stdev(poc_user_stack_mapping) if len(poc_user_stack_mapping) > 1 else 0,
        statistics.stdev(poc_final_setup) if len(poc_final_setup) > 1 else 0,
    ]
    
    colors = {'dandelion': '#2ecc71', 'poc': '#3498db'}
    
    # Clip lower error bars to not go below zero (use asymmetric error bars)
    dandelion_lower = [min(std, mean) for std, mean in zip(dandelion_stds, dandelion_means)]
    poc_lower = [min(std, mean) for std, mean in zip(poc_stds, poc_means)]
    
    bars1 = ax.bar(x - width/2, dandelion_means, width, label='KVM', 
                   color=colors['dandelion'], alpha=0.8, 
                   yerr=[dandelion_lower, dandelion_stds], capsize=5)
    bars2 = ax.bar(x + width/2, poc_means, width, label='Unikraft',
                   color=colors['poc'], alpha=0.8, 
                   yerr=[poc_lower, poc_stds], capsize=5)
    
    ax.set_ylabel('Time (μs)')
    ax.set_xlabel('Setup Stage')
    ax.set_xticks(x)
    ax.set_xticklabels(stages)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    def add_bar_labels(bars, values):
        for bar, val in zip(bars, values):
            if val > 0:
                height = bar.get_height()
                ax.annotate(f'{val:.0f}',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3),
                           textcoords="offset points",
                           ha='center', va='bottom',
                           fontsize=8, fontweight='bold')
    
    add_bar_labels(bars1, dandelion_means)
    add_bar_labels(bars2, poc_means)
    
    # Add total annotations to verify sums match Plot 1
    dandelion_total = sum(dandelion_means)
    poc_total = sum(poc_means)
    
    ax.text(0.02, 0.98, f'KVM Total: {dandelion_total:.0f}μs\nUnikraft Total: {poc_total:.0f}μs',
            transform=ax.transAxes,
            fontsize=10,
            fontweight='bold',
            verticalalignment='top',
            horizontalalignment='left',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved setup comparison plot to: {output_path}")
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
        # Setup Critical Path = UserSpaceSetup + (PatchingUserSpace - UserTrampolineSetupComplete)
        poc_setup = [
            ts.user_space_setup_complete + (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
            for ts in results.poc_runs
        ]
        # Execution time = AfterUserExecution - ApBootComplete
        poc_exec = [ts.after_user_execution - ts.ap_boot_complete for ts in results.poc_runs]
        
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
    
    # Data consistency verification
    print("\n--- Data Consistency Check ---")
    
    if results.poc_runs:
        # Plot 1 PoC Setup Critical Path
        plot1_poc_setup = [
            ts.user_space_setup_complete + (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
            for ts in results.poc_runs
        ]
        
        # Plot 3 stages sum (should equal Plot 1)
        plot3_poc_sum = [
            ts.buffer_allocation_complete +
            (ts.user_code_mapping_complete - ts.buffer_allocation_complete) +
            (ts.user_stack_mapping_complete - ts.user_code_mapping_complete) +
            (ts.interrupt_setup_complete - ts.user_stack_mapping_complete) +
            (ts.user_space_setup_complete - ts.interrupt_setup_complete) +
            (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
            for ts in results.poc_runs
        ]
        
        # Plot 4 PoC stages sum (should equal Plot 1)
        plot4_poc_sum = [
            ts.buffer_allocation_complete +
            (ts.user_code_mapping_complete - ts.buffer_allocation_complete) +
            (ts.user_stack_mapping_complete - ts.user_code_mapping_complete) +
            (ts.user_space_setup_complete - ts.user_stack_mapping_complete) +
            (ts.patching_user_space_complete - ts.user_trampoline_setup_complete)
            for ts in results.poc_runs
        ]
        
        print(f"  PoC Plot 1 Setup Critical Path: mean={statistics.mean(plot1_poc_setup):.1f}μs")
        print(f"  PoC Plot 3 Stages Sum:          mean={statistics.mean(plot3_poc_sum):.1f}μs")
        print(f"  PoC Plot 4 Stages Sum:          mean={statistics.mean(plot4_poc_sum):.1f}μs")
        
        # Check if they match
        poc_match = abs(statistics.mean(plot1_poc_setup) - statistics.mean(plot3_poc_sum)) < 0.1 and \
                    abs(statistics.mean(plot1_poc_setup) - statistics.mean(plot4_poc_sum)) < 0.1
        print(f"  PoC consistency: {'✓ PASS' if poc_match else '✗ FAIL'}")
    
    if results.dandelion_runs:
        # Plot 1 Dandelion Setup
        plot1_dandelion_setup = [ts.engine_setup_end - ts.engine_start for ts in results.dandelion_runs]
        
        # Plot 4 Dandelion stages sum (should equal Plot 1)
        plot4_dandelion_sum = [
            max(0, ts.buffer_allocation_complete - ts.engine_start) +
            max(0, ts.user_code_mapping_complete - ts.buffer_allocation_complete) +
            max(0, ts.user_stack_mapping_complete - ts.user_code_mapping_complete) +
            max(0, ts.engine_setup_end - ts.user_stack_mapping_complete)
            for ts in results.dandelion_runs
        ]
        
        print(f"  Dandelion Plot 1 Setup:         mean={statistics.mean(plot1_dandelion_setup):.1f}μs")
        print(f"  Dandelion Plot 4 Stages Sum:    mean={statistics.mean(plot4_dandelion_sum):.1f}μs")
        
        # Check if they match
        dandelion_match = abs(statistics.mean(plot1_dandelion_setup) - statistics.mean(plot4_dandelion_sum)) < 0.1
        print(f"  Dandelion consistency: {'✓ PASS' if dandelion_match else '✗ FAIL'}")
    
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
                      f"exec={poc_ts.after_user_execution - poc_ts.ap_boot_complete}μs")
        
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
        create_setup_comparison_plot(results, str(output_dir / "benchmark_setup_comparison.png"))
    
    if results.poc_runs:
        create_detailed_plot(results, str(output_dir / "benchmark_detailed.png"))
        create_setup_breakdown_plot(results, str(output_dir / "benchmark_setup_breakdown.png"))
    
    print(f"\nBenchmark complete!")


if __name__ == "__main__":
    main()
