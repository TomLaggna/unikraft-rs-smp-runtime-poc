# Visual Architecture Guide: Multi-Core CPU Startup

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Physical Memory Layout                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  0x00000000  ┌────────────────────────────────────────────────┐   │
│              │          BIOS/Bootloader Code                 │   │
│  0x000FFFFF  │     (Real mode accessible, first 1 MiB)       │   │
│              ├────────────────────────────────────────────────┤   │
│              │  0x8000: Boot Trampoline (4 KiB)  ◄── CRITICAL│   │
│              │          • 16-bit real mode code              │   │
│              │          • 32-bit GDT/code                    │   │
│              │          • 64-bit GDT/code                    │   │
│              └────────────────────────────────────────────────┘   │
│                                                                     │
│  0x00100000  ┌────────────────────────────────────────────────┐   │
│              │     Kernel/Application Code                    │   │
│              │         (64-bit mode)                          │   │
│              ├────────────────────────────────────────────────┤   │
│              │  Page Tables (PML4, PDPT, PD, PT)             │   │
│              ├────────────────────────────────────────────────┤   │
│              │  AP Stack #1 (8 KiB)                          │   │
│              │  AP Stack #2 (8 KiB)                          │   │
│              │  ...                                           │   │
│              │  AP Stack #N (8 KiB)                          │   │
│              ├────────────────────────────────────────────────┤   │
│              │  Per-CPU Data (TLS, LCPU struct, etc)         │   │
│              └────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## CPU Startup State Machine

```
┌─────────┐
│  OFFLINE│  (Before startup)
└────┬────┘
     │ call start_ap()
     ▼
┌─────────────────────────────────────────────────────────┐
│ 1. APIC INIT IPI                                        │
│    - Send INIT to target APIC ID                        │
│    - Target CPU resets to 16-bit real mode at 0xFFFF0  │
│    - Wait 10 milliseconds                               │
└────┬────────────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────────────────┐
│ 2. SIPI #1 (First Start-up IPI)                          │
│    - Send SIPI with vector = boot_addr >> 12            │
│    - CPU jumps to boot_addr (0x8000) in 16-bit mode     │
│    - Boot code begins execution                          │
│    - Wait 200 microseconds                               │
└────┬───────────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────────────────┐
│ 3. SIPI #2 (Second Start-up IPI)                         │
│    - Send same SIPI again (per Intel manual)             │
│    - Some CPUs may have missed first, this retries       │
│    - Wait 200 microseconds                               │
└────┬───────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ BOOT CODE EXECUTION (Boot Trampoline)                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  16-bit Real Mode:                                           │
│  ├─ Set up basic CPU state                                  │
│  ├─ Load 32-bit GDT                                         │
│  └─ Jump to 32-bit code                                     │
│                                                               │
│  32-bit Protected Mode:                                      │
│  ├─ Enable PAE (CR4.PAE)                                    │
│  ├─ Enable Long Mode (EFER.LME via MSR)                     │
│  ├─ Load 64-bit GDT                                         │
│  ├─ Load page tables (CR3)                                  │
│  ├─ Enable paging (CR0.PG)                                  │
│  └─ Jump to 64-bit code                                     │
│                                                               │
│  64-bit Long Mode:                                           │
│  ├─ Get APIC ID (CPUID.1:EBX[31:24])                        │
│  ├─ Load RSP (stack pointer)                                │
│  ├─ Load RDI (APIC ID or other parameter)                   │
│  └─ Call entry function pointer (e.g., ap_main)             │
│                                                               │
└────┬────────────────────────────────────────────────────────┘
     │
     ▼
┌──────────────┐
│   AP RUNNING │  (Entry function called)
└──────────────┘
```

## Boot Trampoline Memory Layout

```
At Physical Address 0x8000 (page-aligned):

0x8000  ┌────────────────────────────┐
        │ lcpu_start16_ap:           │  16-bit real mode entry
        │ • Real mode initialization │  (SIPI vector jumps here)
0x8100  │ • Protected mode setup     │
        │ • Far jump to 32-bit code  │  4 KiB total
0x8200  ├────────────────────────────┤
        │ GDT32 Table                │  32-bit GDT for protected mode
        │ • Null descriptor          │
        │ • Code32 descriptor        │
        │ • Data32 descriptor        │
0x8300  ├────────────────────────────┤
        │ jump_to32:                 │  32-bit code
        │ • PAE setup (CR4)          │
        │ • Long mode enable (EFER)  │
        │ • Load page tables (CR3)   │
        │ • Enable paging (CR0)      │
        │ • Far jump to 64-bit code  │
0x8400  ├────────────────────────────┤
        │ GDT64 Table                │  64-bit GDT for long mode
        │ • Null descriptor          │
        │ • Code64 descriptor        │
        │ • Data64 descriptor        │
0x8500  ├────────────────────────────┤
        │ jump_to64:                 │  64-bit code
        │ • Get APIC ID              │
        │ • Setup registers          │
        │ • Call AP entry function   │
0x8FFF  └────────────────────────────┘
```

## x2APIC IPI (Inter-Processor Interrupt) Flow

```
┌─────────────────────────────────────────────────────────────────┐
│             Sending IPI via x2APIC (MSR interface)              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INIT IPI (Reset target CPU):                                   │
│  ┌─ Read MSR 0x1b (IA32_APIC_BASE)                             │
│  ├─ Enable x2APIC mode bit (0x400)                             │
│  ├─ Write MSR 0x80f (APIC_SVR) to enable software              │
│  ├─ Set ICR (Interrupt Command Register):                      │
│  │  • Bits [63:32] = Destination APIC ID                       │
│  │  • Bits [31:0]  = Command:                                  │
│  │    - Bit 15: Trigger (level)                                │
│  │    - Bit 14: Level (assert)                                 │
│  │    - Bits [10:8] = Delivery mode (5 = INIT)                 │
│  ├─ Write MSR 0x830 with ICR value                             │
│  └─ CPU asserts INIT signal to target                          │
│                                                                  │
│  SIPI (Start-up IPI):                                           │
│  ┌─ Set ICR with:                                              │
│  │  • Delivery mode = 6 (Start-up)                             │
│  │  • Vector = boot_address >> 12                              │
│  │    (e.g., 0x8000 >> 12 = 0x8)                               │
│  ├─ Write MSR 0x830                                            │
│  └─ CPU fetches boot code from [vector << 12]                 │
│                                                                  │
│  NMI (for other purposes):                                      │
│  ┌─ Set ICR with:                                              │
│  │  • Delivery mode = 4 (NMI)                                  │
│  │  • Vector bits ignored                                      │
│  └─ Write MSR 0x830                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

ICR Register Format (x2APIC):
┌─────────────────────────────────────────────┐
│ Bits [63:32]: Destination APIC ID           │
├─────────────────────────────────────────────┤
│ Bits [31:20]: Reserved (0)                  │
│ Bits [19:16]: Reserved (0)                  │
│ Bits [15:15]: Trigger Mode (1=Level)        │
│ Bits [14:14]: Level (1=Assert)              │
│ Bits [13:11]: Reserved (0)                  │
│ Bits [10:8]:  Delivery Mode:                │
│               • 0 = Fixed                   │
│               • 4 = NMI                     │
│               • 5 = INIT                    │
│               • 6 = Start-up (SIPI)         │
│ Bits [7:0]:   Vector (0-255)                │
│               For SIPI: Vector = addr >> 12│
└─────────────────────────────────────────────┘
```

## Execution Timeline

```
TIME  EVENT                         DETAIL
────  ─────────────────────────────  ────────────────────────────
T+0   Send INIT IPI                 BSP sends INIT to target APIC
      │                             
      ├─ Target CPU receives        
      ├─ CPU resets to 0xFFFF0      
      ├─ Clears cache, TLB          
      
T+10ms Send SIPI #1                 Wait 10ms per Intel manual
      │
      ├─ Target CPU jumps to 0x8000 (boot code)
      ├─ Executes 16-bit real mode code
      ├─ Transitions to 32-bit mode
      ├─ Transitions to 64-bit mode
      
T+10.2ms Send SIPI #2               Wait 200µs per Intel manual
      │
      ├─ Retransmit (some CPUs might have missed)
      
T+10.4ms Boot complete (if quick)   AP entry function called
      │
      ├─ AP now running Rust code
      ├─ per-CPU initialization
      ├─ Signal ready via atomic
      
T+timeout BSP detects AP ready      BSP sees atomic bit set
      │
      ├─ Move to next AP or continue
```

## Data Flow Diagram

```
         ┌─────────────────────────┐
         │   Rust Application      │
         │  (BSP - Bootstrap CPU)  │
         └──────────┬──────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │ enable_x2apic()                         │
         │ • Check CPUID for x2APIC support        │
         │ • Enable IA32_APIC_BASE.EXTD            │
         │ • Enable IA32_APIC_SVR.EN               │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │ copy_boot_code(src, 0x8000)             │
         │ • Copy assembly from ROM to RAM         │
         │ • Located at 0x8000 (first 1 MiB)       │
         │ • Must be page-aligned                  │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │ start_ap(config)                        │
         │ • Send INIT IPI                         │
         │ • Wait 10ms                             │
         │ • Send SIPI #1                          │
         │ • Wait 200µs                            │
         │ • Send SIPI #2                          │
         └──────────┬──────────────────────────────┘
                    │
                    │ APIC IPI via x2APIC (MSRs)
                    │
         ┌──────────▼──────────────────────────────┐
         │       Target CPU (AP)                   │
         │    (Receives IPI vector)                │
         │ • CPU jumps to 0x8000                   │
         │ • Boot trampoline code executes         │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │  Boot Trampoline (Assembly)             │
         │ • 16-bit real mode                      │
         │ • 32-bit protected mode                 │
         │ • 64-bit long mode                      │
         │ • Gets APIC ID from CPUID               │
         │ • Loads RSP, RDI                        │
         │ • Calls entry_fn(apic_id)               │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │   AP Entry Function (ap_main)           │
         │   (User-provided Rust code)             │
         │ • setup_per_cpu_data(apic_id)           │
         │ • init_cpu_state()                      │
         │ • signal_ap_ready(apic_id)              │
         │ • Enter scheduler loop                  │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────▼──────────────────────────────┐
         │   Atomic Flag: AP_READY_MASK            │
         │   (Lock-free synchronization)           │
         │ • AP sets bit for its APIC ID           │
         │ • BSP waits for bit via atomic load     │
         └──────────────────────────────────────────┘
         
         ┌──────────────────────────────────────────┐
         │   BSP detects AP ready                   │
         │   • Boot all remaining APs or continue  │
         └──────────────────────────────────────────┘
```

## Key Addressing Details

```
SIPI Vector to Physical Address Conversion:

SIPI Vector (8 bits from ICR):
┌─────────────────────────────┐
│ Bits [7:0] from ICR         │  Example: 0x8 (for 0x8000)
└─────────────┬───────────────┘
              │
              ▼ Multiply by 4096 (or shift left 12 bits)
              │
              ▼
Physical Address: vector << 12
                = 0x8 << 12
                = 0x8000

So SIPI vector 0x8 → CPU jumps to physical address 0x8000
   SIPI vector 0x10 → CPU jumps to physical address 0x10000
```

## Page Table Identity Mapping (Simplified)

```
Virtual Address = Physical Address (for first 1 MiB during boot)

Virtual  ├─ 0x000000 ──────────────┐
         │                          │
         ├─ 0x008000 ←─ Boot code  │  Identity mapped
         │                          │  (VA == PA)
         ├─ 0x010000 ──────────────┤
         │                          │
         └─ 0x100000 ──────────────┘

Paging structure (simplified):
PML4[0] → PDPT[0] → PD[0] → PT[0] → 0x000000 (PA)
                                  → 0x001000 (PA)
                                  → ...
                                  → 0x008000 (PA) ← Boot code
                                  → ...
                                  → 0x0FF000 (PA)
```

## Common Failure Points

```
┌──────────────────────────────────────────────────────────┐
│ FAILURE: AP doesn't start at all                         │
├──────────────────────────────────────────────────────────┤
│ Causes:                                                  │
│ ├─ Boot code not at 0x8000                              │
│ ├─ Boot code not page-aligned                           │
│ ├─ First 1 MiB not identity-mapped                      │
│ ├─ SIPI vector calculation wrong                        │
│ └─ x2APIC not enabled on BSP                            │
│                                                          │
│ Debug:                                                   │
│ ├─ Print boot_code_addr before copy                     │
│ ├─ Verify 0x8000 % 4096 == 0                            │
│ ├─ Check page table entries for 0x8000                  │
│ └─ Call enable_x2apic() explicitly                      │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ FAILURE: AP starts but crashes immediately              │
├──────────────────────────────────────────────────────────┤
│ Causes:                                                  │
│ ├─ Stack pointer invalid → writes to bad memory         │
│ ├─ Entry function not extern "C"                        │
│ ├─ GDT/IDT not initialized on AP                        │
│ ├─ Long mode paging not set up                          │
│ └─ RIP not pointing to valid code                       │
│                                                          │
│ Debug:                                                   │
│ ├─ Print from entry_fn first thing                      │
│ ├─ Use `extern "C" fn` for entry function               │
│ ├─ Setup IDT/GDT in entry_fn immediately                │
│ └─ Verify stack_ptr is valid and writable               │
└──────────────────────────────────────────────────────────┘
```

---

This visual guide should help you understand the architecture and data flow of the multi-core startup process.

