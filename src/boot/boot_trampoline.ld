/* boot_trampoline.ld - Linker script for standalone trampoline binary */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(lcpu_start16_ap)

SECTIONS {
    /* All code and data should be contiguous and start at 0x0 */
    /* Will be copied to 0x8000 at runtime */
    . = 0x0;
    
    .boot : {
        /* 16-bit real mode code - MUST be first (entry point) */
        *(.text.boot.16)
        
        /* 32-bit protected mode data (GDT tables) */
        *(.data.boot.32)
        
        /* 32-bit protected mode code */
        *(.text.boot.32)
        
        /* 64-bit long mode code */
        *(.text.boot.64)
        
        /* Runtime data structures (must be part of copied blob) */
        *(.data)
    }
    
    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame)
    }
}
