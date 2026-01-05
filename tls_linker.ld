/* TLS section definitions for Rust */

SECTIONS
{
    /* TLS sections */
    .tdata : {
        _tls_start = .;
        *(.tdata .tdata.*)
        _etdata = .;
    }
    
    .tbss : {
        *(.tbss .tbss.*)
        _tls_end = .;
    }
}

/* Insert TLS sections after .data but before .bss */
INSERT AFTER .data;
