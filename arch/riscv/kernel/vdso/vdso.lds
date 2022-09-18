OUTPUT_ARCH(riscv)
SECTIONS
{
    PROVIDE(_vdso_data = . - 2 * (1 << (12)));
    PROVIDE(_timens_data = _vdso_data + (1 << (12)));
    . = SIZEOF_HEADERS;
    .hash : { *(.hash) } :text
    .gnu.hash : { *(.gnu.hash) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .gnu.version : { *(.gnu.version) }
    .gnu.version_d : { *(.gnu.version_d) }
    .gnu.version_r : { *(.gnu.version_r) }
    .note : { *(.note.*) } :text :note
    .dynamic : { *(.dynamic) } :text :dynamic
    .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
    .eh_frame : { KEEP (*(.eh_frame)) } :text
    .rodata : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
    . = 0x800;
    .text : { *(.text .text.*) } :text
    .data : {
        *(.got.plt) *(.got)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
    }
}
PHDRS
{
    text PT_LOAD FLAGS(5) FILEHDR PHDRS;
    dynamic PT_DYNAMIC FLAGS(4);
    note PT_NOTE FLAGS(4);
    eh_frame_hdr PT_GNU_EH_FRAME;
}
VERSION
{
    LINUX_4.15 {
    global:
        __vdso_rt_sigreturn;
        __vdso_gettimeofday;
        __vdso_clock_gettime;
        __vdso_clock_getres;
        __vdso_getcpu;
        __vdso_flush_icache;
    local: *;
    };
}
