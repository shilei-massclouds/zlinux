/* SPDX-License-Identifier: GPL-2.0-only */

#define LOAD_OFFSET PAGE_OFFSET
#include <asm/vmlinux.lds.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/thread_info.h>
#include <asm/set_memory.h>

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
	/* Beginning of code and text segment */
	. = LOAD_OFFSET;
    _start = .;
    _stext = .;
    HEAD_TEXT_SECTION
    . = ALIGN(PAGE_SIZE);

    __init_begin = .;
    INIT_TEXT_SECTION(PAGE_SIZE)
    INIT_DATA_SECTION(16)
    . = ALIGN(8);
    __init_end = .;

    . = ALIGN(SECTION_ALIGN);
    .text : {
        _text = .;
        TEXT_TEXT
        _etext = .;
    }

    /* Start of data section */
    _sdata = .;
    RO_DATA(SECTION_ALIGN)
    .srodata : {
        *(.srodata*)
    }

    . = ALIGN(SECTION_ALIGN);
    _data = .;

    RW_DATA(L1_CACHE_BYTES, PAGE_SIZE, THREAD_SIZE)
    .sdata : {
        __global_pointer$ = . + 0x800;
        *(.sdata*)
        /* End of data section */
        _edata = .;
    }

    BSS_SECTION(PAGE_SIZE, PAGE_SIZE, 0)

    _end = .;
}
