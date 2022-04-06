/* SPDX-License-Identifier: GPL-2.0-only */

#define LOAD_OFFSET PAGE_OFFSET
#include <asm/vmlinux.lds.h>
#include <asm/page.h>

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
}
