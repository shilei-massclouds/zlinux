/* SPDX-License-Identifier: GPL-2.0-only */

#define LOAD_OFFSET PAGE_OFFSET
#include <asm/page.h>

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
	/* Beginning of code and text segment */
	. = LOAD_OFFSET;
}
