/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/linkage.h>
#include <asm/asm.h>

/* void *memset(void *, int, size_t) */
ENTRY(__memset)
WEAK(memset)
    move t0, a0  /* Preserve return value */

    ret
END(__memset)
