/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_UACCESS_H
#define _ASM_RISCV_UACCESS_H

#include <asm/pgtable.h>        /* for TASK_SIZE */

/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define MAKE_MM_SEG(s)  ((mm_segment_t) { (s) })

#define KERNEL_DS   MAKE_MM_SEG(~0UL)
#define USER_DS     MAKE_MM_SEG(TASK_SIZE)

#endif /* _ASM_RISCV_UACCESS_H */
