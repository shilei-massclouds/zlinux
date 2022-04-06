/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_PAGE_H
#define _ASM_RISCV_PAGE_H

#include <linux/const.h>

#define PAGE_SHIFT  (12)
#define PAGE_SIZE   (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK   (~(PAGE_SIZE - 1))

#define PAGE_OFFSET _AC(CONFIG_PAGE_OFFSET, UL)

#endif /* _ASM_RISCV_PAGE_H */
