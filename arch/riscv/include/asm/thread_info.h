/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_THREAD_INFO_H
#define _ASM_RISCV_THREAD_INFO_H

#include <asm/page.h>

#define THREAD_SIZE_ORDER (2)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

#endif /* _ASM_RISCV_THREAD_INFO_H */
