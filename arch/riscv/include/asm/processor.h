/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PROCESSOR_H
#define _ASM_RISCV_PROCESSOR_H

#include <linux/const.h>

#include <vdso/processor.h>

#include <asm/ptrace.h>

#ifndef __ASSEMBLY__

struct device_node;
int riscv_of_processor_hartid(struct device_node *node);

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PROCESSOR_H */
