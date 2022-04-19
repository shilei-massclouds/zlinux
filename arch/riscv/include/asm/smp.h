/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SMP_H
#define _ASM_RISCV_SMP_H

#include <linux/cpumask.h>
//#include <linux/irqreturn.h>
#include <linux/thread_info.h>

/*
 * Obtains the hart ID of the currently executing task.  This relies on
 * THREAD_INFO_IN_TASK, but we define that unconditionally.
 */
#define raw_smp_processor_id() (current_thread_info()->cpu)

#endif /* _ASM_RISCV_SMP_H */
