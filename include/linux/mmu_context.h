/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMU_CONTEXT_H
#define _LINUX_MMU_CONTEXT_H

//#include <asm/mmu_context.h>
//#include <asm/mmu.h>

/*
 * CPUs that are capable of running user task @p. Must contain at least one
 * active CPU. It is assumed that the kernel can run on all CPUs, so calling
 * this for a kernel thread is pointless.
 *
 * By default, we assume a sane, homogeneous system.
 */
# define task_cpu_possible_mask(p)  cpu_possible_mask
# define task_cpu_possible(cpu, p)  true

#endif /* _LINUX_MMU_CONTEXT_H */
