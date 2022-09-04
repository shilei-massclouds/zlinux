/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BH_H
#define _LINUX_BH_H

#include <linux/instruction_pointer.h>
#include <linux/preempt.h>

static __always_inline void
__local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
    preempt_count_add(cnt);
    barrier();
}

extern void __local_bh_enable_ip(unsigned long ip, unsigned int cnt);

#endif /* _LINUX_BH_H */
