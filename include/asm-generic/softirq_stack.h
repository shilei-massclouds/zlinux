/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_GENERIC_SOFTIRQ_STACK_H
#define __ASM_GENERIC_SOFTIRQ_STACK_H

static inline void do_softirq_own_stack(void)
{
    __do_softirq();
}

#endif /* __ASM_GENERIC_SOFTIRQ_STACK_H */
