/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion
 */
#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/preempt.h>
#include <asm/processor.h>

/* Exported common interfaces */
void call_rcu(struct rcu_head *head, rcu_callback_t func);

void synchronize_rcu(void);

#endif /* __LINUX_RCUPDATE_H */
