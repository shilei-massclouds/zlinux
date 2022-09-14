/*
 * Read-Copy Update definitions shared among RCU implementations.
 *
 * Copyright IBM Corporation, 2011
 *
 * Author: Paul E. McKenney <paulmck@linux.ibm.com>
 */

#ifndef __LINUX_RCU_H
#define __LINUX_RCU_H

#define RCU_SCHEDULER_INACTIVE  0
#define RCU_SCHEDULER_INIT      1
#define RCU_SCHEDULER_RUNNING   2

/* Offset to allow distinguishing irq vs. task-based idle entry/exit. */
#define DYNTICK_IRQ_NONIDLE ((LONG_MAX / 2) + 1)

#endif /* __LINUX_RCU_H */
