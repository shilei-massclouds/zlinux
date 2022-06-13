/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 *
 * Copyright IBM Corporation, 2008
 *
 * Author: Dipankar Sarma <dipankar@in.ibm.com>
 *     Paul E. McKenney <paulmck@linux.ibm.com> Hierarchical algorithm
 *
 * Based on the original work by Paul McKenney <paulmck@linux.ibm.com>
 * and inputs from Rusty Russell, Andrea Arcangeli and Andi Kleen.
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *  Documentation/RCU
 */

#ifndef __LINUX_RCUTREE_H
#define __LINUX_RCUTREE_H

void rcu_scheduler_starting(void);

#endif /* __LINUX_RCUTREE_H */
