/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 * Internal non-public definitions.
 *
 * Copyright IBM Corporation, 2008
 *
 * Author: Ingo Molnar <mingo@elte.hu>
 *     Paul E. McKenney <paulmck@linux.ibm.com>
 */

#include <linux/cache.h>
#include <linux/spinlock.h>
/*
#include <linux/rtmutex.h>
#include <linux/threads.h>
*/
#include <linux/cpumask.h>
/*
#include <linux/seqlock.h>
#include <linux/swait.h>
#include <linux/rcu_node_tree.h>
*/

//#include "rcu_segcblist.h"

