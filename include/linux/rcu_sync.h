/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * RCU-based infrastructure for lightweight reader-writer locking
 *
 * Copyright (c) 2015, Red Hat, Inc.
 *
 * Author: Oleg Nesterov <oleg@redhat.com>
 */

#ifndef _LINUX_RCU_SYNC_H_
#define _LINUX_RCU_SYNC_H_

#include <linux/wait.h>
#include <linux/rcupdate.h>

/* Structure to mediate between updaters and fastpath-using readers.  */
struct rcu_sync {
    int         gp_state;
    int         gp_count;
    wait_queue_head_t   gp_wait;

    struct rcu_head     cb_head;
};

/**
 * rcu_sync_is_idle() - Are readers permitted to use their fastpaths?
 * @rsp: Pointer to rcu_sync structure to use for synchronization
 *
 * Returns true if readers are permitted to use their fastpaths.  Must be
 * invoked within some flavor of RCU read-side critical section.
 */
static inline bool rcu_sync_is_idle(struct rcu_sync *rsp)
{
    return !READ_ONCE(rsp->gp_state); /* GP_IDLE */
}

#endif /* _LINUX_RCU_SYNC_H_ */
