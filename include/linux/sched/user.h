/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_USER_H
#define _LINUX_SCHED_USER_H

#include <linux/uidgid.h>
#include <linux/atomic.h>
#include <linux/percpu_counter.h>
#include <linux/refcount.h>
#include <linux/ratelimit.h>

/*
 * Some day this will be a full-fledged user tracking system..
 */
struct user_struct {
    refcount_t __count; /* reference count */
    struct percpu_counter epoll_watches; /* The number of file descriptors currently watched */
    unsigned long unix_inflight;    /* How many files in flight in unix sockets */
    atomic_long_t pipe_bufs;  /* how many pages are allocated in pipe buffers */

    /* Hash table maintenance information */
    struct hlist_node uidhash_node;
    kuid_t uid;

    atomic_long_t locked_vm;

    /* Miscellaneous per-user rate limit */
    struct ratelimit_state ratelimit;
};

/* per-UID process charging. */
extern struct user_struct *alloc_uid(kuid_t);
static inline struct user_struct *get_uid(struct user_struct *u)
{
    refcount_inc(&u->__count);
    return u;
}
extern void free_uid(struct user_struct *);

extern struct user_struct root_user;
#define INIT_USER (&root_user)

#endif /* _LINUX_SCHED_USER_H */
