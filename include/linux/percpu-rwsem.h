/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PERCPU_RWSEM_H
#define _LINUX_PERCPU_RWSEM_H

#include <linux/atomic.h>
#include <linux/percpu.h>
#if 0
#include <linux/rcuwait.h>
#include <linux/rcu_sync.h>
#endif
#include <linux/wait.h>
#include <linux/lockdep.h>

struct percpu_rw_semaphore {
    //struct rcu_sync     rss;
    unsigned int __percpu   *read_count;
    //struct rcuwait      writer;
    wait_queue_head_t   waiters;
    atomic_t            block;
};

#define __PERCPU_RWSEM_DEP_MAP_INIT(lockname)

#define __DEFINE_PERCPU_RWSEM(name, is_static)              \
static DEFINE_PER_CPU(unsigned int, __percpu_rwsem_rc_##name);      \
is_static struct percpu_rw_semaphore name = {               \
    /* .rss = __RCU_SYNC_INITIALIZER(name.rss), */            \
    .read_count = &__percpu_rwsem_rc_##name,            \
    /* .writer = __RCUWAIT_INITIALIZER(name.writer), */           \
    .waiters = __WAIT_QUEUE_HEAD_INITIALIZER(name.waiters),     \
    .block = ATOMIC_INIT(0),                    \
    __PERCPU_RWSEM_DEP_MAP_INIT(name)               \
}

#define DEFINE_PERCPU_RWSEM(name)       \
    __DEFINE_PERCPU_RWSEM(name, /* not static */)
#define DEFINE_STATIC_PERCPU_RWSEM(name)    \
    __DEFINE_PERCPU_RWSEM(name, static)

extern bool __percpu_down_read(struct percpu_rw_semaphore *, bool);

static inline void percpu_down_read(struct percpu_rw_semaphore *sem)
{
    panic("%s: END!\n", __func__);
}

static inline bool percpu_down_read_trylock(struct percpu_rw_semaphore *sem)
{
    panic("%s: END!\n", __func__);
}

static inline void percpu_up_read(struct percpu_rw_semaphore *sem)
{
    panic("%s: END!\n", __func__);
}

extern void percpu_down_write(struct percpu_rw_semaphore *);
extern void percpu_up_write(struct percpu_rw_semaphore *);

extern int __percpu_init_rwsem(struct percpu_rw_semaphore *,
                               const char *, struct lock_class_key *);

extern void percpu_free_rwsem(struct percpu_rw_semaphore *);

#define percpu_init_rwsem(sem)                  \
({                                              \
    static struct lock_class_key rwsem_key;     \
    __percpu_init_rwsem(sem, #sem, &rwsem_key); \
})

#endif /* _LINUX_PERCPU_RWSEM_H */
