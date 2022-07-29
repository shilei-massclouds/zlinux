/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H
/*
 * Linux wait queue related types and methods
 */
#include <linux/list.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>

#include <asm/current.h>
//#include <uapi/linux/wait.h>

/* wait_queue_entry::flags */
#define WQ_FLAG_EXCLUSIVE   0x01
#define WQ_FLAG_WOKEN       0x02
#define WQ_FLAG_BOOKMARK    0x04
#define WQ_FLAG_CUSTOM      0x08
#define WQ_FLAG_DONE        0x10
#define WQ_FLAG_PRIORITY    0x20

typedef struct wait_queue_entry wait_queue_entry_t;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry,
                                 unsigned mode, int flags, void *key);

/*
 * A single wait-queue entry structure:
 */
struct wait_queue_entry {
    unsigned int        flags;
    void                *private;
    wait_queue_func_t   func;
    struct list_head    entry;
};

struct wait_queue_head {
    spinlock_t          lock;
    struct list_head    head;
};
typedef struct wait_queue_head wait_queue_head_t;

struct task_struct;

int default_wake_function(struct wait_queue_entry *wq_entry,
                          unsigned mode, int flags, void *key);

/*
 * Macros for declaration and initialisaton of the datatypes
 */

#define __WAITQUEUE_INITIALIZER(name, tsk) {                    \
    .private    = tsk,                          \
    .func       = default_wake_function,                \
    .entry      = { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)                        \
    struct wait_queue_entry name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {                   \
    .lock       = __SPIN_LOCK_UNLOCKED(name.lock),          \
    .head       = LIST_HEAD_INIT(name.head) }

#define DECLARE_WAIT_QUEUE_HEAD(name) \
    struct wait_queue_head name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

#define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)

int autoremove_wake_function(struct wait_queue_entry *wq_entry,
                             unsigned mode, int sync, void *key);

#define init_wait(wait)                             \
    do {                                            \
        (wait)->private = current;                  \
        (wait)->func = autoremove_wake_function;    \
        INIT_LIST_HEAD(&(wait)->entry);             \
        (wait)->flags = 0;                          \
    } while (0)

extern void
__init_waitqueue_head(struct wait_queue_head *wq_head,
                      const char *name, struct lock_class_key *);

#define init_waitqueue_head(wq_head)        \
    do {                                    \
        static struct lock_class_key __key; \
                                            \
        __init_waitqueue_head((wq_head), #wq_head, &__key); \
    } while (0)

static inline void
__add_wait_queue_entry_tail(struct wait_queue_head *wq_head,
                            struct wait_queue_entry *wq_entry)
{
    list_add_tail(&wq_entry->entry, &wq_head->head);
}

#endif /* _LINUX_WAIT_H */
