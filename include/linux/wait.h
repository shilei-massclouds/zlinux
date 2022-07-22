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

struct wait_queue_head {
    spinlock_t          lock;
    struct list_head    head;
};
typedef struct wait_queue_head wait_queue_head_t;

struct task_struct;

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

#endif /* _LINUX_WAIT_H */
