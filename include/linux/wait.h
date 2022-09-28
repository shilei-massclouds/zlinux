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

#define DEFINE_WAIT_FUNC(name, function)                    \
    struct wait_queue_entry name = {                    \
        .private    = current,                  \
        .func       = function,                 \
        .entry      = LIST_HEAD_INIT((name).entry),         \
    }

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)

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

/**
 * waitqueue_active -- locklessly test for waiters on the queue
 * @wq_head: the waitqueue to test for waiters
 *
 * returns true if the wait list is not empty
 *
 * NOTE: this function is lockless and requires care, incorrect usage _will_
 * lead to sporadic and non-obvious failure.
 *
 * Use either while holding wait_queue_head::lock or when used for wakeups
 * with an extra smp_mb() like::
 *
 *      CPU0 - waker                    CPU1 - waiter
 *
 *                                      for (;;) {
 *      @cond = true;                     prepare_to_wait(&wq_head, &wait, state);
 *      smp_mb();                         // smp_mb() from set_current_state()
 *      if (waitqueue_active(wq_head))         if (@cond)
 *        wake_up(wq_head);                      break;
 *                                        schedule();
 *                                      }
 *                                      finish_wait(&wq_head, &wait);
 *
 * Because without the explicit smp_mb() it's possible for the
 * waitqueue_active() load to get hoisted over the @cond store such that we'll
 * observe an empty wait list while the waiter might not observe @cond.
 *
 * Also note that this 'optimization' trades a spin_lock() for an smp_mb(),
 * which (when the lock is uncontended) are of roughly equal cost.
 */
static inline int waitqueue_active(struct wait_queue_head *wq_head)
{
    return !list_empty(&wq_head->head);
}

void __wake_up(struct wait_queue_head *wq_head,
               unsigned int mode, int nr, void *key);

#define wake_up(x)      __wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)  __wake_up(x, TASK_NORMAL, 0, NULL)

#define wake_up_interruptible(x) \
    __wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)

static inline void __add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
    struct list_head *head = &wq_head->head;
    struct wait_queue_entry *wq;

    list_for_each_entry(wq, &wq_head->head, entry) {
        if (!(wq->flags & WQ_FLAG_PRIORITY))
            break;
        head = &wq->entry;
    }
    list_add(&wq_entry->entry, head);
}

/*
 * Waitqueues which are removed from the waitqueue_head at wakeup time
 */
void prepare_to_wait(struct wait_queue_head *wq_head,
                     struct wait_queue_entry *wq_entry, int state);
bool prepare_to_wait_exclusive(struct wait_queue_head *wq_head,
                               struct wait_queue_entry *wq_entry, int state);
long prepare_to_wait_event(struct wait_queue_head *wq_head,
                           struct wait_queue_entry *wq_entry, int state);
void finish_wait(struct wait_queue_head *wq_head,
                 struct wait_queue_entry *wq_entry);
long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode, long timeout);
int woken_wake_function(struct wait_queue_entry *wq_entry,
                        unsigned mode, int sync, void *key);
int autoremove_wake_function(struct wait_queue_entry *wq_entry,
                             unsigned mode, int sync, void *key);


void __wake_up_locked_key(struct wait_queue_head *wq_head, unsigned int mode,
                          void *key);
void __wake_up_locked_key_bookmark(struct wait_queue_head *wq_head,
                                   unsigned int mode,
                                   void *key,
                                   wait_queue_entry_t *bookmark);
void __wake_up_sync_key(struct wait_queue_head *wq_head,
                        unsigned int mode, void *key);
void __wake_up_locked_sync_key(struct wait_queue_head *wq_head,
                               unsigned int mode, void *key);
void __wake_up_locked(struct wait_queue_head *wq_head, unsigned int mode,
                      int nr);
void __wake_up_sync(struct wait_queue_head *wq_head, unsigned int mode);
void __wake_up_pollfree(struct wait_queue_head *wq_head);

#define ___wait_is_interruptible(state) \
    (!__builtin_constant_p(state) || \
     state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)

extern void init_wait_entry(struct wait_queue_entry *wq_entry,
                            int flags);

/*
 * The below macro ___wait_event() has an explicit shadow of the __ret
 * variable when used from the wait_event_*() macros.
 *
 * This is so that both can use the ___wait_cond_timeout() construct
 * to wrap the condition.
 *
 * The type inconsistency of the wait_event_*() __ret variable is also
 * on purpose; we use long where we can return timeout values and int
 * otherwise.
 */
#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd) \
({                                              \
    __label__ __out;                            \
    struct wait_queue_entry __wq_entry;         \
    long __ret = ret;   /* explicit shadow */   \
                                                \
    init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0); \
    for (;;) {                                  \
        long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
                                                \
        if (condition)                          \
            break;                              \
                                        \
        if (___wait_is_interruptible(state) && __int) {         \
            __ret = __int;                      \
            goto __out;                     \
        }                               \
                                        \
        cmd;                                \
    }                                   \
    finish_wait(&wq_head, &__wq_entry);                 \
__out:  __ret;                                  \
})

#define __wait_event(wq_head, condition) \
    (void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, \
                        0, 0, schedule())

/**
 * wait_event - sleep until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event(wq_head, condition)                      \
do {                                        \
    might_sleep();                              \
    if (condition)                              \
        break;                              \
    __wait_event(wq_head, condition);                   \
} while (0)

#define wake_up_interruptible_nr(x, nr) \
    __wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x) \
    __wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_sync(x) \
    __wake_up_sync((x), TASK_INTERRUPTIBLE)

#endif /* _LINUX_WAIT_H */
