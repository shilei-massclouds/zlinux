/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H
/* Simple interface for creating and stopping kernel threads without mess. */
#include <linux/err.h>
#include <linux/sched.h>

bool set_kthread_struct(struct task_struct *p);

int kthread_stop(struct task_struct *k);

bool set_kthread_struct(struct task_struct *p);

struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
                                          void *data,
                                          unsigned int cpu,
                                          const char *namefmt);

bool __kthread_should_park(struct task_struct *k);

void free_kthread_struct(struct task_struct *k);
void kthread_bind(struct task_struct *k, unsigned int cpu);
void kthread_bind_mask(struct task_struct *k, const struct cpumask *mask);
bool kthread_should_stop(void);
bool kthread_should_park(void);
bool kthread_freezable_should_stop(bool *was_frozen);
void *kthread_func(struct task_struct *k);
void *kthread_data(struct task_struct *k);
void *kthread_probe_data(struct task_struct *k);
int kthread_park(struct task_struct *k);
void kthread_unpark(struct task_struct *k);
void kthread_parkme(void);
void kthread_exit(long result) __noreturn;
void kthread_complete_and_exit(struct completion *, long) __noreturn;

__printf(4, 5)
struct task_struct *
kthread_create_on_node(int (*threadfn)(void *data),
                       void *data,
                       int node,
                       const char namefmt[], ...);

/**
 * kthread_create - create a kthread on the current node
 * @threadfn: the function to run in the thread
 * @data: data pointer for @threadfn()
 * @namefmt: printf-style format string for the thread name
 * @arg: arguments for @namefmt.
 *
 * This macro will create a kthread on the current node, leaving it in
 * the stopped state.  This is just a helper for kthread_create_on_node();
 * see the documentation there for more details.
 */
#define kthread_create(threadfn, data, namefmt, arg...) \
    kthread_create_on_node(threadfn, data, NUMA_NO_NODE, namefmt, ##arg)

/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process().  Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...)              \
({                                     \
    struct task_struct *__k                        \
        = kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
    if (!IS_ERR(__k))                          \
        wake_up_process(__k);                      \
    __k;                                   \
})

int kthreadd(void *unused);
extern struct task_struct *kthreadd_task;
extern int tsk_fork_get_node(struct task_struct *tsk);

#endif /* _LINUX_KTHREAD_H */
