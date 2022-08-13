/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H
/* Simple interface for creating and stopping kernel threads without mess. */
#include <linux/err.h>
#include <linux/sched.h>

extern struct task_struct *kthreadd_task;

extern int tsk_fork_get_node(struct task_struct *tsk);

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

#endif /* _LINUX_KTHREAD_H */
