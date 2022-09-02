/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KERNEL_STATS_H
#define _KERNEL_STATS_H

static inline void psi_enqueue(struct task_struct *p, bool wakeup) {}
static inline void psi_dequeue(struct task_struct *p, bool sleep) {}
static inline void psi_ttwu_dequeue(struct task_struct *p) {}
static inline void psi_sched_switch(struct task_struct *prev,
                                    struct task_struct *next,
                                    bool sleep)
{
}

# define sched_info_enqueue(rq, t)  do { } while (0)
# define sched_info_dequeue(rq, t)  do { } while (0)
# define sched_info_switch(rq, t, next) do { } while (0)

#endif /* _KERNEL_STATS_H */
