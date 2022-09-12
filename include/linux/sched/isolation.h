#ifndef _LINUX_SCHED_ISOLATION_H
#define _LINUX_SCHED_ISOLATION_H

#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/tick.h>
#include <linux/jump_label.h>

enum hk_type {
    HK_TYPE_TIMER,
    HK_TYPE_RCU,
    HK_TYPE_MISC,
    HK_TYPE_SCHED,
    HK_TYPE_TICK,
    HK_TYPE_DOMAIN,
    HK_TYPE_WQ,
    HK_TYPE_MANAGED_IRQ,
    HK_TYPE_KTHREAD,
    HK_TYPE_MAX
};

extern bool housekeeping_enabled(enum hk_type type);

DECLARE_STATIC_KEY_FALSE(housekeeping_overridden);
extern int housekeeping_any_cpu(enum hk_type type);
extern const struct cpumask *housekeeping_cpumask(enum hk_type type);
extern bool housekeeping_enabled(enum hk_type type);
extern void housekeeping_affine(struct task_struct *t, enum hk_type type);
extern bool housekeeping_test_cpu(int cpu, enum hk_type type);
extern void __init housekeeping_init(void);

extern bool housekeeping_test_cpu(int cpu, enum hk_type type);

static inline bool housekeeping_cpu(int cpu, enum hk_type type)
{
    if (static_branch_unlikely(&housekeeping_overridden))
        return housekeeping_test_cpu(cpu, type);
    return true;
}

#endif /* _LINUX_SCHED_ISOLATION_H */
