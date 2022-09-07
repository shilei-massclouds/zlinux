// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Housekeeping management. Manage the targets for routine code that can run on
 *  any CPU: unbound workqueues, timers, kthreads and any offloadable work.
 *
 * Copyright (C) 2017 Red Hat, Inc., Frederic Weisbecker
 * Copyright (C) 2017-2018 SUSE, Frederic Weisbecker
 *
 */

struct housekeeping {
    cpumask_var_t cpumasks[HK_TYPE_MAX];
    unsigned long flags;
};

DEFINE_STATIC_KEY_FALSE(housekeeping_overridden);
static struct housekeeping housekeeping;

bool housekeeping_enabled(enum hk_type type)
{
    return !!(housekeeping.flags & BIT(type));
}

const struct cpumask *housekeeping_cpumask(enum hk_type type)
{
    if (static_branch_unlikely(&housekeeping_overridden))
        if (housekeeping.flags & BIT(type))
            return housekeeping.cpumasks[type];
    return cpu_possible_mask;
}
EXPORT_SYMBOL_GPL(housekeeping_cpumask);

bool housekeeping_test_cpu(int cpu, enum hk_type type)
{
    if (static_branch_unlikely(&housekeeping_overridden))
        if (housekeeping.flags & BIT(type))
            return cpumask_test_cpu(cpu, housekeeping.cpumasks[type]);
    return true;
}
EXPORT_SYMBOL_GPL(housekeeping_test_cpu);
