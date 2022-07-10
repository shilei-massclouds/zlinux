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

static struct housekeeping housekeeping;

bool housekeeping_enabled(enum hk_type type)
{
    return !!(housekeeping.flags & BIT(type));
}
