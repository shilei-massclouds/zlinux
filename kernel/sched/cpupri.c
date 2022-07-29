// SPDX-License-Identifier: GPL-2.0-only
/*
 *  kernel/sched/cpupri.c
 *
 *  CPU priority management
 *
 *  Copyright (C) 2007-2008 Novell
 *
 *  Author: Gregory Haskins <ghaskins@novell.com>
 *
 *  This code tracks the priority of each CPU so that global migration
 *  decisions are easy to calculate.  Each CPU can be in a state as follows:
 *
 *                 (INVALID), NORMAL, RT1, ... RT99, HIGHER
 *
 *  going from the lowest priority to the highest.  CPUs in the INVALID state
 *  are not eligible for routing.  The system maintains this state with
 *  a 2 dimensional bitmap (the first for priority class, the second for CPUs
 *  in that class).  Therefore a typical application without affinity
 *  restrictions can find a suitable CPU with O(1) complexity (e.g. two bit
 *  searches).  For tasks with affinity restrictions, the algorithm has a
 *  worst case complexity of O(min(101, nr_domcpus)), though the scenario that
 *  yields the worst case search is fairly contrived.
 */

/*
 * p->rt_priority   p->prio   newpri   cpupri
 *
 *                -1       -1 (CPUPRI_INVALID)
 *
 *                99        0 (CPUPRI_NORMAL)
 *
 *      1        98       98        1
 *        ...
 *         49        50       50       49
 *         50        49       49       50
 *        ...
 *         99         0        0       99
 *
 *               100      100 (CPUPRI_HIGHER)
 */

/**
 * cpupri_init - initialize the cpupri structure
 * @cp: The cpupri context
 *
 * Return: -ENOMEM on memory allocation failure.
 */
int cpupri_init(struct cpupri *cp)
{
    int i;

    for (i = 0; i < CPUPRI_NR_PRIORITIES; i++) {
        struct cpupri_vec *vec = &cp->pri_to_cpu[i];

        atomic_set(&vec->count, 0);
        if (!zalloc_cpumask_var(&vec->mask, GFP_KERNEL))
            goto cleanup;
    }

    cp->cpu_to_pri = kcalloc(nr_cpu_ids, sizeof(int), GFP_KERNEL);
    if (!cp->cpu_to_pri)
        goto cleanup;

    for_each_possible_cpu(i)
        cp->cpu_to_pri[i] = CPUPRI_INVALID;

    return 0;

cleanup:
    for (i--; i >= 0; i--)
        free_cpumask_var(cp->pri_to_cpu[i].mask);
    return -ENOMEM;
}
