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

/**
 * cpupri_cleanup - clean up the cpupri structure
 * @cp: The cpupri context
 */
void cpupri_cleanup(struct cpupri *cp)
{
    int i;

    kfree(cp->cpu_to_pri);
    for (i = 0; i < CPUPRI_NR_PRIORITIES; i++)
        free_cpumask_var(cp->pri_to_cpu[i].mask);
}

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
static int convert_prio(int prio)
{
    int cpupri;

    switch (prio) {
    case CPUPRI_INVALID:
        cpupri = CPUPRI_INVALID;    /* -1 */
        break;

    case 0 ... 98:
        cpupri = MAX_RT_PRIO-1 - prio;  /* 1 ... 99 */
        break;

    case MAX_RT_PRIO-1:
        cpupri = CPUPRI_NORMAL;     /*  0 */
        break;

    case MAX_RT_PRIO:
        cpupri = CPUPRI_HIGHER;     /* 100 */
        break;
    }

    return cpupri;
}

/**
 * cpupri_set - update the CPU priority setting
 * @cp: The cpupri context
 * @cpu: The target CPU
 * @newpri: The priority (INVALID,NORMAL,RT1-RT99,HIGHER) to assign to this CPU
 *
 * Note: Assumes cpu_rq(cpu)->lock is locked
 *
 * Returns: (void)
 */
void cpupri_set(struct cpupri *cp, int cpu, int newpri)
{
    int *currpri = &cp->cpu_to_pri[cpu];
    int oldpri = *currpri;
    int do_mb = 0;

    newpri = convert_prio(newpri);

    BUG_ON(newpri >= CPUPRI_NR_PRIORITIES);

    BUG_ON(newpri >= CPUPRI_NR_PRIORITIES);

    if (newpri == oldpri)
        return;

    /*
     * If the CPU was currently mapped to a different value, we
     * need to map it to the new value then remove the old value.
     * Note, we must add the new value first, otherwise we risk the
     * cpu being missed by the priority loop in cpupri_find.
     */
    if (likely(newpri != CPUPRI_INVALID)) {
        struct cpupri_vec *vec = &cp->pri_to_cpu[newpri];

        cpumask_set_cpu(cpu, vec->mask);
        /*
         * When adding a new vector, we update the mask first,
         * do a write memory barrier, and then update the count, to
         * make sure the vector is visible when count is set.
         */
        smp_mb__before_atomic();
        atomic_inc(&(vec)->count);
        do_mb = 1;
    }
    if (likely(oldpri != CPUPRI_INVALID)) {
        panic("%s: 1!\n", __func__);
    }

    *currpri = newpri;
}
