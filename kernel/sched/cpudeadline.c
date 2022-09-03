// SPDX-License-Identifier: GPL-2.0-only
/*
 *  kernel/sched/cpudeadline.c
 *
 *  Global CPU deadline management
 *
 *  Author: Juri Lelli <j.lelli@sssup.it>
 */

/*
 * cpudl_init - initialize the cpudl structure
 * @cp: the cpudl max-heap context
 */
int cpudl_init(struct cpudl *cp)
{
    int i;

    raw_spin_lock_init(&cp->lock);
    cp->size = 0;

    cp->elements = kcalloc(nr_cpu_ids,
                   sizeof(struct cpudl_item),
                   GFP_KERNEL);
    if (!cp->elements)
        return -ENOMEM;

    if (!zalloc_cpumask_var(&cp->free_cpus, GFP_KERNEL)) {
        kfree(cp->elements);
        return -ENOMEM;
    }

    for_each_possible_cpu(i)
        cp->elements[i].idx = IDX_INVALID;

    return 0;
}

/*
 * cpudl_cleanup - clean up the cpudl structure
 * @cp: the cpudl max-heap context
 */
void cpudl_cleanup(struct cpudl *cp)
{
    free_cpumask_var(cp->free_cpus);
    kfree(cp->elements);
}

/*
 * cpudl_set_freecpu - Set the cpudl.free_cpus
 * @cp: the cpudl max-heap context
 * @cpu: rd attached CPU
 */
void cpudl_set_freecpu(struct cpudl *cp, int cpu)
{
    cpumask_set_cpu(cpu, cp->free_cpus);
}

/*
 * cpudl_set - update the cpudl max-heap
 * @cp: the cpudl max-heap context
 * @cpu: the target CPU
 * @dl: the new earliest deadline for this CPU
 *
 * Notes: assumes cpu_rq(cpu)->lock is locked
 *
 * Returns: (void)
 */
void cpudl_set(struct cpudl *cp, int cpu, u64 dl)
{
    panic("%s: END!\n", __func__);
}
