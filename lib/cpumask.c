// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/export.h>
#include <linux/memblock.h>
#include <linux/numa.h>

static DEFINE_PER_CPU(int, distribute_cpu_mask_prev);

/**
 * cpumask_next - get the next cpu in a cpumask
 * @n: the cpu prior to the place to search (ie. return will be > @n)
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no further cpus set.
 */
unsigned int cpumask_next(int n, const struct cpumask *srcp)
{
    /* -1 is a legal arg here. */
    if (n != -1)
        cpumask_check(n);
    return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n + 1);
}
EXPORT_SYMBOL(cpumask_next);

/**
 * Returns an arbitrary cpu within srcp1 & srcp2.
 *
 * Iterated calls using the same srcp1 and srcp2 will be distributed within
 * their intersection.
 *
 * Returns >= nr_cpu_ids if the intersection is empty.
 */
int cpumask_any_and_distribute(const struct cpumask *src1p,
                   const struct cpumask *src2p)
{
    int next, prev;

    /* NOTE: our first selection will skip 0. */
    prev = __this_cpu_read(distribute_cpu_mask_prev);

    next = cpumask_next_and(prev, src1p, src2p);
    if (next >= nr_cpu_ids)
        next = cpumask_first_and(src1p, src2p);

    if (next < nr_cpu_ids)
        __this_cpu_write(distribute_cpu_mask_prev, next);

    return next;
}
EXPORT_SYMBOL(cpumask_any_and_distribute);

/**
 * cpumask_next_and - get the next cpu in *src1p & *src2p
 * @n: the cpu prior to the place to search (ie. return will be > @n)
 * @src1p: the first cpumask pointer
 * @src2p: the second cpumask pointer
 *
 * Returns >= nr_cpu_ids if no further cpus set in both.
 */
int cpumask_next_and(int n,
                     const struct cpumask *src1p,
                     const struct cpumask *src2p)
{
    /* -1 is a legal arg here. */
    if (n != -1)
        cpumask_check(n);
    return find_next_and_bit(cpumask_bits(src1p), cpumask_bits(src2p),
                             nr_cpumask_bits, n + 1);
}
EXPORT_SYMBOL(cpumask_next_and);

/**
 * cpumask_any_but - return a "random" in a cpumask, but not this one.
 * @mask: the cpumask to search
 * @cpu: the cpu to ignore.
 *
 * Often used to find any cpu but smp_processor_id() in a mask.
 * Returns >= nr_cpu_ids if no cpus set.
 */
int cpumask_any_but(const struct cpumask *mask, unsigned int cpu)
{
    unsigned int i;

    cpumask_check(cpu);
    for_each_cpu(i, mask)
        if (i != cpu)
            break;
    return i;
}
EXPORT_SYMBOL(cpumask_any_but);
