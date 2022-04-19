/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CPUMASK_H
#define __LINUX_CPUMASK_H

/*
 * Cpumasks provide a bitmap suitable for representing the
 * set of CPU's in a system, one bit position per CPU number.  In general,
 * only nr_cpu_ids (<= NR_CPUS) bits are valid.
 */
#include <linux/kernel.h>
#include <linux/threads.h>
//#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/bug.h>

/* Don't assign or return these: may not be this big! */
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

extern struct cpumask __cpu_possible_mask;
extern struct cpumask __cpu_online_mask;
extern struct cpumask __cpu_present_mask;
extern struct cpumask __cpu_active_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)

/**
 * cpumask_bits - get the bits in a cpumask
 * @maskp: the struct cpumask *
 *
 * You should only assume nr_cpu_ids bits of this mask are valid.  This is
 * a macro so it's const-correct.
 */
#define cpumask_bits(maskp) ((maskp)->bits)

#define cpu_online(cpu) cpumask_test_cpu((cpu), cpu_online_mask)

#define nr_cpumask_bits ((unsigned int)NR_CPUS)

static inline void cpu_max_bits_warn(unsigned int cpu, unsigned int bits)
{
    WARN_ON_ONCE(cpu >= bits);
}

/* verify cpu argument to cpumask_* operators */
static inline unsigned int cpumask_check(unsigned int cpu)
{
    cpu_max_bits_warn(cpu, nr_cpumask_bits);
    return cpu;
}

/**
 * cpumask_test_cpu - test for a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in @cpumask, else returns 0
 */
static inline int
cpumask_test_cpu(int cpu, const struct cpumask *cpumask)
{
    return test_bit(cpumask_check(cpu), cpumask_bits((cpumask)));
}

/**
 * cpumask_set_cpu - set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
    set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

/**
 * cpumask_test_and_set_cpu - atomically test and set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in old bitmap of @cpumask, else returns 0
 *
 * test_and_set_bit wrapper for cpumasks.
 */
static inline int
cpumask_test_and_set_cpu(int cpu, struct cpumask *cpumask)
{
    return test_and_set_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

/**
 * cpumask_test_and_clear_cpu - atomically test and clear a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in old bitmap of @cpumask, else returns 0
 *
 * test_and_clear_bit wrapper for cpumasks.
 */
static inline int
cpumask_test_and_clear_cpu(int cpu, struct cpumask *cpumask)
{
    return test_and_clear_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

/**
 * cpumask_clear_cpu - clear a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
    clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

void set_cpu_online(unsigned int cpu, bool online);

static inline void
set_cpu_active(unsigned int cpu, bool active)
{
    if (active)
        cpumask_set_cpu(cpu, &__cpu_active_mask);
    else
        cpumask_clear_cpu(cpu, &__cpu_active_mask);
}

static inline void
set_cpu_present(unsigned int cpu, bool present)
{
    if (present)
        cpumask_set_cpu(cpu, &__cpu_present_mask);
    else
        cpumask_clear_cpu(cpu, &__cpu_present_mask);
}

static inline void
set_cpu_possible(unsigned int cpu, bool possible)
{
    if (possible)
        cpumask_set_cpu(cpu, &__cpu_possible_mask);
    else
        cpumask_clear_cpu(cpu, &__cpu_possible_mask);
}

#endif /* __LINUX_CPUMASK_H */
