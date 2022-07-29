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
#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/bug.h>

/**
 * cpumask_pr_args - printf args to output a cpumask
 * @maskp: cpumask to be printed
 *
 * Can be used to provide arguments for '%*pb[l]' when printing a cpumask.
 */
#define cpumask_pr_args(maskp)      nr_cpu_ids, cpumask_bits(maskp)

extern unsigned int nr_cpu_ids;

/* Don't assign or return these: may not be this big! */
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

extern struct cpumask __cpu_possible_mask;
extern struct cpumask __cpu_online_mask;
extern struct cpumask __cpu_present_mask;
extern struct cpumask __cpu_active_mask;
extern struct cpumask __cpu_dying_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_dying_mask    ((const struct cpumask *)&__cpu_dying_mask)

/**
 * cpumask_bits - get the bits in a cpumask
 * @maskp: the struct cpumask *
 *
 * You should only assume nr_cpu_ids bits of this mask are valid.  This is
 * a macro so it's const-correct.
 */
#define cpumask_bits(maskp) ((maskp)->bits)

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

static inline bool cpu_online(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, cpu_online_mask);
}

static inline bool cpu_possible(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, cpu_possible_mask);
}

static inline bool cpu_present(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, cpu_present_mask);
}

static inline bool cpu_active(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, cpu_active_mask);
}

static inline bool cpu_dying(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, cpu_dying_mask);
}

/**
 * for_each_cpu - iterate over every cpu in a mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu(cpu, mask)                 \
    for ((cpu) = -1;                            \
        (cpu) = cpumask_next((cpu), (mask)),    \
        (cpu) < nr_cpu_ids;)

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)

#define CPU_BITS_NONE \
{                     \
    [0 ... BITS_TO_LONGS(NR_CPUS)-1] = 0UL \
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

unsigned int __pure cpumask_next(int n, const struct cpumask *srcp);

/**
 * cpumask_weight - Count of bits in *srcp
 * @srcp: the cpumask to count bits (< nr_cpu_ids) in.
 */
static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
    return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_clear - clear all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear(struct cpumask *dstp)
{
    bitmap_zero(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input cpumask
 */
static inline void
cpumask_copy(struct cpumask *dstp, const struct cpumask *srcp)
{
    bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_empty - *srcp == 0
 * @srcp: the cpumask to that all cpus < nr_cpu_ids are clear.
 */
static inline bool cpumask_empty(const struct cpumask *srcp)
{
    return bitmap_empty(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_first - get the first cpu in a cpumask
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
static inline unsigned int cpumask_first(const struct cpumask *srcp)
{
    return find_first_bit(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_size - size to allocate for a 'struct cpumask' in bytes
 */
static inline unsigned int cpumask_size(void)
{
    return BITS_TO_LONGS(nr_cpumask_bits) * sizeof(long);
}

/**
 * cpumask_first_and - return the first cpu from *srcp1 & *srcp2
 * @src1p: the first input
 * @src2p: the second input
 *
 * Returns >= nr_cpu_ids if no cpus set in both.  See also cpumask_next_and().
 */
static inline
unsigned int cpumask_first_and(const struct cpumask *srcp1,
                               const struct cpumask *srcp2)
{
    return find_first_and_bit(cpumask_bits(srcp1), cpumask_bits(srcp2),
                              nr_cpumask_bits);
}

/**
 * cpumask_any - pick a "random" cpu from *srcp
 * @srcp: the input cpumask
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
#define cpumask_any(srcp) cpumask_first(srcp)

/**
 * cpumask_any_and - pick a "random" cpu from *mask1 & *mask2
 * @mask1: the first input cpumask
 * @mask2: the second input cpumask
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))

/**
 * cpumask_of - the cpumask containing just a given cpu
 * @cpu: the cpu (<= nr_cpu_ids)
 */
#define cpumask_of(cpu) (get_cpu_mask(cpu))

/**
 * to_cpumask - convert an NR_CPUS bitmap to a struct cpumask *
 * @bitmap: the bitmap
 *
 * There are a few places where cpumask_var_t isn't appropriate and
 * static cpumasks must be used (eg. very early boot), yet we don't
 * expose the definition of 'struct cpumask'.
 *
 * This does the conversion, and can be used as a constant initializer.
 */
#define to_cpumask(bitmap) \
    ((struct cpumask *)(1 ? (bitmap) : \
                        (void *)sizeof(__check_is_bitmap(bitmap))))

static inline int __check_is_bitmap(const unsigned long *bitmap)
{
    return 1;
}

/*
 * Special-case data structure for "single bit set only" constant CPU masks.
 *
 * We pre-generate all the 64 (or 32) possible bit positions, with enough
 * padding to the left and the right, and return the constant pointer
 * appropriately offset.
 */
extern const unsigned long
cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)];

static inline const struct cpumask *get_cpu_mask(unsigned int cpu)
{
    const unsigned long *p = cpu_bit_bitmap[1 + cpu % BITS_PER_LONG];
    p -= cpu / BITS_PER_LONG;
    return to_cpumask(p);
}

extern atomic_t __num_online_cpus;

/**
 * num_online_cpus() - Read the number of online CPUs
 *
 * Despite the fact that __num_online_cpus is of type atomic_t, this
 * interface gives only a momentary snapshot and is not protected against
 * concurrent CPU hotplug operations unless invoked from a cpuhp_lock held
 * region.
 */
static inline unsigned int num_online_cpus(void)
{
    return atomic_read(&__num_online_cpus);
}

#define num_possible_cpus() cpumask_weight(cpu_possible_mask)
#define num_present_cpus()  cpumask_weight(cpu_present_mask)
#define num_active_cpus()   cpumask_weight(cpu_active_mask)

#if NR_CPUS <= BITS_PER_LONG
#define CPU_MASK_ALL                            \
(cpumask_t) { {                             \
    [BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS) \
} }
#else
#define CPU_MASK_ALL                            \
(cpumask_t) { {                             \
    [0 ... BITS_TO_LONGS(NR_CPUS)-2] = ~0UL,            \
    [BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS) \
} }
#endif /* NR_CPUS > BITS_PER_LONG */

typedef struct cpumask cpumask_var_t[1];

static inline bool
zalloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags, int node)
{
    cpumask_clear(*mask);
    return true;
}

/**
 * cpumask_and - *dstp = *src1p & *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int cpumask_and(struct cpumask *dstp,
                              const struct cpumask *src1p,
                              const struct cpumask *src2p)
{
    return bitmap_and(cpumask_bits(dstp), cpumask_bits(src1p),
                      cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_or - *dstp = *src1p | *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 */
static inline void cpumask_or(struct cpumask *dstp,
                              const struct cpumask *src1p,
                              const struct cpumask *src2p)
{
    bitmap_or(cpumask_bits(dstp), cpumask_bits(src1p),
              cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_intersects - (*src1p & *src2p) != 0
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool cpumask_intersects(const struct cpumask *src1p,
                                      const struct cpumask *src2p)
{
    return bitmap_intersects(cpumask_bits(src1p), cpumask_bits(src2p),
                             nr_cpumask_bits);
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
    cpumask_clear(*mask);
    return true;
}

#endif /* __LINUX_CPUMASK_H */
