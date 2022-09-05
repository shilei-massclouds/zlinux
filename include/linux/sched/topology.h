/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TOPOLOGY_H
#define _LINUX_SCHED_TOPOLOGY_H

#include <linux/topology.h>

#include <linux/sched/idle.h>

struct sched_domain_attr {
    int relax_domain_level;
};

/* Generate SD flag indexes */
#define SD_FLAG(name, mflags) __##name,
enum {
    #include <linux/sched/sd_flags.h>
    __SD_FLAG_CNT,
};
#undef SD_FLAG

/* Generate SD flag bits */
#define SD_FLAG(name, mflags) name = 1 << __##name,
enum {
    #include <linux/sched/sd_flags.h>
};
#undef SD_FLAG

extern int sched_domain_level_max;

struct sched_group;

struct sched_domain_shared {
    atomic_t    ref;
    atomic_t    nr_busy_cpus;
    int     has_idle_cores;
};

struct sched_domain {
    /* These fields must be setup */
    struct sched_domain __rcu *parent;  /* top domain must be null terminated */
    struct sched_domain __rcu *child;   /* bottom domain must be null terminated */
    struct sched_group *groups; /* the balancing groups of the domain */
    unsigned long min_interval; /* Minimum balance interval ms */
    unsigned long max_interval; /* Maximum balance interval ms */
    unsigned int busy_factor;   /* less balancing by factor if busy */
    unsigned int imbalance_pct; /* No balance until over watermark */
    unsigned int cache_nice_tries;  /* Leave cache hot tasks for # tries */
    unsigned int imb_numa_nr;   /* Nr running tasks that allows a NUMA imbalance */

    int nohz_idle;          /* NOHZ IDLE status */
    int flags;          /* See SD_* */
    int level;

    /* Runtime fields. */
    unsigned long last_balance; /* init to jiffies. units in jiffies */
    unsigned int balance_interval;  /* initialise to 1. units in ms. */
    unsigned int nr_balance_failed; /* initialise to 0 */

    /* idle_balance() stats */
    u64 max_newidle_lb_cost;
    unsigned long last_decay_max_lb_cost;

    u64 avg_scan_cost;      /* select_idle_sibling */

    union {
        void *private;      /* used during construction */
        struct rcu_head rcu;    /* used during destruction */
    };
    struct sched_domain_shared *shared;

    unsigned int span_weight;
    /*
     * Span of all CPUs in this domain.
     *
     * NOTE: this field is variable length. (Allocated dynamically
     * by attaching extra space to the end of the structure,
     * depending on how many CPUs the kernel has booted up with)
     */
    unsigned long span[];
};

typedef const struct cpumask *(*sched_domain_mask_f)(int cpu);
typedef int (*sched_domain_flags_f)(void);

#define SDTL_OVERLAP    0x01

struct sd_data {
    struct sched_domain *__percpu *sd;
    struct sched_domain_shared *__percpu *sds;
    struct sched_group *__percpu *sg;
    struct sched_group_capacity *__percpu *sgc;
};

struct sched_domain_topology_level {
    sched_domain_mask_f mask;
    sched_domain_flags_f sd_flags;
    int         flags;
    int         numa_level;
    struct sd_data      data;
};

bool cpus_share_cache(int this_cpu, int that_cpu);

#ifndef arch_scale_cpu_capacity
/**
 * arch_scale_cpu_capacity - get the capacity scale factor of a given CPU.
 * @cpu: the CPU in question.
 *
 * Return: the CPU scale factor normalized against SCHED_CAPACITY_SCALE, i.e.
 *
 *             max_perf(cpu)
 *      ----------------------------- * SCHED_CAPACITY_SCALE
 *      max(max_perf(c) : c \in CPUs)
 */
static __always_inline
unsigned long arch_scale_cpu_capacity(int cpu)
{
    return SCHED_CAPACITY_SCALE;
}
#endif

#define SD_INIT_NAME(type)

static inline struct cpumask *sched_domain_span(struct sched_domain *sd)
{
    return to_cpumask(sd->span);
}

extern int arch_asym_cpu_priority(int cpu);

#endif /* _LINUX_SCHED_TOPOLOGY_H */
