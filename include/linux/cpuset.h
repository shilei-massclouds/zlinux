/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CPUSET_H
#define _LINUX_CPUSET_H
/*
 *  cpuset interface
 *
 *  Copyright (C) 2003 BULL SA
 *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 *
 */

#include <linux/sched.h>
#include <linux/sched/topology.h>
#include <linux/sched/task.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/jump_label.h>

static inline bool cpusets_enabled(void) { return false; }

static inline bool cpusets_insane_config(void) { return false; }

static inline int cpuset_init(void) { return 0; }
static inline void cpuset_init_smp(void) {}

static inline void cpuset_force_rebuild(void) { }

static inline void cpuset_update_active_cpus(void)
{
    //partition_sched_domains(1, NULL, NULL);
    panic("%s: END!\n", __func__);
}

static inline void cpuset_wait_for_hotplug(void) { }

static inline void cpuset_read_lock(void) { }
static inline void cpuset_read_unlock(void) { }

static inline void cpuset_cpus_allowed(struct task_struct *p,
                       struct cpumask *mask)
{
    cpumask_copy(mask, task_cpu_possible_mask(p));
}

static inline bool cpuset_cpus_allowed_fallback(struct task_struct *p)
{
    return false;
}

static inline nodemask_t cpuset_mems_allowed(struct task_struct *p)
{
    //return node_possible_map;
    panic("%s: END!\n", __func__);
}

#define cpuset_current_mems_allowed (node_states[N_MEMORY])
static inline void cpuset_init_current_mems_allowed(void) {}

static inline int cpuset_nodemask_valid_mems_allowed(nodemask_t *nodemask)
{
    return 1;
}

static inline bool cpuset_node_allowed(int node, gfp_t gfp_mask)
{
    return true;
}

static inline bool __cpuset_zone_allowed(struct zone *z, gfp_t gfp_mask)
{
    return true;
}

static inline bool cpuset_zone_allowed(struct zone *z, gfp_t gfp_mask)
{
    return true;
}
static inline int cpuset_mems_allowed_intersects(const struct task_struct *tsk1,
                         const struct task_struct *tsk2)
{
    return 1;
}

static inline void cpuset_memory_pressure_bump(void) {}

static inline void cpuset_task_status_allowed(struct seq_file *m,
                        struct task_struct *task)
{
}

static inline int cpuset_mem_spread_node(void)
{
    return 0;
}

static inline int cpuset_slab_spread_node(void)
{
    return 0;
}

static inline int cpuset_do_page_mem_spread(void)
{
    return 0;
}

static inline int cpuset_do_slab_mem_spread(void)
{
    return 0;
}

static inline bool current_cpuset_is_being_rebound(void)
{
    return false;
}

static inline void rebuild_sched_domains(void)
{
    //partition_sched_domains(1, NULL, NULL);
    panic("%s: END!\n", __func__);
}

static inline void cpuset_print_current_mems_allowed(void)
{
}

static inline void set_mems_allowed(nodemask_t nodemask)
{
}

static inline unsigned int read_mems_allowed_begin(void)
{
    return 0;
}

static inline bool read_mems_allowed_retry(unsigned int seq)
{
    return false;
}

#endif /* _LINUX_CPUSET_H */
