// SPDX-License-Identifier: GPL-2.0
/*
 * Arch specific cpu topology information
 *
 * Copyright (C) 2016, ARM Ltd.
 * Written by: Juri Lelli, ARM Ltd.
 */

#include <linux/cpu.h>
#if 0
#include <linux/cpufreq.h>
#endif
#include <linux/device.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/sched/topology.h>
#if 0
#include <linux/cpuset.h>
#endif
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>

/*
 * cpu topology table
 */
struct cpu_topology cpu_topology[NR_CPUS];
EXPORT_SYMBOL_GPL(cpu_topology);
