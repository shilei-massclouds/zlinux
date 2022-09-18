// SPDX-License-Identifier: GPL-2.0
/*
 * cacheinfo support - processor cache information via sysfs
 *
 * Based on arch/x86/kernel/cpu/intel_cacheinfo.c
 * Author: Sudeep Holla <sudeep.holla@arm.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

//#include <linux/acpi.h>
#include <linux/bitops.h>
#include <linux/cacheinfo.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/sysfs.h>

/* pointer to per cpu cacheinfo */
static DEFINE_PER_CPU(struct cpu_cacheinfo, ci_cpu_cacheinfo);
#define ci_cacheinfo(cpu)   (&per_cpu(ci_cpu_cacheinfo, cpu))
#define cache_leaves(cpu)   (ci_cacheinfo(cpu)->num_leaves)
#define per_cpu_cacheinfo(cpu)  (ci_cacheinfo(cpu)->info_list)

struct cpu_cacheinfo *get_cpu_cacheinfo(unsigned int cpu)
{
    return ci_cacheinfo(cpu);
}
