/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/cpu.h - generic cpu definition
 *
 * This is mainly for topological representation. We define the
 * basic 'struct cpu' here, which can be embedded in per-arch
 * definitions of processors.
 *
 * Basic handling of the devices is done in drivers/base/cpu.c
 *
 * CPUs are exported via sysfs in the devices/system/cpu
 * directory.
 */
#ifndef _LINUX_CPU_H_
#define _LINUX_CPU_H_

//#include <linux/node.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/cpuhotplug.h>

struct device;

extern void boot_cpu_init(void);

extern void boot_cpu_hotplug_init(void);

extern void cpus_write_lock(void);
extern void cpus_write_unlock(void);
extern void cpus_read_lock(void);
extern void cpus_read_unlock(void);
extern int  cpus_read_trylock(void);
extern void lockdep_assert_cpus_held(void);
extern void cpu_hotplug_disable(void);
extern void cpu_hotplug_enable(void);
void clear_tasks_mm_cpumask(int cpu);
int remove_cpu(unsigned int cpu);
int cpu_device_down(struct device *dev);
extern void smp_shutdown_nonboot_cpus(unsigned int primary_cpu);

void bringup_nonboot_cpus(unsigned int setup_max_cpus);

void __noreturn cpu_startup_entry(enum cpuhp_state state);

#endif /* _LINUX_CPU_H_ */
