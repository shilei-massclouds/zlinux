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
//#include <linux/cpuhotplug.h>

extern void boot_cpu_init(void);

#endif /* _LINUX_CPU_H_ */
