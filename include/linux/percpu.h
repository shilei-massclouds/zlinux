/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PERCPU_H
#define __LINUX_PERCPU_H

//#include <linux/mmdebug.h>
#include <linux/preempt.h>
#include <linux/smp.h>
//#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/pfn.h>
#include <linux/init.h>

#include <asm/percpu.h>

/* minimum unit size, also is the maximum supported allocation size */
#define PCPU_MIN_UNIT_SIZE      PFN_ALIGN(32 << 10)

/* minimum allocation size and shift in bytes */
#define PCPU_MIN_ALLOC_SHIFT    2
#define PCPU_MIN_ALLOC_SIZE     (1 << PCPU_MIN_ALLOC_SHIFT)

extern void __init setup_per_cpu_areas(void);

extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);

extern void free_percpu(void __percpu *__pdata);

#define alloc_percpu(type) \
    (typeof(type) __percpu *)__alloc_percpu(sizeof(type), __alignof__(type))

#endif /* __LINUX_PERCPU_H */
