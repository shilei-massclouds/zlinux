/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

/*
 *  Generic SMP support
 *      Alan Cox. <alan@redhat.com>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/smp_types.h>

#include <linux/preempt.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/thread_info.h>
#include <asm/smp.h>

typedef void (*smp_call_func_t)(void *info);
typedef bool (*smp_cond_func_t)(int cpu, void *info);

/*
 * structure shares (partial) layout with struct irq_work
 */
struct __call_single_data {
    struct __call_single_node node;
    smp_call_func_t func;
    void *info;
};

/*
 * Allow the architecture to differentiate between a stable and unstable read.
 * For example, x86 uses an IRQ-safe asm-volatile read for the unstable but a
 * regular asm read for the stable.
 */
#ifndef __smp_processor_id
#define __smp_processor_id(x) raw_smp_processor_id(x)
#endif

#define smp_processor_id() __smp_processor_id()

void smp_setup_processor_id(void);
void kick_all_cpus_sync(void);

extern void __init setup_nr_cpu_ids(void);
extern void __init smp_init(void);

#define CSD_INIT(_func, _info) \
    (struct __call_single_data){ .func = (_func), .info = (_info), }

/* Use __aligned() to avoid to use 2 cache lines for 1 csd */
typedef struct __call_single_data call_single_data_t
    __aligned(sizeof(struct __call_single_data));

#define INIT_CSD(_csd, _func, _info)        \
do {                        \
    *(_csd) = CSD_INIT((_func), (_info));   \
} while (0)

#define get_cpu()       ({ preempt_disable(); __smp_processor_id(); })
#define put_cpu()       preempt_enable()

void on_each_cpu_cond_mask(smp_cond_func_t cond_func, smp_call_func_t func,
                           void *info, bool wait, const struct cpumask *mask);

/*
 * Call a function on each processor for which the supplied function
 * cond_func returns a positive value. This may include the local
 * processor.  May be used during early boot while early_boot_irqs_disabled is
 * set. Use local_irq_save/restore() instead of local_irq_disable/enable().
 */
static inline
void on_each_cpu_cond(smp_cond_func_t cond_func,
                      smp_call_func_t func, void *info, bool wait)
{
    on_each_cpu_cond_mask(cond_func, func, info, wait, cpu_online_mask);
}

/*
 * sends a 'reschedule' event to another CPU:
 */
extern void smp_send_reschedule(int cpu);

#endif /* __LINUX_SMP_H */
