/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/irqflags.h
 *
 * IRQ flags tracing: follow the state of the hardirq and softirq flags and
 * provide callbacks for transitions between ON and OFF states.
 *
 * This file gets included from lowlevel asm headers too, to provide
 * wrapped versions of the local_irq_*() APIs, based on the
 * raw_local_irq_*() macros from the lowlevel headers.
 */
#ifndef _LINUX_TRACE_IRQFLAGS_H
#define _LINUX_TRACE_IRQFLAGS_H

#include <linux/typecheck.h>
#include <asm/irqflags.h>
//#include <asm/percpu.h>

#define raw_irqs_disabled() (arch_irqs_disabled())

#define irqs_disabled() raw_irqs_disabled()

#define local_irq_enable()  do { raw_local_irq_enable(); } while (0)
#define local_irq_disable() do { raw_local_irq_disable(); } while (0)

#define local_irq_save(flags) \
    do { raw_local_irq_save(flags); } while (0)

#define local_irq_restore(flags) \
    do { raw_local_irq_restore(flags); } while (0)

/*
 * Wrap the arch provided IRQ routines to provide appropriate checks.
 */
#define raw_local_irq_disable() arch_local_irq_disable()
#define raw_local_irq_enable()  arch_local_irq_enable()
#define raw_local_irq_save(flags)           \
    do {                        \
        typecheck(unsigned long, flags);    \
        flags = arch_local_irq_save();      \
    } while (0)
#define raw_local_irq_restore(flags)            \
    do {                        \
        typecheck(unsigned long, flags);    \
        arch_local_irq_restore(flags);      \
    } while (0)

#endif /* _LINUX_TRACE_IRQFLAGS_H */
