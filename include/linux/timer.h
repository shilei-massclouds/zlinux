/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMER_H
#define _LINUX_TIMER_H

#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/stddef.h>
//#include <linux/debugobjects.h>
#include <linux/stringify.h>

struct timer_list {
    /*
     * All fields that change during normal runtime grouped to the
     * same cacheline
     */
    struct hlist_node   entry;
    unsigned long       expires;
    void            (*function)(struct timer_list *);
    u32             flags;
};

/**
 * @TIMER_DEFERRABLE: A deferrable timer will work normally when the
 * system is busy, but will not cause a CPU to come out of idle just
 * to service it; instead, the timer will be serviced when the CPU
 * eventually wakes up with a subsequent non-deferrable timer.
 *
 * @TIMER_IRQSAFE: An irqsafe timer is executed with IRQ disabled and
 * it's safe to wait for the completion of the running instance from
 * IRQ handlers, for example, by calling del_timer_sync().
 *
 * Note: The irq disabled callback execution is a special case for
 * workqueue locking issues. It's not meant for executing random crap
 * with interrupts disabled. Abuse is monitored!
 *
 * @TIMER_PINNED: A pinned timer will not be affected by any timer
 * placement heuristics (like, NOHZ) and will always expire on the CPU
 * on which the timer was enqueued.
 *
 * Note: Because enqueuing of timers can migrate the timer from one
 * CPU to another, pinned timers are not guaranteed to stay on the
 * initialy selected CPU.  They move to the CPU on which the enqueue
 * function is invoked via mod_timer() or add_timer().  If the timer
 * should be placed on a particular CPU, then add_timer_on() has to be
 * used.
 */
#define TIMER_CPUMASK       0x0003FFFF
#define TIMER_MIGRATING     0x00040000
#define TIMER_BASEMASK      (TIMER_CPUMASK | TIMER_MIGRATING)
#define TIMER_DEFERRABLE    0x00080000
#define TIMER_PINNED        0x00100000
#define TIMER_IRQSAFE       0x00200000
#define TIMER_INIT_FLAGS    (TIMER_DEFERRABLE | TIMER_PINNED | TIMER_IRQSAFE)
#define TIMER_ARRAYSHIFT    22
#define TIMER_ARRAYMASK     0xFFC00000

#define TIMER_TRACE_FLAGMASK \
    (TIMER_MIGRATING | TIMER_DEFERRABLE | TIMER_PINNED | TIMER_IRQSAFE)

#define __TIMER_INITIALIZER(_function, _flags) {        \
        .entry = { .next = TIMER_ENTRY_STATIC },    \
        .function = (_function),            \
        .flags = (_flags),              \
    }

#endif /* _LINUX_TIMER_H */
