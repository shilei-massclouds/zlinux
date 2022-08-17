/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _linux_POSIX_TIMERS_H
#define _linux_POSIX_TIMERS_H

#include <linux/spinlock.h>
#include <linux/list.h>
//#include <linux/alarmtimer.h>
#include <linux/timerqueue.h>

#define CPUCLOCK_PERTHREAD_MASK 4
#define CPUCLOCK_WHICH(clock)   ((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define CPUCLOCK_CLOCK_MASK 3
#define CPUCLOCK_PROF       0
#define CPUCLOCK_VIRT       1
#define CPUCLOCK_SCHED      2
#define CPUCLOCK_MAX        3
#define CLOCKFD             CPUCLOCK_MAX
#define CLOCKFD_MASK        (CPUCLOCK_PERTHREAD_MASK|CPUCLOCK_CLOCK_MASK)

struct kernel_siginfo;
struct task_struct;

/**
 * cpu_timer - Posix CPU timer representation for k_itimer
 * @node:   timerqueue node to queue in the task/sig
 * @head:   timerqueue head on which this timer is queued
 * @task:   Pointer to target task
 * @elist:  List head for the expiry list
 * @firing: Timer is currently firing
 */
struct cpu_timer {
    struct timerqueue_node  node;
    struct timerqueue_head  *head;
    struct pid              *pid;
    struct list_head        elist;
    int                     firing;
};

/**
 * posix_cputimer_base - Container per posix CPU clock
 * @nextevt:        Earliest-expiration cache
 * @tqhead:     timerqueue head for cpu_timers
 */
struct posix_cputimer_base {
    u64                     nextevt;
    struct timerqueue_head  tqhead;
};

/**
 * posix_cputimers - Container for posix CPU timer related data
 * @bases:      Base container for posix CPU clocks
 * @timers_active:  Timers are queued.
 * @expiry_active:  Timer expiry is active. Used for
 *          process wide timers to avoid multiple
 *          task trying to handle expiry concurrently
 *
 * Used in task_struct and signal_struct
 */
struct posix_cputimers {
    struct posix_cputimer_base  bases[CPUCLOCK_MAX];
    unsigned int            timers_active;
    unsigned int            expiry_active;
};

/* Init task static initializer */
#define INIT_CPU_TIMERBASE(b) { \
    .nextevt    = U64_MAX,      \
}

#define INIT_CPU_TIMERBASES(b) {                    \
    INIT_CPU_TIMERBASE(b[0]),                   \
    INIT_CPU_TIMERBASE(b[1]),                   \
    INIT_CPU_TIMERBASE(b[2]),                   \
}

#define INIT_CPU_TIMERS(s)  \
    .posix_cputimers = {    \
        .bases = INIT_CPU_TIMERBASES(s.posix_cputimers.bases),  \
    },

#endif /* _linux_POSIX_TIMERS_H */
