// SPDX-License-Identifier: GPL-2.0

#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/autogroup.h>
#include <linux/init.h>
#include <linux/mm.h>

#include <asm/cache.h>
#include <linux/uaccess.h>

static struct signal_struct init_signals = {
#if 0
    .nr_threads = 1,
    .thread_head    = LIST_HEAD_INIT(init_task.thread_node),
    .wait_chldexit  = __WAIT_QUEUE_HEAD_INITIALIZER(init_signals.wait_chldexit),
    .shared_pending = {
        .list = LIST_HEAD_INIT(init_signals.shared_pending.list),
        .signal =  {{0}}
    },
    .multiprocess   = HLIST_HEAD_INIT,
    .rlim       = INIT_RLIMITS,
    .cred_guard_mutex = __MUTEX_INITIALIZER(init_signals.cred_guard_mutex),
    .exec_update_lock = __RWSEM_INITIALIZER(init_signals.exec_update_lock),
    .posix_timers = LIST_HEAD_INIT(init_signals.posix_timers),
    .cputimer   = {
        .cputime_atomic = INIT_CPUTIME_ATOMIC,
    },
    INIT_CPU_TIMERS(init_signals)
#endif
    .pids = {
        [PIDTYPE_PID]   = &init_struct_pid,
        [PIDTYPE_TGID]  = &init_struct_pid,
        [PIDTYPE_PGID]  = &init_struct_pid,
        [PIDTYPE_SID]   = &init_struct_pid,
    },
#if 0
    INIT_PREV_CPUTIME(init_signals)
#endif
};

struct task_struct init_task __aligned(L1_CACHE_BYTES) = {
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
    .__state        = 0,
    .stack          = init_stack,
    .prio           = MAX_PRIO - 20,
    .normal_prio    = MAX_PRIO - 20,
    .policy         = SCHED_NORMAL,
    .usage          = REFCOUNT_INIT(2),
    .flags          = PF_KTHREAD,
    .thread_pid     = &init_struct_pid,
    .cpus_ptr       = &init_task.cpus_mask,
    .user_cpus_ptr  = NULL,
    .cpus_mask      = CPU_MASK_ALL,
    .nr_cpus_allowed= NR_CPUS,
    .mm             = NULL,
    .active_mm      = &init_mm,
    RCU_POINTER_INITIALIZER(real_cred, &init_cred),
    RCU_POINTER_INITIALIZER(cred, &init_cred),
    .comm           = INIT_TASK_COMM,
    .signal         = &init_signals,
    .pi_lock        = __RAW_SPIN_LOCK_UNLOCKED(init_task.pi_lock),
    .nsproxy        = &init_nsproxy,
    .se             = {
        .group_node     = LIST_HEAD_INIT(init_task.se.group_node),
    },
    .sched_task_group = &root_task_group,
};
EXPORT_SYMBOL(init_task);
