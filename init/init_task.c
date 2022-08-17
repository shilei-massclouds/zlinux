// SPDX-License-Identifier: GPL-2.0

#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/mqueue.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/autogroup.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>

#include <asm/cache.h>
#include <linux/uaccess.h>

static struct signal_struct init_signals = {
    .nr_threads     = 1,
    .thread_head    = LIST_HEAD_INIT(init_task.thread_node),
    .wait_chldexit  = __WAIT_QUEUE_HEAD_INITIALIZER(init_signals.wait_chldexit),
    .shared_pending = {
        .list = LIST_HEAD_INIT(init_signals.shared_pending.list),
        .signal =  {{0}}
    },
    .multiprocess   = HLIST_HEAD_INIT,
    .rlim           = INIT_RLIMITS,
    .cred_guard_mutex = __MUTEX_INITIALIZER(init_signals.cred_guard_mutex),
    .exec_update_lock = __RWSEM_INITIALIZER(init_signals.exec_update_lock),
    .posix_timers   = LIST_HEAD_INIT(init_signals.posix_timers),
#if 0
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

static struct sighand_struct init_sighand = {
    .count      = REFCOUNT_INIT(1),
    .action     = { { { .sa_handler = SIG_DFL, } }, },
    .siglock    = __SPIN_LOCK_UNLOCKED(init_sighand.siglock),
    .signalfd_wqh =
        __WAIT_QUEUE_HEAD_INITIALIZER(init_sighand.signalfd_wqh),
};

/*
 * Set up the first task table, touch at your own risk!. Base=0,
 * limit=0x1fffff (=2MB)
 */
struct task_struct init_task __aligned(L1_CACHE_BYTES) = {
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
    .__state        = 0,
    .stack          = init_stack,
    .usage          = REFCOUNT_INIT(2),
    .flags          = PF_KTHREAD,
    .prio           = MAX_PRIO - 20,
    .static_prio    = MAX_PRIO - 20,
    .normal_prio    = MAX_PRIO - 20,
    .policy         = SCHED_NORMAL,
    .cpus_ptr       = &init_task.cpus_mask,
    .user_cpus_ptr  = NULL,
    .cpus_mask      = CPU_MASK_ALL,
    .nr_cpus_allowed= NR_CPUS,
    .mm             = NULL,
    .active_mm      = &init_mm,
#if 0
    .restart_block  = {
        .fn = do_no_restart_syscall,
    },
#endif
    .se = {
        .group_node = LIST_HEAD_INIT(init_task.se.group_node),
    },
#if 0
    .rt = {
        .run_list   = LIST_HEAD_INIT(init_task.rt.run_list),
        .time_slice = RR_TIMESLICE,
    },
#endif
    .tasks          = LIST_HEAD_INIT(init_task.tasks),
#if 0
    .pushable_tasks = PLIST_NODE_INIT(init_task.pushable_tasks, MAX_PRIO),
#endif
    .sched_task_group = &root_task_group,
#if 0
    .ptraced        = LIST_HEAD_INIT(init_task.ptraced),
    .ptrace_entry   = LIST_HEAD_INIT(init_task.ptrace_entry),
#endif
    .real_parent    = &init_task,
    .parent         = &init_task,
    .children       = LIST_HEAD_INIT(init_task.children),
    .sibling        = LIST_HEAD_INIT(init_task.sibling),
    .group_leader   = &init_task,
    RCU_POINTER_INITIALIZER(real_cred, &init_cred),
    RCU_POINTER_INITIALIZER(cred, &init_cred),
    .comm           = INIT_TASK_COMM,
    .thread         = INIT_THREAD,
    .fs             = &init_fs,
    .files          = &init_files,
    .io_uring       = NULL,
    .signal         = &init_signals,
    .sighand        = &init_sighand,
    .nsproxy        = &init_nsproxy,
    .pending = {
        .list = LIST_HEAD_INIT(init_task.pending.list),
        .signal = {{0}}
    },
    .blocked        = {{0}},
    .alloc_lock     = __SPIN_LOCK_UNLOCKED(init_task.alloc_lock),
    .journal_info   = NULL,
    INIT_CPU_TIMERS(init_task)
    .pi_lock        = __RAW_SPIN_LOCK_UNLOCKED(init_task.pi_lock),
    .timer_slack_ns = 50000, /* 50 usec default slack */
    .thread_pid     = &init_struct_pid,
    .thread_group   = LIST_HEAD_INIT(init_task.thread_group),
    .thread_node    = LIST_HEAD_INIT(init_signals.thread_head),

#if 0
    .perf_event_mutex   = __MUTEX_INITIALIZER(init_task.perf_event_mutex),
    .perf_event_list    = LIST_HEAD_INIT(init_task.perf_event_list),

    .pi_waiters     = RB_ROOT_CACHED,
    .pi_top_task    = NULL,
#endif

    INIT_PREV_CPUTIME(init_task)

#if 0
    .seccomp    = { .filter_count = ATOMIC_INIT(0) },
#endif
};
EXPORT_SYMBOL(init_task);
