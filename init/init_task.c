// SPDX-License-Identifier: GPL-2.0

#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/init.h>
#include <linux/mm.h>

#include <asm/cache.h>
#include <linux/uaccess.h>

struct task_struct init_task __aligned(L1_CACHE_BYTES) = {
    .thread_info    = INIT_THREAD_INFO(init_task),
    .stack_refcount = REFCOUNT_INIT(1),
    .__state        = 0,
    .stack          = init_stack,
    .usage          = REFCOUNT_INIT(2),
    .flags          = PF_KTHREAD,
    .thread_pid     = &init_struct_pid,
    .cpus_ptr       = &init_task.cpus_mask,
    .user_cpus_ptr  = NULL,
    .comm           = INIT_TASK_COMM,
};
EXPORT_SYMBOL(init_task);
