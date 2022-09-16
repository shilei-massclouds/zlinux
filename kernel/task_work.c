// SPDX-License-Identifier: GPL-2.0
#include <linux/spinlock.h>
#include <linux/task_work.h>
//#include <linux/resume_user_mode.h>

/**
 * task_work_run - execute the works added by task_work_add()
 *
 * Flush the pending works. Should be used by the core kernel code.
 * Called before the task returns to the user-mode or stops, or when
 * it exits. In the latter case task_work_add() can no longer add the
 * new work after task_work_run() returns.
 */
void task_work_run(void)
{
    panic("%s: END!\n", __func__);
}
