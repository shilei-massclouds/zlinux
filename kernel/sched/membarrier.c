// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2010-2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * membarrier system call
 */

/*
 * For documentation purposes, here are some membarrier ordering
 * scenarios to keep in mind:
 *
 * A) Userspace thread execution after IPI vs membarrier's memory
 *    barrier before sending the IPI
 *
 * Userspace variables:
 *
 * int x = 0, y = 0;
 *
 * The memory barrier at the start of membarrier() on CPU0 is necessary in
 * order to enforce the guarantee that any writes occurring on CPU0 before
 * the membarrier() is executed will be visible to any code executing on
 * CPU1 after the IPI-induced memory barrier:
 *
 *         CPU0                              CPU1
 *
 *         x = 1
 *         membarrier():
 *           a: smp_mb()
 *           b: send IPI                       IPI-induced mb
 *           c: smp_mb()
 *         r2 = y
 *                                           y = 1
 *                                           barrier()
 *                                           r1 = x
 *
 *                     BUG_ON(r1 == 0 && r2 == 0)
 *
 * The write to y and load from x by CPU1 are unordered by the hardware,
 * so it's possible to have "r1 = x" reordered before "y = 1" at any
 * point after (b).  If the memory barrier at (a) is omitted, then "x = 1"
 * can be reordered after (a) (although not after (c)), so we get r1 == 0
 * and r2 == 0.  This violates the guarantee that membarrier() is
 * supposed by provide.
 *
 * The timing of the memory barrier at (a) has to ensure that it executes
 * before the IPI-induced memory barrier on CPU1.
 *
 * B) Userspace thread execution before IPI vs membarrier's memory
 *    barrier after completing the IPI
 *
 * Userspace variables:
 *
 * int x = 0, y = 0;
 *
 * The memory barrier at the end of membarrier() on CPU0 is necessary in
 * order to enforce the guarantee that any writes occurring on CPU1 before
 * the membarrier() is executed will be visible to any code executing on
 * CPU0 after the membarrier():
 *
 *         CPU0                              CPU1
 *
 *                                           x = 1
 *                                           barrier()
 *                                           y = 1
 *         r2 = y
 *         membarrier():
 *           a: smp_mb()
 *           b: send IPI                       IPI-induced mb
 *           c: smp_mb()
 *         r1 = x
 *         BUG_ON(r1 == 0 && r2 == 1)
 *
 * The writes to x and y are unordered by the hardware, so it's possible to
 * have "r2 = 1" even though the write to x doesn't execute until (b).  If
 * the memory barrier at (c) is omitted then "r1 = x" can be reordered
 * before (b) (although not before (a)), so we get "r1 = 0".  This violates
 * the guarantee that membarrier() is supposed to provide.
 *
 * The timing of the memory barrier at (c) has to ensure that it executes
 * after the IPI-induced memory barrier on CPU1.
 *
 * C) Scheduling userspace thread -> kthread -> userspace thread vs membarrier
 *
 *           CPU0                            CPU1
 *
 *           membarrier():
 *           a: smp_mb()
 *                                           d: switch to kthread (includes mb)
 *           b: read rq->curr->mm == NULL
 *                                           e: switch to user (includes mb)
 *           c: smp_mb()
 *
 *
 * Using the scenario from (A), we can show that (a) needs to be paired
 * with (e). Using the scenario from (B), we can show that (c) needs to
 * be paired with (d).
 *
 * D) exit_mm vs membarrier
 *
 * Two thread groups are created, A and B.  Thread group B is created by
 * issuing clone from group A with flag CLONE_VM set, but not CLONE_THREAD.
 * Let's assume we have a single thread within each thread group (Thread A
 * and Thread B).  Thread A runs on CPU0, Thread B runs on CPU1.
 *
 *           CPU0                            CPU1
 *
 *           membarrier():
 *             a: smp_mb()
 *                                           exit_mm():
 *                                             d: smp_mb()
 *                                             e: current->mm = NULL
 *             b: read rq->curr->mm == NULL
 *             c: smp_mb()
 *
 * Using scenario (B), we can show that (c) needs to be paired with (d).
 *
 * E) kthread_{use,unuse}_mm vs membarrier
 *
 *           CPU0                            CPU1
 *
 *           membarrier():
 *           a: smp_mb()
 *                                           kthread_unuse_mm()
 *                                             d: smp_mb()
 *                                             e: current->mm = NULL
 *           b: read rq->curr->mm == NULL
 *                                           kthread_use_mm()
 *                                             f: current->mm = mm
 *                                             g: smp_mb()
 *           c: smp_mb()
 *
 * Using the scenario from (A), we can show that (a) needs to be paired
 * with (g). Using the scenario from (B), we can show that (c) needs to
 * be paired with (d).
 */

/*
 * Bitmask made from a "or" of all commands within enum membarrier_cmd,
 * except MEMBARRIER_CMD_QUERY.
 */

void membarrier_exec_mmap(struct mm_struct *mm)
{
    /*
     * Issue a memory barrier before clearing membarrier_state to
     * guarantee that no memory access prior to exec is reordered after
     * clearing this state.
     */
    smp_mb();
    atomic_set(&mm->membarrier_state, 0);
    /*
     * Keep the runqueue membarrier_state in sync with this mm
     * membarrier_state.
     */
    this_cpu_write(runqueues.membarrier_state, 0);
}
