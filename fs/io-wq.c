// SPDX-License-Identifier: GPL-2.0
/*
 * Basic worker thread pool for io_uring
 *
 * Copyright (C) 2019 Jens Axboe
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/rculist_nulls.h>
#include <linux/cpu.h>
#if 0
#include <linux/task_work.h>
#include <linux/audit.h>
#include <uapi/linux/io_uring.h>
#endif
#include <linux/workqueue.h>

#include "io-wq.h"

#define IO_WQ_HASH_ORDER    6

#define IO_WQ_NR_HASH_BUCKETS   (1u << IO_WQ_HASH_ORDER)

enum {
    IO_WQ_ACCT_BOUND,
    IO_WQ_ACCT_UNBOUND,
    IO_WQ_ACCT_NR,
};

struct io_wqe_acct {
    unsigned nr_workers;
    unsigned max_workers;
    int index;
    atomic_t nr_running;
    raw_spinlock_t lock;
    struct io_wq_work_list work_list;
    unsigned long flags;
};

/*
 * One for each thread in a wqe pool
 */
struct io_worker {
    refcount_t ref;
    unsigned flags;
    struct hlist_nulls_node nulls_node;
    struct list_head all_list;
    struct task_struct *task;
    struct io_wqe *wqe;

    struct io_wq_work *cur_work;
    struct io_wq_work *next_work;
    raw_spinlock_t lock;

    struct completion ref_done;

    unsigned long create_state;
    struct callback_head create_work;
    int create_index;

    union {
        struct rcu_head rcu;
        struct work_struct work;
    };
};

/*
 * Per-node worker thread pool
 */
struct io_wqe {
    raw_spinlock_t lock;
    struct io_wqe_acct acct[IO_WQ_ACCT_NR];

    int node;

    struct hlist_nulls_head free_list;
    struct list_head all_list;

    struct wait_queue_entry wait;

    struct io_wq *wq;
    struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS];

    cpumask_var_t cpu_mask;
};

/*
 * Per io_wq state
  */
struct io_wq {
    unsigned long state;

    free_work_fn *free_work;
    io_wq_work_fn *do_work;

    struct io_wq_hash *hash;

    atomic_t worker_refs;
    struct completion worker_done;

    struct hlist_node cpuhp_node;

    struct task_struct *task;

    struct io_wqe *wqes[];
};

struct online_data {
    unsigned int cpu;
    bool online;
};

static enum cpuhp_state io_wq_online;

/*
 * Called when a worker is scheduled in. Mark us as currently running.
 */
void io_wq_worker_running(struct task_struct *tsk)
{
    panic("%s: END!\n", __func__);
}

static bool io_worker_get(struct io_worker *worker)
{
    return refcount_inc_not_zero(&worker->ref);
}

static void io_worker_release(struct io_worker *worker)
{
    if (refcount_dec_and_test(&worker->ref))
        complete(&worker->ref_done);
}

/*
 * Iterate the passed in list and call the specific function for each
 * worker that isn't exiting
 */
static bool io_wq_for_each_worker(struct io_wqe *wqe,
                                  bool (*func)(struct io_worker *,
                                               void *),
                                  void *data)
{
    struct io_worker *worker;
    bool ret = false;

    list_for_each_entry_rcu(worker, &wqe->all_list, all_list) {
        if (io_worker_get(worker)) {
            /* no task if node is/was offline */
            if (worker->task)
                ret = func(worker, data);
            io_worker_release(worker);
            if (ret)
                break;
        }
    }

    return ret;
}

static bool io_wq_worker_affinity(struct io_worker *worker, void *data)
{
    struct online_data *od = data;

    if (od->online)
        cpumask_set_cpu(od->cpu, worker->wqe->cpu_mask);
    else
        cpumask_clear_cpu(od->cpu, worker->wqe->cpu_mask);
    return false;
}

static int __io_wq_cpu_online(struct io_wq *wq, unsigned int cpu,
                              bool online)
{
    struct online_data od = {
        .cpu = cpu,
        .online = online
    };
    int i;

    rcu_read_lock();
    for_each_node(i)
        io_wq_for_each_worker(wq->wqes[i], io_wq_worker_affinity, &od);
    rcu_read_unlock();
    return 0;
}

static int io_wq_cpu_online(unsigned int cpu, struct hlist_node *node)
{
    struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

    return __io_wq_cpu_online(wq, cpu, true);
}

static int io_wq_cpu_offline(unsigned int cpu, struct hlist_node *node)
{
    struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

    return __io_wq_cpu_online(wq, cpu, false);
}

static __init int io_wq_init(void)
{
    int ret;

    ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "io-wq/online",
                                  io_wq_cpu_online, io_wq_cpu_offline);
    if (ret < 0)
        return ret;
    io_wq_online = ret;
    return 0;
}
subsys_initcall(io_wq_init);
