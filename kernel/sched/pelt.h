#include "sched-pelt.h"

int __update_load_avg_blocked_se(u64 now, struct sched_entity *se);
int __update_load_avg_se(u64 now, struct cfs_rq *cfs_rq,
                         struct sched_entity *se);
int __update_load_avg_cfs_rq(u64 now, struct cfs_rq *cfs_rq);
int update_rt_rq_load_avg(u64 now, struct rq *rq, int running);
int update_dl_rq_load_avg(u64 now, struct rq *rq, int running);

/*
 * The clock_pelt scales the time to reflect the effective amount of
 * computation done during the running delta time but then sync back to
 * clock_task when rq is idle.
 *
 *
 * absolute time   | 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|16
 * @ max capacity  ------******---------------******---------------
 * @ half capacity ------************---------************---------
 * clock pelt      | 1| 2|    3|    4| 7| 8| 9|   10|   11|14|15|16
 *
 */
static inline void update_rq_clock_pelt(struct rq *rq, s64 delta)
{
    if (unlikely(is_idle_task(rq->curr))) {
        /* The rq is idle, we can sync to clock_task */
        rq->clock_pelt  = rq_clock_task(rq);
        return;
    }

    /*
     * When a rq runs at a lower compute capacity, it will need
     * more time to do the same amount of work than at max
     * capacity. In order to be invariant, we scale the delta to
     * reflect how much work has been really done.
     * Running longer results in stealing idle time that will
     * disturb the load signal compared to max capacity. This
     * stolen idle time will be automatically reflected when the
     * rq will be idle and the clock will be synced with
     * rq_clock_task.
     */

    /*
     * Scale the elapsed time to reflect the real amount of
     * computation
     */
    delta = cap_scale(delta, arch_scale_cpu_capacity(cpu_of(rq)));
    delta = cap_scale(delta, arch_scale_freq_capacity(cpu_of(rq)));

    rq->clock_pelt += delta;
}

static inline int
update_thermal_load_avg(u64 now, struct rq *rq, u64 capacity)
{
    return 0;
}

static inline u64 thermal_load_avg(struct rq *rq)
{
    return 0;
}

static inline u64 rq_clock_pelt(struct rq *rq)
{
    assert_clock_updated(rq);

    return rq->clock_pelt - rq->lost_idle_time;
}

/* rq->task_clock normalized against any time this cfs_rq has spent throttled */
static inline u64 cfs_rq_clock_pelt(struct cfs_rq *cfs_rq)
{
    if (unlikely(cfs_rq->throttle_count))
        return cfs_rq->throttled_clock_task -
            cfs_rq->throttled_clock_task_time;

    return rq_clock_pelt(rq_of(cfs_rq)) -
        cfs_rq->throttled_clock_task_time;
}

#define PELT_MIN_DIVIDER    (LOAD_AVG_MAX - 1024)

static inline u32 get_pelt_divider(struct sched_avg *avg)
{
    return PELT_MIN_DIVIDER + avg->period_contrib;
}

static inline int
update_irq_load_avg(struct rq *rq, u64 running)
{
    return 0;
}
