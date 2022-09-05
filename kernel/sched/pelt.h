#include "sched-pelt.h"

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
