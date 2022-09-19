/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PART_STAT_H
#define _LINUX_PART_STAT_H

#include <linux/blkdev.h>
#include <asm/local.h>

struct disk_stats {
    u64 nsecs[NR_STAT_GROUPS];
    unsigned long sectors[NR_STAT_GROUPS];
    unsigned long ios[NR_STAT_GROUPS];
    unsigned long merges[NR_STAT_GROUPS];
    unsigned long io_ticks;
    local_t in_flight[2];
};

/*
 * Macros to operate on percpu disk statistics:
 *
 * {disk|part|all}_stat_{add|sub|inc|dec}() modify the stat counters and should
 * be called between disk_stat_lock() and disk_stat_unlock().
 *
 * part_stat_read() can be called at any time.
 */
#define part_stat_lock()    preempt_disable()
#define part_stat_unlock()  preempt_enable()

#define __part_stat_add(part, field, addnd) \
    __this_cpu_add((part)->bd_stats->field, addnd)

#define part_stat_add(part, field, addnd) \
    do { \
        __part_stat_add((part), field, addnd);  \
        if ((part)->bd_partno)                  \
            __part_stat_add(bdev_whole(part), field, addnd); \
    } while (0)

#define part_stat_dec(part, field)  \
    part_stat_add(part, field, -1)
#define part_stat_inc(part, field)  \
    part_stat_add(part, field, 1)
#define part_stat_sub(part, field, subnd)   \
    part_stat_add(part, field, -subnd)

#endif /* _LINUX_PART_STAT_H */
