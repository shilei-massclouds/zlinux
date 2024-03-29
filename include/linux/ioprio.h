/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOPRIO_H
#define IOPRIO_H

#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/iocontext.h>

#include <uapi/linux/ioprio.h>

/*
 * Default IO priority.
 */
#define IOPRIO_DEFAULT \
    IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_BE_NORM)

/*
 * Check that a priority value has a valid class.
 */
static inline bool ioprio_valid(unsigned short ioprio)
{
    unsigned short class = IOPRIO_PRIO_CLASS(ioprio);

    return class > IOPRIO_CLASS_NONE && class <= IOPRIO_CLASS_IDLE;
}

/*
 * If the calling process has set an I/O priority, use that. Otherwise, return
 * the default I/O priority.
 */
static inline int get_current_ioprio(void)
{
    struct io_context *ioc = current->io_context;

    if (ioc)
        return ioc->ioprio;
    return IOPRIO_DEFAULT;
}

#endif /* IOPRIO_H */
