/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM signal

#if !defined(_TRACE_SIGNAL_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SIGNAL_H

#include <linux/signal.h>
#include <linux/sched.h>
#if 0
#include <linux/tracepoint.h>
#endif

enum {
    TRACE_SIGNAL_DELIVERED,
    TRACE_SIGNAL_IGNORED,
    TRACE_SIGNAL_ALREADY_PENDING,
    TRACE_SIGNAL_OVERFLOW_FAIL,
    TRACE_SIGNAL_LOSE_INFO,
};

#endif /* _TRACE_SIGNAL_H */

#if 0
/* This part must be outside protection */
#include <trace/define_trace.h>
#endif
