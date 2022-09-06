/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_RSEQ_H
#define _UAPI_LINUX_RSEQ_H

/*
 * linux/rseq.h
 *
 * Restartable sequences system call API
 *
 * Copyright (c) 2015-2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/types.h>
#include <asm/byteorder.h>


enum rseq_cs_flags_bit {
    RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT  = 0,
    RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT   = 1,
    RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT  = 2,
};

#endif /* _UAPI_LINUX_RSEQ_H */
