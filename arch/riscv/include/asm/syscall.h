/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2008-2009 Red Hat, Inc.  All rights reserved.
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 * Copyright 2015 Regents of the University of California, Berkeley
 *
 * See asm-generic/syscall.h for descriptions of what we must do here.
 */

#ifndef _ASM_RISCV_SYSCALL_H
#define _ASM_RISCV_SYSCALL_H

//#include <uapi/linux/audit.h>
#include <linux/sched.h>
#include <linux/err.h>

asmlinkage long sys_riscv_flush_icache(uintptr_t, uintptr_t, uintptr_t);

#endif  /* _ASM_RISCV_SYSCALL_H */
