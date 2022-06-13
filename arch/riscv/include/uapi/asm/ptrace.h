/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _UAPI_ASM_RISCV_PTRACE_H
#define _UAPI_ASM_RISCV_PTRACE_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

struct __riscv_d_ext_state {
    __u64 f[32];
    __u32 fcsr;
};

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_ASM_RISCV_PTRACE_H */
