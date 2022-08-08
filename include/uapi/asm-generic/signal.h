/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__ASM_GENERIC_SIGNAL_H
#define _UAPI__ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG       64
#define _NSIG_BPW   __BITS_PER_LONG
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

#ifndef __ASSEMBLY__
typedef struct {
    unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* not actually used, but required for linux/syscalls.h */
typedef unsigned long old_sigset_t;

//#include <asm-generic/signal-defs.h>

#endif /* __ASSEMBLY__ */

#endif /* _UAPI__ASM_GENERIC_SIGNAL_H */
