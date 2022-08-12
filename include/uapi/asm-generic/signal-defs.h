/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_GENERIC_SIGNAL_DEFS_H
#define __ASM_GENERIC_SIGNAL_DEFS_H

#include <linux/compiler.h>

#ifndef __ASSEMBLY__
typedef void __signalfn_t(int);
typedef __signalfn_t __user *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t __user *__sigrestore_t;

/* default signal handling */
#define SIG_DFL ((__force __sighandler_t)0)
/* ignore signal */
#define SIG_IGN ((__force __sighandler_t)1)
/* error return from signal */
#define SIG_ERR ((__force __sighandler_t)-1)
#endif

#endif /* __ASM_GENERIC_SIGNAL_DEFS_H */
