/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_GENERIC_SIGNAL_DEFS_H
#define __ASM_GENERIC_SIGNAL_DEFS_H

#include <linux/compiler.h>

#define SA_UNSUPPORTED      0x00000400
#define SA_EXPOSE_TAGBITS   0x00000800

#ifndef SA_ONSTACK
#define SA_ONSTACK      0x08000000
#endif
#ifndef SA_RESTART
#define SA_RESTART      0x10000000
#endif
#ifndef SA_NODEFER
#define SA_NODEFER      0x40000000
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND    0x80000000
#endif

#define SA_NOMASK   SA_NODEFER
#define SA_ONESHOT  SA_RESETHAND

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
