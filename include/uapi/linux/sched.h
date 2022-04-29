/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

#include <linux/types.h>

/*
 * cloning flags:
 */
#define CSIGNAL     0x000000ff  /* signal mask to be sent at exit */
#define CLONE_VM    0x00000100  /* set if VM shared between processes */
#define CLONE_FS    0x00000200  /* set if fs info shared between processes */
#define CLONE_PIDFD 0x00001000  /* set if a pidfd should be placed in parent */
#define CLONE_PARENT_SETTID 0x00100000  /* set the TID in the parent */
#define CLONE_UNTRACED  0x00800000  /* set if the tracing process can't force CLONE_PTRACE on this clone */

#ifndef __ASSEMBLY__

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_LINUX_SCHED_H */
