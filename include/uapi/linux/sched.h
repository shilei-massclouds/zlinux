/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

#include <linux/types.h>

/*
 * cloning flags:
 */
#define CSIGNAL         0x000000ff  /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100  /* set if VM shared between processes */
#define CLONE_FS        0x00000200  /* set if fs info shared between processes */
#define CLONE_SIGHAND   0x00000800  /* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD     0x00001000  /* set if a pidfd should be placed in parent */
#define CLONE_VFORK     0x00004000  /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000  /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000  /* Same thread group? */
#define CLONE_NEWNS     0x00020000  /* New mount namespace group */

#define CLONE_PARENT_SETTID 0x00100000  /* set the TID in the parent */
#define CLONE_DETACHED      0x00400000  /* Unused, ignored */
#define CLONE_UNTRACED      0x00800000  /* set if the tracing process can't force CLONE_PTRACE on this clone */

#define CLONE_CHILD_SETTID      0x01000000  /* set the TID in the child */
#define CLONE_CHILD_CLEARTID    0x00200000  /* clear the TID in the child */

#define CLONE_NEWUSER       0x10000000  /* New user namespace */
#define CLONE_NEWPID        0x20000000  /* New pid namespace */

#ifndef __ASSEMBLY__

#endif /* !__ASSEMBLY__ */

/*
 * Scheduling policies
 */
#define SCHED_NORMAL    0
#define SCHED_FIFO      1
#define SCHED_RR        2
#define SCHED_BATCH     3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE      5
#define SCHED_DEADLINE  6

#endif /* _UAPI_LINUX_SCHED_H */
