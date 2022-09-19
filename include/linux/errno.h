/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERRNO_H
#define _LINUX_ERRNO_H

#include <uapi/linux/errno.h>

/*
 * These should never be seen by user programs.  To return one of ERESTART*
 * codes, signal_pending() MUST be set.  Note that ptrace can observe these
 * at syscall exit tracing, but they will never be left for the debugged user
 * process to see.
 */
#define ERESTARTSYS     512
#define ERESTARTNOINTR  513
#define ERESTARTNOHAND  514 /* restart if no handler.. */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
#define EPROBE_DEFER    517 /* Driver requests probe retry */
#define EOPENSTALE      518 /* open found a stale dentry */
#define ENOPARAM        519 /* Parameter not supported */
#define ENOTSUPP        524 /* Operation is not supported */
#define EIOCBQUEUED     529 /* iocb queued, will get completion event */

#endif /* _LINUX_ERRNO_H */
