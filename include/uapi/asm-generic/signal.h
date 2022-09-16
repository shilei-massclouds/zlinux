/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__ASM_GENERIC_SIGNAL_H
#define _UAPI__ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG       64
#define _NSIG_BPW   __BITS_PER_LONG
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

#define SIGHUP       1
#define SIGINT       2
#define SIGQUIT      3
#define SIGILL       4
#define SIGTRAP      5
#define SIGABRT      6
#define SIGBUS       7
#define SIGFPE       8
#define SIGKILL      9

#define SIGSEGV     11

#define SIGURG      16
#define SIGCHLD     17
#define SIGCONT     18
#define SIGSTOP     19
#define SIGTSTP     20
#define SIGTTIN     21
#define SIGTTOU     22

#define SIGXCPU     24
#define SIGXFSZ     25

#define SIGWINCH    28
#define SIGIO       29
#define SIGPOLL     SIGIO
#define SIGSYS      31

/* These should not be considered constants from userland.  */
#define SIGRTMIN    32

#ifndef __ASSEMBLY__
typedef struct {
    unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* not actually used, but required for linux/syscalls.h */
typedef unsigned long old_sigset_t;

#include <asm-generic/signal-defs.h>

#endif /* __ASSEMBLY__ */

#endif /* _UAPI__ASM_GENERIC_SIGNAL_H */
