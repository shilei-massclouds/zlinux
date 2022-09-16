/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIGNAL_H
#define _LINUX_SIGNAL_H

#include <linux/bug.h>
#include <linux/signal_types.h>
#include <linux/string.h>

struct task_struct;

enum siginfo_layout {
    SIL_KILL,
    SIL_TIMER,
    SIL_POLL,
    SIL_FAULT,
    SIL_FAULT_TRAPNO,
    SIL_FAULT_MCEERR,
    SIL_FAULT_BNDERR,
    SIL_FAULT_PKUERR,
    SIL_FAULT_PERF_EVENT,
    SIL_CHLD,
    SIL_RT,
    SIL_SYS,
};

static inline
void copy_siginfo(kernel_siginfo_t *to,
                  const kernel_siginfo_t *from)
{
    memcpy(to, from, sizeof(*to));
}

static inline void sigemptyset(sigset_t *set)
{
    switch (_NSIG_WORDS) {
    default:
        memset(set, 0, sizeof(sigset_t));
        break;
    case 2: set->sig[1] = 0;
        fallthrough;
    case 1: set->sig[0] = 0;
        break;
    }
}

void signals_init(void);

static inline void clear_siginfo(kernel_siginfo_t *info)
{
    memset(info, 0, sizeof(*info));
}

static inline int sigismember(sigset_t *set, int _sig)
{
    unsigned long sig = _sig - 1;
    if (_NSIG_WORDS == 1)
        return 1 & (set->sig[0] >> sig);
    else
        return 1 & (set->sig[sig / _NSIG_BPW] >> (sig % _NSIG_BPW));
}

static inline void sigdelset(sigset_t *set, int _sig)
{
    unsigned long sig = _sig - 1;
    if (_NSIG_WORDS == 1)
        set->sig[0] &= ~(1UL << sig);
    else
        set->sig[sig / _NSIG_BPW] &= ~(1UL << (sig % _NSIG_BPW));
}

#define sigmask(sig)    (1UL << ((sig) - 1))

#if SIGRTMIN > BITS_PER_LONG
#define rt_sigmask(sig) (1ULL << ((sig)-1))
#else
#define rt_sigmask(sig) sigmask(sig)
#endif

#define siginmask(sig, mask) \
    ((sig) > 0 && (sig) < SIGRTMIN && (rt_sigmask(sig) & (mask)))

#define SIG_KERNEL_STOP_MASK (\
    rt_sigmask(SIGSTOP)   |  rt_sigmask(SIGTSTP)   | \
    rt_sigmask(SIGTTIN)   |  rt_sigmask(SIGTTOU)   )

#define SIG_KERNEL_ONLY_MASK (\
    rt_sigmask(SIGKILL)   |  rt_sigmask(SIGSTOP))

#define SIG_KERNEL_IGNORE_MASK (\
    rt_sigmask(SIGCONT)   |  rt_sigmask(SIGCHLD)   | \
    rt_sigmask(SIGWINCH)  |  rt_sigmask(SIGURG)    )

#define SIG_KERNEL_COREDUMP_MASK (\
        rt_sigmask(SIGQUIT)   |  rt_sigmask(SIGILL)    | \
    rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGABRT)   | \
        rt_sigmask(SIGFPE)    |  rt_sigmask(SIGSEGV)   | \
    rt_sigmask(SIGBUS)    |  rt_sigmask(SIGSYS)    | \
        rt_sigmask(SIGXCPU)   |  rt_sigmask(SIGXFSZ)   | \
    SIGEMT_MASK                    )

#define sig_kernel_only(sig)    siginmask(sig, SIG_KERNEL_ONLY_MASK)
#define sig_kernel_coredump(sig) \
    siginmask(sig, SIG_KERNEL_COREDUMP_MASK)
#define sig_kernel_stop(sig)    siginmask(sig, SIG_KERNEL_STOP_MASK)
#define sig_kernel_ignore(sig)  siginmask(sig, SIG_KERNEL_IGNORE_MASK)

#define sig_fatal(t, signr) \
    (!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
     (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)

#define SIG_KTHREAD ((__force __sighandler_t)2)
#define SIG_KTHREAD_KERNEL ((__force __sighandler_t)3)

#ifdef SIGEMT
#define SIGEMT_MASK rt_sigmask(SIGEMT)
#else
#define SIGEMT_MASK 0
#endif

/* We don't use <linux/bitops.h> for these because there is no need to
   be atomic.  */
static inline void sigaddset(sigset_t *set, int _sig)
{
    unsigned long sig = _sig - 1;
    if (_NSIG_WORDS == 1)
        set->sig[0] |= 1UL << sig;
    else
        set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
}

extern bool get_signal(struct ksignal *ksig);

#endif /* _LINUX_SIGNAL_H */
