/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * syscalls.h - Linux syscall interfaces (non-arch-specific)
 *
 * Copyright (c) 2004 Randy Dunlap
 * Copyright (c) 2004 Open Source Development Labs
 */

#ifndef _LINUX_SYSCALLS_H
#define _LINUX_SYSCALLS_H

struct __aio_sigset;
struct epoll_event;
struct iattr;
struct inode;
struct iocb;
struct io_event;
struct iovec;
struct __kernel_old_itimerval;
struct kexec_segment;
struct linux_dirent;
struct linux_dirent64;
struct list_head;
struct mmap_arg_struct;
struct msgbuf;
struct user_msghdr;
struct mmsghdr;
struct msqid_ds;
struct new_utsname;
struct nfsctl_arg;
struct __old_kernel_stat;
struct oldold_utsname;
struct old_utsname;
struct pollfd;
struct rlimit;
struct rlimit64;
struct rusage;
struct sched_param;
struct sched_attr;
struct sel_arg_struct;
struct semaphore;
struct sembuf;
struct shmid_ds;
struct sockaddr;
struct stat;
struct stat64;
struct statfs;
struct statfs64;
struct statx;
struct sysinfo;
struct timespec;
struct __kernel_old_timeval;
struct __kernel_timex;
struct timezone;
struct tms;
struct utimbuf;
struct mq_attr;
struct compat_stat;
struct old_timeval32;
struct robust_list_head;
struct futex_waitv;
struct getcpu_cache;
struct old_linux_dirent;
struct perf_event_attr;
struct file_handle;
struct sigaltstack;
struct rseq;
union bpf_attr;
struct io_uring_params;
struct clone_args;
struct open_how;
struct mount_attr;
struct landlock_ruleset_attr;
enum landlock_rule_type;

#include <linux/types.h>
#if 0
#include <linux/aio_abi.h>
#include <linux/capability.h>
#endif
#include <linux/signal.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/sem.h>
#include <asm/siginfo.h>
#include <linux/unistd.h>
#if 0
#include <linux/quota.h>
#include <linux/key.h>
#endif
#include <linux/personality.h>
//#include <trace/syscall.h>

/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP0(m,...)
#define __MAP1(m,t,a,...) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define __SC_DECL(t, a) t a
#define __TYPE_AS(t, v) __same_type((__force t)0, v)
#define __TYPE_IS_LL(t) (__TYPE_AS(t, 0LL) || __TYPE_AS(t, 0ULL))

#define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
#define __SC_CAST(t, a) (__force t) a
#define __SC_ARGS(t, a) a
#define __SC_TEST(t, a) (void)BUILD_BUG_ON_ZERO(!__TYPE_IS_LL(t) && sizeof(t) > sizeof(long))

/*
 * Not a real system call, but a placeholder for syscalls which are
 * not implemented -- see kernel/sys_ni.c
 */
asmlinkage long sys_ni_syscall(void);

#define SYSCALL_METADATA(sname, nb, ...)

static inline int is_syscall_trace_event(struct trace_event_call *tp_event)
{
    return 0;
}

#ifndef SYSCALL_DEFINE0
#define SYSCALL_DEFINE0(sname)                  \
    asmlinkage long sys_##sname(void);          \
    asmlinkage long sys_##sname(void)
#endif /* SYSCALL_DEFINE0 */

#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define SYSCALL_DEFINEx(x, sname, ...)  \
    __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

/*
 * The asmlinkage stub is aliased to a function named __se_sys_*() which
 * sign-extends 32-bit ints to longs whenever needed. The actual work is
 * done within __do_sys_*().
 */
#ifndef __SYSCALL_DEFINEx
#define __SYSCALL_DEFINEx(x, name, ...)                 \
    __diag_push();                          \
    __diag_ignore(GCC, 8, "-Wattribute-alias",          \
              "Type aliasing is used to sanitize syscall arguments");\
    asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))   \
        __attribute__((alias(__stringify(__se_sys##name))));    \
    static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
    asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__)); \
    asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))  \
    {                               \
        long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
        __MAP(x,__SC_TEST,__VA_ARGS__);             \
        return ret;                     \
    }                               \
    __diag_pop();                           \
    static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#endif /* __SYSCALL_DEFINEx */

/* mm/nommu.c, also with MMU */
asmlinkage long sys_brk(unsigned long brk);

/* kernel/sys.c */
asmlinkage long sys_newuname(struct new_utsname __user *name);

/* fs/open.c */
asmlinkage long sys_faccessat(int dfd, const char __user *filename,
                              int mode);

asmlinkage long
sys_clock_settime(clockid_t which_clock,
                  const struct __kernel_timespec __user *tp);
asmlinkage long
sys_clock_gettime(clockid_t which_clock,
                  struct __kernel_timespec __user *tp);
asmlinkage long
sys_clock_getres(clockid_t which_clock,
                 struct __kernel_timespec __user *tp);

asmlinkage long
sys_getcpu(unsigned __user *cpu, unsigned __user *node,
           struct getcpu_cache __user *cache);

/* kernel/time.c */
asmlinkage long
sys_gettimeofday(struct __kernel_old_timeval __user *tv,
                 struct timezone __user *tz);
asmlinkage long
sys_settimeofday(struct __kernel_old_timeval __user *tv,
                 struct timezone __user *tz);
asmlinkage long sys_adjtimex(struct __kernel_timex __user *txc_p);
asmlinkage long sys_adjtimex_time32(struct old_timex32 __user *txc_p);

asmlinkage long
sys_openat(int dfd, const char __user *filename, int flags,
           umode_t mode);

asmlinkage long
sys_openat2(int dfd, const char __user *filename,
            struct open_how *how, size_t size);

asmlinkage long sys_close(unsigned int fd);

asmlinkage long
sys_close_range(unsigned int fd, unsigned int max_fd,
                unsigned int flags);

/* fs/stat.c */
asmlinkage long
sys_readlinkat(int dfd, const char __user *path, char __user *buf,
               int bufsiz);
asmlinkage long
sys_newfstatat(int dfd, const char __user *filename,
               struct stat __user *statbuf, int flag);
asmlinkage long
sys_newfstat(unsigned int fd, struct stat __user *statbuf);

#endif /* _LINUX_SYSCALLS_H */
