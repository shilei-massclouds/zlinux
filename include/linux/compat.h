/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_COMPAT_H
#define _LINUX_COMPAT_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#include <linux/types.h>
//#include <linux/time.h>

//#include <linux/stat.h>
#include <linux/param.h>    /* for HZ */
#if 0
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/aio_abi.h>  /* for aio_context_t */
#endif
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/compat.h>
#include <asm/signal.h>
#include <asm/siginfo.h>

typedef union compat_sigval {
    compat_int_t    sival_int;
    compat_uptr_t   sival_ptr;
} compat_sigval_t;

typedef struct compat_siginfo {
    int si_signo;
    int si_errno;
    int si_code;

    union {
        int _pad[128/sizeof(int) - 3];

        /* kill() */
        struct {
            compat_pid_t _pid;  /* sender's pid */
            __compat_uid32_t _uid;  /* sender's uid */
        } _kill;

        /* POSIX.1b timers */
        struct {
            compat_timer_t _tid;    /* timer id */
            int _overrun;       /* overrun count */
            compat_sigval_t _sigval;    /* same as below */
        } _timer;

        /* POSIX.1b signals */
        struct {
            compat_pid_t _pid;  /* sender's pid */
            __compat_uid32_t _uid;  /* sender's uid */
            compat_sigval_t _sigval;
        } _rt;

        /* SIGCHLD */
        struct {
            compat_pid_t _pid;  /* which child */
            __compat_uid32_t _uid;  /* sender's uid */
            int _status;        /* exit code */
            compat_clock_t _utime;
            compat_clock_t _stime;
        } _sigchld;

        /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
        struct {
            compat_uptr_t _addr;    /* faulting insn/memory ref. */
#define __COMPAT_ADDR_BND_PKEY_PAD \
            (__alignof__(compat_uptr_t) < sizeof(short) ? \
             sizeof(short) : __alignof__(compat_uptr_t))

            union {
                /* used on alpha and sparc */
                int _trapno;    /* TRAP # which caused the signal */
                /*
                 * used when si_code=BUS_MCEERR_AR or
                 * used when si_code=BUS_MCEERR_AO
                 */
                short int _addr_lsb;    /* Valid LSB of the reported address. */
                /* used when si_code=SEGV_BNDERR */
                struct {
                    char _dummy_bnd[__COMPAT_ADDR_BND_PKEY_PAD];
                    compat_uptr_t _lower;
                    compat_uptr_t _upper;
                } _addr_bnd;
                /* used when si_code=SEGV_PKUERR */
                struct {
                    char _dummy_pkey[__COMPAT_ADDR_BND_PKEY_PAD];
                    u32 _pkey;
                } _addr_pkey;
                /* used when si_code=TRAP_PERF */
                struct {
                    compat_ulong_t _data;
                    u32 _type;
                } _perf;
            };
        } _sigfault;

        /* SIGPOLL */
        struct {
            compat_long_t _band;    /* POLL_IN, POLL_OUT, POLL_MSG */
            int _fd;
        } _sigpoll;

        struct {
            compat_uptr_t _call_addr; /* calling user insn */
            int _syscall;   /* triggering system call number */
            unsigned int _arch; /* AUDIT_ARCH_* of syscall */
        } _sigsys;
    } _sifields;
} compat_siginfo_t;

#endif /* _LINUX_COMPAT_H */
