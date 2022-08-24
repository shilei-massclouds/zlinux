/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_SIGINFO_H
#define _UAPI_ASM_GENERIC_SIGINFO_H

#include <linux/compiler.h>
#include <linux/types.h>

typedef union sigval {
    int sival_int;
    void __user *sival_ptr;
} sigval_t;

#define SI_MAX_SIZE 128

#define __ARCH_SI_BAND_T long

#define __ARCH_SI_CLOCK_T __kernel_clock_t

/*
 * Be careful when extending this union.  On 32bit siginfo_t is 32bit
 * aligned.  Which means that a 64bit field or any other field that
 * would increase the alignment of siginfo_t will break the ABI.
 */
union __sifields {
    /* kill() */
    struct {
        __kernel_pid_t _pid;    /* sender's pid */
        __kernel_uid32_t _uid;  /* sender's uid */
    } _kill;

    /* POSIX.1b timers */
    struct {
        __kernel_timer_t _tid;  /* timer id */
        int _overrun;       /* overrun count */
        sigval_t _sigval;   /* same as below */
        int _sys_private;       /* not to be passed to user */
    } _timer;

    /* POSIX.1b signals */
    struct {
        __kernel_pid_t _pid;    /* sender's pid */
        __kernel_uid32_t _uid;  /* sender's uid */
        sigval_t _sigval;
    } _rt;

    /* SIGCHLD */
    struct {
        __kernel_pid_t _pid;    /* which child */
        __kernel_uid32_t _uid;  /* sender's uid */
        int _status;        /* exit code */
        __ARCH_SI_CLOCK_T _utime;
        __ARCH_SI_CLOCK_T _stime;
    } _sigchld;

    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
    struct {
        void __user *_addr; /* faulting insn/memory ref. */

#define __ADDR_BND_PKEY_PAD \
        (__alignof__(void *) < sizeof(short) ? \
         sizeof(short) : __alignof__(void *))

        union {
            /* used on alpha and sparc */
            int _trapno;    /* TRAP # which caused the signal */
            /*
             * used when si_code=BUS_MCEERR_AR or
             * used when si_code=BUS_MCEERR_AO
             */
            short _addr_lsb; /* LSB of the reported address */
            /* used when si_code=SEGV_BNDERR */
            struct {
                char _dummy_bnd[__ADDR_BND_PKEY_PAD];
                void __user *_lower;
                void __user *_upper;
            } _addr_bnd;
            /* used when si_code=SEGV_PKUERR */
            struct {
                char _dummy_pkey[__ADDR_BND_PKEY_PAD];
                __u32 _pkey;
            } _addr_pkey;
            /* used when si_code=TRAP_PERF */
            struct {
                unsigned long _data;
                __u32 _type;
            } _perf;
        };
    } _sigfault;

    /* SIGPOLL */
    struct {
        __ARCH_SI_BAND_T _band; /* POLL_IN, POLL_OUT, POLL_MSG */
        int _fd;
    } _sigpoll;

    /* SIGSYS */
    struct {
        void __user *_call_addr;    /* calling user insn */
        int _syscall;               /* triggering system call number */
        unsigned int _arch;         /* AUDIT_ARCH_* of syscall */
    } _sigsys;
};

#define __SIGINFO           \
struct {                    \
    int si_signo;           \
    int si_code;            \
    int si_errno;           \
    union __sifields _sifields; \
}

typedef struct siginfo {
    union {
        __SIGINFO;
        int _si_pad[SI_MAX_SIZE/sizeof(int)];
    };
} siginfo_t;

/*
 * How these fields are to be accessed.
 */
#define si_pid      _sifields._kill._pid
#define si_uid      _sifields._kill._uid
#define si_tid      _sifields._timer._tid
#define si_overrun  _sifields._timer._overrun
#define si_sys_private  _sifields._timer._sys_private
#define si_status   _sifields._sigchld._status
#define si_utime    _sifields._sigchld._utime
#define si_stime    _sifields._sigchld._stime
#define si_value    _sifields._rt._sigval
#define si_int      _sifields._rt._sigval.sival_int
#define si_ptr      _sifields._rt._sigval.sival_ptr
#define si_addr     _sifields._sigfault._addr
#define si_trapno   _sifields._sigfault._trapno
#define si_addr_lsb _sifields._sigfault._addr_lsb
#define si_lower    _sifields._sigfault._addr_bnd._lower
#define si_upper    _sifields._sigfault._addr_bnd._upper
#define si_pkey     _sifields._sigfault._addr_pkey._pkey
#define si_perf_data    _sifields._sigfault._perf._data
#define si_perf_type    _sifields._sigfault._perf._type
#define si_band     _sifields._sigpoll._band
#define si_fd       _sifields._sigpoll._fd
#define si_call_addr    _sifields._sigsys._call_addr
#define si_syscall  _sifields._sigsys._syscall
#define si_arch     _sifields._sigsys._arch

/*
 * SIGILL si_codes
 */
#define ILL_ILLOPC  1   /* illegal opcode */
#define ILL_ILLOPN  2   /* illegal operand */
#define ILL_ILLADR  3   /* illegal addressing mode */
#define ILL_ILLTRP  4   /* illegal trap */
#define ILL_PRVOPC  5   /* privileged opcode */
#define ILL_PRVREG  6   /* privileged register */
#define ILL_COPROC  7   /* coprocessor error */
#define ILL_BADSTK  8   /* internal stack error */
#define ILL_BADIADDR    9   /* unimplemented instruction address */
#define __ILL_BREAK     10  /* illegal break */
#define __ILL_BNDMOD    11  /* bundle-update (modification) in progress */
#define NSIGILL     11

/*
 * SIGSEGV si_codes
 */
#define SEGV_MAPERR 1   /* address not mapped to object */
#define SEGV_ACCERR 2   /* invalid permissions for mapped object */
#define SEGV_BNDERR 3   /* failed address bound checks */
#define SEGV_PKUERR 4   /* failed protection key checks */
#define SEGV_ACCADI 5   /* ADI not enabled for mapped object */
#define SEGV_ADIDERR    6   /* Disrupting MCD error */
#define SEGV_ADIPERR    7   /* Precise MCD exception */
#define SEGV_MTEAERR    8   /* Asynchronous ARM MTE error */
#define SEGV_MTESERR    9   /* Synchronous ARM MTE exception */
#define NSIGSEGV    9

/*
 * SIGBUS si_codes
 */
#define BUS_ADRALN  1   /* invalid address alignment */
#define BUS_ADRERR  2   /* non-existent physical address */
#define BUS_OBJERR  3   /* object specific hardware error */
/* hardware memory error consumed on a machine check: action required */
#define BUS_MCEERR_AR   4
/* hardware memory error detected in process but not consumed: action optional*/
#define BUS_MCEERR_AO   5
#define NSIGBUS     5

#endif /* _UAPI_ASM_GENERIC_SIGINFO_H */
