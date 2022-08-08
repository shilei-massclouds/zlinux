/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_RESOURCE_H
#define _UAPI_ASM_GENERIC_RESOURCE_H

/*
 * Resource limit IDs
 *
 * ( Compatibility detail: there are architectures that have
 *   a different rlimit ID order in the 5-9 range and want
 *   to keep that order for binary compatibility. The reasons
 *   are historic and all new rlimits are identical across all
 *   arches. If an arch has such special order for some rlimits
 *   then it defines them prior including asm-generic/resource.h. )
 */
#define RLIMIT_CPU      0   /* CPU time in sec */
#define RLIMIT_FSIZE    1   /* Maximum filesize */
#define RLIMIT_DATA     2   /* max data size */
#define RLIMIT_STACK    3   /* max stack size */
#define RLIMIT_CORE     4   /* max core file size */
#define RLIMIT_RSS      5   /* max resident set size */
#define RLIMIT_NPROC    6   /* max number of processes */
#define RLIMIT_NOFILE   7   /* max number of open files */
#define RLIMIT_MEMLOCK  8   /* max locked-in-memory address space */
# define RLIMIT_AS      9   /* address space limit */
#define RLIMIT_LOCKS        10  /* maximum file locks held */
#define RLIMIT_SIGPENDING   11  /* max number of pending signals */
#define RLIMIT_MSGQUEUE     12  /* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE         13  /* max nice prio allowed to raise to
                                   0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO       14  /* maximum realtime priority */
#define RLIMIT_RTTIME       15  /* timeout for RT tasks in us */
#define RLIM_NLIMITS        16

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#define RLIM_INFINITY       (~0UL)

#endif /* _UAPI_ASM_GENERIC_RESOURCE_H */
