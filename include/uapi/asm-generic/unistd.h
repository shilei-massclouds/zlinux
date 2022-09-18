/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#include <asm/bitsperlong.h>

/*
 * This file contains the system call numbers, based on the
 * layout of the x86-64 architecture, which embeds the
 * pointer to the syscall in the table.
 *
 * As a basic principle, no duplication of functionality
 * should be added, e.g. we don't use lseek when llseek
 * is present. New architectures should use this file
 * and implement the less feature-full calls in user space.
 */

#ifndef __SYSCALL
#define __SYSCALL(x, y)
#endif

/* fs/stat.c */
#define __NR_readlinkat 78
__SYSCALL(__NR_readlinkat, sys_readlinkat)

/* kernel/sys.c */
#define __NR_uname 160
__SYSCALL(__NR_uname, sys_newuname)

/* mm/nommu.c, also with MMU */
#define __NR_brk 214
__SYSCALL(__NR_brk, sys_brk)

/* fs/open.c */
#define __NR_faccessat 48
__SYSCALL(__NR_faccessat, sys_faccessat)

#define __NR_clock_gettime 113
__SYSCALL(__NR_clock_gettime, sys_clock_gettime)

#define __NR_clock_getres 114
__SYSCALL(__NR_clock_getres, sys_clock_getres)

#define __NR_rt_sigreturn 139
__SYSCALL(__NR_rt_sigreturn, sys_rt_sigreturn)

/* kernel/time.c */
#define __NR_gettimeofday 169
__SYSCALL(__NR_gettimeofday, sys_gettimeofday)

#undef __NR_syscalls
#define __NR_syscalls 451
