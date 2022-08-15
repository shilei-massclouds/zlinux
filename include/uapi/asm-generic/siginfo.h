/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_SIGINFO_H
#define _UAPI_ASM_GENERIC_SIGINFO_H

#include <linux/compiler.h>
#include <linux/types.h>

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
