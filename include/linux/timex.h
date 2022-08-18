/*****************************************************************************
 *                                                                           *
 * Copyright (c) David L. Mills 1993                                         *
 *                                                                           *
 * Permission to use, copy, modify, and distribute this software and its     *
 * documentation for any purpose and without fee is hereby granted, provided *
 * that the above copyright notice appears in all copies and that both the   *
 * copyright notice and this permission notice appear in supporting          *
 * documentation, and that the name University of Delaware not be used in    *
 * advertising or publicity pertaining to distribution of the software       *
 * without specific, written prior permission.  The University of Delaware   *
 * makes no representations about the suitability this software for any      *
 * purpose.  It is provided "as is" without express or implied warranty.     *
 *                                                                           *
 *****************************************************************************/

#ifndef _LINUX_TIMEX_H
#define _LINUX_TIMEX_H

//#include <uapi/linux/timex.h>

#define ADJ_ADJTIME     0x8000  /* switch between adjtime/adjtimex modes */
#define ADJ_OFFSET_SINGLESHOT   0x0001  /* old-fashioned adjtime */
#define ADJ_OFFSET_READONLY 0x2000  /* read-only adjtime */
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/param.h>

unsigned long random_get_entropy_fallback(void);

#include <asm/timex.h>

#endif /* LINUX_TIMEX_H */
