/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>
#include <linux/types.h>

#include <asm/errno.h>

#ifndef __ASSEMBLY__

static inline void * __must_check ERR_PTR(long error)
{
    return (void *) error;
}

#endif /* ! __ASSEMBLY__ */

#endif /* _LINUX_ERR_H */
