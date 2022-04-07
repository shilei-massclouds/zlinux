/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BUG_H
#define _LINUX_BUG_H

#include <asm/bug.h>

#ifdef CONFIG_GENERIC_BUG
#include <asm-generic/bug.h>
#else   /* !CONFIG_GENERIC_BUG */
#endif  /* CONFIG_GENERIC_BUG */

#endif  /* _LINUX_BUG_H */
