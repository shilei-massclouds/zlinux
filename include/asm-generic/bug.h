/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>

#ifndef __ASSEMBLY__

struct bug_entry {
    signed int  bug_addr_disp;
    signed int  file_disp;
    unsigned short  line;
    unsigned short  flags;
};

#ifndef HAVE_ARCH_BUG_ON
#define BUG_ON(condition) \
    do { if (unlikely(condition)) BUG(); } while (0)
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_GENERIC_BUG_H */
