/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>

#define BUGFLAG_WARNING         (1 << 0)
#define BUGFLAG_ONCE            (1 << 1)
#define BUGFLAG_DONE            (1 << 2)
#define BUGFLAG_NO_CUT_HERE     (1 << 3)    /* CUT_HERE already sent */
#define BUGFLAG_TAINT(taint)    ((taint) << 8)
#define BUG_GET_TAINT(bug)      ((bug)->flags >> 8)

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

#define __WARN()    __WARN_FLAGS(BUGFLAG_TAINT(TAINT_WARN))

#ifndef WARN_ON
#define WARN_ON(condition) ({                       \
    int __ret_warn_on = !!(condition);              \
    if (unlikely(__ret_warn_on))                    \
        __WARN();                       \
    unlikely(__ret_warn_on);                    \
})
#endif

#ifndef WARN
#define WARN(condition, format...) ({   \
    int __ret_warn_on = !!(condition);  \
    no_printk(format);                  \
    unlikely(__ret_warn_on);            \
})
#endif

#define WARN_ON_ONCE(condition) ({              \
    int __ret_warn_on = !!(condition);          \
    if (unlikely(__ret_warn_on))                \
        __WARN_FLAGS(BUGFLAG_ONCE |             \
                     BUGFLAG_TAINT(TAINT_WARN));    \
    unlikely(__ret_warn_on);                    \
})

#define WARN_ONCE(condition, format...) ({          \
    static bool __section(.data.once) __warned;     \
    int __ret_warn_once = !!(condition);            \
                                \
    if (unlikely(__ret_warn_once && !__warned)) {       \
        __warned = true;                \
        WARN(1, format);                \
    }                           \
    unlikely(__ret_warn_once);              \
})

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_GENERIC_BUG_H */
