/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>
#include <linux/instrumentation.h>
#include <linux/once_lite.h>

#define CUT_HERE        "------------[ cut here ]------------\n"

#define BUGFLAG_WARNING         (1 << 0)
#define BUGFLAG_ONCE            (1 << 1)
#define BUGFLAG_DONE            (1 << 2)
#define BUGFLAG_NO_CUT_HERE     (1 << 3)    /* CUT_HERE already sent */
#define BUGFLAG_TAINT(taint)    ((taint) << 8)
#define BUG_GET_TAINT(bug)      ((bug)->flags >> 8)

#ifndef __ASSEMBLY__
#include <linux/panic.h>
#include <linux/printk.h>

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

extern __printf(1, 2) void __warn_printk(const char *fmt, ...);
#define __WARN_printf(taint, arg...) do {               \
        instrumentation_begin();                \
        __warn_printk(arg);                 \
        __WARN_FLAGS(BUGFLAG_NO_CUT_HERE | BUGFLAG_TAINT(taint));\
        instrumentation_end();                  \
    } while (0)

#ifndef WARN
#define WARN(condition, format...) ({                   \
    int __ret_warn_on = !!(condition);              \
    if (unlikely(__ret_warn_on))                    \
        __WARN_printf(TAINT_WARN, format);          \
    unlikely(__ret_warn_on);                    \
})
#endif

#define WARN_ON_ONCE(condition) ({              \
    int __ret_warn_on = !!(condition);          \
    if (unlikely(__ret_warn_on))                \
        __WARN_FLAGS(BUGFLAG_ONCE |             \
                     BUGFLAG_TAINT(TAINT_WARN));    \
    unlikely(__ret_warn_on);                    \
})

#define WARN_ONCE(condition, format...) \
    DO_ONCE_LITE_IF(condition, WARN, 1, format)

#define WARN_ON_FUNCTION_MISMATCH(x, fn) WARN_ON_ONCE((x) != (fn))

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_GENERIC_BUG_H */
