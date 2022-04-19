/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <linux/compiler.h>
#include <linux/types.h>

#define __noinitretpoline

/* These are for everybody (although not all archs will actually
   discard it in modules) */
#define __init \
    __section(.init.text) __cold __latent_entropy __noinitretpoline

#define __initdata  __section(.init.data)
#define __initconst __section(.init.rodata)

/* For assembly routines */
#define __HEAD  .section ".head.text","ax"
#define __INIT  .section ".init.text","ax"

#ifndef __ASSEMBLY__

struct obs_kernel_param {
    const char *str;
    int (*setup_func)(char *);
    int early;
};

extern char __initdata boot_command_line[];

/* used by init/main.c */
void setup_arch(char **);

/*
 * Only for really core code.  See moduleparam.h for the normal way.
 *
 * Force the alignment so the compiler doesn't space elements of the
 * obs_kernel_param "array" too far apart in .init.setup.
 */
#define __setup_param(str, unique_id, fn, early)                \
    static const char __setup_str_##unique_id[] __initconst     \
        __aligned(1) = str;                                     \
    static struct obs_kernel_param __setup_##unique_id          \
        __used __section(.init.setup)                           \
        __attribute__((aligned((sizeof(long)))))                \
        = { __setup_str_##unique_id, fn, early }

#define __setup(str, fn) __setup_param(str, fn, fn, 0)

/*
 * NOTE: fn is as per module_param, not __setup!
 * Emits warning if fn returns non-zero.
 */
#define early_param(str, fn) __setup_param(str, fn, fn, 1)

/* Relies on boot_command_line being set */
void __init parse_early_param(void);
void __init parse_early_options(char *cmdline);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_INIT_H */
