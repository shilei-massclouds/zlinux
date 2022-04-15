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

/* Relies on boot_command_line being set */
void __init parse_early_param(void);
void __init parse_early_options(char *cmdline);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_INIT_H */
