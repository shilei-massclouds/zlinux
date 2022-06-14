// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/rcupdate.h>
#include <linux/kernel_stat.h>

#include <asm/setup.h>
#include "z_tests.h"

#define bootconfig_found false

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;

/* Command line for parameter parsing */
static char *static_command_line;

/* Untouched extra command line */
static char *extra_command_line;

/* Extra init arguments */
static char *extra_init_args;

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

static int __ref kernel_init(void *unused)
{
    panic("%s: BEGIN!\n", __func__);

    system_state = SYSTEM_FREEING_INITMEM;

    /* */

    system_state = SYSTEM_RUNNING;

    z_tests();

    panic("%s: END!\n", __func__);
}

noinline void __ref rest_init(void)
{
    int pid;

    z_tests_early();

    rcu_scheduler_starting();

    /*
     * We need to spawn init first so that it obtains pid 1, however
     * the init task will end up wanting to create kthreads, which, if
     * we schedule it before we create kthreadd, will OOPS.
     */
    pid = kernel_thread(kernel_init, NULL, CLONE_FS);

    panic("%s: pid(%d) END!\n", __func__, pid);

    /*
     * Enable might_sleep() and smp_processor_id() checks.
     * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
     * kernel_thread() would trigger might_sleep() splats. With
     * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
     * already, but it's stuck on the kthreadd_done completion.
     */
    system_state = SYSTEM_SCHEDULING;
}

void __init __weak arch_call_rest_init(void)
{
    rest_init();
}

/* Report memory auto-initialization states for this boot. */
static void __init report_meminit(void)
{
    pr_info("mem auto-init: stack:off, heap alloc:%s, heap free:%s\n",
            want_init_on_alloc(GFP_KERNEL) ? "on" : "off",
            want_init_on_free() ? "on" : "off");
    if (want_init_on_free())
        pr_info("mem auto-init: clearing system memory may take some time...\n");
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
    /*
     * page_ext requires contiguous pages,
     * bigger than MAX_ORDER unless SPARSEMEM.
     */
#if 0
    page_ext_init_flatmem();
    init_mem_debugging_and_hardening();
#endif
    report_meminit();
    mem_init();
    mem_init_print_info();
    kmem_cache_init();
    /*
     * page_owner must be initialized after buddy is ready, and also after
     * slab is ready so that stack_depot_init() works properly
     */
#if 0
    page_ext_init_flatmem_late();
    vmalloc_init();
#endif
}

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
    size_t len, xlen = 0, ilen = 0;

    if (extra_command_line)
        xlen = strlen(extra_command_line);
    if (extra_init_args)
        ilen = strlen(extra_init_args) + 4; /* for " -- " */

    len = xlen + strlen(boot_command_line) + 1;

    saved_command_line = memblock_alloc(len + ilen, SMP_CACHE_BYTES);
    if (!saved_command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len + ilen);

    static_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
    if (!static_command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len);

    if (xlen) {
        /*
         * We have to put extra_command_line before boot command
         * lines because there could be dashes (separator of init
         * command line) in the command lines.
         */
        strcpy(saved_command_line, extra_command_line);
        strcpy(static_command_line, extra_command_line);
    }
    strcpy(saved_command_line + xlen, boot_command_line);
    strcpy(static_command_line + xlen, command_line);

    if (ilen) {
        /*
         * Append supplemental init boot args to saved_command_line
         * so that user can check what command line options passed
         * to init.
         * The order should always be
         * " -- "[bootconfig init-param][cmdline init-param]
         */
        len = strlen(saved_command_line);
        strcpy(saved_command_line + len, " -- ");
        len += 4;
        strcpy(saved_command_line + len, extra_init_args);
    }
}

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
    if (val) {
        /* param=val or param="val"? */
        if (val == param+strlen(param)+1)
            val[-1] = '=';
        else if (val == param+strlen(param)+2) {
            val[-2] = '=';
            memmove(val-1, val, strlen(val)+1);
        } else
            BUG();
    }
}

static bool __init obsolete_checksetup(char *line)
{
    const struct obs_kernel_param *p;
    bool had_early_param = false;

    p = __setup_start;
    do {
        int n = strlen(p->str);
        if (parameqn(line, p->str, n)) {
            if (p->early) {
                /* Already done in parse_early_param?
                 * (Needs exact match on param part).
                 * Keep iterating, as we can have early
                 * params and __setups of same names 8( */
                if (line[n] == '\0' || line[n] == '=')
                    had_early_param = true;
            } else if (!p->setup_func) {
                pr_warn("Parameter %s is obsolete, ignored\n", p->str);
                return true;
            } else if (p->setup_func(line + n))
                return true;
        }
        p++;
    } while (p < __setup_end);

    return had_early_param;
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
                               const char *unused, void *arg)
{
    unsigned int i;

    if (panic_later)
        return 0;

    repair_env_string(param, val);

    for (i = 0; argv_init[i]; i++) {
        if (i == MAX_INIT_ARGS) {
            panic_later = "init";
            panic_param = param;
            return 0;
        }
    }
    argv_init[i] = param;
    return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
                                     const char *unused, void *arg)
{
    size_t len = strlen(param);

    repair_env_string(param, val);

    /* Handle obsolete-style parameters */
    if (obsolete_checksetup(param))
        return 0;

    /* Unused module parameter. */
    if (strnchr(param, len, '.'))
        return 0;

    if (panic_later)
        return 0;

    if (val) {
        /* Environment option */
        unsigned int i;
        for (i = 0; envp_init[i]; i++) {
            if (i == MAX_INIT_ENVS) {
                panic_later = "env";
                panic_param = param;
            }
            if (!strncmp(param, envp_init[i], len+1))
                break;
        }
        envp_init[i] = param;
    } else {
        /* Command line option */
        unsigned int i;
        for (i = 0; argv_init[i]; i++) {
            if (i == MAX_INIT_ARGS) {
                panic_later = "init";
                panic_param = param;
            }
        }
        argv_init[i] = param;
    }
    return 0;
}

static void __init print_unknown_bootoptions(void)
{
    char *unknown_options;
    char *end;
    const char *const *p;
    size_t len;

    if (panic_later || (!argv_init[1] && !envp_init[2]))
        return;

    /*
     * Determine how many options we have to print out, plus a space
     * before each
     */
    len = 1; /* null terminator */
    for (p = &argv_init[1]; *p; p++) {
        len++;
        len += strlen(*p);
    }
    for (p = &envp_init[2]; *p; p++) {
        len++;
        len += strlen(*p);
    }

    unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
    if (!unknown_options) {
        pr_err("%s: Failed to allocate %zu bytes\n",
            __func__, len);
        return;
    }
    end = unknown_options;

    for (p = &argv_init[1]; *p; p++)
        end += sprintf(end, " %s", *p);
    for (p = &envp_init[2]; *p; p++)
        end += sprintf(end, " %s", *p);

    /* Start at unknown_options[1] to skip the initial space */
    pr_notice("Unknown kernel command line parameters \"%s\", "
              "will be passed to user space.\n",
              &unknown_options[1]);
    memblock_free(unknown_options, len);
}

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
    char *command_line;
    char *after_dashes;

    set_task_stack_end_magic(&init_task);
    smp_setup_processor_id();

    local_irq_disable();
    early_boot_irqs_disabled = true;

    /*
     * Interrupts are still disabled. Do necessary setups, then
     * enable them.
     */
    boot_cpu_init();

    pr_notice("%s", linux_banner);
    setup_arch(&command_line);

#if 0
    setup_boot_config();
#endif
    setup_command_line(command_line);
    setup_nr_cpu_ids();

    setup_per_cpu_areas();
#if 0
    smp_prepare_boot_cpu(); /* arch-specific boot-cpu hooks */
#endif
    boot_cpu_hotplug_init();

    build_all_zonelists(NULL);
#if 0
    page_alloc_init();
#endif

    pr_notice("Kernel command line: %s\n", saved_command_line);

#if 0
    /* parameters may set static keys */
    jump_label_init();
#endif
    parse_early_param();
    after_dashes = parse_args("Booting kernel",
                              static_command_line, __start___param,
                              __stop___param - __start___param,
                              -1, -1, NULL, &unknown_bootoption);

    print_unknown_bootoptions();
    if (!IS_ERR_OR_NULL(after_dashes))
        parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
                   NULL, set_init_arg);
    if (extra_init_args)
        parse_args("Setting extra init args", extra_init_args,
                   NULL, 0, -1, -1, NULL, set_init_arg);

#if 0
    /*
     * These use large bootmem allocations and must precede
     * kmem_cache_init()
     */
    setup_log_buf(0);
    vfs_caches_init_early();
    sort_main_extable();
    trap_init();
#endif
    mm_init();

    setup_per_cpu_pageset();

    early_boot_irqs_disabled = false;
    local_irq_enable();

    kmem_cache_init_late();
    printk("%s: ================== PILOT ==================\n", __func__);

    fork_init();

    /* Do the rest non-__init'ed, we're now alive */
    arch_call_rest_init();

    prevent_tail_call_optimization();
}

/* Check for early params. */
static int __init
do_early_param(char *param, char *val, const char *unused, void *arg)
{
    const struct obs_kernel_param *p;

    for (p = __setup_start; p < __setup_end; p++) {
        if ((p->early && parameq(param, p->str)) ||
            (strcmp(param, "console") == 0 &&
             strcmp(p->str, "earlycon") == 0)
        ) {
            if (p->setup_func(val) != 0)
                pr_warn("Malformed early option '%s'\n", param);
        }
    }
    /* We accept everything at this stage. */
    return 0;
}

void __init parse_early_options(char *cmdline)
{
    parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
               do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
    static int done __initdata;
    static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

    if (done)
        return;

    /* All fall through to do_early_param. */
    strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
    parse_early_options(tmp_cmdline);
    done = 1;
}
