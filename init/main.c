// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 */

#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/binfmts.h>
#include <linux/percpu.h>
#include <linux/console.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/rcupdate.h>
#include <linux/kernel_stat.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/device/driver.h>
#include <linux/irq.h>
#include <linux/fs.h>
#include <linux/init_syscalls.h>
#include <linux/kthread.h>
#include <linux/rmap.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/file.h>

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

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

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

static __initdata DECLARE_COMPLETION(kthreadd_done);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

static char *ramdisk_execute_command = "/init";

extern void time_init(void);

extern void radix_tree_init(void);

void __init __weak trap_init(void) { }

struct blacklist_entry {
    struct list_head next;
    char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
    char *str_entry;
    struct blacklist_entry *entry;

    /* str argument is a comma-separated list of functions */
    do {
        str_entry = strsep(&str, ",");
        if (str_entry) {
            pr_debug("blacklisting initcall %s\n", str_entry);
            entry = memblock_alloc(sizeof(*entry), SMP_CACHE_BYTES);
            if (!entry)
                panic("%s: Failed to allocate %zu bytes\n",
                      __func__, sizeof(*entry));
            entry->buf = memblock_alloc(strlen(str_entry) + 1, SMP_CACHE_BYTES);
            if (!entry->buf)
                panic("%s: Failed to allocate %zu bytes\n",
                      __func__, strlen(str_entry) + 1);
            strcpy(entry->buf, str_entry);
            list_add(&entry->next, &blacklisted_initcalls);
        }
    } while (str_entry);

    return 1;
}
__setup("initcall_blacklist=", initcall_blacklist);

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
    unsigned long addr;
    char fn_name[KSYM_SYMBOL_LEN];
    struct blacklist_entry *entry;

    if (list_empty(&blacklisted_initcalls))
        return false;

    panic("%s: NO implementation!\n", __func__);
}

extern initcall_entry_t __initcall_start[];
extern initcall_entry_t __initcall0_start[];
extern initcall_entry_t __initcall1_start[];
extern initcall_entry_t __initcall2_start[];
extern initcall_entry_t __initcall3_start[];
extern initcall_entry_t __initcall4_start[];
extern initcall_entry_t __initcall5_start[];
extern initcall_entry_t __initcall6_start[];
extern initcall_entry_t __initcall7_start[];
extern initcall_entry_t __initcall_end[];

static initcall_entry_t *initcall_levels[] __initdata = {
    __initcall0_start,
    __initcall1_start,
    __initcall2_start,
    __initcall3_start,
    __initcall4_start,
    __initcall5_start,
    __initcall6_start,
    __initcall7_start,
    __initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static const char *initcall_level_names[] __initdata = {
    "pure",
    "core",
    "postcore",
    "arch",
    "subsys",
    "fs",
    "device",
    "late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
                                            const char *unused, void *arg)
{
    return 0;
}

int __init_or_module do_one_initcall(initcall_t fn)
{
    int ret;
    char msgbuf[64];
    int count = preempt_count();

    if (initcall_blacklisted(fn))
        return -EPERM;

    ret = fn();

    msgbuf[0] = 0;

    if (preempt_count() != count) {
        sprintf(msgbuf, "preemption imbalance ");
        preempt_count_set(count);
    }
    if (irqs_disabled()) {
        strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
        local_irq_enable();
    }
    WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

    return ret;
}

static void __init do_initcall_level(int level, char *command_line)
{
    initcall_entry_t *fn;

    parse_args(initcall_level_names[level], command_line,
               __start___param, __stop___param - __start___param,
               level, level, NULL, ignore_unknown_bootoption);

    for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
        do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
    int level;
    size_t len = strlen(saved_command_line) + 1;
    char *command_line;

    command_line = kzalloc(len, GFP_KERNEL);
    if (!command_line)
        panic("%s: Failed to allocate %zu bytes\n", __func__, len);

    for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
        /* Parser modifies command_line, restore it each time */
        strcpy(command_line, saved_command_line);
        do_initcall_level(level, command_line);
    }

    kfree(command_line);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
    printk("%s: ...\n", __func__);
#if 0
    cpuset_init_smp();
#endif
    driver_init();
#if 0
    init_irq_proc();
    do_ctors();
#endif
    do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
    initcall_entry_t *fn;

    for (fn = __initcall_start; fn < __initcall0_start; fn++)
        do_one_initcall(initcall_from_entry(fn));
}

/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
    struct file *file = filp_open("/dev/console", O_RDWR, 0);

    if (IS_ERR(file)) {
        pr_err("Warning: unable to open an initial console.\n");
        return;
    }
    init_dup(file);
    init_dup(file);
    init_dup(file);
    fput(file);
}

static noinline void __init kernel_init_freeable(void)
{
    /* Now the scheduler is fully set up and can do blocking allocations */
    gfp_allowed_mask = __GFP_BITS_MASK;

#if 0
    /*
     * init can allocate pages on any node
     */
    set_mems_allowed(node_states[N_MEMORY]);

    cad_pid = get_pid(task_pid(current));

    smp_prepare_cpus(setup_max_cpus);
#endif

    workqueue_init();

#if 0
    init_mm_internals();

    rcu_init_tasks_generic();
#endif
    do_pre_smp_initcalls();
#if 0
    lockup_detector_init();
#endif

    smp_init();
    sched_init_smp();

#if 0
    padata_init();
#endif
    page_alloc_init_late();
#if 0
    /* Initialize page ext after all struct pages are initialized. */
    page_ext_init();
#endif

    do_basic_setup();

    console_on_rootfs();

    /*
     * check if there is an early userspace init.  If yes, let it do all
     * the work
     */
    if (init_eaccess(ramdisk_execute_command) != 0) {
        ramdisk_execute_command = NULL;
        prepare_namespace();
    }

    /*
     * Ok, we have completed the initial bootup, and
     * we're essentially up and running. Get rid of the
     * initmem segments and start the user-mode stuff..
     *
     * rootfs is available now, try loading the public keys
     * and default modules
     */

}

static int run_init_process(const char *init_filename)
{
    const char *const *p;

    argv_init[0] = init_filename;
    pr_info("Run %s as init process\n", init_filename);
    pr_debug("  with arguments:\n");
    for (p = argv_init; *p; p++)
        pr_debug("    %s\n", *p);
    pr_debug("  with environment:\n");
    for (p = envp_init; *p; p++)
        pr_debug("    %s\n", *p);
    return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
    int ret;

    ret = run_init_process(init_filename);

    if (ret && ret != -ENOENT) {
        pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
               init_filename, ret);
    }

    return ret;
}

static int __ref kernel_init(void *unused)
{
    int ret;

    printk("############## %s: ...\n", __func__);
    /*
     * Wait until kthreadd is all set-up.
     */
    wait_for_completion(&kthreadd_done);

    kernel_init_freeable();
#if 0
    /* need to finish all async __init code before freeing the memory */
    async_synchronize_full();
#endif

    system_state = SYSTEM_FREEING_INITMEM;
    free_initmem();

    /* */

    system_state = SYSTEM_RUNNING;

    z_tests();

    printk("############## %s: before /sbin/init \n", __func__);
    if (!try_to_run_init_process("/sbin/init") ||
        !try_to_run_init_process("/etc/init") ||
        !try_to_run_init_process("/bin/init") ||
        !try_to_run_init_process("/bin/sh"))
        return 0;

    panic("No working init found.  Try passing init= option to kernel. "
          "See Linux Documentation/admin-guide/init.rst for guidance.");
}

noinline void __ref rest_init(void)
{
    struct task_struct *tsk;
    int pid;

    printk("############## %s: ...\n", __func__);

    z_tests_early();

    rcu_scheduler_starting();

    /*
     * We need to spawn init first so that it obtains pid 1, however
     * the init task will end up wanting to create kthreads, which, if
     * we schedule it before we create kthreadd, will OOPS.
     */
    pid = kernel_thread(kernel_init, NULL, CLONE_FS);
    /*
     * Pin init on the boot CPU. Task migration is not properly working
     * until sched_init_smp() has been run. It will set the allowed
     * CPUs for init to the non isolated CPUs.
     */
    rcu_read_lock();
    tsk = find_task_by_pid_ns(pid, &init_pid_ns);
    tsk->flags |= PF_NO_SETAFFINITY;
    set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
    rcu_read_unlock();

    pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
    rcu_read_lock();
    kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
    rcu_read_unlock();

    /*
     * Enable might_sleep() and smp_processor_id() checks.
     * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
     * kernel_thread() would trigger might_sleep() splats. With
     * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
     * already, but it's stuck on the kthreadd_done completion.
     */
    system_state = SYSTEM_SCHEDULING;

    complete(&kthreadd_done);

    printk("###### %s: 3\n", __func__);

    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();

    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(CPUHP_ONLINE);
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
#endif
    vmalloc_init();
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

asmlinkage __visible
void __init __no_sanitize_address start_kernel(void)
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
    page_alloc_init();

    pr_notice("Kernel command line: %s\n", saved_command_line);
    /* parameters may set static keys */
    jump_label_init();
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

    printk("############## %s: step1\n", __func__);

#if 0
    /*
     * These use large bootmem allocations and must precede
     * kmem_cache_init()
     */
    setup_log_buf(0);
#endif
    vfs_caches_init_early();
#if 0
    sort_main_extable();
#endif
    trap_init();
    mm_init();

    /*
     * Set up the scheduler prior starting any interrupts (such as the
     * timer interrupt). Full topology setup happens at smp_init()
     * time - but meanwhile we still have a functioning scheduler.
     */
    sched_init();

    if (WARN(!irqs_disabled(),
             "Interrupts were enabled *very* early, fixing it\n"))
        local_irq_disable();
    radix_tree_init();

#if 0
    /*
     * Set up housekeeping before setting up workqueues to allow the unbound
     * workqueue to take non-housekeeping into account.
     */
    housekeeping_init();
#endif

    /*
     * Allow workqueue creation and work item queueing/cancelling
     * early.  Work item execution depends on kthreads and starts after
     * workqueue_init().
     */
    workqueue_init_early();

    printk("############## %s: step2\n", __func__);

    init_IRQ();
    hrtimers_init();
    softirq_init();
    timekeeping_init();
    time_init();

    setup_per_cpu_pageset();

    early_boot_irqs_disabled = false;
    local_irq_enable();

    kmem_cache_init_late();

    /*
     * HACK ALERT! This is early. We're enabling the console before
     * we've done PCI setups etc, and console_init() must be aware of
     * this. But we do want output early, in case something goes wrong.
     */
    console_init();
#if 0
    if (panic_later)
        panic("Too many boot %s vars at `%s'",
              panic_later, panic_param);
#endif

    sched_clock_init();

    pid_idr_init();
    anon_vma_init();

    printk("############## %s: step3\n", __func__);

    cred_init();
    fork_init();
    proc_caches_init();
    uts_ns_init();

    vfs_caches_init();
    pagecache_init();
    signals_init();
    proc_root_init();

    printk("############## %s: step!\n", __func__);
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
