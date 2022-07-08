// SPDX-License-Identifier: GPL-2.0-only

//#include <linux/debug_locks.h>
#include <linux/sched/debug.h>
#if 0
#include <linux/interrupt.h>
#include <linux/kgdb.h>
#include <linux/kmsg_dump.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/vt_kern.h>
#endif
#include <linux/module.h>
#if 0
#include <linux/random.h>
#include <linux/ftrace.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#endif
#include <linux/sched.h>
//#include <linux/sysrq.h>
#include <linux/init.h>
//#include <linux/nmi.h>
#include <linux/console.h>
#include <linux/bug.h>
#include <linux/reboot.h>
//#include <linux/ratelimit.h>
//#include <linux/debugfs.h>
#include <asm/sections.h>

#include <linux/irqflags.h>

#define PANIC_TIMER_STEP 100
#define PANIC_BLINK_SPD 18

bool crash_kexec_post_notifiers;

atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

/*
 * Stop ourself in panic -- architecture code may override this
 */
void __weak panic_smp_self_stop(void)
{
    while (1)
        cpu_relax();
}

/**
 *  panic - halt the system
 *  @fmt: The text string to print
 *
 *  Display a message, then perform cleanups.
 *
 *  This function never returns.
 */
void panic(const char *fmt, ...)
{
    //long i, i_next = 0, len;
    long i, len;
    va_list args;
    int old_cpu, this_cpu;
    static char buf[1024];
#if 0
    int state = 0;
    bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;
#endif

    /*
     * Disable local interrupts. This will prevent panic_smp_self_stop
     * from deadlocking the first cpu that invokes the panic, since
     * there is nothing to prevent an interrupt handler (that runs
     * after setting panic_cpu) from invoking panic() again.
     */
    local_irq_disable();
    preempt_disable_notrace();

    /*
     * It's possible to come here directly from a panic-assertion and
     * not have preempt disabled. Some functions called from here want
     * preempt to be disabled. No point enabling it later though...
     *
     * Only one CPU is allowed to execute the panic code from here. For
     * multiple parallel invocations of panic, all other CPUs either
     * stop themself or will wait until they are stopped by the 1st CPU
     * with smp_send_stop().
     *
     * `old_cpu == PANIC_CPU_INVALID' means this is the 1st CPU which
     * comes here, so go ahead.
     * `old_cpu == this_cpu' means we came from nmi_panic() which sets
     * panic_cpu to this CPU.  In this case, this is also the 1st CPU.
     */
    this_cpu = raw_smp_processor_id();
    old_cpu  = atomic_cmpxchg(&panic_cpu, PANIC_CPU_INVALID, this_cpu);

    if (old_cpu != PANIC_CPU_INVALID && old_cpu != this_cpu)
        panic_smp_self_stop();

    console_verbose();
    //bust_spinlocks(1);
    va_start(args, fmt);
    len = vscnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    pr_emerg("Kernel panic - not syncing: %s\n", buf);

    pr_emerg("---[ end Kernel panic - not syncing: %s ]---\n", buf);

    /* Do not scroll important messages printed above */
    suppress_printk = 1;
    local_irq_enable();
#if 0
    for (i = 0; ; i += PANIC_TIMER_STEP) {
        touch_softlockup_watchdog();
        if (i >= i_next) {
            i += panic_blink(state ^= 1);
            i_next = i + 3600 / PANIC_BLINK_SPD;
        }
        mdelay(PANIC_TIMER_STEP);
    }
#endif

    /* Power off when panic */
    machine_power_off();
}
EXPORT_SYMBOL(panic);

#ifdef CONFIG_STACKPROTECTOR
/*
 * Called when gcc's -fstack-protector feature is used, and
 * gcc detects corruption of the on-stack canary value
 */
__visible noinstr void __stack_chk_fail(void)
{
    panic("stack-protector: Kernel stack is corrupted in: %pB",
          __builtin_return_address(0));
}
EXPORT_SYMBOL(__stack_chk_fail);
#endif
