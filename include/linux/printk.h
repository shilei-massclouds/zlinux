/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KERNEL_PRINTK__
#define __KERNEL_PRINTK__

#include <linux/stdarg.h>
#include <linux/init.h>
#include <linux/kern_levels.h>
#include <linux/linkage.h>
#include <linux/cache.h>
#include <linux/ratelimit_types.h>
#include <linux/once_lite.h>

struct va_format {
    const char *fmt;
    va_list *va;
};

/* printk's without a loglevel use this.. */
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT

#define CONSOLE_LOGLEVEL_MIN 1 /* Minimum loglevel we let people use */

/*
 * Default used to be hard-coded at 7, quiet used to be hardcoded at 4,
 * we're now allowing both to be set from kernel config.
 */
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_QUIET   CONFIG_CONSOLE_LOGLEVEL_QUIET

extern int suppress_printk;
extern int console_printk[];

#define console_loglevel (console_printk[0])
#define default_message_loglevel (console_printk[1])

static inline int printk_get_level(const char *buffer)
{
    if (buffer[0] == KERN_SOH_ASCII && buffer[1]) {
        switch (buffer[1]) {
        case '0' ... '7':
        case 'c':   /* KERN_CONT */
            return buffer[1];
        }
    }
    return 0;
}

/**
 * pr_fmt - used by the pr_*() macros to generate the printk format string
 * @fmt: format string passed from a pr_*() macro
 *
 * This macro can be used to generate a unified format string for pr_*()
 * macros. A common use is to prefix all pr_*() messages in a file with a common
 * string. For example, defining this at the top of a source file:
 *
 *        #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 *
 * would prefix all pr_info, pr_emerg... messages in the file with the module
 * name.
 */
#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

/**
 * pr_emerg - Print an emergency-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_EMERG loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_emerg(fmt, ...) \
    printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_alert - Print an alert-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_ALERT loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_alert(fmt, ...) \
    printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)

/*
 * Dummy printk for disabled debugging statements to use whilst maintaining
 * gcc's format checking.
 */
#define no_printk(fmt, ...)         \
({                                  \
    if (0)                          \
        printk(fmt, ##__VA_ARGS__); \
    0;                              \
})

#if defined(DEBUG)
#define pr_debug(fmt, ...) \
    printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) \
    no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

/**
 * pr_crit - Print a critical-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_CRIT loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_crit(fmt, ...) \
    printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
/**
 * pr_err - Print an error-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_ERR loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_err(fmt, ...) \
    printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
/**
 * pr_warn - Print a warning-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_WARNING loglevel. It uses pr_fmt()
 * to generate the format string.
 */
#define pr_warn(fmt, ...) \
    printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
/**
 * pr_notice - Print a notice-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_NOTICE loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_notice(fmt, ...) \
    printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_info - Print an info-level message
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_INFO loglevel. It uses pr_fmt() to
 * generate the format string.
 */
#define pr_info(fmt, ...) \
    printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

/**
 * pr_cont - Continues a previous log message in the same line.
 * @fmt: format string
 * @...: arguments for the format string
 *
 * This macro expands to a printk with KERN_CONT loglevel. It should only be
 * used when continuing a log message with no newline ('\n') enclosed. Otherwise
 * it defaults back to KERN_DEFAULT loglevel.
 */
#define pr_cont(fmt, ...) printk(KERN_CONT fmt, ##__VA_ARGS__)

#define printk_once(fmt, ...) DO_ONCE_LITE(printk, fmt, ##__VA_ARGS__)

#if 0
#define printk_ratelimited(fmt, ...)                    \
({                                  \
    static DEFINE_RATELIMIT_STATE(_rs,              \
                      DEFAULT_RATELIMIT_INTERVAL,   \
                      DEFAULT_RATELIMIT_BURST);     \
                                    \
    if (__ratelimit(&_rs))                      \
        printk(fmt, ##__VA_ARGS__);             \
})
#else
#define printk_ratelimited(fmt, ...) \
    printk(fmt, ##__VA_ARGS__);
#endif

#define pr_emerg_ratelimited(fmt, ...)                  \
    printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...)                  \
    printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)                   \
    printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)                    \
    printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...) \
    printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...)                 \
    printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)                   \
    printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

asmlinkage __printf(1, 2) __cold
int printk(const char *fmt, ...);

#define CONSOLE_EXT_LOG_MAX 8192

#define CONSOLE_LOGLEVEL_MOTORMOUTH 15  /* You can't shut this one up */

static inline void console_verbose(void)
{
    if (console_loglevel)
        console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;
}

extern const char linux_banner[];

asmlinkage __printf(1, 0)
int vprintk(const char *fmt, va_list args);

/* If set, an oops, panic(), BUG() or die() is in progress */
extern int oops_in_progress;

#define pr_emerg_once(fmt, ...)                 \
    printk_once(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_once(fmt, ...)                 \
    printk_once(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)                  \
    printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_once(fmt, ...)                   \
    printk_once(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_once(fmt, ...)                  \
    printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_once(fmt, ...)                \
    printk_once(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_once(fmt, ...)                  \
    printk_once(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

__printf(1, 2) void dump_stack_set_arch_desc(const char *fmt, ...);

#define __printk_index_emit(...) do {} while (0)

/*
 * Some subsystems have their own custom printk that applies a va_format to a
 * generic format, for example, to include a device number or other metadata
 * alongside the format supplied by the caller.
 *
 * In order to store these in the way they would be emitted by the printk
 * infrastructure, the subsystem provides us with the start, fixed string, and
 * any subsequent text in the format string.
 *
 * We take a variable argument list as pr_fmt/dev_fmt/etc are sometimes passed
 * as multiple arguments (eg: `"%s: ", "blah"`), and we must only take the
 * first one.
 *
 * subsys_fmt_prefix must be known at compile time, or compilation will fail
 * (since this is a mistake). If fmt or level is not known at compile time, no
 * index entry will be made (since this can legitimately happen).
 */
#define printk_index_subsys_emit(subsys_fmt_prefix, level, fmt, ...) \
    __printk_index_emit(fmt, level, subsys_fmt_prefix)

#endif /* __KERNEL_PRINTK__ */
