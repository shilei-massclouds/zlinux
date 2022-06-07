/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>
#include <linux/irqflags.h>

/* Flags for a single printk record. */
enum printk_info_flags {
    LOG_NEWLINE = 2,    /* text ended with a newline */
    LOG_CONT    = 8,    /* text is a fragment of a continuation line */
};

__printf(4, 0)
int vprintk_store(int facility, int level,
                  const struct dev_printk_info *dev_info,
                  const char *fmt, va_list args);

__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_deferred(const char *fmt, va_list args);

bool printk_percpu_data_ready(void);
void defer_console_output(void);

void __printk_safe_enter(void);
void __printk_safe_exit(void);

#define printk_safe_enter_irqsave(flags)    \
    do {                    \
        local_irq_save(flags);      \
        __printk_safe_enter();      \
    } while (0)

#define printk_safe_exit_irqrestore(flags)  \
    do {                    \
        __printk_safe_exit();       \
        local_irq_restore(flags);   \
    } while (0)
