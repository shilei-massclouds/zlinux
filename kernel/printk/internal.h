/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>
#include <linux/irqflags.h>

__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_func(const char *fmt, va_list args);

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
