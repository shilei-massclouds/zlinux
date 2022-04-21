// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/console.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/semaphore.h>

#include "console_cmdline.h"
#include "internal.h"

#define PREFIX_MAX      32
#define LOG_LINE_MAX    (1024 - PREFIX_MAX)

#define logbuf_lock_irqsave(flags)          \
    do {                        \
        printk_safe_enter_irqsave(flags);   \
        raw_spin_lock(&logbuf_lock);        \
    } while (0)

#define logbuf_unlock_irqrestore(flags)     \
    do {                        \
        raw_spin_unlock(&logbuf_lock);      \
        printk_safe_exit_irqrestore(flags); \
    } while (0)

static bool printk_time = true;

int console_printk[4] = {
    CONSOLE_LOGLEVEL_DEFAULT,   /* console_loglevel */
    MESSAGE_LOGLEVEL_DEFAULT,   /* default_message_loglevel */
    CONSOLE_LOGLEVEL_MIN,       /* minimum_console_loglevel */
    CONSOLE_LOGLEVEL_DEFAULT,   /* default_console_loglevel */
};
EXPORT_SYMBOL_GPL(console_printk);

/*
 * console_sem protects the console_drivers list, and also
 * provides serialisation for access to the entire console
 * driver system.
 */
static DEFINE_SEMAPHORE(console_sem);

/*
 * The logbuf_lock protects kmsg buffer, indices, counters.  This can be taken
 * within the scheduler's rq lock. It must be released before calling
 * console_unlock() or anything else that might wake up a process.
 */
DEFINE_RAW_SPINLOCK(logbuf_lock);

struct console *console_drivers;
EXPORT_SYMBOL_GPL(console_drivers);

/*
 *  Array of consoles built from command line options (console=)
 */
#define MAX_CMDLINECONSOLES 8
static struct console_cmdline console_cmdline[MAX_CMDLINECONSOLES];

static int preferred_console = -1;
static bool has_preferred_console;

/* Flag: console code may call schedule() */
static int console_may_schedule;

enum con_msg_format_flags {
    MSG_FORMAT_DEFAULT  = 0,
    MSG_FORMAT_SYSLOG   = (1 << 0),
};

static int console_msg_format = MSG_FORMAT_DEFAULT;

enum log_flags {
    LOG_NEWLINE = 2,    /* text ended with a newline */
    LOG_CONT    = 8,    /* text is a fragment of a continuation line */
};

/* Number of registered extended console drivers. */
static int nr_ext_console_drivers;

static DEFINE_RAW_SPINLOCK(console_owner_lock);
static struct task_struct *console_owner;
static bool console_waiter;

/*
 * Helper macros to handle lockdep when locking/unlocking console_sem. We use
 * macros instead of functions so that _RET_IP_ contains useful information.
 */
#define down_console_sem() do { down(&console_sem); } while (0)

static int __down_trylock_console_sem(unsigned long ip)
{
    int lock_failed;
    unsigned long flags;

    /*
     * Here and in __up_console_sem() we need to be in safe mode,
     * because spindump/WARN/etc from under console ->lock will
     * deadlock in printk()->down_trylock_console_sem() otherwise.
     */
    printk_safe_enter_irqsave(flags);
    lock_failed = down_trylock(&console_sem);
    printk_safe_exit_irqrestore(flags);

    if (lock_failed)
        return 1;
    return 0;
}
#define down_trylock_console_sem() __down_trylock_console_sem(_RET_IP_)

/**
 * console_lock_spinning_enable - mark beginning of code where another
 *  thread might safely busy wait
 *
 * This basically converts console_lock into a spinlock. This marks
 * the section where the console_lock owner can not sleep, because
 * there may be a waiter spinning (like a spinlock). Also it must be
 * ready to hand over the lock at the end of the section.
 */
static void console_lock_spinning_enable(void)
{
    raw_spin_lock(&console_owner_lock);
    console_owner = current;
    raw_spin_unlock(&console_owner_lock);
}

/**
 * console_lock_spinning_disable_and_check - mark end of code where another
 *  thread was able to busy wait and check if there is a waiter
 *
 * This is called at the end of the section where spinning is allowed.
 * It has two functions. First, it is a signal that it is no longer
 * safe to start busy waiting for the lock. Second, it checks if
 * there is a busy waiter and passes the lock rights to her.
 *
 * Important: Callers lose the lock if there was a busy waiter.
 *  They must not touch items synchronized by console_lock
 *  in this case.
 *
 * Return: 1 if the lock rights were passed, 0 otherwise.
 */
static int console_lock_spinning_disable_and_check(void)
{
    int waiter;

    raw_spin_lock(&console_owner_lock);
    waiter = READ_ONCE(console_waiter);
    console_owner = NULL;
    raw_spin_unlock(&console_owner_lock);

    if (!waiter) {
        return 0;
    }

    /* The waiter is now free to continue */
    WRITE_ONCE(console_waiter, false);

    return 1;
}

static void __up_console_sem(unsigned long ip)
{
    unsigned long flags;

    printk_safe_enter_irqsave(flags);
    up(&console_sem);
    printk_safe_exit_irqrestore(flags);
}
#define up_console_sem() __up_console_sem(_RET_IP_)

/*
 * This is used for debugging the mess that is the VT code by
 * keeping track if we have the console semaphore held. It's
 * definitely not the perfect debug tool (we don't know if _WE_
 * hold it and are racing, but it helps tracking those weird code
 * paths in the console code where we end up in places I want
 * locked without the console sempahore held).
 */
static int console_locked, console_suspended;

/*
 * If exclusive_console is non-NULL then only this console is to be printed to.
 */
static struct console *exclusive_console;

static int __read_mostly keep_bootcon;

/*
 * System may need to suppress printk message under certain
 * circumstances, like after kernel panic happens.
 */
int __read_mostly suppress_printk;

/* index and sequence number of the first record stored in the buffer */
static u64 log_first_seq;
static u32 log_first_idx;

/* index and sequence number of the next record to store in the buffer */
static u64 log_next_seq;
static u32 log_next_idx;

/* the next printk record to write to the console */
static u64 console_seq;
static u32 console_idx;
static u64 exclusive_console_stop_seq;

/* the next printk record to read after the last 'clear' command */
static u64 clear_seq;
static u32 clear_idx;

struct printk_log {
    u64 ts_nsec;    /* timestamp in nanoseconds */
    u16 len;        /* length of entire record */
    u16 text_len;   /* length of text buffer */
    u16 dict_len;   /* length of dictionary buffer */
    u8 facility;    /* syslog facility */
    u8 flags:5;     /* internal record flags */
    u8 level:3;     /* syslog level */
};

/* record buffer */
#define LOG_ALIGN __alignof__(struct printk_log)
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
#define LOG_BUF_LEN_MAX (u32)(1 << 31)

static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
static char *log_buf = __log_buf;
static u32 log_buf_len = __LOG_BUF_LEN;

/* human readable text of the record */
static char *log_text(const struct printk_log *msg)
{
    return (char *)msg + sizeof(struct printk_log);
}

/* optional key/value pair dictionary attached to the record */
static char *log_dict(const struct printk_log *msg)
{
    return (char *)msg + sizeof(struct printk_log) + msg->text_len;
}

/* get record by index; idx must point to valid msg */
static struct printk_log *log_from_idx(u32 idx)
{
    struct printk_log *msg = (struct printk_log *)(log_buf + idx);

    /*
     * A length == 0 record is the end of buffer marker. Wrap around and
     * read the message at the start of the buffer.
     */
    if (!msg->len)
        return (struct printk_log *)log_buf;
    return msg;
}

/* get next record; idx must point to valid msg */
static u32 log_next(u32 idx)
{
    struct printk_log *msg = (struct printk_log *)(log_buf + idx);

    /* length == 0 indicates the end of the buffer; wrap */
    /*
     * A length == 0 record is the end of buffer marker. Wrap around and
     * read the message at the start of the buffer as *this* one, and
     * return the one after that.
     */
    if (!msg->len) {
        msg = (struct printk_log *)log_buf;
        return msg->len;
    }
    return idx + msg->len;
}

asmlinkage __visible int printk(const char *fmt, ...)
{
    va_list args;
    int r;

    va_start(args, fmt);
    r = vprintk_func(fmt, args);
    va_end(args);

    return r;
}
EXPORT_SYMBOL(printk);

/*
 * This is called by register_console() to try to match
 * the newly registered console with any of the ones selected
 * by either the command line or add_preferred_console() and
 * setup/enable it.
 *
 * Care need to be taken with consoles that are statically
 * enabled such as netconsole
 */
static int
try_enable_new_console(struct console *newcon, bool user_specified)
{
    struct console_cmdline *c;
    int i;
    //int i, err;

    for (i = 0, c = console_cmdline;
         i < MAX_CMDLINECONSOLES && c->name[0];
         i++, c++) {
#if 0
        if (c->user_specified != user_specified)
            continue;
        if (!newcon->match ||
            newcon->match(newcon, c->name, c->index, c->options) != 0) {
            /* default matching */
            BUILD_BUG_ON(sizeof(c->name) != sizeof(newcon->name));
            if (strcmp(c->name, newcon->name) != 0)
                continue;
            if (newcon->index >= 0 &&
                newcon->index != c->index)
                continue;
            if (newcon->index < 0)
                newcon->index = c->index;

            if (_braille_register_console(newcon, c))
                return 0;

            if (newcon->setup &&
                (err = newcon->setup(newcon, c->options)) != 0)
                return err;
        }
        newcon->flags |= CON_ENABLED;
        if (i == preferred_console) {
            newcon->flags |= CON_CONSDEV;
            has_preferred_console = true;
        }
        return 0;
#endif
    }

    /*
     * Some consoles, such as pstore and netconsole, can be enabled even
     * without matching. Accept the pre-enabled consoles only
     * when match() and setup() had a chance to be called.
     */
    if (newcon->flags & CON_ENABLED && c->user_specified == user_specified)
        return 0;

    return -ENOENT;
}

/*
 * Call the console drivers, asking them to write out
 * log_buf[start] to log_buf[end - 1].
 * The console_lock must be held.
 */
static void call_console_drivers(const char *ext_text, size_t ext_len,
                                 const char *text, size_t len)
{
    struct console *con;

    for_each_console(con) {
        if (exclusive_console && con != exclusive_console)
            continue;
        if (!(con->flags & CON_ENABLED))
            continue;
        if (!con->write)
            continue;
        if (!cpu_online(smp_processor_id()) &&
            !(con->flags & CON_ANYTIME))
            continue;
        if (con->flags & CON_EXTENDED)
            con->write(con, ext_text, ext_len);
        else
            con->write(con, text, len);
    }
}

/**
 * console_trylock - try to lock the console system for exclusive use.
 *
 * Try to acquire a lock which guarantees that the caller has exclusive
 * access to the console system and the console_drivers list.
 *
 * returns 1 on success, and 0 on failure to acquire the lock.
 */
int console_trylock(void)
{
    if (down_trylock_console_sem())
        return 0;
    if (console_suspended) {
        up_console_sem();
        return 0;
    }
    console_locked = 1;
    console_may_schedule = 0;
    return 1;
}
EXPORT_SYMBOL(console_trylock);

/**
 * console_lock - lock the console system for exclusive use.
 *
 * Acquires a lock which guarantees that the caller has
 * exclusive access to the console system and the console_drivers list.
 *
 * Can sleep, returns nothing.
 */
void console_lock(void)
{
    might_sleep();

    down_console_sem();
    if (console_suspended)
        return;
    console_locked = 1;
    console_may_schedule = 1;
}
EXPORT_SYMBOL(console_lock);

/*
 * Check if we have any console that is capable of printing while cpu is
 * booting or shutting down. Requires console_sem.
 */
static int have_callable_console(void)
{
    struct console *con;

    for_each_console(con) {
        if ((con->flags & CON_ENABLED) && (con->flags & CON_ANYTIME))
            return 1;
    }
    return 0;
}

/*
 * Can we actually use the console at this time on this cpu?
 *
 * Console drivers may assume that per-cpu resources have been allocated. So
 * unless they're explicitly marked as being able to cope (CON_ANYTIME) don't
 * call them until this CPU is officially up.
 */
static inline int can_use_console(void)
{
    return cpu_online(raw_smp_processor_id()) || have_callable_console();
}

static size_t
print_prefix(const struct printk_log *msg, bool syslog, bool time, char *buf)
{
    size_t len = 0;

#if 0
    if (syslog)
        len = print_syslog((msg->facility << 3) | msg->level, buf);

    if (time)
        len += print_time(msg->ts_nsec, buf + len);

    len += print_caller(msg->caller_id, buf + len);

    if (time) {
        buf[len++] = ' ';
        buf[len] = '\0';
    }
#endif

    return len;
}

static size_t
msg_print_text(const struct printk_log *msg,
               bool syslog, bool time, char *buf, size_t size)
{
    const char *text = log_text(msg);
    size_t text_size = msg->text_len;
    size_t len = 0;
    char prefix[PREFIX_MAX];
    const size_t prefix_len = print_prefix(msg, syslog, time, prefix);

    do {
        const char *next = memchr(text, '\n', text_size);
        size_t text_len;

        if (next) {
            text_len = next - text;
            next++;
            text_size -= next - text;
        } else {
            text_len = text_size;
        }

        if (buf) {
            if (prefix_len + text_len + 1 >= size - len)
                break;

            memcpy(buf + len, prefix, prefix_len);
            len += prefix_len;
            memcpy(buf + len, text, text_len);
            len += text_len;
            buf[len++] = '\n';
        } else {
            /* SYSLOG_ACTION_* buffer size only calculation */
            len += prefix_len + text_len + 1;
        }

        text = next;
    } while (text);

    return len;
}

/**
 * console_unlock - unlock the console system
 *
 * Releases the console_lock which the caller holds on the console system
 * and the console driver list.
 *
 * While the console_lock was held, console output may have been buffered
 * by printk().  If this is the case, console_unlock(); emits
 * the output prior to releasing the lock.
 *
 * If there is output waiting, we wake /dev/kmsg and syslog() users.
 *
 * console_unlock(); may be called from any context.
 */
void console_unlock(void)
{
    static char ext_text[CONSOLE_EXT_LOG_MAX];
    static char text[LOG_LINE_MAX + PREFIX_MAX];
    unsigned long flags;
    bool do_cond_resched, retry;

    if (console_suspended) {
        up_console_sem();
        return;
    }

    /*
     * Console drivers are called with interrupts disabled, so
     * @console_may_schedule should be cleared before; however, we may
     * end up dumping a lot of lines, for example, if called from
     * console registration path, and should invoke cond_resched()
     * between lines if allowable.  Not doing so can cause a very long
     * scheduling stall on a slow console leading to RCU stall and
     * softlockup warnings which exacerbate the issue with more
     * messages practically incapacitating the system.
     *
     * console_trylock() is not able to detect the preemptive
     * context reliably. Therefore the value must be stored before
     * and cleared after the the "again" goto label.
     */
    do_cond_resched = console_may_schedule;

 again:
    console_may_schedule = 0;

    /*
     * We released the console_sem lock, so we need to recheck if
     * cpu is online and (if not) is there at least one CON_ANYTIME
     * console.
     */
    if (!can_use_console()) {
        console_locked = 0;
        up_console_sem();
        return;
    }

    for (;;) {
        struct printk_log *msg;
        size_t ext_len = 0;
        size_t len;

        printk_safe_enter_irqsave(flags);
        raw_spin_lock(&logbuf_lock);
        if (console_seq < log_first_seq) {
            len = snprintf(text, sizeof(text),
                           "** %llu printk messages dropped **\n",
                           log_first_seq - console_seq);

            /* messages are gone, move to first one */
            console_seq = log_first_seq;
            console_idx = log_first_idx;
        } else {
            len = 0;
        }
// skip:
        if (console_seq == log_next_seq)
            break;

        msg = log_from_idx(console_idx);
#if 0
        if (suppress_message_printing(msg->level)) {
            /*
             * Skip record we have buffered and already printed
             * directly to the console when we received it, and
             * record that has level above the console loglevel.
             */
            console_idx = log_next(console_idx);
            console_seq++;
            goto skip;
        }
#endif

        /* Output to all consoles once old messages replayed. */
        if (unlikely(exclusive_console &&
                     console_seq >= exclusive_console_stop_seq)) {
            exclusive_console = NULL;
        }

        len += msg_print_text(msg, console_msg_format & MSG_FORMAT_SYSLOG,
                              printk_time, text + len, sizeof(text) - len);
#if 0
        if (nr_ext_console_drivers) {
            ext_len = msg_print_ext_header(ext_text,
                        sizeof(ext_text),
                        msg, console_seq);
            ext_len += msg_print_ext_body(ext_text + ext_len,
                        sizeof(ext_text) - ext_len,
                        log_dict(msg), msg->dict_len,
                        log_text(msg), msg->text_len);
        }
#endif
        console_idx = log_next(console_idx);
        console_seq++;

        raw_spin_unlock(&logbuf_lock);

        /*
         * While actively printing out messages, if another printk()
         * were to occur on another CPU, it may wait for this one to
         * finish. This task can not be preempted if there is a
         * waiter waiting to take over.
         */
        console_lock_spinning_enable();

        call_console_drivers(ext_text, ext_len, text, len);

        if (console_lock_spinning_disable_and_check()) {
            printk_safe_exit_irqrestore(flags);
            return;
        }

        printk_safe_exit_irqrestore(flags);

        if (do_cond_resched)
            cond_resched();
    }

    console_locked = 0;

    raw_spin_unlock(&logbuf_lock);

    up_console_sem();

    /*
     * Someone could have filled up the buffer again, so re-check if there's
     * something to flush. In case we cannot trylock the console_sem again,
     * there's a new owner and the console_unlock() from them will do the
     * flush, no worries.
     */
    raw_spin_lock(&logbuf_lock);
    retry = console_seq != log_next_seq;
    raw_spin_unlock(&logbuf_lock);
    printk_safe_exit_irqrestore(flags);

    if (retry && console_trylock())
        goto again;
}

/*
 * The console driver calls this routine during kernel initialization
 * to register the console printing procedure with printk() and to
 * print any messages that were printed by the kernel before the
 * console driver was initialized.
 *
 * This can happen pretty early during the boot process (because of
 * early_printk) - sometimes before setup_arch() completes - be careful
 * of what kernel features are used - they may not be initialised yet.
 *
 * There are two types of consoles - bootconsoles (early_printk) and
 * "real" consoles (everything which is not a bootconsole) which are
 * handled differently.
 *  - Any number of bootconsoles can be registered at any time.
 *  - As soon as a "real" console is registered, all bootconsoles
 *    will be unregistered automatically.
 *  - Once a "real" console is registered, any attempt to register a
 *    bootconsoles will be rejected
 */
void register_console(struct console *newcon)
{
    //unsigned long flags;
    struct console *bcon = NULL;
    int err;

    for_each_console(bcon) {
        if (WARN(bcon == newcon, "console '%s%d' already registered\n",
                 bcon->name, bcon->index))
            return;
    }

    /*
     * before we register a new CON_BOOT console, make sure we don't
     * already have a valid console
     */
    if (newcon->flags & CON_BOOT) {
        for_each_console(bcon) {
            if (!(bcon->flags & CON_BOOT)) {
                pr_info("Too late to register bootconsole %s%d\n",
                        newcon->name, newcon->index);
                return;
            }
        }
    }

    if (console_drivers && console_drivers->flags & CON_BOOT)
        bcon = console_drivers;

    if (!has_preferred_console || bcon || !console_drivers)
        has_preferred_console = preferred_console >= 0;

    /*
     *  See if we want to use this console driver. If we
     *  didn't select a console we take the first one
     *  that registers here.
     */
    if (!has_preferred_console) {
        if (newcon->index < 0)
            newcon->index = 0;
        if (newcon->setup == NULL ||
            newcon->setup(newcon, NULL) == 0) {
            newcon->flags |= CON_ENABLED;
            if (newcon->device) {
                newcon->flags |= CON_CONSDEV;
                has_preferred_console = true;
            }
        }
    }

    /* See if this console matches one we selected on the command line */
    err = try_enable_new_console(newcon, true);

    /* If not, try to match against the platform default(s) */
    if (err == -ENOENT)
        err = try_enable_new_console(newcon, false);

    /* printk() messages are not printed to the Braille console. */
    if (err || newcon->flags & CON_BRL)
        return;

    /*
     * If we have a bootconsole, and are switching to a real console,
     * don't print everything out again, since when the boot console, and
     * the real console are the same physical device, it's annoying to
     * see the beginning boot messages twice
     */
    if (bcon && ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV))
        newcon->flags &= ~CON_PRINTBUFFER;

    /*
     *  Put this console in the list - keep the
     *  preferred driver at the head of the list.
     */
    console_lock();
    if ((newcon->flags & CON_CONSDEV) || console_drivers == NULL) {
        newcon->next = console_drivers;
        console_drivers = newcon;
        if (newcon->next)
            newcon->next->flags &= ~CON_CONSDEV;
        /* Ensure this flag is always set for the head of the list */
        newcon->flags |= CON_CONSDEV;
    } else {
        newcon->next = console_drivers->next;
        console_drivers->next = newcon;
    }

    if (newcon->flags & CON_EXTENDED)
        nr_ext_console_drivers++;

#if 0
    if (newcon->flags & CON_PRINTBUFFER) {
        /*
         * console_unlock(); will print out the buffered messages
         * for us.
         */
        logbuf_lock_irqsave(flags);
        /*
         * We're about to replay the log buffer.  Only do this to the
         * just-registered console to avoid excessive message spam to
         * the already-registered consoles.
         *
         * Set exclusive_console with disabled interrupts to reduce
         * race window with eventual console_flush_on_panic() that
         * ignores console_lock.
         */
        exclusive_console = newcon;
        exclusive_console_stop_seq = console_seq;
        console_seq = syslog_seq;
        console_idx = syslog_idx;
        logbuf_unlock_irqrestore(flags);
    }
#endif

    console_unlock();
    //console_sysfs_notify();

    /*
     * By unregistering the bootconsoles after we enable the real console
     * we get the "console xxx enabled" message on all the consoles -
     * boot consoles, real consoles, etc - this is to ensure that end
     * users know there might be something in the kernel's log buffer that
     * went to the bootconsole (that they do not see on the real console)
     */
    pr_info("%sconsole [%s%d] enabled\n",
        (newcon->flags & CON_BOOT) ? "boot" : "" ,
        newcon->name, newcon->index);
    if (bcon &&
        ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV) &&
        !keep_bootcon) {
        /* We need to iterate through all boot consoles, to make
         * sure we print everything out, before we unregister them.
         */
        for_each_console(bcon)
            if (bcon->flags & CON_BOOT)
                unregister_console(bcon);
    }
}
EXPORT_SYMBOL(register_console);

int unregister_console(struct console *console)
{
    struct console *con;
    int res;

    pr_info("%sconsole [%s%d] disabled\n",
            (console->flags & CON_BOOT) ? "boot" : "" ,
            console->name, console->index);

    res = -ENODEV;
    console_lock();
    if (console_drivers == console) {
        console_drivers = console->next;
        res = 0;
    } else {
        for_each_console(con) {
            if (con->next == console) {
                con->next = console->next;
                res = 0;
                break;
            }
        }
    }

    if (res)
        goto out_disable_unlock;

    if (console->flags & CON_EXTENDED)
        nr_ext_console_drivers--;

    /*
     * If this isn't the last console and it has CON_CONSDEV set, we
     * need to set it on the next preferred console.
     */
    if (console_drivers != NULL && console->flags & CON_CONSDEV)
        console_drivers->flags |= CON_CONSDEV;

    console->flags &= ~CON_ENABLED;
    console_unlock();
    //console_sysfs_notify();

    if (console->exit)
        res = console->exit(console);

    return res;

out_disable_unlock:
    console->flags &= ~CON_ENABLED;
    console_unlock();

    return res;
}

/**
 * console_trylock_spinning - try to get console_lock by busy waiting
 *
 * This allows to busy wait for the console_lock when the current
 * owner is running in specially marked sections. It means that
 * the current owner is running and cannot reschedule until it
 * is ready to lose the lock.
 *
 * Return: 1 if we got the lock, 0 othrewise
 */
static int console_trylock_spinning(void)
{
    struct task_struct *owner = NULL;
    bool waiter;
    bool spin = false;
    unsigned long flags;

    if (console_trylock())
        return 1;

    printk_safe_enter_irqsave(flags);

    raw_spin_lock(&console_owner_lock);
    owner = READ_ONCE(console_owner);
    waiter = READ_ONCE(console_waiter);
    if (!waiter && owner && owner != current) {
        WRITE_ONCE(console_waiter, true);
        spin = true;
    }
    raw_spin_unlock(&console_owner_lock);

    /*
     * If there is an active printk() writing to the
     * consoles, instead of having it write our data too,
     * see if we can offload that load from the active
     * printer, and do some printing ourselves.
     * Go into a spin only if there isn't already a waiter
     * spinning, and there is an active printer, and
     * that active printer isn't us (recursive printk?).
     */
    if (!spin) {
        printk_safe_exit_irqrestore(flags);
        return 0;
    }

    /* We spin waiting for the owner to release us */
    /* Owner will clear console_waiter on hand off */
    while (READ_ONCE(console_waiter))
        cpu_relax();

    printk_safe_exit_irqrestore(flags);
    return 1;
}

static inline u32 printk_caller_id(void)
{
    /*
    return in_task() ? task_pid_nr(current) :
        0x80000000 + raw_smp_processor_id();
        */
    return 0;
}

/* compute the message size including the padding bytes */
static u32 msg_used_size(u16 text_len, u16 dict_len, u32 *pad_len)
{
    u32 size;

    size = sizeof(struct printk_log) + text_len + dict_len;
    *pad_len = (-size) & (LOG_ALIGN - 1);
    size += *pad_len;

    return size;
}

static int logbuf_has_space(u32 msg_size, bool empty)
{
    u32 free;

    if (log_next_idx > log_first_idx || empty)
        free = max(log_buf_len - log_next_idx, log_first_idx);
    else
        free = log_first_idx - log_next_idx;

    /*
     * We need space also for an empty header that signalizes wrapping
     * of the buffer.
     */
    return free >= msg_size + sizeof(struct printk_log);
}

static int log_make_free_space(u32 msg_size)
{
    while (log_first_seq < log_next_seq &&
           !logbuf_has_space(msg_size, false)) {
        /* drop old messages until we have enough contiguous space */
        log_first_idx = log_next(log_first_idx);
        log_first_seq++;
    }

    if (clear_seq < log_first_seq) {
        clear_seq = log_first_seq;
        clear_idx = log_first_idx;
    }

    /* sequence numbers are equal, so the log buffer is empty */
    if (logbuf_has_space(msg_size, log_first_seq == log_next_seq))
        return 0;

    return -ENOMEM;
}

/*
 * Define how much of the log buffer we could take at maximum.
 * The value must be greater than two.
 * Note that only half of the buffer is available
 * when the index points to the middle.
 */
#define MAX_LOG_TAKE_PART 4
static const char trunc_msg[] = "<truncated>";

static u32 truncate_msg(u16 *text_len, u16 *trunc_msg_len,
                        u16 *dict_len, u32 *pad_len)
{
    /*
     * The message should not take the whole buffer. Otherwise, it might
     * get removed too soon.
     */
    u32 max_text_len = log_buf_len / MAX_LOG_TAKE_PART;
    if (*text_len > max_text_len)
        *text_len = max_text_len;
    /* enable the warning message */
    *trunc_msg_len = strlen(trunc_msg);
    /* disable the "dict" completely */
    *dict_len = 0;
    /* compute the size again, count also the warning message */
    return msg_used_size(*text_len + *trunc_msg_len, 0, pad_len);
}

/* insert record into the buffer, discard old ones, update heads */
static int
log_store(u32 caller_id, int facility, int level,
          enum log_flags flags, u64 ts_nsec,
          const char *dict, u16 dict_len,
          const char *text, u16 text_len)
{
    struct printk_log *msg;
    u32 size, pad_len;
    u16 trunc_msg_len = 0;

    /* number of '\0' padding bytes to next message */
    size = msg_used_size(text_len, dict_len, &pad_len);

    if (log_make_free_space(size)) {
        /* truncate the message if it is too long for empty buffer */
        size = truncate_msg(&text_len, &trunc_msg_len,
                            &dict_len, &pad_len);
        /* survive when the log buffer is too small for trunc_msg */
        if (log_make_free_space(size))
            return 0;
    }

    if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
        /*
         * This message + an additional empty header does not fit
         * at the end of the buffer.
         * Add an empty header with len == 0 to signify a wrap around.
         */
        memset(log_buf + log_next_idx, 0, sizeof(struct printk_log));
        log_next_idx = 0;
    }

    /* fill message */
    msg = (struct printk_log *)(log_buf + log_next_idx);
    memcpy(log_text(msg), text, text_len);
    msg->text_len = text_len;
    if (trunc_msg_len) {
        memcpy(log_text(msg) + text_len, trunc_msg, trunc_msg_len);
        msg->text_len += trunc_msg_len;
    }
    memcpy(log_dict(msg), dict, dict_len);
    msg->dict_len = dict_len;
    msg->facility = facility;
    msg->level = level & 7;
    msg->flags = flags & 0x1f;
    if (ts_nsec > 0) {
        msg->ts_nsec = ts_nsec;
    } else {
        msg->ts_nsec = 0;
        //msg->ts_nsec = local_clock();
    }

    memset(log_dict(msg) + dict_len, 0, pad_len);
    msg->len = size;

    /* insert message */
    log_next_idx += msg->len;
    log_next_seq++;

    return msg->text_len;
}

static size_t
log_output(int facility, int level, enum log_flags lflags,
           const char *dict, size_t dictlen,
           char *text, size_t text_len)
{
    const u32 caller_id = printk_caller_id();

#if 0
    /*
     * If an earlier line was buffered, and we're a continuation
     * write from the same context, try to add it to the buffer.
     */
    if (cont.len) {
        if (cont.caller_id == caller_id && (lflags & LOG_CONT)) {
            if (cont_add(caller_id, facility, level, lflags, text, text_len))
                return text_len;
        }
        /* Otherwise, make sure it's flushed */
        cont_flush();
    }
#endif

    /* Skip empty continuation lines that couldn't be added - they just flush */
    if (!text_len && (lflags & LOG_CONT))
        return 0;

#if 0
    /* If it doesn't end in a newline, try to buffer the current line */
    if (!(lflags & LOG_NEWLINE)) {
        if (cont_add(caller_id, facility, level, lflags, text, text_len))
            return text_len;
    }
#endif

    /* Store it in the record log */
    return log_store(caller_id, facility, level, lflags, 0,
                     dict, dictlen, text, text_len);
}

/* Must be called under logbuf_lock. */
int vprintk_store(int facility, int level,
                  const char *dict, size_t dictlen,
                  const char *fmt, va_list args)
{
    static char textbuf[LOG_LINE_MAX];
    char *text = textbuf;
    size_t text_len;
    enum log_flags lflags = 0;

    /*
     * The printf needs to come first; we need the syslog
     * prefix which might be passed-in as a parameter.
     */
    text_len = vscnprintf(text, sizeof(textbuf), fmt, args);

    /* mark and strip a trailing newline */
    if (text_len && text[text_len-1] == '\n') {
        text_len--;
        lflags |= LOG_NEWLINE;
    }

    /* strip kernel syslog prefix and extract log level or control flags */
    if (facility == 0) {
        int kern_level;

        while ((kern_level = printk_get_level(text)) != 0) {
            switch (kern_level) {
            case '0' ... '7':
                if (level == LOGLEVEL_DEFAULT)
                    level = kern_level - '0';
                break;
            case 'c':   /* KERN_CONT */
                lflags |= LOG_CONT;
            }

            text_len -= 2;
            text += 2;
        }
    }

    if (level == LOGLEVEL_DEFAULT)
        level = default_message_loglevel;

    if (dict)
        lflags |= LOG_NEWLINE;

    return log_output(facility, level, lflags,
                      dict, dictlen, text, text_len);
}

asmlinkage int
vprintk_emit(int facility, int level,
             const char *dict, size_t dictlen,
             const char *fmt, va_list args)
{
    int printed_len;
    bool in_sched = false, pending_output;
    unsigned long flags;
    u64 curr_log_seq;

    /* Suppress unimportant messages after panic happens */
    if (unlikely(suppress_printk))
        return 0;

    if (level == LOGLEVEL_SCHED) {
        level = LOGLEVEL_DEFAULT;
        in_sched = true;
    }

    //printk_delay();

    /* This stops the holder of console_sem just where we want him */
    logbuf_lock_irqsave(flags);
    curr_log_seq = log_next_seq;
    printed_len = vprintk_store(facility, level, dict, dictlen, fmt, args);
    pending_output = (curr_log_seq != log_next_seq);
    logbuf_unlock_irqrestore(flags);

    /* If called from the scheduler, we can not call up(). */
    if (!in_sched && pending_output) {
        /*
         * Disable preemption to avoid being preempted while holding
         * console_sem which would prevent anyone from printing to
         * console
         */
        preempt_disable();
        /*
         * Try to acquire and then immediately release the console
         * semaphore.  The release will print out buffers and wake up
         * /dev/kmsg and syslog() users.
         */
        if (console_trylock_spinning())
            console_unlock();
        preempt_enable();
    }

    /*
    if (pending_output)
        wake_up_klogd();
        */
    return printed_len;
}

int vprintk_default(const char *fmt, va_list args)
{
    return vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);
}
EXPORT_SYMBOL_GPL(vprintk_default);
