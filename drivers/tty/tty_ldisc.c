// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/bitops.h>
//#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
#include "tty.h"

#define tty_ldisc_debug(tty, f, args...)

/*
 *  This guards the refcounted line discipline lists. The lock
 *  must be taken with irqs off because there are hangup path
 *  callers who will do ldisc lookups and cannot sleep.
 */

static DEFINE_RAW_SPINLOCK(tty_ldiscs_lock);
/* Line disc dispatch table */
static struct tty_ldisc_ops *tty_ldiscs[NR_LDISCS];

static void put_ldops(struct tty_ldisc_ops *ldops)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&tty_ldiscs_lock, flags);
    module_put(ldops->owner);
    raw_spin_unlock_irqrestore(&tty_ldiscs_lock, flags);
}

static struct tty_ldisc_ops *get_ldops(int disc)
{
    unsigned long flags;
    struct tty_ldisc_ops *ldops, *ret;

    raw_spin_lock_irqsave(&tty_ldiscs_lock, flags);
    ret = ERR_PTR(-EINVAL);
    ldops = tty_ldiscs[disc];
    if (ldops) {
        ret = ERR_PTR(-EAGAIN);
        if (try_module_get(ldops->owner))
            ret = ldops;
    }
    raw_spin_unlock_irqrestore(&tty_ldiscs_lock, flags);
    return ret;
}

/**
 * tty_ldisc_get    -   take a reference to an ldisc
 * @tty: tty device
 * @disc: ldisc number
 *
 * Takes a reference to a line discipline. Deals with refcounts and module
 * locking counts. If the discipline is not available, its module loaded, if
 * possible.
 *
 * Returns:
 * * -%EINVAL if the discipline index is not [%N_TTY .. %NR_LDISCS] or if the
 *   discipline is not registered
 * * -%EAGAIN if request_module() failed to load or register the discipline
 * * -%ENOMEM if allocation failure
 * * Otherwise, returns a pointer to the discipline and bumps the ref count
 *
 * Locking: takes %tty_ldiscs_lock to guard against ldisc races
 */
static struct tty_ldisc *tty_ldisc_get(struct tty_struct *tty, int disc)
{
    struct tty_ldisc *ld;
    struct tty_ldisc_ops *ldops;

    if (disc < N_TTY || disc >= NR_LDISCS)
        return ERR_PTR(-EINVAL);

    /*
     * Get the ldisc ops - we may need to request them to be loaded
     * dynamically and try again.
     */
    ldops = get_ldops(disc);
    if (IS_ERR(ldops)) {
#if 0
        if (!capable(CAP_SYS_MODULE) && !tty_ldisc_autoload)
            return ERR_PTR(-EPERM);
#endif
        request_module("tty-ldisc-%d", disc);
        ldops = get_ldops(disc);
        if (IS_ERR(ldops))
            return ERR_CAST(ldops);
    }

    /*
     * There is no way to handle allocation failure of only 16 bytes.
     * Let's simplify error handling and save more memory.
     */
    ld = kmalloc(sizeof(struct tty_ldisc), GFP_KERNEL | __GFP_NOFAIL);
    ld->ops = ldops;
    ld->tty = tty;

    return ld;
}

/**
 * tty_ldisc_put    -   release the ldisc
 * @ld: lisdsc to release
 *
 * Complement of tty_ldisc_get().
 */
static void tty_ldisc_put(struct tty_ldisc *ld)
{
    if (WARN_ON_ONCE(!ld))
        return;

    put_ldops(ld->ops);
    kfree(ld);
}

/**
 * tty_register_ldisc   -   install a line discipline
 * @new_ldisc: pointer to the ldisc object
 *
 * Installs a new line discipline into the kernel. The discipline is set up as
 * unreferenced and then made available to the kernel from this point onwards.
 *
 * Locking: takes %tty_ldiscs_lock to guard against ldisc races
 */
int tty_register_ldisc(struct tty_ldisc_ops *new_ldisc)
{
    unsigned long flags;
    int ret = 0;

    if (new_ldisc->num < N_TTY || new_ldisc->num >= NR_LDISCS)
        return -EINVAL;

    raw_spin_lock_irqsave(&tty_ldiscs_lock, flags);
    tty_ldiscs[new_ldisc->num] = new_ldisc;
    raw_spin_unlock_irqrestore(&tty_ldiscs_lock, flags);

    return ret;
}
EXPORT_SYMBOL(tty_register_ldisc);

/**
 * tty_ldisc_deinit -   ldisc cleanup for new tty
 * @tty: tty that was allocated recently
 *
 * The tty structure must not be completely set up (tty_ldisc_setup()) when
 * this call is made.
 */
void tty_ldisc_deinit(struct tty_struct *tty)
{
    /* no ldisc_sem, tty is being destroyed */
    if (tty->ldisc)
        tty_ldisc_put(tty->ldisc);
    tty->ldisc = NULL;
}

/**
 * tty_name -   return tty naming
 * @tty: tty structure
 *
 * Convert a tty structure into a name. The name reflects the kernel naming
 * policy and if udev is in use may not reflect user space
 *
 * Locking: none
 */
const char *tty_name(const struct tty_struct *tty)
{
    if (!tty) /* Hmm.  NULL pointer.  That's fun. */
        return "NULL tty";
    return tty->name;
}
EXPORT_SYMBOL(tty_name);

/**
 * tty_ldisc_open       -   open a line discipline
 * @tty: tty we are opening the ldisc on
 * @ld: discipline to open
 *
 * A helper opening method. Also a convenient debugging and check point.
 *
 * Locking: always called with BTM already held.
 */
static int tty_ldisc_open(struct tty_struct *tty, struct tty_ldisc *ld)
{
    WARN_ON(test_and_set_bit(TTY_LDISC_OPEN, &tty->flags));
    if (ld->ops->open) {
        int ret;
        /* BTM here locks versus a hangup event */
        ret = ld->ops->open(tty);
        if (ret)
            clear_bit(TTY_LDISC_OPEN, &tty->flags);

        tty_ldisc_debug(tty, "%p: opened\n", ld);
        return ret;
    }
    return 0;
}

/**
 * tty_ldisc_close      -   close a line discipline
 * @tty: tty we are opening the ldisc on
 * @ld: discipline to close
 *
 * A helper close method. Also a convenient debugging and check point.
 */
static void tty_ldisc_close(struct tty_struct *tty, struct tty_ldisc *ld)
{
    WARN_ON(!test_bit(TTY_LDISC_OPEN, &tty->flags));
    clear_bit(TTY_LDISC_OPEN, &tty->flags);
    if (ld->ops->close)
        ld->ops->close(tty);
    tty_ldisc_debug(tty, "%p: closed\n", ld);
}

/**
 * tty_ldisc_setup  -   open line discipline
 * @tty: tty being shut down
 * @o_tty: pair tty for pty/tty pairs
 *
 * Called during the initial open of a tty/pty pair in order to set up the line
 * disciplines and bind them to the @tty. This has no locking issues as the
 * device isn't yet active.
 */
int tty_ldisc_setup(struct tty_struct *tty, struct tty_struct *o_tty)
{
    int retval = tty_ldisc_open(tty, tty->ldisc);

    if (retval)
        return retval;

    if (o_tty) {
        /*
         * Called without o_tty->ldisc_sem held, as o_tty has been
         * just allocated and no one has a reference to it.
         */
        retval = tty_ldisc_open(o_tty, o_tty->ldisc);
        if (retval) {
            tty_ldisc_close(tty, tty->ldisc);
            return retval;
        }
    }
    return 0;
}

/**
 * tty_ldisc_init   -   ldisc setup for new tty
 * @tty: tty being allocated
 *
 * Set up the line discipline objects for a newly allocated tty. Note that the
 * tty structure is not completely set up when this call is made.
 */
int tty_ldisc_init(struct tty_struct *tty)
{
    struct tty_ldisc *ld = tty_ldisc_get(tty, N_TTY);

    if (IS_ERR(ld))
        return PTR_ERR(ld);
    tty->ldisc = ld;
    return 0;
}

static inline int
__tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout)
{
    return ldsem_down_write(&tty->ldisc_sem, timeout);
}

static inline void __tty_ldisc_unlock(struct tty_struct *tty)
{
    ldsem_up_write(&tty->ldisc_sem);
}

int tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout)
{
    int ret;

    /* Kindly asking blocked readers to release the read side */
    set_bit(TTY_LDISC_CHANGING, &tty->flags);
    wake_up_interruptible_all(&tty->read_wait);
    wake_up_interruptible_all(&tty->write_wait);

    ret = __tty_ldisc_lock(tty, timeout);
    if (!ret)
        return -EBUSY;
    set_bit(TTY_LDISC_HALTED, &tty->flags);
    return 0;
}

void tty_ldisc_unlock(struct tty_struct *tty)
{
    clear_bit(TTY_LDISC_HALTED, &tty->flags);
    /* Can be cleared here - ldisc_unlock will wake up writers firstly */
    clear_bit(TTY_LDISC_CHANGING, &tty->flags);
    __tty_ldisc_unlock(tty);
}

/**
 * tty_ldisc_ref    -   get the tty ldisc
 * @tty: tty device
 *
 * Dereference the line discipline for the terminal and take a reference to it.
 * If the line discipline is in flux then return %NULL. Can be called from IRQ
 * and timer functions.
 */
struct tty_ldisc *tty_ldisc_ref(struct tty_struct *tty)
{
    struct tty_ldisc *ld = NULL;

    if (ldsem_down_read_trylock(&tty->ldisc_sem)) {
        ld = tty->ldisc;
        if (!ld)
            ldsem_up_read(&tty->ldisc_sem);
    }
    return ld;
}
EXPORT_SYMBOL_GPL(tty_ldisc_ref);

/**
 * tty_ldisc_deref  -   free a tty ldisc reference
 * @ld: reference to free up
 *
 * Undoes the effect of tty_ldisc_ref() or tty_ldisc_ref_wait(). May be called
 * in IRQ context.
 */
void tty_ldisc_deref(struct tty_ldisc *ld)
{
    ldsem_up_read(&ld->tty->ldisc_sem);
}
EXPORT_SYMBOL_GPL(tty_ldisc_deref);
