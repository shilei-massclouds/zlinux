// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/percpu-refcount.h>

#define PERCPU_COUNT_BIAS   (1LU << (BITS_PER_LONG - 1))

/**
 * percpu_ref_init - initialize a percpu refcount
 * @ref: percpu_ref to initialize
 * @release: function which will be called when refcount hits 0
 * @flags: PERCPU_REF_INIT_* flags
 * @gfp: allocation mask to use
 *
 * Initializes @ref.  @ref starts out in percpu mode with a refcount of 1 unless
 * @flags contains PERCPU_REF_INIT_ATOMIC or PERCPU_REF_INIT_DEAD.  These flags
 * change the start state to atomic with the latter setting the initial refcount
 * to 0.  See the definitions of PERCPU_REF_INIT_* flags for flag behaviors.
 *
 * Note that @release must not sleep - it may potentially be called from RCU
 * callback context by percpu_ref_kill().
 */
int percpu_ref_init(struct percpu_ref *ref, percpu_ref_func_t *release,
                    unsigned int flags, gfp_t gfp)
{
    size_t align = max_t(size_t, 1 << __PERCPU_REF_FLAG_BITS,
                         __alignof__(unsigned long));
    unsigned long start_count = 0;
    struct percpu_ref_data *data;

    ref->percpu_count_ptr = (unsigned long)
        __alloc_percpu_gfp(sizeof(unsigned long), align, gfp);
    if (!ref->percpu_count_ptr)
        return -ENOMEM;

    data = kzalloc(sizeof(*ref->data), gfp);
    if (!data) {
        free_percpu((void __percpu *)ref->percpu_count_ptr);
        ref->percpu_count_ptr = 0;
        return -ENOMEM;
    }

    data->force_atomic = flags & PERCPU_REF_INIT_ATOMIC;
    data->allow_reinit = flags & PERCPU_REF_ALLOW_REINIT;

    if (flags & (PERCPU_REF_INIT_ATOMIC | PERCPU_REF_INIT_DEAD)) {
        ref->percpu_count_ptr |= __PERCPU_REF_ATOMIC;
        data->allow_reinit = true;
    } else {
        start_count += PERCPU_COUNT_BIAS;
    }

    if (flags & PERCPU_REF_INIT_DEAD)
        ref->percpu_count_ptr |= __PERCPU_REF_DEAD;
    else
        start_count++;

    atomic_long_set(&data->count, start_count);

    data->release = release;
    data->confirm_switch = NULL;
    data->ref = ref;
    ref->data = data;
    return 0;
}
EXPORT_SYMBOL_GPL(percpu_ref_init);
