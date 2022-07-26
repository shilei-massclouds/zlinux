/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Percpu refcounts:
 * (C) 2012 Google, Inc.
 * Author: Kent Overstreet <koverstreet@google.com>
 *
 * This implements a refcount with similar semantics to atomic_t - atomic_inc(),
 * atomic_dec_and_test() - but percpu.
 *
 * There's one important difference between percpu refs and normal atomic_t
 * refcounts; you have to keep track of your initial refcount, and then when you
 * start shutting down you call percpu_ref_kill() _before_ dropping the initial
 * refcount.
 *
 * The refcount will have a range of 0 to ((1U << 31) - 1), i.e. one bit less
 * than an atomic_t - this is because of the way shutdown works, see
 * percpu_ref_kill()/PERCPU_COUNT_BIAS.
 *
 * Before you call percpu_ref_kill(), percpu_ref_put() does not check for the
 * refcount hitting 0 - it can't, if it was in percpu mode. percpu_ref_kill()
 * puts the ref back in single atomic_t mode, collecting the per cpu refs and
 * issuing the appropriate barriers, and then marks the ref as shutting down so
 * that percpu_ref_put() will check for the ref hitting 0.  After it returns,
 * it's safe to drop the initial ref.
 *
 * USAGE:
 *
 * See fs/aio.c for some example usage; it's used there for struct kioctx, which
 * is created when userspaces calls io_setup(), and destroyed when userspace
 * calls io_destroy() or the process exits.
 *
 * In the aio code, kill_ioctx() is called when we wish to destroy a kioctx; it
 * removes the kioctx from the proccess's table of kioctxs and kills percpu_ref.
 * After that, there can't be any new users of the kioctx (from lookup_ioctx())
 * and it's then safe to drop the initial ref with percpu_ref_put().
 *
 * Note that the free path, free_ioctx(), needs to go through explicit call_rcu()
 * to synchronize with RCU protected lookup_ioctx().  percpu_ref operations don't
 * imply RCU grace periods of any kind and if a user wants to combine percpu_ref
 * with RCU protection, it must be done explicitly.
 *
 * Code that does a two stage shutdown like this often needs some kind of
 * explicit synchronization to ensure the initial refcount can only be dropped
 * once - percpu_ref_kill() does this for you, it returns true once and false if
 * someone else already called it. The aio code uses it this way, but it's not
 * necessary if the code has some other mechanism to synchronize teardown.
 * around.
 */
#ifndef _LINUX_PERCPU_REFCOUNT_H
#define _LINUX_PERCPU_REFCOUNT_H

#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/gfp.h>

struct percpu_ref;
typedef void (percpu_ref_func_t)(struct percpu_ref *);

/* flags set in the lower bits of percpu_ref->percpu_count_ptr */
enum {
    __PERCPU_REF_ATOMIC = 1LU << 0, /* operating in atomic mode */
    __PERCPU_REF_DEAD   = 1LU << 1, /* (being) killed */
    __PERCPU_REF_ATOMIC_DEAD = __PERCPU_REF_ATOMIC | __PERCPU_REF_DEAD,

    __PERCPU_REF_FLAG_BITS  = 2,
};

struct percpu_ref_data {
    atomic_long_t       count;
    percpu_ref_func_t   *release;
    percpu_ref_func_t   *confirm_switch;
    bool            force_atomic:1;
    bool            allow_reinit:1;
    struct rcu_head     rcu;
    struct percpu_ref   *ref;
};

struct percpu_ref {
    /*
     * The low bit of the pointer indicates whether the ref is in percpu
     * mode; if set, then get/put will manipulate the atomic_t.
     */
    unsigned long percpu_count_ptr;

    /*
     * 'percpu_ref' is often embedded into user structure, and only
     * 'percpu_count_ptr' is required in fast path, move other fields
     * into 'percpu_ref_data', so we can reduce memory footprint in
     * fast path.
     */
    struct percpu_ref_data *data;
};

/*
 * Internal helper.  Don't use outside percpu-refcount proper.  The
 * function doesn't return the pointer and let the caller test it for NULL
 * because doing so forces the compiler to generate two conditional
 * branches as it can't assume that @ref->percpu_count is not NULL.
 */
static inline bool __ref_is_percpu(struct percpu_ref *ref,
                      unsigned long __percpu **percpu_countp)
{
    unsigned long percpu_ptr;

    /*
     * The value of @ref->percpu_count_ptr is tested for
     * !__PERCPU_REF_ATOMIC, which may be set asynchronously, and then
     * used as a pointer.  If the compiler generates a separate fetch
     * when using it as a pointer, __PERCPU_REF_ATOMIC may be set in
     * between contaminating the pointer value, meaning that
     * READ_ONCE() is required when fetching it.
     *
     * The dependency ordering from the READ_ONCE() pairs
     * with smp_store_release() in __percpu_ref_switch_to_percpu().
     */
    percpu_ptr = READ_ONCE(ref->percpu_count_ptr);

    /*
     * Theoretically, the following could test just ATOMIC; however,
     * then we'd have to mask off DEAD separately as DEAD may be
     * visible without ATOMIC if we race with percpu_ref_kill().  DEAD
     * implies ATOMIC anyway.  Test them together.
     */
    if (unlikely(percpu_ptr & __PERCPU_REF_ATOMIC_DEAD))
        return false;

    *percpu_countp = (unsigned long __percpu *)percpu_ptr;
    return true;
}

/**
 * percpu_ref_put_many - decrement a percpu refcount
 * @ref: percpu_ref to put
 * @nr: number of references to put
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 *
 * This function is safe to call as long as @ref is between init and exit.
 */
static inline void percpu_ref_put_many(struct percpu_ref *ref, unsigned long nr)
{
    unsigned long __percpu *percpu_count;

    rcu_read_lock();

    if (__ref_is_percpu(ref, &percpu_count))
        this_cpu_sub(*percpu_count, nr);
    else if (unlikely(atomic_long_sub_and_test(nr, &ref->data->count)))
        ref->data->release(ref);

    rcu_read_unlock();
}

/**
 * percpu_ref_put - decrement a percpu refcount
 * @ref: percpu_ref to put
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 *
 * This function is safe to call as long as @ref is between init and exit.
 */
static inline void percpu_ref_put(struct percpu_ref *ref)
{
    percpu_ref_put_many(ref, 1);
}

#endif /* _LINUX_PERCPU_REFCOUNT_H */
