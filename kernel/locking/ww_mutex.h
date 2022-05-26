/* SPDX-License-Identifier: GPL-2.0-only */

#define MUTEX           mutex
#define MUTEX_WAITER    mutex_waiter

static __always_inline void
ww_mutex_set_context_fastpath(struct ww_mutex *lock, struct ww_acquire_ctx *ctx)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * We just acquired @lock under @ww_ctx, if there are more important contexts
 * waiting behind us on the wait-list, check if they need to die, or wound us.
 *
 * See __ww_mutex_add_waiter() for the list-order construction; basically the
 * list is ordered by stamp, smallest (oldest) first.
 *
 * This relies on never mixing wait-die/wound-wait on the same wait-list;
 * which is currently ensured by that being a ww_class property.
 *
 * The current task must not be on the wait list.
 */
static void
__ww_mutex_check_waiters(struct MUTEX *lock, struct ww_acquire_ctx *ww_ctx)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Add @waiter to the wait-list, keep the wait-list ordered by stamp, smallest
 * first. Such that older contexts are preferred to acquire the lock over
 * younger contexts.
 *
 * Waiters without context are interspersed in FIFO order.
 *
 * Furthermore, for Wait-Die kill ourself immediately when possible (there are
 * older contexts already waiting) to avoid unnecessary waiting and for
 * Wound-Wait ensure we wound the owning context when it is younger.
 */
static inline int
__ww_mutex_add_waiter(struct MUTEX_WAITER *waiter,
                      struct MUTEX *lock, struct ww_acquire_ctx *ww_ctx)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Check the wound condition for the current lock acquire.
 *
 * Wound-Wait: If we're wounded, kill ourself.
 *
 * Wait-Die: If we're trying to acquire a lock already held by an older
 *           context, kill ourselves.
 *
 * Since __ww_mutex_add_waiter() orders the wait-list on stamp, we only have to
 * look at waiters before us in the wait-list.
 */
static inline int
__ww_mutex_check_kill(struct MUTEX *lock, struct MUTEX_WAITER *waiter,
                      struct ww_acquire_ctx *ctx)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Associate the ww_mutex @ww with the context @ww_ctx under which we acquired
 * it.
 */
static __always_inline void
ww_mutex_lock_acquired(struct ww_mutex *ww, struct ww_acquire_ctx *ww_ctx)
{
    ww_ctx->acquired++;
    ww->ctx = ww_ctx;
}
