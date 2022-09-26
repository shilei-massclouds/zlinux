// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic waiting primitives.
 *
 * (C) 2004 Nadia Yvette Chambers, Oracle
 */

/*
 * Scan threshold to break wait queue walk.
 * This allows a waker to take a break from holding the
 * wait queue lock during the wait queue walk.
 */
#define WAITQUEUE_WALK_BREAK_CNT 64

void __init_waitqueue_head(struct wait_queue_head *wq_head,
                           const char *name, struct lock_class_key *key)
{
    spin_lock_init(&wq_head->lock);
    INIT_LIST_HEAD(&wq_head->head);
}
EXPORT_SYMBOL(__init_waitqueue_head);

int autoremove_wake_function(struct wait_queue_entry *wq_entry,
                             unsigned mode, int sync, void *key)
{
    int ret = default_wake_function(wq_entry, mode, sync, key);

    if (ret)
        list_del_init_careful(&wq_entry->entry);

    return ret;
}
EXPORT_SYMBOL(autoremove_wake_function);

/*
 * The core wakeup function. Non-exclusive wakeups (nr_exclusive == 0) just
 * wake everything up. If it's an exclusive wakeup (nr_exclusive == small +ve
 * number) then we wake that number of exclusive tasks, and potentially all
 * the non-exclusive tasks. Normally, exclusive tasks will be at the end of
 * the list and any non-exclusive tasks will be woken first. A priority task
 * may be at the head of the list, and can consume the event without any other
 * tasks being woken.
 *
 * There are circumstances in which we can try to wake a task which has already
 * started to run but is not in state TASK_RUNNING. try_to_wake_up() returns
 * zero in this (rare) case, and we handle it by continuing to scan the queue.
 */
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
                            int nr_exclusive, int wake_flags, void *key,
                            wait_queue_entry_t *bookmark)
{
    wait_queue_entry_t *curr, *next;
    int cnt = 0;

    if (bookmark && (bookmark->flags & WQ_FLAG_BOOKMARK)) {
        curr = list_next_entry(bookmark, entry);

        list_del(&bookmark->entry);
        bookmark->flags = 0;
    } else
        curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);

    if (&curr->entry == &wq_head->head)
        return nr_exclusive;

    list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
        unsigned flags = curr->flags;
        int ret;

        if (flags & WQ_FLAG_BOOKMARK)
            continue;

        ret = curr->func(curr, mode, wake_flags, key);
        if (ret < 0)
            break;
        if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
            break;

        if (bookmark && (++cnt > WAITQUEUE_WALK_BREAK_CNT) &&
            (&next->entry != &wq_head->head)) {
            bookmark->flags = WQ_FLAG_BOOKMARK;
            list_add_tail(&bookmark->entry, &next->entry);
            break;
        }
    }

    return nr_exclusive;
}

static void __wake_up_common_lock(struct wait_queue_head *wq_head,
                                  unsigned int mode,
                                  int nr_exclusive,
                                  int wake_flags,
                                  void *key)
{
    unsigned long flags;
    wait_queue_entry_t bookmark;

    bookmark.flags = 0;
    bookmark.private = NULL;
    bookmark.func = NULL;
    INIT_LIST_HEAD(&bookmark.entry);

    do {
        spin_lock_irqsave(&wq_head->lock, flags);
        nr_exclusive = __wake_up_common(wq_head, mode, nr_exclusive,
                                        wake_flags, key, &bookmark);
        spin_unlock_irqrestore(&wq_head->lock, flags);
    } while (bookmark.flags & WQ_FLAG_BOOKMARK);
}

/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @wq_head: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: is directly passed to the wakeup function
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 */
void __wake_up(struct wait_queue_head *wq_head, unsigned int mode,
               int nr_exclusive, void *key)
{
    __wake_up_common_lock(wq_head, mode, nr_exclusive, 0, key);
}
EXPORT_SYMBOL(__wake_up);

void __wake_up_locked_key_bookmark(struct wait_queue_head *wq_head,
                                   unsigned int mode,
                                   void *key,
                                   wait_queue_entry_t *bookmark)
{
    __wake_up_common(wq_head, mode, 1, 0, key, bookmark);
}
EXPORT_SYMBOL_GPL(__wake_up_locked_key_bookmark);

void init_wait_entry(struct wait_queue_entry *wq_entry, int flags)
{
    wq_entry->flags = flags;
    wq_entry->private = current;
    wq_entry->func = autoremove_wake_function;
    INIT_LIST_HEAD(&wq_entry->entry);
}
EXPORT_SYMBOL(init_wait_entry);

long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state)
{
    unsigned long flags;
    long ret = 0;

    spin_lock_irqsave(&wq_head->lock, flags);
    if (signal_pending_state(state, current)) {
        /*
         * Exclusive waiter must not fail if it was selected by wakeup,
         * it should "consume" the condition we were waiting for.
         *
         * The caller will recheck the condition and return success if
         * we were already woken up, we can not miss the event because
         * wakeup locks/unlocks the same wq_head->lock.
         *
         * But we need to ensure that set-condition + wakeup after that
         * can't see us, it should wake up another exclusive waiter if
         * we fail.
         */
        list_del_init(&wq_entry->entry);
        ret = -ERESTARTSYS;
    } else {
        if (list_empty(&wq_entry->entry)) {
            if (wq_entry->flags & WQ_FLAG_EXCLUSIVE)
                __add_wait_queue_entry_tail(wq_head, wq_entry);
            else
                __add_wait_queue(wq_head, wq_entry);
        }
        set_current_state(state);
    }
    spin_unlock_irqrestore(&wq_head->lock, flags);

    return ret;
}
EXPORT_SYMBOL(prepare_to_wait_event);
