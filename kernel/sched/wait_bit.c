// SPDX-License-Identifier: GPL-2.0-only

/*
 * The implementation of the wait_bit*() and related waiting APIs:
 */

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)

static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;

wait_queue_head_t *bit_waitqueue(void *word, int bit)
{
    const int shift = 6;
    unsigned long val = (unsigned long)word << shift | bit;

    return bit_wait_table + hash_long(val, WAIT_TABLE_BITS);
}
EXPORT_SYMBOL(bit_waitqueue);

void __wake_up_bit(struct wait_queue_head *wq_head, void *word, int bit)
{
    struct wait_bit_key key = __WAIT_BIT_KEY_INITIALIZER(word, bit);

    if (waitqueue_active(wq_head))
        __wake_up(wq_head, TASK_NORMAL, 1, &key);
}
EXPORT_SYMBOL(__wake_up_bit);

/**
 * wake_up_bit - wake up a waiter on a bit
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that wakes up waiters
 * on a bit. For instance, if one were to have waiters on a bitflag,
 * one would call wake_up_bit() after clearing the bit.
 *
 * In order for this to function properly, as it uses waitqueue_active()
 * internally, some kind of memory barrier must be done prior to calling
 * this. Typically, this will be smp_mb__after_atomic(), but in some
 * cases where bitflags are manipulated non-atomically under a lock, one
 * may need to use a less regular barrier, such fs/inode.c's smp_mb(),
 * because spin_unlock() does not guarantee a memory barrier.
 */
void wake_up_bit(void *word, int bit)
{
    __wake_up_bit(bit_waitqueue(word, bit), word, bit);
}
EXPORT_SYMBOL(wake_up_bit);

/*
 * Note: we use "set_current_state()" _after_ the wait-queue add,
 * because we need a memory barrier there on SMP, so that any
 * wake-function that tests for the wait-queue being active
 * will be guaranteed to see waitqueue addition _or_ subsequent
 * tests in this thread will see the wakeup having taken place.
 *
 * The spin_unlock() itself is semi-permeable and only protects
 * one way (it only protects stuff inside the critical region and
 * stops them from bleeding out - it would still allow subsequent
 * loads to move into the critical region).
 */
void
prepare_to_wait(struct wait_queue_head *wq_head,
                struct wait_queue_entry *wq_entry, int state)
{
    unsigned long flags;

    wq_entry->flags &= ~WQ_FLAG_EXCLUSIVE;
    spin_lock_irqsave(&wq_head->lock, flags);
    if (list_empty(&wq_entry->entry))
        __add_wait_queue(wq_head, wq_entry);
    set_current_state(state);
    spin_unlock_irqrestore(&wq_head->lock, flags);
}
EXPORT_SYMBOL(prepare_to_wait);

/**
 * finish_wait - clean up after waiting in a queue
 * @wq_head: waitqueue waited on
 * @wq_entry: wait descriptor
 *
 * Sets current thread back to running state and removes
 * the wait descriptor from the given waitqueue if still
 * queued.
 */
void finish_wait(struct wait_queue_head *wq_head,
                 struct wait_queue_entry *wq_entry)
{
    unsigned long flags;

    __set_current_state(TASK_RUNNING);
    /*
     * We can check for list emptiness outside the lock
     * IFF:
     *  - we use the "careful" check that verifies both
     *    the next and prev pointers, so that there cannot
     *    be any half-pending updates in progress on other
     *    CPU's that we haven't seen yet (and that might
     *    still change the stack area.
     * and
     *  - all other users take the lock (ie we can only
     *    have _one_ other CPU that looks at or modifies
     *    the list).
     */
    if (!list_empty_careful(&wq_entry->entry)) {
        spin_lock_irqsave(&wq_head->lock, flags);
        list_del_init(&wq_entry->entry);
        spin_unlock_irqrestore(&wq_head->lock, flags);
    }
}
EXPORT_SYMBOL(finish_wait);

/*
 * To allow interruptible waiting and asynchronous (i.e. nonblocking)
 * waiting, the actions of __wait_on_bit() and __wait_on_bit_lock() are
 * permitted return codes. Nonzero return codes halt waiting and return.
 */
int __sched
__wait_on_bit(struct wait_queue_head *wq_head,
              struct wait_bit_queue_entry *wbq_entry,
              wait_bit_action_f *action, unsigned mode)
{
    int ret = 0;

    do {
        prepare_to_wait(wq_head, &wbq_entry->wq_entry, mode);
        if (test_bit(wbq_entry->key.bit_nr, wbq_entry->key.flags))
            ret = (*action)(&wbq_entry->key, mode);
    } while (test_bit(wbq_entry->key.bit_nr, wbq_entry->key.flags) && !ret);

    finish_wait(wq_head, &wbq_entry->wq_entry);

    return ret;
}
EXPORT_SYMBOL(__wait_on_bit);

int __sched out_of_line_wait_on_bit(void *word, int bit,
                                    wait_bit_action_f *action, unsigned mode)
{
    struct wait_queue_head *wq_head = bit_waitqueue(word, bit);
    DEFINE_WAIT_BIT(wq_entry, word, bit);

    return __wait_on_bit(wq_head, &wq_entry, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_bit);

void __init wait_bit_init(void)
{
    int i;

    for (i = 0; i < WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(bit_wait_table + i);
}

int wake_bit_function(struct wait_queue_entry *wq_entry,
                      unsigned mode, int sync, void *arg)
{
    struct wait_bit_key *key = arg;
    struct wait_bit_queue_entry *wait_bit =
        container_of(wq_entry, struct wait_bit_queue_entry, wq_entry);

    if (wait_bit->key.flags != key->flags ||
        wait_bit->key.bit_nr != key->bit_nr ||
        test_bit(key->bit_nr, key->flags))
        return 0;

    return autoremove_wake_function(wq_entry, mode, sync, key);
}
EXPORT_SYMBOL(wake_bit_function);

__sched int bit_wait_io(struct wait_bit_key *word, int mode)
{
    io_schedule();
    if (signal_pending_state(mode, current))
        return -EINTR;

    return 0;
}
EXPORT_SYMBOL(bit_wait_io);
