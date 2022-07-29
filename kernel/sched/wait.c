// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic waiting primitives.
 *
 * (C) 2004 Nadia Yvette Chambers, Oracle
 */

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
