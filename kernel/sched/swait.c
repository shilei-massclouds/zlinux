// SPDX-License-Identifier: GPL-2.0
/*
 * <linux/swait.h> (simple wait queues ) implementation:
 */

void __init_swait_queue_head(struct swait_queue_head *q, const char *name,
                             struct lock_class_key *key)
{
    raw_spin_lock_init(&q->lock);
    INIT_LIST_HEAD(&q->task_list);
}
EXPORT_SYMBOL(__init_swait_queue_head);
