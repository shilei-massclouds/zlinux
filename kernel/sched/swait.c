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

/*
 * The thing about the wake_up_state() return value; I think we can ignore it.
 *
 * If for some reason it would return 0, that means the previously waiting
 * task is already running, so it will observe condition true (or has already).
 */
void swake_up_locked(struct swait_queue_head *q)
{
    struct swait_queue *curr;

    if (list_empty(&q->task_list))
        return;

    curr = list_first_entry(&q->task_list, typeof(*curr), task_list);
    wake_up_process(curr->task);
    list_del_init(&curr->task_list);
}
EXPORT_SYMBOL(swake_up_locked);

void __prepare_to_swait(struct swait_queue_head *q,
                        struct swait_queue *wait)
{
    wait->task = current;
    if (list_empty(&wait->task_list))
        list_add_tail(&wait->task_list, &q->task_list);
}

void __finish_swait(struct swait_queue_head *q,
                    struct swait_queue *wait)
{
    __set_current_state(TASK_RUNNING);
    if (!list_empty(&wait->task_list))
        list_del_init(&wait->task_list);
}
