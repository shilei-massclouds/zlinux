// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/irqflags.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include "printk_ringbuffer.h"

/**
 * prb_reserve_in_last() - Re-reserve and extend the space in the ringbuffer
 *                         used by the newest record.
 *
 * @e:         The entry structure to setup.
 * @rb:        The ringbuffer to re-reserve and extend data in.
 * @r:         The record structure to allocate buffers for.
 * @caller_id: The caller ID of the caller (reserving writer).
 * @max_size:  Fail if the extended size would be greater than this.
 *
 * This is the public function available to writers to re-reserve and extend
 * data.
 *
 * The writer specifies the text size to extend (not the new total size) by
 * setting the @text_buf_size field of @r. To ensure proper initialization
 * of @r, prb_rec_init_wr() should be used.
 *
 * This function will fail if @caller_id does not match the caller ID of the
 * newest record. In that case the caller must reserve new data using
 * prb_reserve().
 *
 * Context: Any context. Disables local interrupts on success.
 * Return: true if text data could be extended, otherwise false.
 *
 * On success:
 *
 *   - @r->text_buf points to the beginning of the entire text buffer.
 *
 *   - @r->text_buf_size is set to the new total size of the buffer.
 *
 *   - @r->info is not touched so that @r->info->text_len could be used
 *     to append the text.
 *
 *   - prb_record_text_space() can be used on @e to query the new
 *     actually used space.
 *
 * Important: All @r->info fields will already be set with the current values
 *            for the record. I.e. @r->info->text_len will be less than
 *            @text_buf_size. Writers can use @r->info->text_len to know
 *            where concatenation begins and writers should update
 *            @r->info->text_len after concatenating.
 */
bool prb_reserve_in_last(struct prb_reserved_entry *e,
                         struct printk_ringbuffer *rb,
                         struct printk_record *r,
                         u32 caller_id,
                         unsigned int max_size)
{
    struct prb_desc_ring *desc_ring = &rb->desc_ring;
    struct printk_info *info;
    unsigned int data_size;
    struct prb_desc *d;
    unsigned long id;

    local_irq_save(e->irqflags);

    /* Transition the newest descriptor back to the reserved state. */
    d = desc_reopen_last(desc_ring, caller_id, &id);
    if (!d) {
        local_irq_restore(e->irqflags);
        goto fail_reopen;
    }

    /* Now the writer has exclusive access: LMM(prb_reserve_in_last:A) */

    info = to_info(desc_ring, id);

    /*
     * Set the @e fields here so that prb_commit() can be used if
     * anything fails from now on.
     */
    e->rb = rb;
    e->id = id;


    /*
     * desc_reopen_last() checked the caller_id, but there was no
     * exclusive access at that point. The descriptor may have
     * changed since then.
     */
    if (caller_id != info->caller_id)
        goto fail;

    if (BLK_DATALESS(&d->text_blk_lpos)) {
        if (WARN_ON_ONCE(info->text_len != 0)) {
            pr_warn_once("wrong text_len value (%hu, expecting 0)\n",
                     info->text_len);
            info->text_len = 0;
        }

        if (!data_check_size(&rb->text_data_ring, r->text_buf_size))
            goto fail;

        if (r->text_buf_size > max_size)
            goto fail;

        r->text_buf = data_alloc(rb, r->text_buf_size,
                     &d->text_blk_lpos, id);
    } else {
        if (!get_data(&rb->text_data_ring, &d->text_blk_lpos, &data_size))
            goto fail;

        /*
         * Increase the buffer size to include the original size. If
         * the meta data (@text_len) is not sane, use the full data
         * block size.
         */
        if (WARN_ON_ONCE(info->text_len > data_size)) {
            pr_warn_once("wrong text_len value (%hu, expecting <=%u)\n",
                     info->text_len, data_size);
            info->text_len = data_size;
        }
        r->text_buf_size += info->text_len;

        if (!data_check_size(&rb->text_data_ring, r->text_buf_size))
            goto fail;

        if (r->text_buf_size > max_size)
            goto fail;

        r->text_buf = data_realloc(rb, r->text_buf_size,
                       &d->text_blk_lpos, id);
    }
    if (r->text_buf_size && !r->text_buf)
        goto fail;

    r->info = info;

    e->text_space = space_used(&rb->text_data_ring, &d->text_blk_lpos);

    return true;
fail:
    prb_commit(e);
    /* prb_commit() re-enabled interrupts. */
fail_reopen:
    /* Make it clear to the caller that the re-reserve failed. */
    memset(r, 0, sizeof(*r));
    return false;
}
