// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Facebook
 * Copyright (C) 2013-2014 Jens Axboe
 */

#include <linux/sched.h>
#include <linux/random.h>
#include <linux/sbitmap.h>
//#include <linux/seq_file.h>

static int init_alloc_hint(struct sbitmap *sb, gfp_t flags)
{
    unsigned depth = sb->depth;

    sb->alloc_hint = alloc_percpu_gfp(unsigned int, flags);
    if (!sb->alloc_hint)
        return -ENOMEM;

    if (depth && !sb->round_robin) {
        int i;

        for_each_possible_cpu(i)
            *per_cpu_ptr(sb->alloc_hint, i) = prandom_u32() % depth;
    }
    return 0;
}

int sbitmap_init_node(struct sbitmap *sb, unsigned int depth, int shift,
                      gfp_t flags, int node, bool round_robin,
                      bool alloc_hint)
{
    unsigned int bits_per_word;

    if (shift < 0)
        shift = sbitmap_calculate_shift(depth);

    bits_per_word = 1U << shift;
    if (bits_per_word > BITS_PER_LONG)
        return -EINVAL;

    sb->shift = shift;
    sb->depth = depth;
    sb->map_nr = DIV_ROUND_UP(sb->depth, bits_per_word);
    sb->round_robin = round_robin;

    if (depth == 0) {
        sb->map = NULL;
        return 0;
    }

    if (alloc_hint) {
        if (init_alloc_hint(sb, flags))
            return -ENOMEM;
    } else {
        sb->alloc_hint = NULL;
    }

    sb->map = kvzalloc_node(sb->map_nr * sizeof(*sb->map), flags, node);
    if (!sb->map) {
        free_percpu(sb->alloc_hint);
        return -ENOMEM;
    }

    return 0;
}

static unsigned int sbq_calc_wake_batch(struct sbitmap_queue *sbq,
                                        unsigned int depth)
{
    unsigned int wake_batch;
    unsigned int shallow_depth;

    /*
     * For each batch, we wake up one queue. We need to make sure that our
     * batch size is small enough that the full depth of the bitmap,
     * potentially limited by a shallow depth, is enough to wake up all of
     * the queues.
     *
     * Each full word of the bitmap has bits_per_word bits, and there might
     * be a partial word. There are depth / bits_per_word full words and
     * depth % bits_per_word bits left over. In bitwise arithmetic:
     *
     * bits_per_word = 1 << shift
     * depth / bits_per_word = depth >> shift
     * depth % bits_per_word = depth & ((1 << shift) - 1)
     *
     * Each word can be limited to sbq->min_shallow_depth bits.
     */
    shallow_depth = min(1U << sbq->sb.shift, sbq->min_shallow_depth);
    depth = ((depth >> sbq->sb.shift) * shallow_depth +
             min(depth & ((1U << sbq->sb.shift) - 1), shallow_depth));
    wake_batch = clamp_t(unsigned int, depth / SBQ_WAIT_QUEUES, 1,
                         SBQ_WAKE_BATCH);

    return wake_batch;
}

int sbitmap_queue_init_node(struct sbitmap_queue *sbq, unsigned int depth,
                            int shift, bool round_robin, gfp_t flags, int node)
{
    int ret;
    int i;

    ret = sbitmap_init_node(&sbq->sb, depth, shift, flags, node,
                            round_robin, true);
    if (ret)
        return ret;

    sbq->min_shallow_depth = UINT_MAX;
    sbq->wake_batch = sbq_calc_wake_batch(sbq, depth);
    atomic_set(&sbq->wake_index, 0);
    atomic_set(&sbq->ws_active, 0);

    sbq->ws = kzalloc_node(SBQ_WAIT_QUEUES * sizeof(*sbq->ws), flags, node);
    if (!sbq->ws) {
        sbitmap_free(&sbq->sb);
        return -ENOMEM;
    }

#if 0
    for (i = 0; i < SBQ_WAIT_QUEUES; i++) {
        init_waitqueue_head(&sbq->ws[i].wait);
        atomic_set(&sbq->ws[i].wait_cnt, sbq->wake_batch);
    }
#endif

    return 0;
}
EXPORT_SYMBOL_GPL(sbitmap_queue_init_node);
