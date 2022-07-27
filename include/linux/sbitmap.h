/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Fast and scalable bitmaps.
 *
 * Copyright (C) 2016 Facebook
 * Copyright (C) 2013-2014 Jens Axboe
 */

#ifndef __LINUX_SCALE_BITMAP_H
#define __LINUX_SCALE_BITMAP_H

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/wait.h>

#define SBQ_WAIT_QUEUES 8
#define SBQ_WAKE_BATCH  8

struct seq_file;

/**
 * struct sbitmap_word - Word in a &struct sbitmap.
 */
struct sbitmap_word {
    /**
     * @word: word holding free bits
     */
    unsigned long word;

    /**
     * @cleared: word holding cleared bits
     */
    unsigned long cleared ____cacheline_aligned_in_smp;
} ____cacheline_aligned_in_smp;

/**
 * struct sbitmap - Scalable bitmap.
 *
 * A &struct sbitmap is spread over multiple cachelines to avoid ping-pong. This
 * trades off higher memory usage for better scalability.
 */
struct sbitmap {
    /**
     * @depth: Number of bits used in the whole bitmap.
     */
    unsigned int depth;

    /**
     * @shift: log2(number of bits used per word)
     */
    unsigned int shift;

    /**
     * @map_nr: Number of words (cachelines) being used for the bitmap.
     */
    unsigned int map_nr;

    /**
     * @round_robin: Allocate bits in strict round-robin order.
     */
    bool round_robin;

    /**
     * @map: Allocated bitmap.
     */
    struct sbitmap_word *map;

    /*
     * @alloc_hint: Cache of last successfully allocated or freed bit.
     *
     * This is per-cpu, which allows multiple users to stick to different
     * cachelines until the map is exhausted.
     */
    unsigned int __percpu *alloc_hint;
};

/**
 * struct sbq_wait_state - Wait queue in a &struct sbitmap_queue.
 */
struct sbq_wait_state {
    /**
     * @wait_cnt: Number of frees remaining before we wake up.
     */
    atomic_t wait_cnt;

#if 0
    /**
     * @wait: Wait queue.
     */
    wait_queue_head_t wait;
#endif
} ____cacheline_aligned_in_smp;

/**
 * struct sbitmap_queue - Scalable bitmap with the added ability to wait on free
 * bits.
 *
 * A &struct sbitmap_queue uses multiple wait queues and rolling wakeups to
 * avoid contention on the wait queue spinlock. This ensures that we don't hit a
 * scalability wall when we run out of free bits and have to start putting tasks
 * to sleep.
 */
struct sbitmap_queue {
    /**
     * @sb: Scalable bitmap.
     */
    struct sbitmap sb;

    /**
     * @wake_batch: Number of bits which must be freed before we wake up any
     * waiters.
     */
    unsigned int wake_batch;

    /**
     * @wake_index: Next wait queue in @ws to wake up.
     */
    atomic_t wake_index;

    /**
     * @ws: Wait queues.
     */
    struct sbq_wait_state *ws;

    /*
     * @ws_active: count of currently active ws waitqueues
     */
    atomic_t ws_active;

    /**
     * @min_shallow_depth: The minimum shallow depth which may be passed to
     * sbitmap_queue_get_shallow()
     */
    unsigned int min_shallow_depth;
};

/**
 * sbitmap_free() - Free memory used by a &struct sbitmap.
 * @sb: Bitmap to free.
 */
static inline void sbitmap_free(struct sbitmap *sb)
{
    free_percpu(sb->alloc_hint);
    kvfree(sb->map);
    sb->map = NULL;
}

/**
 * sbitmap_queue_free() - Free memory used by a &struct sbitmap_queue.
 *
 * @sbq: Bitmap queue to free.
 */
static inline void sbitmap_queue_free(struct sbitmap_queue *sbq)
{
    kfree(sbq->ws);
    sbitmap_free(&sbq->sb);
}

/**
 * sbitmap_queue_init_node() - Initialize a &struct sbitmap_queue on a specific
 * memory node.
 * @sbq: Bitmap queue to initialize.
 * @depth: See sbitmap_init_node().
 * @shift: See sbitmap_init_node().
 * @round_robin: See sbitmap_get().
 * @flags: Allocation flags.
 * @node: Memory node to allocate on.
 *
 * Return: Zero on success or negative errno on failure.
 */
int sbitmap_queue_init_node(struct sbitmap_queue *sbq, unsigned int depth,
                            int shift, bool round_robin, gfp_t flags, int node);

static inline int sbitmap_calculate_shift(unsigned int depth)
{
    int shift = ilog2(BITS_PER_LONG);

    /*
     * If the bitmap is small, shrink the number of bits per word so
     * we spread over a few cachelines, at least. If less than 4
     * bits, just forget about it, it's not going to work optimally
     * anyway.
     */
    if (depth >= 4) {
        while ((4U << shift) > depth)
            shift--;
    }

    return shift;
}

/**
 * sbitmap_init_node() - Initialize a &struct sbitmap on a specific memory node.
 * @sb: Bitmap to initialize.
 * @depth: Number of bits to allocate.
 * @shift: Use 2^@shift bits per word in the bitmap; if a negative number if
 *         given, a good default is chosen.
 * @flags: Allocation flags.
 * @node: Memory node to allocate on.
 * @round_robin: If true, be stricter about allocation order; always allocate
 *               starting from the last allocated bit. This is less efficient
 *               than the default behavior (false).
 * @alloc_hint: If true, apply percpu hint for where to start searching for
 *              a free bit.
 *
 * Return: Zero on success or negative errno on failure.
 */
int sbitmap_init_node(struct sbitmap *sb, unsigned int depth, int shift,
                      gfp_t flags, int node, bool round_robin, bool alloc_hint);

/**
 * sbitmap_resize() - Resize a &struct sbitmap.
 * @sb: Bitmap to resize.
 * @depth: New number of bits to resize to.
 *
 * Doesn't reallocate anything. It's up to the caller to ensure that the new
 * depth doesn't exceed the depth that the sb was initialized with.
 */
void sbitmap_resize(struct sbitmap *sb, unsigned int depth);

/**
 * sbitmap_queue_min_shallow_depth() - Inform a &struct sbitmap_queue of the
 * minimum shallow depth that will be used.
 * @sbq: Bitmap queue in question.
 * @min_shallow_depth: The minimum shallow depth that will be passed to
 * sbitmap_queue_get_shallow() or __sbitmap_queue_get_shallow().
 *
 * sbitmap_queue_clear() batches wakeups as an optimization. The batch size
 * depends on the depth of the bitmap. Since the shallow allocation functions
 * effectively operate with a different depth, the shallow depth must be taken
 * into account when calculating the batch size. This function must be called
 * with the minimum shallow depth that will be used. Failure to do so can result
 * in missed wakeups.
 */
void sbitmap_queue_min_shallow_depth(struct sbitmap_queue *sbq,
                                     unsigned int min_shallow_depth);

/**
 * sbitmap_queue_clear() - Free an allocated bit and wake up waiters on a
 * &struct sbitmap_queue.
 * @sbq: Bitmap to free from.
 * @nr: Bit number to free.
 * @cpu: CPU the bit was allocated on.
 */
void sbitmap_queue_clear(struct sbitmap_queue *sbq, unsigned int nr,
                         unsigned int cpu);

/**
 * sbitmap_queue_get_shallow() - Try to allocate a free bit from a &struct
 * sbitmap_queue, limiting the depth used from each word, with preemption
 * already disabled.
 * @sbq: Bitmap queue to allocate from.
 * @shallow_depth: The maximum number of bits to allocate from a single word.
 * See sbitmap_get_shallow().
 *
 * If you call this, make sure to call sbitmap_queue_min_shallow_depth() after
 * initializing @sbq.
 *
 * Return: Non-negative allocated bit number if successful, -1 otherwise.
 */
int sbitmap_queue_get_shallow(struct sbitmap_queue *sbq,
                              unsigned int shallow_depth);

/**
 * __sbitmap_queue_get() - Try to allocate a free bit from a &struct
 * sbitmap_queue with preemption already disabled.
 * @sbq: Bitmap queue to allocate from.
 *
 * Return: Non-negative allocated bit number if successful, -1 otherwise.
 */
int __sbitmap_queue_get(struct sbitmap_queue *sbq);

#define SB_NR_TO_INDEX(sb, bitnr) ((bitnr) >> (sb)->shift)
#define SB_NR_TO_BIT(sb, bitnr) \
    ((bitnr) & ((1U << (sb)->shift) - 1U))

/* sbitmap internal helper */
static inline unsigned int __map_depth(const struct sbitmap *sb, int index)
{
    if (index == sb->map_nr - 1)
        return sb->depth - (index << sb->shift);
    return 1U << sb->shift;
}

/**
 * __sbitmap_queue_get_batch() - Try to allocate a batch of free bits
 * @sbq: Bitmap queue to allocate from.
 * @nr_tags: number of tags requested
 * @offset: offset to add to returned bits
 *
 * Return: Mask of allocated tags, 0 if none are found. Each tag allocated is
 * a bit in the mask returned, and the caller must add @offset to the value to
 * get the absolute tag value.
 */
unsigned long __sbitmap_queue_get_batch(struct sbitmap_queue *sbq, int nr_tags,
                                        unsigned int *offset);

#endif /* __LINUX_SCALE_BITMAP_H */
