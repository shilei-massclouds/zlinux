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

#endif /* __LINUX_SCALE_BITMAP_H */
