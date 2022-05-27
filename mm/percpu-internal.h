/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_PERCPU_INTERNAL_H
#define _MM_PERCPU_INTERNAL_H

#include <linux/types.h>
#include <linux/percpu.h>

/*
 * pcpu_block_md is the metadata block struct.
 * Each chunk's bitmap is split into a number of full blocks.
 * All units are in terms of bits.
 *
 * The scan hint is the largest known contiguous area before the contig hint.
 * It is not necessarily the actual largest contig hint though.  There is an
 * invariant that the scan_hint_start > contig_hint_start iff
 * scan_hint == contig_hint.  This is necessary because when scanning forward,
 * we don't know if a new contig hint would be better than the current one.
 */
struct pcpu_block_md {
    int scan_hint;  /* scan hint for block */
    int scan_hint_start; /* block relative starting position of the scan hint */
    int contig_hint;    /* contig hint for block */
    int contig_hint_start; /* block relative starting
                              position of the contig hint */
    int left_free;      /* size of free space along
                           the left side of the block */
    int right_free;     /* size of free space along
                           the right side of the block */
    int first_free;     /* block position of first free */
    int nr_bits;        /* total bits responsible for */
};

struct pcpu_chunk {
    struct list_head list;  /* linked to pcpu_slot lists */
    int free_bytes;         /* free bytes in the chunk */
    struct pcpu_block_md    chunk_md;

    void *base_addr;    /* base address of this chunk */

    unsigned long           *alloc_map; /* allocation map */
    unsigned long           *bound_map; /* boundary map */
    struct pcpu_block_md    *md_blocks; /* metadata blocks */

    bool immutable;     /* no [de]population allowed */

    int start_offset;   /* the overlap with the previous
                           region to have a page aligned base_addr */
    int end_offset;     /* additional area required
                           to have the region end page aligned */

    int nr_pages;           /* # of pages served by this chunk */
    int nr_populated;       /* # of populated pages */
    int nr_empty_pop_pages; /* # of empty populated pages */

    unsigned long   populated[];    /* populated bitmap */
};

/*
 * For debug purposes. We don't care about the flexible array.
 */
static inline void pcpu_stats_save_ai(const struct pcpu_alloc_info *ai)
{
}

/**
 * pcpu_chunk_nr_blocks - converts nr_pages to # of md_blocks
 * @chunk: chunk of interest
 *
 * This conversion is from the number of physical pages that the chunk
 * serves to the number of bitmap blocks used.
 */
static inline int pcpu_chunk_nr_blocks(struct pcpu_chunk *chunk)
{
    return chunk->nr_pages * PAGE_SIZE / PCPU_BITMAP_BLOCK_SIZE;
}

/**
 * pcpu_nr_pages_to_map_bits - converts the pages to size of bitmap
 * @pages: number of physical pages
 *
 * This conversion is from physical pages to the number of bits
 * required in the bitmap.
 */
static inline int pcpu_nr_pages_to_map_bits(int pages)
{
    return pages * PAGE_SIZE / PCPU_MIN_ALLOC_SIZE;
}

/**
 * pcpu_chunk_map_bits - helper to convert nr_pages to size of bitmap
 * @chunk: chunk of interest
 *
 * This conversion is from the number of physical pages that the chunk
 * serves to the number of bits in the bitmap.
 */
static inline int pcpu_chunk_map_bits(struct pcpu_chunk *chunk)
{
    return pcpu_nr_pages_to_map_bits(chunk->nr_pages);
}

#endif /* _MM_PERCPU_INTERNAL_H */
