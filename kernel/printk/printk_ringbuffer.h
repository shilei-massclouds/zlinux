/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KERNEL_PRINTK_RINGBUFFER_H
#define _KERNEL_PRINTK_RINGBUFFER_H

#include <linux/atomic.h>
#include <linux/dev_printk.h>

#define _DATA_SIZE(sz_bits) (1UL << (sz_bits))
#define _DESCS_COUNT(ct_bits)   (1U << (ct_bits))
#define DESC_SV_BITS        (sizeof(unsigned long) * 8)
#define DESC_FLAGS_SHIFT    (DESC_SV_BITS - 2)
#define DESC_FLAGS_MASK     (3UL << DESC_FLAGS_SHIFT)
#define DESC_STATE(sv)      (3UL & (sv >> DESC_FLAGS_SHIFT))
#define DESC_SV(id, state)  (((unsigned long)state << DESC_FLAGS_SHIFT) | id)
#define DESC_ID_MASK        (~DESC_FLAGS_MASK)
#define DESC_ID(sv)         ((sv) & DESC_ID_MASK)
#define FAILED_LPOS         0x1
#define NO_LPOS             0x3

#define FAILED_BLK_LPOS     \
{                           \
    .begin  = FAILED_LPOS,  \
    .next   = FAILED_LPOS,  \
}

/*
 * Initiating Logical Value Overflows
 *
 * Both logical position (lpos) and ID values can be mapped to array indexes
 * but may experience overflows during the lifetime of the system. To ensure
 * that printk_ringbuffer can handle the overflows for these types, initial
 * values are chosen that map to the correct initial array indexes, but will
 * result in overflows soon.
 *
 *   BLK0_LPOS
 *     The initial @head_lpos and @tail_lpos for data rings. It is at index
 *     0 and the lpos value is such that it will overflow on the first wrap.
 *
 *   DESC0_ID
 *     The initial @head_id and @tail_id for the desc ring. It is at the last
 *     index of the descriptor array (see Req3 above) and the ID value is such
 *     that it will overflow on the second wrap.
 */
#define BLK0_LPOS(sz_bits)  (-(_DATA_SIZE(sz_bits)))
#define DESC0_ID(ct_bits)   DESC_ID(-(_DESCS_COUNT(ct_bits) + 1))
#define DESC0_SV(ct_bits)   DESC_SV(DESC0_ID(ct_bits), desc_reusable)

/*
 * Define a ringbuffer with an external text data buffer. The same as
 * DEFINE_PRINTKRB() but requires specifying an external buffer for the
 * text data.
 *
 * Note: The specified external buffer must be of the size:
 *       2 ^ (descbits + avgtextbits)
 */
#define _DEFINE_PRINTKRB(name, descbits, avgtextbits, text_buf)     \
static struct prb_desc _##name##_descs[_DESCS_COUNT(descbits)] = {  \
    /* the initial head and tail */                                 \
    [_DESCS_COUNT(descbits) - 1] = {                                \
        /* reusable */                                              \
        .state_var = ATOMIC_INIT(DESC0_SV(descbits)),               \
        /* no associated data block */                              \
        .text_blk_lpos = FAILED_BLK_LPOS,                           \
    },                                                              \
};                                                                  \
static struct printk_info _##name##_infos[_DESCS_COUNT(descbits)] = {   \
    /* this will be the first record reserved by a writer */            \
    [0] = {                                                             \
        /* will be incremented to 0 on the first reservation */         \
        .seq = -(u64)_DESCS_COUNT(descbits),                            \
    },                                                                  \
    /* the initial head and tail */                                     \
    [_DESCS_COUNT(descbits) - 1] = {                                    \
        /* reports the first seq value during the bootstrap phase */    \
        .seq = 0,                                                       \
    },                                                                  \
};                                                                      \
static struct printk_ringbuffer name = {                        \
    .desc_ring = {                                              \
        .count_bits = descbits,                                 \
        .descs      = &_##name##_descs[0],                      \
        .infos      = &_##name##_infos[0],                      \
        .head_id    = ATOMIC_INIT(DESC0_ID(descbits)),          \
        .tail_id    = ATOMIC_INIT(DESC0_ID(descbits)),          \
        .last_finalized_id = ATOMIC_INIT(DESC0_ID(descbits)),   \
    },                                                          \
    .text_data_ring = {                                         \
        .size_bits  = (avgtextbits) + (descbits),               \
        .data       = text_buf,                                 \
        .head_lpos  = ATOMIC_LONG_INIT(BLK0_LPOS((avgtextbits) + (descbits))), \
        .tail_lpos  = ATOMIC_LONG_INIT(BLK0_LPOS((avgtextbits) + (descbits))), \
    },                                                          \
    .fail           = ATOMIC_LONG_INIT(0),                      \
}

/* The possible responses of a descriptor state-query. */
enum desc_state {
    desc_miss   =  -1,  /* ID mismatch (pseudo state) */
    desc_reserved   = 0x0,  /* reserved, in use by writer */
    desc_committed  = 0x1,  /* committed by writer, could get reopened */
    desc_finalized  = 0x2,  /* committed, no further modification allowed */
    desc_reusable   = 0x3,  /* free, not yet used by any writer */
};

/*
 * Meta information about each stored message.
 *
 * All fields are set by the printk code except for @seq, which is
 * set by the ringbuffer code.
 */
struct printk_info {
    u64 seq;        /* sequence number */
    u64 ts_nsec;    /* timestamp in nanoseconds */
    u16 text_len;   /* length of text message */
    u8  facility;   /* syslog facility */
    u8  flags:5;    /* internal record flags */
    u8  level:3;    /* syslog level */
    u32 caller_id;  /* thread id or processor id */

    struct dev_printk_info  dev_info;
};

/*
 * A structure providing the buffers, used by writers and readers.
 *
 * Writers:
 * Using prb_rec_init_wr(), a writer sets @text_buf_size before calling
 * prb_reserve(). On success, prb_reserve() sets @info and @text_buf to
 * buffers reserved for that writer.
 *
 * Readers:
 * Using prb_rec_init_rd(), a reader sets all fields before calling
 * prb_read_valid(). Note that the reader provides the @info and @text_buf,
 * buffers. On success, the struct pointed to by @info will be filled and
 * the char array pointed to by @text_buf will be filled with text data.
 */
struct printk_record {
    struct printk_info  *info;
    char                *text_buf;
    unsigned int        text_buf_size;
};

/* Specifies the logical position and span of a data block. */
struct prb_data_blk_lpos {
    unsigned long   begin;
    unsigned long   next;
};

/*
 * A descriptor: the complete meta-data for a record.
 *
 * @state_var: A bitwise combination of descriptor ID and descriptor state.
 */
struct prb_desc {
    atomic_long_t               state_var;
    struct prb_data_blk_lpos    text_blk_lpos;
};

/* A ringbuffer of "ID + data" elements. */
struct prb_data_ring {
    unsigned int    size_bits;
    char            *data;
    atomic_long_t   head_lpos;
    atomic_long_t   tail_lpos;
};

/* A ringbuffer of "struct prb_desc" elements. */
struct prb_desc_ring {
    unsigned int        count_bits;
    struct prb_desc     *descs;
    struct printk_info  *infos;
    atomic_long_t       head_id;
    atomic_long_t       tail_id;
    atomic_long_t       last_finalized_id;
};

/*
 * The high level structure representing the printk ringbuffer.
 *
 * @fail: Count of failed prb_reserve() calls where not even a data-less
 *        record was created.
 */
struct printk_ringbuffer {
    struct prb_desc_ring    desc_ring;
    struct prb_data_ring    text_data_ring;
    atomic_long_t           fail;
};

/*
 * Used by writers as a reserve/commit handle.
 *
 * @rb:         Ringbuffer where the entry is reserved.
 * @irqflags:   Saved irq flags to restore on entry commit.
 * @id:         ID of the reserved descriptor.
 * @text_space: Total occupied buffer space in the text data ring, including
 *              ID, alignment padding, and wrapping data blocks.
 *
 * This structure is an opaque handle for writers. Its contents are only
 * to be used by the ringbuffer implementation.
 */
struct prb_reserved_entry {
    struct printk_ringbuffer    *rb;
    unsigned long           irqflags;
    unsigned long           id;
    unsigned int            text_space;
};

/**
 * prb_rec_init_wr() - Initialize a buffer for writing records.
 *
 * @r:             The record to initialize.
 * @text_buf_size: The needed text buffer size.
 */
static inline void prb_rec_init_wr(struct printk_record *r,
                                   unsigned int text_buf_size)
{
    r->info = NULL;
    r->text_buf = NULL;
    r->text_buf_size = text_buf_size;
}

bool prb_reserve(struct prb_reserved_entry *e, struct printk_ringbuffer *rb,
                 struct printk_record *r);

bool prb_reserve_in_last(struct prb_reserved_entry *e,
                         struct printk_ringbuffer *rb,
                         struct printk_record *r,
                         u32 caller_id,
                         unsigned int max_size);

void prb_commit(struct prb_reserved_entry *e);
void prb_final_commit(struct prb_reserved_entry *e);

/* Reader Interface */

/**
 * prb_rec_init_rd() - Initialize a buffer for reading records.
 *
 * @r:             The record to initialize.
 * @info:          A buffer to store record meta-data.
 * @text_buf:      A buffer to store text data.
 * @text_buf_size: The size of @text_buf.
 *
 * Initialize all the fields that a reader is interested in. All arguments
 * (except @r) are optional. Only record data for arguments that are
 * non-NULL or non-zero will be read.
 */
static inline void prb_rec_init_rd(struct printk_record *r,
                                   struct printk_info *info,
                                   char *text_buf, unsigned int text_buf_size)
{
    r->info = info;
    r->text_buf = text_buf;
    r->text_buf_size = text_buf_size;
}

bool prb_read_valid(struct printk_ringbuffer *rb, u64 seq,
                    struct printk_record *r);

#endif /* _KERNEL_PRINTK_RINGBUFFER_H */
