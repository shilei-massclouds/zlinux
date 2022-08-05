/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/buffer_head.h
 *
 * Everything to do with buffer_heads.
 */

#ifndef _LINUX_BUFFER_HEAD_H
#define _LINUX_BUFFER_HEAD_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#define MAX_BUF_PER_PAGE (PAGE_SIZE / 512)

enum bh_state_bits {
    BH_Uptodate,    /* Contains valid data */
    BH_Dirty,       /* Is dirty */
    BH_Lock,        /* Is locked */
    BH_Req,         /* Has been submitted for I/O */

    BH_Mapped,      /* Has a disk mapping */
    BH_New,         /* Disk mapping was newly created by get_block */
    BH_Async_Read,  /* Is under end_buffer_async_read I/O */
    BH_Async_Write, /* Is under end_buffer_async_write I/O */
    BH_Delay,       /* Buffer is not yet allocated on disk */
    BH_Boundary,    /* Block is followed by a discontiguity */
    BH_Write_EIO,   /* I/O error on write */
    BH_Unwritten,   /* Buffer is allocated on disk but not written */
    BH_Quiet,       /* Buffer Error Prinks to be quiet */
    BH_Meta,        /* Buffer contains metadata */
    BH_Prio,        /* Buffer should be submitted with REQ_PRIO */
    BH_Defer_Completion, /* Defer AIO completion to workqueue */

    BH_PrivateStart,/* not a state bit, but the first bit available
                     * for private allocation by other entities
                     */
};

struct page;
struct buffer_head;
struct address_space;
typedef void (bh_end_io_t)(struct buffer_head *bh, int uptodate);

/*
 * Historically, a buffer_head was used to map a single block
 * within a page, and of course as the unit of I/O through the
 * filesystem and block layers.  Nowadays the basic I/O unit
 * is the bio, and buffer_heads are used for extracting block
 * mappings (via a get_block_t call), for tracking state within
 * a page (via a page_mapping) and for wrapping bio submission
 * for backward compatibility reasons (e.g. submit_bh).
 */
struct buffer_head {
    unsigned long b_state;          /* buffer state bitmap (see above) */
    struct buffer_head *b_this_page;/* circular list of page's buffers */
    struct page *b_page;            /* the page this bh is mapped to */

    sector_t b_blocknr;     /* start block number */
    size_t b_size;          /* size of mapping */
    char *b_data;           /* pointer to data within the page */

    struct block_device *b_bdev;
    bh_end_io_t *b_end_io;              /* I/O completion */
    void *b_private;                    /* reserved for b_end_io */
    struct list_head b_assoc_buffers;   /* associated with another mapping */
    struct address_space *b_assoc_map;  /* mapping this buffer is
                                           associated with */
    atomic_t b_count;                   /* users using this buffer_head */
    spinlock_t b_uptodate_lock;         /* Used by the first bh in a page, to
                                         * serialise IO completion of other
                                         * * buffers in the page */
};

/*
 * macro tricks to expand the set_buffer_foo(), clear_buffer_foo()
 * and buffer_foo() functions.
 * To avoid reset buffer flags that are already set, because that causes
 * a costly cache line transition, check the flag first.
 */
#define BUFFER_FNS(bit, name)                       \
static __always_inline void set_buffer_##name(struct buffer_head *bh)   \
{                                   \
    if (!test_bit(BH_##bit, &(bh)->b_state))            \
        set_bit(BH_##bit, &(bh)->b_state);          \
}                                   \
static __always_inline void clear_buffer_##name(struct buffer_head *bh) \
{                                   \
    clear_bit(BH_##bit, &(bh)->b_state);                \
}                                   \
static __always_inline int buffer_##name(const struct buffer_head *bh)  \
{                                   \
    return test_bit(BH_##bit, &(bh)->b_state);          \
}

/*
 * test_set_buffer_foo() and test_clear_buffer_foo()
 */
#define TAS_BUFFER_FNS(bit, name)                   \
static __always_inline int test_set_buffer_##name(struct buffer_head *bh) \
{                                   \
    return test_and_set_bit(BH_##bit, &(bh)->b_state);      \
}                                   \
static __always_inline int test_clear_buffer_##name(struct buffer_head *bh) \
{                                   \
    return test_and_clear_bit(BH_##bit, &(bh)->b_state);        \
}                                   \

/*
 * Generic address_space_operations implementations for buffer_head-backed
 * address_spaces.
 */
void block_invalidate_folio(struct folio *folio, size_t offset, size_t length);
int block_write_full_page(struct page *page, get_block_t *get_block,
                          struct writeback_control *wbc);
int
__block_write_full_page(struct inode *inode, struct page *page,
                        get_block_t *get_block, struct writeback_control *wbc,
                        bh_end_io_t *handler);

int block_read_full_page(struct page*, get_block_t*);
bool block_is_partially_uptodate(struct folio *, size_t from, size_t count);
int
block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
                  unsigned flags, struct page **pagep, get_block_t *get_block);
int __block_write_begin(struct page *page, loff_t pos, unsigned len,
                        get_block_t *get_block);
int block_write_end(struct file *, struct address_space *,
                    loff_t, unsigned, unsigned,
                    struct page *, void *);
int generic_write_end(struct file *, struct address_space *,
                      loff_t, unsigned, unsigned,
                      struct page *, void *);

bool block_dirty_folio(struct address_space *mapping, struct folio *folio);

void buffer_check_dirty_writeback(struct page *page,
                                  bool *dirty, bool *writeback);

BUFFER_FNS(Uptodate, uptodate)
BUFFER_FNS(Dirty, dirty)
TAS_BUFFER_FNS(Dirty, dirty)
BUFFER_FNS(Lock, locked)
BUFFER_FNS(Req, req)
TAS_BUFFER_FNS(Req, req)
BUFFER_FNS(Mapped, mapped)
BUFFER_FNS(Async_Read, async_read)
BUFFER_FNS(Delay, delay)
BUFFER_FNS(Write_EIO, write_io_error)
BUFFER_FNS(Unwritten, unwritten)
BUFFER_FNS(Meta, meta)
BUFFER_FNS(Prio, prio)

#define bh_offset(bh)   ((unsigned long)(bh)->b_data & ~PAGE_MASK)

/* If we *know* page->private refers to buffer_heads */
#define page_buffers(page)      \
({                              \
    BUG_ON(!PagePrivate(page)); \
    ((struct buffer_head *)page_private(page)); \
})

#define page_has_buffers(page)  PagePrivate(page)

void buffer_init(void);

void unlock_buffer(struct buffer_head *bh);
void __lock_buffer(struct buffer_head *bh);

static inline int trylock_buffer(struct buffer_head *bh)
{
    return likely(!test_and_set_bit_lock(BH_Lock, &bh->b_state));
}

static inline void lock_buffer(struct buffer_head *bh)
{
    might_sleep();
    if (!trylock_buffer(bh))
        __lock_buffer(bh);
}

void invalidate_bh_lrus(void);

struct buffer_head *__bread_gfp(struct block_device *,
                                sector_t block, unsigned size, gfp_t gfp);

static inline struct buffer_head *
sb_bread(struct super_block *sb, sector_t block)
{
    return __bread_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE);
}

static inline void get_bh(struct buffer_head *bh)
{
    atomic_inc(&bh->b_count);
}

void __brelse(struct buffer_head *);

static inline void brelse(struct buffer_head *bh)
{
    if (bh)
        __brelse(bh);
}

static inline void put_bh(struct buffer_head *bh)
{
    smp_mb__before_atomic();
    atomic_dec(&bh->b_count);
}

void __wait_on_buffer(struct buffer_head *);

static inline void wait_on_buffer(struct buffer_head *bh)
{
    might_sleep();
    if (buffer_locked(bh))
        __wait_on_buffer(bh);
}

#define folio_buffers(folio)    folio_get_private(folio)

int try_to_free_buffers(struct page *);

int inode_has_buffers(struct inode *);

int nobh_write_begin(struct address_space *, loff_t, unsigned, unsigned,
                     struct page **, void **, get_block_t*);
int nobh_write_end(struct file *, struct address_space *,
                   loff_t, unsigned, unsigned,
                   struct page *, void *);

#endif /* _LINUX_BUFFER_HEAD_H */
