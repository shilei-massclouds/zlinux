// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "ext2.h"
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/iversion.h>

typedef struct ext2_dir_entry_2 ext2_dirent;

/*
 * Tests against MAX_REC_LEN etc were put in place for 64k block
 * sizes; if that is not possible on this arch, we can skip
 * those tests and speed things up.
 */
static inline unsigned ext2_rec_len_from_disk(__le16 dlen)
{
    unsigned len = le16_to_cpu(dlen);

    if (len == EXT2_MAX_REC_LEN)
        return 1 << 16;
    return len;
}

static int
ext2_readdir(struct file *file, struct dir_context *ctx)
{
    panic("%s: END!\n", __func__);
}

const struct file_operations ext2_dir_operations = {
    .llseek     = generic_file_llseek,
    .read       = generic_read_dir,
    .iterate_shared = ext2_readdir,
    .unlocked_ioctl = ext2_ioctl,
    .fsync      = ext2_fsync,
};

/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned ext2_chunk_size(struct inode *inode)
{
    return inode->i_sb->s_blocksize;
}

static bool ext2_check_page(struct page *page, int quiet, char *kaddr)
{
    struct inode *dir = page->mapping->host;
    struct super_block *sb = dir->i_sb;
    unsigned chunk_size = ext2_chunk_size(dir);
    u32 max_inumber = le32_to_cpu(EXT2_SB(sb)->s_es->s_inodes_count);
    unsigned offs, rec_len;
    unsigned limit = PAGE_SIZE;
    ext2_dirent *p;
    char *error;

    if ((dir->i_size >> PAGE_SHIFT) == page->index) {
        limit = dir->i_size & ~PAGE_MASK;
        if (limit & (chunk_size - 1))
            goto Ebadsize;
        if (!limit)
            goto out;
    }
    for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
        p = (ext2_dirent *)(kaddr + offs);
        rec_len = ext2_rec_len_from_disk(p->rec_len);

        if (unlikely(rec_len < EXT2_DIR_REC_LEN(1)))
            goto Eshort;
        if (unlikely(rec_len & 3))
            goto Ealign;
        if (unlikely(rec_len < EXT2_DIR_REC_LEN(p->name_len)))
            goto Enamelen;
        if (unlikely(((offs + rec_len - 1) ^ offs) & ~(chunk_size-1)))
            goto Espan;
        if (unlikely(le32_to_cpu(p->inode) > max_inumber))
            goto Einumber;
    }
    if (offs != limit)
        goto Eend;

 out:
    SetPageChecked(page);
    return true;

    /* Too bad, we had an error */

 Ebadsize:
    if (!quiet)
        ext2_error(sb, __func__,
                   "size of directory #%lu is not a multiple of chunk size",
                   dir->i_ino);
    goto fail;
 Eshort:
    error = "rec_len is smaller than minimal";
    goto bad_entry;
 Ealign:
    error = "unaligned directory entry";
    goto bad_entry;
 Enamelen:
    error = "rec_len is too small for name_len";
    goto bad_entry;
 Espan:
    error = "directory entry across blocks";
    goto bad_entry;
 Einumber:
    error = "inode out of bounds";
 bad_entry:
    if (!quiet)
        ext2_error(sb, __func__,
                   "bad entry in directory #%lu: : %s - "
                   "offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
                   dir->i_ino, error, (page->index<<PAGE_SHIFT)+offs,
                   (unsigned long) le32_to_cpu(p->inode),
                   rec_len, p->name_len);
    goto fail;
Eend:
    if (!quiet) {
        p = (ext2_dirent *)(kaddr + offs);
        ext2_error(sb, "ext2_check_page",
                   "entry in directory #%lu spans the page boundary"
                   "offset=%lu, inode=%lu",
                   dir->i_ino, (page->index<<PAGE_SHIFT)+offs,
                   (unsigned long) le32_to_cpu(p->inode));
    }
fail:
    SetPageError(page);
    return false;
}

/*
 * Calls to ext2_get_page()/ext2_put_page() must be nested according to the
 * rules documented in kmap_local_page()/kunmap_local().
 *
 * NOTE: ext2_find_entry() and ext2_dotdot() act as a call to ext2_get_page()
 * and should be treated as a call to ext2_get_page() for nesting purposes.
 */
static struct page *
ext2_get_page(struct inode *dir, unsigned long n, int quiet, void **page_addr)
{
    struct address_space *mapping = dir->i_mapping;
    struct page *page = read_mapping_page(mapping, n, NULL);
    if (!IS_ERR(page)) {
        *page_addr = kmap_local_page(page);
        if (unlikely(!PageChecked(page))) {
            if (PageError(page) || !ext2_check_page(page, quiet, *page_addr))
                goto fail;
        }
    }
    return page;

fail:
    ext2_put_page(page, *page_addr);
    return ERR_PTR(-EIO);
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
ext2_last_byte(struct inode *inode, unsigned long page_nr)
{
    unsigned last_byte = inode->i_size;

    last_byte -= page_nr << PAGE_SHIFT;
    if (last_byte > PAGE_SIZE)
        last_byte = PAGE_SIZE;
    return last_byte;
}

/*
 * NOTE! unlike strncmp, ext2_match returns 1 for success, 0 for failure.
 *
 * len <= EXT2_NAME_LEN and de != NULL are guaranteed by caller.
 */
static inline int ext2_match(int len, const char * const name,
                             struct ext2_dir_entry_2 *de)
{
    if (len != de->name_len)
        return 0;
    if (!de->inode)
        return 0;
    return !memcmp(name, de->name, len);
}

/*
 * p is at least 6 bytes before the end of page
 */
static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
    return (ext2_dirent *)((char *)p + ext2_rec_len_from_disk(p->rec_len));
}

/*
 *  ext2_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found (as a parameter - res_page),
 * and the entry itself. Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 *
 * On Success ext2_put_page() should be called on *res_page.
 *
 * NOTE: Calls to ext2_get_page()/ext2_put_page() must be nested according to
 * the rules documented in kmap_local_page()/kunmap_local().
 *
 * ext2_find_entry() and ext2_dotdot() act as a call to ext2_get_page() and
 * should be treated as a call to ext2_get_page() for nesting purposes.
 */
struct ext2_dir_entry_2 *
ext2_find_entry(struct inode *dir, const struct qstr *child,
                struct page **res_page, void **res_page_addr)
{
    const char *name = child->name;
    int namelen = child->len;
    unsigned reclen = EXT2_DIR_REC_LEN(namelen);
    unsigned long start, n;
    unsigned long npages = dir_pages(dir);
    struct page *page = NULL;
    struct ext2_inode_info *ei = EXT2_I(dir);
    ext2_dirent *de;
    void *page_addr;

    if (npages == 0)
        goto out;

    /* OFFSET_CACHE */
    *res_page = NULL;
    *res_page_addr = NULL;

    start = ei->i_dir_start_lookup;
    if (start >= npages)
        start = 0;
    n = start;
    do {
        char *kaddr;
        page = ext2_get_page(dir, n, 0, &page_addr);
        if (IS_ERR(page))
            return ERR_CAST(page);

        kaddr = page_addr;
        de = (ext2_dirent *) kaddr;
        kaddr += ext2_last_byte(dir, n) - reclen;
        while ((char *) de <= kaddr) {
            if (de->rec_len == 0) {
                ext2_error(dir->i_sb, __func__, "zero-length directory entry");
                ext2_put_page(page, page_addr);
                goto out;
            }
            if (ext2_match(namelen, name, de))
                goto found;
            de = ext2_next_entry(de);
        }
        ext2_put_page(page, page_addr);

        if (++n >= npages)
            n = 0;
        /* next page is past the blocks we've got */
        if (unlikely(n > (dir->i_blocks >> (PAGE_SHIFT - 9)))) {
            ext2_error(dir->i_sb, __func__,
                       "dir %lu size %lld exceeds block count %llu",
                       dir->i_ino, dir->i_size,
                       (unsigned long long)dir->i_blocks);
            goto out;
        }
    } while (n != start);
 out:
    return ERR_PTR(-ENOENT);

 found:
    *res_page = page;
    *res_page_addr = page_addr;
    ei->i_dir_start_lookup = n;
    return de;
}

int ext2_inode_by_name(struct inode *dir, const struct qstr *child, ino_t *ino)
{
    struct ext2_dir_entry_2 *de;
    struct page *page;
    void *page_addr;

    de = ext2_find_entry(dir, child, &page, &page_addr);
    if (IS_ERR(de))
        return PTR_ERR(de);

    *ino = le32_to_cpu(de->inode);
    ext2_put_page(page, page_addr);
    return 0;
}
