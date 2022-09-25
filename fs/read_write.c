// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/read_write.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched/xacct.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#if 0
#include <linux/security.h>
#endif
#include <linux/export.h>
#include <linux/syscalls.h>
#if 0
#include <linux/splice.h>
#include <linux/compat.h>
#endif
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "internal.h"

#include <linux/uaccess.h>
//#include <asm/unistd.h>

static inline bool unsigned_offsets(struct file *file)
{
    return file->f_mode & FMODE_UNSIGNED_OFFSET;
}

/**
 * noop_llseek - No Operation Performed llseek implementation
 * @file:   file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 *
 * This is an implementation of ->llseek useable for the rare special case when
 * userspace expects the seek to succeed but the (device) file is actually not
 * able to perform the seek. In this case you use noop_llseek() instead of
 * falling back to the default implementation of ->llseek.
 */
loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
    return file->f_pos;
}
EXPORT_SYMBOL(noop_llseek);

/**
 * generic_file_llseek - generic llseek implementation for regular files
 * @file:   file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 *
 * This is a generic implemenation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
#if 0
    struct inode *inode = file->f_mapping->host;

    return generic_file_llseek_size(file, offset, whence,
                                    inode->i_sb->s_maxbytes,
                                    i_size_read(inode));
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(generic_file_llseek);

int rw_verify_area(int read_write, struct file *file,
                   const loff_t *ppos, size_t count)
{
    if (unlikely((ssize_t) count < 0))
        return -EINVAL;

    if (ppos) {
        loff_t pos = *ppos;

        if (unlikely(pos < 0)) {
            if (!unsigned_offsets(file))
                return -EINVAL;
            if (count >= -pos) /* both values are in 0..LLONG_MAX */
                return -EOVERFLOW;
        } else if (unlikely((loff_t) (pos + count) < 0)) {
            if (!unsigned_offsets(file))
                return -EINVAL;
        }
    }

    return 0;
}

static int warn_unsupported(struct file *file, const char *op)
{
    pr_warn_ratelimited("kernel %s not supported for file %pD4 "
                        "(pid: %d comm: %.20s)\n",
                        op, file, current->pid, current->comm);
    return -EINVAL;
}

ssize_t __kernel_read(struct file *file, void *buf, size_t count,
                      loff_t *pos)
{
    struct kvec iov = {
        .iov_base   = buf,
        .iov_len    = min_t(size_t, count, MAX_RW_COUNT),
    };
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    if (WARN_ON_ONCE(!(file->f_mode & FMODE_READ)))
        return -EINVAL;
    if (!(file->f_mode & FMODE_CAN_READ))
        return -EINVAL;
    /*
     * Also fail if ->read_iter and ->read are both wired up as that
     * implies very convoluted semantics.
     */
    if (unlikely(!file->f_op->read_iter || file->f_op->read))
        return warn_unsupported(file, "read");

    init_sync_kiocb(&kiocb, file);
    kiocb.ki_pos = pos ? *pos : 0;
    iov_iter_kvec(&iter, READ, &iov, 1, iov.iov_len);

    ret = file->f_op->read_iter(&kiocb, &iter);
    if (ret > 0) {
        if (pos)
            *pos = kiocb.ki_pos;
        //fsnotify_access(file);
    }
    return ret;
}

ssize_t kernel_read(struct file *file, void *buf, size_t count,
                    loff_t *pos)
{
    ssize_t ret;

    ret = rw_verify_area(READ, file, pos, count);
    if (ret)
        return ret;
    return __kernel_read(file, buf, count, pos);
}
EXPORT_SYMBOL(kernel_read);

/* file_ppos returns &file->f_pos or NULL if file is stream */
static inline loff_t *file_ppos(struct file *file)
{
    return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf,
                             size_t len, loff_t *ppos)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct kiocb kiocb;
    struct iov_iter iter;
    ssize_t ret;

    init_sync_kiocb(&kiocb, filp);
    kiocb.ki_pos = (ppos ? *ppos : 0);
    iov_iter_init(&iter, READ, &iov, 1, len);

    ret = call_read_iter(filp, &kiocb, &iter);
    BUG_ON(ret == -EIOCBQUEUED);
    if (ppos)
        *ppos = kiocb.ki_pos;
    return ret;
}

ssize_t vfs_read(struct file *file, char __user *buf, size_t count,
                 loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_READ))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_READ))
        return -EINVAL;
    if (unlikely(!access_ok(buf, count)))
        return -EFAULT;

    ret = rw_verify_area(READ, file, pos, count);
    if (ret)
        return ret;
    if (count > MAX_RW_COUNT)
        count =  MAX_RW_COUNT;

    if (file->f_op->read)
        ret = file->f_op->read(file, buf, count, pos);
    else if (file->f_op->read_iter)
        ret = new_sync_read(file, buf, count, pos);
    else
        ret = -EINVAL;
    if (ret > 0) {
        fsnotify_access(file);
        add_rchar(current, ret);
    }
    inc_syscr(current);
    return ret;
}

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);
    ssize_t ret = -EBADF;

    if (f.file) {
        loff_t pos, *ppos = file_ppos(f.file);
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }

        printk("%s: file(%s) pos(%llx) count(%x)\n",
               __func__, f.file->f_path.dentry->d_name.name,
               pos, count);

        ret = vfs_read(f.file, buf, count, ppos);
        if (ret >= 0 && ppos)
            f.file->f_pos = pos;
        fdput_pos(f);
    }
    return ret;
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf,
                size_t, count)
{
    printk("--------- %s: ...\n", __func__);
    return ksys_read(fd, buf, count);
}

ssize_t vfs_write(struct file *file, const char __user *buf,
                  size_t count, loff_t *pos)
{
    ssize_t ret;

    if (!(file->f_mode & FMODE_WRITE))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_WRITE))
        return -EINVAL;
    if (unlikely(!access_ok(buf, count)))
        return -EFAULT;

    panic("%s: END!\n", __func__);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf,
                   size_t count)
{
    struct fd f = fdget_pos(fd);
    ssize_t ret = -EBADF;

    if (f.file) {
        loff_t pos, *ppos = file_ppos(f.file);
        if (ppos) {
            pos = *ppos;
            ppos = &pos;
        }
        ret = vfs_write(f.file, buf, count, ppos);
        if (ret >= 0 && ppos)
            f.file->f_pos = pos;
        fdput_pos(f);
    }

    return ret;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
                size_t, count)
{
    printk("--------- %s: fd(%u) ...\n", __func__, fd);
    return ksys_write(fd, buf, count);
}

loff_t no_llseek(struct file *file, loff_t offset, int whence)
{
    return -ESPIPE;
}
EXPORT_SYMBOL(no_llseek);
