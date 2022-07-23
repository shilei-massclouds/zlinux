// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/filesystems.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  table of configured filesystems
 */

#include <linux/fs.h>
#if 0
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
//#include <linux/fs_parser.h>

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);

/* WARNING: This can be used only if we _already_ own a reference */
struct file_system_type *get_filesystem(struct file_system_type *fs)
{
    __module_get(fs->owner);
    return fs;
}

void put_filesystem(struct file_system_type *fs)
{
    module_put(fs->owner);
}

static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
    struct file_system_type **p;
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strncmp((*p)->name, name, len) == 0 && !(*p)->name[len])
            break;
    return p;
}

/**
 *  register_filesystem - register a new filesystem
 *  @fs: the file system structure
 *
 *  Adds the file system passed to the list of file systems the kernel
 *  is aware of for mount and other syscalls. Returns 0 on success,
 *  or a negative errno code on an error.
 *
 *  The &struct file_system_type that is passed is linked into the kernel
 *  structures and must not be freed until the file system has been
 *  unregistered.
 */
int register_filesystem(struct file_system_type *fs)
{
    int res = 0;
    struct file_system_type ** p;

    BUG_ON(strchr(fs->name, '.'));
    if (fs->next)
        return -EBUSY;
    write_lock(&file_systems_lock);
    p = find_filesystem(fs->name, strlen(fs->name));
    if (*p)
        res = -EBUSY;
    else
        *p = fs;
    write_unlock(&file_systems_lock);
    return res;
}
EXPORT_SYMBOL(register_filesystem);

/**
 *  unregister_filesystem - unregister a file system
 *  @fs: filesystem to unregister
 *
 *  Remove a file system that was previously successfully registered
 *  with the kernel. An error is returned if the file system is not found.
 *  Zero is returned on a success.
 *
 *  Once this function has returned the &struct file_system_type structure
 *  may be freed or reused.
 */
int unregister_filesystem(struct file_system_type * fs)
{
    struct file_system_type ** tmp;

    write_lock(&file_systems_lock);
    tmp = &file_systems;
    while (*tmp) {
        if (fs == *tmp) {
            *tmp = fs->next;
            fs->next = NULL;
            write_unlock(&file_systems_lock);
            synchronize_rcu();
            return 0;
        }
        tmp = &(*tmp)->next;
    }
    write_unlock(&file_systems_lock);

    return -EINVAL;
}
EXPORT_SYMBOL(unregister_filesystem);

int __init list_bdev_fs_names(char *buf, size_t size)
{
    struct file_system_type *p;
    size_t len;
    int count = 0;

    read_lock(&file_systems_lock);
    for (p = file_systems; p; p = p->next) {
        if (!(p->fs_flags & FS_REQUIRES_DEV))
            continue;
        len = strlen(p->name) + 1;
        if (len > size) {
            pr_warn("%s: truncating file system list\n", __func__);
            break;
        }
        memcpy(buf, p->name, len);
        buf += len;
        size -= len;
        count++;
    }
    read_unlock(&file_systems_lock);
    return count;
}
