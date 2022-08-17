// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/stat.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/file.h>
//#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/compat.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "internal.h"
#include "mount.h"

static int do_readlinkat(int dfd, const char __user *pathname,
                         char __user *buf, int bufsiz)
{
    struct path path;
    int error;
    int empty = 0;
    unsigned int lookup_flags = LOOKUP_EMPTY;

    printk("%s: pathname(%s) bufsiz(%d)\n", __func__, pathname, bufsiz);
    if (bufsiz <= 0)
        return -EINVAL;

 retry:
    error = user_path_at_empty(dfd, pathname, lookup_flags, &path, &empty);
    if (!error) {
        panic("%s: !error!\n", __func__);
    }
    return error;
}

SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
                char __user *, buf, int, bufsiz)
{
    return do_readlinkat(dfd, pathname, buf, bufsiz);
}
