// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
//#include <linux/seq_file.h>

#include <linux/kobject.h>
#if 0
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#endif
#include <linux/mutex.h>
#include <linux/backing-dev.h>
//#include <linux/tty.h>

#include "internal.h"

/*
 * Called every time a character special file is opened
 */
static int chrdev_open(struct inode *inode, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
const struct file_operations def_chr_fops = {
    .open = chrdev_open,
    .llseek = noop_llseek,
};
