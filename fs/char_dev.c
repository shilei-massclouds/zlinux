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
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
//#include <linux/tty.h>

#include "internal.h"

static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
#if 0
    struct module *owner = p->owner;
    struct kobject *kobj;

    if (owner && !try_module_get(owner))
        return NULL;
    kobj = kobject_get_unless_zero(&p->kobj);
    if (!kobj)
        module_put(owner);
    return kobj;
#endif
    panic("%s: END!\n", __func__);
}

void cdev_put(struct cdev *p)
{
    if (p) {
        struct module *owner = p->owner;
        kobject_put(&p->kobj);
        module_put(owner);
    }
}

/*
 * Called every time a character special file is opened
 */
static int chrdev_open(struct inode *inode, struct file *filp)
{
    const struct file_operations *fops;
    struct cdev *p;
    struct cdev *new = NULL;
    int ret = 0;

    spin_lock(&cdev_lock);
    p = inode->i_cdev;
    if (!p) {
        struct kobject *kobj;
        int idx;
        spin_unlock(&cdev_lock);
        kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
        if (!kobj)
            return -ENXIO;
#if 0
        new = container_of(kobj, struct cdev, kobj);
        spin_lock(&cdev_lock);
        /* Check i_cdev again in case somebody beat us to it while
           we dropped the lock. */
        p = inode->i_cdev;
        if (!p) {
            inode->i_cdev = p = new;
            list_add(&inode->i_devices, &p->list);
            new = NULL;
        } else if (!cdev_get(p))
            ret = -ENXIO;
#endif
        panic("%s: !p\n", __func__);
    } else if (!cdev_get(p))
        ret = -ENXIO;

    spin_unlock(&cdev_lock);
    cdev_put(new);
    if (ret)
        return ret;

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

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
#if 0
    if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
        /* Make old-style 2.4 aliases work */
        request_module("char-major-%d", MAJOR(dev));
#endif
    return NULL;
}

void __init chrdev_init(void)
{
    cdev_map = kobj_map_init(base_probe, &chrdevs_lock);
}
