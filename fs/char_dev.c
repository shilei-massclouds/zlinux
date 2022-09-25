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

#define CHRDEV_MAJOR_HASH_SIZE 255

static struct char_device_struct {
    struct char_device_struct *next;
    unsigned int major;
    unsigned int baseminor;
    int minorct;
    char name[64];
    struct cdev *cdev;      /* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

/* index in the above */
static inline int major_to_index(unsigned major)
{
    return major % CHRDEV_MAJOR_HASH_SIZE;
}

static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

static DEFINE_SPINLOCK(cdev_lock);

static int find_dynamic_major(void)
{
    int i;
    struct char_device_struct *cd;

    for (i = ARRAY_SIZE(chrdevs)-1; i >= CHRDEV_MAJOR_DYN_END; i--) {
        if (chrdevs[i] == NULL)
            return i;
    }

    for (i = CHRDEV_MAJOR_DYN_EXT_START;
         i >= CHRDEV_MAJOR_DYN_EXT_END; i--) {
        for (cd = chrdevs[major_to_index(i)]; cd; cd = cd->next)
            if (cd->major == i)
                break;

        if (cd == NULL)
            return i;
    }

    return -EBUSY;
}

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

/**
 * unregister_chrdev_region() - unregister a range of device numbers
 * @from: the first in the range of numbers to unregister
 * @count: the number of device numbers to unregister
 *
 * This function will unregister a range of @count device numbers,
 * starting with @from.  The caller should normally be the one who
 * allocated those numbers in the first place...
 */
void unregister_chrdev_region(dev_t from, unsigned count)
{
    panic("%s: END!\n", __func__);
}

static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor,
                           int minorct)
{
    panic("%s: END!\n", __func__);
}

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this function will dynamically allocate an unused major.
 * If major > 0 this function will attempt to reserve the range of minors
 * with given major.
 *
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
                         int minorct, const char *name)
{
    struct char_device_struct *cd, *curr, *prev = NULL;
    int ret;
    int i;

    if (major >= CHRDEV_MAJOR_MAX) {
        pr_err("CHRDEV \"%s\" major requested (%u) is greater than "
               "the maximum (%u)\n",
               name, major, CHRDEV_MAJOR_MAX-1);
        return ERR_PTR(-EINVAL);
    }

    if (minorct > MINORMASK + 1 - baseminor) {
        pr_err("CHRDEV \"%s\" minor range requested (%u-%u) is out of "
               "range of maximum range (%u-%u) for a single major\n",
               name, baseminor, baseminor + minorct - 1, 0, MINORMASK);
        return ERR_PTR(-EINVAL);
    }

    cd = kzalloc(sizeof(struct char_device_struct), GFP_KERNEL);
    if (cd == NULL)
        return ERR_PTR(-ENOMEM);

    mutex_lock(&chrdevs_lock);

    if (major == 0) {
        ret = find_dynamic_major();
        if (ret < 0) {
            pr_err("CHRDEV \"%s\" dynamic allocation region is full\n",
                   name);
            goto out;
        }
        major = ret;
    }

    ret = -EBUSY;
    i = major_to_index(major);
    for (curr = chrdevs[i]; curr; prev = curr, curr = curr->next) {
        if (curr->major < major)
            continue;

        if (curr->major > major)
            break;

        if (curr->baseminor + curr->minorct <= baseminor)
            continue;

        if (curr->baseminor >= baseminor + minorct)
            break;

        goto out;
    }

    cd->major = major;
    cd->baseminor = baseminor;
    cd->minorct = minorct;
    strlcpy(cd->name, name, sizeof(cd->name));

    if (!prev) {
        cd->next = curr;
        chrdevs[i] = cd;
    } else {
        cd->next = prev->next;
        prev->next = cd;
    }

    mutex_unlock(&chrdevs_lock);
    return cd;

 out:
    mutex_unlock(&chrdevs_lock);
    kfree(cd);
    return ERR_PTR(ret);
}

/**
 * register_chrdev_region() - register a range of device numbers
 * @from: the first in the desired range of device numbers; must include
 *        the major number.
 * @count: the number of consecutive device numbers required
 * @name: the name of the device or driver.
 *
 * Return value is zero on success, a negative error code on failure.
 */
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
    struct char_device_struct *cd;
    dev_t to = from + count;
    dev_t n, next;

    for (n = from; n < to; n = next) {
        next = MKDEV(MAJOR(n)+1, 0);
        if (next > to)
            next = to;
        cd = __register_chrdev_region(MAJOR(n), MINOR(n),
                                      next - n, name);
        if (IS_ERR(cd))
            goto fail;
    }
    return 0;

 fail:
    to = n;
    for (n = from; n < to; n = next) {
        next = MKDEV(MAJOR(n)+1, 0);
        kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
    }
    return PTR_ERR(cd);
}

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

static void cdev_dynamic_release(struct kobject *kobj)
{
#if 0
    struct cdev *p = container_of(kobj, struct cdev, kobj);
    struct kobject *parent = kobj->parent;

    cdev_purge(p);
    kfree(p);
    kobject_put(parent);
#endif
    panic("%s: END!\n", __func__);
}

static struct kobj_type ktype_cdev_dynamic = {
    .release    = cdev_dynamic_release,
};

/**
 * cdev_alloc() - allocate a cdev structure
 *
 * Allocates and returns a cdev structure, or NULL on failure.
 */
struct cdev *cdev_alloc(void)
{
    struct cdev *p = kzalloc(sizeof(struct cdev), GFP_KERNEL);
    if (p) {
        INIT_LIST_HEAD(&p->list);
        kobject_init(&p->kobj, &ktype_cdev_dynamic);
    }
    return p;
}

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
    struct cdev *p = data;
    return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
    struct cdev *p = data;
    return cdev_get(p) ? 0 : -1;
}

/**
 * cdev_add() - add a char device to the system
 * @p: the cdev structure for the device
 * @dev: the first device number for which this device is responsible
 * @count: the number of consecutive minor numbers corresponding to this
 *         device
 *
 * cdev_add() adds the device represented by @p to the system, making it
 * live immediately.  A negative error code is returned on failure.
 */
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
    int error;

    p->dev = dev;
    p->count = count;

    if (WARN_ON(dev == WHITEOUT_DEV))
        return -EBUSY;

    error = kobj_map(cdev_map, dev, count, NULL,
                     exact_match, exact_lock, p);
    if (error)
        return error;

    kobject_get(p->kobj.parent);

    return 0;
}
