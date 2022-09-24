// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/drivers/base/map.c
 *
 * (C) Copyright Al Viro 2002,2003
 *
 * NOTE: data structure needs to be changed.  It works, but for large dev_t
 * it will be too slow.  It is isolated, though, so these changes will be
 * local to that file.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kdev_t.h>
#include <linux/kobject.h>
#include <linux/kobj_map.h>

struct kobj_map {
    struct probe {
        struct probe *next;
        dev_t dev;
        unsigned long range;
        struct module *owner;
        kobj_probe_t *get;
        int (*lock)(dev_t, void *);
        void *data;
    } *probes[255];
    struct mutex *lock;
};

struct kobject *
kobj_lookup(struct kobj_map *domain, dev_t dev, int *index)
{
    struct kobject *kobj;
    struct probe *p;
    unsigned long best = ~0UL;

retry:
    mutex_lock(domain->lock);
    for (p = domain->probes[MAJOR(dev) % 255]; p; p = p->next) {
        struct kobject *(*probe)(dev_t, int *, void *);
        struct module *owner;
        void *data;

        if (p->dev > dev || p->dev + p->range - 1 < dev)
            continue;
        if (p->range - 1 >= best)
            break;
        if (!try_module_get(p->owner))
            continue;
        owner = p->owner;
        data = p->data;
        probe = p->get;
        best = p->range - 1;
        *index = dev - p->dev;
        if (p->lock && p->lock(dev, data) < 0) {
            module_put(owner);
            continue;
        }
        mutex_unlock(domain->lock);
        kobj = probe(dev, index, data);
        /* Currently ->owner protects _only_ ->probe() itself. */
        module_put(owner);
        if (kobj)
            return kobj;
        goto retry;
    }
    mutex_unlock(domain->lock);
    return NULL;
}

struct kobj_map *
kobj_map_init(kobj_probe_t *base_probe, struct mutex *lock)
{
    struct kobj_map *p = kmalloc(sizeof(struct kobj_map), GFP_KERNEL);
    struct probe *base = kzalloc(sizeof(*base), GFP_KERNEL);
    int i;

    if ((p == NULL) || (base == NULL)) {
        kfree(p);
        kfree(base);
        return NULL;
    }

    base->dev = 1;
    base->range = ~0;
    base->get = base_probe;
    for (i = 0; i < 255; i++)
        p->probes[i] = base;
    p->lock = lock;
    return p;
}
