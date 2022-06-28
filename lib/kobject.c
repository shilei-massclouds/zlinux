// SPDX-License-Identifier: GPL-2.0
/*
 * kobject.c - library routines for handling generic kernel objects
 *
 * Copyright (c) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2006-2007 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2007 Novell Inc.
 *
 * Please see the file Documentation/core-api/kobject.rst for critical information
 * about using the kobject interface.
 */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/export.h>
//#include <linux/stat.h>
#include <linux/slab.h>
//#include <linux/random.h>

static void kobject_init_internal(struct kobject *kobj)
{
    if (!kobj)
        return;
    kref_init(&kobj->kref);
    INIT_LIST_HEAD(&kobj->entry);
    //kobj->state_in_sysfs = 0;
    //kobj->state_add_uevent_sent = 0;
    //kobj->state_remove_uevent_sent = 0;
    kobj->state_initialized = 1;
}

/**
 * kobject_set_name_vargs() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 * @vargs: vargs to format the string.
 */
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs)
{
    const char *s;

    if (kobj->name && !fmt)
        return 0;

    s = kvasprintf_const(GFP_KERNEL, fmt, vargs);
    if (!s)
        return -ENOMEM;

    /*
     * ewww... some of these buggers have '/' in the name ... If
     * that's the case, we need to make sure we have an actual
     * allocated copy to modify, since kvasprintf_const may have
     * returned something from .rodata.
     */
    if (strchr(s, '/')) {
        char *t;

        t = kstrdup(s, GFP_KERNEL);
        kfree_const(s);
        if (!t)
            return -ENOMEM;
        strreplace(t, '/', '!');
        s = t;
    }
    kfree_const(kobj->name);
    kobj->name = s;

    return 0;
}

void kobject_init(struct kobject *kobj, struct kobj_type *ktype)
{
    char *err_str;

    if (!kobj) {
        err_str = "invalid kobject pointer!";
        goto error;
    }
    if (!ktype) {
        err_str = "must have a ktype to be initialized properly!\n";
        goto error;
    }
    if (kobj->state_initialized) {
        /* do not error out as sometimes we can recover */
        pr_err("kobject (%p): tried to init an initialized object, something is seriously wrong.\n",
               kobj);
        //dump_stack();
    }

    kobject_init_internal(kobj);
    kobj->ktype = ktype;
    return;

error:
    pr_err("kobject (%p): %s\n", kobj, err_str);
    //dump_stack();
}
EXPORT_SYMBOL(kobject_init);
