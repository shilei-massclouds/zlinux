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

static void kset_release(struct kobject *kobj)
{
    struct kset *kset = container_of(kobj, struct kset, kobj);
    pr_debug("kobject: '%s' (%p): %s\n",
             kobject_name(kobj), kobj, __func__);
    kfree(kset);
}

static struct kobj_type kset_ktype = {
    //.sysfs_ops  = &kobj_sysfs_ops,
    .release    = kset_release,
    //.get_ownership  = kset_get_ownership,
};

static void kobject_init_internal(struct kobject *kobj)
{
    if (!kobj)
        return;
    kref_init(&kobj->kref);
    INIT_LIST_HEAD(&kobj->entry);
    kobj->state_in_sysfs = 0;
    kobj->state_add_uevent_sent = 0;
    kobj->state_remove_uevent_sent = 0;
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

/**
 * kobject_init() - Initialize a kobject structure.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 *
 * This function will properly initialize a kobject such that it can then
 * be passed to the kobject_add() call.
 *
 * After this function is called, the kobject MUST be cleaned up by a call
 * to kobject_put(), not by a call to kfree directly to ensure that all of
 * the memory is cleaned up properly.
 */
void kobject_init(struct kobject *kobj, const struct kobj_type *ktype)
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

static void __kobject_del(struct kobject *kobj)
{
    panic("%s: NO implementation!\n", __func__);
}

/**
 * kobject_del() - Unlink kobject from hierarchy.
 * @kobj: object.
 *
 * This is the function that should be called to delete an object
 * successfully added via kobject_add().
 */
void kobject_del(struct kobject *kobj)
{
    struct kobject *parent;

    if (!kobj)
        return;

    parent = kobj->parent;
    __kobject_del(kobj);
    kobject_put(parent);
}
EXPORT_SYMBOL(kobject_del);

/**
 * kobject_get() - Increment refcount for object.
 * @kobj: object.
 */
struct kobject *kobject_get(struct kobject *kobj)
{
    if (kobj) {
        if (!kobj->state_initialized)
            WARN(1, KERN_WARNING
                "kobject: '%s' (%p): is not initialized, yet kobject_get() is being called.\n",
                 kobject_name(kobj), kobj);
        kref_get(&kobj->kref);
    }
    return kobj;
}
EXPORT_SYMBOL(kobject_get);

/*
 * kobject_cleanup - free kobject resources.
 * @kobj: object to cleanup
 */
static void kobject_cleanup(struct kobject *kobj)
{
    struct kobject *parent = kobj->parent;
    const struct kobj_type *t = get_ktype(kobj);
    const char *name = kobj->name;

    pr_info("kobject: '%s' (%p): %s, parent %p\n",
            kobject_name(kobj), kobj, __func__, kobj->parent);

    if (t && !t->release)
        pr_warn("kobject: '%s' (%p): does not have a release() function, "
                "it is broken and must be fixed. "
                "See Documentation/core-api/kobject.rst.\n",
                kobject_name(kobj), kobj);

    /* remove from sysfs if the caller did not do it */
    if (kobj->state_in_sysfs) {
        pr_debug("kobject: '%s' (%p): auto cleanup kobject_del\n",
                 kobject_name(kobj), kobj);
        __kobject_del(kobj);
    } else {
        /* avoid dropping the parent reference unnecessarily */
        parent = NULL;
    }

    if (t && t->release) {
        pr_info("kobject: '%s' (%p): calling ktype release\n",
                kobject_name(kobj), kobj);
        t->release(kobj);
    }

    /* free name if we allocated it */
    if (name) {
        pr_debug("kobject: '%s': free name\n", name);
        kfree_const(name);
    }

    kobject_put(parent);
}

static void kobject_release(struct kref *kref)
{
    struct kobject *kobj = container_of(kref, struct kobject, kref);
    kobject_cleanup(kobj);
}

/**
 * kobject_put() - Decrement refcount for object.
 * @kobj: object.
 *
 * Decrement the refcount, and if 0, call kobject_cleanup().
 */
void kobject_put(struct kobject *kobj)
{
    if (kobj) {
        if (!kobj->state_initialized)
            WARN(1, KERN_WARNING
                "kobject: '%s' (%p): is not initialized, "
                "yet kobject_put() is being called.\n",
                 kobject_name(kobj), kobj);
        kref_put(&kobj->kref, kobject_release);
    }
}
EXPORT_SYMBOL(kobject_put);

/* add the kobject to its kset's list */
static void kobj_kset_join(struct kobject *kobj)
{
    if (!kobj->kset)
        return;

    kset_get(kobj->kset);
    spin_lock(&kobj->kset->list_lock);
    list_add_tail(&kobj->entry, &kobj->kset->list);
    spin_unlock(&kobj->kset->list_lock);
}

static int create_dir(struct kobject *kobj)
{
    pr_warn("%s: NO implementation!\n", __func__);
    return 0;
}

static int kobject_add_internal(struct kobject *kobj)
{
    int error = 0;
    struct kobject *parent;

    if (!kobj)
        return -ENOENT;

    if (!kobj->name || !kobj->name[0]) {
        WARN(1, "kobject: (%p): attempted to be registered with empty name!\n",
             kobj);
        return -EINVAL;
    }

    parent = kobject_get(kobj->parent);

    /* join kset if set, use it as parent if we do not already have one */
    if (kobj->kset) {
        if (!parent)
            parent = kobject_get(&kobj->kset->kobj);
        kobj_kset_join(kobj);
        kobj->parent = parent;
    }

    pr_debug("kobject: '%s' (%p): %s: parent: '%s', set: '%s'\n",
             kobject_name(kobj), kobj, __func__,
             parent ? kobject_name(parent) : "<NULL>",
             kobj->kset ? kobject_name(&kobj->kset->kobj) : "<NULL>");

    error = create_dir(kobj);
    if (error) {
        panic("%s: create_dir error!\n", __func__);
#if 0
        kobj_kset_leave(kobj);
        kobject_put(parent);
        kobj->parent = NULL;

        /* be noisy on error issues */
        if (error == -EEXIST)
            pr_err("%s failed for %s with -EEXIST, don't try to register things with the same name in the same directory.\n",
                   __func__, kobject_name(kobj));
        else
            pr_err("%s failed for %s (error: %d parent: %s)\n",
                   __func__, kobject_name(kobj), error,
                   parent ? kobject_name(parent) : "'none'");
#endif
    } else
        kobj->state_in_sysfs = 1;

    return error;
}

static __printf(3, 0)
int kobject_add_varg(struct kobject *kobj,
                     struct kobject *parent,
                     const char *fmt, va_list vargs)
{
    int retval;

    retval = kobject_set_name_vargs(kobj, fmt, vargs);
    if (retval) {
        pr_err("kobject: can not set name properly!\n");
        return retval;
    }
    kobj->parent = parent;
    return kobject_add_internal(kobj);
}

/**
 * kobject_add() - The main kobject add function.
 * @kobj: the kobject to add
 * @parent: pointer to the parent of the kobject.
 * @fmt: format to name the kobject with.
 *
 * The kobject name is set and added to the kobject hierarchy in this
 * function.
 *
 * If @parent is set, then the parent of the @kobj will be set to it.
 * If @parent is NULL, then the parent of the @kobj will be set to the
 * kobject associated with the kset assigned to this kobject.  If no kset
 * is assigned to the kobject, then the kobject will be located in the
 * root of the sysfs tree.
 *
 * Note, no "add" uevent will be created with this call, the caller should set
 * up all of the necessary sysfs files for the object and then call
 * kobject_uevent() with the UEVENT_ADD parameter to ensure that
 * userspace is properly notified of this kobject's creation.
 *
 * Return: If this function returns an error, kobject_put() must be
 *         called to properly clean up the memory associated with the
 *         object.  Under no instance should the kobject that is passed
 *         to this function be directly freed with a call to kfree(),
 *         that can leak memory.
 *
 *         If this function returns success, kobject_put() must also be called
 *         in order to properly clean up the memory associated with the object.
 *
 *         In short, once this function is called, kobject_put() MUST be called
 *         when the use of the object is finished in order to properly free
 *         everything.
 */
int kobject_add(struct kobject *kobj, struct kobject *parent,
                const char *fmt, ...)
{
    va_list args;
    int retval;

    if (!kobj)
        return -EINVAL;

    if (!kobj->state_initialized) {
        pr_err("kobject '%s' (%p): tried to add an uninitialized object, "
               "something is seriously wrong.\n",
               kobject_name(kobj), kobj);
        //dump_stack();
        return -EINVAL;
    }
    va_start(args, fmt);
    retval = kobject_add_varg(kobj, parent, fmt, args);
    va_end(args);

    return retval;
}
EXPORT_SYMBOL(kobject_add);

/**
 * kobject_set_name() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 *
 * This sets the name of the kobject.  If you have already added the
 * kobject to the system, you must call kobject_rename() in order to
 * change the name of the kobject.
 */
int kobject_set_name(struct kobject *kobj, const char *fmt, ...)
{
    va_list vargs;
    int retval;

    va_start(vargs, fmt);
    retval = kobject_set_name_vargs(kobj, fmt, vargs);
    va_end(vargs);

    return retval;
}
EXPORT_SYMBOL(kobject_set_name);

/**
 * kset_create() - Create a struct kset dynamically.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically.  This structure can
 * then be registered with the system and show up in sysfs with a call to
 * kset_register().  When you are finished with this structure, if
 * kset_register() has been called, call kset_unregister() and the
 * structure will be dynamically freed when it is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
static struct kset *kset_create(const char *name,
                                const struct kset_uevent_ops *uevent_ops,
                                struct kobject *parent_kobj)
{
    struct kset *kset;
    int retval;

    kset = kzalloc(sizeof(*kset), GFP_KERNEL);
    if (!kset)
        return NULL;
    retval = kobject_set_name(&kset->kobj, "%s", name);
    if (retval) {
        kfree(kset);
        return NULL;
    }
    kset->uevent_ops = uevent_ops;
    kset->kobj.parent = parent_kobj;

    /*
     * The kobject of this kset will have a type of kset_ktype and belong to
     * no kset itself.  That way we can properly free it when it is
     * finished being used.
     */
    kset->kobj.ktype = &kset_ktype;
    kset->kobj.kset = NULL;

    return kset;
}

/**
 * kset_create_and_add() - Create a struct kset dynamically and add it to sysfs.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kset_unregister() and the structure will be dynamically freed when it
 * is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
struct kset *kset_create_and_add(const char *name,
                                 const struct kset_uevent_ops *uevent_ops,
                                 struct kobject *parent_kobj)
{
    struct kset *kset;
    int error;

    kset = kset_create(name, uevent_ops, parent_kobj);
    if (!kset)
        return NULL;
    error = kset_register(kset);
    if (error) {
        kfree(kset);
        return NULL;
    }
    return kset;
}
EXPORT_SYMBOL_GPL(kset_create_and_add);

static void dynamic_kobj_release(struct kobject *kobj)
{
    pr_debug("kobject: (%p): %s\n", kobj, __func__);
    kfree(kobj);
}

static struct kobj_type dynamic_kobj_ktype = {
    .release    = dynamic_kobj_release,
    //.sysfs_ops  = &kobj_sysfs_ops,
};

/**
 * kobject_create() - Create a struct kobject dynamically.
 *
 * This function creates a kobject structure dynamically and sets it up
 * to be a "dynamic" kobject with a default release function set up.
 *
 * If the kobject was not able to be created, NULL will be returned.
 * The kobject structure returned from here must be cleaned up with a
 * call to kobject_put() and not kfree(), as kobject_init() has
 * already been called on this structure.
 */
static struct kobject *kobject_create(void)
{
    struct kobject *kobj;

    kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
    if (!kobj)
        return NULL;

    kobject_init(kobj, &dynamic_kobj_ktype);
    return kobj;
}

/**
 * kobject_create_and_add() - Create a struct kobject dynamically and
 *                            register it with sysfs.
 * @name: the name for the kobject
 * @parent: the parent kobject of this kobject, if any.
 *
 * This function creates a kobject structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kobject_put() and the structure will be dynamically freed when
 * it is no longer being used.
 *
 * If the kobject was not able to be created, NULL will be returned.
 */
struct kobject *kobject_create_and_add(const char *name, struct kobject *parent)
{
    struct kobject *kobj;
    int retval;

    kobj = kobject_create();
    if (!kobj)
        return NULL;

    retval = kobject_add(kobj, parent, "%s", name);
    if (retval) {
        pr_warn("%s: kobject_add error: %d\n", __func__, retval);
        kobject_put(kobj);
        kobj = NULL;
    }
    return kobj;
}
EXPORT_SYMBOL_GPL(kobject_create_and_add);

/**
 * kset_init() - Initialize a kset for use.
 * @k: kset
 */
void kset_init(struct kset *k)
{
    kobject_init_internal(&k->kobj);
    INIT_LIST_HEAD(&k->list);
    spin_lock_init(&k->list_lock);
}

/**
 * kset_register() - Initialize and add a kset.
 * @k: kset.
 */
int kset_register(struct kset *k)
{
    int err;

    if (!k)
        return -EINVAL;

    kset_init(k);
    err = kobject_add_internal(&k->kobj);
    if (err)
        return err;
    //kobject_uevent(&k->kobj, KOBJ_ADD);
    return 0;
}
EXPORT_SYMBOL(kset_register);

/**
 * kset_unregister() - Remove a kset.
 * @k: kset.
 */
void kset_unregister(struct kset *k)
{
    if (!k)
        return;
    kobject_del(&k->kobj);
    kobject_put(&k->kobj);
}
EXPORT_SYMBOL(kset_unregister);

struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj)
{
    if (!kobj)
        return NULL;
    if (!kref_get_unless_zero(&kobj->kref))
        kobj = NULL;
    return kobj;
}
EXPORT_SYMBOL(kobject_get_unless_zero);

/**
 * kset_find_obj() - Search for object in kset.
 * @kset: kset we're looking in.
 * @name: object's name.
 *
 * Lock kset via @kset->subsys, and iterate over @kset->list,
 * looking for a matching kobject. If matching object is found
 * take a reference and return the object.
 */
struct kobject *kset_find_obj(struct kset *kset, const char *name)
{
    struct kobject *k;
    struct kobject *ret = NULL;

    spin_lock(&kset->list_lock);

    list_for_each_entry(k, &kset->list, entry) {
        if (kobject_name(k) && !strcmp(kobject_name(k), name)) {
            ret = kobject_get_unless_zero(k);
            break;
        }
    }

    spin_unlock(&kset->list_lock);
    return ret;
}
EXPORT_SYMBOL_GPL(kset_find_obj);

/**
 * kobject_init_and_add() - Initialize a kobject structure and add it to
 *                          the kobject hierarchy.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 * @parent: pointer to the parent of this kobject.
 * @fmt: the name of the kobject.
 *
 * This function combines the call to kobject_init() and kobject_add().
 *
 * If this function returns an error, kobject_put() must be called to
 * properly clean up the memory associated with the object.  This is the
 * same type of error handling after a call to kobject_add() and kobject
 * lifetime rules are the same here.
 */
int kobject_init_and_add(struct kobject *kobj, const struct kobj_type *ktype,
                         struct kobject *parent, const char *fmt, ...)
{
    va_list args;
    int retval;

    kobject_init(kobj, ktype);

    va_start(args, fmt);
    retval = kobject_add_varg(kobj, parent, fmt, args);
    va_end(args);

    return retval;
}
EXPORT_SYMBOL_GPL(kobject_init_and_add);
