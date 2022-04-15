/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MODULE_PARAMS_H
#define _LINUX_MODULE_PARAMS_H
/* (C) Copyright 2001, 2002 Rusty Russell IBM Corporation */

#include <linux/init.h>
#include <linux/kernel.h>

struct kernel_param;

struct kernel_param_ops {
    /* How the ops should behave */
    unsigned int flags;
    /* Returns 0, or -errno.  arg is in kp->arg. */
    int (*set)(const char *val, const struct kernel_param *kp);
    /* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
    int (*get)(char *buffer, const struct kernel_param *kp);
    /* Optional function to free kp->arg when module unloaded. */
    void (*free)(void *arg);
};

struct kernel_param {
    const char *name;
    struct module *mod;
    const struct kernel_param_ops *ops;
    const u16 perm;
    s8 level;
    u8 flags;
    union {
        void *arg;
        const struct kparam_string *str;
        const struct kparam_array *arr;
    };
};

/**
 * parameq - checks if two parameter names match
 * @name1: parameter name 1
 * @name2: parameter name 2
 *
 * Returns true if the two parameter names are equal.
 * Dashes (-) are considered equal to underscores (_).
 */
extern bool parameq(const char *name1, const char *name2);

/**
 * parameqn - checks if two parameter names match
 * @name1: parameter name 1
 * @name2: parameter name 2
 * @n: the length to compare
 *
 * Similar to parameq(), except it compares @n characters.
 */
extern bool parameqn(const char *name1, const char *name2, size_t n);

/* Called on module insert or kernel boot */
extern char *
parse_args(const char *name,
           char *args,
           const struct kernel_param *params,
           unsigned num,
           s16 level_min,
           s16 level_max,
           void *arg,
           int (*unknown)(char *param, char *val,
                          const char *doing, void *arg));

#endif /* _LINUX_MODULE_PARAMS_H */
