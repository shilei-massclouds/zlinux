/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UIDGID_H
#define _LINUX_UIDGID_H

/*
 * A set of types for the internal kernel types representing uids and gids.
 *
 * The types defined in this header allow distinguishing which uids and gids in
 * the kernel are values used by userspace and which uid and gid values are
 * the internal kernel values.  With the addition of user namespaces the values
 * can be different.  Using the type system makes it possible for the compiler
 * to detect when we overlook these differences.
 *
 */
#include <linux/types.h>
#if 0
#include <linux/highuid.h>
#endif

typedef struct {
    uid_t val;
} kuid_t;

typedef struct {
    gid_t val;
} kgid_t;

#define KUIDT_INIT(value) (kuid_t){ value }
#define KGIDT_INIT(value) (kgid_t){ value }

#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define GLOBAL_ROOT_GID KGIDT_INIT(0)

extern kuid_t make_kuid(struct user_namespace *from, uid_t uid);
extern kgid_t make_kgid(struct user_namespace *from, gid_t gid);

extern uid_t from_kuid(struct user_namespace *to, kuid_t uid);
extern gid_t from_kgid(struct user_namespace *to, kgid_t gid);
extern uid_t from_kuid_munged(struct user_namespace *to, kuid_t uid);
extern gid_t from_kgid_munged(struct user_namespace *to, kgid_t gid);

static inline uid_t __kuid_val(kuid_t uid)
{
    return uid.val;
}

static inline gid_t __kgid_val(kgid_t gid)
{
    return gid.val;
}

static inline
bool kuid_has_mapping(struct user_namespace *ns, kuid_t uid)
{
    return from_kuid(ns, uid) != (uid_t) -1;
}

static inline
bool kgid_has_mapping(struct user_namespace *ns, kgid_t gid)
{
    return from_kgid(ns, gid) != (gid_t) -1;
}

static inline bool uid_eq(kuid_t left, kuid_t right)
{
    return __kuid_val(left) == __kuid_val(right);
}

static inline bool uid_valid(kuid_t uid)
{
    return __kuid_val(uid) != (uid_t) -1;
}

static inline bool gid_valid(kgid_t gid)
{
    return __kgid_val(gid) != (gid_t) -1;
}

#endif /* _LINUX_UIDGID_H */
