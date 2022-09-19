/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MNT_IDMAPPING_H
#define _LINUX_MNT_IDMAPPING_H

#include <linux/types.h>
#include <linux/uidgid.h>

struct user_namespace;
/*
 * Carries the initial idmapping of 0:0:4294967295 which is an identity
 * mapping. This means that {g,u}id 0 is mapped to {g,u}id 0, {g,u}id 1 is
 * mapped to {g,u}id 1, [...], {g,u}id 1000 to {g,u}id 1000, [...].
 */
extern struct user_namespace init_user_ns;

/**
 * initial_idmapping - check whether this is the initial mapping
 * @ns: idmapping to check
 *
 * Check whether this is the initial mapping, mapping 0 to 0, 1 to 1,
 * [...], 1000 to 1000 [...].
 *
 * Return: true if this is the initial mapping, false if not.
 */
static inline bool initial_idmapping(const struct user_namespace *ns)
{
    return ns == &init_user_ns;
}

/**
 * no_idmapping - check whether we can skip remapping a kuid/gid
 * @mnt_userns: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 *
 * This function can be used to check whether a remapping between two
 * idmappings is required.
 * An idmapped mount is a mount that has an idmapping attached to it that
 * is different from the filsystem's idmapping and the initial idmapping.
 * If the initial mapping is used or the idmapping of the mount and the
 * filesystem are identical no remapping is required.
 *
 * Return: true if remapping can be skipped, false if not.
 */
static inline
bool no_idmapping(const struct user_namespace *mnt_userns,
                  const struct user_namespace *fs_userns)
{
    return initial_idmapping(mnt_userns) || mnt_userns == fs_userns;
}

/**
 * mapped_kuid_fs - map a filesystem kuid into a mnt_userns
 * @mnt_userns: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @kuid : kuid to be mapped
 *
 * Take a @kuid and remap it from @fs_userns into @mnt_userns. Use this
 * function when preparing a @kuid to be reported to userspace.
 *
 * If no_idmapping() determines that this is not an idmapped mount we can
 * simply return @kuid unchanged.
 * If initial_idmapping() tells us that the filesystem is not mounted with an
 * idmapping we know the value of @kuid won't change when calling
 * from_kuid() so we can simply retrieve the value via __kuid_val()
 * directly.
 *
 * Return: @kuid mapped according to @mnt_userns.
 * If @kuid has no mapping in either @mnt_userns or @fs_userns INVALID_UID is
 * returned.
 */
static inline
kuid_t mapped_kuid_fs(struct user_namespace *mnt_userns,
                      struct user_namespace *fs_userns,
                      kuid_t kuid)
{
    uid_t uid;

    if (no_idmapping(mnt_userns, fs_userns))
        return kuid;

    panic("%s: END!\n", __func__);
}

/**
 * mapped_kgid_fs - map a filesystem kgid into a mnt_userns
 * @mnt_userns: the mount's idmapping
 * @fs_userns: the filesystem's idmapping
 * @kgid : kgid to be mapped
 *
 * Take a @kgid and remap it from @fs_userns into @mnt_userns. Use this
 * function when preparing a @kgid to be reported to userspace.
 *
 * If no_idmapping() determines that this is not an idmapped mount we can
 * simply return @kgid unchanged.
 * If initial_idmapping() tells us that the filesystem is not mounted with an
 * idmapping we know the value of @kgid won't change when calling
 * from_kgid() so we can simply retrieve the value via __kgid_val()
 * directly.
 *
 * Return: @kgid mapped according to @mnt_userns.
 * If @kgid has no mapping in either @mnt_userns or @fs_userns INVALID_GID is
 * returned.
 */
static inline
kgid_t mapped_kgid_fs(struct user_namespace *mnt_userns,
                      struct user_namespace *fs_userns,
                      kgid_t kgid)
{
    gid_t gid;

    if (no_idmapping(mnt_userns, fs_userns))
        return kgid;

    panic("%s: END!\n", __func__);
}

#endif /* _LINUX_MNT_IDMAPPING_H */
