// SPDX-License-Identifier: GPL-2.0-only

#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/user_namespace.h>
#if 0
#include <linux/proc_ns.h>
#endif
#include <linux/highuid.h>
#include <linux/cred.h>
#if 0
#include <linux/securebits.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/seq_file.h>
#endif
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#if 0
#include <linux/projid.h>
#include <linux/fs_struct.h>
#include <linux/sort.h>
#endif
#include <linux/bsearch.h>

void __put_user_ns(struct user_namespace *ns)
{
    panic("%s: END!\n", __func__);
    schedule_work(&ns->work);
}
EXPORT_SYMBOL(__put_user_ns);

/**
 * map_id_range_down_base - Find idmap via binary search in static extent array.
 * Can only be called if number of mappings is equal or less than
 * UID_GID_MAP_MAX_BASE_EXTENTS.
 */
static struct uid_gid_extent *
map_id_range_down_base(unsigned extents, struct uid_gid_map *map,
                       u32 id, u32 count)
{
    unsigned idx;
    u32 first, last, id2;

    id2 = id + count - 1;

    /* Find the matching extent */
    for (idx = 0; idx < extents; idx++) {
        first = map->extent[idx].first;
        last = first + map->extent[idx].count - 1;
        if (id >= first && id <= last &&
            (id2 >= first && id2 <= last))
            return &map->extent[idx];
    }
    return NULL;
}

/**
 * idmap_key struct holds the information necessary to find an idmapping in a
 * sorted idmap array. It is passed to cmp_map_id() as first argument.
 */
struct idmap_key {
    bool map_up; /* true  -> id from kid; false -> kid from id */
    u32 id; /* id to find */
    u32 count; /* == 0 unless used with map_id_range_down() */
};

/**
 * cmp_map_id - Function to be passed to bsearch() to find the requested
 * idmapping. Expects struct idmap_key to be passed via @k.
 */
static int cmp_map_id(const void *k, const void *e)
{
    u32 first, last, id2;
    const struct idmap_key *key = k;
    const struct uid_gid_extent *el = e;

    id2 = key->id + key->count - 1;

    /* handle map_id_{down,up}() */
    if (key->map_up)
        first = el->lower_first;
    else
        first = el->first;

    last = first + el->count - 1;

    if (key->id >= first && key->id <= last &&
        (id2 >= first && id2 <= last))
        return 0;

    if (key->id < first || id2 < first)
        return -1;

    return 1;
}

/**
 * map_id_range_down_max - Find idmap via binary search in ordered idmap array.
 * Can only be called if number of mappings exceeds UID_GID_MAP_MAX_BASE_EXTENTS.
 */
static struct uid_gid_extent *
map_id_range_down_max(unsigned extents, struct uid_gid_map *map,
                      u32 id, u32 count)
{
    struct idmap_key key;

    key.map_up = false;
    key.count = count;
    key.id = id;

    return bsearch(&key, map->forward, extents,
                   sizeof(struct uid_gid_extent), cmp_map_id);
}

static u32 map_id_range_down(struct uid_gid_map *map, u32 id, u32 count)
{
    struct uid_gid_extent *extent;
    unsigned extents = map->nr_extents;
    smp_rmb();

    if (extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
        extent = map_id_range_down_base(extents, map, id, count);
    else
        extent = map_id_range_down_max(extents, map, id, count);

    /* Map the id or note failure */
    if (extent)
        id = (id - extent->first) + extent->lower_first;
    else
        id = (u32) -1;

    return id;
}

static u32 map_id_down(struct uid_gid_map *map, u32 id)
{
    return map_id_range_down(map, id, 1);
}

/**
 *  make_kuid - Map a user-namespace uid pair into a kuid.
 *  @ns:  User namespace that the uid is in
 *  @uid: User identifier
 *
 *  Maps a user-namespace uid pair into a kernel internal kuid,
 *  and returns that kuid.
 *
 *  When there is no mapping defined for the user-namespace uid
 *  pair INVALID_UID is returned.  Callers are expected to test
 *  for and handle INVALID_UID being returned.  INVALID_UID
 *  may be tested for using uid_valid().
 */
kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
    /* Map the uid to a global kernel uid */
    return KUIDT_INIT(map_id_down(&ns->uid_map, uid));
}
EXPORT_SYMBOL(make_kuid);

/**
 * map_id_up_max - Find idmap via binary search in ordered idmap array.
 * Can only be called if number of mappings exceeds UID_GID_MAP_MAX_BASE_EXTENTS.
 */
static struct uid_gid_extent *
map_id_up_max(unsigned extents, struct uid_gid_map *map, u32 id)
{
    struct idmap_key key;

    key.map_up = true;
    key.count = 1;
    key.id = id;

    return bsearch(&key, map->reverse, extents,
                   sizeof(struct uid_gid_extent), cmp_map_id);
}

/**
 * map_id_up_base - Find idmap via binary search in static extent array.
 * Can only be called if number of mappings is equal or less than
 * UID_GID_MAP_MAX_BASE_EXTENTS.
 */
static struct uid_gid_extent *
map_id_up_base(unsigned extents, struct uid_gid_map *map, u32 id)
{
    unsigned idx;
    u32 first, last;

    /* Find the matching extent */
    for (idx = 0; idx < extents; idx++) {
        first = map->extent[idx].lower_first;
        last = first + map->extent[idx].count - 1;
        if (id >= first && id <= last)
            return &map->extent[idx];
    }
    return NULL;
}

static u32 map_id_up(struct uid_gid_map *map, u32 id)
{
    struct uid_gid_extent *extent;
    unsigned extents = map->nr_extents;
    smp_rmb();

    if (extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
        extent = map_id_up_base(extents, map, id);
    else
        extent = map_id_up_max(extents, map, id);

    /* Map the id or note failure */
    if (extent)
        id = (id - extent->lower_first) + extent->first;
    else
        id = (u32) -1;

    return id;
}

/**
 *  from_kuid - Create a uid from a kuid user-namespace pair.
 *  @targ: The user namespace we want a uid in.
 *  @kuid: The kernel internal uid to start with.
 *
 *  Map @kuid into the user-namespace specified by @targ and
 *  return the resulting uid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  If @kuid has no mapping in @targ (uid_t)-1 is returned.
 */
uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
    /* Map the uid from a global kernel uid */
    return map_id_up(&targ->uid_map, __kuid_val(kuid));
}
EXPORT_SYMBOL(from_kuid);

/**
 *  from_kuid_munged - Create a uid from a kuid user-namespace pair.
 *  @targ: The user namespace we want a uid in.
 *  @kuid: The kernel internal uid to start with.
 *
 *  Map @kuid into the user-namespace specified by @targ and
 *  return the resulting uid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  Unlike from_kuid from_kuid_munged never fails and always
 *  returns a valid uid.  This makes from_kuid_munged appropriate
 *  for use in syscalls like stat and getuid where failing the
 *  system call and failing to provide a valid uid are not an
 *  options.
 *
 *  If @kuid has no mapping in @targ overflowuid is returned.
 */
uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
    uid_t uid;
    uid = from_kuid(targ, kuid);

    if (uid == (uid_t) -1)
        uid = overflowuid;
    return uid;
}
EXPORT_SYMBOL(from_kuid_munged);

/**
 *  from_kgid - Create a gid from a kgid user-namespace pair.
 *  @targ: The user namespace we want a gid in.
 *  @kgid: The kernel internal gid to start with.
 *
 *  Map @kgid into the user-namespace specified by @targ and
 *  return the resulting gid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  If @kgid has no mapping in @targ (gid_t)-1 is returned.
 */
gid_t from_kgid(struct user_namespace *targ, kgid_t kgid)
{
    /* Map the gid from a global kernel gid */
    return map_id_up(&targ->gid_map, __kgid_val(kgid));
}
EXPORT_SYMBOL(from_kgid);

/**
 *  from_kgid_munged - Create a gid from a kgid user-namespace pair.
 *  @targ: The user namespace we want a gid in.
 *  @kgid: The kernel internal gid to start with.
 *
 *  Map @kgid into the user-namespace specified by @targ and
 *  return the resulting gid.
 *
 *  There is always a mapping into the initial user_namespace.
 *
 *  Unlike from_kgid from_kgid_munged never fails and always
 *  returns a valid gid.  This makes from_kgid_munged appropriate
 *  for use in syscalls like stat and getgid where failing the
 *  system call and failing to provide a valid gid are not options.
 *
 *  If @kgid has no mapping in @targ overflowgid is returned.
 */
gid_t from_kgid_munged(struct user_namespace *targ, kgid_t kgid)
{
    gid_t gid;
    gid = from_kgid(targ, kgid);

    if (gid == (gid_t) -1)
        gid = overflowgid;
    return gid;
}
EXPORT_SYMBOL(from_kgid_munged);
