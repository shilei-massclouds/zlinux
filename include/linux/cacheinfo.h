/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CACHEINFO_H
#define _LINUX_CACHEINFO_H

#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/smp.h>

struct device_node;
struct attribute;

enum cache_type {
    CACHE_TYPE_NOCACHE = 0,
    CACHE_TYPE_INST = BIT(0),
    CACHE_TYPE_DATA = BIT(1),
    CACHE_TYPE_SEPARATE = CACHE_TYPE_INST | CACHE_TYPE_DATA,
    CACHE_TYPE_UNIFIED = BIT(2),
};

/**
 * struct cacheinfo - represent a cache leaf node
 * @id: This cache's id. It is unique among caches with the same (type, level).
 * @type: type of the cache - data, inst or unified
 * @level: represents the hierarchy in the multi-level cache
 * @coherency_line_size: size of each cache line usually representing
 *  the minimum amount of data that gets transferred from memory
 * @number_of_sets: total number of sets, a set is a collection of cache
 *  lines sharing the same index
 * @ways_of_associativity: number of ways in which a particular memory
 *  block can be placed in the cache
 * @physical_line_partition: number of physical cache lines sharing the
 *  same cachetag
 * @size: Total size of the cache
 * @shared_cpu_map: logical cpumask representing all the cpus sharing
 *  this cache node
 * @attributes: bitfield representing various cache attributes
 * @fw_token: Unique value used to determine if different cacheinfo
 *  structures represent a single hardware cache instance.
 * @disable_sysfs: indicates whether this node is visible to the user via
 *  sysfs or not
 * @priv: pointer to any private data structure specific to particular
 *  cache design
 *
 * While @of_node, @disable_sysfs and @priv are used for internal book
 * keeping, the remaining members form the core properties of the cache
 */
struct cacheinfo {
    unsigned int id;
    enum cache_type type;
    unsigned int level;
    unsigned int coherency_line_size;
    unsigned int number_of_sets;
    unsigned int ways_of_associativity;
    unsigned int physical_line_partition;
    unsigned int size;
    cpumask_t shared_cpu_map;
    unsigned int attributes;
#define CACHE_WRITE_THROUGH BIT(0)
#define CACHE_WRITE_BACK    BIT(1)
#define CACHE_WRITE_POLICY_MASK     \
    (CACHE_WRITE_THROUGH | CACHE_WRITE_BACK)
#define CACHE_READ_ALLOCATE BIT(2)
#define CACHE_WRITE_ALLOCATE    BIT(3)
#define CACHE_ALLOCATE_POLICY_MASK  \
    (CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE)
#define CACHE_ID        BIT(4)
    void *fw_token;
    bool disable_sysfs;
    void *priv;
};

struct cpu_cacheinfo {
    struct cacheinfo *info_list;
    unsigned int num_levels;
    unsigned int num_leaves;
    bool cpu_map_populated;
};

extern unsigned int coherency_max_size;

struct cpu_cacheinfo *get_cpu_cacheinfo(unsigned int cpu);

#endif /* _LINUX_CACHEINFO_H */
