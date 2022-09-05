// SPDX-License-Identifier: GPL-2.0
/*
 * Scheduler topology setup/handling methods
 */

/* Generate a mask of SD flags with the SDF_NEEDS_GROUPS metaflag */
#define SD_FLAG(name, mflags) (name * !!((mflags) & SDF_NEEDS_GROUPS)) |
static const unsigned int SD_DEGENERATE_GROUPS_MASK =
#include <linux/sched/sd_flags.h>
0;
#undef SD_FLAG

/*
 * SD_flags allowed in topology descriptions.
 *
 * These flags are purely descriptive of the topology and do not prescribe
 * behaviour. Behaviour is artificial and mapped in the below sd_init()
 * function:
 *
 *   SD_SHARE_CPUCAPACITY   - describes SMT topologies
 *   SD_SHARE_PKG_RESOURCES - describes shared caches
 *   SD_NUMA                - describes NUMA topologies
 *
 * Odd one out, which beside describing the topology has a quirk also
 * prescribes the desired behaviour that goes along with it:
 *
 *   SD_ASYM_PACKING        - describes SMT quirks
 */
#define TOPOLOGY_SD_FLAGS       \
    (SD_SHARE_CPUCAPACITY   |   \
     SD_SHARE_PKG_RESOURCES |   \
     SD_NUMA        |   \
     SD_ASYM_PACKING)

DEFINE_MUTEX(sched_domains_mutex);

/* Protected by sched_domains_mutex: */
static cpumask_var_t sched_domains_tmpmask;
static cpumask_var_t sched_domains_tmpmask2;

/*
 * Initializers for schedule domains
 * Non-inlined to reduce accumulated stack pressure in build_sched_domains()
 */

static int default_relax_domain_level = -1;
int sched_domain_level_max;

/*
 * Special case: If a kmalloc() of a doms_cur partition (array of
 * cpumask) fails, then fallback to a single sched domain,
 * as determined by the single cpumask fallback_doms.
 */
static cpumask_var_t            fallback_doms;

/* Current sched domains: */
static cpumask_var_t            *doms_cur;

/* Number of sched domains in 'doms_cur': */
static int              ndoms_cur;

/*
 * By default the system creates a single root-domain with all CPUs as
 * members (mimicking the global state we have today).
 */
struct root_domain def_root_domain;

/*
 * Asymmetric CPU capacity bits
 */
struct asym_cap_data {
    struct list_head link;
    unsigned long capacity;
    unsigned long cpus[];
};

struct s_data {
    struct sched_domain * __percpu *sd;
    struct root_domain  *rd;
};

enum s_alloc {
    sa_rootdomain,
    sa_sd,
    sa_sd_storage,
    sa_none,
};

/*
 * Set of available CPUs grouped by their corresponding capacities
 * Each list entry contains a CPU mask reflecting CPUs that share the same
 * capacity.
 * The lifespan of data is unlimited.
 */
static LIST_HEAD(asym_cap_list);

/*
 * Keep a special pointer to the highest sched_domain that has
 * SD_SHARE_PKG_RESOURCE set (Last Level Cache Domain) for this
 * allows us to avoid some pointer chasing select_idle_sibling().
 *
 * Also keep a unique ID per domain (we use the first CPU number in
 * the cpumask of the domain), this allows us to quickly tell if
 * two CPUs are in the same cache domain, see cpus_share_cache().
 */
DEFINE_PER_CPU(struct sched_domain __rcu *, sd_llc);
DEFINE_PER_CPU(int, sd_llc_size);
DEFINE_PER_CPU(int, sd_llc_id);
DEFINE_PER_CPU(struct sched_domain_shared __rcu *, sd_llc_shared);
DEFINE_PER_CPU(struct sched_domain __rcu *, sd_numa);
DEFINE_PER_CPU(struct sched_domain __rcu *, sd_asym_packing);
DEFINE_PER_CPU(struct sched_domain __rcu *, sd_asym_cpucapacity);
DEFINE_STATIC_KEY_FALSE(sched_asym_cpucapacity);

#define cpu_capacity_span(asym_data) to_cpumask((asym_data)->cpus)

static void free_sched_groups(struct sched_group *sg, int free_sgc);

static int init_rootdomain(struct root_domain *rd)
{
    if (!zalloc_cpumask_var(&rd->span, GFP_KERNEL))
        goto out;
    if (!zalloc_cpumask_var(&rd->online, GFP_KERNEL))
        goto free_span;
    if (!zalloc_cpumask_var(&rd->dlo_mask, GFP_KERNEL))
        goto free_online;
    if (!zalloc_cpumask_var(&rd->rto_mask, GFP_KERNEL))
        goto free_dlo_mask;

    rd->visit_gen = 0;
    //init_dl_bw(&rd->dl_bw);
    if (cpudl_init(&rd->cpudl) != 0)
        goto free_rto_mask;

    if (cpupri_init(&rd->cpupri) != 0)
        goto free_cpudl;
    return 0;

free_cpudl:
    cpudl_cleanup(&rd->cpudl);
free_rto_mask:
    free_cpumask_var(rd->rto_mask);
free_dlo_mask:
    free_cpumask_var(rd->dlo_mask);
free_online:
    free_cpumask_var(rd->online);
free_span:
    free_cpumask_var(rd->span);
out:
    return -ENOMEM;
}

static void __sdt_free(const struct cpumask *cpu_map);
static int __sdt_alloc(const struct cpumask *cpu_map);

void init_defrootdomain(void)
{
    init_rootdomain(&def_root_domain);

    atomic_set(&def_root_domain.refcount, 1);
}

static void free_rootdomain(struct rcu_head *rcu)
{
    struct root_domain *rd = container_of(rcu, struct root_domain, rcu);

    cpupri_cleanup(&rd->cpupri);
    cpudl_cleanup(&rd->cpudl);
    free_cpumask_var(rd->dlo_mask);
    free_cpumask_var(rd->rto_mask);
    free_cpumask_var(rd->online);
    free_cpumask_var(rd->span);
    kfree(rd);
}

static void __free_domain_allocs(struct s_data *d, enum s_alloc what,
                                 const struct cpumask *cpu_map)
{
    switch (what) {
    case sa_rootdomain:
        if (!atomic_read(&d->rd->refcount))
            free_rootdomain(&d->rd->rcu);
        fallthrough;
    case sa_sd:
        free_percpu(d->sd);
        fallthrough;
    case sa_sd_storage:
        __sdt_free(cpu_map);
        fallthrough;
    case sa_none:
        break;
    }
}

void rq_attach_root(struct rq *rq, struct root_domain *rd)
{
    struct root_domain *old_rd = NULL;
    unsigned long flags;

    raw_spin_rq_lock_irqsave(rq, flags);

    if (rq->rd) {
        old_rd = rq->rd;

        if (cpumask_test_cpu(rq->cpu, old_rd->online))
            set_rq_offline(rq);

        cpumask_clear_cpu(rq->cpu, old_rd->span);

        /*
         * If we dont want to free the old_rd yet then
         * set old_rd to NULL to skip the freeing later
         * in this function:
         */
        if (!atomic_dec_and_test(&old_rd->refcount))
            old_rd = NULL;
    }

    atomic_inc(&rd->refcount);
    rq->rd = rd;

    cpumask_set_cpu(rq->cpu, rd->span);
    if (cpumask_test_cpu(rq->cpu, cpu_active_mask))
        set_rq_online(rq);

    raw_spin_rq_unlock_irqrestore(rq, flags);

    if (old_rd)
        call_rcu(&old_rd->rcu, free_rootdomain);
}

static inline void asym_cpu_capacity_update_data(int cpu)
{
    unsigned long capacity = arch_scale_cpu_capacity(cpu);
    struct asym_cap_data *entry = NULL;

    list_for_each_entry(entry, &asym_cap_list, link) {
        if (capacity == entry->capacity)
            goto done;
    }

    entry = kzalloc(sizeof(*entry) + cpumask_size(), GFP_KERNEL);
    if (WARN_ONCE(!entry, "Failed to allocate memory for asymmetry data\n"))
        return;
    entry->capacity = capacity;
    list_add(&entry->link, &asym_cap_list);
done:
    __cpumask_set_cpu(cpu, cpu_capacity_span(entry));
}

/*
 * Build-up/update list of CPUs grouped by their capacities
 * An update requires explicit request to rebuild sched domains
 * with state indicating CPU topology changes.
 */
static void asym_cpu_capacity_scan(void)
{
    struct asym_cap_data *entry, *next;
    int cpu;

    list_for_each_entry(entry, &asym_cap_list, link)
        cpumask_clear(cpu_capacity_span(entry));

    for_each_cpu_and(cpu, cpu_possible_mask,
                     housekeeping_cpumask(HK_TYPE_DOMAIN))
        asym_cpu_capacity_update_data(cpu);

    list_for_each_entry_safe(entry, next, &asym_cap_list, link) {
        if (cpumask_empty(cpu_capacity_span(entry))) {
            list_del(&entry->link);
            kfree(entry);
        }
    }

    /*
     * Only one capacity value has been detected i.e. this system is symmetric.
     * No need to keep this data around.
     */
    if (list_is_singular(&asym_cap_list)) {
        entry = list_first_entry(&asym_cap_list, typeof(*entry), link);
        list_del(&entry->link);
        kfree(entry);
    }
}

void free_sched_domains(cpumask_var_t doms[], unsigned int ndoms)
{
    unsigned int i;
    for (i = 0; i < ndoms; i++)
        free_cpumask_var(doms[i]);
    kfree(doms);
}

cpumask_var_t *alloc_sched_domains(unsigned int ndoms)
{
    int i;
    cpumask_var_t *doms;

    doms = kmalloc_array(ndoms, sizeof(*doms), GFP_KERNEL);
    if (!doms)
        return NULL;
    for (i = 0; i < ndoms; i++) {
        if (!alloc_cpumask_var(&doms[i], GFP_KERNEL)) {
            free_sched_domains(doms, i);
            return NULL;
        }
    }
    return doms;
}

/*
 * Topology list, bottom-up.
 */
static struct sched_domain_topology_level default_topology[] = {

    { cpu_cpu_mask, SD_INIT_NAME(DIE) },
    { NULL, },
};

static struct sched_domain_topology_level *sched_domain_topology =
    default_topology;
static struct sched_domain_topology_level *sched_domain_topology_saved;

#define for_each_sd_topology(tl)            \
    for (tl = sched_domain_topology; tl->mask; tl++)

static int __sdt_alloc(const struct cpumask *cpu_map)
{
    struct sched_domain_topology_level *tl;
    int j;

    for_each_sd_topology(tl) {
        struct sd_data *sdd = &tl->data;

        sdd->sd = alloc_percpu(struct sched_domain *);
        if (!sdd->sd)
            return -ENOMEM;

        sdd->sds = alloc_percpu(struct sched_domain_shared *);
        if (!sdd->sds)
            return -ENOMEM;

        sdd->sg = alloc_percpu(struct sched_group *);
        if (!sdd->sg)
            return -ENOMEM;

        sdd->sgc = alloc_percpu(struct sched_group_capacity *);
        if (!sdd->sgc)
            return -ENOMEM;

        for_each_cpu(j, cpu_map) {
            struct sched_domain *sd;
            struct sched_domain_shared *sds;
            struct sched_group *sg;
            struct sched_group_capacity *sgc;

            sd = kzalloc_node(sizeof(struct sched_domain) +
                              cpumask_size(),
                              GFP_KERNEL, cpu_to_node(j));
            if (!sd)
                return -ENOMEM;

            *per_cpu_ptr(sdd->sd, j) = sd;

            sds = kzalloc_node(sizeof(struct sched_domain_shared),
                               GFP_KERNEL, cpu_to_node(j));
            if (!sds)
                return -ENOMEM;

            *per_cpu_ptr(sdd->sds, j) = sds;

            sg = kzalloc_node(sizeof(struct sched_group) +
                              cpumask_size(),
                              GFP_KERNEL, cpu_to_node(j));
            if (!sg)
                return -ENOMEM;

            sg->next = sg;

            *per_cpu_ptr(sdd->sg, j) = sg;

            sgc = kzalloc_node(sizeof(struct sched_group_capacity) +
                               cpumask_size(),
                               GFP_KERNEL, cpu_to_node(j));
            if (!sgc)
                return -ENOMEM;

            *per_cpu_ptr(sdd->sgc, j) = sgc;
        }
    }

    return 0;
}

static void __sdt_free(const struct cpumask *cpu_map)
{
    struct sched_domain_topology_level *tl;
    int j;

    for_each_sd_topology(tl) {
        struct sd_data *sdd = &tl->data;

        for_each_cpu(j, cpu_map) {
            struct sched_domain *sd;

            if (sdd->sd) {
                sd = *per_cpu_ptr(sdd->sd, j);
                if (sd && (sd->flags & SD_OVERLAP))
                    free_sched_groups(sd->groups, 0);
                kfree(*per_cpu_ptr(sdd->sd, j));
            }

            if (sdd->sds)
                kfree(*per_cpu_ptr(sdd->sds, j));
            if (sdd->sg)
                kfree(*per_cpu_ptr(sdd->sg, j));
            if (sdd->sgc)
                kfree(*per_cpu_ptr(sdd->sgc, j));
        }
        free_percpu(sdd->sd);
        sdd->sd = NULL;
        free_percpu(sdd->sds);
        sdd->sds = NULL;
        free_percpu(sdd->sg);
        sdd->sg = NULL;
        free_percpu(sdd->sgc);
        sdd->sgc = NULL;
    }
}

static struct root_domain *alloc_rootdomain(void)
{
    struct root_domain *rd;

    rd = kzalloc(sizeof(*rd), GFP_KERNEL);
    if (!rd)
        return NULL;

    if (init_rootdomain(rd) != 0) {
        kfree(rd);
        return NULL;
    }

    return rd;
}

static enum s_alloc
__visit_domain_allocation_hell(struct s_data *d,
                               const struct cpumask *cpu_map)
{
    memset(d, 0, sizeof(*d));

    if (__sdt_alloc(cpu_map))
        return sa_sd_storage;
    d->sd = alloc_percpu(struct sched_domain *);
    if (!d->sd)
        return sa_sd_storage;
    d->rd = alloc_rootdomain();
    if (!d->rd)
        return sa_sd;

    return sa_rootdomain;
}

/*
 * Ensure topology masks are sane, i.e. there are no conflicts (overlaps) for
 * any two given CPUs at this (non-NUMA) topology level.
 */
static bool topology_span_sane(struct sched_domain_topology_level *tl,
                               const struct cpumask *cpu_map, int cpu)
{
    int i;

    /* NUMA levels are allowed to overlap */
    if (tl->flags & SDTL_OVERLAP)
        return true;

    /*
     * Non-NUMA levels cannot partially overlap - they must be either
     * completely equal or completely disjoint. Otherwise we can end up
     * breaking the sched_group lists - i.e. a later get_group() pass
     * breaks the linking done for an earlier span.
     */
    for_each_cpu(i, cpu_map) {
        if (i == cpu)
            continue;
        /*
         * We should 'and' all those masks with 'cpu_map' to exactly
         * match the topology we're about to build, but that can only
         * remove CPUs, which only lessens our ability to detect
         * overlaps
         */
        if (!cpumask_equal(tl->mask(cpu), tl->mask(i)) &&
            cpumask_intersects(tl->mask(cpu), tl->mask(i)))
            return false;
    }

    return true;
}

/*
 * Verify whether there is any CPU capacity asymmetry in a given sched domain.
 * Provides sd_flags reflecting the asymmetry scope.
 */
static inline int
asym_cpu_capacity_classify(const struct cpumask *sd_span,
                           const struct cpumask *cpu_map)
{
    struct asym_cap_data *entry;
    int count = 0, miss = 0;

    /*
     * Count how many unique CPU capacities this domain spans across
     * (compare sched_domain CPUs mask with ones representing  available
     * CPUs capacities). Take into account CPUs that might be offline:
     * skip those.
     */
    list_for_each_entry(entry, &asym_cap_list, link) {
        if (cpumask_intersects(sd_span, cpu_capacity_span(entry)))
            ++count;
        else if (cpumask_intersects(cpu_map, cpu_capacity_span(entry)))
            ++miss;
    }

    WARN_ON_ONCE(!count && !list_empty(&asym_cap_list));

    /* No asymmetry detected */
    if (count < 2)
        return 0;
    /* Some of the available CPU capacity values have not been detected */
    if (miss)
        return SD_ASYM_CPUCAPACITY;

    /* Full asymmetry */
    return SD_ASYM_CPUCAPACITY | SD_ASYM_CPUCAPACITY_FULL;
}

static struct sched_domain *
sd_init(struct sched_domain_topology_level *tl,
        const struct cpumask *cpu_map,
        struct sched_domain *child, int cpu)
{
    struct sd_data *sdd = &tl->data;
    struct sched_domain *sd = *per_cpu_ptr(sdd->sd, cpu);
    int sd_id, sd_weight, sd_flags = 0;
    struct cpumask *sd_span;

    sd_weight = cpumask_weight(tl->mask(cpu));

    if (tl->sd_flags)
        sd_flags = (*tl->sd_flags)();
    if (WARN_ONCE(sd_flags & ~TOPOLOGY_SD_FLAGS,
                  "wrong sd_flags in topology description\n"))
        sd_flags &= TOPOLOGY_SD_FLAGS;

    *sd = (struct sched_domain){
        .min_interval       = sd_weight,
        .max_interval       = 2*sd_weight,
        .busy_factor        = 16,
        .imbalance_pct      = 117,

        .cache_nice_tries   = 0,

        .flags          = 1*SD_BALANCE_NEWIDLE
                    | 1*SD_BALANCE_EXEC
                    | 1*SD_BALANCE_FORK
                    | 0*SD_BALANCE_WAKE
                    | 1*SD_WAKE_AFFINE
                    | 0*SD_SHARE_CPUCAPACITY
                    | 0*SD_SHARE_PKG_RESOURCES
                    | 0*SD_SERIALIZE
                    | 1*SD_PREFER_SIBLING
                    | 0*SD_NUMA
                    | sd_flags
                    ,

        .last_balance       = jiffies,
        .balance_interval   = sd_weight,
        .max_newidle_lb_cost    = 0,
        .last_decay_max_lb_cost = jiffies,
        .child          = child,
    };

    sd_span = sched_domain_span(sd);
    cpumask_and(sd_span, cpu_map, tl->mask(cpu));
    sd_id = cpumask_first(sd_span);

    sd->flags |= asym_cpu_capacity_classify(sd_span, cpu_map);

    WARN_ONCE((sd->flags & (SD_SHARE_CPUCAPACITY |
                            SD_ASYM_CPUCAPACITY)) ==
              (SD_SHARE_CPUCAPACITY | SD_ASYM_CPUCAPACITY),
              "CPU capacity asymmetry not supported on SMT\n");

    /*
     * Convert topological properties into behaviour.
     */
    /* Don't attempt to spread across CPUs of different capacities. */
    if ((sd->flags & SD_ASYM_CPUCAPACITY) && sd->child)
        sd->child->flags &= ~SD_PREFER_SIBLING;

    if (sd->flags & SD_SHARE_CPUCAPACITY) {
        sd->imbalance_pct = 110;

    } else if (sd->flags & SD_SHARE_PKG_RESOURCES) {
        sd->imbalance_pct = 117;
        sd->cache_nice_tries = 1;

    } else {
        sd->cache_nice_tries = 1;
    }

    /*
     * For all levels sharing cache; connect a sched_domain_shared
     * instance.
     */
    if (sd->flags & SD_SHARE_PKG_RESOURCES) {
        sd->shared = *per_cpu_ptr(sdd->sds, sd_id);
        atomic_inc(&sd->shared->ref);
        atomic_set(&sd->shared->nr_busy_cpus, sd_weight);
    }

    sd->private = sdd;

    return sd;
}

static void set_domain_attribute(struct sched_domain *sd,
                                 struct sched_domain_attr *attr)
{
    int request;

    if (!attr || attr->relax_domain_level < 0) {
        if (default_relax_domain_level < 0)
            return;
        request = default_relax_domain_level;
    } else
        request = attr->relax_domain_level;

    if (sd->level > request) {
        /* Turn off idle balance on this domain: */
        sd->flags &= ~(SD_BALANCE_WAKE|SD_BALANCE_NEWIDLE);
    }
}

static struct sched_domain *
build_sched_domain(struct sched_domain_topology_level *tl,
                   const struct cpumask *cpu_map,
                   struct sched_domain_attr *attr,
                   struct sched_domain *child,
                   int cpu)
{
    struct sched_domain *sd = sd_init(tl, cpu_map, child, cpu);

    if (child) {
        panic("%s: child!\n", __func__);
    }
    set_domain_attribute(sd, attr);

    return sd;
}

static int
build_overlap_sched_groups(struct sched_domain *sd, int cpu)
{
    struct sched_group *first = NULL, *last = NULL, *sg;
    const struct cpumask *span = sched_domain_span(sd);
    struct cpumask *covered = sched_domains_tmpmask;
    struct sd_data *sdd = sd->private;
    struct sched_domain *sibling;
    int i;

    panic("%s: END!\n", __func__);
}

/*
 * Package topology (also see the load-balance blurb in fair.c)
 *
 * The scheduler builds a tree structure to represent a number of important
 * topology features. By default (default_topology[]) these include:
 *
 *  - Simultaneous multithreading (SMT)
 *  - Multi-Core Cache (MC)
 *  - Package (DIE)
 *
 * Where the last one more or less denotes everything up to a NUMA node.
 *
 * The tree consists of 3 primary data structures:
 *
 *  sched_domain -> sched_group -> sched_group_capacity
 *      ^ ^             ^ ^
 *          `-'             `-'
 *
 * The sched_domains are per-CPU and have a two way link (parent & child) and
 * denote the ever growing mask of CPUs belonging to that level of topology.
 *
 * Each sched_domain has a circular (double) linked list of sched_group's, each
 * denoting the domains of the level below (or individual CPUs in case of the
 * first domain level). The sched_group linked by a sched_domain includes the
 * CPU of that sched_domain [*].
 *
 * Take for instance a 2 threaded, 2 core, 2 cache cluster part:
 *
 * CPU   0   1   2   3   4   5   6   7
 *
 * DIE  [                             ]
 * MC   [             ] [             ]
 * SMT  [     ] [     ] [     ] [     ]
 *
 *  - or -
 *
 * DIE  0-7 0-7 0-7 0-7 0-7 0-7 0-7 0-7
 * MC   0-3 0-3 0-3 0-3 4-7 4-7 4-7 4-7
 * SMT  0-1 0-1 2-3 2-3 4-5 4-5 6-7 6-7
 *
 * CPU   0   1   2   3   4   5   6   7
 *
 * One way to think about it is: sched_domain moves you up and down among these
 * topology levels, while sched_group moves you sideways through it, at child
 * domain granularity.
 *
 * sched_group_capacity ensures each unique sched_group has shared storage.
 *
 * There are two related construction problems, both require a CPU that
 * uniquely identify each group (for a given domain):
 *
 *  - The first is the balance_cpu (see should_we_balance() and the
 *    load-balance blub in fair.c); for each group we only want 1 CPU to
 *    continue balancing at a higher domain.
 *
 *  - The second is the sched_group_capacity; we want all identical groups
 *    to share a single sched_group_capacity.
 *
 * Since these topologies are exclusive by construction. That is, its
 * impossible for an SMT thread to belong to multiple cores, and cores to
 * be part of multiple caches. There is a very clear and unique location
 * for each CPU in the hierarchy.
 *
 * Therefore computing a unique CPU for each group is trivial (the iteration
 * mask is redundant and set all 1s; all CPUs in a group will end up at _that_
 * group), we can simply pick the first CPU in each group.
 *
 *
 * [*] in other words, the first group of each domain is its child domain.
 */
static struct sched_group *get_group(int cpu, struct sd_data *sdd)
{
    struct sched_domain *sd = *per_cpu_ptr(sdd->sd, cpu);
    struct sched_domain *child = sd->child;
    struct sched_group *sg;
    bool already_visited;

    if (child)
        cpu = cpumask_first(sched_domain_span(child));

    sg = *per_cpu_ptr(sdd->sg, cpu);
    sg->sgc = *per_cpu_ptr(sdd->sgc, cpu);

    /* Increase refcounts for claim_allocations: */
    already_visited = atomic_inc_return(&sg->ref) > 1;
    /* sgc visits should follow a similar trend as sg */
    WARN_ON(already_visited != (atomic_inc_return(&sg->sgc->ref) > 1));

    /* If we have already visited that group, it's already initialized. */
    if (already_visited)
        return sg;

    if (child) {
        cpumask_copy(sched_group_span(sg), sched_domain_span(child));
        cpumask_copy(group_balance_mask(sg), sched_group_span(sg));
        sg->flags = child->flags;
    } else {
        cpumask_set_cpu(cpu, sched_group_span(sg));
        cpumask_set_cpu(cpu, group_balance_mask(sg));
    }

    sg->sgc->capacity = SCHED_CAPACITY_SCALE *
        cpumask_weight(sched_group_span(sg));
    sg->sgc->min_capacity = SCHED_CAPACITY_SCALE;
    sg->sgc->max_capacity = SCHED_CAPACITY_SCALE;

    return sg;
}

/*
 * build_sched_groups will build a circular linked list of the groups
 * covered by the given span, will set each group's ->cpumask correctly,
 * and will initialize their ->sgc.
 *
 * Assumes the sched_domain tree is fully constructed
 */
static int
build_sched_groups(struct sched_domain *sd, int cpu)
{
    struct sched_group *first = NULL, *last = NULL;
    struct sd_data *sdd = sd->private;
    const struct cpumask *span = sched_domain_span(sd);
    struct cpumask *covered;
    int i;

    covered = sched_domains_tmpmask;

    cpumask_clear(covered);

    for_each_cpu_wrap(i, span, cpu) {
        struct sched_group *sg;

        if (cpumask_test_cpu(i, covered))
            continue;

        sg = get_group(i, sdd);

        cpumask_or(covered, covered, sched_group_span(sg));

        if (!first)
            first = sg;
        if (last)
            last->next = sg;
        last = sg;
    }
    last->next = first;
    sd->groups = first;

    return 0;
}

/*
 * NULL the sd_data elements we've used to build the sched_domain and
 * sched_group structure so that the subsequent __free_domain_allocs()
 * will not free the data we're using.
 */
static void claim_allocations(int cpu, struct sched_domain *sd)
{
    struct sd_data *sdd = sd->private;

    WARN_ON_ONCE(*per_cpu_ptr(sdd->sd, cpu) != sd);
    *per_cpu_ptr(sdd->sd, cpu) = NULL;

    if (atomic_read(&(*per_cpu_ptr(sdd->sds, cpu))->ref))
        *per_cpu_ptr(sdd->sds, cpu) = NULL;

    if (atomic_read(&(*per_cpu_ptr(sdd->sg, cpu))->ref))
        *per_cpu_ptr(sdd->sg, cpu) = NULL;

    if (atomic_read(&(*per_cpu_ptr(sdd->sgc, cpu))->ref))
        *per_cpu_ptr(sdd->sgc, cpu) = NULL;
}

/*
 * Return the canonical balance CPU for this group, this is the first CPU
 * of this group that's also in the balance mask.
 *
 * The balance mask are all those CPUs that could actually end up at this
 * group. See build_balance_mask().
 *
 * Also see should_we_balance().
 */
int group_balance_cpu(struct sched_group *sg)
{
    return cpumask_first(group_balance_mask(sg));
}

/*
 * Initialize sched groups cpu_capacity.
 *
 * cpu_capacity indicates the capacity of sched group, which is used while
 * distributing the load between different sched groups in a sched domain.
 * Typically cpu_capacity for all the groups in a sched domain will be same
 * unless there are asymmetries in the topology. If there are asymmetries,
 * group having more cpu_capacity will pickup more load compared to the
 * group having less cpu_capacity.
 */
static void init_sched_groups_capacity(int cpu, struct sched_domain *sd)
{
    struct sched_group *sg = sd->groups;

    WARN_ON(!sg);

    do {
        int cpu, max_cpu = -1;

        sg->group_weight = cpumask_weight(sched_group_span(sg));

        if (!(sd->flags & SD_ASYM_PACKING))
            goto next;

        for_each_cpu(cpu, sched_group_span(sg)) {
            if (max_cpu < 0)
                max_cpu = cpu;
            else if (sched_asym_prefer(cpu, max_cpu))
                max_cpu = cpu;
        }
        sg->asym_prefer_cpu = max_cpu;

     next:
        sg = sg->next;
    } while (sg != sd->groups);

    if (cpu != group_balance_cpu(sg))
        return;

    update_group_capacity(sd, cpu);
}

static int sd_degenerate(struct sched_domain *sd)
{
    if (cpumask_weight(sched_domain_span(sd)) == 1)
        return 1;

    /* Following flags need at least 2 groups */
    if ((sd->flags & SD_DEGENERATE_GROUPS_MASK) &&
        (sd->groups != sd->groups->next))
        return 0;

    /* Following flags don't use groups */
    if (sd->flags & (SD_WAKE_AFFINE))
        return 0;

    return 1;
}

static void update_top_cache_domain(int cpu)
{
    struct sched_domain_shared *sds = NULL;
    struct sched_domain *sd;
    int id = cpu;
    int size = 1;

    sd = highest_flag_domain(cpu, SD_SHARE_PKG_RESOURCES);
    if (sd) {
        id = cpumask_first(sched_domain_span(sd));
        size = cpumask_weight(sched_domain_span(sd));
        sds = sd->shared;
    }

    rcu_assign_pointer(per_cpu(sd_llc, cpu), sd);
    per_cpu(sd_llc_size, cpu) = size;
    per_cpu(sd_llc_id, cpu) = id;
    rcu_assign_pointer(per_cpu(sd_llc_shared, cpu), sds);

    sd = lowest_flag_domain(cpu, SD_NUMA);
    rcu_assign_pointer(per_cpu(sd_numa, cpu), sd);

    sd = highest_flag_domain(cpu, SD_ASYM_PACKING);
    rcu_assign_pointer(per_cpu(sd_asym_packing, cpu), sd);

    sd = lowest_flag_domain(cpu, SD_ASYM_CPUCAPACITY_FULL);
    rcu_assign_pointer(per_cpu(sd_asym_cpucapacity, cpu), sd);
}

static void destroy_sched_domains_rcu(struct rcu_head *rcu)
{
    panic("%s: END!\n", __func__);
}

static void destroy_sched_domains(struct sched_domain *sd)
{
    if (sd)
        call_rcu(&sd->rcu, destroy_sched_domains_rcu);
}

static void free_sched_groups(struct sched_group *sg, int free_sgc)
{
    struct sched_group *tmp, *first;

    if (!sg)
        return;

    first = sg;
    do {
        tmp = sg->next;

        if (free_sgc && atomic_dec_and_test(&sg->sgc->ref))
            kfree(sg->sgc);

        if (atomic_dec_and_test(&sg->ref))
            kfree(sg);
        sg = tmp;
    } while (sg != first);
}

static void destroy_sched_domain(struct sched_domain *sd)
{
    /*
     * A normal sched domain may have multiple group references, an
     * overlapping domain, having private groups, only one.  Iterate,
     * dropping group/capacity references, freeing where none remain.
     */
    free_sched_groups(sd->groups, 1);

    if (sd->shared && atomic_dec_and_test(&sd->shared->ref))
        kfree(sd->shared);
    kfree(sd);
}

/*
 * Attach the domain 'sd' to 'cpu' as its base domain. Callers must
 * hold the hotplug lock.
 */
static void
cpu_attach_domain(struct sched_domain *sd, struct root_domain *rd,
                  int cpu)
{
    struct rq *rq = cpu_rq(cpu);
    struct sched_domain *tmp;

    /* Remove the sched domains which do not contribute to scheduling. */
    for (tmp = sd; tmp; ) {
        struct sched_domain *parent = tmp->parent;
        if (!parent)
            break;

        panic("%s: 1!\n", __func__);
    }

    if (sd && sd_degenerate(sd)) {
        tmp = sd;
        sd = sd->parent;
        destroy_sched_domain(tmp);
        if (sd) {

            panic("%s: 2!\n", __func__);
        }
    }

    rq_attach_root(rq, rd);
    tmp = rq->sd;
    rcu_assign_pointer(rq->sd, sd);
    destroy_sched_domains(tmp);

    update_top_cache_domain(cpu);
}

/*
 * Build sched domains for a given set of CPUs and attach the sched domains
 * to the individual CPUs
 */
static int
build_sched_domains(const struct cpumask *cpu_map,
                    struct sched_domain_attr *attr)
{
    enum s_alloc alloc_state = sa_none;
    struct sched_domain *sd;
    struct s_data d;
    struct rq *rq = NULL;
    int i, ret = -ENOMEM;
    bool has_asym = false;

    if (WARN_ON(cpumask_empty(cpu_map)))
        goto error;

    alloc_state = __visit_domain_allocation_hell(&d, cpu_map);
    if (alloc_state != sa_rootdomain)
        goto error;

    /* Set up domains for CPUs specified by the cpu_map: */
    for_each_cpu(i, cpu_map) {
        struct sched_domain_topology_level *tl;

        sd = NULL;
        for_each_sd_topology(tl) {
            if (WARN_ON(!topology_span_sane(tl, cpu_map, i)))
                goto error;

            sd = build_sched_domain(tl, cpu_map, attr, sd, i);

            has_asym |= sd->flags & SD_ASYM_CPUCAPACITY;

            if (tl == sched_domain_topology)
                *per_cpu_ptr(d.sd, i) = sd;
            if (tl->flags & SDTL_OVERLAP)
                sd->flags |= SD_OVERLAP;
            if (cpumask_equal(cpu_map, sched_domain_span(sd)))
                break;
        }
    }

    /* Build the groups for the domains */
    for_each_cpu(i, cpu_map) {
        for (sd = *per_cpu_ptr(d.sd, i); sd; sd = sd->parent) {
            sd->span_weight = cpumask_weight(sched_domain_span(sd));
            if (sd->flags & SD_OVERLAP) {
                if (build_overlap_sched_groups(sd, i))
                    goto error;
            } else {
                if (build_sched_groups(sd, i))
                    goto error;
            }
        }
    }

    /*
     * Calculate an allowed NUMA imbalance such that LLCs do not get
     * imbalanced.
     */
    for_each_cpu(i, cpu_map) {
        unsigned int imb = 0;
        unsigned int imb_span = 1;

        for (sd = *per_cpu_ptr(d.sd, i); sd; sd = sd->parent) {
            struct sched_domain *child = sd->child;

            if (!(sd->flags & SD_SHARE_PKG_RESOURCES) && child &&
                (child->flags & SD_SHARE_PKG_RESOURCES)) {
                panic("%s: 0.1!\n", __func__);
            } else {
                int factor = max(1U, (sd->span_weight / imb_span));

                sd->imb_numa_nr = imb * factor;
            }
        }
    }

    /* Calculate CPU capacity for physical packages and nodes */
    for (i = nr_cpumask_bits-1; i >= 0; i--) {
        if (!cpumask_test_cpu(i, cpu_map))
            continue;

        for (sd = *per_cpu_ptr(d.sd, i); sd; sd = sd->parent) {
            claim_allocations(i, sd);
            init_sched_groups_capacity(i, sd);
        }
    }

    /* Attach the domains */
    rcu_read_lock();
    for_each_cpu(i, cpu_map) {
        rq = cpu_rq(i);
        sd = *per_cpu_ptr(d.sd, i);

        /* Use READ_ONCE()/WRITE_ONCE() to avoid load/store tearing: */
        if (rq->cpu_capacity_orig > READ_ONCE(d.rd->max_cpu_capacity))
            WRITE_ONCE(d.rd->max_cpu_capacity, rq->cpu_capacity_orig);

        cpu_attach_domain(sd, d.rd, i);
    }
    rcu_read_unlock();

    if (has_asym)
        static_branch_inc_cpuslocked(&sched_asym_cpucapacity);

#if 0
    if (rq && sched_debug_verbose) {
        pr_info("root domain span: %*pbl (max cpu_capacity = %lu)\n",
                cpumask_pr_args(cpu_map), rq->rd->max_cpu_capacity);
    }
#endif

    ret = 0;

 error:
    __free_domain_allocs(&d, alloc_state, cpu_map);

    return ret;
}

/*
 * Set up scheduler domains and groups.  For now this just excludes isolated
 * CPUs, but could be used to exclude other special cases in the future.
 */
int sched_init_domains(const struct cpumask *cpu_map)
{
    int err;

    zalloc_cpumask_var(&sched_domains_tmpmask, GFP_KERNEL);
    zalloc_cpumask_var(&sched_domains_tmpmask2, GFP_KERNEL);
    zalloc_cpumask_var(&fallback_doms, GFP_KERNEL);

    asym_cpu_capacity_scan();
    ndoms_cur = 1;
    doms_cur = alloc_sched_domains(ndoms_cur);
    if (!doms_cur)
        doms_cur = &fallback_doms;

    cpumask_and(doms_cur[0], cpu_map,
                housekeeping_cpumask(HK_TYPE_DOMAIN));
    err = build_sched_domains(doms_cur[0], NULL);

    return err;
}
