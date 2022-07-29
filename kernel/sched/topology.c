// SPDX-License-Identifier: GPL-2.0
/*
 * Scheduler topology setup/handling methods
 */

DEFINE_MUTEX(sched_domains_mutex);

/* Protected by sched_domains_mutex: */
static cpumask_var_t sched_domains_tmpmask;
static cpumask_var_t sched_domains_tmpmask2;

/*
 * By default the system creates a single root-domain with all CPUs as
 * members (mimicking the global state we have today).
 */
struct root_domain def_root_domain;

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

void init_defrootdomain(void)
{
    init_rootdomain(&def_root_domain);

    atomic_set(&def_root_domain.refcount, 1);
}

void rq_attach_root(struct rq *rq, struct root_domain *rd)
{
    panic("%s: END!\n", __func__);
}
