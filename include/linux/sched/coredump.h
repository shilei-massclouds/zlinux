/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_COREDUMP_H
#define _LINUX_SCHED_COREDUMP_H

#include <linux/mm_types.h>

/* mm flags */

/* for SUID_DUMP_* above */
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)

/* coredump filter bits */
#define MMF_DUMP_ANON_PRIVATE   2
#define MMF_DUMP_ANON_SHARED    3
#define MMF_DUMP_MAPPED_PRIVATE 4
#define MMF_DUMP_MAPPED_SHARED  5
#define MMF_DUMP_ELF_HEADERS    6
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_DAX_PRIVATE    9
#define MMF_DUMP_DAX_SHARED     10

#define MMF_DUMP_MASK_DEFAULT_ELF  (1 << MMF_DUMP_ELF_HEADERS)

#define MMF_DUMP_FILTER_SHIFT   MMF_DUMPABLE_BITS
#define MMF_DUMP_FILTER_BITS    9
#define MMF_DUMP_FILTER_MASK \
    (((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_FILTER_DEFAULT \
    ((1 << MMF_DUMP_ANON_PRIVATE) | (1 << MMF_DUMP_ANON_SHARED) |\
     (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)

#define MMF_HAS_UPROBES     19  /* has uprobes */
#define MMF_RECALC_UPROBES  20  /* MMF_HAS_UPROBES can be wrong */
#define MMF_OOM_SKIP        21  /* mm is of no interest for the OOM killer */
#define MMF_UNSTABLE        22  /* mm is unstable for copy_from_user */
#define MMF_HUGE_ZERO_PAGE  23      /* mm has ever used the global huge zero page */
#define MMF_DISABLE_THP     24  /* disable THP for all VMAs */
#define MMF_OOM_VICTIM      25  /* mm is the oom victim */
#define MMF_OOM_REAP_QUEUED 26  /* mm was queued for oom_reaper */
#define MMF_MULTIPROCESS    27  /* mm is shared between processes */
/*
 * MMF_HAS_PINNED: Whether this mm has pinned any pages.  This can be either
 * replaced in the future by mm.pinned_vm when it becomes stable, or grow into
 * a counter on its own. We're aggresive on this bit for now: even if the
 * pinned pages were unpinned later on, we'll still keep this bit set for the
 * lifecycle of this mm, just for simplicity.
 */
#define MMF_HAS_PINNED      28  /* FOLL_PIN has run, never cleared */
#define MMF_DISABLE_THP_MASK    (1 << MMF_DISABLE_THP)

#define MMF_INIT_MASK \
    (MMF_DUMPABLE_MASK | MMF_DUMP_FILTER_MASK | MMF_DISABLE_THP_MASK)

#endif /* _LINUX_SCHED_COREDUMP_H */
