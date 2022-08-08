/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_MMU_H
#define _ASM_RISCV_MMU_H

#ifndef __ASSEMBLY__

typedef struct {
    atomic_long_t id;
    void *vdso;
    /* A local icache flush is needed before user execution can resume. */
    cpumask_t icache_stale_mask;
} mm_context_t;

void __init create_pgd_mapping(pgd_t *pgdp, uintptr_t va, phys_addr_t pa,
                               phys_addr_t sz, pgprot_t prot);

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_MMU_H */
