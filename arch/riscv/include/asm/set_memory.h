/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_SET_MEMORY_H
#define _ASM_RISCV_SET_MEMORY_H

#define SECTION_ALIGN (1 << 21)

#ifndef __ASSEMBLY__

int set_memory_rw(unsigned long addr, int numpages);

static __always_inline
int set_kernel_memory(char *startp, char *endp,
                      int (*set_memory)(unsigned long start, int num_pages))
{
    unsigned long start = (unsigned long)startp;
    unsigned long end = (unsigned long)endp;
    int num_pages = PAGE_ALIGN(end - start) >> PAGE_SHIFT;

    return set_memory(start, num_pages);
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_SET_MEMORY_H */
