// SPDX-License-Identifier: GPL-2.0
#include <linux/hugetlb.h>
#include <linux/err.h>

int pud_huge(pud_t pud)
{
    return pud_leaf(pud);
}

int pmd_huge(pmd_t pmd)
{
    return pmd_leaf(pmd);
}
