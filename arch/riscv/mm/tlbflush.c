// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <asm/sbi.h>
//#include <asm/mmu_context.h>

void flush_tlb_all(void)
{
    sbi_remote_sfence_vma(NULL, 0, -1);
}
