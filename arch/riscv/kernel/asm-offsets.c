// SPDX-License-Identifier: GPL-2.0-only

#define GENERATING_ASM_OFFSETS

#include <linux/kbuild.h>
#include <linux/mm.h>
#include <linux/sched.h>
//#include <asm/kvm_host.h>
#include <asm/thread_info.h>
#include <asm/ptrace.h>
#include <asm/cpu_ops_sbi.h>

void asm_offsets(void)
{
    OFFSET(KERNEL_MAP_VIRT_ADDR, kernel_mapping, virt_addr);

    OFFSET(SBI_HART_BOOT_TASK_PTR_OFFSET, sbi_hart_boot_data, task_ptr);
    OFFSET(SBI_HART_BOOT_STACK_PTR_OFFSET, sbi_hart_boot_data, stack_ptr);
}
