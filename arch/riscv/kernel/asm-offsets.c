// SPDX-License-Identifier: GPL-2.0-only

#define GENERATING_ASM_OFFSETS

#include <linux/kbuild.h>
#include <linux/mm.h>
#include <linux/sched.h>
//#include <asm/kvm_host.h>
#include <asm/thread_info.h>
#include <asm/ptrace.h>

void asm_offsets(void)
{
    OFFSET(KERNEL_MAP_VIRT_ADDR, kernel_mapping, virt_addr);
}
