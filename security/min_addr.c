// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/security.h>
//#include <linux/sysctl.h>

/* amount of vm to protect from userspace access by both DAC and the LSM*/
unsigned long mmap_min_addr;
/* amount of vm to protect from userspace using CAP_SYS_RAWIO (DAC) */
unsigned long dac_mmap_min_addr = CONFIG_DEFAULT_MMAP_MIN_ADDR;
/* amount of vm to protect from userspace using the LSM = CONFIG_LSM_MMAP_MIN_ADDR */

/*
 * Update mmap_min_addr = max(dac_mmap_min_addr, CONFIG_LSM_MMAP_MIN_ADDR)
 */
static void update_mmap_min_addr(void)
{
    mmap_min_addr = dac_mmap_min_addr;
}

static int __init init_mmap_min_addr(void)
{
    update_mmap_min_addr();

    return 0;
}
pure_initcall(init_mmap_min_addr);
