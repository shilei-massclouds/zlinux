// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
//#include <linux/async.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/string.h>
//#include <linux/dirent.h>
#include <linux/syscalls.h>
//#include <linux/utime.h>
#include <linux/file.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/init_syscalls.h>
//#include <linux/umh.h>

#include <linux/initrd.h>
//#include <linux/kexec.h>

void __init reserve_initrd_mem(void)
{
    phys_addr_t start;
    unsigned long size;

    /* Ignore the virtul address computed during device tree parsing */
    initrd_start = initrd_end = 0;

    if (!phys_initrd_size)
        return;

    panic("%s: END!\n", __func__);
}
