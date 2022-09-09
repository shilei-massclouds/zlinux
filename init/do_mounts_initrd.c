// SPDX-License-Identifier: GPL-2.0
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/fs.h>
//#include <linux/minix_fs.h>
//#include <linux/romfs_fs.h>
#include <linux/initrd.h>
#include <linux/sched.h>
//#include <linux/freezer.h>
#include <linux/kmod.h>
#include <uapi/linux/mount.h>

#include "do_mounts.h"

unsigned long initrd_start, initrd_end;

phys_addr_t phys_initrd_start __initdata;
unsigned long phys_initrd_size __initdata;

static int __init early_initrdmem(char *p)
{
    phys_addr_t start;
    unsigned long size;
    char *endp;

    start = memparse(p, &endp);
    if (*endp == ',') {
        size = memparse(endp + 1, NULL);

        phys_initrd_start = start;
        phys_initrd_size = size;
    }
    return 0;
}
early_param("initrdmem", early_initrdmem);
