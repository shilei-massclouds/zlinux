/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_INITRD_H
#define __LINUX_INITRD_H

#define INITRD_MINOR 250 /* shouldn't collide with /dev/ram* too soon ... */

extern unsigned long phys_initrd_size;

/* free_initrd_mem always gets called with the next two as arguments.. */
extern unsigned long initrd_start, initrd_end;
extern void free_initrd_mem(unsigned long, unsigned long);

extern void __init reserve_initrd_mem(void);
extern void wait_for_initramfs(void);

#endif /* __LINUX_INITRD_H */
