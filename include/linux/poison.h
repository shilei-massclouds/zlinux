/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_POISON_H
#define _LINUX_POISON_H

/********** include/linux/list.h **********/

#define POISON_POINTER_DELTA 0

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)

/********** mm/page_alloc.c ************/

#define TAIL_MAPPING    ((void *) 0x400 + POISON_POINTER_DELTA)

/********** arch/$ARCH/mm/init.c **********/
#define POISON_FREE_INITMEM 0xcc

/********** include/linux/timer.h **********/
#define TIMER_ENTRY_STATIC  ((void *) 0x300 + POISON_POINTER_DELTA)

#endif /* _LINUX_POISON_H */
