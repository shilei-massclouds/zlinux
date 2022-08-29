// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm_init.c - Memory initialisation verification and debugging
 *
 * Copyright 2008 IBM Corporation, 2008
 * Author Mel Gorman <mel@csn.ul.ie>
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/export.h>
#if 0
#include <linux/memory.h>
#include <linux/notifier.h>
#endif
#include <linux/sched.h>
#include <linux/mman.h>
#include "internal.h"

s32 vm_committed_as_batch = 32;
