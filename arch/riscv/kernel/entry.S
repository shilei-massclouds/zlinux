/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/init.h>
#include <linux/linkage.h>

.set resume_kernel, restore_all

ENTRY(handle_exception)
    ebreak
