/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_MM_DEBUG_H
#define LINUX_MM_DEBUG_H

#include <linux/bug.h>
#include <linux/stringify.h>

#define VM_BUG_ON(cond)                 BUILD_BUG_ON_INVALID(cond)
#define VM_BUG_ON_PAGE(cond, page)      VM_BUG_ON(cond)
#define VM_BUG_ON_PGFLAGS(cond, page)   BUILD_BUG_ON_INVALID(cond)
#define VM_WARN_ON(cond)                BUILD_BUG_ON_INVALID(cond)
#define VM_WARN_ON_ONCE(cond)           BUILD_BUG_ON_INVALID(cond)
#define VM_WARN_ONCE(cond, format...)   BUILD_BUG_ON_INVALID(cond)
#define VM_BUG_ON_FOLIO(cond, folio)    VM_BUG_ON(cond)
#define VM_BUG_ON_MM(cond, mm)          VM_BUG_ON(cond)
#define VM_BUG_ON_VMA(cond, vma)        VM_BUG_ON(cond)

#endif /* LINUX_MM_DEBUG_H */
