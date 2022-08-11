/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CACHEFLUSH_H
#define _LINUX_CACHEFLUSH_H

#include <asm/cacheflush.h>

struct folio;

#ifndef ARCH_IMPLEMENTS_FLUSH_DCACHE_FOLIO
void flush_dcache_folio(struct folio *folio);
#endif

#endif /* _LINUX_CACHEFLUSH_H */
