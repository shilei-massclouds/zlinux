/*
 * Compatibility functions which bloat the callers too much to make inline.
 * All of the callers of these functions should be converted to use folios
 * eventually.
 */

#include <linux/migrate.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include "internal.h"

void unlock_page(struct page *page)
{
    return folio_unlock(page_folio(page));
}
EXPORT_SYMBOL(unlock_page);
