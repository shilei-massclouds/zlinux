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

void mark_page_accessed(struct page *page)
{
    folio_mark_accessed(page_folio(page));
}
EXPORT_SYMBOL(mark_page_accessed);

noinline
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t index,
                                int fgp_flags, gfp_t gfp)
{
    struct folio *folio;

    folio = __filemap_get_folio(mapping, index, fgp_flags, gfp);
    if ((fgp_flags & FGP_HEAD) || !folio || xa_is_value(folio))
        return &folio->page;
    return folio_file_page(folio, index);
}
EXPORT_SYMBOL(pagecache_get_page);
