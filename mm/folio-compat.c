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

void lru_cache_add(struct page *page)
{
    folio_add_lru(page_folio(page));
}
EXPORT_SYMBOL(lru_cache_add);

bool set_page_dirty(struct page *page)
{
    return folio_mark_dirty(page_folio(page));
}
EXPORT_SYMBOL(set_page_dirty);

void end_page_writeback(struct page *page)
{
    return folio_end_writeback(page_folio(page));
}
EXPORT_SYMBOL(end_page_writeback);

struct address_space *page_mapping(struct page *page)
{
    return folio_mapping(page_folio(page));
}
EXPORT_SYMBOL(page_mapping);

void delete_from_page_cache(struct page *page)
{
    return filemap_remove_folio(page_folio(page));
}

bool page_mapped(struct page *page)
{
    return folio_mapped(page_folio(page));
}
EXPORT_SYMBOL(page_mapped);

void putback_lru_page(struct page *page)
{
    folio_putback_lru(page_folio(page));
}

int try_to_release_page(struct page *page, gfp_t gfp)
{
    return filemap_release_folio(page_folio(page), gfp);
}
EXPORT_SYMBOL(try_to_release_page);
