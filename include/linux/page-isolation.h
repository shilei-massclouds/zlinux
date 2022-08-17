/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGEISOLATION_H
#define __LINUX_PAGEISOLATION_H

static inline bool has_isolate_pageblock(struct zone *zone)
{
    return false;
}
static inline bool is_migrate_isolate_page(struct page *page)
{
    return false;
}
static inline bool is_migrate_isolate(int migratetype)
{
    return false;
}

struct page *has_unmovable_pages(struct zone *zone, struct page *page,
                                 int migratetype, int flags);
void set_pageblock_migratetype(struct page *page, int migratetype);
int move_freepages_block(struct zone *zone, struct page *page,
                         int migratetype, int *num_movable);

#endif /* __LINUX_PAGEISOLATION_H */
