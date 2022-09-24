/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_OF_PRIVATE_H
#define _LINUX_OF_PRIVATE_H
/*
 * Private symbols used by OF support code
 *
 * Paul Mackerras   August 1996.
 * Copyright (C) 1996-2005 Paul Mackerras.
 */

#define OF_ROOT_NODE_ADDR_CELLS_DEFAULT 1
#define OF_ROOT_NODE_SIZE_CELLS_DEFAULT 1

/**
 * struct alias_prop - Alias property in 'aliases' node
 * @link:   List node to link the structure in aliases_lookup list
 * @alias:  Alias property name
 * @np:     Pointer to device_node that the alias stands for
 * @id:     Index value from end of alias name
 * @stem:   Alias string without the index
 *
 * The structure represents one alias property of 'aliases' node as
 * an entry in aliases_lookup list.
 */
struct alias_prop {
    struct list_head link;
    const char *alias;
    struct device_node *np;
    int id;
    char stem[];
};

void fdt_init_reserved_mem(void);
void fdt_reserved_mem_save_node(unsigned long node, const char *uname,
                                phys_addr_t base, phys_addr_t size);

extern const void *__of_get_property(const struct device_node *np,
                                     const char *name, int *lenp);

int of_dma_get_range(struct device_node *np, const struct bus_dma_region **map);

#endif /* _LINUX_OF_PRIVATE_H */
