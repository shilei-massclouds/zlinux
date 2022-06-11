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

void fdt_init_reserved_mem(void);
void fdt_reserved_mem_save_node(unsigned long node, const char *uname,
                                phys_addr_t base, phys_addr_t size);

extern const void *__of_get_property(const struct device_node *np,
                                     const char *name, int *lenp);

#endif /* _LINUX_OF_PRIVATE_H */
