/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OF_RESERVED_MEM_H
#define __OF_RESERVED_MEM_H

//#include <linux/device.h>
#include <linux/of.h>

struct of_phandle_args;
struct reserved_mem_ops;

struct reserved_mem {
    const char          *name;
    unsigned long       fdt_node;
    unsigned long       phandle;
    const struct reserved_mem_ops   *ops;
    phys_addr_t         base;
    phys_addr_t         size;
    void                *priv;
};

#endif /* __OF_RESERVED_MEM_H */
