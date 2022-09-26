// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "OF: " fmt

#include <linux/device.h>
#if 0
#include <linux/fwnode.h>
#endif
#include <linux/io.h>
#include <linux/ioport.h>
#if 0
#include <linux/logic_pio.h>
#endif
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/pci_regs.h>
#if 0
#include <linux/pci.h>
#endif
#include <linux/dma-direct.h> /* for bus_dma_region */
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "of_private.h"

/* Max address size we deal with */
#define OF_MAX_ADDR_CELLS   4
#define OF_CHECK_ADDR_COUNT(na) ((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)
#define OF_CHECK_COUNTS(na, ns) (OF_CHECK_ADDR_COUNT(na) && (ns) > 0)

/* Callbacks for bus specific translators */
struct of_bus {
    const char  *name;
    const char  *addresses;
    int (*match)(struct device_node *parent);
    void (*count_cells)(struct device_node *child, int *addrc, int *sizec);
    u64 (*map)(__be32 *addr, const __be32 *range, int na, int ns, int pna);
    int (*translate)(__be32 *addr, u64 offset, int na);
    bool has_flags;
    unsigned int (*get_flags)(const __be32 *addr);
};

/*
 * Default translator (generic bus)
 */

static void of_bus_default_count_cells(struct device_node *dev,
                                       int *addrc, int *sizec)
{
    if (addrc)
        *addrc = of_n_addr_cells(dev);
    if (sizec)
        *sizec = of_n_size_cells(dev);
}

static u64 of_bus_default_map(__be32 *addr, const __be32 *range,
                              int na, int ns, int pna)
{
    panic("%s: NO implementation!\n", __func__);
}

static int of_bus_default_translate(__be32 *addr, u64 offset, int na)
{
    u64 a = of_read_number(addr, na);
    memset(addr, 0, na * 4);
    a += offset;
    if (na > 1)
        addr[na - 2] = cpu_to_be32(a >> 32);
    addr[na - 1] = cpu_to_be32(a & 0xffffffffu);

    return 0;
}

static unsigned int of_bus_default_get_flags(const __be32 *addr)
{
    return IORESOURCE_MEM;
}

/*
 * Array of bus specific translators
 */
static struct of_bus of_busses[] = {
#if 0
    /* PCI */
    {
        .name = "pci",
        .addresses = "assigned-addresses",
        .match = of_bus_pci_match,
        .count_cells = of_bus_pci_count_cells,
        .map = of_bus_pci_map,
        .translate = of_bus_pci_translate,
        .has_flags = true,
        .get_flags = of_bus_pci_get_flags,
    },
    /* ISA */
    {
        .name = "isa",
        .addresses = "reg",
        .match = of_bus_isa_match,
        .count_cells = of_bus_isa_count_cells,
        .map = of_bus_isa_map,
        .translate = of_bus_isa_translate,
        .has_flags = true,
        .get_flags = of_bus_isa_get_flags,
    },
#endif
    /* Default */
    {
        .name = "default",
        .addresses = "reg",
        .match = NULL,
        .count_cells = of_bus_default_count_cells,
        .map = of_bus_default_map,
        .translate = of_bus_default_translate,
        .get_flags = of_bus_default_get_flags,
    },
};

static struct of_bus *of_match_bus(struct device_node *np)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(of_busses); i++)
        if (!of_busses[i].match || of_busses[i].match(np))
            return &of_busses[i];
    BUG();
    return NULL;
}

const __be32 *
__of_get_address(struct device_node *dev, int index, int bar_no,
                 u64 *size, unsigned int *flags)
{
    const __be32 *prop;
    unsigned int psize;
    struct device_node *parent;
    struct of_bus *bus;
    int onesize, i, na, ns;

    /* Get parent & match bus type */
    parent = of_get_parent(dev);
    if (parent == NULL)
        return NULL;
    bus = of_match_bus(parent);
    if (strcmp(bus->name, "pci") && (bar_no >= 0)) {
        of_node_put(parent);
        return NULL;
    }
    bus->count_cells(dev, &na, &ns);
    of_node_put(parent);
    if (!OF_CHECK_ADDR_COUNT(na))
        return NULL;

    /* Get "reg" or "assigned-addresses" property */
    prop = of_get_property(dev, bus->addresses, &psize);
    if (prop == NULL)
        return NULL;
    psize /= 4;

    onesize = na + ns;
    for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++) {
        u32 val = be32_to_cpu(prop[0]);
        /* PCI bus matches on BAR number instead of index */
        if (((bar_no >= 0) &&
             ((val & 0xff) == ((bar_no * 4) + PCI_BASE_ADDRESS_0))) ||
            ((index >= 0) && (i == index))) {
            if (size)
                *size = of_read_number(prop + na, ns);
            if (flags)
                *flags = bus->get_flags(prop);
            return prop;
        }
    }
    return NULL;
}
EXPORT_SYMBOL(__of_get_address);

static int of_translate_one(struct device_node *parent, struct of_bus *bus,
                            struct of_bus *pbus, __be32 *addr,
                            int na, int ns, int pna, const char *rprop)
{
    const __be32 *ranges;
    unsigned int rlen;
    int rone;
    u64 offset = OF_BAD_ADDR;

    /*
     * Normally, an absence of a "ranges" property means we are
     * crossing a non-translatable boundary, and thus the addresses
     * below the current cannot be converted to CPU physical ones.
     * Unfortunately, while this is very clear in the spec, it's not
     * what Apple understood, and they do have things like /uni-n or
     * /ht nodes with no "ranges" property and a lot of perfectly
     * useable mapped devices below them. Thus we treat the absence of
     * "ranges" as equivalent to an empty "ranges" property which means
     * a 1:1 translation at that level. It's up to the caller not to try
     * to translate addresses that aren't supposed to be translated in
     * the first place. --BenH.
     *
     * As far as we know, this damage only exists on Apple machines, so
     * This code is only enabled on powerpc. --gcl
     *
     * This quirk also applies for 'dma-ranges' which frequently exist in
     * child nodes without 'dma-ranges' in the parent nodes. --RobH
     */
    ranges = of_get_property(parent, rprop, &rlen);
    if (ranges == NULL && strcmp(rprop, "dma-ranges")) {
        pr_warn("no ranges; cannot translate\n");
        return 1;
    }
    if (ranges == NULL || rlen == 0) {
        offset = of_read_number(addr, na);
        memset(addr, 0, pna * 4);
        pr_debug("empty ranges; 1:1 translation\n");
        goto finish;
    }

    pr_info("walking ranges...\n");

    panic("%s: name(%s) END!\n", __func__, parent->name);

 finish:
    pr_debug("with offset: %llx\n", offset);

    /* Translate it into parent bus space */
    return pbus->translate(addr, offset, pna);
}

/*
 * Translate an address from the device-tree into a CPU physical address,
 * this walks up the tree and applies the various bus mappings on the
 * way.
 *
 * Note: We consider that crossing any level with #size-cells == 0 to mean
 * that translation is impossible (that is we are not dealing with a value
 * that can be mapped to a cpu physical address). This is not really specified
 * that way, but this is traditionally the way IBM at least do things
 *
 * Whenever the translation fails, the *host pointer will be set to the
 * device that had registered logical PIO mapping, and the return code is
 * relative to that node.
 */
static u64
__of_translate_address(struct device_node *dev,
                       struct device_node *(*get_parent)(const struct device_node *),
                       const __be32 *in_addr, const char *rprop,
                       struct device_node **host)
{
    struct device_node *parent = NULL;
    struct of_bus *bus, *pbus;
    __be32 addr[OF_MAX_ADDR_CELLS];
    int na, ns, pna, pns;
    u64 result = OF_BAD_ADDR;

    pr_debug("** translation for device %pOF **\n", dev);

    /* Increase refcount at current level */
    of_node_get(dev);

    *host = NULL;
    /* Get parent & match bus type */
    parent = get_parent(dev);
    if (parent == NULL)
        goto bail;
    bus = of_match_bus(parent);

    /* Count address cells & copy address locally */
    bus->count_cells(dev, &na, &ns);
    if (!OF_CHECK_COUNTS(na, ns)) {
        pr_debug("Bad cell count for %pOF\n", dev);
        goto bail;
    }
    memcpy(addr, in_addr, na * 4);

    pr_debug("bus is %s (na=%d, ns=%d) on %pOF\n",
             bus->name, na, ns, parent);

    /* Translate */
    for (;;) {
        //struct logic_pio_hwaddr *iorange;

        /* Switch to parent bus */
        of_node_put(dev);
        dev = parent;
        parent = get_parent(dev);

        /* If root, we have finished */
        if (parent == NULL) {
            pr_debug("reached root node\n");
            result = of_read_number(addr, na);
            break;
        }

        /*
         * For indirectIO device which has no ranges property, get
         * the address from reg directly.
         */
#if 0
        iorange = find_io_range_by_fwnode(&dev->fwnode);
        if (iorange && (iorange->flags != LOGIC_PIO_CPU_MMIO)) {
            result = of_read_number(addr + 1, na - 1);
            pr_debug("indirectIO matched(%pOF) 0x%llx\n",
                 dev, result);
            *host = of_node_get(dev);
            break;
        }
#endif

        /* Get new parent bus and counts */
        pbus = of_match_bus(parent);
        pbus->count_cells(dev, &pna, &pns);
        if (!OF_CHECK_COUNTS(pna, pns)) {
            pr_err("Bad cell count for %pOF\n", dev);
            break;
        }

        pr_debug("parent bus is %s (na=%d, ns=%d) on %pOF\n",
                 pbus->name, pna, pns, parent);

        /* Apply bus translation */
        if (of_translate_one(dev, bus, pbus, addr, na, ns, pna, rprop))
            break;

        /* Complete the move up one level */
        na = pna;
        ns = pns;
        bus = pbus;
    }

 bail:
    of_node_put(parent);
    of_node_put(dev);

    return result;
}

u64 of_translate_address(struct device_node *dev, const __be32 *in_addr)
{
    struct device_node *host;
    u64 ret;

    ret = __of_translate_address(dev, of_get_parent, in_addr, "ranges", &host);
    if (host) {
        of_node_put(host);
        return OF_BAD_ADDR;
    }

    return ret;
}
EXPORT_SYMBOL(of_translate_address);

static u64
of_translate_ioport(struct device_node *dev, const __be32 *in_addr, u64 size)
{
    panic("%s: NO implementation!\n", __func__);
}

static int
__of_address_to_resource(struct device_node *dev, int index, int bar_no,
                         struct resource *r)
{
    u64 taddr;
    const __be32    *addrp;
    u64     size;
    unsigned int    flags;
    const char  *name = NULL;

    addrp = __of_get_address(dev, index, bar_no, &size, &flags);
    if (addrp == NULL)
        return -EINVAL;

    /* Get optional "reg-names" property to add a name to a resource */
    if (index >= 0)
        of_property_read_string_index(dev, "reg-names", index, &name);

    if (flags & IORESOURCE_MEM)
        taddr = of_translate_address(dev, addrp);
    else if (flags & IORESOURCE_IO)
        taddr = of_translate_ioport(dev, addrp, size);
    else
        return -EINVAL;

    if (taddr == OF_BAD_ADDR)
        return -EINVAL;

    memset(r, 0, sizeof(struct resource));

    r->start = taddr;
    r->end = taddr + size - 1;
    r->flags = flags;
    r->name = name ? name : dev->full_name;

    return 0;
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 * @dev:    Caller's Device Node
 * @index:  Index into the array
 * @r:      Pointer to resource array
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called too early or it
 * can't be matched to any host bridge IO space
 */
int of_address_to_resource(struct device_node *dev, int index,
                           struct resource *r)
{
    return __of_address_to_resource(dev, index, -1, r);
}
EXPORT_SYMBOL_GPL(of_address_to_resource);

/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @np:     the device whose io range will be mapped
 * @index:  index of the io range
 *
 * Returns a pointer to the mapped memory
 */
void __iomem *of_iomap(struct device_node *np, int index)
{
    struct resource res;

    if (of_address_to_resource(np, index, &res))
        return NULL;

    if (res.flags & IORESOURCE_MEM_NONPOSTED)
        return ioremap_np(res.start, resource_size(&res));
    else
        return ioremap(res.start, resource_size(&res));
}
EXPORT_SYMBOL(of_iomap);

static struct device_node *__of_get_dma_parent(const struct device_node *np)
{
    struct of_phandle_args args;
    int ret, index;

    index = of_property_match_string(np, "interconnect-names", "dma-mem");
    if (index < 0)
        return of_get_parent(np);

    panic("%s: END!\n", __func__);
#if 0
    ret = of_parse_phandle_with_args(np, "interconnects", "#interconnect-cells",
                                     index, &args);
    if (ret < 0)
        return of_get_parent(np);

    return of_node_get(args.np);
#endif
}

static struct device_node *of_get_next_dma_parent(struct device_node *np)
{
    struct device_node *parent;

    parent = __of_get_dma_parent(np);
    of_node_put(np);

    return parent;
}

/**
 * of_dma_get_range - Get DMA range info and put it into a map array
 * @np:     device node to get DMA range info
 * @map:    dma range structure to return
 *
 * Look in bottom up direction for the first "dma-ranges" property
 * and parse it.  Put the information into a DMA offset map array.
 *
 * dma-ranges format:
 *  DMA addr (dma_addr) : naddr cells
 *  CPU addr (phys_addr_t)  : pna cells
 *  size            : nsize cells
 *
 * It returns -ENODEV if "dma-ranges" property was not found for this
 * device in the DT.
 */
int of_dma_get_range(struct device_node *np, const struct bus_dma_region **map)
{
    struct device_node *node = of_node_get(np);
    const __be32 *ranges = NULL;
    bool found_dma_ranges = false;
#if 0
    struct of_range_parser parser;
    struct of_range range;
#endif
    struct bus_dma_region *r;
    int len, num_ranges = 0;
    int ret = 0;

    while (node) {
        ranges = of_get_property(node, "dma-ranges", &len);

        /* Ignore empty ranges, they imply no translation required */
        if (ranges && len > 0)
            break;

        /* Once we find 'dma-ranges', then a missing one is an error */
        if (found_dma_ranges && !ranges) {
            ret = -ENODEV;
            goto out;
        }
        found_dma_ranges = true;

        node = of_get_next_dma_parent(node);
    }

    if (!node || !ranges) {
        pr_info("no dma-ranges found for node(%pOF)\n", np);
        ret = -ENODEV;
        goto out;
    }

    panic("%s: END!\n", __func__);
 out:
    of_node_put(node);
    return ret;
}

/**
 * of_dma_is_coherent - Check if device is coherent
 * @np: device node
 *
 * It returns true if "dma-coherent" property was found
 * for this device in the DT, or if DMA is coherent by
 * default for OF devices on the current platform.
 */
bool of_dma_is_coherent(struct device_node *np)
{
    struct device_node *node;

    node = of_node_get(np);

    while (node) {
        if (of_property_read_bool(node, "dma-coherent")) {
            of_node_put(node);
            return true;
        }
        node = of_get_next_dma_parent(node);
    }
    of_node_put(node);
    return false;
}
EXPORT_SYMBOL_GPL(of_dma_is_coherent);
