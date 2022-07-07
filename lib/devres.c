// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/of_address.h>

enum devm_ioremap_type {
    DEVM_IOREMAP = 0,
    DEVM_IOREMAP_UC,
    DEVM_IOREMAP_WC,
    DEVM_IOREMAP_NP,
};

void devm_ioremap_release(struct device *dev, void *res)
{
    iounmap(*(void __iomem **)res);
}

static void __iomem *
__devm_ioremap(struct device *dev, resource_size_t offset,
               resource_size_t size,
               enum devm_ioremap_type type)
{
    void __iomem **ptr, *addr = NULL;

    ptr = devres_alloc(devm_ioremap_release, sizeof(*ptr), GFP_KERNEL);
    if (!ptr)
        return NULL;

    switch (type) {
    case DEVM_IOREMAP:
        addr = ioremap(offset, size);
        break;
    case DEVM_IOREMAP_UC:
        panic("%s: NO DEVM_IOREMAP_UC!\n", __func__);
        //addr = ioremap_uc(offset, size);
        break;
    case DEVM_IOREMAP_WC:
        panic("%s: NO DEVM_IOREMAP_WC!\n", __func__);
        //addr = ioremap_wc(offset, size);
        break;
    case DEVM_IOREMAP_NP:
        panic("%s: NO DEVM_IOREMAP_NP!\n", __func__);
        //addr = ioremap_np(offset, size);
        break;
    }

    if (addr) {
        *ptr = addr;
        devres_add(dev, ptr);
    } else
        devres_free(ptr);

    return addr;
}

static void __iomem *
__devm_ioremap_resource(struct device *dev, const struct resource *res,
                        enum devm_ioremap_type type)
{
    resource_size_t size;
    void __iomem *dest_ptr;
    char *pretty_name;

    BUG_ON(!dev);

    if (!res || resource_type(res) != IORESOURCE_MEM) {
        pr_err("invalid resource\n");
        return IOMEM_ERR_PTR(-EINVAL);
    }

    if (type == DEVM_IOREMAP && res->flags & IORESOURCE_MEM_NONPOSTED)
        type = DEVM_IOREMAP_NP;

    size = resource_size(res);

    if (res->name)
        pretty_name = devm_kasprintf(dev, GFP_KERNEL, "%s %s",
                                     dev_name(dev), res->name);
    else
        pretty_name = devm_kstrdup(dev, dev_name(dev), GFP_KERNEL);
    if (!pretty_name) {
        pr_err("can't generate pretty name for resource %pR\n", res);
        return IOMEM_ERR_PTR(-ENOMEM);
    }

    if (!devm_request_mem_region(dev, res->start, size, pretty_name)) {
        pr_err("can't request region for resource %pR\n", res);
        return IOMEM_ERR_PTR(-EBUSY);
    }

    dest_ptr = __devm_ioremap(dev, res->start, size, type);
    if (!dest_ptr) {
        pr_err("ioremap failed for resource %pR\n", res);
        devm_release_mem_region(dev, res->start, size);
        dest_ptr = IOMEM_ERR_PTR(-ENOMEM);
    }

    return dest_ptr;
}

/**
 * devm_ioremap_resource() - check, request region, and ioremap resource
 * @dev: generic device to handle the resource for
 * @res: resource to be handled
 *
 * Checks that a resource is a valid memory region, requests the memory
 * region and ioremaps it. All operations are managed and will be undone
 * on driver detach.
 *
 * Usage example:
 *
 *  res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
 *  base = devm_ioremap_resource(&pdev->dev, res);
 *  if (IS_ERR(base))
 *      return PTR_ERR(base);
 *
 * Return: a pointer to the remapped memory or an ERR_PTR() encoded error code
 * on failure.
 */
void __iomem *devm_ioremap_resource(struct device *dev,
                                    const struct resource *res)
{
    return __devm_ioremap_resource(dev, res, DEVM_IOREMAP);
}
EXPORT_SYMBOL(devm_ioremap_resource);
