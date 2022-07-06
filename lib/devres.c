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

    panic("%s: END!\n", __func__);
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
