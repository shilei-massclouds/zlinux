// SPDX-License-Identifier: GPL-2.0

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/err.h>
#if 0
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/gpio.h>
#endif
#include <linux/idr.h>
#include <linux/slab.h>
#if 0
#include <linux/acpi.h>
#include <linux/gpio/driver.h>
#include <linux/pinctrl/consumer.h>
#endif
#include <linux/gpio/machine.h>
#include <linux/fs.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/property.h>
#include <linux/of.h>
//#include <uapi/linux/gpio.h>

#include "gpiolib.h"
#include "gpiolib-of.h"
#if 0
#include "gpiolib-acpi.h"
#include "gpiolib-cdev.h"
#include "gpiolib-sysfs.h"
#endif

#define CREATE_TRACE_POINTS
//#include <trace/events/gpio.h>

/**
 * gpiod_get_index - obtain a GPIO from a multi-index GPIO function
 * @dev:    GPIO consumer, can be NULL for system-global GPIOs
 * @con_id: function within the GPIO consumer
 * @idx:    index of the GPIO to obtain in the consumer
 * @flags:  optional GPIO initialization flags
 *
 * This variant of gpiod_get() allows to access GPIOs other than the first
 * defined one for functions that define several GPIOs.
 *
 * Return a valid GPIO descriptor, -ENOENT if no GPIO has been assigned to the
 * requested function and/or index, or another IS_ERR() code if an error
 * occurred while trying to acquire the GPIO.
 */
struct gpio_desc *__must_check
gpiod_get_index(struct device *dev,
                const char *con_id,
                unsigned int idx,
                enum gpiod_flags flags)
{
    unsigned long lookupflags = GPIO_LOOKUP_FLAGS_DEFAULT;
    struct gpio_desc *desc = NULL;
    int ret;
    /* Maybe we have a device name, maybe not */
    const char *devname = dev ? dev_name(dev) : "?";
    const struct fwnode_handle *fwnode = dev ? dev_fwnode(dev) : NULL;

    dev_dbg(dev, "GPIO lookup for consumer %s\n", con_id);

    /* Using device tree? */
    if (is_of_node(fwnode)) {
        dev_dbg(dev, "using device tree for GPIO lookup\n");
        desc = of_find_gpio(dev, con_id, idx, &lookupflags);
    }

#if 0
    /*
     * Either we are not using DT or ACPI, or their lookup did not return
     * a result. In that case, use platform lookup as a fallback.
     */
    if (!desc || gpiod_not_found(desc)) {
        dev_dbg(dev, "using lookup tables for GPIO lookup\n");
        desc = gpiod_find(dev, con_id, idx, &lookupflags);
    }

    if (IS_ERR(desc)) {
        dev_dbg(dev, "No GPIO consumer %s found\n", con_id);
        return desc;
    }

    /*
     * If a connection label was passed use that, else attempt to use
     * the device name as label
     */
    ret = gpiod_request(desc, con_id ?: devname);
    if (ret) {
        if (!(ret == -EBUSY && flags & GPIOD_FLAGS_BIT_NONEXCLUSIVE))
            return ERR_PTR(ret);

        /*
         * This happens when there are several consumers for
         * the same GPIO line: we just return here without
         * further initialization. It is a bit of a hack.
         * This is necessary to support fixed regulators.
         *
         * FIXME: Make this more sane and safe.
         */
        dev_info(dev, "nonexclusive access to GPIO for %s\n", con_id ?: devname);
        return desc;
    }

    ret = gpiod_configure_flags(desc, con_id, lookupflags, flags);
    if (ret < 0) {
        dev_dbg(dev, "setup of GPIO %s failed\n", con_id);
        gpiod_put(desc);
        return ERR_PTR(ret);
    }

    blocking_notifier_call_chain(&desc->gdev->notifier,
                     GPIOLINE_CHANGED_REQUESTED, desc);

    return desc;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(gpiod_get_index);
