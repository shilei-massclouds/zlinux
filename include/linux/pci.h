/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  pci.h
 *
 *  PCI defines and function prototypes
 *  Copyright 1994, Drew Eckhardt
 *  Copyright 1997--1999 Martin Mares <mj@ucw.cz>
 *
 *  PCI Express ASPM defines and function prototypes
 *  Copyright (c) 2007 Intel Corp.
 *      Zhang Yanmin (yanmin.zhang@intel.com)
 *      Shaohua Li (shaohua.li@intel.com)
 *
 *  For more information, please consult the following manuals (look at
 *  http://www.pcisig.com/ for how to get them):
 *
 *  PCI BIOS Specification
 *  PCI Local Bus Specification
 *  PCI to PCI Bridge Specification
 *  PCI Express Specification
 *  PCI System Design Guide
 */
#ifndef LINUX_PCI_H
#define LINUX_PCI_H

#include <linux/mod_devicetable.h>

#include <linux/types.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/atomic.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#if 0
#include <linux/resource_ext.h>
#include <uapi/linux/pci.h>

#include <linux/pci_ids.h>
#endif

#define dev_is_pci(d) ((d)->bus == &pci_bus_type)

extern struct bus_type pci_bus_type;

#endif /* LINUX_PCI_H */
