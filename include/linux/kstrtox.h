/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KSTRTOX_H
#define _LINUX_KSTRTOX_H

#include <linux/compiler.h>
#include <linux/types.h>

/* Internal, do not use. */
int __must_check
_kstrtoul(const char *s, unsigned int base, unsigned long *res);

int __must_check _kstrtol(const char *s, unsigned int base, long *res);

int __must_check
kstrtoull(const char *s, unsigned int base, unsigned long long *res);

int __must_check kstrtoll(const char *s, unsigned int base, long long *res);

int __must_check
kstrtouint(const char *s, unsigned int base, unsigned int *res);

int __must_check kstrtoint(const char *s, unsigned int base, int *res);

#endif  /* _LINUX_KSTRTOX_H */
