// SPDX-License-Identifier: GPL-2.0-only
/*
 * Helpers for formatting and printing strings
 *
 * Copyright 31 August 2008 James Bottomley
 * Copyright (C) 2013, Intel Corporation
 */
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/export.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/errno.h>
#if 0
#include <linux/fs.h>
#endif
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/string_helpers.h>

/**
 * strreplace - Replace all occurrences of character in string.
 * @s: The string to operate on.
 * @old: The character being replaced.
 * @new: The character @old is replaced with.
 *
 * Returns pointer to the nul byte at the end of @s.
 */
char *strreplace(char *s, char old, char new)
{
    for (; *s; ++s)
        if (*s == old)
            *s = new;
    return s;
}
EXPORT_SYMBOL(strreplace);
