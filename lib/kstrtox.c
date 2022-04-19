// SPDX-License-Identifier: GPL-2.0
/*
 * Convert integer string representation to an integer.
 * If an integer doesn't fit into specified type, -E is returned.
 *
 * Integer starts with optional sign.
 * kstrtou*() functions do not accept sign "-".
 *
 * Radix 0 means autodetection: leading "0x" implies radix 16,
 * leading "0" implies radix 8, otherwise radix is 10.
 * Autodetection hints work after optional sign, but not before.
 *
 * If -E is returned, result is not touched.
 */
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
//#include <linux/math64.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "kstrtox.h"

const char *_parse_integer_fixup_radix(const char *s, unsigned int *base)
{
    if (*base == 0) {
        if (s[0] == '0') {
            if (_tolower(s[1]) == 'x' && isxdigit(s[2]))
                *base = 16;
            else
                *base = 8;
        } else
            *base = 10;
    }
    if (*base == 16 && s[0] == '0' && _tolower(s[1]) == 'x')
        s += 2;
    return s;
}

/*
 * Convert non-negative integer string representation in explicitly given radix
 * to an integer.
 * Return number of characters consumed maybe or-ed with overflow bit.
 * If overflow occurs, result integer (incorrect) is still returned.
 *
 * Don't you dare use this function.
 */
unsigned int
_parse_integer(const char *s, unsigned int base, unsigned long long *p)
{
    unsigned long long res;
    unsigned int rv;

    res = 0;
    rv = 0;
    while (1) {
        unsigned int c = *s;
        unsigned int lc = c | 0x20; /* don't tolower() this line */
        unsigned int val;

        if ('0' <= c && c <= '9')
            val = c - '0';
        else if ('a' <= lc && lc <= 'f')
            val = lc - 'a' + 10;
        else
            break;

        if (val >= base)
            break;
        res = res * base + val;
        rv++;
        s++;
    }
    *p = res;
    return rv;
}
