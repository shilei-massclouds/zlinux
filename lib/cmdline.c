// SPDX-License-Identifier: GPL-2.0-only
/*
 * linux/lib/cmdline.c
 * Helper functions generally used for parsing kernel command line
 * and module options.
 *
 * Code and copyrights come from init/main.c and arch/i386/kernel/setup.c.
 *
 * GNU Indent formatting options for this file: -kr -i8 -npsl -pcs
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>

/*
 * Parse a string to get a param value pair.
 * You can use " around spaces, but can't escape ".
 * Hyphens and underscores equivalent in parameter names.
 */
char *next_arg(char *args, char **param, char **val)
{
    unsigned int i, equals = 0;
    int in_quote = 0, quoted = 0;
    char *next;

    if (*args == '"') {
        args++;
        in_quote = 1;
        quoted = 1;
    }

    for (i = 0; args[i]; i++) {
        if (isspace(args[i]) && !in_quote)
            break;
        if (equals == 0) {
            if (args[i] == '=')
                equals = i;
        }
        if (args[i] == '"')
            in_quote = !in_quote;
    }

    *param = args;
    if (!equals)
        *val = NULL;
    else {
        args[equals] = '\0';
        *val = args + equals + 1;

        /* Don't include quotes in value. */
        if (**val == '"') {
            (*val)++;
            if (args[i-1] == '"')
                args[i-1] = '\0';
        }
    }
    if (quoted && args[i-1] == '"')
        args[i-1] = '\0';

    if (args[i]) {
        args[i] = '\0';
        next = args + i + 1;
    } else
        next = args + i;

    /* Chew up trailing spaces. */
    return skip_spaces(next);
}
