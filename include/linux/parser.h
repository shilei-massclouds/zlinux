/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/include/linux/parser.h
 *
 * Header for lib/parser.c
 * Intended use of these functions is parsing filesystem argument lists,
 * but could potentially be used anywhere else that simple option=arg
 * parsing is required.
 */
#ifndef _LINUX_PARSER_H
#define _LINUX_PARSER_H

/* Maximum number of arguments that match_token will find in a pattern */
enum {MAX_OPT_ARGS = 3};

/* Describe the location within a string of a substring */
typedef struct {
    char *from;
    char *to;
} substring_t;

#endif /* _LINUX_PARSER_H */
