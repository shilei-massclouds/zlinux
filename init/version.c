// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/version.c
 *
 *  Copyright (C) 1992  Theodore Ts'o
 *
 *  May be freely distributed as part of Linux.
 */

#include <generated/compile.h>
#include <linux/build-salt.h>
#include <linux/export.h>
/*
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
*/
#include <generated/utsrelease.h>

/* FIXED STRINGS! Don't touch! */
const char linux_banner[] =
    "Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
    LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";

BUILD_SALT;
