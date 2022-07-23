// SPDX-License-Identifier: GPL-2.0-only
/*
 * "splice": joining two ropes together by interweaving their strands.
 *
 * This is the "extended pipe" functionality, where a pipe is used as
 * an arbitrary in-memory buffer. Think of a pipe as a small kernel
 * buffer that you can use to transfer data from one end to the other.
 *
 * The traditional unix read/write is extended with a "splice()" operation
 * that transfers data buffers to or from a pipe buffer.
 *
 * Named by Larry McVoy, original implementation from Linus, extended by
 * Jens to support splicing to files, network, direct splicing, etc and
 * fixing lots of bugs.
 *
 * Copyright (C) 2005-2006 Jens Axboe <axboe@kernel.dk>
 * Copyright (C) 2005-2006 Linus Torvalds <torvalds@osdl.org>
 * Copyright (C) 2006 Ingo Molnar <mingo@elte.hu>
 *
 */

#include <linux/bvec.h>
#include <linux/fs.h>
//#include <linux/file.h>
#include <linux/pagemap.h>
#if 0
#include <linux/splice.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#endif
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/export.h>
#if 0
#include <linux/syscalls.h>
#include <linux/uio.h>
#include <linux/security.h>
#include <linux/socket.h>
#endif
#include <linux/gfp.h>
#include <linux/sched/signal.h>

#include "internal.h"

/**
 * generic_file_splice_read - splice data from file to a pipe
 * @in:     file to splice from
 * @ppos:   position in @in
 * @pipe:   pipe to splice to
 * @len:    number of bytes to splice
 * @flags:  splice modifier flags
 *
 * Description:
 *    Will read pages from given file and fill them into a pipe. Can be
 *    used as long as it has more or less sane ->read_iter().
 *
 */
ssize_t generic_file_splice_read(struct file *in, loff_t *ppos,
                                 struct pipe_inode_info *pipe, size_t len,
                                 unsigned int flags)
{
    panic("%s: END!\n", __func__);
}

/**
 * iter_file_splice_write - splice data from a pipe to a file
 * @pipe:   pipe info
 * @out:    file to write to
 * @ppos:   position in @out
 * @len:    number of bytes to splice
 * @flags:  splice modifier flags
 *
 * Description:
 *    Will either move or copy pages (determined by @flags options) from
 *    the given pipe inode to the given file.
 *    This one is ->write_iter-based.
 *
 */
ssize_t
iter_file_splice_write(struct pipe_inode_info *pipe, struct file *out,
                       loff_t *ppos, size_t len, unsigned int flags)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(iter_file_splice_write);

