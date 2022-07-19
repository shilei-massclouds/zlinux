/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_EXPORTFS_H
#define LINUX_EXPORTFS_H 1

#include <linux/types.h>

struct dentry;
struct iattr;
struct inode;
struct iomap;
struct super_block;
struct vfsmount;

/**
 * struct export_operations - for nfsd to communicate with file systems
 * @encode_fh:      encode a file handle fragment from a dentry
 * @fh_to_dentry:   find the implied object and get a dentry for it
 * @fh_to_parent:   find the implied object's parent and get a dentry for it
 * @get_name:       find the name for a given inode in a given directory
 * @get_parent:     find the parent of a given directory
 * @commit_metadata: commit metadata changes to stable storage
 *
 * See Documentation/filesystems/nfs/exporting.rst for details on how to use
 * this interface correctly.
 *
 * encode_fh:
 *    @encode_fh should store in the file handle fragment @fh (using at most
 *    @max_len bytes) information that can be used by @decode_fh to recover the
 *    file referred to by the &struct dentry @de.  If the @connectable flag is
 *    set, the encode_fh() should store sufficient information so that a good
 *    attempt can be made to find not only the file but also it's place in the
 *    filesystem.   This typically means storing a reference to de->d_parent in
 *    the filehandle fragment.  encode_fh() should return the fileid_type on
 *    success and on error returns 255 (if the space needed to encode fh is
 *    greater than @max_len*4 bytes). On error @max_len contains the minimum
 *    size(in 4 byte unit) needed to encode the file handle.
 *
 * fh_to_dentry:
 *    @fh_to_dentry is given a &struct super_block (@sb) and a file handle
 *    fragment (@fh, @fh_len). It should return a &struct dentry which refers
 *    to the same file that the file handle fragment refers to.  If it cannot,
 *    it should return a %NULL pointer if the file cannot be found, or an
 *    %ERR_PTR error code of %ENOMEM if a memory allocation failure occurred.
 *    Any other error code is treated like %NULL, and will cause an %ESTALE error
 *    for callers of exportfs_decode_fh().
 *    Any suitable dentry can be returned including, if necessary, a new dentry
 *    created with d_alloc_root.  The caller can then find any other extant
 *    dentries by following the d_alias links.
 *
 * fh_to_parent:
 *    Same as @fh_to_dentry, except that it returns a pointer to the parent
 *    dentry if it was encoded into the filehandle fragment by @encode_fh.
 *
 * get_name:
 *    @get_name should find a name for the given @child in the given @parent
 *    directory.  The name should be stored in the @name (with the
 *    understanding that it is already pointing to a %NAME_MAX+1 sized
 *    buffer.   get_name() should return %0 on success, a negative error code
 *    or error.  @get_name will be called without @parent->i_mutex held.
 *
 * get_parent:
 *    @get_parent should find the parent directory for the given @child which
 *    is also a directory.  In the event that it cannot be found, or storage
 *    space cannot be allocated, a %ERR_PTR should be returned.
 *
 * commit_metadata:
 *    @commit_metadata should commit metadata changes to stable storage.
 *
 * Locking rules:
 *    get_parent is called with child->d_inode->i_mutex down
 *    get_name is not (which is possibly inconsistent)
 */
struct export_operations {
    int (*encode_fh)(struct inode *inode, __u32 *fh, int *max_len,
                     struct inode *parent);
    struct dentry * (*fh_to_dentry)(struct super_block *sb, struct fid *fid,
                                    int fh_len, int fh_type);
    struct dentry * (*fh_to_parent)(struct super_block *sb, struct fid *fid,
                                    int fh_len, int fh_type);
    int (*get_name)(struct dentry *parent, char *name, struct dentry *child);
    struct dentry * (*get_parent)(struct dentry *child);
    int (*commit_metadata)(struct inode *inode);

    int (*get_uuid)(struct super_block *sb, u8 *buf, u32 *len, u64 *offset);
    int (*map_blocks)(struct inode *inode, loff_t offset,
                      u64 len, struct iomap *iomap,
                      bool write, u32 *device_generation);
    int (*commit_blocks)(struct inode *inode, struct iomap *iomaps,
                         int nr_iomaps, struct iattr *iattr);
    u64 (*fetch_iversion)(struct inode *);
#define EXPORT_OP_NOWCC         (0x1) /* don't collect v3 wcc data */
#define EXPORT_OP_NOSUBTREECHK      (0x2) /* no subtree checking */
#define EXPORT_OP_CLOSE_BEFORE_UNLINK   (0x4) /* close files before unlink */
#define EXPORT_OP_REMOTE_FS     (0x8) /* Filesystem is remote */
#define EXPORT_OP_NOATOMIC_ATTR     (0x10) /* Filesystem cannot supply
                                              atomic attribute updates
                                            */
    unsigned long   flags;
};

#endif /* LINUX_EXPORTFS_H */
