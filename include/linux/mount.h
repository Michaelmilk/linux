/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

/* 禁止执行setuid */
#define MNT_NOSUID	0x01
/* 没有对应的物理设备，如虚拟文件系统，设置该标志 */
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20
#define MNT_READONLY	0x40	/* does the user want this to be r/o? */

#define MNT_SHRINKABLE	0x100
#define MNT_WRITE_HOLD	0x200

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
/*
 * MNT_SHARED_MASK is the set of flags that should be cleared when a
 * mount becomes shared.  Currently, this is only the flag that says a
 * mount cannot be bind mounted, since this is how we create a mount
 * that shares events with another mount.  If you add a new MNT_*
 * flag, consider how it interacts with shared mounts.
 */
#define MNT_SHARED_MASK	(MNT_UNBINDABLE)
#define MNT_PROPAGATION_MASK	(MNT_SHARED | MNT_UNBINDABLE)

#define MNT_INTERNAL_FLAGS (MNT_SHARED | MNT_WRITE_HOLD | MNT_INTERNAL | \
			    MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED)

#define MNT_INTERNAL	0x4000

#define MNT_LOCK_READONLY	0x400000
#define MNT_LOCKED		0x800000
#define MNT_DOOMED		0x1000000
#define MNT_SYNC_UMOUNT		0x2000000
#define MNT_MARKED		0x4000000

/*
对于每一个mount的文件系统，都由一个vfsmount实例来表示

对于某个文件系统实例，内存中super_block和vfsmount都是唯一的。
比如，我们将某个挂载硬盘分区mount -t vfat /dev/hda2 /mnt/d。
实际上就是新建一个vfsmount结构作为连接件，
vfsmount->mnt_sb = /dev/hda2的超级块结构；
vfsmount->mntroot = /dev/hda2的"根"目录的dentry；
vfsmount->mnt_mountpoint = /mnt/d的dentry； 
vfsmount->mnt_parent = /mnt/d所属的文件系统的vfsmount。
并且把这个新建的vfsmount链入一个全局的hash表mount_hashtable中。
*/

struct vfsmount {
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* pointer to superblock */
	int mnt_flags;
};

struct file; /* forward dec */

extern int mnt_want_write(struct vfsmount *mnt);
extern int mnt_want_write_file(struct file *file);
extern int mnt_clone_write(struct vfsmount *mnt);
extern void mnt_drop_write(struct vfsmount *mnt);
extern void mnt_drop_write_file(struct file *file);
extern void mntput(struct vfsmount *mnt);
extern struct vfsmount *mntget(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);
extern int __mnt_is_readonly(struct vfsmount *mnt);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

extern void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list);
extern void mark_mounts_for_expiry(struct list_head *mounts);

extern dev_t name_to_dev_t(char *name);

#endif /* _LINUX_MOUNT_H */
