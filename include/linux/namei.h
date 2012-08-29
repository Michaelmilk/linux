#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/dcache.h>
#include <linux/linkage.h>
#include <linux/path.h>

struct vfsmount;

enum { MAX_NESTED_LINKS = 8 };

/*
在递归寻找目标节点的过程中，需要借助一个搜索辅助结构nameidata，
这是一个临时结构，仅仅用在寻找目标节点的过程中。
*/
struct nameidata {
	/* 上层目录 */
	struct path	path;
	/* 路径的最后一个部分 */
	struct qstr	last;
	/* 已安装文件系统的根目录 */
	struct path	root;
	/* 第一个字段@path的path.dentry.d_inode */
	struct inode	*inode; /* path.dentry.d_inode */
	/* 查找标志 */
	unsigned int	flags;
	unsigned	seq;
	/* 路径名称最后一部分的类型 */
	int		last_type;
	/* 符号链接的嵌套深度 */
	unsigned	depth;
	/* 与嵌套的符号链接关联的路径名数组 */
	char *saved_names[MAX_NESTED_LINKS + 1];
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
/*
@LAST_NORM	: 最后一个部分是普通文件名
@LAST_ROOT	: '/'
@LAST_DOT	: '.'
@LAST_DOTDOT	: '..'
@LAST_BIND	: 符号链接
*/
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path components" flag
 *  - dentry cache is untrusted; force a real lookup
 *  - suppress terminal automount
 */
/* 路径最后一个部分是链接，则继续跟踪该链接 */
#define LOOKUP_FOLLOW		0x0001
/* 路径最后一个部分必须是目录 */
#define LOOKUP_DIRECTORY	0x0002
#define LOOKUP_AUTOMOUNT	0x0004

#define LOOKUP_PARENT		0x0010
#define LOOKUP_REVAL		0x0020
#define LOOKUP_RCU		0x0040

/*
 * Intent data
 */
/* 试图打开一个文件 */
#define LOOKUP_OPEN		0x0100
/* 试图创建一个文件 */
#define LOOKUP_CREATE		0x0200
#define LOOKUP_EXCL		0x0400
#define LOOKUP_RENAME_TARGET	0x0800

#define LOOKUP_JUMPED		0x1000
#define LOOKUP_ROOT		0x2000
#define LOOKUP_EMPTY		0x4000

extern int user_path_at(int, const char __user *, unsigned, struct path *);
extern int user_path_at_empty(int, const char __user *, unsigned, struct path *, int *empty);

#define user_path(name, path) user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, path)
#define user_lpath(name, path) user_path_at(AT_FDCWD, name, 0, path)
#define user_path_dir(name, path) \
	user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, path)

extern int kern_path(const char *, unsigned, struct path *);

extern struct dentry *kern_path_create(int, const char *, struct path *, int);
extern struct dentry *user_path_create(int, const char __user *, struct path *, int);
extern void done_path_create(struct path *, struct dentry *);
extern struct dentry *kern_path_locked(const char *, struct path *);
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct path *);

extern struct dentry *lookup_one_len(const char *, struct dentry *, int);

extern int follow_down_one(struct path *);
extern int follow_down(struct path *);
extern int follow_up(struct path *);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

extern void nd_jump_link(struct nameidata *nd, struct path *path);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

static inline void nd_terminate_link(void *name, size_t len, size_t maxlen)
{
	((char *) name)[min(len, maxlen)] = '\0';
}

#endif /* _LINUX_NAMEI_H */
