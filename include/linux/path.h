#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

/*
封装在一起的路径信息
*/
struct path {
	/* 指向dentry对应的一个已经装载的文件系统 */
	struct vfsmount *mnt;
	/* 指向缓存的目录 */
	struct dentry *dentry;
};

extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

#endif  /* _LINUX_PATH_H */
