/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <linux/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

struct fdtable {
	/* 进程所能处理的文件描述符最大数目 */
	unsigned int max_fds;
	/* 指针数组，每个指针指向一个file结构实例
	   由文件描述符的值作为数组的索引 */
	struct file __rcu **fd;      /* current fd array */
	/* 进程退出时需要关闭的文件描述符位图 */
	unsigned long *close_on_exec;
	/* 打开的文件描述符位图 */
	unsigned long *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

static inline void __set_close_on_exec(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

static inline void __clear_close_on_exec(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->close_on_exec);
}

static inline bool close_on_exec(int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->close_on_exec);
}

static inline void __set_open_fd(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
}

/*
清除@fd对应的bit位
*/
static inline void __clear_open_fd(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
}

static inline bool fd_is_open(int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->open_fds);
}

/*
 * Open file table structure
 */
/*
该结构体由进程描述符中的files域指向。
所有与每个进程相关的信息，如打开的文件及文件描述符都包含在其中
*/
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	/* 指向文件表 */
	struct fdtable __rcu *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	/* 下一次打开文件时使用的文件描述符 */
	int next_fd;
	unsigned long close_on_exec_init[1];
	unsigned long open_fds_init[1];
	/* 指针数组，指向每个打开的文件struct file实例 */
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
};

#define rcu_dereference_check_fdtable(files, fdtfd) \
	(rcu_dereference_check((fdtfd), \
			       lockdep_is_held(&(files)->file_lock) || \
			       atomic_read(&(files)->count) == 1 || \
			       rcu_my_thread_group_empty()))

#define files_fdtable(files) \
		(rcu_dereference_check_fdtable((files), (files)->fdt))

struct file_operations;
struct vfsmount;
struct dentry;

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable_rcu(struct rcu_head *rcu);
extern void __init files_defer_init(void);

static inline void free_fdtable(struct fdtable *fdt)
{
	call_rcu(&fdt->rcu, free_fdtable_rcu);
}

/*
取@fd对应的file结构
*/
static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference_check_fdtable(files, fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, int *);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
