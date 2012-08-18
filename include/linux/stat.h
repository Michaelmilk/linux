#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H

#ifdef __KERNEL__

#include <asm/stat.h>

#endif

#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

/* 文件类型的bit位掩码 */
#define S_IFMT  00170000
/* socket文件 */
#define S_IFSOCK 0140000
/* 链接文件 */
#define S_IFLNK	 0120000
/* 普通文件 */
#define S_IFREG  0100000
/* 块设备 */
#define S_IFBLK  0060000
/* 目录文件 */
#define S_IFDIR  0040000
/* 字符设备 */
#define S_IFCHR  0020000
/* 管道文件 */
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

/* 是否为链接文件 */
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
/* 是否为普通文件 */
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
/* 是否为目录文件 */
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

/* 文件所有者可读，可写，可执行 */
#define S_IRWXU 00700
/* 文件所有者可读 */
#define S_IRUSR 00400
/* 文件所有者可写 */
#define S_IWUSR 00200
/* 文件所有者可执行 */
#define S_IXUSR 00100

/* 组用户 */
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

/* 其他用户 */
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#endif

#ifdef __KERNEL__
/* 0x777模式 */
#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
/* 文件所有者，组用户，其他用户均可读 */
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
/* 文件所有者，组用户，其他用户均可写 */
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
/* 文件所有者，组用户，其他用户均可执行 */
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define UTIME_NOW	((1l << 30) - 1l)
#define UTIME_OMIT	((1l << 30) - 2l)

#include <linux/types.h>
#include <linux/time.h>
#include <linux/uidgid.h>

struct kstat {
	u64		ino;
	dev_t		dev;
	umode_t		mode;
	unsigned int	nlink;
	kuid_t		uid;
	kgid_t		gid;
	dev_t		rdev;
	loff_t		size;
	struct timespec  atime;
	struct timespec	mtime;
	struct timespec	ctime;
	unsigned long	blksize;
	unsigned long long	blocks;
};

#endif

#endif
