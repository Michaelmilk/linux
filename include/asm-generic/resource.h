#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

/*
 * Resource limit IDs
 *
 * ( Compatibility detail: there are architectures that have
 *   a different rlimit ID order in the 5-9 range and want
 *   to keep that order for binary compatibility. The reasons
 *   are historic and all new rlimits are identical across all
 *   arches. If an arch has such special order for some rlimits
 *   then it defines them prior including asm-generic/resource.h. )
 */

/* 按秒计的最大CPU时间 */
#define RLIMIT_CPU		0	/* CPU time in sec */
/* 最大文件长度 */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
/* 数据段最大长度 */
#define RLIMIT_DATA		2	/* max data size */
/* 用户态栈最大长度 */
#define RLIMIT_STACK		3	/* max stack size */
/* 内核转储文件最大长度 */
#define RLIMIT_CORE		4	/* max core file size */

/* 常驻内存的最大大小 */
#ifndef RLIMIT_RSS
# define RLIMIT_RSS		5	/* max resident set size */
#endif

/* 与进程真正UID关联的用户可以拥有的进程的最大数目 */
#ifndef RLIMIT_NPROC
# define RLIMIT_NPROC		6	/* max number of processes */
#endif

/* 打开文件的最大数目 */
#ifndef RLIMIT_NOFILE
# define RLIMIT_NOFILE		7	/* max number of open files */
#endif

/* 不可换出页的最大数目 */
#ifndef RLIMIT_MEMLOCK
# define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#endif

/* 进程占用的虚拟地址空间的最大大小 */
#ifndef RLIMIT_AS
# define RLIMIT_AS		9	/* address space limit */
#endif

/* 文件锁的最大数目 */
#define RLIMIT_LOCKS		10	/* maximum file locks held */
/* 待决信号的最大数目 */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
/* 消息队列的最大大小 */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
/* 非实时进程优先级对应的nice */
#define RLIMIT_NICE		13	/* max nice prio allowed to raise to
					   0-39 for nice level 19 .. -20 */
/* 最大的实时优先级 */
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */
#define RLIMIT_RTTIME		15	/* timeout for RT tasks in us */
#define RLIM_NLIMITS		16

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#ifndef RLIM_INFINITY
# define RLIM_INFINITY		(~0UL)
#endif

/*
 * RLIMIT_STACK default maximum - some architectures override it:
 */
#ifndef _STK_LIM_MAX
# define _STK_LIM_MAX		RLIM_INFINITY
#endif

#ifdef __KERNEL__

/*
 * boot-time rlimit defaults for the init task:
 */
#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_DATA]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {       _STK_LIM,   _STK_LIM_MAX },	\
	[RLIMIT_CORE]		= {              0,  RLIM_INFINITY },	\
	[RLIMIT_RSS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {              0,              0 },	\
	[RLIMIT_NOFILE]		= {   INR_OPEN_CUR,   INR_OPEN_MAX },	\
	[RLIMIT_MEMLOCK]	= {    MLOCK_LIMIT,    MLOCK_LIMIT },	\
	[RLIMIT_AS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { 		0,	       0 },	\
	[RLIMIT_MSGQUEUE]	= {   MQ_BYTES_MAX,   MQ_BYTES_MAX },	\
	[RLIMIT_NICE]		= { 0, 0 },				\
	[RLIMIT_RTPRIO]		= { 0, 0 },				\
	[RLIMIT_RTTIME]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
}

#endif	/* __KERNEL__ */

#endif
