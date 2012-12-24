#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#define __EXPORTED_HEADERS__
#include <uapi/linux/types.h>

#ifndef __ASSEMBLY__

/*
����һ��λͼ
�Ƚ�bit�ĸ���ת������Ҫ����long����
Ȼ����һ��long�������ʾ
*/
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

typedef __u32 __kernel_dev_t;

typedef __kernel_fd_set		fd_set;
typedef __kernel_dev_t		dev_t;
typedef __kernel_ino_t		ino_t;
typedef __kernel_mode_t		mode_t;
typedef unsigned short		umode_t;
typedef __u32			nlink_t;
typedef __kernel_off_t		off_t;
typedef __kernel_pid_t		pid_t;
typedef __kernel_daddr_t	daddr_t;
typedef __kernel_key_t		key_t;
typedef __kernel_suseconds_t	suseconds_t;
typedef __kernel_timer_t	timer_t;
typedef __kernel_clockid_t	clockid_t;
typedef __kernel_mqd_t		mqd_t;

typedef _Bool			bool;

typedef __kernel_uid32_t	uid_t;
typedef __kernel_gid32_t	gid_t;
typedef __kernel_uid16_t        uid16_t;
typedef __kernel_gid16_t        gid16_t;

typedef unsigned long		uintptr_t;

#ifdef CONFIG_UID16
/* This is defined by include/asm-{arch}/posix_types.h */
typedef __kernel_old_uid_t	old_uid_t;
typedef __kernel_old_gid_t	old_gid_t;
#endif /* CONFIG_UID16 */

#if defined(__GNUC__)
typedef __kernel_loff_t		loff_t;
#endif

/*
 * The following typedefs are also protected by individual ifdefs for
 * historical reasons:
 */
#ifndef _SIZE_T
#define _SIZE_T
typedef __kernel_size_t		size_t;
#endif

#ifndef _SSIZE_T
#define _SSIZE_T
typedef __kernel_ssize_t	ssize_t;
#endif

#ifndef _PTRDIFF_T
#define _PTRDIFF_T
typedef __kernel_ptrdiff_t	ptrdiff_t;
#endif

#ifndef _TIME_T
#define _TIME_T
/*
time_t���з��ŵ�32λ��
*/
typedef __kernel_time_t		time_t;
#endif

#ifndef _CLOCK_T
#define _CLOCK_T
typedef __kernel_clock_t	clock_t;
#endif

#ifndef _CADDR_T
#define _CADDR_T
typedef __kernel_caddr_t	caddr_t;
#endif

/* bsd */
typedef unsigned char		u_char;
typedef unsigned short		u_short;
typedef unsigned int		u_int;
typedef unsigned long		u_long;

/* sysv */
typedef unsigned char		unchar;
typedef unsigned short		ushort;
typedef unsigned int		uint;
typedef unsigned long		ulong;

#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__

typedef		__u8		u_int8_t;
typedef		__s8		int8_t;
typedef		__u16		u_int16_t;
typedef		__s16		int16_t;
typedef		__u32		u_int32_t;
typedef		__s32		int32_t;

#endif /* !(__BIT_TYPES_DEFINED__) */

typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;

#if defined(__GNUC__)
typedef		__u64		uint64_t;
typedef		__u64		u_int64_t;
typedef		__s64		int64_t;
#endif

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64 __u64 __attribute__((aligned(8)))
#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))

/**
 * The type used for indexing onto a disc or disc partition.
 *
 * Linux always considers sectors to be 512 bytes long independently
 * of the devices real block size.
 *
 * blkcnt_t is the type of the inode's block count.
 */
#ifdef CONFIG_LBDAF
typedef u64 sector_t;
typedef u64 blkcnt_t;
#else
typedef unsigned long sector_t;
typedef unsigned long blkcnt_t;
#endif

/*
 * The type of an index into the pagecache.  Use a #define so asm/types.h
 * can override it.
 */
#ifndef pgoff_t
#define pgoff_t unsigned long
#endif

#ifdef CONFIG_ARCH_DMA_ADDR_T_64BIT
typedef u64 dma_addr_t;
#else
typedef u32 dma_addr_t;
#endif /* dma_addr_t */

#ifdef __CHECKER__
#else
#endif
#ifdef __CHECK_ENDIAN__
#else
#endif
typedef unsigned __bitwise__ gfp_t;
typedef unsigned __bitwise__ fmode_t;
typedef unsigned __bitwise__ oom_flags_t;

#ifdef CONFIG_PHYS_ADDR_T_64BIT
typedef u64 phys_addr_t;
#else
typedef u32 phys_addr_t;
#endif

typedef phys_addr_t resource_size_t;

/*
 * This type is the placeholder for a hardware interrupt number. It has to be
 * big enough to enclose whatever representation is used by a given platform.
 */
typedef unsigned long irq_hw_number_t;

/*
ԭ�����ͣ��ýṹ��򵥷�װ��һ�����ͱ���
*/

typedef struct {
	int counter;
} atomic_t;

#ifdef CONFIG_64BIT
typedef struct {
	long counter;
} atomic64_t;
#endif

/*
����ڵ�
�����ṹ��ͨ����Ƕ������ڵ�ṹ���Ӷ�ʵ������Ĳ���
ͨ��container_of��ʵ�������ṹ�ķ���λ

����ָ������˵���ֻ�첲
ǣ�����ֱ��ҵ������ҵ��ˣ�Ҳ����Ȼ�ܹ��ҵ��˱���
*/
struct list_head {
	struct list_head *next, *prev;
};

/*
��ϣ�����Ͱͷ��㣬���hlist_node��ʡ��һ��ָ��ռ�
*/
struct hlist_head {
	struct hlist_node *first;
};

/*
pprev����Ƴ�hlist_node�Ķ���ָ�룬
����ָ��ǰһ���ڵ��next��(���߶��ڵ�һ���ڵ㣬ָ���ͷ��first��)
ΪʲôҪ��Ƴ�������
������ͨ�ĵ��������£�
struct node {
      struct node *next;
};
����������������ָ���ڵ�(a)�����ڵ�(b)�����ף�b->next = a->next; a->next = b;
����Ҫ��ָ���ڵ�(a)ǰ����(b)����鷳��
��ͨ��while(i->next == a) i = i->next;
�õ�a��ǰһ���ڵ㣬Ȼ���ٽ���i->next = b; b->next = a;���в��룻
��ͻ���һ����ʱ����������a��ǰһ���ڵ㡣
linuxҪ��ʡ�ⲿ��ʱ�䡣
����һ�£�������Ŀ�����޸���һ���ڵ��next��
Ϊ��ʡȥ������hlist_node��������pprev��ָ����һ���ڵ��next��
Ҫ�޸���һ���ڵ��next��������*pprev = ? ���ٵ��޸ġ�
�ܽ�һ�£�����**pprev���ǰѵ������ǰ��������š�
*/
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct ustat {
	__kernel_daddr_t	f_tfree;
	__kernel_ino_t		f_tinode;
	char			f_fname[6];
	char			f_fpack[6];
};

/**
 * struct callback_head - callback structure for use with RCU and task_work
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 */
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
};
/*
ͨ����Ƕ��Ҫ���ͷŵĽṹ����
*/
#define rcu_head callback_head

#endif /*  __ASSEMBLY__ */
#endif /* _LINUX_TYPES_H */
