#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>

#include <asm/errno.h>

/*
内核中很多函数需要返回一个结构的指针
但是出错的时候希望返回错误码

内核虚拟地址空间中数值最大的1页4KB空间是预留的
正常申请的结构空间指针不会指向那里
将错误码封装在那里作为指针返回
*/

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095

#ifndef __ASSEMBLY__

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

/*
将错误码转换为一个指针
*/
static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

/*
将一个指针转换为long数值
*/
static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

/*
指针的值是一个错误码
*/
static inline long __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

/*
是一个空指针
或者是一个错误码
*/
static inline long __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/*
去掉了指针的const限定符
*/

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

/*
如果是错误码指针的话，转换为错误码返回
正常指针则返回0
*/
static inline int __must_check PTR_RET(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

#endif

#endif /* _LINUX_ERR_H */
