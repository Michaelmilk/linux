#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>

#include <asm/errno.h>

/*
�ں��кܶຯ����Ҫ����һ���ṹ��ָ��
���ǳ����ʱ��ϣ�����ش�����

�ں������ַ�ռ�����ֵ����1ҳ4KB�ռ���Ԥ����
��������Ľṹ�ռ�ָ�벻��ָ������
���������װ��������Ϊָ�뷵��
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
��������ת��Ϊһ��ָ��
*/
static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

/*
��һ��ָ��ת��Ϊlong��ֵ
*/
static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

/*
ָ���ֵ��һ��������
*/
static inline long __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

/*
��һ����ָ��
������һ��������
*/
static inline long __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/*
ȥ����ָ���const�޶���
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
����Ǵ�����ָ��Ļ���ת��Ϊ�����뷵��
����ָ���򷵻�0
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
