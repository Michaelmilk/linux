#ifndef _LINUX_STDDEF_H
#define _LINUX_STDDEF_H

#include <linux/compiler.h>

#ifdef __KERNEL__

#undef NULL
#define NULL ((void *)0)

enum {
	false	= 0,
	true	= 1
};

#undef offsetof
#ifdef __compiler_offsetof
/*
ʹ��gcc4����ı���������ʹ�ñ������ڽ�֧�ֵ�__builtin_offsetof(a,b)����ƫ��
__compiler_offsetof��compiler-gcc4.h�ж���
*/
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
/*
ʹ��gcc4��ǰ�ı���������ʹ��0��ַ����ת���ķ�ʽ����ƫ��
*/
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif /* __KERNEL__ */

#endif
