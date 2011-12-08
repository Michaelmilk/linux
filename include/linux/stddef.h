#ifndef _LINUX_STDDEF_H
#define _LINUX_STDDEF_H

#include <linux/compiler.h>

#undef NULL
#if defined(__cplusplus)
#define NULL 0
#else
#define NULL ((void *)0)
#endif

#ifdef __KERNEL__

enum {
	false	= 0,
	true	= 1
};

#undef offsetof
#ifdef __compiler_offsetof
/*
使用gcc4往后的编译器，则使用编译器内建支持的__builtin_offsetof(a,b)计算偏移
__compiler_offsetof在compiler-gcc4.h中定义
*/
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
/*
使用gcc4以前的编译器，则使用0地址类型转换的方式计算偏移
*/
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif /* __KERNEL__ */

#endif
