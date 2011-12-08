#ifndef __LINUX_COMPILER_H
#error "Please don't include <linux/compiler-gcc4.h> directly, include <linux/compiler.h> instead."
#endif

/* GCC 4.1.[01] miscompiles __weak */
#ifdef __KERNEL__
# if __GNUC_MINOR__ == 1 && __GNUC_PATCHLEVEL__ <= 1
#  error Your version of gcc miscompiles the __weak directive
# endif
#endif

/* 标记变量已经使用，不再产生警告 */
#define __used			__attribute__((__used__))
/* 必须对函数的返回值进行检查 */
#define __must_check 		__attribute__((warn_unused_result))
/* 编译器gcc4往后的版本内建支持offsetof(TYPE,MEMBER)宏的偏移计算功能 */
#define __compiler_offsetof(a,b) __builtin_offsetof(a,b)

/* gcc4.3往后的版本 */
#if __GNUC_MINOR__ >= 3
/* Mark functions as cold. gcc will assume any path leading to a call
   to them will be unlikely.  This means a lot of manual unlikely()s
   are unnecessary now for any paths leading to the usual suspects
   like BUG(), printk(), panic() etc. [but let's keep them for now for
   older compilers]

   Early snapshots of gcc 4.3 don't support this and we can't detect this
   in the preprocessor, but we can live with this because they're unreleased.
   Maketime probing would be overkill here.

   gcc also has a __attribute__((__hot__)) to move hot functions into
   a special section, but I don't see any sense in this right now in
   the kernel context */
/*
__cold__属性告诉编译器该函数不太可能会被执行
编译的时候会进行相应的优化
*/
#define __cold			__attribute__((__cold__))


/* gcc4.5往后的版本 */
#if __GNUC_MINOR__ >= 5
/*
 * Mark a position in code as unreachable.  This can be used to
 * suppress control flow warnings after asm blocks that transfer
 * control elsewhere.
 *
 * Early snapshots of gcc 4.5 don't support this and we can't detect
 * this in the preprocessor, but we can live with this because they're
 * unreleased.  Really, we need to have autoconf for the kernel.
 */
#define unreachable() __builtin_unreachable()

/* Mark a function definition as prohibited from being cloned. */
/* 阻止对整个函数的拷贝 */
#define __noclone	__attribute__((__noclone__))

#endif
#endif

#if __GNUC_MINOR__ > 0
#define __compiletime_object_size(obj) __builtin_object_size(obj, 0)
#endif
#if __GNUC_MINOR__ >= 4 && !defined(__CHECKER__)
#define __compiletime_warning(message) __attribute__((warning(message)))
#define __compiletime_error(message) __attribute__((error(message)))
#endif
