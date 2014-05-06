/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/asm-offsets.h>
#include <asm/syscall.h>

#define __SYSCALL_COMMON(nr, sym, compat) __SYSCALL_64(nr, sym, compat)

#ifdef CONFIG_X86_X32_ABI
# define __SYSCALL_X32(nr, sym, compat) __SYSCALL_64(nr, sym, compat)
#else
# define __SYSCALL_X32(nr, sym, compat) /* nothing */
#endif

/*
先将宏定义为把系统调用展开成函数声明
这样在包含生成的头文件syscalls_64.h
先展开的为函数声明
*/
#define __SYSCALL_64(nr, sym, compat) extern asmlinkage void sym(void) ;
#include <asm/syscalls_64.h>
#undef __SYSCALL_64

/*
定义为数组中项的初始化
这样下面包含生成的头文件syscalls_64.h时
初始化数组sys_call_table[]的各项
*/
#define __SYSCALL_64(nr, sym, compat) [nr] = sym,

extern void sys_ni_syscall(void);

/* 系统调用的函数指针数组 */
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_64.h>
};
