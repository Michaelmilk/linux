/* System call table for i386. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/asm-offsets.h>

/* 定义宏，根据头文件展开为函数声明 */
#define __SYSCALL_I386(nr, sym, compat) extern asmlinkage void sym(void) ;
#include <asm/syscalls_32.h>
#undef __SYSCALL_I386

/* 重新定义宏，展开为数组各项赋值为函数指针 */
#define __SYSCALL_I386(nr, sym, compat) [nr] = sym,

typedef asmlinkage void (*sys_call_ptr_t)(void);

extern asmlinkage void sys_ni_syscall(void);

/* 系统调用函数表 */
const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_32.h>
};
