#include <linux/io.h>
#include <linux/memblock.h>

#include <asm/trampoline.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

/*
代码起始位置的虚拟地址
*/
unsigned char *x86_trampoline_base;

/*
设置smp的跳转代码
*/
void __init setup_trampolines(void)
{
	phys_addr_t mem;
	/* 符号x86_trampoline_start和x86_trampoline_end定义在连接脚本
	   arch/x86/kernel/vmlinux.lds.S中
	   用于连接.x86_trampoline节的代码
	   比如位于arch/x86/kernel/trampoline_32.S中的代码

	   计算出这节代码的长度，按页对齐 */
	size_t size = PAGE_ALIGN(x86_trampoline_end - x86_trampoline_start);

	/* Has to be in very low memory so we can execute real-mode AP code. */
	/* 在0 ~ 1MB间找出size大小的空间
	   以便AP的实模式下执行该代码
	   AP: application processor 非启动cpu */
	mem = memblock_find_in_range(0, 1<<20, size, PAGE_SIZE);
	if (mem == MEMBLOCK_ERROR)
		panic("Cannot allocate trampoline\n");

	/* 记录虚拟地址 */
	x86_trampoline_base = __va(mem);
	/* 在memblock中标记预留 */
	memblock_x86_reserve_range(mem, mem + size, "TRAMPOLINE");

	/* 打印分配的地址和代码大小
	   例如:Base memory trampoline at [c009b000] 9b000 size 16384 */
	printk(KERN_DEBUG "Base memory trampoline at [%p] %llx size %zu\n",
	       x86_trampoline_base, (unsigned long long)mem, size);

	/* memcpy()使用虚拟地址，此时低地址处的部分页表已经建立了
	   将代码复制到1MB以下的空间处 */
	memcpy(x86_trampoline_base, x86_trampoline_start, size);
}

/*
 * setup_trampolines() gets called very early, to guarantee the
 * availability of low memory.  This is before the proper kernel page
 * tables are set up, so we cannot set page permissions in that
 * function.  Thus, we use an arch_initcall instead.
 */
static int __init configure_trampolines(void)
{
	size_t size = PAGE_ALIGN(x86_trampoline_end - x86_trampoline_start);

	set_memory_x((unsigned long)x86_trampoline_base, size >> PAGE_SHIFT);
	return 0;
}
arch_initcall(configure_trampolines);
