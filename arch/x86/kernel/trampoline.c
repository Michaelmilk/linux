#include <linux/io.h>
#include <linux/memblock.h>

#include <asm/trampoline.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

/*
������ʼλ�õ������ַ
*/
unsigned char *x86_trampoline_base;

/*
����smp����ת����
*/
void __init setup_trampolines(void)
{
	phys_addr_t mem;
	/* ����x86_trampoline_start��x86_trampoline_end���������ӽű�
	   arch/x86/kernel/vmlinux.lds.S��
	   ��������.x86_trampoline�ڵĴ���
	   ����λ��arch/x86/kernel/trampoline_32.S�еĴ���

	   �������ڴ���ĳ��ȣ���ҳ���� */
	size_t size = PAGE_ALIGN(x86_trampoline_end - x86_trampoline_start);

	/* Has to be in very low memory so we can execute real-mode AP code. */
	/* ��0 ~ 1MB���ҳ�size��С�Ŀռ�
	   �Ա�AP��ʵģʽ��ִ�иô���
	   AP: application processor ������cpu */
	mem = memblock_find_in_range(0, 1<<20, size, PAGE_SIZE);
	if (!mem)
		panic("Cannot allocate trampoline\n");

	/* ��¼�����ַ */
	x86_trampoline_base = __va(mem);
	/* ��memblock�б��Ԥ�� */
	memblock_reserve(mem, size);

	/* ��ӡ����ĵ�ַ�ʹ����С
	   ����:Base memory trampoline at [c009b000] 9b000 size 16384 */
	printk(KERN_DEBUG "Base memory trampoline at [%p] %llx size %zu\n",
	       x86_trampoline_base, (unsigned long long)mem, size);

	/* memcpy()ʹ�������ַ����ʱ�͵�ַ���Ĳ���ҳ���Ѿ�������
	   �����븴�Ƶ�1MB���µĿռ䴦 */
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
