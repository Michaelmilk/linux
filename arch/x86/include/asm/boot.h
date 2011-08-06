#ifndef _ASM_X86_BOOT_H
#define _ASM_X86_BOOT_H

/*
VGA��Video Graphics Array������Ƶͼ�����У�
��IBM��1987����PS/2��
��PS/2 ԭ�ǡ�Personal System 2������˼��������ϵͳ2����
��IBM��˾��1987���Ƴ���һ�ָ��˵��ԡ�
PS/2������ʹ�õļ������ӿھ������ڵ�PS/2�ӿڡ�
��Ϊ��׼�����ţ�PS/2�������г���ʧ���ˡ�
ֻ��PS/2�ӿ�һֱ���õ����졣��
һ���Ƴ���ʹ��ģ���źŵ�һ����Ƶ�����׼��
�ڵ�ʱ���зֱ��ʸߡ���ʾ���ʿ졢��ɫ�ḻ���ŵ㣬
�ڲ�ɫ��ʾ������õ��˹㷺��Ӧ�á�
�����׼�����ֽ�ĸ��˵����г��Ѿ�ʮ�ֹ�ʱ��
��ʹ��ˣ�VGA��Ȼ���������������֧ͬ�ֵ�һ����׼��
���˵����ڼ����Լ��Ķ�����������֮ǰ��������֧��VGA�ı�׼��
���磬΢��Windowsϵ�в�Ʒ�Ŀ���������Ȼʹ��VGA��ʾģʽ��
��Ҳ˵����ֱ��ʺ���ɫ���Ĳ��㡣
*/

/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */

#ifdef __KERNEL__

#include <asm/pgtable_types.h>

/* Physical address where kernel should be loaded. */
/*
�ں˼��ص������ַ������CONFIG_PHYSICAL_ALIGN����
CONFIG_PHYSICAL_START�����þ�������include/generated/autoconf.h��
*/
#define LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START \
				+ (CONFIG_PHYSICAL_ALIGN - 1)) \
				& ~(CONFIG_PHYSICAL_ALIGN - 1))

/* Minimum kernel alignment, as a power of two */
#ifdef CONFIG_X86_64
#define MIN_KERNEL_ALIGN_LG2	PMD_SHIFT
#else
#define MIN_KERNEL_ALIGN_LG2	(PAGE_SHIFT + THREAD_ORDER)
#endif
#define MIN_KERNEL_ALIGN	(_AC(1, UL) << MIN_KERNEL_ALIGN_LG2)

#if (CONFIG_PHYSICAL_ALIGN & (CONFIG_PHYSICAL_ALIGN-1)) || \
	(CONFIG_PHYSICAL_ALIGN < MIN_KERNEL_ALIGN)
#error "Invalid value for CONFIG_PHYSICAL_ALIGN"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#define BOOT_HEAP_SIZE             0x400000
#else /* !CONFIG_KERNEL_BZIP2 */

#define BOOT_HEAP_SIZE	0x8000

#endif /* !CONFIG_KERNEL_BZIP2 */

#ifdef CONFIG_X86_64
#define BOOT_STACK_SIZE	0x4000
#else
#define BOOT_STACK_SIZE	0x1000
#endif

#endif /* __KERNEL__ */

#endif /* _ASM_X86_BOOT_H */
