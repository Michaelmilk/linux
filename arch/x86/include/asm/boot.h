#ifndef _ASM_X86_BOOT_H
#define _ASM_X86_BOOT_H

/*
VGA（Video Graphics Array）即视频图形阵列，
是IBM在1987年随PS/2机
（PS/2 原是“Personal System 2”的意思，“个人系统2”，
是IBM公司在1987年推出的一种个人电脑。
PS/2电脑上使用的键盘鼠标接口就是现在的PS/2接口。
因为标准不开放，PS/2电脑在市场中失败了。
只有PS/2接口一直沿用到今天。）
一起推出的使用模拟信号的一种视频传输标准，
在当时具有分辨率高、显示速率快、颜色丰富等优点，
在彩色显示器领域得到了广泛的应用。
这个标准对于现今的个人电脑市场已经十分过时。
即使如此，VGA仍然是最多制造商所共同支持的一个标准，
个人电脑在加载自己的独特驱动程序之前，都必须支持VGA的标准。
例如，微软Windows系列产品的开机画面仍然使用VGA显示模式，
这也说明其分辨率和载色数的不足。
*/

/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */

#ifdef __KERNEL__

#include <asm/pgtable_types.h>

/* Physical address where kernel should be loaded. */
/*
内核加载的物理地址，按照CONFIG_PHYSICAL_ALIGN对齐
CONFIG_PHYSICAL_START由配置决定，在include/generated/autoconf.h中
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
