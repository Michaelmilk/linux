#ifndef __ASM_GENERIC_GETORDER_H
#define __ASM_GENERIC_GETORDER_H

#ifndef __ASSEMBLY__

#include <linux/compiler.h>

/* Pure 2^n version of get_order */
/*
包含@size个字节需要2^order个页面
返回幂次order值

@size	: 字节单位的内存大小
*/
static inline __attribute_const__ int get_order(unsigned long size)
{
	int order;

	/* 需要多少个页 */
	size = (size - 1) >> (PAGE_SHIFT - 1);
	/* 计算2的幂次 */
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

#endif	/* __ASSEMBLY__ */

#endif	/* __ASM_GENERIC_GETORDER_H */
