#ifndef __ASM_GENERIC_GETORDER_H
#define __ASM_GENERIC_GETORDER_H

#ifndef __ASSEMBLY__

#include <linux/compiler.h>

/* Pure 2^n version of get_order */
/*
����@size���ֽ���Ҫ2^order��ҳ��
�����ݴ�orderֵ

@size	: �ֽڵ�λ���ڴ��С
*/
static inline __attribute_const__ int get_order(unsigned long size)
{
	int order;

	/* ��Ҫ���ٸ�ҳ */
	size = (size - 1) >> (PAGE_SHIFT - 1);
	/* ����2���ݴ� */
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

#endif	/* __ASSEMBLY__ */

#endif	/* __ASM_GENERIC_GETORDER_H */
