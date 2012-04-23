/* find_last_bit.c: fallback find next bit implementation
 *
 * Copyright (C) 2008 IBM Corporation
 * Written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/bitops.h>
#include <linux/export.h>
#include <asm/types.h>
#include <asm/byteorder.h>

#ifndef find_last_bit

/*
@addr	: 位图起始地址
@size	: 位图中位的个数

返回@addr指向的空间中前@size个位中最后置1的位下标，该数从0开始
例如@addr指向一个数字8(1<<3)的时候，返回3，也就是2的幂次
但是返回值不会超过位图中有效位的个数@size
*/
unsigned long find_last_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long words;
	unsigned long tmp;

	/* Start at final word. */
	words = size / BITS_PER_LONG;

	/* Partial final word? */
	if (size & (BITS_PER_LONG-1)) {
		tmp = (addr[words] & (~0UL >> (BITS_PER_LONG
					 - (size & (BITS_PER_LONG-1)))));
		if (tmp)
			goto found;
	}

	while (words) {
		tmp = addr[--words];
		if (tmp) {
found:
			return words * BITS_PER_LONG + __fls(tmp);
		}
	}

	/* Not found */
	return size;
}
EXPORT_SYMBOL(find_last_bit);

#endif
