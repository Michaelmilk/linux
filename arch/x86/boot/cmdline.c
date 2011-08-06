/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Simple command-line parser for early boot.
 */

#include "boot.h"

static inline int myisspace(u8 c)
{
	return c <= ' ';	/* Close enough approximation */
}

/*
 * Find a non-boolean option, that is, "option=argument".  In accordance
 * with standard Linux practice, if this option is repeated, this returns
 * the last instance on the command line.
 *
 * Returns the length of the argument (regardless of if it was
 * truncated to fit in the buffer), or -1 on not found.
 */
/*
查找@option在命令行中对应的参数值，'='号后面的参数
命令行中option重复的话，则@buffer中为最后一项的值
返回匹配的选项参数的长度，不管实际接收缓冲区大小是否截断了参数
未找到则返回-1

@cmdline_ptr	: header.S中的cmd_line_ptr
@option			: 待查找的字符串
@buffer			:
@bufsize		:
*/
int __cmdline_find_option(u32 cmdline_ptr, const char *option, char *buffer, int bufsize)
{
	addr_t cptr;
	char c;
	int len = -1;
	const char *opptr = NULL;
	char *bufptr = buffer;
	enum {
		st_wordstart,	/* Start of word/after whitespace */
		st_wordcmp,	/* Comparing this word */
		st_wordskip,	/* Miscompare, skip */
		st_bufcpy	/* Copying this to buffer */
	} state = st_wordstart;

	/* 没有命令行参数
	   或者命令行参数的地址超过了1M */
	if (!cmdline_ptr || cmdline_ptr >= 0x100000)
		return -1;	/* No command line, or inaccessible */

	/* 取低4位，作为段内偏移 */
	cptr = cmdline_ptr & 0xf;
	/* 地址右移4位，作为段地址，写入fs段 */
	set_fs(cmdline_ptr >> 4);

	/* 遍历fs段，0x10000为64K，即遍历不会出段
	   rdfs8()从fs段偏移cptr处取8bit的值 */
	while (cptr < 0x10000 && (c = rdfs8(cptr++))) {
		switch (state) {
		case st_wordstart:
			/* 跳过空格等 */
			if (myisspace(c))
				break;

			/* else */
			/* 否则标记状态为单词比较 */
			state = st_wordcmp;
			/* 置(或是重置)选项起始位置指针 */
			opptr = option;
			/* fall through */

		case st_wordcmp:
			/* 命令行中到了'='号，并且选项单词已经结束，即比较完且相同
			   则标记为复制状态，准备复制命令行中的字符值到@buffer中 */
			if (c == '=' && !*opptr) {
				len = 0;
				bufptr = buffer;
				state = st_bufcpy;
			} else if (myisspace(c)) {
				/* 遇到空格，重新开始比较另一个单词 */
				state = st_wordstart;
			} else if (c != *opptr++) {
				/* 有一个字符不同，则跳过当前比较的单词 */
				state = st_wordskip;
			}
			/* 继续比较下一个字符 */
			break;

		case st_wordskip:
			/* 空格，到了下一个单词前 */
			if (myisspace(c))
				state = st_wordstart;
			/* 继续跳过当前单词中剩余的字符 */
			break;

		case st_bufcpy:
			/* 遇到空格，进入下一个单词 */
			if (myisspace(c)) {
				state = st_wordstart;
			} else {
				/* 还没超过接收缓冲区大小 */
				if (len < bufsize-1)
					/* 复制字符 */
					*bufptr++ = c;
				/* 长度增加，而不管参数是否已被缓冲区截断 */
				len++;
			}
			break;
		}
	}

	/* 字符串以'\0'结尾 */
	if (bufsize)
		*bufptr = '\0';

	/* 返回参数的实际长度 */
	return len;
}

/*
 * Find a boolean option (like quiet,noapic,nosmp....)
 *
 * Returns the position of that option (starts counting with 1)
 * or 0 on not found
 */
/*
查找选项@option是否存在于命令行中

找到则返回@option从命令行参数中第几个字符开始，从1开始计算
未找到则返回0
*/
int __cmdline_find_option_bool(u32 cmdline_ptr, const char *option)
{
	addr_t cptr;
	char c;
	int pos = 0, wstart = 0;
	const char *opptr = NULL;
	enum {
		st_wordstart,	/* Start of word/after whitespace */
		st_wordcmp,	/* Comparing this word */
		st_wordskip,	/* Miscompare, skip */
	} state = st_wordstart;

	if (!cmdline_ptr || cmdline_ptr >= 0x100000)
		return -1;	/* No command line, or inaccessible */

	cptr = cmdline_ptr & 0xf;
	set_fs(cmdline_ptr >> 4);

	while (cptr < 0x10000) {
		c = rdfs8(cptr++);
		pos++;

		switch (state) {
		case st_wordstart:
			/* 字符串结束 */
			if (!c)
				return 0;
			else if (myisspace(c))
				break;

			state = st_wordcmp;
			opptr = option;
			wstart = pos;
			/* fall through */

		case st_wordcmp:
			if (!*opptr)
				if (!c || myisspace(c))
					return wstart;
				else
					state = st_wordskip;
			else if (!c)
				return 0;
			else if (c != *opptr++)
				state = st_wordskip;
			break;

		case st_wordskip:
			if (!c)
				return 0;
			else if (myisspace(c))
				state = st_wordstart;
			break;
		}
	}

	return 0;	/* Buffer overrun */
}
