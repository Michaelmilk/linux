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
����@option���������ж�Ӧ�Ĳ���ֵ��'='�ź���Ĳ���
��������option�ظ��Ļ�����@buffer��Ϊ���һ���ֵ
����ƥ���ѡ������ĳ��ȣ�����ʵ�ʽ��ջ�������С�Ƿ�ض��˲���
δ�ҵ��򷵻�-1

@cmdline_ptr	: header.S�е�cmd_line_ptr
@option			: �����ҵ��ַ���
@buffer			:
@bufsize		:
*/

int __cmdline_find_option(unsigned long cmdline_ptr, const char *option, char *buffer, int bufsize)
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

	/* û�������в��� */
	if (!cmdline_ptr)
		return -1;      /* No command line */

	/* ȡ��4λ����Ϊ����ƫ�� */
	cptr = cmdline_ptr & 0xf;
	/* ��ַ����4λ����Ϊ�ε�ַ��д��fs�� */
	set_fs(cmdline_ptr >> 4);

	/* ����fs�Σ�0x10000Ϊ64K���������������
	   rdfs8()��fs��ƫ��cptr��ȡ8bit��ֵ */
	while (cptr < 0x10000 && (c = rdfs8(cptr++))) {
		switch (state) {
		case st_wordstart:
			/* �����ո�� */
			if (myisspace(c))
				break;

			/* else */
			/* ������״̬Ϊ���ʱȽ� */
			state = st_wordcmp;
			/* ��(��������)ѡ����ʼλ��ָ�� */
			opptr = option;
			/* fall through */

		case st_wordcmp:
			/* �������е���'='�ţ�����ѡ����Ѿ����������Ƚ�������ͬ
			   ����Ϊ����״̬��׼�������������е��ַ�ֵ��@buffer�� */
			if (c == '=' && !*opptr) {
				len = 0;
				bufptr = buffer;
				state = st_bufcpy;
			} else if (myisspace(c)) {
				/* �����ո����¿�ʼ�Ƚ���һ������ */
				state = st_wordstart;
			} else if (c != *opptr++) {
				/* ��һ���ַ���ͬ����������ǰ�Ƚϵĵ��� */
				state = st_wordskip;
			}
			/* �����Ƚ���һ���ַ� */
			break;

		case st_wordskip:
			/* �ո񣬵�����һ������ǰ */
			if (myisspace(c))
				state = st_wordstart;
			/* ����������ǰ������ʣ����ַ� */
			break;

		case st_bufcpy:
			/* �����ո񣬽�����һ������ */
			if (myisspace(c)) {
				state = st_wordstart;
			} else {
				/* ��û�������ջ�������С */
				if (len < bufsize-1)
					/* �����ַ� */
					*bufptr++ = c;
				/* �������ӣ������ܲ����Ƿ��ѱ��������ض� */
				len++;
			}
			break;
		}
	}

	/* �ַ�����'\0'��β */
	if (bufsize)
		*bufptr = '\0';

	/* ���ز�����ʵ�ʳ��� */
	return len;
}

/*
 * Find a boolean option (like quiet,noapic,nosmp....)
 *
 * Returns the position of that option (starts counting with 1)
 * or 0 on not found
 */

/*
����ѡ��@option�Ƿ��������������

�ҵ��򷵻�@option�������в����еڼ����ַ���ʼ����1��ʼ����
δ�ҵ��򷵻�0
*/

int __cmdline_find_option_bool(unsigned long cmdline_ptr, const char *option)
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

	if (!cmdline_ptr)
		return -1;      /* No command line */

	cptr = cmdline_ptr & 0xf;
	set_fs(cmdline_ptr >> 4);

	while (cptr < 0x10000) {
		c = rdfs8(cptr++);
		pos++;

		switch (state) {
		case st_wordstart:
			/* �ַ������� */
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
