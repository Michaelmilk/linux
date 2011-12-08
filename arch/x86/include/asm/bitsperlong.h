#ifndef __ASM_X86_BITSPERLONG_H
#define __ASM_X86_BITSPERLONG_H

#ifdef __x86_64__
/* ��ia64ƽ̨�ϣ�long��������ռ8���ֽڣ�64λ */
# define __BITS_PER_LONG 64
#else
/* ��i386ƽ̨�ϣ�long��������ռ4���ֽڣ�32λ */
# define __BITS_PER_LONG 32
#endif

#include <asm-generic/bitsperlong.h>

#endif /* __ASM_X86_BITSPERLONG_H */

