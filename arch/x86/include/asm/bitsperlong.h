#ifndef __ASM_X86_BITSPERLONG_H
#define __ASM_X86_BITSPERLONG_H

#ifdef __x86_64__
/* 在ia64平台上，long数据类型占8个字节，64位 */
# define __BITS_PER_LONG 64
#else
/* 在i386平台上，long数据类型占4个字节，32位 */
# define __BITS_PER_LONG 32
#endif

#include <asm-generic/bitsperlong.h>

#endif /* __ASM_X86_BITSPERLONG_H */

