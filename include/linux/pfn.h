#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

/*

+-----------+ <- ҳ���PFN_UP(x)
|			|
|			|
|			|
|			| <- �����ַx
|			|
|			|
|			|
+-----------+ <- ҳ���PFN_DOWN(x)

*/

/*
�������ַ@x����ҳ����󣬼���������ҳ��������ַ
*/
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
/*
�����ַ@x����ҳ�����һ��ҳ���
*/
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
/*
�����ַ@x���ڵ�ҳ���
*/
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/*
ҳ���@x��Ӧ�������ַ
*/
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
