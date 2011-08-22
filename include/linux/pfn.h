#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

/*

+-----------+ <- 页框号PFN_UP(x)
|			|
|			|
|			|
|			| <- 物理地址x
|			|
|			|
|			|
+-----------+ <- 页框号PFN_DOWN(x)

*/

/*
将物理地址@x进行页对齐后，计算其所在页框的物理地址
*/
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
/*
物理地址@x所在页框的下一个页框号
*/
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
/*
物理地址@x所在的页框号
*/
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/*
页框号@x对应的物理地址
*/
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

#endif
