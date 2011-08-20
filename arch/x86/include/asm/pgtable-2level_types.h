#ifndef _ASM_X86_PGTABLE_2LEVEL_DEFS_H
#define _ASM_X86_PGTABLE_2LEVEL_DEFS_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef union {
	pteval_t pte;
	pteval_t pte_low;
} pte_t;
#endif	/* !__ASSEMBLY__ */

#define SHARED_KERNEL_PMD	0
#define PAGETABLE_LEVELS	2

/*
 * traditional i386 two-level paging structure:
 */

/*
传统的2级页表，偏移22，占高10位
*/
#define PGDIR_SHIFT	22
/*
传统的2级页表，页目录中含有1024个指针
*/
#define PTRS_PER_PGD	1024


/*
 * the i386 is two-level, so we don't really have any
 * PMD directory physically.
 */

/*
每个页表含有1024个指针
*/
#define PTRS_PER_PTE	1024

#endif /* _ASM_X86_PGTABLE_2LEVEL_DEFS_H */
