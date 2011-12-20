/*
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 */

#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/pfn.h>
#include <linux/poison.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/proc_fs.h>
#include <linux/memory_hotplug.h>
#include <linux/initrd.h>
#include <linux/cpumask.h>
#include <linux/gfp.h>

#include <asm/asm.h>
#include <asm/bios_ebda.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/apic.h>
#include <asm/bugs.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/olpc_ofw.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <asm/paravirt.h>
#include <asm/setup.h>
#include <asm/cacheflush.h>
#include <asm/page_types.h>
#include <asm/init.h>

unsigned long highstart_pfn, highend_pfn;

static noinline int do_test_wp_bit(void);

bool __read_mostly __vmalloc_start_set = false;

static __init void *alloc_low_page(void)
{
	unsigned long pfn = pgt_buf_end++;
	void *adr;

	if (pfn >= pgt_buf_top)
		panic("alloc_low_page: ran out of memory");

	adr = __va(pfn * PAGE_SIZE);
	clear_page(adr);
	return adr;
}

/*
 * Creates a middle page table and puts a pointer to it in the
 * given global directory entry. This only returns the gd entry
 * in non-PAE compilation mode, since the middle layer is folded.
 */
/*
如果内核不启用PAE选项，函数将通过 pmd_offset返回pgd的地址。
因为linux的二级映射模型，本来就是忽略pmd中间目录表的。
*/
static pmd_t * __init one_md_table_init(pgd_t *pgd)
{
	pud_t *pud;
	pmd_t *pmd_table;

#ifdef CONFIG_X86_PAE
	if (!(pgd_val(*pgd) & _PAGE_PRESENT)) {
		if (after_bootmem)
			pmd_table = (pmd_t *)alloc_bootmem_pages(PAGE_SIZE);
		else
			pmd_table = (pmd_t *)alloc_low_page();
		paravirt_alloc_pmd(&init_mm, __pa(pmd_table) >> PAGE_SHIFT);
		set_pgd(pgd, __pgd(__pa(pmd_table) | _PAGE_PRESENT));
		pud = pud_offset(pgd, 0);
		BUG_ON(pmd_table != pmd_offset(pud, 0));

		return pmd_table;
	}
#endif
	pud = pud_offset(pgd, 0);
	pmd_table = pmd_offset(pud, 0);

	return pmd_table;
}

/*
 * Create a page table and place a pointer to it in a middle page
 * directory entry:
 */
static pte_t * __init one_page_table_init(pmd_t *pmd)
{
	if (!(pmd_val(*pmd) & _PAGE_PRESENT)) {
		pte_t *page_table = NULL;

		/* 分配一个4K大小的物理页面 */
		if (after_bootmem) {
#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KMEMCHECK)
			page_table = (pte_t *) alloc_bootmem_pages(PAGE_SIZE);
#endif
			if (!page_table)
				page_table =
				(pte_t *)alloc_bootmem_pages(PAGE_SIZE);
		} else
			page_table = (pte_t *)alloc_low_page();

		paravirt_alloc_pte(&init_mm, __pa(page_table) >> PAGE_SHIFT);
		/* page_table显然属于线性地址，先通过__pa宏转化为物理地址
		   再或上_PAGE_TABLE宏，此时它们还是无符号整数，
		   再通过__pmd把无符号整数转化为pmd类型，
		   经过这些转换，就得到了一个具有属性的表项，
		   然后通过set_pmd宏设置pmd表项
		*/
		set_pmd(pmd, __pmd(__pa(page_table) | _PAGE_TABLE));
		/* 确保刚建立的页表项所指示的线性地址
		   与上面分配的页对应的线性地址一致
		*/
		BUG_ON(page_table != pte_offset_kernel(pmd, 0));
	}

	/* 返回该页表的线性地址 */
	return pte_offset_kernel(pmd, 0);
}

pmd_t * __init populate_extra_pmd(unsigned long vaddr)
{
	int pgd_idx = pgd_index(vaddr);
	int pmd_idx = pmd_index(vaddr);

	return one_md_table_init(swapper_pg_dir + pgd_idx) + pmd_idx;
}

pte_t * __init populate_extra_pte(unsigned long vaddr)
{
	int pte_idx = pte_index(vaddr);
	pmd_t *pmd;

	pmd = populate_extra_pmd(vaddr);
	return one_page_table_init(pmd) + pte_idx;
}

static pte_t *__init page_table_kmap_check(pte_t *pte, pmd_t *pmd,
					   unsigned long vaddr, pte_t *lastpte)
{
#ifdef CONFIG_HIGHMEM
	/*
	 * Something (early fixmap) may already have put a pte
	 * page here, which causes the page table allocation
	 * to become nonlinear. Attempt to fix it, and if it
	 * is still nonlinear then we have to bug.
	 */
	int pmd_idx_kmap_begin = fix_to_virt(FIX_KMAP_END) >> PMD_SHIFT;
	int pmd_idx_kmap_end = fix_to_virt(FIX_KMAP_BEGIN) >> PMD_SHIFT;

	if (pmd_idx_kmap_begin != pmd_idx_kmap_end
	    && (vaddr >> PMD_SHIFT) >= pmd_idx_kmap_begin
	    && (vaddr >> PMD_SHIFT) <= pmd_idx_kmap_end
	    && ((__pa(pte) >> PAGE_SHIFT) < pgt_buf_start
		|| (__pa(pte) >> PAGE_SHIFT) >= pgt_buf_end)) {
		pte_t *newpte;
		int i;

		BUG_ON(after_bootmem);
		newpte = alloc_low_page();
		for (i = 0; i < PTRS_PER_PTE; i++)
			set_pte(newpte + i, pte[i]);

		paravirt_alloc_pte(&init_mm, __pa(newpte) >> PAGE_SHIFT);
		set_pmd(pmd, __pmd(__pa(newpte)|_PAGE_TABLE));
		BUG_ON(newpte != pte_offset_kernel(pmd, 0));
		__flush_tlb_all();

		paravirt_release_pte(__pa(pte) >> PAGE_SHIFT);
		pte = newpte;
	}
	BUG_ON(vaddr < fix_to_virt(FIX_KMAP_BEGIN - 1)
	       && vaddr > fix_to_virt(FIX_KMAP_END)
	       && lastpte && lastpte + PTRS_PER_PTE != pte);
#endif
	return pte;
}

/*
 * This function initializes a certain range of kernel virtual memory
 * with new bootmem page tables, everywhere page tables are missing in
 * the given range.
 *
 * NOTE: The pagetables are allocated contiguous on the physical space
 * so we can cache the place of the first one and move around without
 * checking the pgd every time.
 */
static void __init
page_table_range_init(unsigned long start, unsigned long end, pgd_t *pgd_base)
{
	int pgd_idx, pmd_idx;
	unsigned long vaddr;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte = NULL;

	vaddr = start;
	pgd_idx = pgd_index(vaddr);
	pmd_idx = pmd_index(vaddr);
	pgd = pgd_base + pgd_idx;

	for ( ; (pgd_idx < PTRS_PER_PGD) && (vaddr != end); pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);
		pmd = pmd + pmd_index(vaddr);
		for (; (pmd_idx < PTRS_PER_PMD) && (vaddr != end);
							pmd++, pmd_idx++) {
			pte = page_table_kmap_check(one_page_table_init(pmd),
			                            pmd, vaddr, pte);

			vaddr += PMD_SIZE;
		}
		pmd_idx = 0;
	}
}

/*
判断线性地址是否小于了内核代码段

__init_end是个内核符号，在内核链接的时候生成的，表示内核代码段的终止地址
*/
static inline int is_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)_text && addr <= (unsigned long)__init_end)
		return 1;
	return 0;
}

/*
 * This maps the physical memory to kernel virtual address space, a total
 * of max_low_pfn pages, by creating page tables starting from address
 * PAGE_OFFSET:
 */
/*
映射物理内存到内核虚拟地址空间
映射常规内存
页表对应的虚拟地址从3G开始
*/
unsigned long __init
kernel_physical_mapping_init(unsigned long start,
			     unsigned long end,
			     unsigned long page_size_mask)
{
	int use_pse = page_size_mask == (1<<PG_LEVEL_2M);
	unsigned long last_map_addr = end;
	unsigned long start_pfn, end_pfn;
	pgd_t *pgd_base = swapper_pg_dir;
	int pgd_idx, pmd_idx, pte_ofs;
	/* pfn是页框号，被初始为0 */
	unsigned long pfn;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	unsigned pages_2m, pages_4k;
	int mapping_iter;

	start_pfn = start >> PAGE_SHIFT;
	end_pfn = end >> PAGE_SHIFT;

	/*
	 * First iteration will setup identity mapping using large/small pages
	 * based on use_pse, with other attributes same as set by
	 * the early code in head_32.S
	 *
	 * Second iteration will setup the appropriate attributes (NX, GLOBAL..)
	 * as desired for the kernel identity mapping.
	 *
	 * This two pass mechanism conforms to the TLB app note which says:
	 *
	 *     "Software should not write to a paging-structure entry in a way
	 *      that would change, for any linear address, both the page size
	 *      and either the page frame or attributes."
	 */
	mapping_iter = 1;

	if (!cpu_has_pse)
		use_pse = 0;

repeat:
	pages_2m = pages_4k = 0;
	pfn = start_pfn;
	/*
	   取得虚拟地址PAGE_OFFSET对应的页目录索引
	   对于PAGE_OFFSET为3G的情况，即0xc0000000
	   index值为0x300=768
	   pgd_idx根据pgd_index宏计算结果为768，
	   也是内核要从目录表中第768个表项开始进行设置。
	   从768到1024这个256个表项被linux内核设置成内核目录项，
	   低768个目录项被用户空间使用. 
	   pgd = pgd_base + pgd_idx; pgd便指向了第768个表项。
	*/
	pgd_idx = pgd_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
	pgd = pgd_base + pgd_idx;
	/* 遍历页目录表
	   PTRS_PER_PGD表示页目录表中有多少项，对于2级页表来说，这里为1024
	   循环填充从768到1024这256个目录项的内容。
	*/
	for (; pgd_idx < PTRS_PER_PGD; pgd++, pgd_idx++) {
		pmd = one_md_table_init(pgd);

		/* 保证只映射end_pfn个页面
		   这个很关键，end_pfn代表着整个物理内存一共有多少页框。
		   当pfn大于end_pfn的时候，
		   表明内核已经把整个物理内存都映射到了系统空间中，
		   所以剩下有没被填充的表项就直接忽略了。
		   因为内核已经可以映射整个物理空间了，没必要继续填充剩下的表项。
		*/
		if (pfn >= end_pfn)
			continue;
#ifdef CONFIG_X86_PAE
		pmd_idx = pmd_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
		pmd += pmd_idx;
#else
		pmd_idx = 0;
#endif
		/* 遍历页中间目录表
		   对应2级页表，则PTRS_PER_PMD为1
		   在linux的3级映射模型中，是要设置pmd表的，
		   但在2级映射中忽略，只循环一次，直接进行页表pte的设置。
		*/
		for (; pmd_idx < PTRS_PER_PMD && pfn < end_pfn;
		     pmd++, pmd_idx++) {
			/* 从虚拟地址PAGE_OFFSET开始映射，即3G开始
			   也就是从内核空间开始
			*/
			unsigned int addr = pfn * PAGE_SIZE + PAGE_OFFSET;

			/*
			 * Map with big pages if possible, otherwise
			 * create normal page tables:
			 */
			if (use_pse) {
				unsigned int addr2;
				pgprot_t prot = PAGE_KERNEL_LARGE;
				/*
				 * first pass will use the same initial
				 * identity mapping attribute + _PAGE_PSE.
				 */
				pgprot_t init_prot =
					__pgprot(PTE_IDENT_ATTR |
						 _PAGE_PSE);

				addr2 = (pfn + PTRS_PER_PTE-1) * PAGE_SIZE +
					PAGE_OFFSET + PAGE_SIZE-1;

				if (is_kernel_text(addr) ||
				    is_kernel_text(addr2))
					prot = PAGE_KERNEL_LARGE_EXEC;

				pages_2m++;
				if (mapping_iter == 1)
					set_pmd(pmd, pfn_pmd(pfn, init_prot));
				else
					set_pmd(pmd, pfn_pmd(pfn, prot));

				pfn += PTRS_PER_PTE;
				continue;
			}
			pte = one_page_table_init(pmd);

			pte_ofs = pte_index((pfn<<PAGE_SHIFT) + PAGE_OFFSET);
			pte += pte_ofs;
			/* 遍历页表项 */
			for (; pte_ofs < PTRS_PER_PTE && pfn < end_pfn;
			     pte++, pfn++, pte_ofs++, addr += PAGE_SIZE) {
				/* 如果address属于内核代码段，
				   那么在设置页表项的时候就要加个PAGE_KERNEL_EXEC属性，
				   如果不是，则加个PAGE_KERNEL属性
				*/
				pgprot_t prot = PAGE_KERNEL;
				/*
				 * first pass will use the same initial
				 * identity mapping attribute.
				 */
				pgprot_t init_prot = __pgprot(PTE_IDENT_ATTR);

				if (is_kernel_text(addr))
					prot = PAGE_KERNEL_EXEC;

				pages_4k++;
				if (mapping_iter == 1) {
					set_pte(pte, pfn_pte(pfn, init_prot));
					last_map_addr = (pfn << PAGE_SHIFT) + PAGE_SIZE;
				} else
					set_pte(pte, pfn_pte(pfn, prot));
			}
		}
	}
	if (mapping_iter == 1) {
		/*
		 * update direct mapping page count only in the first
		 * iteration.
		 */
		update_page_count(PG_LEVEL_2M, pages_2m);
		update_page_count(PG_LEVEL_4K, pages_4k);

		/*
		 * local global flush tlb, which will flush the previous
		 * mappings present in both small and large page TLB's.
		 */
		__flush_tlb_all();

		/*
		 * Second iteration will set the actual desired PTE attributes.
		 */
		mapping_iter = 2;
		goto repeat;
	}
	return last_map_addr;
}

pte_t *kmap_pte;
pgprot_t kmap_prot;

static inline pte_t *kmap_get_fixmap_pte(unsigned long vaddr)
{
	return pte_offset_kernel(pmd_offset(pud_offset(pgd_offset_k(vaddr),
			vaddr), vaddr), vaddr);
}

/*
专用页面映射区
*/
static void __init kmap_init(void)
{
	unsigned long kmap_vstart;

	/*
	 * Cache the first kmap pte:
	 */
	kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
	kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

	kmap_prot = PAGE_KERNEL;
}

#ifdef CONFIG_HIGHMEM
/*
高端内存映射区
*/
static void __init permanent_kmaps_init(pgd_t *pgd_base)
{
	unsigned long vaddr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	vaddr = PKMAP_BASE;
	page_table_range_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, pgd_base);

	pgd = swapper_pg_dir + pgd_index(vaddr);
	pud = pud_offset(pgd, vaddr);
	pmd = pmd_offset(pud, vaddr);
	pte = pte_offset_kernel(pmd, vaddr);
	pkmap_page_table = pte;
}

static void __init add_one_highpage_init(struct page *page)
{
	ClearPageReserved(page);
	init_page_count(page);
	__free_page(page);
	totalhigh_pages++;
}

void __init add_highpages_with_active_regions(int nid,
			 unsigned long start_pfn, unsigned long end_pfn)
{
	struct range *range;
	int nr_range;
	int i;

	nr_range = __get_free_all_memory_range(&range, nid, start_pfn, end_pfn);

	for (i = 0; i < nr_range; i++) {
		struct page *page;
		int node_pfn;

		for (node_pfn = range[i].start; node_pfn < range[i].end;
		     node_pfn++) {
			if (!pfn_valid(node_pfn))
				continue;
			page = pfn_to_page(node_pfn);
			add_one_highpage_init(page);
		}
	}
}
#else
static inline void permanent_kmaps_init(pgd_t *pgd_base)
{
}
#endif /* CONFIG_HIGHMEM */

void __init native_pagetable_setup_start(pgd_t *base)
{
	unsigned long pfn, va;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/*
	 * Remove any mappings which extend past the end of physical
	 * memory from the boot time page table:
	 */
	/* 遍历高端内存的页框号 */
	for (pfn = max_low_pfn + 1; pfn < 1<<(32-PAGE_SHIFT); pfn++) {
		/* 转换为对应的虚拟地址 */
		va = PAGE_OFFSET + (pfn<<PAGE_SHIFT);
		pgd = base + pgd_index(va);
		/* 检查页目录项的_PAGE_PRESENT标志位 */
		if (!pgd_present(*pgd))
			break;

		/* 对于2级页表，pmd = pud = pgd */
		pud = pud_offset(pgd, va);
		pmd = pmd_offset(pud, va);
		/* 检查pmd的_PAGE_PRESENT标志位 */
		if (!pmd_present(*pmd))
			break;

		pte = pte_offset_kernel(pmd, va);
		if (!pte_present(*pte))
			break;

		/* 将页表中的值清0 */
		pte_clear(NULL, va, pte);
	}
	/* 未定义CONFIG_PARAVIRT时
	   paravirt_alloc_pmd()函数为空 */
	paravirt_alloc_pmd(&init_mm, __pa(base) >> PAGE_SHIFT);
}

void __init native_pagetable_setup_done(pgd_t *base)
{
}

/*
 * Build a proper pagetable for the kernel mappings.  Up until this
 * point, we've been running on some set of pagetables constructed by
 * the boot process.
 *
 * If we're booting on native hardware, this will be a pagetable
 * constructed in arch/x86/kernel/head_32.S.  The root of the
 * pagetable will be swapper_pg_dir.
 *
 * If we're booting paravirtualized under a hypervisor, then there are
 * more options: we may already be running PAE, and the pagetable may
 * or may not be based in swapper_pg_dir.  In any case,
 * paravirt_pagetable_setup_start() will set up swapper_pg_dir
 * appropriately for the rest of the initialization to work.
 *
 * In general, pagetable_init() assumes that the pagetable may already
 * be partially populated, and so it avoids stomping on any existing
 * mappings.
 */
void __init early_ioremap_page_table_range_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;
	unsigned long vaddr, end;

	/*
	 * Fixed mappings, only the page table structure has to be
	 * created - mappings will be set by set_fixmap():
	 */
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	end = (FIXADDR_TOP + PMD_SIZE - 1) & PMD_MASK;
	page_table_range_init(vaddr, end, pgd_base);
	early_ioremap_reset();
}

static void __init pagetable_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;

	permanent_kmaps_init(pgd_base);
}

pteval_t __supported_pte_mask __read_mostly = ~(_PAGE_NX | _PAGE_GLOBAL | _PAGE_IOMAP);
EXPORT_SYMBOL_GPL(__supported_pte_mask);

/* user-defined highmem size */
/*
命令行参数配置的高端内存大小
转换为页个数
*/
static unsigned int highmem_pages = -1;

/*
 * highmem=size forces highmem to be exactly 'size' bytes.
 * This works even on boxes that have no highmem otherwise.
 * This also works to reduce highmem size on bigger boxes.
 */
static int __init parse_highmem(char *arg)
{
	if (!arg)
		return -EINVAL;

	highmem_pages = memparse(arg, &arg) >> PAGE_SHIFT;
	return 0;
}
early_param("highmem", parse_highmem);

#define MSG_HIGHMEM_TOO_BIG \
	"highmem size (%luMB) is bigger than pages available (%luMB)!\n"

#define MSG_LOWMEM_TOO_SMALL \
	"highmem size (%luMB) results in <64MB lowmem, ignoring it!\n"
/*
 * All of RAM fits into lowmem - but if user wants highmem
 * artificially via the highmem=x boot parameter then create
 * it:
 */
/*
所有的物理内存都为常规内存
但是如果命令行参数配置了highmem
则从常规内存中创建高端内存
*/
void __init lowmem_pfn_init(void)
{
	/* max_low_pfn is 0, we already have early_res support */
	/* 记录常规内存最大页框号 */
	max_low_pfn = max_pfn;

	if (highmem_pages == -1)
		highmem_pages = 0;
#ifdef CONFIG_HIGHMEM
	/* 超过了物理内存 */
	if (highmem_pages >= max_pfn) {
		printk(KERN_ERR MSG_HIGHMEM_TOO_BIG,
			pages_to_mb(highmem_pages), pages_to_mb(max_pfn));
		highmem_pages = 0;
	}
	if (highmem_pages) {
		/* 留给常规内存的大小不能小于64MB */
		if (max_low_pfn - highmem_pages < 64*1024*1024/PAGE_SIZE) {
			printk(KERN_ERR MSG_LOWMEM_TOO_SMALL,
				pages_to_mb(highmem_pages));
			highmem_pages = 0;
		}
		max_low_pfn -= highmem_pages;
	}
#else
	if (highmem_pages)
		printk(KERN_ERR "ignoring highmem size on non-highmem kernel!\n");
#endif
}

#define MSG_HIGHMEM_TOO_SMALL \
	"only %luMB highmem pages available, ignoring highmem size of %luMB!\n"

#define MSG_HIGHMEM_TRIMMED \
	"Warning: only 4GB will be used. Use a HIGHMEM64G enabled kernel!\n"
/*
 * We have more RAM than fits into lowmem - we try to put it into
 * highmem, also taking the highmem=x boot parameter into account:
 */
/*
物理内存大于常规内存896MB
*/
void __init highmem_pfn_init(void)
{
	/* 常规内存对应的最大页框号 */
	max_low_pfn = MAXMEM_PFN;

	if (highmem_pages == -1)
		highmem_pages = max_pfn - MAXMEM_PFN;

	if (highmem_pages + MAXMEM_PFN < max_pfn)
		max_pfn = MAXMEM_PFN + highmem_pages;

	if (highmem_pages + MAXMEM_PFN > max_pfn) {
		printk(KERN_WARNING MSG_HIGHMEM_TOO_SMALL,
			pages_to_mb(max_pfn - MAXMEM_PFN),
			pages_to_mb(highmem_pages));
		highmem_pages = 0;
	}
#ifndef CONFIG_HIGHMEM
	/* Maximum memory usable is what is directly addressable */
	printk(KERN_WARNING "Warning only %ldMB will be used.\n", MAXMEM>>20);
	if (max_pfn > MAX_NONPAE_PFN)
		printk(KERN_WARNING "Use a HIGHMEM64G enabled kernel.\n");
	else
		printk(KERN_WARNING "Use a HIGHMEM enabled kernel.\n");
	/* 如果没有配置CONFIG_HIGHMEM的话
	   则会截断，只能使用到896MB */
	max_pfn = MAXMEM_PFN;
#else /* !CONFIG_HIGHMEM */
#ifndef CONFIG_HIGHMEM64G
	/* 如果没有配置CONFIG_HIGHMEM64G的话
	   那么最大页框号不会超过4GB对应的页框号
	   超过了则截断，只能处理到4GB */
	if (max_pfn > MAX_NONPAE_PFN) {
		max_pfn = MAX_NONPAE_PFN;
		printk(KERN_WARNING MSG_HIGHMEM_TRIMMED);
	}
#endif /* !CONFIG_HIGHMEM64G */
#endif /* !CONFIG_HIGHMEM */
}

/*
 * Determine low and high memory ranges:
 */
/*
根据配置
重新调整
设置常规内存最大页框号max_low_pfn
设置可以使用的物理内存最大页框号max_pfn
*/
void __init find_low_pfn_range(void)
{
	/* it could update max_pfn */

	/* 物理内存小于常规内存896MB */
	if (max_pfn <= MAXMEM_PFN)
		lowmem_pfn_init();
	/* 大于896MB */
	else
		highmem_pfn_init();
}

#ifndef CONFIG_NEED_MULTIPLE_NODES
/*
物理内存
+---------------+ <- max_pfn 		highend_pfn		num_physpages
|				|
|				|
|				| <- max_low_pfn 	highstart_pfn
|				|
|				|
|				|
|				|
+---------------+


*/
void __init initmem_init(void)
{
#ifdef CONFIG_HIGHMEM
	highstart_pfn = highend_pfn = max_pfn;
	if (max_pfn > max_low_pfn)
		highstart_pfn = max_low_pfn;
	memblock_x86_register_active_regions(0, 0, highend_pfn);
	sparse_memory_present_with_active_regions(0);
	printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
		pages_to_mb(highend_pfn - highstart_pfn));
	num_physpages = highend_pfn;
	/* 高端内存开始的虚拟地址 */
	high_memory = (void *) __va(highstart_pfn * PAGE_SIZE - 1) + 1;
#else
	memblock_x86_register_active_regions(0, 0, max_low_pfn);
	sparse_memory_present_with_active_regions(0);
	num_physpages = max_low_pfn;
	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE - 1) + 1;
#endif
#ifdef CONFIG_FLATMEM
	max_mapnr = num_physpages;
#endif
	__vmalloc_start_set = true;

	printk(KERN_NOTICE "%ldMB LOWMEM available.\n",
			pages_to_mb(max_low_pfn));

	setup_bootmem_allocator();
}
#endif /* !CONFIG_NEED_MULTIPLE_NODES */

static void __init zone_sizes_init(void)
{
	/* 各个区中最大的页框号 */
	unsigned long max_zone_pfns[MAX_NR_ZONES];
	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));
#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA] =
		virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
#endif
	max_zone_pfns[ZONE_NORMAL] = max_low_pfn;
#ifdef CONFIG_HIGHMEM
	max_zone_pfns[ZONE_HIGHMEM] = highend_pfn;
#endif

	free_area_init_nodes(max_zone_pfns);
}

void __init setup_bootmem_allocator(void)
{
	printk(KERN_INFO "  mapped low ram: 0 - %08lx\n",
		 max_pfn_mapped<<PAGE_SHIFT);
	printk(KERN_INFO "  low ram: 0 - %08lx\n", max_low_pfn<<PAGE_SHIFT);

	after_bootmem = 1;
}

/*
 * paging_init() sets up the page tables - note that the first 8MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
/*
pesky: 讨厌的

在arch/x86/kernel/head_32.S中只初始化了部分页表

这里也会取消掉虚拟地址0的映射，以便检查NULL指针引用
*/
void __init paging_init(void)
{
	pagetable_init();

	/* 刷新TLB缓存

	   将控制swapper_pg_dir送入控制寄存器cr3. 
	   每当重新设置cr3时，CPU就会将页面映射目录所在的页面装入CPU内部高速缓存中的TLB部分. 
	   现在内存中(实际上是高速缓存中)的映射目录变了，就要再让CPU装入一次。
	   由于页面映射机制本来就是开启着的，
	   所以从这条指令以后就扩大了系统空间中有映射区域的大小, 
	   使整个映射覆盖到整个物理内存(高端内存)除外. 
	   实际上此时swapper_pg_dir中已经改变的目录项很可能还在高速缓存中，
	   所以还要通过__flush_tlb_all()将高速缓存中的内容冲刷到内存中，
	   这样才能保证内存中映射目录内容的一致性。
	*/
	__flush_tlb_all();

	kmap_init();

	/*
	 * NOTE: at this point the bootmem allocator is fully available.
	 */
	olpc_dt_build_devicetree();
	sparse_memory_present_with_active_regions(MAX_NUMNODES);
	sparse_init();
	zone_sizes_init();
}

/*
 * Test if the WP bit works in supervisor mode. It isn't supported on 386's
 * and also on some strange 486's. All 586+'s are OK. This used to involve
 * black magic jumps to work around some nasty CPU bugs, but fortunately the
 * switch to using exceptions got rid of all that.
 */
static void __init test_wp_bit(void)
{
	printk(KERN_INFO
  "Checking if this processor honours the WP bit even in supervisor mode...");

	/* Any page-aligned address will do, the test is non-destructive */
	__set_fixmap(FIX_WP_TEST, __pa(&swapper_pg_dir), PAGE_READONLY);
	boot_cpu_data.wp_works_ok = do_test_wp_bit();
	clear_fixmap(FIX_WP_TEST);

	if (!boot_cpu_data.wp_works_ok) {
		printk(KERN_CONT "No.\n");
#ifdef CONFIG_X86_WP_WORKS_OK
		panic(
  "This kernel doesn't support CPU's with broken WP. Recompile it for a 386!");
#endif
	} else {
		printk(KERN_CONT "Ok.\n");
	}
}

void __init mem_init(void)
{
	int codesize, reservedpages, datasize, initsize;
	int tmp;

	pci_iommu_alloc();

#ifdef CONFIG_FLATMEM
	BUG_ON(!mem_map);
#endif
	/* this will put all low memory onto the freelists */
	totalram_pages += free_all_bootmem();

	reservedpages = 0;
	for (tmp = 0; tmp < max_low_pfn; tmp++)
		/*
		 * Only count reserved RAM pages:
		 */
		if (page_is_ram(tmp) && PageReserved(pfn_to_page(tmp)))
			reservedpages++;

	set_highmem_pages_init();

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	/* 打印内存信息，例如:

Memory: 472884k/524288k available (3285k kernel code, 50888k reserved, 1654k data, 420k init, 0k highmem)
virtual kernel memory layout:
    fixmap  : 0xffe6f000 - 0xfffff000   (1600 kB)
    pkmap   : 0xffa00000 - 0xffc00000   (2048 kB)
    vmalloc : 0xe0800000 - 0xff9fe000   ( 497 MB)
    lowmem  : 0xc0000000 - 0xe0000000   ( 512 MB)
      .init : 0xc14d4000 - 0xc153d000   ( 420 kB)
      .data : 0xc13354f8 - 0xc14d30c0   (1654 kB)
      .text : 0xc1000000 - 0xc13354f8   (3285 kB)

	*/
	printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, "
			"%dk reserved, %dk data, %dk init, %ldk highmem)\n",
		nr_free_pages() << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		totalhigh_pages << (PAGE_SHIFT-10));

	printk(KERN_INFO "virtual kernel memory layout:\n"
		"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
		"    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
		"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
		"      .init : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"      .data : 0x%08lx - 0x%08lx   (%4ld kB)\n"
		"      .text : 0x%08lx - 0x%08lx   (%4ld kB)\n",
		FIXADDR_START, FIXADDR_TOP,
		(FIXADDR_TOP - FIXADDR_START) >> 10,

#ifdef CONFIG_HIGHMEM
		PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
		(LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

		VMALLOC_START, VMALLOC_END,
		(VMALLOC_END - VMALLOC_START) >> 20,

		(unsigned long)__va(0), (unsigned long)high_memory,
		((unsigned long)high_memory - (unsigned long)__va(0)) >> 20,

		(unsigned long)&__init_begin, (unsigned long)&__init_end,
		((unsigned long)&__init_end -
		 (unsigned long)&__init_begin) >> 10,

		(unsigned long)&_etext, (unsigned long)&_edata,
		((unsigned long)&_edata - (unsigned long)&_etext) >> 10,

		(unsigned long)&_text, (unsigned long)&_etext,
		((unsigned long)&_etext - (unsigned long)&_text) >> 10);

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can
	 * be detected at build time already.
	 */
#define __FIXADDR_TOP (-PAGE_SIZE)
#ifdef CONFIG_HIGHMEM
	BUILD_BUG_ON(PKMAP_BASE + LAST_PKMAP*PAGE_SIZE	> FIXADDR_START);
	BUILD_BUG_ON(VMALLOC_END			> PKMAP_BASE);
#endif
#define high_memory (-128UL << 20)
	BUILD_BUG_ON(VMALLOC_START			>= VMALLOC_END);
#undef high_memory
#undef __FIXADDR_TOP

#ifdef CONFIG_HIGHMEM
	BUG_ON(PKMAP_BASE + LAST_PKMAP*PAGE_SIZE	> FIXADDR_START);
	BUG_ON(VMALLOC_END				> PKMAP_BASE);
#endif
	BUG_ON(VMALLOC_START				>= VMALLOC_END);
	BUG_ON((unsigned long)high_memory		> VMALLOC_START);

	if (boot_cpu_data.wp_works_ok < 0)
		test_wp_bit();
}

#ifdef CONFIG_MEMORY_HOTPLUG
int arch_add_memory(int nid, u64 start, u64 size)
{
	struct pglist_data *pgdata = NODE_DATA(nid);
	struct zone *zone = pgdata->node_zones + ZONE_HIGHMEM;
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long nr_pages = size >> PAGE_SHIFT;

	return __add_pages(nid, zone, start_pfn, nr_pages);
}
#endif

/*
 * This function cannot be __init, since exceptions don't work in that
 * section.  Put this after the callers, so that it cannot be inlined.
 */
static noinline int do_test_wp_bit(void)
{
	char tmp_reg;
	int flag;

	__asm__ __volatile__(
		"	movb %0, %1	\n"
		"1:	movb %1, %0	\n"
		"	xorl %2, %2	\n"
		"2:			\n"
		_ASM_EXTABLE(1b,2b)
		:"=m" (*(char *)fix_to_virt(FIX_WP_TEST)),
		 "=q" (tmp_reg),
		 "=r" (flag)
		:"2" (1)
		:"memory");

	return flag;
}

#ifdef CONFIG_DEBUG_RODATA
const int rodata_test_data = 0xC3;
EXPORT_SYMBOL_GPL(rodata_test_data);

int kernel_set_to_readonly __read_mostly;

void set_kernel_text_rw(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = PFN_ALIGN(_etext) - start;

	if (!kernel_set_to_readonly)
		return;

	pr_debug("Set kernel text: %lx - %lx for read write\n",
		 start, start+size);

	set_pages_rw(virt_to_page(start), size >> PAGE_SHIFT);
}

void set_kernel_text_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = PFN_ALIGN(_etext) - start;

	if (!kernel_set_to_readonly)
		return;

	pr_debug("Set kernel text: %lx - %lx for read only\n",
		 start, start+size);

	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
}

static void mark_nxdata_nx(void)
{
	/*
	 * When this called, init has already been executed and released,
	 * so everything past _etext should be NX.
	 */
	unsigned long start = PFN_ALIGN(_etext);
	/*
	 * This comes from is_kernel_text upper limit. Also HPAGE where used:
	 */
	unsigned long size = (((unsigned long)__init_end + HPAGE_SIZE) & HPAGE_MASK) - start;

	if (__supported_pte_mask & _PAGE_NX)
		printk(KERN_INFO "NX-protecting the kernel data: %luk\n", size >> 10);
	set_pages_nx(virt_to_page(start), size >> PAGE_SHIFT);
}

void mark_rodata_ro(void)
{
	unsigned long start = PFN_ALIGN(_text);
	unsigned long size = PFN_ALIGN(_etext) - start;

	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel text: %luk\n",
		size >> 10);

	kernel_set_to_readonly = 1;

#ifdef CONFIG_CPA_DEBUG
	printk(KERN_INFO "Testing CPA: Reverting %lx-%lx\n",
		start, start+size);
	set_pages_rw(virt_to_page(start), size>>PAGE_SHIFT);

	printk(KERN_INFO "Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size>>PAGE_SHIFT);
#endif

	start += size;
	size = (unsigned long)__end_rodata - start;
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
	printk(KERN_INFO "Write protecting the kernel read-only data: %luk\n",
		size >> 10);
	rodata_test();

#ifdef CONFIG_CPA_DEBUG
	printk(KERN_INFO "Testing CPA: undo %lx-%lx\n", start, start + size);
	set_pages_rw(virt_to_page(start), size >> PAGE_SHIFT);

	printk(KERN_INFO "Testing CPA: write protecting again\n");
	set_pages_ro(virt_to_page(start), size >> PAGE_SHIFT);
#endif
	mark_nxdata_nx();
}
#endif

