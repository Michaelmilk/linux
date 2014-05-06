#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 */

/* 管理一个高速缓存 */
struct kmem_cache {
/* 1) Cache tunables. Protected by slab_mutex */

	/* 要转移本地高速缓存的大批对象的数量 */

	unsigned int batchcount;
	/* 本地高速缓存中空闲对象的最大数目 */
	unsigned int limit;
	unsigned int shared;

	/* 高速缓存的大小 */
	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	/* 描述高速缓存永久属性的一组标志 */
	unsigned int flags;		/* constant flags */
	/* 封装在一个单独slab中的对象个数 */
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	/* 一个单独slab中包含的连续页框数目的对数 */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags;

	/* slab使用的颜色个数 */
	size_t colour;			/* cache colouring range */
	/* slab中的基本对齐偏移 */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	/* 存放高速缓存名字的字符数组 */
	const char *name;
	/* 高速缓存描述符双向链表使用的指针 */
	struct list_head list;
	int refcount;
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
	struct memcg_cache_params *memcg_params;
#endif

/* 6) per-cpu/per-node data, touched during every alloc/free */
	/*
	 * We put array[] at the end of kmem_cache, because we want to size
	 * this array to nr_cpu_ids slots instead of NR_CPUS
	 * (see kmem_cache_init())
	 * We still use [NR_CPUS] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of cpus.
	 *
	 * We also need to guarantee that the list is able to accomodate a
	 * pointer for each node since "nodelists" uses the remainder of
	 * available pointers.
	 */

	/* 高速缓存中的slab链表 */

	struct kmem_cache_node **node;
	struct array_cache *array[NR_CPUS + MAX_NUMNODES];
	/*
	 * Do not add fields after array[]
	 */
};

#endif	/* _LINUX_SLAB_DEF_H */
