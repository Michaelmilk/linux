/*
 * inet fragments management
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * 		Authors:	Pavel Emelyanov <xemul@openvz.org>
 *				Started as consolidation of ipv4/ip_fragment.c,
 *				ipv6/reassembly. and ipv6 nf conntrack reassembly
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>

#include <net/sock.h>
#include <net/inet_frag.h>
#include <net/inet_ecn.h>

/* Given the OR values of all fragments, apply RFC 3168 5.3 requirements
 * Value : 0xff if frame should be dropped.
 *         0 or INET_ECN_CE value, to be ORed in to final iph->tos field
 */
const u8 ip_frag_ecn_table[16] = {
	/* at least one fragment had CE, and others ECT_0 or ECT_1 */
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1]	= INET_ECN_CE,

	/* invalid combinations : drop frame */
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
};
EXPORT_SYMBOL(ip_frag_ecn_table);

static void inet_frag_secret_rebuild(unsigned long dummy)
{
	struct inet_frags *f = (struct inet_frags *)dummy;
	unsigned long now = jiffies;
	int i;

	/* Per bucket lock NOT needed here, due to write lock protection */
	write_lock(&f->lock);

	get_random_bytes(&f->rnd, sizeof(u32));
	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_bucket *hb;
		struct inet_frag_queue *q;
		struct hlist_node *n;

		hb = &f->hash[i];
		hlist_for_each_entry_safe(q, n, &hb->chain, list) {
			unsigned int hval = f->hashfn(q);

			if (hval != i) {
				struct inet_frag_bucket *hb_dest;

				hlist_del(&q->list);

				/* Relink to new hash chain. */
				hb_dest = &f->hash[hval];
				hlist_add_head(&q->list, &hb_dest->chain);
			}
		}
	}
	write_unlock(&f->lock);

	mod_timer(&f->secret_timer, now + f->secret_interval);
}

void inet_frags_init(struct inet_frags *f)
{
	int i;

	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_bucket *hb = &f->hash[i];

		spin_lock_init(&hb->chain_lock);
		INIT_HLIST_HEAD(&hb->chain);
	}
	rwlock_init(&f->lock);

	f->rnd = (u32) ((num_physpages ^ (num_physpages>>7)) ^
				   (jiffies ^ (jiffies >> 6)));

	setup_timer(&f->secret_timer, inet_frag_secret_rebuild,
			(unsigned long)f);
	f->secret_timer.expires = jiffies + f->secret_interval;
	add_timer(&f->secret_timer);
}
EXPORT_SYMBOL(inet_frags_init);

void inet_frags_init_net(struct netns_frags *nf)
{
	nf->nqueues = 0;
	init_frag_mem_limit(nf);
	INIT_LIST_HEAD(&nf->lru_list);
	spin_lock_init(&nf->lru_lock);
}
EXPORT_SYMBOL(inet_frags_init_net);

void inet_frags_fini(struct inet_frags *f)
{
	del_timer(&f->secret_timer);
}
EXPORT_SYMBOL(inet_frags_fini);

void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	nf->low_thresh = 0;

	local_bh_disable();
	inet_frag_evictor(nf, f, true);
	local_bh_enable();

	percpu_counter_destroy(&nf->mem);
}
EXPORT_SYMBOL(inet_frags_exit_net);

/*
将@fq从各个管理链表中移出
*/
static inline void fq_unlink(struct inet_frag_queue *fq, struct inet_frags *f)
{
	struct inet_frag_bucket *hb;
	unsigned int hash;

	read_lock(&f->lock);
	hash = f->hashfn(fq);
	hb = &f->hash[hash];

	spin_lock(&hb->chain_lock);
	hlist_del(&fq->list);
	spin_unlock(&hb->chain_lock);

	read_unlock(&f->lock);
	inet_frag_lru_del(fq);
}

void inet_frag_kill(struct inet_frag_queue *fq, struct inet_frags *f)
{
	if (del_timer(&fq->timer))
		atomic_dec(&fq->refcnt);

	if (!(fq->last_in & INET_FRAG_COMPLETE)) {
		fq_unlink(fq, f);
		atomic_dec(&fq->refcnt);
		/* 标记分片已经完整了 */
		fq->last_in |= INET_FRAG_COMPLETE;
	}
}
EXPORT_SYMBOL(inet_frag_kill);

static inline void frag_kfree_skb(struct netns_frags *nf, struct inet_frags *f,
		struct sk_buff *skb)
{
	if (f->skb_free)
		f->skb_free(skb);
	kfree_skb(skb);
}

void inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f,
					int *work)
{
	struct sk_buff *fp;
	struct netns_frags *nf;
	unsigned int sum, sum_truesize = 0;

	WARN_ON(!(q->last_in & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	/* Release all fragment data. */
	fp = q->fragments;
	nf = q->net;
	while (fp) {
		struct sk_buff *xp = fp->next;

		sum_truesize += fp->truesize;
		frag_kfree_skb(nf, f, fp);
		fp = xp;
	}
	sum = sum_truesize + f->qsize;
	if (work)
		*work -= sum;
	sub_frag_mem_limit(q, sum);

	/* ipfrag_init()中为ip4_frags注册的destructor函数为ip4_frag_free() */
	if (f->destructor)
		f->destructor(q);
	/* 释放分片的管理结构空间
	   改指针指向的是@q，inet_frag_alloc()中分配空间时包含ipq余下的空间
	   即释放了一个ipq管理结构空间 */
	kfree(q);

}
EXPORT_SYMBOL(inet_frag_destroy);

/*

force	: true  - 超过low_thresh清理
	  false - 超过high_thresh才清理
*/
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f, bool force)
{
	struct inet_frag_queue *q;
	int work, evicted = 0;

	if (!force) {
		if (frag_mem_limit(nf) <= nf->high_thresh)
			return 0;
	}

	work = frag_mem_limit(nf) - nf->low_thresh;
	while (work > 0) {
		spin_lock(&nf->lru_lock);

		if (list_empty(&nf->lru_list)) {
			spin_unlock(&nf->lru_lock);
			break;
		}

		/* 链表第一个节点，即最老的节点 */
		q = list_first_entry(&nf->lru_list,
				struct inet_frag_queue, lru_list);
		atomic_inc(&q->refcnt);
		/* Remove q from list to avoid several CPUs grabbing it */
		list_del_init(&q->lru_list);

		spin_unlock(&nf->lru_lock);

		spin_lock(&q->lock);
		if (!(q->last_in & INET_FRAG_COMPLETE))
			inet_frag_kill(q, f);
		spin_unlock(&q->lock);

		/* 减1后引用为0 */
		if (atomic_dec_and_test(&q->refcnt))
			/* 释放inet_frag_queue */
			inet_frag_destroy(q, f, &work);
		evicted++;
	}

	return evicted;
}
EXPORT_SYMBOL(inet_frag_evictor);

static struct inet_frag_queue *inet_frag_intern(struct netns_frags *nf,
		struct inet_frag_queue *qp_in, struct inet_frags *f,
		void *arg)
{
	struct inet_frag_bucket *hb;
	struct inet_frag_queue *qp;
#ifdef CONFIG_SMP
#endif
	unsigned int hash;

	read_lock(&f->lock); /* Protects against hash rebuild */
	/*
	 * While we stayed w/o the lock other CPU could update
	 * the rnd seed, so we need to re-calculate the hash
	 * chain. Fortunatelly the qp_in can be used to get one.
	 */
	/* 根据ipfrag_init()中为ip4_frags.hashfn初始化为
	   ip4_hashfn()
	   计算新节点所在的哈希桶下标 */
	hash = f->hashfn(qp_in);
	hb = &f->hash[hash];
	spin_lock(&hb->chain_lock);

#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * released the hash bucket lock.
	 */

	/* 在SMP情况下，前面查找的时候使用的是读锁
	   现在创建了新的节点要加入链表，获得了写锁
	   再次查找看是否在读锁期间，已经在另外的cpu上创建了相同key的分片管理节点
	   有相同的话则释放这个@qp_in */
	hlist_for_each_entry(qp, &hb->chain, list) {
		if (qp->net == nf && f->match(qp, arg)) {
			atomic_inc(&qp->refcnt);
			spin_unlock(&hb->chain_lock);
			read_unlock(&f->lock);
			qp_in->last_in |= INET_FRAG_COMPLETE;
			inet_frag_put(qp_in, f);
			/* 返回已经存在的那个管理节点 */
			return qp;
		}
	}
#endif
	qp = qp_in;
	if (!mod_timer(&qp->timer, jiffies + nf->timeout))
		atomic_inc(&qp->refcnt);

	/* 增加引用计数，此时应该为0增加为1 */
	atomic_inc(&qp->refcnt);
	/* 链入struct inet_frags的hash[]数组 */
	hlist_add_head(&qp->list, &hb->chain);
	spin_unlock(&hb->chain_lock);
	read_unlock(&f->lock);
	inet_frag_lru_add(nf, qp);
	return qp;
}

/*
分配一个新的ipq结构大小的空间
然后初始化记录各项参数
*/
static struct inet_frag_queue *inet_frag_alloc(struct netns_frags *nf,
		struct inet_frags *f, void *arg)
{
	struct inet_frag_queue *q;

	/* 分配的大小实际上是struct ipq的大小
	   参考函数ipfrag_init() */
	q = kzalloc(f->qsize, GFP_ATOMIC);
	if (q == NULL)
		return NULL;

	/* 记录所属的命名空间分片结构 */
	q->net = nf;
	/* 依据函数ipfrag_init()为ip4_frags的constructor赋值为
	   ip4_frag_init()
	   在新分配的节点q中记录新报文的各项参数 */
	f->constructor(q, arg);
	/* 记录内存分配 */
	add_frag_mem_limit(q, f->qsize);

	/* 注册定时器函数ip_expire() */
	setup_timer(&q->timer, f->frag_expire, (unsigned long)q);
	spin_lock_init(&q->lock);
	/* 引用记录置为1 */
	atomic_set(&q->refcnt, 1);
	INIT_LIST_HEAD(&q->lru_list);

	/* 返回新节点 */
	return q;
}

static struct inet_frag_queue *inet_frag_create(struct netns_frags *nf,
		struct inet_frags *f, void *arg)
{
	struct inet_frag_queue *q;

	q = inet_frag_alloc(nf, f, arg);
	if (q == NULL)
		return NULL;

	return inet_frag_intern(nf, q, f, arg);
}

/*
查找一个ipq管理节点
没有则创建一个新的
*/
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
	__releases(&f->lock)
{
	struct inet_frag_bucket *hb;
	struct inet_frag_queue *q;
	int depth = 0;

	hb = &f->hash[hash];

	spin_lock(&hb->chain_lock);
	/* 根据计算出的@hash值下标
	   遍历对应桶下面的链表 */
	hlist_for_each_entry(q, &hb->chain, list) {
		/* ipfrag_init()中初始化变量ip4_frags时的match()方法为
		   ip4_frag_match()
		   判断链表中的节点q是否与传递进来的key参数一致 */
		if (q->net == nf && f->match(q, key)) {
			atomic_inc(&q->refcnt);
			spin_unlock(&hb->chain_lock);
			read_unlock(&f->lock);
			return q;
		}
		depth++;
	}
	spin_unlock(&hb->chain_lock);
	read_unlock(&f->lock);

	if (depth <= INETFRAGS_MAXDEPTH)
		return inet_frag_create(nf, f, key);
	else
		return ERR_PTR(-ENOBUFS);
}
EXPORT_SYMBOL(inet_frag_find);

void inet_frag_maybe_warn_overflow(struct inet_frag_queue *q,
				   const char *prefix)
{
	static const char msg[] = "inet_frag_find: Fragment hash bucket"
		" list length grew over limit " __stringify(INETFRAGS_MAXDEPTH)
		". Dropping fragment.\n";

	if (PTR_ERR(q) == -ENOBUFS)
		LIMIT_NETDEBUG(KERN_WARNING "%s%s", prefix, msg);
}
EXPORT_SYMBOL(inet_frag_maybe_warn_overflow);
