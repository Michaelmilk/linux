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

#include <net/inet_frag.h>

static void inet_frag_secret_rebuild(unsigned long dummy)
{
	struct inet_frags *f = (struct inet_frags *)dummy;
	unsigned long now = jiffies;
	int i;

	write_lock(&f->lock);
	get_random_bytes(&f->rnd, sizeof(u32));
	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_queue *q;
		struct hlist_node *p, *n;

		hlist_for_each_entry_safe(q, p, n, &f->hash[i], list) {
			unsigned int hval = f->hashfn(q);

			if (hval != i) {
				hlist_del(&q->list);

				/* Relink to new hash chain. */
				hlist_add_head(&q->list, &f->hash[hval]);
			}
		}
	}
	write_unlock(&f->lock);

	mod_timer(&f->secret_timer, now + f->secret_interval);
}

void inet_frags_init(struct inet_frags *f)
{
	int i;

	for (i = 0; i < INETFRAGS_HASHSZ; i++)
		INIT_HLIST_HEAD(&f->hash[i]);

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
	atomic_set(&nf->mem, 0);
	INIT_LIST_HEAD(&nf->lru_list);
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
	inet_frag_evictor(nf, f);
	local_bh_enable();
}
EXPORT_SYMBOL(inet_frags_exit_net);

/*
将@fq从各个管理链表中移出
*/
static inline void fq_unlink(struct inet_frag_queue *fq, struct inet_frags *f)
{
	write_lock(&f->lock);
	hlist_del(&fq->list);
	list_del(&fq->lru_list);
	fq->net->nqueues--;
	write_unlock(&f->lock);
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
		struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;

	atomic_sub(skb->truesize, &nf->mem);
	if (f->skb_free)
		f->skb_free(skb);
	kfree_skb(skb);
}

void inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f,
					int *work)
{
	struct sk_buff *fp;
	struct netns_frags *nf;

	WARN_ON(!(q->last_in & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	/* Release all fragment data. */
	fp = q->fragments;
	nf = q->net;
	while (fp) {
		struct sk_buff *xp = fp->next;

		frag_kfree_skb(nf, f, fp, work);
		fp = xp;
	}

	if (work)
		*work -= f->qsize;
	atomic_sub(f->qsize, &nf->mem);

	/* ipfrag_init()中为ip4_frags注册的destructor函数为ip4_frag_free() */
	if (f->destructor)
		f->destructor(q);
	/* 释放分片的管理结构空间
	   改指针指向的是@q，inet_frag_alloc()中分配空间时包含ipq余下的空间
	   即释放了一个ipq管理结构空间 */
	kfree(q);

}
EXPORT_SYMBOL(inet_frag_destroy);

int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f)
{
	struct inet_frag_queue *q;
	int work, evicted = 0;

	work = atomic_read(&nf->mem) - nf->low_thresh;
	while (work > 0) {
		read_lock(&f->lock);
		if (list_empty(&nf->lru_list)) {
			read_unlock(&f->lock);
			break;
		}

		q = list_first_entry(&nf->lru_list,
				struct inet_frag_queue, lru_list);
		atomic_inc(&q->refcnt);
		read_unlock(&f->lock);

		spin_lock(&q->lock);
		if (!(q->last_in & INET_FRAG_COMPLETE))
			inet_frag_kill(q, f);
		spin_unlock(&q->lock);

		if (atomic_dec_and_test(&q->refcnt))
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
	struct inet_frag_queue *qp;
#ifdef CONFIG_SMP
	struct hlist_node *n;
#endif
	unsigned int hash;

	write_lock(&f->lock);
	/*
	 * While we stayed w/o the lock other CPU could update
	 * the rnd seed, so we need to re-calculate the hash
	 * chain. Fortunatelly the qp_in can be used to get one.
	 */
	/* 根据ipfrag_init()中为ip4_frags.hashfn初始化为
	   ip4_hashfn()
	   计算新节点所在的哈希桶下标 */
	hash = f->hashfn(qp_in);
#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * promoted read lock to write lock.
	 */
	/* 在SMP情况下，前面查找的时候使用的是读锁
	   现在创建了新的节点要加入链表，获得了写锁
	   再次查找看是否在读锁期间，已经在另外的cpu上创建了相同key的分片管理节点
	   有相同的话则释放这个@qp_in */
	hlist_for_each_entry(qp, n, &f->hash[hash], list) {
		if (qp->net == nf && f->match(qp, arg)) {
			atomic_inc(&qp->refcnt);
			write_unlock(&f->lock);
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
	hlist_add_head(&qp->list, &f->hash[hash]);
	/* 增加到最近最少使用链表的末尾 */
	list_add_tail(&qp->lru_list, &nf->lru_list);
	/* 统计分片节点ipq的个数 */
	nf->nqueues++;
	/* 释放写锁 */
	write_unlock(&f->lock);
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

	/* 依据函数ipfrag_init()为ip4_frags的constructor赋值为
	   ip4_frag_init()
	   在新分配的节点q中记录新报文的各项参数 */
	f->constructor(q, arg);
	/* 记录内存分配 */
	atomic_add(f->qsize, &nf->mem);
	/* 注册定时器函数ip_expire() */
	setup_timer(&q->timer, f->frag_expire, (unsigned long)q);
	spin_lock_init(&q->lock);
	/* 引用记录置为1 */
	atomic_set(&q->refcnt, 1);
	/* 记录所属的命名空间分片结构 */
	q->net = nf;

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
	struct inet_frag_queue *q;
	struct hlist_node *n;

	/* 根据计算出的@hash值下标
	   遍历对应桶下面的链表 */
	hlist_for_each_entry(q, n, &f->hash[hash], list) {
		/* ipfrag_init()中初始化变量ip4_frags时的match()方法为
		   ip4_frag_match()
		   判断链表中的节点q是否与传递进来的key参数一致 */
		if (q->net == nf && f->match(q, key)) {
			atomic_inc(&q->refcnt);
			read_unlock(&f->lock);
			return q;
		}
	}
	read_unlock(&f->lock);

	return inet_frag_create(nf, f, key);
}
EXPORT_SYMBOL(inet_frag_find);
