#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

struct netns_frags {
	int			nqueues;
	/* 记录分配的ipq空间大小及skb所分配的空间大小之和 */
	atomic_t		mem;
	struct list_head	lru_list;

	/* sysctls */
	int			timeout;
	int			high_thresh;
	int			low_thresh;
};

struct inet_frag_queue {
	/* list用于链入struct inet_frags中的hash[]数组对应的桶中 */
	struct hlist_node	list;
	struct netns_frags	*net;
	/* 链入最近最少使用的链表 */
	struct list_head	lru_list;   /* lru list member */
	/* 分片链表锁 */
	spinlock_t		lock;
	/* 引用计数 */
	atomic_t		refcnt;
	struct timer_list	timer;      /* when will this queue expire? */
	/* 组成链表 */
	struct sk_buff		*fragments; /* list of received fragments */
	/* 指向最后一个skb，加速查找 */
	struct sk_buff		*fragments_tail;
	ktime_t			stamp;
	/* 记录所有IP分片数据可能的总长度 */
	int			len;        /* total length of orig datagram */
	/* 记录已经接收到的分片数据长度 */
	int			meat;
	/* 标记分片链表的状态 */
	__u8			last_in;    /* first/last segment arrived? */

#define INET_FRAG_COMPLETE	4
#define INET_FRAG_FIRST_IN	2
#define INET_FRAG_LAST_IN	1
};

#define INETFRAGS_HASHSZ		64

struct inet_frags {
	/* 链入结构struct inet_frag_queue */
	struct hlist_head	hash[INETFRAGS_HASHSZ];
	rwlock_t		lock;
	u32			rnd;
	int			qsize;
	int			secret_interval;
	struct timer_list	secret_timer;

	unsigned int		(*hashfn)(struct inet_frag_queue *);
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);
	void			(*destructor)(struct inet_frag_queue *);
	void			(*skb_free)(struct sk_buff *);
	int			(*match)(struct inet_frag_queue *q,
						void *arg);
	void			(*frag_expire)(unsigned long data);
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frags_init_net(struct netns_frags *nf);
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f);
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
	__releases(&f->lock);

/*
@q的引用计数减1
减1后为0的话则取消定时器，释放相关的各个空间等
*/
static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

#endif
