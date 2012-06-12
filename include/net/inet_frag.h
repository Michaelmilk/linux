#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

struct netns_frags {
	int			nqueues;
	/* ��¼�����ipq�ռ��С��skb������Ŀռ��С֮�� */
	atomic_t		mem;
	struct list_head	lru_list;

	/* sysctls */
	int			timeout;
	int			high_thresh;
	int			low_thresh;
};

struct inet_frag_queue {
	/* list��������struct inet_frags�е�hash[]�����Ӧ��Ͱ�� */
	struct hlist_node	list;
	struct netns_frags	*net;
	/* �����������ʹ�õ����� */
	struct list_head	lru_list;   /* lru list member */
	/* ��Ƭ������ */
	spinlock_t		lock;
	/* ���ü��� */
	atomic_t		refcnt;
	struct timer_list	timer;      /* when will this queue expire? */
	/* ������� */
	struct sk_buff		*fragments; /* list of received fragments */
	/* ָ�����һ��skb�����ٲ��� */
	struct sk_buff		*fragments_tail;
	ktime_t			stamp;
	/* ��¼����IP��Ƭ���ݿ��ܵ��ܳ��� */
	int			len;        /* total length of orig datagram */
	/* ��¼�Ѿ����յ��ķ�Ƭ���ݳ��� */
	int			meat;
	/* ��Ƿ�Ƭ�����״̬ */
	__u8			last_in;    /* first/last segment arrived? */

#define INET_FRAG_COMPLETE	4
#define INET_FRAG_FIRST_IN	2
#define INET_FRAG_LAST_IN	1
};

#define INETFRAGS_HASHSZ		64

struct inet_frags {
	/* ����ṹstruct inet_frag_queue */
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
	bool			(*match)(struct inet_frag_queue *q, void *arg);
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
@q�����ü�����1
��1��Ϊ0�Ļ���ȡ����ʱ�����ͷ���صĸ����ռ��
*/
static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

#endif
