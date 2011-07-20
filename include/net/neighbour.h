#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 */

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

/*
邻接参数，与邻接和网卡设备相关联
*/
struct neigh_parms {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	/* 绑定的设备,给struct in_device用 */
	struct net_device *dev;
	/* 每个dev都有相应的neigh_parms,通过arp_tbl.parms.next组织 */
	struct neigh_parms *next;
	/* 与设备相关的setup,一般为空 */
	int	(*neigh_setup)(struct neighbour *);
	/* 与设备相关的cleanup,一般为空 */
	void	(*neigh_cleanup)(struct neighbour *);
	/* 指向所属邻接表 */
	struct neigh_table *tbl;

	/* system control, /proc/sys/net/ipv4/neigh */
	void	*sysctl_table;

	/* 死亡标志 */
	int dead;
	/* 邻接引用计数 */
	atomic_t refcnt;
	struct rcu_head rcu_head;

	/* 几种邻接状态定时器 */
	/* 默认30sec */
	int	base_reachable_time;
	/* 默认1sec */
	int	retrans_time;
	/* 默认60sec */
	int	gc_staletime;
	/* 默认30sec,通过neigh_rand_reach_time初始化为1/2 base_reachable_time */
	int	reachable_time;
	/* 默认5sec */
	int	delay_probe_time;

	/* arp缓存队列长度，默认3个skb */
	int	queue_len;
	/* 单播探测,默认3次 */
	int	ucast_probes;
	/* 应用探测,默认0次 */
	int	app_probes;
	/* 多播探测,默认3次 */
	int	mcast_probes;
	/* 探测延迟,默认1秒 */
	int	anycast_delay;
	/* 代理延迟,默认4/5秒 */
	int	proxy_delay;
	/* arp代理队列长度,默认64 */
	int	proxy_qlen;
	/* 邻接锁定时间,默认1秒,即如果邻接发生变化,会有一秒的锁定时间,防变化过于频繁 */
	int	locktime;
};

struct neigh_statistics {
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* number of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */

	unsigned long unres_discards;	/* number of unresolved drops */
};

#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)

/*
在Linux内核中, 将能与自已在硬件层直接通信的外部主机的网络接口设备称为"邻居",
用neighbour结构描述, 它包含设备的硬件地址信息.
系统中所有的IP包都通过路由所绑定的邻居发送到接口设备上. 
邻居由邻居表(arp_tbl)来索引, 用邻居的IP地址可查询邻居表中某个设备的邻居.

每个neighbour结构都通过neigh_ops定义了一组操作函数集,
neigh_ops结构都由其父亲neigh_table定义的构造函数填充
*/
struct neighbour {
	/* 处理hash冲突的链表 */
	struct neighbour __rcu	*next;
	/* 所在的邻居表，指向上层的neigh_table结构，指向arp_tbl */
	struct neigh_table	*tbl;
	/* 指向设备邻接参数 */
	struct neigh_parms	*parms;
	/* 确认时间 */
	unsigned long		confirmed;
	/* 最近邻接更新时间 */
	unsigned long		updated;
	/* 邻接锁 */
	rwlock_t		lock;
	/* 引用计数 */
	atomic_t		refcnt;
	/* arp队列
	   当邻居接收到要发送的IP包时, 如果邻居的硬件地址还未解析,
	   则将发送包暂时缓冲在arp_queue队列中,然后发送地址解析请求,
	   这时的状态为未完成状态(NUD_INCOMPLETE).
	   如果1秒内没收到外部设备应答, 邻居将重发arp请求, 
	   如果重发达到3次, 则解析失败, 邻居为失败状态(NUD_FAILED).
	   当收到正确应答, 邻居进入连接状态(NUD_REACHABLE),
	   这时arp_queue中发送包将被创建帧头后发送到设备上 */
	struct sk_buff_head	arp_queue;
	/* 定时器 */
	struct timer_list	timer;
	/* 最近使用时间 */
	unsigned long		used;
	/* 探测次数，会动态变化 */
	atomic_t		probes;
	/* 邻接标记，参考neigh_update() */
	__u8			flags;
	/* 邻接状态 */
	__u8			nud_state;
	__u8			type;
	/* 死亡标志，1表示该项还未激活 */
	__u8			dead;
	seqlock_t		ha_lock;
	/* 硬件地址 */
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	/* 邻接缓存指针
	   hh 指向 hh_cache，此结构用于 cache L2 地址，以加速 L3 到 L2 的映射过程

	   为了缩短IP包到设备的传输路径, 
	   在邻居结构上还引入了帧头缓冲结构(hh_cache).
	   如果邻居建立了帧头缓冲, IP包将通过帧头缓冲的输出发送出去. 
	   当邻居处于连接状态时, 帧头缓冲输出直接指向dev_queue_xmit(), 
	   当处于过期状态时, 帧头缓冲输出切换为邻居的输出口, 
	   对以太网设备来说,邻居的输出口指向neigh_resolve_output(),
	   neigh_connect()和neigh_suspect()两个函数用来进行这种切换. */
	struct hh_cache		*hh;
	/* 邻接输出函数,会变
	   找到合适的邻居节点之后，系统将调用这个函数指针，
	   使用结构中的dev设备，将数据包发送出去，
	   如果协议族是AF_INET，将调用dev_queue_xmit()函数发送数据

	   对于 output 域，关键是看 neighbour 的状态，
	   如果是有效状态，则设置为ops->connected_output()，这样可以加快速度，
	   否则设置为 ops->output()，这样，需要进行neighbor discovery 的处理。
	   对于 ARP 来说，无论是 output ，
	   还是 connect_output都是指向 neigh_resolve_output()。
	   neigh_resolve_output() 进行 neighbor discovery 的过程。 */
	int			(*output)(struct sk_buff *skb);
	/* 邻接操作函数数据结构
	   根据底层 driver 的类型进行不同的设置，
	   对于没有链路层地址的，指向arp_direct_ops
	   对于没有链路层 cache 的，指向arp_generic_ops
	   对于有链路层 cache 的， 指向arp_hh_ops

	   对于以太网驱动程序，它的 net_device 结构在初始化的时候，
	   已经有了默认的 hard_header 和 hard_header_cache 函数，
	   参考ether_setup()
	   			dev->hard_header        = eth_header;
	      		dev->hard_header_cache  = eth_header_cache;
	   因此，默认情况下，它的 ops 指向 arp_hh_ops() */
	const struct neigh_ops	*ops;
	struct rcu_head		rcu;
	/* 邻居所对应的网络设备接口指针 */
	struct net_device	*dev;
	/* 哈希关键字,用于存放IP地址 */
	u8			primary_key[0];
};

struct neigh_ops {
	int			family;
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	int			(*output)(struct sk_buff*);
	int			(*connected_output)(struct sk_buff*);
	int			(*hh_output)(struct sk_buff*);
	int			(*queue_xmit)(struct sk_buff*);
};

struct pneigh_entry {
	struct pneigh_entry	*next;
#ifdef CONFIG_NET_NS
	struct net		*net;
#endif
	struct net_device	*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

/*
对该结构的分配由neigh_hash_alloc()完成
*/
struct neigh_hash_table {
	/* 哈希数组，存入其中的邻居，
	   在一个neigh_table里面，最多可以有32个neighbour结构的链表 */
	struct neighbour __rcu	**hash_buckets;
	/* 哈希数组大小的掩码
	   +1为目前桶头节点指针数组的大小，数组大小总是2的幂次
	   hash_mask初始为(8-1)，参考neigh_table_init_no_netlink()
	   会动态增长 */
	unsigned int		hash_mask;
	/* hash随机种子，初始化时赋值 */
	__u32			hash_rnd;
	struct rcu_head		rcu;
};


/*
描述邻居表的结构
例如arp_tbl
*/
struct neigh_table {
	/* 用于挂接到neigh_tables全局链表
	   下一个邻居表,实际上就是ARP报文到达的下一台机器 */
	struct neigh_table	*next;
	/* 地址族，对于以太网而言就是 AF_INET，协议簇(PF_INET)
	   arp协议用于解析IPv4地址与物理地址之间的对应关系 */
	int			family;
	/* 入口长度,也就是一个邻居结构的大小
	   因为hashkey为IPv4地址，故此处为sizeof(struct neighbour)+4
	   参考arp_tbl的定义 */
	int			entry_size;
	/* 哈希关键值长度 即IP地址的长度，为4 */
	int			key_len;
	/* 构造出存放和检索这个neigh_table的neighbour的哈希函数 */
	__u32			(*hash)(const void *pkey,
					const struct net_device *dev,
					__u32 hash_rnd);
	int			(*constructor)(struct neighbour *);
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;
	struct neigh_parms	parms;
	/* HACK. gc_* should follow parms without a gap! */
	int			gc_interval;
	int			gc_thresh1;
	int			gc_thresh2;
	/* 允许邻居的上限，根据网络的类型，大小会有所变化，
	   例如C类地址，邻居限制就应该小于255 */
	int			gc_thresh3;
	unsigned long		last_flush;
	struct delayed_work	gc_work;
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue;
	/* 记录已有邻居表条数 */
	atomic_t		entries;
	rwlock_t		lock;
	unsigned long		last_rand;
	struct kmem_cache	*kmem_cachep;
	struct neigh_statistics	__percpu *stats;
	/* 邻居哈希表 */
	struct neigh_hash_table __rcu *nht;
	/* 邻接代理hash表 */
	struct pneigh_entry	**phash_buckets;
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   struct net *net,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net			*neigh_parms_net(const struct neigh_parms *parms)
{
	return read_pnet(&parms->net);
}

extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev, int creat);
extern struct pneigh_entry	*__pneigh_lookup(struct neigh_table *tbl,
						 struct net *net,
						 const void *key,
						 struct net_device *dev);
extern int			pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev);

static inline
struct net			*pneigh_net(const struct pneigh_entry *pneigh)
{
	return read_pnet(&pneigh->net);
}

extern void neigh_app_ns(struct neighbour *n);
extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	struct neigh_hash_table *nht;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      char *p_name,
						      proc_handler *proc_handler);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	/* 若引用计数减1后为0了，则释放该邻居表节点 */
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	unsigned long now = jiffies;
	
	if (neigh->used != now)
		neigh->used = now;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

#ifdef CONFIG_BRIDGE_NETFILTER
static inline int neigh_hh_bridge(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq, hh_alen;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(ETH_HLEN);
		memcpy(skb->data - hh_alen, hh->hh_data, ETH_ALEN + hh_alen - ETH_HLEN);
	} while (read_seqretry(&hh->hh_lock, seq));
	return 0;
}
#endif

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	/* 到哈希表中查找 */
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	/* 找到则返回找到的节点指针
	   若未找到，又不创建新节点，则返回NULL */
	if (n || !creat)
		return n;

	/* 创建新的邻居表节点 */
	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	/* 找不到的时候创建新的 */
	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

static inline void neigh_ha_snapshot(char *dst, const struct neighbour *n,
				     const struct net_device *dev)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&n->ha_lock);
		memcpy(dst, n->ha, dev->addr_len);
	} while (read_seqretry(&n->ha_lock, seq));
}
#endif
