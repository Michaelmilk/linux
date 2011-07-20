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
�ڽӲ��������ڽӺ������豸�����
*/
struct neigh_parms {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	/* �󶨵��豸,��struct in_device�� */
	struct net_device *dev;
	/* ÿ��dev������Ӧ��neigh_parms,ͨ��arp_tbl.parms.next��֯ */
	struct neigh_parms *next;
	/* ���豸��ص�setup,һ��Ϊ�� */
	int	(*neigh_setup)(struct neighbour *);
	/* ���豸��ص�cleanup,һ��Ϊ�� */
	void	(*neigh_cleanup)(struct neighbour *);
	/* ָ�������ڽӱ� */
	struct neigh_table *tbl;

	/* system control, /proc/sys/net/ipv4/neigh */
	void	*sysctl_table;

	/* ������־ */
	int dead;
	/* �ڽ����ü��� */
	atomic_t refcnt;
	struct rcu_head rcu_head;

	/* �����ڽ�״̬��ʱ�� */
	/* Ĭ��30sec */
	int	base_reachable_time;
	/* Ĭ��1sec */
	int	retrans_time;
	/* Ĭ��60sec */
	int	gc_staletime;
	/* Ĭ��30sec,ͨ��neigh_rand_reach_time��ʼ��Ϊ1/2 base_reachable_time */
	int	reachable_time;
	/* Ĭ��5sec */
	int	delay_probe_time;

	/* arp������г��ȣ�Ĭ��3��skb */
	int	queue_len;
	/* ����̽��,Ĭ��3�� */
	int	ucast_probes;
	/* Ӧ��̽��,Ĭ��0�� */
	int	app_probes;
	/* �ಥ̽��,Ĭ��3�� */
	int	mcast_probes;
	/* ̽���ӳ�,Ĭ��1�� */
	int	anycast_delay;
	/* �����ӳ�,Ĭ��4/5�� */
	int	proxy_delay;
	/* arp������г���,Ĭ��64 */
	int	proxy_qlen;
	/* �ڽ�����ʱ��,Ĭ��1��,������ڽӷ����仯,����һ�������ʱ��,���仯����Ƶ�� */
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
��Linux�ں���, ������������Ӳ����ֱ��ͨ�ŵ��ⲿ����������ӿ��豸��Ϊ"�ھ�",
��neighbour�ṹ����, �������豸��Ӳ����ַ��Ϣ.
ϵͳ�����е�IP����ͨ��·�����󶨵��ھӷ��͵��ӿ��豸��. 
�ھ����ھӱ�(arp_tbl)������, ���ھӵ�IP��ַ�ɲ�ѯ�ھӱ���ĳ���豸���ھ�.

ÿ��neighbour�ṹ��ͨ��neigh_ops������һ�����������,
neigh_ops�ṹ�����丸��neigh_table����Ĺ��캯�����
*/
struct neighbour {
	/* ����hash��ͻ������ */
	struct neighbour __rcu	*next;
	/* ���ڵ��ھӱ�ָ���ϲ��neigh_table�ṹ��ָ��arp_tbl */
	struct neigh_table	*tbl;
	/* ָ���豸�ڽӲ��� */
	struct neigh_parms	*parms;
	/* ȷ��ʱ�� */
	unsigned long		confirmed;
	/* ����ڽӸ���ʱ�� */
	unsigned long		updated;
	/* �ڽ��� */
	rwlock_t		lock;
	/* ���ü��� */
	atomic_t		refcnt;
	/* arp����
	   ���ھӽ��յ�Ҫ���͵�IP��ʱ, ����ھӵ�Ӳ����ַ��δ����,
	   �򽫷��Ͱ���ʱ������arp_queue������,Ȼ���͵�ַ��������,
	   ��ʱ��״̬Ϊδ���״̬(NUD_INCOMPLETE).
	   ���1����û�յ��ⲿ�豸Ӧ��, �ھӽ��ط�arp����, 
	   ����ط��ﵽ3��, �����ʧ��, �ھ�Ϊʧ��״̬(NUD_FAILED).
	   ���յ���ȷӦ��, �ھӽ�������״̬(NUD_REACHABLE),
	   ��ʱarp_queue�з��Ͱ���������֡ͷ���͵��豸�� */
	struct sk_buff_head	arp_queue;
	/* ��ʱ�� */
	struct timer_list	timer;
	/* ���ʹ��ʱ�� */
	unsigned long		used;
	/* ̽��������ᶯ̬�仯 */
	atomic_t		probes;
	/* �ڽӱ�ǣ��ο�neigh_update() */
	__u8			flags;
	/* �ڽ�״̬ */
	__u8			nud_state;
	__u8			type;
	/* ������־��1��ʾ���δ���� */
	__u8			dead;
	seqlock_t		ha_lock;
	/* Ӳ����ַ */
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	/* �ڽӻ���ָ��
	   hh ָ�� hh_cache���˽ṹ���� cache L2 ��ַ���Լ��� L3 �� L2 ��ӳ�����

	   Ϊ������IP�����豸�Ĵ���·��, 
	   ���ھӽṹ�ϻ�������֡ͷ����ṹ(hh_cache).
	   ����ھӽ�����֡ͷ����, IP����ͨ��֡ͷ�����������ͳ�ȥ. 
	   ���ھӴ�������״̬ʱ, ֡ͷ�������ֱ��ָ��dev_queue_xmit(), 
	   �����ڹ���״̬ʱ, ֡ͷ��������л�Ϊ�ھӵ������, 
	   ����̫���豸��˵,�ھӵ������ָ��neigh_resolve_output(),
	   neigh_connect()��neigh_suspect()���������������������л�. */
	struct hh_cache		*hh;
	/* �ڽ��������,���
	   �ҵ����ʵ��ھӽڵ�֮��ϵͳ�������������ָ�룬
	   ʹ�ýṹ�е�dev�豸�������ݰ����ͳ�ȥ��
	   ���Э������AF_INET��������dev_queue_xmit()������������

	   ���� output �򣬹ؼ��ǿ� neighbour ��״̬��
	   �������Ч״̬��������Ϊops->connected_output()���������Լӿ��ٶȣ�
	   ��������Ϊ ops->output()����������Ҫ����neighbor discovery �Ĵ���
	   ���� ARP ��˵�������� output ��
	   ���� connect_output����ָ�� neigh_resolve_output()��
	   neigh_resolve_output() ���� neighbor discovery �Ĺ��̡� */
	int			(*output)(struct sk_buff *skb);
	/* �ڽӲ����������ݽṹ
	   ���ݵײ� driver �����ͽ��в�ͬ�����ã�
	   ����û����·���ַ�ģ�ָ��arp_direct_ops
	   ����û����·�� cache �ģ�ָ��arp_generic_ops
	   ��������·�� cache �ģ� ָ��arp_hh_ops

	   ������̫�������������� net_device �ṹ�ڳ�ʼ����ʱ��
	   �Ѿ�����Ĭ�ϵ� hard_header �� hard_header_cache ������
	   �ο�ether_setup()
	   			dev->hard_header        = eth_header;
	      		dev->hard_header_cache  = eth_header_cache;
	   ��ˣ�Ĭ������£����� ops ָ�� arp_hh_ops() */
	const struct neigh_ops	*ops;
	struct rcu_head		rcu;
	/* �ھ�����Ӧ�������豸�ӿ�ָ�� */
	struct net_device	*dev;
	/* ��ϣ�ؼ���,���ڴ��IP��ַ */
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
�Ըýṹ�ķ�����neigh_hash_alloc()���
*/
struct neigh_hash_table {
	/* ��ϣ���飬�������е��ھӣ�
	   ��һ��neigh_table���棬��������32��neighbour�ṹ������ */
	struct neighbour __rcu	**hash_buckets;
	/* ��ϣ�����С������
	   +1ΪĿǰͰͷ�ڵ�ָ������Ĵ�С�������С����2���ݴ�
	   hash_mask��ʼΪ(8-1)���ο�neigh_table_init_no_netlink()
	   �ᶯ̬���� */
	unsigned int		hash_mask;
	/* hash������ӣ���ʼ��ʱ��ֵ */
	__u32			hash_rnd;
	struct rcu_head		rcu;
};


/*
�����ھӱ�Ľṹ
����arp_tbl
*/
struct neigh_table {
	/* ���ڹҽӵ�neigh_tablesȫ������
	   ��һ���ھӱ�,ʵ���Ͼ���ARP���ĵ������һ̨���� */
	struct neigh_table	*next;
	/* ��ַ�壬������̫�����Ծ��� AF_INET��Э���(PF_INET)
	   arpЭ�����ڽ���IPv4��ַ�������ַ֮��Ķ�Ӧ��ϵ */
	int			family;
	/* ��ڳ���,Ҳ����һ���ھӽṹ�Ĵ�С
	   ��ΪhashkeyΪIPv4��ַ���ʴ˴�Ϊsizeof(struct neighbour)+4
	   �ο�arp_tbl�Ķ��� */
	int			entry_size;
	/* ��ϣ�ؼ�ֵ���� ��IP��ַ�ĳ��ȣ�Ϊ4 */
	int			key_len;
	/* �������źͼ������neigh_table��neighbour�Ĺ�ϣ���� */
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
	/* �����ھӵ����ޣ�������������ͣ���С�������仯��
	   ����C���ַ���ھ����ƾ�Ӧ��С��255 */
	int			gc_thresh3;
	unsigned long		last_flush;
	struct delayed_work	gc_work;
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue;
	/* ��¼�����ھӱ����� */
	atomic_t		entries;
	rwlock_t		lock;
	unsigned long		last_rand;
	struct kmem_cache	*kmem_cachep;
	struct neigh_statistics	__percpu *stats;
	/* �ھӹ�ϣ�� */
	struct neigh_hash_table __rcu *nht;
	/* �ڽӴ���hash�� */
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
	/* �����ü�����1��Ϊ0�ˣ����ͷŸ��ھӱ�ڵ� */
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
	/* ����ϣ���в��� */
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	/* �ҵ��򷵻��ҵ��Ľڵ�ָ��
	   ��δ�ҵ����ֲ������½ڵ㣬�򷵻�NULL */
	if (n || !creat)
		return n;

	/* �����µ��ھӱ�ڵ� */
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

	/* �Ҳ�����ʱ�򴴽��µ� */
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
