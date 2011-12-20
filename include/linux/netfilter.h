#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/wait.h>
#include <linux/list.h>
#endif
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>

/* Responses from hook functions. */
/* 丢弃该数据包 */
#define NF_DROP 0
/* 保留该数据包，继续处理 */
#define NF_ACCEPT 1
/* 忘掉该数据包 stolen:偷 */
#define NF_STOLEN 2
/* 将该数据包插入到用户空间 */
#define NF_QUEUE 3
/* 再次调用该hook函数 */
#define NF_REPEAT 4
/* 停止该hook点下hook函数的迭代，即使链表中该函数后面还有其他函数 */
#define NF_STOP 5
#define NF_MAX_VERDICT NF_STOP

/* we overload the higher bits for encoding auxiliary(辅助的) data such as the queue
 * number or errno values. Not nice, but better than additional function
 * arguments. */
#define NF_VERDICT_MASK 0x000000ff

/* extra verdict flags have mask 0x0000ff00 */
#define NF_VERDICT_FLAG_QUEUE_BYPASS	0x00008000

/* queue number (NF_QUEUE) or errno (NF_DROP) */
#define NF_VERDICT_QMASK 0xffff0000
#define NF_VERDICT_QBITS 16

#define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)

#define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)

/* only for userspace compatibility */
#ifndef __KERNEL__
/* Generic cache responses from hook functions.
   <= 0x2000 is used for protocol-flags. */
#define NFC_UNKNOWN 0x4000
#define NFC_ALTERED 0x8000

/* NF_VERDICT_BITS should be 8 now, but userspace might break if this changes */
#define NF_VERDICT_BITS 16
#endif

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};

enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

union nf_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};

#ifdef __KERNEL__
#ifdef CONFIG_NETFILTER
static inline int NF_DROP_GETERR(int verdict)
{
	return -(verdict >> NF_VERDICT_QBITS);
}

static inline int nf_inet_addr_cmp(const union nf_inet_addr *a1,
				   const union nf_inet_addr *a2)
{
	return a1->all[0] == a2->all[0] &&
	       a1->all[1] == a2->all[1] &&
	       a1->all[2] == a2->all[2] &&
	       a1->all[3] == a2->all[3];
}

extern void netfilter_init(void);

/* Largest hook number + 1 */
#define NF_MAX_HOOKS 8

struct sk_buff;

typedef unsigned int nf_hookfn(unsigned int hooknum,
			       struct sk_buff *skb,
				/* 指向收到数据帧的实际物理接口 */
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn)(struct sk_buff *));

/* 钩子结构 */
struct nf_hook_ops {
	/* 组成链表 */
	struct list_head list;

	/* User fills in from here down. */
	/* 钩子处理函数 */
	nf_hookfn *hook;
	struct module *owner;
	u_int8_t pf;
	/* hook号，5个hook点 */
	unsigned int hooknum;
	/* Hooks are ordered in ascending priority. */
	/* 优先级，数值越小的越先执行 */
	int priority;
};

struct nf_sockopt_ops {
	/* 链表节点 */
	struct list_head list;

	/* protocal family 协议族 */
	u_int8_t pf;

	/* Non-inclusive ranges: use 0/0/NULL to never get called. */
	/* set命令的最小和最大值
	   最小值可以取到
	   最大值不可以取到
	*/
	int set_optmin;
	int set_optmax;
	/* set函数 */
	int (*set)(struct sock *sk, int optval, void __user *user, unsigned int len);
#ifdef CONFIG_COMPAT
	int (*compat_set)(struct sock *sk, int optval,
			void __user *user, unsigned int len);
#endif
	/* get命令的最小和最大值 */
	int get_optmin;
	int get_optmax;
	/* get函数 */
	int (*get)(struct sock *sk, int optval, void __user *user, int *len);
#ifdef CONFIG_COMPAT
	int (*compat_get)(struct sock *sk, int optval,
			void __user *user, int *len);
#endif
	/* Use the module struct to lock set/get code in place */
	struct module *owner;
};

/* Function to register/unregister hook points. */
int nf_register_hook(struct nf_hook_ops *reg);
void nf_unregister_hook(struct nf_hook_ops *reg);
int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n);
void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n);

/* Functions to register get/setsockopt ranges (non-inclusive).  You
   need to check permissions yourself! */
int nf_register_sockopt(struct nf_sockopt_ops *reg);
void nf_unregister_sockopt(struct nf_sockopt_ops *reg);

#ifdef CONFIG_SYSCTL
/* Sysctl registration */
extern struct ctl_path nf_net_netfilter_sysctl_path[];
extern struct ctl_path nf_net_ipv4_netfilter_sysctl_path[];
#endif /* CONFIG_SYSCTL */

extern struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];

int nf_hook_slow(u_int8_t pf, unsigned int hook, struct sk_buff *skb,
		 struct net_device *indev, struct net_device *outdev,
		 int (*okfn)(struct sk_buff *), int thresh);

/**
 *	nf_hook_thresh - call a netfilter hook
 *	
 *	Returns 1 if the hook has allowed the packet to pass.  The function
 *	okfn must be invoked by the caller in this case.  Any other return
 *	value indicates the packet has been consumed by the hook.
 */
/*
返回1，说明钩子函数允许skb继续，此时要调用okfn函数
其他值说明skb被钩子函数消耗了，不再调用okfn函数了
*/
static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
				 struct sk_buff *skb,
				 struct net_device *indev,
				 struct net_device *outdev,
				 int (*okfn)(struct sk_buff *), int thresh)
{
#ifndef CONFIG_NETFILTER_DEBUG
	/* hook空，即没有为该@pf下的@hook点注册钩子函数，返回1，调用okfn(skb) */
	if (list_empty(&nf_hooks[pf][hook]))
		return 1;
#endif
	return nf_hook_slow(pf, hook, skb, indev, outdev, okfn, thresh);
}

static inline int nf_hook(u_int8_t pf, unsigned int hook, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct sk_buff *))
{
	return nf_hook_thresh(pf, hook, skb, indev, outdev, okfn, INT_MIN);
}
                   
/* Activate hook; either okfn or kfree_skb called, unless a hook
   returns NF_STOLEN (in which case, it's up to the hook to deal with
   the consequences).

   Returns -ERRNO if packet dropped.  Zero means queued, stolen or
   accepted.
*/

/* RR:
   > I don't want nf_hook to return anything because people might forget
   > about async and trust the return value to mean "packet was ok".

   AK:
   Just document it clearly, then you can expect some sense from kernel
   coders :)
*/

/*
只会走优先级小于或等于(数值上大于或等于)@thresh的钩子函数
*/
static inline int
NF_HOOK_THRESH(uint8_t pf, unsigned int hook, struct sk_buff *skb,
	       struct net_device *in, struct net_device *out,
	       int (*okfn)(struct sk_buff *), int thresh)
{
	int ret = nf_hook_thresh(pf, hook, skb, in, out, okfn, thresh);
	/* 当对应hook链表下相应的一些hook函数处理完，并返回1时，才继续调用@okfn() */
	if (ret == 1)
		ret = okfn(skb);
	return ret;
}

/*
@cond : 调用钩子函数的条件
	如果cond为假，则直接调用okfn()函数，不会进hook点
	cond为真时，则调用nf_hook_thresh()函数
*/
static inline int
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct sk_buff *skb,
	     struct net_device *in, struct net_device *out,
	     int (*okfn)(struct sk_buff *), bool cond)
{
	int ret;

	if (!cond ||
	    ((ret = nf_hook_thresh(pf, hook, skb, in, out, okfn, INT_MIN)) == 1))
		ret = okfn(skb);
	return ret;
}

static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	/* 传的优先级INT_MIN最小，表示将调用对应链表下的所有hook函数 */
	return NF_HOOK_THRESH(pf, hook, skb, in, out, okfn, INT_MIN);
}

/* Call setsockopt() */
int nf_setsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  unsigned int len);
int nf_getsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  int *len);
#ifdef CONFIG_COMPAT
int compat_nf_setsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, unsigned int len);
int compat_nf_getsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, int *len);
#endif

/* Call this before modifying an existing packet: ensures it is
   modifiable and linear to the point you care about (writable_len).
   Returns true or false. */
extern int skb_make_writable(struct sk_buff *skb, unsigned int writable_len);

struct flowi;
struct nf_queue_entry;

struct nf_afinfo {
	unsigned short	family;
	__sum16		(*checksum)(struct sk_buff *skb, unsigned int hook,
				    unsigned int dataoff, u_int8_t protocol);
	__sum16		(*checksum_partial)(struct sk_buff *skb,
					    unsigned int hook,
					    unsigned int dataoff,
					    unsigned int len,
					    u_int8_t protocol);
	int		(*route)(struct net *net, struct dst_entry **dst,
				 struct flowi *fl, bool strict);
	void		(*saveroute)(const struct sk_buff *skb,
				     struct nf_queue_entry *entry);
	int		(*reroute)(struct sk_buff *skb,
				   const struct nf_queue_entry *entry);
	int		route_key_size;
};

extern const struct nf_afinfo __rcu *nf_afinfo[NFPROTO_NUMPROTO];
static inline const struct nf_afinfo *nf_get_afinfo(unsigned short family)
{
	return rcu_dereference(nf_afinfo[family]);
}

static inline __sum16
nf_checksum(struct sk_buff *skb, unsigned int hook, unsigned int dataoff,
	    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum(skb, hook, dataoff, protocol);
	rcu_read_unlock();
	return csum;
}

static inline __sum16
nf_checksum_partial(struct sk_buff *skb, unsigned int hook,
		    unsigned int dataoff, unsigned int len,
		    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum_partial(skb, hook, dataoff, len,
						protocol);
	rcu_read_unlock();
	return csum;
}

extern int nf_register_afinfo(const struct nf_afinfo *afinfo);
extern void nf_unregister_afinfo(const struct nf_afinfo *afinfo);

#include <net/flow.h>
extern void (*ip_nat_decode_session)(struct sk_buff *, struct flowi *);

static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
#ifdef CONFIG_NF_NAT_NEEDED
	void (*decodefn)(struct sk_buff *, struct flowi *);

	if (family == AF_INET) {
		rcu_read_lock();
		decodefn = rcu_dereference(ip_nat_decode_session);
		if (decodefn)
			decodefn(skb, fl);
		rcu_read_unlock();
	}
#endif
}

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
extern struct proc_dir_entry *proc_net_netfilter;
#endif

#else /* !CONFIG_NETFILTER */
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn) (okfn)(skb)
#define NF_HOOK_COND(pf, hook, skb, indev, outdev, okfn, cond) (okfn)(skb)
static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
				 struct sk_buff *skb,
				 struct net_device *indev,
				 struct net_device *outdev,
				 int (*okfn)(struct sk_buff *), int thresh)
{
	/* 没有netfilter则直接调用okfn()函数 */
	return okfn(skb);
}
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct sk_buff *))
{
	/* 没有netfilter则直接返回1 */
	return 1;
}
struct flowi;
static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
}
#endif /*CONFIG_NETFILTER*/

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
extern void (*ip_ct_attach)(struct sk_buff *, struct sk_buff *) __rcu;
extern void nf_ct_attach(struct sk_buff *, struct sk_buff *);
extern void (*nf_ct_destroy)(struct nf_conntrack *) __rcu;
#else
static inline void nf_ct_attach(struct sk_buff *new, struct sk_buff *skb) {}
#endif

#endif /*__KERNEL__*/
#endif /*__LINUX_NETFILTER_H*/
