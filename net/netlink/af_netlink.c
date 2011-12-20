/*
 * NETLINK      Kernel-user communication protocol.
 *
 * 		Authors:	Alan Cox <alan@lxorguk.ukuu.org.uk>
 * 				Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Tue Jun 26 14:36:48 MEST 2001 Herbert "herp" Rosmanith
 *                               added netlink_proto_exit
 * Tue Jan 22 18:32:44 BRST 2002 Arnaldo C. de Melo <acme@conectiva.com.br>
 * 				 use nlk_sk, as sk->protinfo is on a diet 8)
 * Fri Jul 22 19:51:12 MEST 2005 Harald Welte <laforge@gnumonks.org>
 * 				 - inc module use count of module that owns
 * 				   the kernel socket in case userspace opens
 * 				   socket of same protocol
 * 				 - remove all module support, since netlink is
 * 				   mandatory if CONFIG_NET=y these days
 */

#include <linux/module.h>

#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/fcntl.h>
#include <linux/termios.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/notifier.h>
#include <linux/security.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/mutex.h>

#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/scm.h>
#include <net/netlink.h>

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

/*
netlink�׽ӿڽṹ

����ṹ������Ƕһ����׼��struct sock�ṹ,
�����ָ���netlink��ص������������,
�ں�������Э���sockҲ�����ƶ����, 
ע��sock�ṹ������ڵ�һλ,����Ϊ�˿���ֱ�ӽ�sock��ָ��תΪnetlink_sock��ָ�롣
*/
struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	/* �Լ���pid, ͨ����0 */
	u32			pid;
	/* �Է���pid */
	u32			dst_pid;
	/* �Է����� */
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	/* �ಥ������ */
	u32			ngroups;
	/* �ಥ��� */
	unsigned long		*groups;
	unsigned long		state;
	/* �ȴ�����,���ڴ�����շ��Ͱ�ʱ��top half */
	wait_queue_head_t	wait;
	/* �ص��ṹ,�����ص����� */
	struct netlink_callback	*cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	struct module		*module;
};

struct listeners {
	struct rcu_head		rcu;
	unsigned long		masks[0];
};

#define NETLINK_KERNEL_SOCKET	0x1
#define NETLINK_RECV_PKTINFO	0x2
#define NETLINK_BROADCAST_SEND_ERROR	0x4
#define NETLINK_RECV_NO_ENOBUFS	0x8

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

static inline int netlink_is_kernel(struct sock *sk)
{
	return nlk_sk(sk)->flags & NETLINK_KERNEL_SOCKET;
}

struct nl_pid_hash {
	/* ����ڵ� */
	struct hlist_head *table;
	/* ���¼���HASH��ʱ���� */
	unsigned long rehash_time;

	unsigned int mask;
	unsigned int shift;

	/* ����ڵ��� */
	unsigned int entries;
	/* �����ֵ */
	unsigned int max_shift;

	/* ����� */
	u32 rnd;
};

/*
netlink sock�Ĺ�ϣ��

������MAX_LINKS(32)��������ͬЭ�����͵�netlink�׽ӿ�, 
ע�������������ͨ��, ����ͬʱ��Ϊ�������Ϳͻ���, 
�������Ҫһ���׽ӿڶ�Ӧ, ÿ���ͻ���ҲҪ��һ���׽ӿڶ�Ӧ, 
����ͻ��˵��׽ӿ��γ�һ������.
*/
struct netlink_table {
	/* ����pid����HASH��netlink sock����, �൱�ڿͻ������� */
	struct nl_pid_hash hash;
	/* �ಥ��sock���� */
	struct hlist_head mc_list;
	/* �����߱�־ */
	struct listeners __rcu *listeners;
	unsigned int nl_nonroot;
	/* ÿ��netlink��Э�����Ϳ��Զ�������, 8�ı���,��С��32 */
	unsigned int groups;
	struct mutex *cb_mutex;
	struct module *module;
	int registered;
};

/*
��netlink_proto_init()�з���ռ䣬��32��
�����˿ռ��ʹ�õ�ʱ�����Կ�����struct netlink_table��һ��������
ÿһ��Э�飬��:NETLINK_ROUTE NETLINK_UNUSED����Ϊ�±궼��Ӧ������һ��
*/
static struct netlink_table *nl_table;

static DECLARE_WAIT_QUEUE_HEAD(nl_table_wait);

static int netlink_dump(struct sock *sk);
static void netlink_destroy_callback(struct netlink_callback *cb);

static DEFINE_RWLOCK(nl_table_lock);
static atomic_t nl_table_users = ATOMIC_INIT(0);

static ATOMIC_NOTIFIER_HEAD(netlink_chain);

static u32 netlink_group_mask(u32 group)
{
	return group ? 1 << (group - 1) : 0;
}

static struct hlist_head *nl_pid_hashfn(struct nl_pid_hash *hash, u32 pid)
{
	return &hash->table[jhash_1word(pid, hash->rnd) & hash->mask];
}

static void netlink_sock_destruct(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (nlk->cb) {
		if (nlk->cb->done)
			nlk->cb->done(nlk->cb);
		netlink_destroy_callback(nlk->cb);
	}

	skb_queue_purge(&sk->sk_receive_queue);

	if (!sock_flag(sk, SOCK_DEAD)) {
		printk(KERN_ERR "Freeing alive netlink socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(nlk_sk(sk)->groups);
}

/* This lock without WQ_FLAG_EXCLUSIVE is good on UP and it is _very_ bad on
 * SMP. Look, when several writers sleep and reader wakes them up, all but one
 * immediately hit write lock and grab all the cpus. Exclusive sleep solves
 * this, _but_ remember, it adds useless work on UP machines.
 */

void netlink_table_grab(void)
	__acquires(nl_table_lock)
{
	might_sleep();

	write_lock_irq(&nl_table_lock);

	if (atomic_read(&nl_table_users)) {
		DECLARE_WAITQUEUE(wait, current);

		add_wait_queue_exclusive(&nl_table_wait, &wait);
		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (atomic_read(&nl_table_users) == 0)
				break;
			write_unlock_irq(&nl_table_lock);
			schedule();
			write_lock_irq(&nl_table_lock);
		}

		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&nl_table_wait, &wait);
	}
}

void netlink_table_ungrab(void)
	__releases(nl_table_lock)
{
	write_unlock_irq(&nl_table_lock);
	wake_up(&nl_table_wait);
}

static inline void
netlink_lock_table(void)
{
	/* read_lock() synchronizes us to netlink_table_grab */

	read_lock(&nl_table_lock);
	atomic_inc(&nl_table_users);
	read_unlock(&nl_table_lock);
}

static inline void
netlink_unlock_table(void)
{
	if (atomic_dec_and_test(&nl_table_users))
		wake_up(&nl_table_wait);
}

static inline struct sock *netlink_lookup(struct net *net, int protocol,
					  u32 pid)
{
	struct nl_pid_hash *hash = &nl_table[protocol].hash;
	struct hlist_head *head;
	struct sock *sk;
	struct hlist_node *node;

	read_lock(&nl_table_lock);
	head = nl_pid_hashfn(hash, pid);
	sk_for_each(sk, node, head) {
		if (net_eq(sock_net(sk), net) && (nlk_sk(sk)->pid == pid)) {
			sock_hold(sk);
			goto found;
		}
	}
	sk = NULL;
found:
	read_unlock(&nl_table_lock);
	return sk;
}

static inline struct hlist_head *nl_pid_hash_zalloc(size_t size)
{
	if (size <= PAGE_SIZE)
		return kzalloc(size, GFP_ATOMIC);
	else
		return (struct hlist_head *)
			__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
					 get_order(size));
}

static inline void nl_pid_hash_free(struct hlist_head *table, size_t size)
{
	if (size <= PAGE_SIZE)
		kfree(table);
	else
		free_pages((unsigned long)table, get_order(size));
}

static int nl_pid_hash_rehash(struct nl_pid_hash *hash, int grow)
{
	unsigned int omask, mask, shift;
	size_t osize, size;
	struct hlist_head *otable, *table;
	int i;

	omask = mask = hash->mask;
	osize = size = (mask + 1) * sizeof(*table);
	shift = hash->shift;

	if (grow) {
		if (++shift > hash->max_shift)
			return 0;
		mask = mask * 2 + 1;
		size *= 2;
	}

	table = nl_pid_hash_zalloc(size);
	if (!table)
		return 0;

	otable = hash->table;
	hash->table = table;
	hash->mask = mask;
	hash->shift = shift;
	get_random_bytes(&hash->rnd, sizeof(hash->rnd));

	for (i = 0; i <= omask; i++) {
		struct sock *sk;
		struct hlist_node *node, *tmp;

		sk_for_each_safe(sk, node, tmp, &otable[i])
			__sk_add_node(sk, nl_pid_hashfn(hash, nlk_sk(sk)->pid));
	}

	nl_pid_hash_free(otable, osize);
	hash->rehash_time = jiffies + 10 * 60 * HZ;
	return 1;
}

/*
dilute: ϡ��
*/
static inline int nl_pid_hash_dilute(struct nl_pid_hash *hash, int len)
{
	int avg = hash->entries >> hash->shift;

	if (unlikely(avg > 1) && nl_pid_hash_rehash(hash, 1))
		return 1;

	if (unlikely(len > avg) && time_after(jiffies, hash->rehash_time)) {
		nl_pid_hash_rehash(hash, 0);
		return 1;
	}

	return 0;
}

static const struct proto_ops netlink_ops;

/*
����listeners
*/
static void
netlink_update_listeners(struct sock *sk)
{
	struct netlink_table *tbl = &nl_table[sk->sk_protocol];
	struct hlist_node *node;
	unsigned long mask;
	unsigned int i;

	for (i = 0; i < NLGRPLONGS(tbl->groups); i++) {
		mask = 0;
		/* �����ಥ�������ɶಥ������� */
		sk_for_each_bound(sk, node, &tbl->mc_list) {
			if (i < NLGRPLONGS(nlk_sk(sk)->ngroups))
				mask |= nlk_sk(sk)->groups[i];
		}
		tbl->listeners->masks[i] = mask;
	}
	/* this function is only called with the netlink table "grabbed", which
	 * makes sure updates are visible before bind or setsockopt return. */
}

/*
����pid����
*/
static int netlink_insert(struct sock *sk, struct net *net, u32 pid)
{
	/* netlink��ӦЭ���HASH�ṹ */
	struct nl_pid_hash *hash = &nl_table[sk->sk_protocol].hash;
	struct hlist_head *head;
	/* ȱʡ����Ϊ��ַ�Ѿ���ʹ�� */
	int err = -EADDRINUSE;
	struct sock *osk;
	struct hlist_node *node;
	int len;

	netlink_table_grab();
	/* ����pid������ӦHASH����ͷ */
	head = nl_pid_hashfn(hash, pid);
	len = 0;
	/* ���pid�Ƿ��Ѿ���������, ����ʧ�� */
	sk_for_each(osk, node, head) {
		if (net_eq(sock_net(osk), net) && (nlk_sk(osk)->pid == pid))
			break;
		len++;
	}
	if (node)
		goto err;

	/* ȱʡ�����Ϊϵͳæ */
	err = -EBUSY;
	/* ���sock��pid��Ϊ0, ����, ֻ��pidΪ0��sock����ִ�иú���
	   sock��pid��Ϊ0ʱ�����ٽ���insert������
	*/
	if (nlk_sk(sk)->pid)
		goto err;

	/* ȱʡ�����Ϊ���ڴ�ռ� */
	err = -ENOMEM;
	if (BITS_PER_LONG > 32 && unlikely(hash->entries >= UINT_MAX))
		goto err;

	/* �������Ϊ�ն�����������������,�����HASH��,���»�ȡHASH����ͷ
	   ��������������ٷ���
	*/
	if (len && nl_pid_hash_dilute(hash, len))
		head = nl_pid_hashfn(hash, pid);
	hash->entries++;
	/* ��pid��ֵ��sock��pid���� */
	nlk_sk(sk)->pid = pid;
	/* ��sock�ڵ���ӽ�HASH���� */
	sk_add_node(sk, head);
	err = 0;

err:
	netlink_table_ungrab();
	return err;
}

static void netlink_remove(struct sock *sk)
{
	netlink_table_grab();
	if (sk_del_node_init(sk))
		nl_table[sk->sk_protocol].hash.entries--;
	if (nlk_sk(sk)->subscriptions)
		__sk_del_bind_node(sk);
	netlink_table_ungrab();
}

static struct proto netlink_proto = {
	.name	  = "NETLINK",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct netlink_sock),
};

static int __netlink_create(struct net *net, struct socket *sock,
			    struct mutex *cb_mutex, int protocol)
{
	struct sock *sk;
	struct netlink_sock *nlk;

	/* netlink sock�Ļ������� */
	sock->ops = &netlink_ops;

	/* ����sock�ṹ, ͨ��netlink_proto�е�obj_sizeָ����netlink sock�Ĵ�С */
	sk = sk_alloc(net, PF_NETLINK, GFP_KERNEL, &netlink_proto);
	if (!sk)
		return -ENOMEM;

	/* ��ʼ��sock��������, ��sock��socket�������� */
	sock_init_data(sock, sk);

	/* ����ͨsockתΪnetlink sock,
	   ʵ��ֻ�����¶����һ��ָ������,ָ�뱾��ֵ����
	*/
	nlk = nlk_sk(sk);
	/* ��ʼ��sock���� */
	if (cb_mutex)
		nlk->cb_mutex = cb_mutex;
	else {
		nlk->cb_mutex = &nlk->cb_def_mutex;
		mutex_init(nlk->cb_mutex);
	}
	/* ��ʼ���ȴ����� */
	init_waitqueue_head(&nlk->wait);

	/* sock����������,�ͷŽ��ն����е�skb���ݰ� */
	sk->sk_destruct = netlink_sock_destruct;
	sk->sk_protocol = protocol;
	return 0;
}

/*
���û��ռ�ÿ�δ�netlink socketʱ������ô˺���

�û��ռ�ʹ��socket(2)ϵͳ���ô�netlink���͵��׽ӿ�ʱ, 
���ں��л����sys_sock()����, Ȼ���ǵ���__sock_create()����, 
�����е���netlinkЭ�����create()����, ��netlink_create()����.
*/
static int netlink_create(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	struct module *module = NULL;
	struct mutex *cb_mutex;
	struct netlink_sock *nlk;
	int err = 0;

	/* sock״̬��ʼ�� */
	sock->state = SS_UNCONNECTED;

	/* ����socketʱ��typeֻ����SOCK_RAW��SOCK_DGRAM */
	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	/* �жϴ���socketʱ����Э��protocol��Χ */
	if (protocol < 0 || protocol >= MAX_LINKS)
		return -EPROTONOSUPPORT;

	netlink_lock_table();
#ifdef CONFIG_MODULES
	/* �����Ӧ��netlinkЭ����ģ����û�м��صĻ��ȼ��ظ�ģ�� */
	if (!nl_table[protocol].registered) {
		netlink_unlock_table();
		request_module("net-pf-%d-proto-%d", PF_NETLINK, protocol);
		netlink_lock_table();
	}
#endif
	if (nl_table[protocol].registered &&
	    try_module_get(nl_table[protocol].module))
		module = nl_table[protocol].module;
	else
		err = -EPROTONOSUPPORT;
	cb_mutex = nl_table[protocol].cb_mutex;
	netlink_unlock_table();

	if (err < 0)
		goto out;

	/* �����Ľ���netlink sock�ĺ��� */
	err = __netlink_create(net, sock, cb_mutex, protocol);
	if (err < 0)
		goto out_module;

	local_bh_disable();
	sock_prot_inuse_add(net, &netlink_proto, 1);
	local_bh_enable();

	nlk = nlk_sk(sock->sk);
	nlk->module = module;
out:
	return err;

out_module:
	module_put(module);
	goto out;
}

/*
��close(2)ʱ����
*/
static int netlink_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk;

	if (!sk)
		return 0;

	/* ���׽ӿ�sk��ϵͳsk����Ͱ������жϿ� */
	netlink_remove(sk);
	/* ����sk״̬ΪSOCK_DEAD, �Ͽ�sock��sk�Ļ�ָ */
	sock_orphan(sk);
	nlk = nlk_sk(sk);

	/*
	 * OK. Socket is unlinked, any packets that arrive now
	 * will be purged.
	 */

	sock->sk = NULL;
	/* �������еȴ����� */
	wake_up_interruptible_all(&nlk->wait);

	skb_queue_purge(&sk->sk_write_queue);

	if (nlk->pid) {
		/* �����ͷ�֪ͨ */
		struct netlink_notify n = {
						.net = sock_net(sk),
						.protocol = sk->sk_protocol,
						.pid = nlk->pid,
					  };
		atomic_notifier_call_chain(&netlink_chain,
				NETLINK_URELEASE, &n);
	}

	/* ����ģ����� */
	module_put(nlk->module);

	/* �൱�ڼ��� */
	netlink_table_grab();
	if (netlink_is_kernel(sk)) {
		BUG_ON(nl_table[sk->sk_protocol].registered == 0);
		if (--nl_table[sk->sk_protocol].registered == 0) {
			/* �ͷ��ں��е�netlink�������� */
			kfree(nl_table[sk->sk_protocol].listeners);
			nl_table[sk->sk_protocol].module = NULL;
			nl_table[sk->sk_protocol].registered = 0;
		}
	} else if (nlk->subscriptions)
		netlink_update_listeners(sk);
	/* �൱�ڽ��� */
	netlink_table_ungrab();

	/* �ͷŸ�netlink sock�Ķಥ�� */
	kfree(nlk->groups);
	nlk->groups = NULL;

	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), &netlink_proto, -1);
	local_bh_enable();
	/* �ͷ�sock */
	sock_put(sk);
	return 0;
}

/*
δָ��pidʱ���Զ���
ʵ����ѡһ��û�ù���pid���ٽ��в������
*/
static int netlink_autobind(struct socket *sock)
{
	/* ��socket�ҵ�sock */
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	/* netlink��ӦЭ���HASH�ṹ */
	struct nl_pid_hash *hash = &nl_table[sk->sk_protocol].hash;
	struct hlist_head *head;
	struct sock *osk;
	struct hlist_node *node;
	/* pidȡΪ��ǰ���̵���ID */
	s32 pid = task_tgid_vnr(current);
	int err;
	/* �з���32λ������̬���� */
	static s32 rover = -4097;

retry:
	cond_resched();
	netlink_table_grab();
	/* �Һ��ʵ�HASH����ͷ */
	head = nl_pid_hashfn(hash, pid);
	sk_for_each(osk, node, head) {
		if (!net_eq(sock_net(osk), net))
			continue;
		/* �����������Ƿ��Ѿ��и�pid */
		if (nlk_sk(osk)->pid == pid) {
			/* ����, �����pid, ���¼��, ע����ʱ��pid�Ǹ����� */
			/* Bind collision, search negative pid values. */
			pid = rover--;
			if (rover > -4097)
				rover = -4097;
			netlink_table_ungrab();
			goto retry;
		}
	}
	netlink_table_ungrab();

	/* ��ʱ��pid��һ������ת��Ϊ�޷���32λ��, ����һ���ǳ������
	   ִ��������pid����
	*/
	err = netlink_insert(sk, net, pid);
	if (err == -EADDRINUSE)
		goto retry;

	/* If 2 threads race to autobind, that is fine.  */
	if (err == -EBUSY)
		err = 0;

	return err;
}

static inline int netlink_capable(struct socket *sock, unsigned int flag)
{
	return (nl_table[sock->sk->sk_protocol].nl_nonroot & flag) ||
	       capable(CAP_NET_ADMIN);
}

/*
����subscriotions
*/
static void
netlink_update_subscriptions(struct sock *sk, unsigned int subscriptions)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (nlk->subscriptions && !subscriptions)
		__sk_del_bind_node(sk);
	else if (!nlk->subscriptions && subscriptions)
		sk_add_bind_node(sk, &nl_table[sk->sk_protocol].mc_list);
	nlk->subscriptions = subscriptions;
}

static int netlink_realloc_groups(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	unsigned int groups;
	unsigned long *new_groups;
	int err = 0;

	netlink_table_grab();

	groups = nl_table[sk->sk_protocol].groups;
	if (!nl_table[sk->sk_protocol].registered) {
		err = -ENOENT;
		goto out_unlock;
	}

	if (nlk->ngroups >= groups)
		goto out_unlock;

	new_groups = krealloc(nlk->groups, NLGRPSZ(groups), GFP_ATOMIC);
	if (new_groups == NULL) {
		err = -ENOMEM;
		goto out_unlock;
	}
	memset((char *)new_groups + NLGRPSZ(nlk->ngroups), 0,
	       NLGRPSZ(groups) - NLGRPSZ(nlk->ngroups));

	nlk->groups = new_groups;
	nlk->ngroups = groups;
 out_unlock:
	netlink_table_ungrab();
	return err;
}

/*
��ͨ������Է����
*/
static int netlink_bind(struct socket *sock, struct sockaddr *addr,
			int addr_len)
{
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *nladdr = (struct sockaddr_nl *)addr;
	int err;

	/* ���һ�µ�ַ��Э�����Ƿ�ΪAF_NETLINK */
	if (nladdr->nl_family != AF_NETLINK)
		return -EINVAL;

	/* Only superuser is allowed to listen multicasts */
	if (nladdr->nl_groups) {
		/* ָ���˶ಥ��, ������ҪrootȨ�� */
		if (!netlink_capable(sock, NL_NONROOT_RECV))
			return -EPERM;
		/* ����ಥ��ռ� */
		err = netlink_realloc_groups(sk);
		if (err)
			return err;
	}

	/* ���sock��pid��0, ����Ƿ�ƥ����nladdr��ַ�ṹ��ָ����pid */
	if (nlk->pid) {
		if (nladdr->nl_pid != nlk->pid)
			return -EINVAL;
	} else {
	/* sock��pidΪ0, ����nladdr�Ƿ�ָ��pid��ִ�в����� */
		err = nladdr->nl_pid ?
			netlink_insert(sk, net, nladdr->nl_pid) :
			netlink_autobind(sock);
		if (err)
			return err;
	}

	/* �Ƕಥ���ʱ�Ϳ��Է��سɹ��� */
	if (!nladdr->nl_groups && (nlk->groups == NULL || !(u32)nlk->groups[0]))
		return 0;

	netlink_table_grab();
	/* �ಥ����¸���sock���� */
	netlink_update_subscriptions(sk, nlk->subscriptions +
					 hweight32(nladdr->nl_groups) -
					 hweight32(nlk->groups[0]));
	nlk->groups[0] = (nlk->groups[0] & ~0xffffffffUL) | nladdr->nl_groups;
	netlink_update_listeners(sk);
	netlink_table_ungrab();

	return 0;
}

/*
����ͨ������Կͻ������ӷ�����
*/
static int netlink_connect(struct socket *sock, struct sockaddr *addr,
			   int alen, int flags)
{
	int err = 0;
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *nladdr = (struct sockaddr_nl *)addr;

	if (alen < sizeof(addr->sa_family))
		return -EINVAL;

	/* Ŀ�ĵ�ַЭ����ΪAF_UNSPEC(δָ��), �򵥷��سɹ� */
	if (addr->sa_family == AF_UNSPEC) {
		sk->sk_state	= NETLINK_UNCONNECTED;
		nlk->dst_pid	= 0;
		nlk->dst_group  = 0;
		return 0;
	}
	/* ����Ŀ�ĵ�ַЭ��������ΪAF_NETLINK */
	if (addr->sa_family != AF_NETLINK)
		return -EINVAL;

	/* Only superuser is allowed to send multicasts */
	/* ֻ��ROOTȨ�޲��ܶಥ */
	if (nladdr->nl_groups && !netlink_capable(sock, NL_NONROOT_SEND))
		return -EPERM;

	/* ûָ��pid�Ļ��Զ���һ��pid */
	if (!nlk->pid)
		err = netlink_autobind(sock);

	/* �Ѿ�ָ����pid�����Զ��󶨳ɹ�ʱ����sock�ĶԷ�����, ״̬Ϊ���ӳɹ� */
	if (err == 0) {
		sk->sk_state	= NETLINK_CONNECTED;
		nlk->dst_pid 	= nladdr->nl_pid;
		nlk->dst_group  = ffs(nladdr->nl_groups);
	}

	return err;
}

/*
���sockaddr_nl�ṹ�е�����
*/
static int netlink_getname(struct socket *sock, struct sockaddr *addr,
			   int *addr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_nl *, nladdr, addr);

	/* Э���� */
	nladdr->nl_family = AF_NETLINK;
	nladdr->nl_pad = 0;
	*addr_len = sizeof(*nladdr);

	/* �Է�sock��pid��groups */
	if (peer) {
		nladdr->nl_pid = nlk->dst_pid;
		nladdr->nl_groups = netlink_group_mask(nlk->dst_group);
	} else {
	/* �Լ�sock��pid��groups */
		nladdr->nl_pid = nlk->pid;
		nladdr->nl_groups = nlk->groups ? nlk->groups[0] : 0;
	}
	return 0;
}

static void netlink_overrun(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (!(nlk->flags & NETLINK_RECV_NO_ENOBUFS)) {
		if (!test_and_set_bit(0, &nlk_sk(sk)->state)) {
			sk->sk_err = ENOBUFS;
			sk->sk_error_report(sk);
		}
	}
	atomic_inc(&sk->sk_drops);
}

static struct sock *netlink_getsockbypid(struct sock *ssk, u32 pid)
{
	struct sock *sock;
	struct netlink_sock *nlk;

	sock = netlink_lookup(sock_net(ssk), ssk->sk_protocol, pid);
	if (!sock)
		return ERR_PTR(-ECONNREFUSED);

	/* Don't bother queuing skb if kernel socket has no input function */
	nlk = nlk_sk(sock);
	if (sock->sk_state == NETLINK_CONNECTED &&
	    nlk->dst_pid != nlk_sk(ssk)->pid) {
		sock_put(sock);
		return ERR_PTR(-ECONNREFUSED);
	}
	return sock;
}

struct sock *netlink_getsockbyfilp(struct file *filp)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct sock *sock;

	if (!S_ISSOCK(inode->i_mode))
		return ERR_PTR(-ENOTSOCK);

	sock = SOCKET_I(inode)->sk;
	if (sock->sk_family != AF_NETLINK)
		return ERR_PTR(-EINVAL);

	sock_hold(sock);
	return sock;
}

/*
 * Attach a skb to a netlink socket.
 * The caller must hold a reference to the destination socket. On error, the
 * reference is dropped. The skb is not send to the destination, just all
 * all error checks are performed and memory in the queue is reserved.
 * Return values:
 * < 0: error. skb freed, reference to sock dropped.
 * 0: continue
 * 1: repeat lookup - reference dropped while waiting for socket memory.
 */
/*
ע��������ں�ȫ�ֺ���, ��static
*/
int netlink_attachskb(struct sock *sk, struct sk_buff *skb,
		      long *timeo, struct sock *ssk)
{
	struct netlink_sock *nlk;

	nlk = nlk_sk(sk);

	/* �����ջ����С�Ƿ��㹻, �����Ļ������ȴ�ֱ��������������� */
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    test_bit(0, &nlk->state)) {
		/* ������ǰ���̵ĵȴ����� */
		DECLARE_WAITQUEUE(wait, current);
		if (!*timeo) {
			if (!ssk || netlink_is_kernel(ssk))
				netlink_overrun(sk);
			sock_put(sk);
			kfree_skb(skb);
			return -EAGAIN;
		}

		/* ���õ�ǰ����״̬Ϊ���жϵ� */
		__set_current_state(TASK_INTERRUPTIBLE);
		/* ��sock�ҽӵ��ȴ����� */
		add_wait_queue(&nlk->wait, &wait);

		/* �ռ䲻���Ļ�����, timeoΪ������ʱ */
		if ((atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
		     test_bit(0, &nlk->state)) &&
		    !sock_flag(sk, SOCK_DEAD))
			*timeo = schedule_timeout(*timeo);

		/* ����״̬���� */
		__set_current_state(TASK_RUNNING);
		/* ɾ���ȴ����� */
		remove_wait_queue(&nlk->wait, &wait);
		sock_put(sk);

		/* ������ͨ����ʱ�⿪��,�����ǿռ��������Ͻ⿪, ���ڴ���״̬ */
		if (signal_pending(current)) {
			kfree_skb(skb);
			return sock_intr_errno(*timeo);
		}
		/* ����1, ����ѡsock */
		return 1;
	}
	/* ��������, ֱ�ӽ�skb����������Ϊ��netlink sock */
	skb_set_owner_r(skb, sk);
	return 0;
}

/*
ע��������ں�ȫ�ֺ���, ��static
*/
int netlink_sendskb(struct sock *sk, struct sk_buff *skb)
{
	int len = skb->len;

	/* ��skb��ӵ����ն���ĩβ */
	skb_queue_tail(&sk->sk_receive_queue, skb);
	/* ����netlink sock��sk_data_ready�������� */
	sk->sk_data_ready(sk, len);
	sock_put(sk);
	return len;
}

void netlink_detachskb(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	sock_put(sk);
}

static inline struct sk_buff *netlink_trim(struct sk_buff *skb,
					   gfp_t allocation)
{
	int delta;

	skb_orphan(skb);

	delta = skb->end - skb->tail;
	if (delta * 2 < skb->truesize)
		return skb;

	if (skb_shared(skb)) {
		struct sk_buff *nskb = skb_clone(skb, allocation);
		if (!nskb)
			return skb;
		kfree_skb(skb);
		skb = nskb;
	}

	if (!pskb_expand_head(skb, 0, -delta, allocation))
		skb->truesize -= delta;

	return skb;
}

static inline void netlink_rcv_wake(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (skb_queue_empty(&sk->sk_receive_queue))
		clear_bit(0, &nlk->state);
	if (!test_bit(0, &nlk->state))
		wake_up_interruptible(&nlk->wait);
}

static inline int netlink_unicast_kernel(struct sock *sk, struct sk_buff *skb)
{
	int ret;
	struct netlink_sock *nlk = nlk_sk(sk);

	ret = -ECONNREFUSED;
	if (nlk->netlink_rcv != NULL) {
		ret = skb->len;
		skb_set_owner_r(skb, sk);
		nlk->netlink_rcv(skb);
	}
	kfree_skb(skb);
	sock_put(sk);
	return ret;
}

/*
netlink����
@ssk	: netlink_kernel_create()�������ص�netlink socket
@skb	: skb->dataָ����Ҫ���͵�netlink��Ϣ��
@pid	: ���ճ����pid(��һ���ǽ��̺ţ�����������Ψһ��ʶ)
@noblock: ���������ջ�����������ʱ�Ƿ�Ӧ������������������һ��ʧ����Ϣ
*/
int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 pid, int nonblock)
{
	struct sock *sk;
	int err;
	long timeo;

	/* ����skb��С */
	skb = netlink_trim(skb, gfp_any());

	/* ��ȡ��ʱʱ�� */
	timeo = sock_sndtimeo(ssk, nonblock);
retry:
	/* ssk�Ƿ������˵�sock, Ȼ�����pid�ҵ��ͻ��˵�sock */
	sk = netlink_getsockbypid(ssk, pid);
	if (IS_ERR(sk)) {
		kfree_skb(skb);
		return PTR_ERR(sk);
	}
	if (netlink_is_kernel(sk))
		return netlink_unicast_kernel(sk, skb);

	if (sk_filter(sk, skb)) {
		err = skb->len;
		kfree_skb(skb);
		sock_put(sk);
		return err;
	}

	/* �����ݰ������ڿͻ���sock�� */
	err = netlink_attachskb(sk, skb, &timeo, ssk);
	if (err == 1)
		goto retry;
	if (err)
		return err;

	/* ����netlink���ݰ� */
	return netlink_sendskb(sk, skb);
}
EXPORT_SYMBOL(netlink_unicast);

int netlink_has_listeners(struct sock *sk, unsigned int group)
{
	int res = 0;
	struct listeners *listeners;

	BUG_ON(!netlink_is_kernel(sk));

	rcu_read_lock();
	listeners = rcu_dereference(nl_table[sk->sk_protocol].listeners);

	if (group - 1 < nl_table[sk->sk_protocol].groups)
		res = test_bit(group - 1, listeners->masks);

	rcu_read_unlock();

	return res;
}
EXPORT_SYMBOL_GPL(netlink_has_listeners);

static inline int netlink_broadcast_deliver(struct sock *sk,
					    struct sk_buff *skb)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	/* ���ͻ�����Ҫ���㹻�ռ� */
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf &&
	    !test_bit(0, &nlk->state)) {
		skb_set_owner_r(skb, sk);
		/* ��ӵ����ն���β, �����Ǳ����ڲ�ͨ��, �����Լ��ҵ�Ҫ���͵�Ŀ�ķ�,
		   ����ֱ�ӽ������Ӹ�Ŀ�ķ�, �����ǽ��ն���
		*/
		skb_queue_tail(&sk->sk_receive_queue, skb);
		/* ����netlink sock��sk_data_ready��������, 
		   �ɴ˽����ں���netlink��Э��Ļص�����
		*/
		sk->sk_data_ready(sk, skb->len);
		return atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf;
	}
	return -1;
}

struct netlink_broadcast_data {
	struct sock *exclude_sk;
	struct net *net;
	u32 pid;
	u32 group;
	int failure;
	int delivery_failure;
	int congested;
	int delivered;
	gfp_t allocation;
	struct sk_buff *skb, *skb2;
	int (*tx_filter)(struct sock *dsk, struct sk_buff *skb, void *data);
	void *tx_data;
};

/*
��һ�㲥
*/
static inline int do_one_broadcast(struct sock *sk,
				   struct netlink_broadcast_data *p)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	int val;

	if (p->exclude_sk == sk)
		goto out;

	/* ���pid�����Ƿ�Ϸ� */
	if (nlk->pid == p->pid || p->group - 1 >= nlk->ngroups ||
	    !test_bit(p->group - 1, nlk->groups))
		goto out;

	if (!net_eq(sock_net(sk), p->net))
		goto out;

	if (p->failure) {
		netlink_overrun(sk);
		goto out;
	}

	sock_hold(sk);
	if (p->skb2 == NULL) {
		if (skb_shared(p->skb)) {
			/* ��¡skb */
			p->skb2 = skb_clone(p->skb, p->allocation);
		} else {
			/* ��ʱskb����ΪNULL�� */
			p->skb2 = skb_get(p->skb);
			/*
			 * skb ownership may have been set when
			 * delivered to a previous socket.
			 */
			skb_orphan(p->skb2);
		}
	}
	/* �������ΪNULL��Ȼ�ǿ�¡��ֵʧ�� */
	if (p->skb2 == NULL) {
		netlink_overrun(sk);
		/* Clone failed. Notify ALL listeners. */
		p->failure = 1;
		if (nlk->flags & NETLINK_BROADCAST_SEND_ERROR)
			p->delivery_failure = 1;
	} else if (p->tx_filter && p->tx_filter(sk, p->skb2, p->tx_data)) {
		kfree_skb(p->skb2);
		p->skb2 = NULL;
	} else if (sk_filter(sk, p->skb2)) {
		kfree_skb(p->skb2);
		p->skb2 = NULL;
	/* ������skb2 */
	} else if ((val = netlink_broadcast_deliver(sk, p->skb2)) < 0) {
		netlink_overrun(sk);
		if (nlk->flags & NETLINK_BROADCAST_SEND_ERROR)
			p->delivery_failure = 1;
	/* ������������ */
	} else {
		p->congested |= val;
		p->delivered = 1;
		p->skb2 = NULL;
	}
	sock_put(sk);

out:
	return 0;
}

/*
netlink�㲥, ���͵����ڵ�ȫ��sock

group��ֵ�ǽ�����Ϣ�ĸ�����ı���λ����������Ľ��
allocation���ں��ڴ���������͡�
ͨ����������ж�������ʹ��GFP_ATOMIC,����ʹ��GFP_KERNEL��
�������ڷ��Ͷಥ��Ϣʱ��API������Ҫ����һ�����߶��socket�����������п���������ġ�
*/
int netlink_broadcast_filtered(struct sock *ssk, struct sk_buff *skb, u32 pid,
	u32 group, gfp_t allocation,
	int (*filter)(struct sock *dsk, struct sk_buff *skb, void *data),
	void *filter_data)
{
	struct net *net = sock_net(ssk);
	/* netlink�㲥���ݽṹ��Ϣ */
	struct netlink_broadcast_data info;
	struct hlist_node *node;
	struct sock *sk;

	/* ����skb�ռ� */
	skb = netlink_trim(skb, allocation);

	/* ���info�ṹ�������� */
	info.exclude_sk = ssk;
	info.net = net;
	info.pid = pid;
	info.group = group;
	info.failure = 0;
	info.delivery_failure = 0;
	info.congested = 0;
	info.delivered = 0;
	info.allocation = allocation;
	info.skb = skb;
	info.skb2 = NULL;
	info.tx_filter = filter;
	info.tx_data = filter_data;

	/* While we sleep in clone, do not allow to change socket list */

	netlink_lock_table();

	/* �����ಥ����, �ֱ��ÿ��sock���е��� */
	sk_for_each_bound(sk, node, &nl_table[ssk->sk_protocol].mc_list)
		do_one_broadcast(sk, &info);

	consume_skb(skb);

	netlink_unlock_table();

	if (info.delivery_failure) {
		kfree_skb(info.skb2);
		return -ENOBUFS;
	} else
		consume_skb(info.skb2);

	if (info.delivered) {
		if (info.congested && (allocation & __GFP_WAIT))
			yield();
		return 0;
	}
	return -ESRCH;
}
EXPORT_SYMBOL(netlink_broadcast_filtered);

int netlink_broadcast(struct sock *ssk, struct sk_buff *skb, u32 pid,
		      u32 group, gfp_t allocation)
{
	return netlink_broadcast_filtered(ssk, skb, pid, group, allocation,
		NULL, NULL);
}
EXPORT_SYMBOL(netlink_broadcast);

struct netlink_set_err_data {
	struct sock *exclude_sk;
	u32 pid;
	u32 group;
	int code;
};

static inline int do_one_set_err(struct sock *sk,
				 struct netlink_set_err_data *p)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	int ret = 0;

	if (sk == p->exclude_sk)
		goto out;

	if (!net_eq(sock_net(sk), sock_net(p->exclude_sk)))
		goto out;

	if (nlk->pid == p->pid || p->group - 1 >= nlk->ngroups ||
	    !test_bit(p->group - 1, nlk->groups))
		goto out;

	if (p->code == ENOBUFS && nlk->flags & NETLINK_RECV_NO_ENOBUFS) {
		ret = 1;
		goto out;
	}

	sk->sk_err = p->code;
	sk->sk_error_report(sk);
out:
	return ret;
}

/**
 * netlink_set_err - report error to broadcast listeners
 * @ssk: the kernel netlink socket, as returned by netlink_kernel_create()
 * @pid: the PID of a process that we want to skip (if any)
 * @groups: the broadcast group that will notice the error
 * @code: error code, must be negative (as usual in kernelspace)
 *
 * This function returns the number of broadcast listeners that have set the
 * NETLINK_RECV_NO_ENOBUFS socket option.
 */
int netlink_set_err(struct sock *ssk, u32 pid, u32 group, int code)
{
	struct netlink_set_err_data info;
	struct hlist_node *node;
	struct sock *sk;
	int ret = 0;

	info.exclude_sk = ssk;
	info.pid = pid;
	info.group = group;
	/* sk->sk_err wants a positive error value */
	info.code = -code;

	read_lock(&nl_table_lock);

	sk_for_each_bound(sk, node, &nl_table[ssk->sk_protocol].mc_list)
		ret += do_one_set_err(sk, &info);

	read_unlock(&nl_table_lock);
	return ret;
}
EXPORT_SYMBOL(netlink_set_err);

/* must be called with netlink table grabbed */
static void netlink_update_socket_mc(struct netlink_sock *nlk,
				     unsigned int group,
				     int is_new)
{
	int old, new = !!is_new, subscriptions;

	old = test_bit(group - 1, nlk->groups);
	subscriptions = nlk->subscriptions - old + new;
	if (new)
		__set_bit(group - 1, nlk->groups);
	else
		__clear_bit(group - 1, nlk->groups);
	netlink_update_subscriptions(&nlk->sk, subscriptions);
	netlink_update_listeners(&nlk->sk);
}

/*
����netlink sock�ĸ��ֿ��Ʋ���
*/
static int netlink_setsockopt(struct socket *sock, int level, int optname,
			      char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	unsigned int val = 0;
	int err;

	/* sock���ҪΪSOL_NETLINK */
	if (level != SOL_NETLINK)
		return -ENOPROTOOPT;

	/* ��ȡ�û��ռ��������Ϣ */
	if (optlen >= sizeof(int) &&
	    get_user(val, (unsigned int __user *)optval))
		return -EFAULT;

	switch (optname) {
	/* ����NETLINK_RECV_PKTINFO��־, ��0����, 0Ϊ��� */
	case NETLINK_PKTINFO:
		if (val)
			nlk->flags |= NETLINK_RECV_PKTINFO;
		else
			nlk->flags &= ~NETLINK_RECV_PKTINFO;
		err = 0;
		break;
	/* ������˳��ಥ�� */
	case NETLINK_ADD_MEMBERSHIP:
	case NETLINK_DROP_MEMBERSHIP: {
		/* ���Ȩ�� */
		if (!netlink_capable(sock, NL_NONROOT_RECV))
			return -EPERM;
		/* �����ǰsock�Ķಥ��Ϊ��ʱ����ռ� */
		err = netlink_realloc_groups(sk);
		if (err)
			return err;
		/* ������ݷ�Χ */
		if (!val || val - 1 >= nlk->ngroups)
			return -EINVAL;
		netlink_table_grab();
		netlink_update_socket_mc(nlk, val,
					 optname == NETLINK_ADD_MEMBERSHIP);
		netlink_table_ungrab();
		err = 0;
		break;
	}
	case NETLINK_BROADCAST_ERROR:
		if (val)
			nlk->flags |= NETLINK_BROADCAST_SEND_ERROR;
		else
			nlk->flags &= ~NETLINK_BROADCAST_SEND_ERROR;
		err = 0;
		break;
	case NETLINK_NO_ENOBUFS:
		if (val) {
			nlk->flags |= NETLINK_RECV_NO_ENOBUFS;
			clear_bit(0, &nlk->state);
			wake_up_interruptible(&nlk->wait);
		} else
			nlk->flags &= ~NETLINK_RECV_NO_ENOBUFS;
		err = 0;
		break;
	default:
		err = -ENOPROTOOPT;
	}
	return err;
}

/*
��ȡnetlink sock�ĸ��ֿ��Ʋ���
*/
static int netlink_getsockopt(struct socket *sock, int level, int optname,
			      char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	int len, val, err;

	/* sock���ҪΪSOL_NETLINK */
	if (level != SOL_NETLINK)
		return -ENOPROTOOPT;

	/* ��ȡ�û��ռ�Ĳ�ѯ��Ϣ */
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	/* ѡ����ϢPKTINFO */
	case NETLINK_PKTINFO:
		if (len < sizeof(int))
			return -EINVAL;
		len = sizeof(int);
		/* ��sock��־�Ƿ���NETLINK_RECV_PKTINFO����1��0 */
		val = nlk->flags & NETLINK_RECV_PKTINFO ? 1 : 0;
		if (put_user(len, optlen) ||
		    put_user(val, optval))
			return -EFAULT;
		err = 0;
		break;
	case NETLINK_BROADCAST_ERROR:
		if (len < sizeof(int))
			return -EINVAL;
		len = sizeof(int);
		val = nlk->flags & NETLINK_BROADCAST_SEND_ERROR ? 1 : 0;
		if (put_user(len, optlen) ||
		    put_user(val, optval))
			return -EFAULT;
		err = 0;
		break;
	case NETLINK_NO_ENOBUFS:
		if (len < sizeof(int))
			return -EINVAL;
		len = sizeof(int);
		val = nlk->flags & NETLINK_RECV_NO_ENOBUFS ? 1 : 0;
		if (put_user(len, optlen) ||
		    put_user(val, optval))
			return -EFAULT;
		err = 0;
		break;
	default:
		err = -ENOPROTOOPT;
	}
	return err;
}

static void netlink_cmsg_recv_pktinfo(struct msghdr *msg, struct sk_buff *skb)
{
	struct nl_pktinfo info;

	info.group = NETLINK_CB(skb).dst_group;
	put_cmsg(msg, SOL_NETLINK, NETLINK_PKTINFO, sizeof(info), &info);
}

/*
���û��㷢�����ݵ��ں�, �ں˵�sock�ǽ��շ�
*/
static int netlink_sendmsg(struct kiocb *kiocb, struct socket *sock,
			   struct msghdr *msg, size_t len)
{
	/* sock��IO���ƿ� */
	struct sock_iocb *siocb = kiocb_to_siocb(kiocb);
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *addr = msg->msg_name;
	u32 dst_pid;
	u32 dst_group;
	struct sk_buff *skb;
	int err;
	struct scm_cookie scm;

	/* ������OOB(out of band)��־, ��TCP��֧��,netlink��֧�� */
	if (msg->msg_flags&MSG_OOB)
		return -EOPNOTSUPP;

	if (NULL == siocb->scm)
		siocb->scm = &scm;

	err = scm_send(sock, msg, siocb->scm);
	if (err < 0)
		return err;

	/* ȷ��Ŀ��pid���� */
	if (msg->msg_namelen) {
		err = -EINVAL;
		if (addr->nl_family != AF_NETLINK)
			goto out;
		dst_pid = addr->nl_pid;
		dst_group = ffs(addr->nl_groups);
		err =  -EPERM;
		if (dst_group && !netlink_capable(sock, NL_NONROOT_SEND))
			goto out;
	} else {
		dst_pid = nlk->dst_pid;
		dst_group = nlk->dst_group;
	}

	/* ���sock��pidΪ0, �Զ���һ��pid */
	if (!nlk->pid) {
		err = netlink_autobind(sock);
		if (err)
			goto out;
	}

	err = -EMSGSIZE;
	/* ��Ϣ����̫�� */
	if (len > sk->sk_sndbuf - 32)
		goto out;
	err = -ENOBUFS;
	/* ������һ��skb���ݰ� */
	skb = alloc_skb(len, GFP_KERNEL);
	if (skb == NULL)
		goto out;

	/* ���ø�skb��netlink���ƿ���� */
	NETLINK_CB(skb).pid	= nlk->pid;
	NETLINK_CB(skb).dst_group = dst_group;
	memcpy(NETLINK_CREDS(skb), &siocb->scm->creds, sizeof(struct ucred));

	err = -EFAULT;
	/* �����͵���Ϣ������skb�Ĵ洢�� */
	if (memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len)) {
		kfree_skb(skb);
		goto out;
	}

	err = security_netlink_send(sk, skb);
	if (err) {
		kfree_skb(skb);
		goto out;
	}

	/* ����Ƕಥ��,�Ƚ��й㲥���� */
	if (dst_group) {
		atomic_inc(&skb->users);
		netlink_broadcast(sk, skb, dst_pid, dst_group, GFP_KERNEL);
	}
	/* �������� */
	err = netlink_unicast(sk, skb, dst_pid, msg->msg_flags&MSG_DONTWAIT);

out:
	scm_destroy(siocb->scm);
	return err;
}

/*
�������ں˴����û��ռ��
*/
static int netlink_recvmsg(struct kiocb *kiocb, struct socket *sock,
			   struct msghdr *msg, size_t len,
			   int flags)
{
	/* sock��IO���ƿ� */
	struct sock_iocb *siocb = kiocb_to_siocb(kiocb);
	struct scm_cookie scm;
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	/* �Ƿ��Ƿ������� */
	int noblock = flags&MSG_DONTWAIT;
	size_t copied;
	struct sk_buff *skb, *data_skb;
	int err, ret;

	/* ���ܴ�OOB��־ */
	if (flags&MSG_OOB)
		return -EOPNOTSUPP;

	copied = 0;

	/* ����һ�����ݰ� */
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (skb == NULL)
		goto out;

	data_skb = skb;

#ifdef CONFIG_COMPAT_NETLINK_MESSAGES
	if (unlikely(skb_shinfo(skb)->frag_list)) {
		/*
		 * If this skb has a frag_list, then here that means that we
		 * will have to use the frag_list skb's data for compat tasks
		 * and the regular skb's data for normal (non-compat) tasks.
		 *
		 * If we need to send the compat skb, assign it to the
		 * 'data_skb' variable so that it will be used below for data
		 * copying. We keep 'skb' for everything else, including
		 * freeing both later.
		 */
		if (flags & MSG_CMSG_COMPAT)
			data_skb = skb_shinfo(skb)->frag_list;
	}
#endif

	msg->msg_namelen = 0;

	/* �յ���ʵ�����ݳ��� */
	copied = data_skb->len;
	/* ���ջ���С�����ݳ���, �������ݲü���־ */
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	skb_reset_transport_header(data_skb);
	/* ��skb�����ݿ��������ջ����� */
	err = skb_copy_datagram_iovec(data_skb, 0, msg->msg_iov, copied);

	/* sock��Ч, ��дnl sock������ */
	if (msg->msg_name) {
		struct sockaddr_nl *addr = (struct sockaddr_nl *)msg->msg_name;
		addr->nl_family = AF_NETLINK;
		addr->nl_pad    = 0;
		addr->nl_pid	= NETLINK_CB(skb).pid;
		addr->nl_groups	= netlink_group_mask(NETLINK_CB(skb).dst_group);
		msg->msg_namelen = sizeof(*addr);
	}

	/* �������ݰ���Ϣ��־, ����Ϣͷ�������û��ռ� */
	if (nlk->flags & NETLINK_RECV_PKTINFO)
		netlink_cmsg_recv_pktinfo(msg, skb);

	if (NULL == siocb->scm) {
		memset(&scm, 0, sizeof(scm));
		siocb->scm = &scm;
	}
	siocb->scm->creds = *NETLINK_CREDS(skb);
	if (flags & MSG_TRUNC)
		copied = data_skb->len;

	skb_free_datagram(sk, skb);

	if (nlk->cb && atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf / 2) {
		ret = netlink_dump(sk);
		if (ret) {
			sk->sk_err = ret;
			sk->sk_error_report(sk);
		}
	}

	scm_recv(sock, msg, siocb->scm, flags);
out:
	/* ���ջ��� */
	netlink_rcv_wake(sk);
	return err ? : copied;
}

static void netlink_data_ready(struct sock *sk, int len)
{
	BUG();
}

/*
 *	We export these functions to other modules. They provide a
 *	complete set of kernel non-blocking support for message
 *	queueing.
 */

/*
��ǰҲ���ܹ���һ������netlink sock�ĺ���netlink_kernel_create, 
һ������netlink�ĸ���Э������ģ���ʼ��ʱ���õ�, 
������socketϵͳ����ʱ���õ�, ÿ��netlinkЭ���ʼ����ֻ����һ��, 
����һ���ں��е�netlink�ӿ�, �൱�ڷ�����, ����Ҳ������__netlink_create()����

@unit	: netlinkЭ������ ��:NETLINK_ROUTE
@input	: ����ָ��input,��netlink socket���յ���Ϣʱ���õĴ�����Ϣ�Ļص�����ָ��

netlink��Э��ʹ��netink_kernel_create()������Ϣ��䵽��Ӧ�±��nl_table��
*/
struct sock *
netlink_kernel_create(struct net *net, int unit, unsigned int groups,
		      void (*input)(struct sk_buff *skb),
		      struct mutex *cb_mutex, struct module *module)
{
	struct socket *sock;
	struct sock *sk;
	struct netlink_sock *nlk;
	struct listeners *listeners = NULL;

	BUG_ON(!nl_table);

	if (unit < 0 || unit >= MAX_LINKS)
		return NULL;

	/* �����lite��ʾֻ�Ǽ򵥷���һ��socket,û��������ʼ�� */
	if (sock_create_lite(PF_NETLINK, SOCK_DGRAM, unit, &sock))
		return NULL;

	/*
	 * We have to just have a reference on the net from sk, but don't
	 * get_net it. Besides, we cannot get and then put the net here.
	 * So we create one inside init_net and the move it to net.
	 */

	/* �����lite sock�ٽ���netlink sock */
	if (__netlink_create(&init_net, sock, cb_mutex, unit) < 0)
		goto out_sock_release_nosk;

	sk = sock->sk;
	sk_change_net(sk, net);

	if (groups < 32)
		groups = 32;

	/* listerns�Ǹ�λͼ��Ӧgroups��ÿ��Ԫ�� */
	listeners = kzalloc(sizeof(*listeners) + NLGRPSZ(groups), GFP_KERNEL);
	if (!listeners)
		goto out_sock_release;

	/* ���¶�����sk_data_ready���� */
	sk->sk_data_ready = netlink_data_ready;
	if (input)
		nlk_sk(sk)->netlink_rcv = input;

	if (netlink_insert(sk, net, 0))
		goto out_sock_release;

	nlk = nlk_sk(sk);
	nlk->flags |= NETLINK_KERNEL_SOCKET;

	/* ע�ᵽ��Ӧunit��netlinkЭ�����
	   ʵ����nl_table��һ��ָ�룬����ռ������㵱������������
	*/
	netlink_table_grab();
	if (!nl_table[unit].registered) {
		nl_table[unit].groups = groups;
		rcu_assign_pointer(nl_table[unit].listeners, listeners);
		nl_table[unit].cb_mutex = cb_mutex;
		nl_table[unit].module = module;
		/* �ñ�־��ʾ����Ǽ� */
		nl_table[unit].registered = 1;
	} else {
		kfree(listeners);
		nl_table[unit].registered++;
	}
	netlink_table_ungrab();
	return sk;

out_sock_release:
	kfree(listeners);
	netlink_kernel_release(sk);
	return NULL;

out_sock_release_nosk:
	sock_release(sock);
	return NULL;
}
EXPORT_SYMBOL(netlink_kernel_create);


void
netlink_kernel_release(struct sock *sk)
{
	sk_release_kernel(sk);
}
EXPORT_SYMBOL(netlink_kernel_release);

int __netlink_change_ngroups(struct sock *sk, unsigned int groups)
{
	struct listeners *new, *old;
	struct netlink_table *tbl = &nl_table[sk->sk_protocol];

	if (groups < 32)
		groups = 32;

	if (NLGRPSZ(tbl->groups) < NLGRPSZ(groups)) {
		new = kzalloc(sizeof(*new) + NLGRPSZ(groups), GFP_ATOMIC);
		if (!new)
			return -ENOMEM;
		old = rcu_dereference_protected(tbl->listeners, 1);
		memcpy(new->masks, old->masks, NLGRPSZ(tbl->groups));
		rcu_assign_pointer(tbl->listeners, new);

		kfree_rcu(old, rcu);
	}
	tbl->groups = groups;

	return 0;
}

/**
 * netlink_change_ngroups - change number of multicast groups
 *
 * This changes the number of multicast groups that are available
 * on a certain netlink family. Note that it is not possible to
 * change the number of groups to below 32. Also note that it does
 * not implicitly call netlink_clear_multicast_users() when the
 * number of groups is reduced.
 *
 * @sk: The kernel netlink socket, as returned by netlink_kernel_create().
 * @groups: The new number of groups.
 */
int netlink_change_ngroups(struct sock *sk, unsigned int groups)
{
	int err;

	netlink_table_grab();
	err = __netlink_change_ngroups(sk, groups);
	netlink_table_ungrab();

	return err;
}

void __netlink_clear_multicast_users(struct sock *ksk, unsigned int group)
{
	struct sock *sk;
	struct hlist_node *node;
	struct netlink_table *tbl = &nl_table[ksk->sk_protocol];

	sk_for_each_bound(sk, node, &tbl->mc_list)
		netlink_update_socket_mc(nlk_sk(sk), group, 0);
}

/**
 * netlink_clear_multicast_users - kick off multicast listeners
 *
 * This function removes all listeners from the given group.
 * @ksk: The kernel netlink socket, as returned by
 *	netlink_kernel_create().
 * @group: The multicast group to clear.
 */
void netlink_clear_multicast_users(struct sock *ksk, unsigned int group)
{
	netlink_table_grab();
	__netlink_clear_multicast_users(ksk, group);
	netlink_table_ungrab();
}

void netlink_set_nonroot(int protocol, unsigned int flags)
{
	if ((unsigned int)protocol < MAX_LINKS)
		nl_table[protocol].nl_nonroot = flags;
}
EXPORT_SYMBOL(netlink_set_nonroot);

static void netlink_destroy_callback(struct netlink_callback *cb)
{
	kfree_skb(cb->skb);
	kfree(cb);
}

/*
 * It looks a bit ugly.
 * It would be better to create kernel thread.
 */

static int netlink_dump(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	struct netlink_callback *cb;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	int len, err = -ENOBUFS;
	int alloc_size;

	mutex_lock(nlk->cb_mutex);

	cb = nlk->cb;
	if (cb == NULL) {
		err = -EINVAL;
		goto errout_skb;
	}

	alloc_size = max_t(int, cb->min_dump_alloc, NLMSG_GOODSIZE);

	skb = sock_rmalloc(sk, alloc_size, 0, GFP_KERNEL);
	if (!skb)
		goto errout_skb;

	len = cb->dump(skb, cb);

	if (len > 0) {
		mutex_unlock(nlk->cb_mutex);

		if (sk_filter(sk, skb))
			kfree_skb(skb);
		else {
			skb_queue_tail(&sk->sk_receive_queue, skb);
			sk->sk_data_ready(sk, skb->len);
		}
		return 0;
	}

	nlh = nlmsg_put_answer(skb, cb, NLMSG_DONE, sizeof(len), NLM_F_MULTI);
	if (!nlh)
		goto errout_skb;

	nl_dump_check_consistent(cb, nlh);

	memcpy(nlmsg_data(nlh), &len, sizeof(len));

	if (sk_filter(sk, skb))
		kfree_skb(skb);
	else {
		skb_queue_tail(&sk->sk_receive_queue, skb);
		sk->sk_data_ready(sk, skb->len);
	}

	if (cb->done)
		cb->done(cb);
	nlk->cb = NULL;
	mutex_unlock(nlk->cb_mutex);

	netlink_destroy_callback(cb);
	return 0;

errout_skb:
	mutex_unlock(nlk->cb_mutex);
	kfree_skb(skb);
	return err;
}

int netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
		       const struct nlmsghdr *nlh,
		       int (*dump)(struct sk_buff *skb,
				   struct netlink_callback *),
		       int (*done)(struct netlink_callback *),
		       u16 min_dump_alloc)
{
	struct netlink_callback *cb;
	struct sock *sk;
	struct netlink_sock *nlk;
	int ret;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (cb == NULL)
		return -ENOBUFS;

	cb->dump = dump;
	cb->done = done;
	cb->nlh = nlh;
	cb->min_dump_alloc = min_dump_alloc;
	atomic_inc(&skb->users);
	cb->skb = skb;

	sk = netlink_lookup(sock_net(ssk), ssk->sk_protocol, NETLINK_CB(skb).pid);
	if (sk == NULL) {
		netlink_destroy_callback(cb);
		return -ECONNREFUSED;
	}
	nlk = nlk_sk(sk);
	/* A dump is in progress... */
	mutex_lock(nlk->cb_mutex);
	if (nlk->cb) {
		mutex_unlock(nlk->cb_mutex);
		netlink_destroy_callback(cb);
		sock_put(sk);
		return -EBUSY;
	}
	nlk->cb = cb;
	mutex_unlock(nlk->cb_mutex);

	ret = netlink_dump(sk);

	sock_put(sk);

	if (ret)
		return ret;

	/* We successfully started a dump, by returning -EINTR we
	 * signal not to send ACK even if it was requested.
	 */
	return -EINTR;
}
EXPORT_SYMBOL(netlink_dump_start);

void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err)
{
	struct sk_buff *skb;
	struct nlmsghdr *rep;
	struct nlmsgerr *errmsg;
	size_t payload = sizeof(*errmsg);

	/* error messages get the original request appened */
	if (err)
		payload += nlmsg_len(nlh);

	skb = nlmsg_new(payload, GFP_KERNEL);
	if (!skb) {
		struct sock *sk;

		sk = netlink_lookup(sock_net(in_skb->sk),
				    in_skb->sk->sk_protocol,
				    NETLINK_CB(in_skb).pid);
		if (sk) {
			sk->sk_err = ENOBUFS;
			sk->sk_error_report(sk);
			sock_put(sk);
		}
		return;
	}

	rep = __nlmsg_put(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
			  NLMSG_ERROR, payload, 0);
	errmsg = nlmsg_data(rep);
	errmsg->error = err;
	memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(*nlh));
	netlink_unicast(in_skb->sk, skb, NETLINK_CB(in_skb).pid, MSG_DONTWAIT);
}
EXPORT_SYMBOL(netlink_ack);

int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
						     struct nlmsghdr *))
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
			goto ack;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto ack;

		err = cb(skb, nlh);
		if (err == -EINTR)
			goto skip;

ack:
		if (nlh->nlmsg_flags & NLM_F_ACK || err)
			netlink_ack(skb, nlh, err);

skip:
		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len)
			msglen = skb->len;
		skb_pull(skb, msglen);
	}

	return 0;
}
EXPORT_SYMBOL(netlink_rcv_skb);

/**
 * nlmsg_notify - send a notification netlink message
 * @sk: netlink socket to use
 * @skb: notification message
 * @pid: destination netlink pid for reports or 0
 * @group: destination multicast group or 0
 * @report: 1 to report back, 0 to disable
 * @flags: allocation flags
 */
int nlmsg_notify(struct sock *sk, struct sk_buff *skb, u32 pid,
		 unsigned int group, int report, gfp_t flags)
{
	int err = 0;

	if (group) {
		int exclude_pid = 0;

		if (report) {
			atomic_inc(&skb->users);
			exclude_pid = pid;
		}

		/* errors reported via destination sk->sk_err, but propagate
		 * delivery errors if NETLINK_BROADCAST_ERROR flag is set */
		err = nlmsg_multicast(sk, skb, exclude_pid, group, flags);
	}

	if (report) {
		int err2;

		err2 = nlmsg_unicast(sk, skb, pid);
		if (!err || err == -ESRCH)
			err = err2;
	}

	return err;
}
EXPORT_SYMBOL(nlmsg_notify);

#ifdef CONFIG_PROC_FS
struct nl_seq_iter {
	struct seq_net_private p;
	int link;
	int hash_idx;
};

static struct sock *netlink_seq_socket_idx(struct seq_file *seq, loff_t pos)
{
	struct nl_seq_iter *iter = seq->private;
	int i, j;
	struct sock *s;
	struct hlist_node *node;
	loff_t off = 0;

	for (i = 0; i < MAX_LINKS; i++) {
		struct nl_pid_hash *hash = &nl_table[i].hash;

		for (j = 0; j <= hash->mask; j++) {
			sk_for_each(s, node, &hash->table[j]) {
				if (sock_net(s) != seq_file_net(seq))
					continue;
				if (off == pos) {
					iter->link = i;
					iter->hash_idx = j;
					return s;
				}
				++off;
			}
		}
	}
	return NULL;
}

static void *netlink_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(nl_table_lock)
{
	read_lock(&nl_table_lock);
	return *pos ? netlink_seq_socket_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *netlink_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *s;
	struct nl_seq_iter *iter;
	int i, j;

	++*pos;

	if (v == SEQ_START_TOKEN)
		return netlink_seq_socket_idx(seq, 0);

	iter = seq->private;
	s = v;
	do {
		s = sk_next(s);
	} while (s && sock_net(s) != seq_file_net(seq));
	if (s)
		return s;

	i = iter->link;
	j = iter->hash_idx + 1;

	do {
		struct nl_pid_hash *hash = &nl_table[i].hash;

		for (; j <= hash->mask; j++) {
			s = sk_head(&hash->table[j]);
			while (s && sock_net(s) != seq_file_net(seq))
				s = sk_next(s);
			if (s) {
				iter->link = i;
				iter->hash_idx = j;
				return s;
			}
		}

		j = 0;
	} while (++i < MAX_LINKS);

	return NULL;
}

static void netlink_seq_stop(struct seq_file *seq, void *v)
	__releases(nl_table_lock)
{
	read_unlock(&nl_table_lock);
}


static int netlink_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "sk       Eth Pid    Groups   "
			 "Rmem     Wmem     Dump     Locks     Drops     Inode\n");
	else {
		struct sock *s = v;
		struct netlink_sock *nlk = nlk_sk(s);

		seq_printf(seq, "%pK %-3d %-6d %08x %-8d %-8d %pK %-8d %-8d %-8lu\n",
			   s,
			   s->sk_protocol,
			   nlk->pid,
			   nlk->groups ? (u32)nlk->groups[0] : 0,
			   sk_rmem_alloc_get(s),
			   sk_wmem_alloc_get(s),
			   nlk->cb,
			   atomic_read(&s->sk_refcnt),
			   atomic_read(&s->sk_drops),
			   sock_i_ino(s)
			);

	}
	return 0;
}

static const struct seq_operations netlink_seq_ops = {
	.start  = netlink_seq_start,
	.next   = netlink_seq_next,
	.stop   = netlink_seq_stop,
	.show   = netlink_seq_show,
};


static int netlink_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &netlink_seq_ops,
				sizeof(struct nl_seq_iter));
}

static const struct file_operations netlink_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= netlink_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

#endif

int netlink_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&netlink_chain, nb);
}
EXPORT_SYMBOL(netlink_register_notifier);

int netlink_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&netlink_chain, nb);
}
EXPORT_SYMBOL(netlink_unregister_notifier);

static const struct proto_ops netlink_ops = {
	.family =	PF_NETLINK,
	.owner =	THIS_MODULE,
	.release =	netlink_release,
	.bind =		netlink_bind,
	.connect =	netlink_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	netlink_getname,
	.poll =		datagram_poll,
	.ioctl =	sock_no_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	netlink_setsockopt,
	.getsockopt =	netlink_getsockopt,
	.sendmsg =	netlink_sendmsg,
	.recvmsg =	netlink_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

/*
netlinkЭ�������, ���û�����ʹ��socket��netlink���͵�socketʱ����,
��Ӧ��create������__sock_create(net/socket.c)�����е���
*/
static const struct net_proto_family netlink_family_ops = {
	.family = PF_NETLINK,
	.create = netlink_create,
	.owner	= THIS_MODULE,	/* for consistency 8) */
};

static int __net_init netlink_net_init(struct net *net)
{
#ifdef CONFIG_PROC_FS
	if (!proc_net_fops_create(net, "netlink", 0, &netlink_seq_fops))
		return -ENOMEM;
#endif
	return 0;
}

static void __net_exit netlink_net_exit(struct net *net)
{
#ifdef CONFIG_PROC_FS
	proc_net_remove(net, "netlink");
#endif
}

static void __init netlink_add_usersock_entry(void)
{
	struct listeners *listeners;
	int groups = 32;

	listeners = kzalloc(sizeof(*listeners) + NLGRPSZ(groups), GFP_KERNEL);
	if (!listeners)
		panic("netlink_add_usersock_entry: Cannot allocate listeners\n");

	netlink_table_grab();

	nl_table[NETLINK_USERSOCK].groups = groups;
	rcu_assign_pointer(nl_table[NETLINK_USERSOCK].listeners, listeners);
	nl_table[NETLINK_USERSOCK].module = THIS_MODULE;
	nl_table[NETLINK_USERSOCK].registered = 1;

	netlink_table_ungrab();
}

static struct pernet_operations __net_initdata netlink_net_ops = {
	.init = netlink_net_init,
	.exit = netlink_net_exit,
};

static int __init netlink_proto_init(void)
{
	struct sk_buff *dummy_skb;
	int i;
	unsigned long limit;
	unsigned int order;
	/* ע��netlink_proto�ṹ
	   ���һ������Ϊ0, ��ʾ������slab�ķ���, 
	   ֻ�Ǽ򵥵Ľ�netlink_proto�ṹ�ҽӵ�ϵͳ������Э��������,
	   ����ṹ����Ҫ�Ǹ�֪��netlink sock�ṹ�Ĵ�С
	*/
	int err = proto_register(&netlink_proto, 0);

	if (err != 0)
		goto out;

	BUILD_BUG_ON(sizeof(struct netlink_skb_parms) > sizeof(dummy_skb->cb));

	/* ����MAX_LINKS��netlink��ṹ */
	nl_table = kcalloc(MAX_LINKS, sizeof(*nl_table), GFP_KERNEL);
	if (!nl_table)
		goto panic;

	/* ���¸���ϵͳ�ڴ��С�����������Ԫ�ظ���
	   PAGE_SHIFT��ÿҳ��С��2����,��i386��12,��ÿҳ��4K,2^12
	   ����128M�ڴ�Ļ���,limit����ֵ��(128*1024) >> (21-12) = 256
	   ����64M�ڴ�Ļ���,limit����ֵ��(64*1024) >> (23-12) = 32
	*/
	if (totalram_pages >= (128 * 1024))
		limit = totalram_pages >> (21 - PAGE_SHIFT);
	else
		limit = totalram_pages >> (23 - PAGE_SHIFT);

	/* ����limit�ٺ�PAGE_SHIFT�������ڴ�ռ���Ӧ����ֵorder */
	order = get_bitmask_order(limit) - 1 + PAGE_SHIFT;
	/* limit�����ڵ��� */
	limit = (1UL << order) / sizeof(struct hlist_head);
	/* order��limit����2������ */
	order = get_bitmask_order(min(limit, (unsigned long)UINT_MAX)) - 1;

	for (i = 0; i < MAX_LINKS; i++) {
		struct nl_pid_hash *hash = &nl_table[i].hash;

		/* Ϊnetlink��ÿ����Э�����ͷ���HASH������ͷ */
		hash->table = nl_pid_hash_zalloc(1 * sizeof(*hash->table));
		if (!hash->table) {
			while (i-- > 0)
				nl_pid_hash_free(nl_table[i].hash.table,
						 1 * sizeof(*hash->table));
			kfree(nl_table);
			goto panic;
		}
		/* ������� */
		hash->max_shift = order;
		hash->shift = 0;
		hash->mask = 0;
		hash->rehash_time = jiffies;
	}

	netlink_add_usersock_entry();

	/* ע��netlinkЭ����ĵĲ����ṹ */
	sock_register(&netlink_family_ops);
	register_pernet_subsys(&netlink_net_ops);
	/* The netlink device handler may be needed early. */
	/* ��ʼ��·��netlink */
	rtnetlink_init();
out:
	return err;
panic:
	panic("netlink_init: Cannot allocate nl_table\n");
}

core_initcall(netlink_proto_init);
