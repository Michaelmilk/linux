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
netlink套接口结构

这个结构先是内嵌一个标准的struct sock结构,
后面又跟和netlink相关的特有相关数据,
内核中其他协议的sock也是类似定义的, 
注意sock结构必须放在第一位,这是为了可以直接将sock的指针转为netlink_sock的指针。
*/
struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	/* 自己的pid, 通常是0 */
	u32			pid;
	/* 对方的pid */
	u32			dst_pid;
	/* 对方的组 */
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	/* 多播组数量 */
	u32			ngroups;
	/* 多播组号 */
	unsigned long		*groups;
	unsigned long		state;
	/* 等待队列,用于处理接收发送包时的top half */
	wait_queue_head_t	wait;
	/* 回调结构,包含回调函数 */
	struct netlink_callback	*cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	void			(*netlink_bind)(int group);
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
	/* 链表节点 */
	struct hlist_head	*table;
	/* 重新计算HASH的时间间隔 */
	unsigned long		rehash_time;

	unsigned int		mask;
	unsigned int		shift;

	/* 链表节点数 */
	unsigned int		entries;
	/* 最大幂值 */
	unsigned int		max_shift;
	/* 随机数 */
	u32			rnd;
};

/*
netlink sock的哈希表

最大可有MAX_LINKS(32)个表，处理不同协议类型的netlink套接口, 
注意由于是自身的通信, 本机同时作为服务器和客户端, 
服务端需要一个套接口对应, 每个客户端也要有一个套接口对应, 
多个客户端的套接口形成一个链表.
*/
struct netlink_table {
	/* 根据pid进行HASH的netlink sock链表, 相当于客户端链表 */
	struct nl_pid_hash	hash;
	/* 多播的sock链表 */
	struct hlist_head	mc_list;
	/* 监听者标志 */
	struct listeners __rcu	*listeners;
	unsigned int		nl_nonroot;
	/* 每个netlink的协议类型可以定义多个组, 8的倍数,最小是32 */
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;
	void			(*bind)(int group);
	int			registered;
};

/*
在netlink_proto_init()中分配空间，共32项
分配了空间后，使用的时候便可以看做是struct netlink_table的一个数组了
每一个协议，如:NETLINK_ROUTE NETLINK_UNUSED等作为下标都对应数组中一项
*/
static struct netlink_table *nl_table;

static DECLARE_WAIT_QUEUE_HEAD(nl_table_wait);

static int netlink_dump(struct sock *sk);

static DEFINE_RWLOCK(nl_table_lock);
static atomic_t nl_table_users = ATOMIC_INIT(0);

static ATOMIC_NOTIFIER_HEAD(netlink_chain);

static inline u32 netlink_group_mask(u32 group)
{
	return group ? 1 << (group - 1) : 0;
}

static inline struct hlist_head *nl_pid_hashfn(struct nl_pid_hash *hash, u32 pid)
{
	return &hash->table[jhash_1word(pid, hash->rnd) & hash->mask];
}

static void netlink_destroy_callback(struct netlink_callback *cb)
{
	kfree_skb(cb->skb);
	kfree(cb);
}

static void netlink_consume_callback(struct netlink_callback *cb)
{
	consume_skb(cb->skb);
	kfree(cb);
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

static struct sock *netlink_lookup(struct net *net, int protocol, u32 pid)
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

static struct hlist_head *nl_pid_hash_zalloc(size_t size)
{
	if (size <= PAGE_SIZE)
		return kzalloc(size, GFP_ATOMIC);
	else
		return (struct hlist_head *)
			__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
					 get_order(size));
}

static void nl_pid_hash_free(struct hlist_head *table, size_t size)
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
dilute: 稀释
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
更新listeners
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
		/* 遍历多播链表生成多播组的掩码 */
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
根据pid插入
*/
static int netlink_insert(struct sock *sk, struct net *net, u32 pid)
{
	/* netlink相应协议的HASH结构 */
	struct nl_pid_hash *hash = &nl_table[sk->sk_protocol].hash;
	struct hlist_head *head;
	/* 缺省错误为地址已经被使用 */
	int err = -EADDRINUSE;
	struct sock *osk;
	struct hlist_node *node;
	int len;

	netlink_table_grab();
	/* 根据pid查找相应HASH链表头 */
	head = nl_pid_hashfn(hash, pid);
	len = 0;
	/* 检查pid是否已经在链表中, 有则失败 */
	sk_for_each(osk, node, head) {
		if (net_eq(sock_net(osk), net) && (nlk_sk(osk)->pid == pid))
			break;
		len++;
	}
	if (node)
		goto err;

	/* 缺省错误改为系统忙 */
	err = -EBUSY;
	/* 如果sock的pid不为0, 错误, 只有pid为0的sock才能执行该函数
	   sock的pid不为0时不会再进行insert操作了
	*/
	if (nlk_sk(sk)->pid)
		goto err;

	/* 缺省错误改为无内存空间 */
	err = -ENOMEM;
	if (BITS_PER_LONG > 32 && unlikely(hash->entries >= UINT_MAX))
		goto err;

	/* 如果链表不为空而且链表长度数量过长,会调整HASH表,重新获取HASH链表头
	   不过这种情况很少发生
	*/
	if (len && nl_pid_hash_dilute(hash, len))
		head = nl_pid_hashfn(hash, pid);
	hash->entries++;
	/* 将pid赋值给sock的pid参数 */
	nlk_sk(sk)->pid = pid;
	/* 将sock节点添加进HASH链表 */
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

	/* netlink sock的基本操作 */
	sock->ops = &netlink_ops;

	/* 分配sock结构, 通过netlink_proto中的obj_size指出了netlink sock的大小 */
	sk = sk_alloc(net, PF_NETLINK, GFP_KERNEL, &netlink_proto);
	if (!sk)
		return -ENOMEM;

	/* 初始化sock基本数据, 将sock和socket关联起来 */
	sock_init_data(sock, sk);

	/* 将普通sock转为netlink sock,
	   实际只是重新定义的一下指针类型,指针本身值不变
	*/
	nlk = nlk_sk(sk);
	/* 初始化sock的锁 */
	if (cb_mutex) {
		nlk->cb_mutex = cb_mutex;
	} else {
		nlk->cb_mutex = &nlk->cb_def_mutex;
		mutex_init(nlk->cb_mutex);
	}
	/* 初始化等待队列 */
	init_waitqueue_head(&nlk->wait);

	/* sock的析构函数,释放接收队列中的skb数据包 */
	sk->sk_destruct = netlink_sock_destruct;
	sk->sk_protocol = protocol;
	return 0;
}

/*
在用户空间每次打开netlink socket时都会调用此函数

用户空间使用socket(2)系统调用打开netlink类型的套接口时, 
在内核中会调用sys_sock()函数, 然后是调用__sock_create()函数, 
在其中调用netlink协议族的create()函数, 即netlink_create()函数.
*/
static int netlink_create(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	struct module *module = NULL;
	struct mutex *cb_mutex;
	struct netlink_sock *nlk;
	void (*bind)(int group);
	int err = 0;

	/* sock状态初始化 */
	sock->state = SS_UNCONNECTED;

	/* 创建socket时，type只能填SOCK_RAW或SOCK_DGRAM */
	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	/* 判断创建socket时的子协议protocol范围 */
	if (protocol < 0 || protocol >= MAX_LINKS)
		return -EPROTONOSUPPORT;

	netlink_lock_table();
#ifdef CONFIG_MODULES
	/* 如果相应的netlink协议是模块又没有加载的话先加载该模块 */
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
	bind = nl_table[protocol].bind;
	netlink_unlock_table();

	if (err < 0)
		goto out;

	/* 真正的建立netlink sock的函数 */
	err = __netlink_create(net, sock, cb_mutex, protocol);
	if (err < 0)
		goto out_module;

	local_bh_disable();
	sock_prot_inuse_add(net, &netlink_proto, 1);
	local_bh_enable();

	nlk = nlk_sk(sock->sk);
	nlk->module = module;
	nlk->netlink_bind = bind;
out:
	return err;

out_module:
	module_put(module);
	goto out;
}

/*
在close(2)时调用
*/
static int netlink_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk;

	if (!sk)
		return 0;

	/* 将套接口sk从系统sk链表和绑定链表中断开 */
	netlink_remove(sk);
	/* 设置sk状态为SOCK_DEAD, 断开sock和sk的互指 */
	sock_orphan(sk);
	nlk = nlk_sk(sk);

	/*
	 * OK. Socket is unlinked, any packets that arrive now
	 * will be purged.
	 */

	sock->sk = NULL;
	/* 唤醒所有等待队列 */
	wake_up_interruptible_all(&nlk->wait);

	skb_queue_purge(&sk->sk_write_queue);

	if (nlk->pid) {
		/* 发送释放通知 */
		struct netlink_notify n = {
						.net = sock_net(sk),
						.protocol = sk->sk_protocol,
						.pid = nlk->pid,
					  };
		atomic_notifier_call_chain(&netlink_chain,
				NETLINK_URELEASE, &n);
	}

	/* 减少模块计数 */
	module_put(nlk->module);

	/* 相当于加锁 */
	netlink_table_grab();
	if (netlink_is_kernel(sk)) {
		BUG_ON(nl_table[sk->sk_protocol].registered == 0);
		if (--nl_table[sk->sk_protocol].registered == 0) {
			/* 释放内核中的netlink服务器端 */
			kfree(nl_table[sk->sk_protocol].listeners);
			nl_table[sk->sk_protocol].module = NULL;
			nl_table[sk->sk_protocol].registered = 0;
		}
	} else if (nlk->subscriptions) {
		netlink_update_listeners(sk);
	}

	/* 相当于解锁 */
	netlink_table_ungrab();

	/* 释放该netlink sock的多播组 */
	kfree(nlk->groups);
	nlk->groups = NULL;

	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), &netlink_proto, -1);
	local_bh_enable();
	/* 释放sock */
	sock_put(sk);
	return 0;
}

/*
未指定pid时的自动绑定
实际是选一个没用过的pid后再进行插入操作
*/
static int netlink_autobind(struct socket *sock)
{
	/* 从socket找到sock */
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	/* netlink相应协议的HASH结构 */
	struct nl_pid_hash *hash = &nl_table[sk->sk_protocol].hash;
	struct hlist_head *head;
	struct sock *osk;
	struct hlist_node *node;
	/* pid取为当前进程的组ID */
	s32 pid = task_tgid_vnr(current);
	int err;
	/* 有符号32位数，静态变量 */
	static s32 rover = -4097;

retry:
	cond_resched();
	netlink_table_grab();
	/* 找合适的HASH链表头 */
	head = nl_pid_hashfn(hash, pid);
	sk_for_each(osk, node, head) {
		if (!net_eq(sock_net(osk), net))
			continue;
		/* 查找链表中是否已经有该pid */
		if (nlk_sk(osk)->pid == pid) {
			/* 存在, 则更新pid, 重新检查, 注意这时的pid是个负数 */
			/* Bind collision, search negative pid values. */
			pid = rover--;
			if (rover > -4097)
				rover = -4097;
			netlink_table_ungrab();
			goto retry;
		}
	}
	netlink_table_ungrab();

	/* 此时的pid是一个负数转换为无符号32位数, 将是一个非常大的数
	   执行正常的pid插入
	*/
	err = netlink_insert(sk, net, pid);
	if (err == -EADDRINUSE)
		goto retry;

	/* If 2 threads race to autobind, that is fine.  */
	if (err == -EBUSY)
		err = 0;

	return err;
}

static inline int netlink_capable(const struct socket *sock, unsigned int flag)
{
	return (nl_table[sock->sk->sk_protocol].nl_nonroot & flag) ||
	       capable(CAP_NET_ADMIN);
}

/*
更新subscriotions
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
绑定通常是针对服务端
*/
static int netlink_bind(struct socket *sock, struct sockaddr *addr,
			int addr_len)
{
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *nladdr = (struct sockaddr_nl *)addr;
	int err;

	/* 检查一下地址的协议族是否为AF_NETLINK */
	if (nladdr->nl_family != AF_NETLINK)
		return -EINVAL;

	/* Only superuser is allowed to listen multicasts */
	if (nladdr->nl_groups) {
		/* 指定了多播组, 这是需要root权限 */
		if (!netlink_capable(sock, NL_NONROOT_RECV))
			return -EPERM;
		/* 分配多播组空间 */
		err = netlink_realloc_groups(sk);
		if (err)
			return err;
	}

	/* 如果sock的pid非0, 检查是否匹配在nladdr地址结构中指定的pid */
	if (nlk->pid) {
		if (nladdr->nl_pid != nlk->pid)
			return -EINVAL;
	} else {
	/* sock的pid为0, 根据nladdr是否指定pid来执行插入或绑定 */
		err = nladdr->nl_pid ?
			netlink_insert(sk, net, nladdr->nl_pid) :
			netlink_autobind(sock);
		if (err)
			return err;
	}

	/* 非多播情况时就可以返回成功了 */
	if (!nladdr->nl_groups && (nlk->groups == NULL || !(u32)nlk->groups[0]))
		return 0;

	netlink_table_grab();
	/* 多播情况下更新sock参数 */
	netlink_update_subscriptions(sk, nlk->subscriptions +
					 hweight32(nladdr->nl_groups) -
					 hweight32(nlk->groups[0]));
	nlk->groups[0] = (nlk->groups[0] & ~0xffffffffUL) | nladdr->nl_groups;
	netlink_update_listeners(sk);
	netlink_table_ungrab();

	if (nlk->netlink_bind && nlk->groups[0]) {
		int i;

		for (i=0; i<nlk->ngroups; i++) {
			if (test_bit(i, nlk->groups))
				nlk->netlink_bind(i);
		}
	}

	return 0;
}

/*
连接通常是针对客户端连接服务器
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

	/* 目的地址协议族为AF_UNSPEC(未指定), 简单返回成功 */
	if (addr->sa_family == AF_UNSPEC) {
		sk->sk_state	= NETLINK_UNCONNECTED;
		nlk->dst_pid	= 0;
		nlk->dst_group  = 0;
		return 0;
	}
	/* 限制目的地址协议族类型为AF_NETLINK */
	if (addr->sa_family != AF_NETLINK)
		return -EINVAL;

	/* Only superuser is allowed to send multicasts */
	/* 只有ROOT权限才能多播 */
	if (nladdr->nl_groups && !netlink_capable(sock, NL_NONROOT_SEND))
		return -EPERM;

	/* 没指定pid的话自动绑定一个pid */
	if (!nlk->pid)
		err = netlink_autobind(sock);

	/* 已经指定了pid或者自动绑定成功时设置sock的对方参数, 状态为连接成功 */
	if (err == 0) {
		sk->sk_state	= NETLINK_CONNECTED;
		nlk->dst_pid 	= nladdr->nl_pid;
		nlk->dst_group  = ffs(nladdr->nl_groups);
	}

	return err;
}

/*
填充sockaddr_nl结构中的数据
*/
static int netlink_getname(struct socket *sock, struct sockaddr *addr,
			   int *addr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_nl *, nladdr, addr);

	/* 协议族 */
	nladdr->nl_family = AF_NETLINK;
	nladdr->nl_pad = 0;
	*addr_len = sizeof(*nladdr);

	/* 对方sock的pid和groups */
	if (peer) {
		nladdr->nl_pid = nlk->dst_pid;
		nladdr->nl_groups = netlink_group_mask(nlk->dst_group);
	} else {
	/* 自己sock的pid和groups */
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
注意这个是内核全局函数, 非static
*/
int netlink_attachskb(struct sock *sk, struct sk_buff *skb,
		      long *timeo, struct sock *ssk)
{
	struct netlink_sock *nlk;

	nlk = nlk_sk(sk);

	/* 检查接收缓存大小是否足够, 不够的话阻塞等待直到出错或条件满足 */
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    test_bit(0, &nlk->state)) {
		/* 声明当前进程的等待队列 */
		DECLARE_WAITQUEUE(wait, current);
		if (!*timeo) {
			if (!ssk || netlink_is_kernel(ssk))
				netlink_overrun(sk);
			sock_put(sk);
			kfree_skb(skb);
			return -EAGAIN;
		}

		/* 设置当前进程状态为可中断的 */
		__set_current_state(TASK_INTERRUPTIBLE);
		/* 将sock挂接到等待队列 */
		add_wait_queue(&nlk->wait, &wait);

		/* 空间不够的话阻塞, timeo为阻塞超时 */
		if ((atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
		     test_bit(0, &nlk->state)) &&
		    !sock_flag(sk, SOCK_DEAD))
			*timeo = schedule_timeout(*timeo);

		/* 进程状态运行 */
		__set_current_state(TASK_RUNNING);
		/* 删除等待队列 */
		remove_wait_queue(&nlk->wait, &wait);
		sock_put(sk);

		/* 阻塞是通过超时解开的,而不是空间条件符合解开, 属于错误状态 */
		if (signal_pending(current)) {
			kfree_skb(skb);
			return sock_intr_errno(*timeo);
		}
		/* 返回1, 重新选sock */
		return 1;
	}
	/* 条件满足, 直接将skb的所有者设为该netlink sock */
	skb_set_owner_r(skb, sk);
	return 0;
}

static int __netlink_sendskb(struct sock *sk, struct sk_buff *skb)
{
	int len = skb->len;

	/* 将skb添加到接收队列末尾 */
	skb_queue_tail(&sk->sk_receive_queue, skb);
	/* 调用netlink sock的sk_data_ready函数处理 */
	sk->sk_data_ready(sk, len);
	return len;
}

/*
注意这个是内核全局函数, 非static
*/

int netlink_sendskb(struct sock *sk, struct sk_buff *skb)
{
	int len = __netlink_sendskb(sk, skb);

	sock_put(sk);
	return len;
}

void netlink_detachskb(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	sock_put(sk);
}

static struct sk_buff *netlink_trim(struct sk_buff *skb, gfp_t allocation)
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
		consume_skb(skb);
		skb = nskb;
	}

	if (!pskb_expand_head(skb, 0, -delta, allocation))
		skb->truesize -= delta;

	return skb;
}

static void netlink_rcv_wake(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (skb_queue_empty(&sk->sk_receive_queue))
		clear_bit(0, &nlk->state);
	if (!test_bit(0, &nlk->state))
		wake_up_interruptible(&nlk->wait);
}

static int netlink_unicast_kernel(struct sock *sk, struct sk_buff *skb)
{
	int ret;
	struct netlink_sock *nlk = nlk_sk(sk);

	ret = -ECONNREFUSED;
	if (nlk->netlink_rcv != NULL) {
		ret = skb->len;
		skb_set_owner_r(skb, sk);
		nlk->netlink_rcv(skb);
		consume_skb(skb);
	} else {
		kfree_skb(skb);
	}
	sock_put(sk);
	return ret;
}

/*
netlink单播
@ssk	: netlink_kernel_create()函数返回的netlink socket
@skb	: skb->data指向需要发送的netlink消息体
@pid	: 接收程序的pid(不一定是进程号，可用是其他唯一标识)
@noblock: 表明当接收缓冲区不可用时是否应该阻塞还是立即返回一个失败信息
*/
int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 pid, int nonblock)
{
	struct sock *sk;
	int err;
	long timeo;

	/* 调整skb大小 */
	skb = netlink_trim(skb, gfp_any());

	/* 获取超时时间 */
	timeo = sock_sndtimeo(ssk, nonblock);
retry:
	/* ssk是服务器端的sock, 然后根据pid找到客户端的sock */
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

	/* 将数据包附着在客户端sock上 */
	err = netlink_attachskb(sk, skb, &timeo, ssk);
	if (err == 1)
		goto retry;
	if (err)
		return err;

	/* 发送netlink数据包 */
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

static int netlink_broadcast_deliver(struct sock *sk, struct sk_buff *skb)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	/* 发送缓冲中要有足够空间 */
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf &&
	    !test_bit(0, &nlk->state)) {
		skb_set_owner_r(skb, sk);
		__netlink_sendskb(sk, skb);
		return atomic_read(&sk->sk_rmem_alloc) > (sk->sk_rcvbuf >> 1);
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
单一广播
*/
static int do_one_broadcast(struct sock *sk,
				   struct netlink_broadcast_data *p)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	int val;

	if (p->exclude_sk == sk)
		goto out;

	/* 检查pid和组是否合法 */
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
			/* 克隆skb */
			p->skb2 = skb_clone(p->skb, p->allocation);
		} else {
			/* 此时skb不会为NULL的 */
			p->skb2 = skb_get(p->skb);
			/*
			 * skb ownership may have been set when
			 * delivered to a previous socket.
			 */
			skb_orphan(p->skb2);
		}
	}
	/* 如果还是为NULL必然是克隆或赋值失败 */
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
	/* 否则发送skb2 */
	} else if ((val = netlink_broadcast_deliver(sk, p->skb2)) < 0) {
		netlink_overrun(sk);
		if (nlk->flags & NETLINK_BROADCAST_SEND_ERROR)
			p->delivery_failure = 1;
	/* 数据正常发送 */
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
netlink广播, 发送到组内的全部sock

group的值是接收消息的各个组的比特位进行与运算的结果
allocation是内核内存的申请类型。
通常情况下在中断上下文使用GFP_ATOMIC,否则使用GFP_KERNEL。
这是由于发送多播消息时，API可能需要申请一个或者多个socket缓冲区并进行拷贝所引起的。
*/
int netlink_broadcast_filtered(struct sock *ssk, struct sk_buff *skb, u32 pid,
	u32 group, gfp_t allocation,
	int (*filter)(struct sock *dsk, struct sk_buff *skb, void *data),
	void *filter_data)
{
	struct net *net = sock_net(ssk);
	/* netlink广播数据结构信息 */
	struct netlink_broadcast_data info;
	struct hlist_node *node;
	struct sock *sk;

	/* 调整skb空间 */
	skb = netlink_trim(skb, allocation);

	/* 填充info结构基本参数 */
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

	/* 遍历多播链表, 分别对每个sock进行单播 */
	sk_for_each_bound(sk, node, &nl_table[ssk->sk_protocol].mc_list)
		do_one_broadcast(sk, &info);

	consume_skb(skb);

	netlink_unlock_table();

	if (info.delivery_failure) {
		kfree_skb(info.skb2);
		return -ENOBUFS;
	}
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

static int do_one_set_err(struct sock *sk, struct netlink_set_err_data *p)
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
设置netlink sock的各种控制参数
*/
static int netlink_setsockopt(struct socket *sock, int level, int optname,
			      char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	unsigned int val = 0;
	int err;

	/* sock层次要为SOL_NETLINK */
	if (level != SOL_NETLINK)
		return -ENOPROTOOPT;

	/* 读取用户空间的设置信息 */
	if (optlen >= sizeof(int) &&
	    get_user(val, (unsigned int __user *)optval))
		return -EFAULT;

	switch (optname) {
	/* 处理NETLINK_RECV_PKTINFO标志, 非0设置, 0为清除 */
	case NETLINK_PKTINFO:
		if (val)
			nlk->flags |= NETLINK_RECV_PKTINFO;
		else
			nlk->flags &= ~NETLINK_RECV_PKTINFO;
		err = 0;
		break;
	/* 加入或退出多播组 */
	case NETLINK_ADD_MEMBERSHIP:
	case NETLINK_DROP_MEMBERSHIP: {
		/* 检查权限 */
		if (!netlink_capable(sock, NL_NONROOT_RECV))
			return -EPERM;
		/* 如果当前sock的多播组为空时分配空间 */
		err = netlink_realloc_groups(sk);
		if (err)
			return err;
		/* 检查数据范围 */
		if (!val || val - 1 >= nlk->ngroups)
			return -EINVAL;
		netlink_table_grab();
		netlink_update_socket_mc(nlk, val,
					 optname == NETLINK_ADD_MEMBERSHIP);
		netlink_table_ungrab();

		if (nlk->netlink_bind)
			nlk->netlink_bind(val);

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
		} else {
			nlk->flags &= ~NETLINK_RECV_NO_ENOBUFS;
		}
		err = 0;
		break;
	default:
		err = -ENOPROTOOPT;
	}
	return err;
}

/*
获取netlink sock的各种控制参数
*/
static int netlink_getsockopt(struct socket *sock, int level, int optname,
			      char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	int len, val, err;

	/* sock层次要为SOL_NETLINK */
	if (level != SOL_NETLINK)
		return -ENOPROTOOPT;

	/* 读取用户空间的查询信息 */
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	/* 选项信息PKTINFO */
	case NETLINK_PKTINFO:
		if (len < sizeof(int))
			return -EINVAL;
		len = sizeof(int);
		/* 看sock标志是否有NETLINK_RECV_PKTINFO返回1或0 */
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
从用户层发送数据到内核, 内核的sock是接收方
*/
static int netlink_sendmsg(struct kiocb *kiocb, struct socket *sock,
			   struct msghdr *msg, size_t len)
{
	/* sock的IO控制块 */
	struct sock_iocb *siocb = kiocb_to_siocb(kiocb);
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *addr = msg->msg_name;
	u32 dst_pid;
	u32 dst_group;
	struct sk_buff *skb;
	int err;
	struct scm_cookie scm;

	/* 设置了OOB(out of band)标志, 在TCP中支持,netlink不支持 */
	if (msg->msg_flags&MSG_OOB)
		return -EOPNOTSUPP;

	if (NULL == siocb->scm)
		siocb->scm = &scm;

	err = scm_send(sock, msg, siocb->scm, true);
	if (err < 0)
		return err;

	/* 确定目的pid和组 */
	if (msg->msg_namelen) {
		err = -EINVAL;
		if (addr->nl_family != AF_NETLINK)
			goto out;
		dst_pid = addr->nl_pid;
		dst_group = ffs(addr->nl_groups);
		err =  -EPERM;
		if ((dst_group || dst_pid) &&
		    !netlink_capable(sock, NL_NONROOT_SEND))
			goto out;
	} else {
		dst_pid = nlk->dst_pid;
		dst_group = nlk->dst_group;
	}

	/* 如果sock的pid为0, 自动绑定一个pid */
	if (!nlk->pid) {
		err = netlink_autobind(sock);
		if (err)
			goto out;
	}

	err = -EMSGSIZE;
	/* 消息长度太大 */
	if (len > sk->sk_sndbuf - 32)
		goto out;
	err = -ENOBUFS;
	/* 新生成一个skb数据包 */
	skb = alloc_skb(len, GFP_KERNEL);
	if (skb == NULL)
		goto out;

	/* 设置该skb的netlink控制块参数 */
	NETLINK_CB(skb).pid	= nlk->pid;
	NETLINK_CB(skb).dst_group = dst_group;
	memcpy(NETLINK_CREDS(skb), &siocb->scm->creds, sizeof(struct ucred));

	err = -EFAULT;
	/* 将发送的信息拷贝到skb的存储区 */
	if (memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len)) {
		kfree_skb(skb);
		goto out;
	}

	err = security_netlink_send(sk, skb);
	if (err) {
		kfree_skb(skb);
		goto out;
	}

	/* 如果是多播的,先进行广播发送 */
	if (dst_group) {
		atomic_inc(&skb->users);
		netlink_broadcast(sk, skb, dst_pid, dst_group, GFP_KERNEL);
	}
	/* 单播发送 */
	err = netlink_unicast(sk, skb, dst_pid, msg->msg_flags&MSG_DONTWAIT);

out:
	scm_destroy(siocb->scm);
	return err;
}

/*
数据是内核传向用户空间的
*/
static int netlink_recvmsg(struct kiocb *kiocb, struct socket *sock,
			   struct msghdr *msg, size_t len,
			   int flags)
{
	/* sock的IO控制块 */
	struct sock_iocb *siocb = kiocb_to_siocb(kiocb);
	struct scm_cookie scm;
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	/* 是否是非阻塞的 */
	int noblock = flags&MSG_DONTWAIT;
	size_t copied;
	struct sk_buff *skb, *data_skb;
	int err, ret;

	/* 不能带OOB标志 */
	if (flags&MSG_OOB)
		return -EOPNOTSUPP;

	copied = 0;

	/* 接收一个数据包 */
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

	/* 收到的实际数据长度 */
	copied = data_skb->len;
	/* 接收缓冲小于数据长度, 设置数据裁剪标志 */
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	skb_reset_transport_header(data_skb);
	/* 将skb的数据拷贝到接收缓冲区 */
	err = skb_copy_datagram_iovec(data_skb, 0, msg->msg_iov, copied);

	/* sock有效, 填写nl sock的数据 */
	if (msg->msg_name) {
		struct sockaddr_nl *addr = (struct sockaddr_nl *)msg->msg_name;
		addr->nl_family = AF_NETLINK;
		addr->nl_pad    = 0;
		addr->nl_pid	= NETLINK_CB(skb).pid;
		addr->nl_groups	= netlink_group_mask(NETLINK_CB(skb).dst_group);
		msg->msg_namelen = sizeof(*addr);
	}

	/* 接收数据包信息标志, 将消息头拷贝到用户空间 */
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
	/* 接收唤醒 */
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
以前也介绍过另一个建立netlink sock的函数netlink_kernel_create, 
一般是在netlink的各种协议类型模块初始化时调用的, 
而不是socket系统调用时调用的, 每个netlink协议初始化是只调用一次, 
建立一个内核中的netlink接口, 相当于服务器, 其中也调用了__netlink_create()函数

@unit	: netlink协议类型 如:NETLINK_ROUTE
@input	: 函数指针input,是netlink socket在收到消息时调用的处理消息的回调函数指针

netlink子协议使用netink_kernel_create()把其信息填充到对应下标的nl_table中
*/
struct sock *
netlink_kernel_create(struct net *net, int unit,
		      struct module *module,
		      struct netlink_kernel_cfg *cfg)
{
	struct socket *sock;
	struct sock *sk;
	struct netlink_sock *nlk;
	struct listeners *listeners = NULL;
	struct mutex *cb_mutex = cfg ? cfg->cb_mutex : NULL;
	unsigned int groups;

	BUG_ON(!nl_table);

	if (unit < 0 || unit >= MAX_LINKS)
		return NULL;

	/* 这里的lite表示只是简单分配一个socket,没有真正初始化 */
	if (sock_create_lite(PF_NETLINK, SOCK_DGRAM, unit, &sock))
		return NULL;

	/*
	 * We have to just have a reference on the net from sk, but don't
	 * get_net it. Besides, we cannot get and then put the net here.
	 * So we create one inside init_net and the move it to net.
	 */

	/* 用这个lite sock再建立netlink sock */
	if (__netlink_create(&init_net, sock, cb_mutex, unit) < 0)
		goto out_sock_release_nosk;

	sk = sock->sk;
	sk_change_net(sk, net);

	if (!cfg || cfg->groups < 32)
		groups = 32;
	else
		groups = cfg->groups;

	/* listeners是个位图对应groups中每个元素 */
	listeners = kzalloc(sizeof(*listeners) + NLGRPSZ(groups), GFP_KERNEL);
	if (!listeners)
		goto out_sock_release;

	/* 重新定义了sk_data_ready函数 */
	sk->sk_data_ready = netlink_data_ready;
	if (cfg && cfg->input)
		nlk_sk(sk)->netlink_rcv = cfg->input;

	if (netlink_insert(sk, net, 0))
		goto out_sock_release;

	nlk = nlk_sk(sk);
	nlk->flags |= NETLINK_KERNEL_SOCKET;

	/* 注册到相应unit的netlink协议表中
	   实际上nl_table是一个指针，分配空间后，这里便当成数组来访问
	*/
	netlink_table_grab();
	if (!nl_table[unit].registered) {
		nl_table[unit].groups = groups;
		rcu_assign_pointer(nl_table[unit].listeners, listeners);
		nl_table[unit].cb_mutex = cb_mutex;
		nl_table[unit].module = module;
		nl_table[unit].bind = cfg ? cfg->bind : NULL;
		/* 该标志表示该项被登记 */
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

/*
将nlmsghdr消息头信息封装进skb
*/
struct nlmsghdr *
__nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int len, int flags)
{
	struct nlmsghdr *nlh;
	int size = NLMSG_LENGTH(len);

	nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;
	if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
		memset(NLMSG_DATA(nlh) + len, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}
EXPORT_SYMBOL(__nlmsg_put);

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
		else
			__netlink_sendskb(sk, skb);
		return 0;
	}

	nlh = nlmsg_put_answer(skb, cb, NLMSG_DONE, sizeof(len), NLM_F_MULTI);
	if (!nlh)
		goto errout_skb;

	nl_dump_check_consistent(cb, nlh);

	memcpy(nlmsg_data(nlh), &len, sizeof(len));

	if (sk_filter(sk, skb))
		kfree_skb(skb);
	else
		__netlink_sendskb(sk, skb);

	if (cb->done)
		cb->done(cb);
	nlk->cb = NULL;
	mutex_unlock(nlk->cb_mutex);

	netlink_consume_callback(cb);
	return 0;

errout_skb:
	mutex_unlock(nlk->cb_mutex);
	kfree_skb(skb);
	return err;
}

int netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
		       const struct nlmsghdr *nlh,
		       struct netlink_dump_control *control)
{
	struct netlink_callback *cb;
	struct sock *sk;
	struct netlink_sock *nlk;
	int ret;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (cb == NULL)
		return -ENOBUFS;

	cb->dump = control->dump;
	cb->done = control->done;
	cb->nlh = nlh;
	cb->data = control->data;
	cb->min_dump_alloc = control->min_dump_alloc;
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
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq,
			 "sk       Eth Pid    Groups   "
			 "Rmem     Wmem     Dump     Locks     Drops     Inode\n");
	} else {
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
netlink协议族操作, 在用户程序使用socket打开netlink类型的socket时调用,
相应的create函数在__sock_create(net/socket.c)函数中调用
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
	nl_table[NETLINK_USERSOCK].nl_nonroot = NL_NONROOT_SEND;

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
	/* 注册netlink_proto结构
	   最后一个参数为0, 表示不进行slab的分配, 
	   只是简单的将netlink_proto结构挂接到系统的网络协议链表中,
	   这个结构最主要是告知了netlink sock结构的大小
	*/
	int err = proto_register(&netlink_proto, 0);

	if (err != 0)
		goto out;

	BUILD_BUG_ON(sizeof(struct netlink_skb_parms) > sizeof(dummy_skb->cb));

	/* 分配MAX_LINKS个netlink表结构 */
	nl_table = kcalloc(MAX_LINKS, sizeof(*nl_table), GFP_KERNEL);
	if (!nl_table)
		goto panic;

	/* 以下根据系统内存大小计算最大链表元素个数
	   PAGE_SHIFT是每页大小的2的幂,对i386是12,即每页是4K,2^12
	   对于128M内存的机器,limit计算值是(128*1024) >> (21-12) = 256
	   对于64M内存的机器,limit计算值是(64*1024) >> (23-12) = 32
	*/
	if (totalram_pages >= (128 * 1024))
		limit = totalram_pages >> (21 - PAGE_SHIFT);
	else
		limit = totalram_pages >> (23 - PAGE_SHIFT);

	/* 根据limit再和PAGE_SHIFT计算总内存空间相应的幂值order */
	order = get_bitmask_order(limit) - 1 + PAGE_SHIFT;
	/* limit是最大节点数 */
	limit = (1UL << order) / sizeof(struct hlist_head);
	/* order是limit对于2的幂数 */
	order = get_bitmask_order(min(limit, (unsigned long)UINT_MAX)) - 1;

	for (i = 0; i < MAX_LINKS; i++) {
		struct nl_pid_hash *hash = &nl_table[i].hash;

		/* 为netlink的每个子协议类型分配HASH表链表头 */
		hash->table = nl_pid_hash_zalloc(1 * sizeof(*hash->table));
		if (!hash->table) {
			while (i-- > 0)
				nl_pid_hash_free(nl_table[i].hash.table,
						 1 * sizeof(*hash->table));
			kfree(nl_table);
			goto panic;
		}
		/* 最大幂数 */
		hash->max_shift = order;
		hash->shift = 0;
		hash->mask = 0;
		hash->rehash_time = jiffies;
	}

	netlink_add_usersock_entry();

	/* 注册netlink协议族的的操作结构 */
	sock_register(&netlink_family_ops);
	register_pernet_subsys(&netlink_net_ops);
	/* The netlink device handler may be needed early. */
	/* 初始化路由netlink */
	rtnetlink_init();
out:
	return err;
panic:
	panic("netlink_init: Cannot allocate nl_table\n");
}

core_initcall(netlink_proto_init);
