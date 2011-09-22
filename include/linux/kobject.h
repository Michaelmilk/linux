/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kobject_ns.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			32	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

/* path to the userspace helper executed on an event */
extern char uevent_helper[];

/* counter to tag the uevent, read only except for the kobject core */
extern u64 uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	KOBJ_ADD,
	KOBJ_REMOVE,
	KOBJ_CHANGE,
	KOBJ_MOVE,
	KOBJ_ONLINE,
	KOBJ_OFFLINE,
	KOBJ_MAX
};

/*
kobject通常是嵌入到其他结构中的，其单独意义其实并不大。
相反，那些更为重要的结构体才真正需要用到kobject结构。比如struct cdev。

当kobject被嵌入到其他结构体中时，该结构体便拥有了kobject提供的标准功能。
更重要的一点是，嵌入kobject结构体可以成为对象层次架构中的一部分。
比如cdev结构体就可以通过其父进程指针cdev->kobj->parent
和链表cdev->kobj->entry来插入到对象层次结构中。

kobject代表设备驱动模型中一个基本对象，类似于 MFC 中最顶层的基类 CObject。
每个kobject都对应于sysfs中的一个目录。
上层结构例如 device,device_driver,bus_type都嵌入了一个 kobject，
这相当于面向对象程序设计语言中的继承机制
*/
struct kobject {
	/* kobject名称 */
	const char		*name;
	/* 用于链入所属kset的list链表 */
	struct list_head	entry;
	/* parent指针指向kobject的父对象。
       因此，kobject就会在内核中构造一个对象层次结构，
       并且可以将对各对象间的关系表现出来，就如你看到的，
       这便是sysfs的真正面目：一个用户空间的文件系统，
       用来表示内核中kobject对象的层次结构。

       某对象的kobj->parent指针与其kobj->kset->kobj应该是一致的
       kobject_add_internal()函数内赋值 */
	struct kobject		*parent;
	/* 所属kset，用于实现层次 */
	struct kset		*kset;
	/* 所属ktype，指向对象的类型 */
	struct kobj_type	*ktype;
	/* sysfs中的目录项，会在sysfs_create_dir()内赋值 */
	struct sysfs_dirent	*sd;
	/* 引用计数
	   所有内嵌了kobject结构的容器结构的引用计数也由此字段来记录 */
	struct kref		kref;
	unsigned int state_initialized:1;
	unsigned int state_in_sysfs:1;
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;
};

extern int kobject_set_name(struct kobject *kobj, const char *name, ...)
			    __attribute__((format(printf, 2, 3)));
extern int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

extern void kobject_init(struct kobject *kobj, struct kobj_type *ktype);
extern int __must_check kobject_add(struct kobject *kobj,
				    struct kobject *parent,
				    const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
extern int __must_check kobject_init_and_add(struct kobject *kobj,
					     struct kobj_type *ktype,
					     struct kobject *parent,
					     const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

extern void kobject_del(struct kobject *kobj);

extern struct kobject * __must_check kobject_create(void);
extern struct kobject * __must_check kobject_create_and_add(const char *name,
						struct kobject *parent);

extern int __must_check kobject_rename(struct kobject *, const char *new_name);
extern int __must_check kobject_move(struct kobject *, struct kobject *);

extern struct kobject *kobject_get(struct kobject *kobj);
extern void kobject_put(struct kobject *kobj);

extern char *kobject_get_path(struct kobject *kobj, gfp_t flag);

/*
kobj_type是为了描述一族kobject所具有的普遍特性。
因此，不再需要每个kobject都分别定义自己的特性，
而是将这些普遍的特性在kobj_type结构体中一次定义，
然后所有“同类”的kobject都能共享一样的特性。

release指针指向在kobject引用计数减至0时要被调用的析构函数。
该函数负责释放所有kobject使用的内存和其它相关清理工作。

sysfs_ops变量指向sysfs_ops结构体。该结构体描述了sysfs文件读写时的特性。

default_attrs指向一个attribute结构体数组。
这些结构体定义了该kobject相关的默认属性。
属性给定了对象的特征，如果该kobject被导出到sysfs中，
那么这些属性都将相应的作为文件而导出。

kobj_type是kobject所属的类型，定义了某种类型的kobejct的公共的属性和操作
*/
struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
	const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);
};

struct kobj_uevent_env {
	char *envp[UEVENT_NUM_ENVP];
	int envp_idx;
	char buf[UEVENT_BUFFER_SIZE];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(struct kset *kset, struct kobject *kobj);
	const char *(* const name)(struct kset *kset, struct kobject *kobj);
	int (* const uevent)(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env);
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};

extern const struct sysfs_ops kobj_sysfs_ops;

struct sock;

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
/*
kset是kobject对象的集合体。
把它看成一个容器，可将所有相关的kobject对象，
比如“全部的块设备”置于同一位置。
kset把kobject集中到一个集合中
kobject的kset指针指向相应的kset集合。

kset 是一个kobject 集合（或容器） ，包含了一系列的 kobject。
需要注意的是，kset内部也嵌入了 kobject，这表明 kset 本身也是一个 kobject。

Kset 在概念上是一个集合或者叫容器。
实现了对象的层次。
所有属于一个ksets的对象(kobject)的parent都指向该ksets的kobj
同时这个对象都连接到kset 的list表上。
同时位于ksets层次之上的是subsys，在最新的内核中已经取消subsys，
因为它本质上也就是一个ksets。
Kset有一套类似kobject的操作，实现上只是进一步调用其自身kobj的相应操作，
毕竟ksets本质上也是一个kobject。

kobject通过kset组织成层次化的结构，kset是具有相同类型的kobject的集合
*/
struct kset {
	/* 连接该集合(kset)中所有的kobject对象
	   由kobject.entry链入该list为链头的链表 */
	struct list_head list;
	spinlock_t list_lock;
	/* kobj指向的kobject对象代表了该集合的基类 */
	struct kobject kobj;
	/* 热插拔操作 */
	const struct kset_uevent_ops *uevent_ops;
};

extern void kset_init(struct kset *kset);
extern int __must_check kset_register(struct kset *kset);
extern void kset_unregister(struct kset *kset);
extern struct kset * __must_check kset_create_and_add(const char *name,
						const struct kset_uevent_ops *u,
						struct kobject *parent_kobj);

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

/*
实际上是增加kset->kobj->kref的引用计数
*/
static inline struct kset *kset_get(struct kset *k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type *get_ktype(struct kobject *kobj)
{
	return kobj->ktype;
}

extern struct kobject *kset_find_obj(struct kset *, const char *);
extern struct kobject *kset_find_obj_hinted(struct kset *, const char *,
						struct kobject *);

/* The global /sys/kernel/ kobject for people to chain off of */
extern struct kobject *kernel_kobj;
/* The global /sys/kernel/mm/ kobject for people to chain off of */
extern struct kobject *mm_kobj;
/* The global /sys/hypervisor/ kobject for people to chain off of */
extern struct kobject *hypervisor_kobj;
/* The global /sys/power/ kobject for people to chain off of */
extern struct kobject *power_kobj;
/* The global /sys/firmware/ kobject for people to chain off of */
extern struct kobject *firmware_kobj;

#if defined(CONFIG_HOTPLUG)
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);

int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
	__attribute__((format (printf, 2, 3)));

int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type);
#else
static inline int kobject_uevent(struct kobject *kobj,
				 enum kobject_action action)
{ return 0; }
static inline int kobject_uevent_env(struct kobject *kobj,
				      enum kobject_action action,
				      char *envp[])
{ return 0; }

static inline __attribute__((format(printf, 2, 3)))
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...)
{ return 0; }

static inline int kobject_action_type(const char *buf, size_t count,
				      enum kobject_action *type)
{ return -EINVAL; }
#endif

#endif /* _KOBJECT_H_ */
