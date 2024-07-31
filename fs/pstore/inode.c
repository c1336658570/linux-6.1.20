// SPDX-License-Identifier: GPL-2.0-only
/*
 * Persistent Storage - ramfs parts.
 *
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 */

// pstore 文件系统的注册与操作

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/ramfs.h>
#include <linux/parser.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/pstore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "internal.h"

/* 定义 pstore 记录名称的最大长度为 64 字符 */
#define	PSTORE_NAMELEN	64

/* 定义用于记录列表的互斥锁 */
static DEFINE_MUTEX(records_list_lock);
/* 初始化记录列表的头节点 */
static LIST_HEAD(records_list);

/* 定义用于保护 pstore 的超级块的互斥锁 */
static DEFINE_MUTEX(pstore_sb_lock);
/* 定义指向 pstore 超级块的指针 */
static struct super_block *pstore_sb;

/* pstore 私有数据结构，用于管理 pstore 记录 */
struct pstore_private {
	struct list_head list;  // 链表节点
	struct dentry *dentry;  // 目录项指针
	struct pstore_record *record;  // 指向 pstore 记录的指针
	size_t total_size;  // 记录的总大小
};

/* pstore 函数跟踪序列数据结构，用于管理函数跟踪记录的数据 */
struct pstore_ftrace_seq_data {
	const void *ptr;  // 指向数据的指针
	size_t off;  // 数据偏移量
	size_t size;  // 数据大小
};

/* 定义一个宏，指定 pstore 函数跟踪记录的大小 */
#define REC_SIZE sizeof(struct pstore_ftrace_record)

/* 释放 pstore 私有数据的函数 */
static void free_pstore_private(struct pstore_private *private)
{
	if (!private)
		return;	// 如果 private 为空，直接返回
	if (private->record) {
		kfree(private->record->buf);  // 释放记录缓冲区
		kfree(private->record->priv);  // 释放记录的私有数据
		kfree(private->record);  // 释放记录本身
	}
	kfree(private);	// 释放私有数据结构本身
}

/* 开始序列文件迭代的函数 */
static void *pstore_ftrace_seq_start(struct seq_file *s, loff_t *pos)
{
	struct pstore_private *ps = s->private;	// 从序列文件结构中获取私有数据
	struct pstore_ftrace_seq_data *data;

	/* 为存储序列数据分配内存 */
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)	// 如果内存分配失败，返回 NULL
		return NULL;

	/* 计算记录数据的起始偏移 */
	data->off = ps->total_size % REC_SIZE;	// 总大小与记录大小求余，计算开始位置的偏移
	data->off += *pos * REC_SIZE;		// 根据位置参数计算偏移
	// 如果计算的偏移超出了总大小
	if (data->off + REC_SIZE > ps->total_size) {
		kfree(data);	// 释放之前分配的内存
		return NULL;	// 返回 NULL，表示没有数据或越界
	}

	return data;		// 返回数据指针，用于迭代

}

/* 停止序列文件迭代的函数 */
static void pstore_ftrace_seq_stop(struct seq_file *s, void *v)
{
	kfree(v);		// 释放迭代过程中分配的内存
}

/* 序列文件中获取下一个元素的函数 */
static void *pstore_ftrace_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	// 从序列文件中获取私有数据
	struct pstore_private *ps = s->private;
	// 当前迭代的数据
	struct pstore_ftrace_seq_data *data = v;

	(*pos)++;		// 位置递增
	 // 数据偏移递增一个记录的大小
	data->off += REC_SIZE;
	// 检查是否超出总大小
	if (data->off + REC_SIZE > ps->total_size)
		return NULL;	// 超出则返回 NULL

	return data;		// 返回当前数据指针，用于下一次迭代
}

/* 序列文件中显示当前元素的函数 */
static int pstore_ftrace_seq_show(struct seq_file *s, void *v)
{
	struct pstore_private *ps = s->private;  // 从序列文件中获取私有数据
	struct pstore_ftrace_seq_data *data = v;  // 当前显示的数据
	struct pstore_ftrace_record *rec;  // 函数跟踪记录结构

	// 如果数据为空，直接返回
	if (!data)
		return 0;

	// 根据偏移获取记录
	rec = (struct pstore_ftrace_record *)(ps->record->buf + data->off);
	
	// 打印记录到序列文件中
	seq_printf(s, "CPU:%d ts:%llu %08lx  %08lx  %ps <- %pS\n",
		   pstore_ftrace_decode_cpu(rec),	// 解码 CPU 编号
		   pstore_ftrace_read_timestamp(rec),	// 读取时间戳
		   rec->ip, rec->parent_ip, (void *)rec->ip,	// 当前和父级指令指针
		   (void *)rec->parent_ip);

	return 0;		// 返回成功
}

/* 序列操作结构，定义了开始、下一项、停止和显示函数 */
static const struct seq_operations pstore_ftrace_seq_ops = {
	.start = pstore_ftrace_seq_start,  // 开始迭代函数
	.next = pstore_ftrace_seq_next,  // 获取下一个元素函数
	.stop = pstore_ftrace_seq_stop,  // 停止迭代函数
	.show = pstore_ftrace_seq_show,  // 显示当前元素函数
};

/* 读取 pstore 文件的函数 */
static ssize_t pstore_file_read(struct file *file, char __user *userbuf,
						size_t count, loff_t *ppos)
{
	// 获取文件关联的序列文件结构
	struct seq_file *sf = file->private_data;
	// 获取私有数据结构
	struct pstore_private *ps = sf->private;

	// 如果记录类型是函数跟踪
	if (ps->record->type == PSTORE_TYPE_FTRACE)
		// 使用序列文件读取函数
		return seq_read(file, userbuf, count, ppos);
	// 否则使用简单的缓冲区读取函数
	return simple_read_from_buffer(userbuf, count, ppos,
				       ps->record->buf, ps->total_size);
}

/* 打开 pstore 文件的函数 */
static int pstore_file_open(struct inode *inode, struct file *file)
{
	// 从 inode 获取私有数据
	struct pstore_private *ps = inode->i_private;
	struct seq_file *sf;
	int err;
	const struct seq_operations *sops = NULL;

	// 如果记录类型是函数跟踪
	if (ps->record->type == PSTORE_TYPE_FTRACE)
		// 使用函数跟踪的序列操作
		sops = &pstore_ftrace_seq_ops;

	// 打开一个序列文件
	err = seq_open(file, sops);
	if (err < 0)	// 如果打开失败
		return err;	// 返回错误码

	sf = file->private_data;	// 获取序列文件的私有数据
	sf->private = ps;					// 设置序列文件的私有数据

	return 0;									// 打开成功
}

/* 定位 pstore 文件的函数 */
static loff_t pstore_file_llseek(struct file *file, loff_t off, int whence)
{
	// 获取文件的私有数据
	struct seq_file *sf = file->private_data;

	// 如果存在操作
	if (sf->op)
		// 使用序列文件的定位函数
		return seq_lseek(file, off, whence);
	// 否则使用默认的定位函数
	return default_llseek(file, off, whence);
}

/* 定义 pstore 文件操作结构 */
static const struct file_operations pstore_file_operations = {
	.open		= pstore_file_open,  // 打开函数
	.read		= pstore_file_read,  // 读取函数
	.llseek		= pstore_file_llseek,  // 定位函数
	.release	= seq_release,  // 释放/关闭函数
};

/*
 * When a file is unlinked from our file system we call the
 * platform driver to erase the record from persistent store.
 */
/*
 * 当从我们的文件系统中删除一个文件时，我们调用平台驱动来从持久存储中擦除该记录。
 */
static int pstore_unlink(struct inode *dir, struct dentry *dentry)
{
	// 从目录项获取私有数据
	struct pstore_private *p = d_inode(dentry)->i_private;
	// 获取相关的 pstore 记录
	struct pstore_record *record = p->record;
	int rc = 0;	// 初始化返回码

	// 如果没有定义擦除函数
	if (!record->psi->erase)
		return -EPERM;	// 返回没有权限错误

	/* Make sure we can't race while removing this file. */
	/* 确保在删除此文件时不会有竞态发生 */
	mutex_lock(&records_list_lock);	// 锁定记录列表
	if (!list_empty(&p->list))			// 如果列表不为空
		list_del_init(&p->list);			// 从列表中删除记录
	else
		rc = -ENOENT;		// 如果列表为空，设置为找不到文件的错误
	p->dentry = NULL;	// 清除目录项指针
	mutex_unlock(&records_list_lock);	// 解锁记录列表
	if (rc)
		return rc;	// 如果有错误发生，直接返回错误码

	mutex_lock(&record->psi->read_mutex);  // 锁定读取互斥锁
	record->psi->erase(record);  // 调用擦除函数
	mutex_unlock(&record->psi->read_mutex);  // 解锁读取互斥锁

	return simple_unlink(dir, dentry);  // 调用简单的unlink处理
}

/* 当 inode 被驱逐时调用此函数 */
static void pstore_evict_inode(struct inode *inode)
{
	// 获取 inode 的私有数据
	struct pstore_private	*p = inode->i_private;

	clear_inode(inode);			// 清除 inode
	free_pstore_private(p);		// 释放私有数据
}

/* 定义 pstore 目录的 inode 操作结构 */
static const struct inode_operations pstore_dir_inode_operations = {
	.lookup		= simple_lookup,		// 简单的查找函数
	.unlink		= pstore_unlink,		// 文件删除函数
};

/*
 * 从给定的超级块中获取一个新的 inode。
 */
static struct inode *pstore_get_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);	// 从超级块 sb 创建一个新的 inode
	if (inode) {
		inode->i_ino = get_next_ino();	// 为 inode 分配一个唯一的 inode 号
		// 设置 inode 的访问、修改和状态改变时间为当前时间
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	}
	return inode;	// 返回创建的 inode
}

/* 定义了用于解析挂载选项的枚举。 */
enum {
	Opt_kmsg_bytes,	// 对应 'kmsg_bytes' 挂载选项
	Opt_err		// 对于解析错误或未知选项
};

/* 定义一个匹配表，用于将字符串选项映射到枚举值。 */
static const match_table_t tokens = {
	{Opt_kmsg_bytes, "kmsg_bytes=%u"},  // 匹配 'kmsg_bytes=%u' 格式的选项，%u 是一个占位符，用于解析一个无符号整数
	{Opt_err, NULL}                     // 用于错误处理的条目，没有对应的字符串模式
};

// 定义了一个函数 parse_options，用于解析给定的字符串中的配置选项，并根据这些选项执行相应的操作。
/* 定义函数 parse_options，用于解析字符串中的配置选项 */
static void parse_options(char *options)
{
	char		*p;  	// 用于遍历字符串的指针
	substring_t	args[MAX_OPT_ARGS];	// 存储匹配结果的数组
	int		option;	// 存储转换后的整数选项值

	/* 如果传入的选项字符串为空，直接返回 */
	if (!options)
		return;

	/* 循环处理每一个逗号分隔的片段 */
	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		/* 如果解析到的片段为空，跳过当前循环 */
		if (!*p)
			continue;

		/* 使用 match_token 函数根据 tokens 表来匹配当前片段，并获取匹配到的 token */
		token = match_token(p, tokens, args);
		switch (token) {	/* 根据匹配到的 token 执行相应的操作 */
		case Opt_kmsg_bytes:	/* 如果匹配到的是 kmsg_bytes 选项，尝试将参数转换为整数 */
			if (!match_int(&args[0], &option))
				pstore_set_kmsg_bytes(option);	// 设置 kmsg_bytes 的值
			break;
		}
	}
}

/*
 * Display the mount options in /proc/mounts.
 */
/* 在 /proc/mounts 中显示挂载选项 */
static int pstore_show_options(struct seq_file *m, struct dentry *root)
{
	/* 如果 kmsg_bytes 不是默认值，就在 seq_file 中输出这个设置 */
	if (kmsg_bytes != CONFIG_PSTORE_DEFAULT_KMSG_BYTES)
		seq_printf(m, ",kmsg_bytes=%lu", kmsg_bytes);
	return 0;	// 总是返回 0 表示成功
}

/* 文件系统重新挂载时调用的函数 */
static int pstore_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);	/* 同步文件系统 */
	parse_options(data);	/* 解析挂载时传入的选项 */

	return 0;		// 返回 0 表示重新挂载成功
}

/* 定义 pstore 文件系统操作的结构体 */
static const struct super_operations pstore_ops = {
	.statfs		= simple_statfs,	// 获取文件系统统计信息的简单实现
	.drop_inode	= generic_delete_inode,	// 通用的 inode 删除函数
	.evict_inode	= pstore_evict_inode,	// 特定于 pstore 的 inode 驱逐函数
	.remount_fs	= pstore_remount,	// 文件系统重新挂载函数
	.show_options	= pstore_show_options,	// 显示文件系统选项的函数
};

// 用于获取 pstore 文件系统的根目录项 (dentry)，同时确保在获取过程中线程安全。
// 锁定 pstore 超级块，获取根目录项
/**
 * 通过锁定超级块的互斥锁，函数防止在访问根目录项 (root) 时发生数据竞争。
 * 如果检查到后端不存在或文件系统未挂载，则直接释放锁并返回 NULL。如果一切正常，
 * 函数将继续锁定根目录项的 inode，这是因为接下来的操作可能需要修改文件系统，
 * 然后释放超级块锁。最后，函数返回根目录项，供后续操作使用。
 */
static struct dentry *psinfo_lock_root(void)
{
	struct dentry *root;

	/* 锁定 pstore_sb_lock 以防止并发访问 */
	mutex_lock(&pstore_sb_lock);
	/*
	 * Having no backend is fine -- no records appear.
	 * Not being mounted is fine -- nothing to do.
	 */
	/*
	 * 如果没有后端或文件系统未挂载，返回 NULL：
	 * - 没有后端表示没有记录将出现。
	 * - 未挂载表示没有操作需要执行。
	 */
	if (!psinfo || !pstore_sb) {
		mutex_unlock(&pstore_sb_lock);	// 释放锁
		return NULL;	// 返回 NULL 表示没有根目录项可用
	}

	root = pstore_sb->s_root;	/* 获取 pstore 文件系统的根目录项 */
	inode_lock(d_inode(root));	/* 锁定根目录项的 inode 以同步对目录的操作 */
	mutex_unlock(&pstore_sb_lock);	/* 释放 pstore 超级块锁 */

	return root;	// 返回根目录项
}

// 用于从 pstore 文件系统中删除与特定后端相关联的所有记录。它遍历一个记录列表，并为匹配的后端执行文件删除操作。
/*
 * 首先尝试锁定 pstore 文件系统的根目录项。如果获取根目录项失败，它会直接返回。
 * 成功后，它加锁保护记录列表，并遍历每个记录。对于与指定后端关联的每个记录，
 * 它会从文件系统中删除对应的文件，并从内存中清理相关的目录项。所有操作完成后，
 * 释放锁并解锁根目录项的 inode。最后，返回操作的结果。
 */
int pstore_put_backend_records(struct pstore_info *psi)
{
	struct pstore_private *pos, *tmp;  // 声明两个临时变量用于遍历记录列表
	struct dentry *root;  // 声明一个目录项指针
	int rc = 0;  // 初始化返回码为0

	/* 获取 pstore 文件系统的根目录项，确保线程安全 */
	root = psinfo_lock_root();
	/* 如果没有获取到根目录项，则直接返回 */
	if (!root)
		return 0;

	mutex_lock(&records_list_lock);	/* 锁定记录列表，防止并发修改 */
	/* 安全地遍历记录列表 */
	list_for_each_entry_safe(pos, tmp, &records_list, list) {
		/* 检查当前记录是否属于指定的后端 */
		if (pos->record->psi == psi) {
			/* 从列表中删除当前记录项 */
			list_del_init(&pos->list);
			/* 在文件系统中删除与当前记录关联的文件 */
			rc = simple_unlink(d_inode(root), pos->dentry);
			/* 如果删除操作出错，则记录警告并终止循环 */
			if (WARN_ON(rc))
				break;
			/* 从 dentry 缓存中删除目录项 */
			d_drop(pos->dentry);
			/* 释放目录项引用 */
			dput(pos->dentry);
			/* 将目录项指针置空 */
			pos->dentry = NULL;
		}
	}
	/* 解锁记录列表 */
	mutex_unlock(&records_list_lock);

	inode_unlock(d_inode(root));	/* 解锁根目录项的 inode */

	return rc;	// 返回操作结果
}

/*
 * Make a regular file in the root directory of our file system.
 * Load it up with "size" bytes of data from "buf".
 * Set the mtime & ctime to the date that this record was originally stored.
 */
/* 在我们文件系统的根目录中创建一个常规文件，并从“buf”中加载“size”字节的数据。将 mtime 和 ctime 设置为此记录最初存储的日期。 */
// 用于在 pstore 文件系统的根目录中创建一个常规文件，并填充指定数量的数据。文件的修改时间和创建时间被设置为记录最初存储的日期。
/*
 * 这个函数首先检查是否已经存在相同的记录，如果不存在则创建新的文件。对于新文件，函数设置了 inode 的各种属性，
 * 包括文件类型、权限、大小以及操作函数，并把文件名格式化后添加到目录项中。如果操作成功，新的记录会被加入到记录列表中。
 * 如果在任何步骤中遇到错误，则进行适当的资源释放和错误处理。
 */
int pstore_mkfile(struct dentry *root, struct pstore_record *record)
{
	struct dentry		*dentry;	// 声明目录项指针
	struct inode		*inode;		// 声明 inode 指针
	int			rc = 0;		// 初始化返回代码为 0
	char			name[PSTORE_NAMELEN];	// 文件名缓冲区
	struct pstore_private	*private, *pos;	// 声明私有数据指针
	size_t			size = record->size + record->ecc_notice_size;	// 计算记录的总大小（包括ECC通知）

	/* 检查是否锁定了根目录的 inode，如果未锁定则返回错误 */
	if (WARN_ON(!inode_is_locked(d_inode(root))))
		return -EINVAL;

	rc = -EEXIST;	// 初始设置为已存在错误码
	/* Skip records that are already present in the filesystem. */
	/* 锁定记录列表，避免并发修改 */
	mutex_lock(&records_list_lock);
	/* 检查记录是否已经存在于文件系统中 */
	/* 遍历记录列表，查看是否已经存在相同的记录 */
	list_for_each_entry(pos, &records_list, list) {
		if (pos->record->type == record->type &&
		    pos->record->id == record->id &&
		    pos->record->psi == record->psi)
			goto fail;	// 如果找到相同记录，跳转到失败处理
	}

	rc = -ENOMEM;	// 设置为内存不足错误码
	/* 获取一个新的 inode */
	inode = pstore_get_inode(root->d_sb);
	if (!inode)
		goto fail;	// 如果获取inode失败，跳转到失败处理
	inode->i_mode = S_IFREG | 0444;	// 设置文件类型为普通文件并设置权限为只读
	inode->i_fop = &pstore_file_operations;	// 设置文件操作为 pstore 文件操作
	/* 格式化文件名 */
	scnprintf(name, sizeof(name), "%s-%s-%llu%s",
			pstore_type_to_name(record->type),
			record->psi->name, record->id,
			record->compressed ? ".enc.z" : "");

	/* 分配私有数据结构 */
	private = kzalloc(sizeof(*private), GFP_KERNEL);
	if (!private)
		goto fail_inode;	// 如果内存分配失败，跳转到inode释放处理

	/* 分配并初始化目录项 */
	dentry = d_alloc_name(root, name);
	if (!dentry)
		goto fail_private;	// 如果目录项分配失败，跳转到私有数据释放处理

	private->dentry = dentry;	// 设置私有数据中的目录项指针
	private->record = record;	// 设置私有数据中的记录指针
	inode->i_size = private->total_size = size;	// 设置 inode 和私有数据的大小
	inode->i_private = private;	// 将私有数据关联到inode

	/* 如果记录有时间戳，则设置 inode 的修改和创建时间 */
	if (record->time.tv_sec)
		inode->i_mtime = inode->i_ctime = record->time;

	/* 将目录项和 inode 添加到目录树中 */
	d_add(dentry, inode);	// 将目录项添加到文件系统

	/* 将私有数据添加到记录列表 */
	list_add(&private->list, &records_list);
	mutex_unlock(&records_list_lock);	// 解锁记录列表

	return 0;	// 返回成功

fail_private:
	free_pstore_private(private);	// 释放私有数据
fail_inode:
	iput(inode);	// 释放 inode
fail:
	mutex_unlock(&records_list_lock);	// 解锁记录列表
	return rc;	// 返回错误代码
}

/*
 * Read all the records from the persistent store. Create
 * files in our filesystem.  Don't warn about -EEXIST errors
 * when we are re-scanning the backing store looking to add new
 * error records.
 */
/* 
 * 从持久化存储中读取所有记录，为这些记录在我们的文件系统中创建文件。
 * 在重新扫描后端存储以添加新的错误记录时，不对 -EEXIST 错误发出警告。
 */
// 这段代码负责从持久化存储中读取所有记录，并在文件系统中创建对应的文件。如果在重新扫描后端存储时发现新的错误记录，代码将不会因为已存在的错误（-EEXIST）而发出警告。
void pstore_get_records(int quiet)
{
	struct dentry *root;	// 定义根目录项变量

	root = psinfo_lock_root();	/* 尝试锁定并获取根目录项 */
	if (!root)	// 如果获取根目录项失败
		return;	// 直接返回

	/* 调用后端函数来获取记录，并在根目录下创建文件 */
	pstore_get_backend_records(psinfo, root, quiet);
	inode_unlock(d_inode(root));	/* 解锁根目录项的inode */
}

// 这段代码主要负责初始化 pstore 文件系统的超级块（super_block）和根目录的 inode。
/* 初始化超级块：填充超级块结构体，设置文件系统参数 */
/*
 * 这段代码首先对 super_block 结构体进行初始化，包括设置文件系统的最大文件大小、块大小、文件系统类型标识等。
 * 接着解析挂载时传入的参数，并尝试获取一个新的 inode，用于创建文件系统的根目录。如果成功获取 inode，
 * 会设置为目录类型，并关联相应的操作函数。然后创建根目录的 dentry 并将其设置为超级块的根目录。
 * 在这一过程中，如果遇到错误如内存不足，则会返回相应的错误代码。最后，代码通过调用 pstore_get_records 函数，
 * 从后端存储中读取所有记录，并在文件系统中为这些记录创建文件。
 */
static int pstore_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;	// 定义 inode 结构体变量

	sb->s_maxbytes		= MAX_LFS_FILESIZE;	// 设置文件系统支持的最大文件大小
	sb->s_blocksize		= PAGE_SIZE;		// 设置块大小为系统页面大小
	sb->s_blocksize_bits	= PAGE_SHIFT;		// 块大小的位数，用于计算
	sb->s_magic		= PSTOREFS_MAGIC;	// 设置文件系统类型标识
	sb->s_op		= &pstore_ops;		// 指定文件系统的操作函数集
	sb->s_time_gran		= 1;			// 时间粒度为1秒

	parse_options(data);	/* 解析挂载时传入的选项 */

	/* 获取一个新的 inode 节点 */
	inode = pstore_get_inode(sb);
	if (inode) {	// 如果成功获取 inode
		inode->i_mode = S_IFDIR | 0750;	// 设置 inode 为目录，并设置权限
		inode->i_op = &pstore_dir_inode_operations;	// 设置目录的 inode 操作
		inode->i_fop = &simple_dir_operations;	// 设置目录的文件操作
		inc_nlink(inode);	// 增加 inode 的链接计数
	}
	sb->s_root = d_make_root(inode);	/* 创建根目录 dentry，并将其设置为超级块的根目录 */
	if (!sb->s_root)	// 如果创建根目录失败
		return -ENOMEM;	// 返回内存不足错误

	/* 锁定全局 pstore 超级块锁，并更新 pstore 超级块指针 */
	mutex_lock(&pstore_sb_lock);
	pstore_sb = sb;
	mutex_unlock(&pstore_sb_lock);

	/* 获取存储中的所有记录，并在文件系统中为它们创建文件 */
	pstore_get_records(0);

	return 0;	// 返回成功
}

/*
 * 挂载 pstore 文件系统的函数。
 * 此函数负责调用 mount_single() 来创建并挂载 pstore 文件系统。
 */
/*
 * pstore_mount 函数使用了 mount_single 函数来进行挂载操作，这是因为 pstore 文件系统通常只需要一个全局的实例，
 * 所以使用 mount_single 是合适的。mount_single 被调用时，它会创建一个新的 super_block 结构，
 * 并使用 pstore_fill_super 函数来初始化这个 super_block。pstore_fill_super 函数负责设置文件系统的基本属性，
 * 如最大文件大小、块大小、文件系统类型等，并创建根目录的 inode。如果挂载成功，
 * mount_single 返回一个指向根目录的 dentry，该 dentry 表示文件系统的挂载点。
 */
static struct dentry *pstore_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	/* 
	 * 使用 mount_single 通用挂载函数来挂载 pstore 文件系统。
	 * mount_single 是一个简化的文件系统挂载机制，适用于单实例文件系统。
	 * 
	 * 参数说明：
	 * fs_type - 指向文件系统类型结构的指针。
	 * flags - 挂载标志，用于定义挂载的行为。
	 * data - 指向任何挂载时传递给文件系统的数据。
	 * pstore_fill_super - 文件系统特定的填充 super_block 的函数指针。
	 */
	return mount_single(fs_type, flags, data, pstore_fill_super);
}

// 实现了 pstore 文件系统的销毁函数，主要负责卸载文件系统并清理相关资源。
/*
 * 销毁 pstore 文件系统的 superblock。
 * 这个函数负责卸载 pstore 文件系统并清理相关资源。
 */
/*
 * 在这段代码中，函数首先获取 pstore_sb_lock 互斥锁，保证在修改全局变量 pstore_sb 和 records_list 时不会有并发访问。
 * 它通过调用 kill_litter_super 函数来销毁文件系统的 super_block，这个函数会清理所有与 super_block 相关的资源。
 * 然后，函数会清理记录列表，移除所有挂载时创建的记录，并最终释放所有相关的锁。这确保了文件系统的干净卸载和资源的彻底释放。
 */
static void pstore_kill_sb(struct super_block *sb)
{
	mutex_lock(&pstore_sb_lock);	//  获取 pstore_sb_lock，确保在修改 pstore_sb 和 records_list 时线程安全。
	// 如果 pstore_sb 不为空，并且不是当前的 sb，发出警告。这是一个检查，确保不会意外销毁不正确的 superblock。
	WARN_ON(pstore_sb && pstore_sb != sb);

	// kill_litter_super 是一个帮助函数，用于销毁 superblock。它将关闭文件系统，销毁 superblock 结构中的所有内容。
	kill_litter_super(sb);
	// 将 pstore_sb 置为 NULL，表示当前没有活动的 pstore 文件系统。
	pstore_sb = NULL;

	// 锁定记录列表，准备清理。
	mutex_lock(&records_list_lock);
	// 初始化记录列表，这将移除所有的元素并重置列表头。
	INIT_LIST_HEAD(&records_list);
	// 解锁记录列表。
	mutex_unlock(&records_list_lock);

	// 解锁 pstore_sb_lock，完成操作。
	mutex_unlock(&pstore_sb_lock);
}

/* pstore 文件系统类型的定义 */
static struct file_system_type pstore_fs_type = {
	.owner          = THIS_MODULE,  // 文件系统所属模块
	.name           = "pstore",  // 文件系统的名字
	.mount          = pstore_mount,  // 文件系统的挂载函数
	.kill_sb        = pstore_kill_sb,  // 文件系统卸载时清理超级块的函数
};

/* 初始化 pstore 文件系统 */
int __init pstore_init_fs(void)
{
	int err;

	/* Create a convenient mount point for people to access pstore */
	/* 为方便用户访问 pstore 创建一个挂载点 */
	err = sysfs_create_mount_point(fs_kobj, "pstore");
	if (err)
		goto out;	// 如果创建挂载点失败，跳转到错误处理代码

	/* 注册 pstore 文件系统 */
	err = register_filesystem(&pstore_fs_type);
	if (err < 0)
		// 如果注册文件系统失败，移除之前创建的挂载点
		sysfs_remove_mount_point(fs_kobj, "pstore");

out:
	return err;
}

/* 清理 pstore 文件系统 */
void __exit pstore_exit_fs(void)
{
	// 注销 pstore 文件系统
	unregister_filesystem(&pstore_fs_type);
	// 移除 pstore 的挂载点
	sysfs_remove_mount_point(fs_kobj, "pstore");
}
