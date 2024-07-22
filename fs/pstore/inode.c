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
 * 删除与指定后端关联的所有记录。
 */
static struct inode *pstore_get_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	}
	return inode;
}

enum {
	Opt_kmsg_bytes, Opt_err
};

static const match_table_t tokens = {
	{Opt_kmsg_bytes, "kmsg_bytes=%u"},
	{Opt_err, NULL}
};

static void parse_options(char *options)
{
	char		*p;
	substring_t	args[MAX_OPT_ARGS];
	int		option;

	if (!options)
		return;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_kmsg_bytes:
			if (!match_int(&args[0], &option))
				pstore_set_kmsg_bytes(option);
			break;
		}
	}
}

/*
 * Display the mount options in /proc/mounts.
 */
static int pstore_show_options(struct seq_file *m, struct dentry *root)
{
	if (kmsg_bytes != CONFIG_PSTORE_DEFAULT_KMSG_BYTES)
		seq_printf(m, ",kmsg_bytes=%lu", kmsg_bytes);
	return 0;
}

static int pstore_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	parse_options(data);

	return 0;
}

static const struct super_operations pstore_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= pstore_evict_inode,
	.remount_fs	= pstore_remount,
	.show_options	= pstore_show_options,
};

static struct dentry *psinfo_lock_root(void)
{
	struct dentry *root;

	mutex_lock(&pstore_sb_lock);
	/*
	 * Having no backend is fine -- no records appear.
	 * Not being mounted is fine -- nothing to do.
	 */
	if (!psinfo || !pstore_sb) {
		mutex_unlock(&pstore_sb_lock);
		return NULL;
	}

	root = pstore_sb->s_root;
	inode_lock(d_inode(root));
	mutex_unlock(&pstore_sb_lock);

	return root;
}

int pstore_put_backend_records(struct pstore_info *psi)
{
	struct pstore_private *pos, *tmp;
	struct dentry *root;
	int rc = 0;

	root = psinfo_lock_root();
	if (!root)
		return 0;

	mutex_lock(&records_list_lock);
	list_for_each_entry_safe(pos, tmp, &records_list, list) {
		if (pos->record->psi == psi) {
			list_del_init(&pos->list);
			rc = simple_unlink(d_inode(root), pos->dentry);
			if (WARN_ON(rc))
				break;
			d_drop(pos->dentry);
			dput(pos->dentry);
			pos->dentry = NULL;
		}
	}
	mutex_unlock(&records_list_lock);

	inode_unlock(d_inode(root));

	return rc;
}

/*
 * Make a regular file in the root directory of our file system.
 * Load it up with "size" bytes of data from "buf".
 * Set the mtime & ctime to the date that this record was originally stored.
 */
int pstore_mkfile(struct dentry *root, struct pstore_record *record)
{
	struct dentry		*dentry;
	struct inode		*inode;
	int			rc = 0;
	char			name[PSTORE_NAMELEN];
	struct pstore_private	*private, *pos;
	size_t			size = record->size + record->ecc_notice_size;

	if (WARN_ON(!inode_is_locked(d_inode(root))))
		return -EINVAL;

	rc = -EEXIST;
	/* Skip records that are already present in the filesystem. */
	mutex_lock(&records_list_lock);
	list_for_each_entry(pos, &records_list, list) {
		if (pos->record->type == record->type &&
		    pos->record->id == record->id &&
		    pos->record->psi == record->psi)
			goto fail;
	}

	rc = -ENOMEM;
	inode = pstore_get_inode(root->d_sb);
	if (!inode)
		goto fail;
	inode->i_mode = S_IFREG | 0444;
	inode->i_fop = &pstore_file_operations;
	scnprintf(name, sizeof(name), "%s-%s-%llu%s",
			pstore_type_to_name(record->type),
			record->psi->name, record->id,
			record->compressed ? ".enc.z" : "");

	private = kzalloc(sizeof(*private), GFP_KERNEL);
	if (!private)
		goto fail_inode;

	dentry = d_alloc_name(root, name);
	if (!dentry)
		goto fail_private;

	private->dentry = dentry;
	private->record = record;
	inode->i_size = private->total_size = size;
	inode->i_private = private;

	if (record->time.tv_sec)
		inode->i_mtime = inode->i_ctime = record->time;

	d_add(dentry, inode);

	list_add(&private->list, &records_list);
	mutex_unlock(&records_list_lock);

	return 0;

fail_private:
	free_pstore_private(private);
fail_inode:
	iput(inode);
fail:
	mutex_unlock(&records_list_lock);
	return rc;
}

/*
 * Read all the records from the persistent store. Create
 * files in our filesystem.  Don't warn about -EEXIST errors
 * when we are re-scanning the backing store looking to add new
 * error records.
 */
void pstore_get_records(int quiet)
{
	struct dentry *root;

	root = psinfo_lock_root();
	if (!root)
		return;

	pstore_get_backend_records(psinfo, root, quiet);
	inode_unlock(d_inode(root));
}

static int pstore_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_magic		= PSTOREFS_MAGIC;
	sb->s_op		= &pstore_ops;
	sb->s_time_gran		= 1;

	parse_options(data);

	inode = pstore_get_inode(sb);
	if (inode) {
		inode->i_mode = S_IFDIR | 0750;
		inode->i_op = &pstore_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	mutex_lock(&pstore_sb_lock);
	pstore_sb = sb;
	mutex_unlock(&pstore_sb_lock);

	pstore_get_records(0);

	return 0;
}

static struct dentry *pstore_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, pstore_fill_super);
}

static void pstore_kill_sb(struct super_block *sb)
{
	mutex_lock(&pstore_sb_lock);
	WARN_ON(pstore_sb && pstore_sb != sb);

	kill_litter_super(sb);
	pstore_sb = NULL;

	mutex_lock(&records_list_lock);
	INIT_LIST_HEAD(&records_list);
	mutex_unlock(&records_list_lock);

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
