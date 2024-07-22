/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Persistent Storage - pstore.h
 *
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 *
 * This code is the generic layer to export data records from platform
 * level persistent storage via a file system.
 */
#ifndef _LINUX_PSTORE_H
#define _LINUX_PSTORE_H

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kmsg_dump.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/types.h>

struct module;


// pstore（持久存储）相关的枚举类型和数据结构，用于管理和存储系统崩溃或运行时的重要信息，以便系统重启后分析。
/*
 * pstore record types (see fs/pstore/platform.c for pstore_type_names[])
 * These values may be written to storage (see EFI vars backend), so
 * they are kind of an ABI. Be careful changing the mappings.
 */
/*
 * pstore记录类型（参见fs/pstore/platform.c中的pstore_type_names[]）
 * 这些值可能会写入存储（参见EFI变量后端），因此它们有点像一个ABI。更改映射时要小心。
 */
enum pstore_type_id {
	/* Frontend storage types */
	/* 前端存储类型 */
	// 表示内核日志
	PSTORE_TYPE_DMESG	= 0,			// 内核日志存储类型
	// 表示硬件错误
	PSTORE_TYPE_MCE		= 1,			// 机器检查异常存储类型
	// 表示控制台输出
	PSTORE_TYPE_CONSOLE	= 2,		// 控制台日志存储类型
	// 表示函数调用序列
	PSTORE_TYPE_FTRACE	= 3,		// 用于存储函数跟踪记录的类型

	/* PPC64-specific partition types */
	/* PPC64特定的分区类型 */
		/* PPC64特定的分区类型 */
	PSTORE_TYPE_PPC_RTAS	= 4, // 用于存储PPC64 RTAS相关记录的类型
	PSTORE_TYPE_PPC_OF	= 5, // 用于存储PPC64 Open Firmware相关记录的类型
	PSTORE_TYPE_PPC_COMMON	= 6, // 用于存储PPC64通用记录的类型
	PSTORE_TYPE_PMSG	= 7, // 用于存储持久性消息记录的类型
	PSTORE_TYPE_PPC_OPAL	= 8, // 用于存储PPC64 OPAL相关记录的类型

	/* End of the list */
	/* 列表结束 */
	PSTORE_TYPE_MAX	// 枚举的最大值，用于限制类型数
};

const char *pstore_type_to_name(enum pstore_type_id type);
enum pstore_type_id pstore_name_to_type(const char *name);

struct pstore_info;
/**
 * struct pstore_record - details of a pstore record entry
 * @psi:	pstore backend driver information
 * @type:	pstore record type
 * @id:		per-type unique identifier for record
 * @time:	timestamp of the record
 * @buf:	pointer to record contents
 * @size:	size of @buf
 * @ecc_notice_size:
 *		ECC information for @buf
 * @priv:	pointer for backend specific use, will be
 *		kfree()d by the pstore core if non-NULL
 *		when the record is freed.
 *
 * Valid for PSTORE_TYPE_DMESG @type:
 *
 * @count:	Oops count since boot
 * @reason:	kdump reason for notification
 * @part:	position in a multipart record
 * @compressed:	whether the buffer is compressed
 *
 */
/**
 * struct pstore_record - 详细描述一个pstore记录项
 * @psi:	指向pstore后端驱动信息的指针
 * @type:	pstore记录的类型
 * @id:		每种类型的唯一标识符
 * @time:	记录的时间戳
 * @buf:	指向记录内容的指针
 * @size:	缓冲区@buf的大小
 * @ecc_notice_size:
 *		缓冲区@buf的ECC（错误检测和纠正）信息大小
 * @priv:	后端特定用途的指针，如果非空，在记录释放时由pstore核心通过kfree()释放
 *
 * 对于PSTORE_TYPE_DMESG类型有效：
 *
 * @count:	自启动以来的Oops计数
 * @reason:	kdump通知的原因
 * @part:	多部分记录中的位置
 * @compressed:	缓冲区是否被压缩
 *
 */
struct pstore_record {
	struct pstore_info	*psi; // 后端驱动信息
	enum pstore_type_id	type; // 记录类型
	u64			id; // 记录的唯一标识符
	struct timespec64	time; // 记录的时间戳
	char			*buf; // 指向记录内容的指针
	ssize_t			size; // 记录内容的大小
	ssize_t			ecc_notice_size; // ECC信息的大小
	void			*priv; // 用于特定后端的私有数据指针

	int			count; // Oops计数
	enum kmsg_dump_reason	reason; // kdump的原因
	unsigned int		part; // 多部分记录中的部分编号
	bool			compressed; // 记录是否压缩
};

/**
 * struct pstore_info - backend pstore driver structure
 *
 * @owner:	module which is responsible for this backend driver
 * @name:	name of the backend driver
 *
 * @buf_lock:	spinlock to serialize access to @buf
 * @buf:	preallocated crash dump buffer
 * @bufsize:	size of @buf available for crash dump bytes (must match
 *		smallest number of bytes available for writing to a
 *		backend entry, since compressed bytes don't take kindly
 *		to being truncated)
 *
 * @read_mutex:	serializes @open, @read, @close, and @erase callbacks
 * @flags:	bitfield of frontends the backend can accept writes for
 * @max_reason:	Used when PSTORE_FLAGS_DMESG is set. Contains the
 *		kmsg_dump_reason enum value. KMSG_DUMP_UNDEF means
 *		"use existing kmsg_dump() filtering, based on the
 *		printk.always_kmsg_dump boot param" (which is either
 *		KMSG_DUMP_OOPS when false, or KMSG_DUMP_MAX when
 *		true); see printk.always_kmsg_dump for more details.
 * @data:	backend-private pointer passed back during callbacks
 *
 * Callbacks:
 *
 * @open:
 *	Notify backend that pstore is starting a full read of backend
 *	records. Followed by one or more @read calls, and a final @close.
 *
 *	@psi:	in: pointer to the struct pstore_info for the backend
 *
 *	Returns 0 on success, and non-zero on error.
 *
 * @close:
 *	Notify backend that pstore has finished a full read of backend
 *	records. Always preceded by an @open call and one or more @read
 *	calls.
 *
 *	@psi:	in: pointer to the struct pstore_info for the backend
 *
 *	Returns 0 on success, and non-zero on error. (Though pstore will
 *	ignore the error.)
 *
 * @read:
 *	Read next available backend record. Called after a successful
 *	@open.
 *
 *	@record:
 *		pointer to record to populate. @buf should be allocated
 *		by the backend and filled. At least @type and @id should
 *		be populated, since these are used when creating pstorefs
 *		file names.
 *
 *	Returns record size on success, zero when no more records are
 *	available, or negative on error.
 *
 * @write:
 *	A newly generated record needs to be written to backend storage.
 *
 *	@record:
 *		pointer to record metadata. When @type is PSTORE_TYPE_DMESG,
 *		@buf will be pointing to the preallocated @psi.buf, since
 *		memory allocation may be broken during an Oops. Regardless,
 *		@buf must be proccesed or copied before returning. The
 *		backend is also expected to write @id with something that
 *		can help identify this record to a future @erase callback.
 *		The @time field will be prepopulated with the current time,
 *		when available. The @size field will have the size of data
 *		in @buf.
 *
 *	Returns 0 on success, and non-zero on error.
 *
 * @write_user:
 *	Perform a frontend write to a backend record, using a specified
 *	buffer that is coming directly from userspace, instead of the
 *	@record @buf.
 *
 *	@record:	pointer to record metadata.
 *	@buf:		pointer to userspace contents to write to backend
 *
 *	Returns 0 on success, and non-zero on error.
 *
 * @erase:
 *	Delete a record from backend storage.  Different backends
 *	identify records differently, so entire original record is
 *	passed back to assist in identification of what the backend
 *	should remove from storage.
 *
 *	@record:	pointer to record metadata.
 *
 *	Returns 0 on success, and non-zero on error.
 *
 */
/**
 * struct pstore_info - 后端pstore驱动结构体
 *
 * @owner: 负责此后端驱动的模块
 * @name: 后端驱动的名称
 *
 * @buf_lock: 用于序列化对@buf的访问的自旋锁
 * @buf: 预分配的崩溃转储缓冲区
 * @bufsize: 可用于崩溃转储字节的@buf的大小（必须与可写入后端条目的最小字节数匹配，
 *           因为压缩字节不易被截断）
 *
 * @read_mutex: 序列化@open、@read、@close和@erase回调的互斥锁
 * @flags: 后端可以接受写入的前端的位字段
 * @max_reason: 当PSTORE_FLAGS_DMESG设置时使用。包含kmsg_dump_reason枚举值。
 *              KMSG_DUMP_UNDEF意味着“使用现有的kmsg_dump()过滤，
 *              基于printk.always_kmsg_dump启动参数”（当为false时为KMSG_DUMP_OOPS，
 *              当为true时为KMSG_DUMP_MAX）；有关更多细节请参阅printk.always_kmsg_dump。
 * @data: 在回调期间返回的后端私有指针
 *
 * 回调函数:
 *
 * @open:
 *     通知后端pstore开始完整读取后端记录。这将跟随一个或多个@read调用，以及最终的@close。
 *
 *     @psi: 输入：指向后端的struct pstore_info的指针
 *
 *     成功时返回0，错误时返回非零值。
 *
 * @close:
 *     通知后端pstore已完成对后端记录的完整读取。总是先有一个@open调用和一个或多个@read调用。
 *
 *     @psi: 输入：指向后端的struct pstore_info的指针
 *
 *     成功时返回0，错误时返回非零值。（尽管pstore会忽略错误。）
 *
 * @read:
 *     读取下一个可用的后端记录。在成功的@open之后调用。
 *
 *     @record:
 *         指向需要填充的记录的指针。@buf应由后端分配并填充。至少应填充@type和@id，
 *         因为这些在创建pstorefs文件名时使用。
 *
 *     成功时返回记录大小，没有更多记录时返回零，错误时返回负值。
 *
 * @write:
 *     需要将新生成的记录写入后端存储。
 *
 *     @record:
 *         指向记录元数据的指针。当@type为PSTORE_TYPE_DMESG时，@buf将指向预分配的@psi.buf，
 *         因为在Oops期间可能无法进行内存分配。无论如何，@buf都必须在返回前被处理或复制。
 *         后端还预期将@id写入某些可以帮助将来的@erase回调识别此记录的内容。
 *         @time字段将预先填充当前时间，@size字段将有@buf中数据的大小。
 *
 *     成功时返回0，错误时返回非零值。
 *
 * @write_user:
 *     执行前端写入到后端记录，使用直接来自用户空间的指定缓冲区，而不是@record @buf。
 *
 *     @record: 指向记录元数据的指针。
 *     @buf: 指向要写入后端的用户空间内容的指针
 *
 *     成功时返回0，错误时返回非零值。
 *
 * @erase:
 *     从后端存储中删除记录。不同的后端以不同方式识别记录，因此完整的原始记录被传回以协助识别
 *     后端应从存储中删除的内容。
 *
 *     @record: 指向记录元数据的指针。
 *
 *     成功时返回0，错误时返回非零值。
 *
 */
struct pstore_info {
	struct module	*owner;      // 此后端驱动的负责模块
	const char	*name;       // 后端驱动的名称

	spinlock_t	buf_lock;    // 用于序列化对buf的访问的自旋锁
	char		*buf;        // 预分配的崩溃转储缓冲区
	size_t		bufsize;     // buf的大小，用于崩溃转储

	struct mutex	read_mutex; // 用于序列化open、read、close和erase的互斥锁

	int		flags;       // 可以接受写入的前端的位字段
	int		max_reason;  // 最大kmsg_dump_reason值
	void		*data;       // 后端在回调中返回的私有指针

	int		(*open)(struct pstore_info *psi);          // 开启后端存储的回调函数
	int		(*close)(struct pstore_info *psi);         // 关闭后端存储的回调函数
	ssize_t		(*read)(struct pstore_record *record);    // 读取后端存储记录的回调函数
	int		(*write)(struct pstore_record *record);    // 写入后端存储记录的回调函数
	int		(*write_user)(struct pstore_record *record, const char __user *buf); // 从用户空间写入记录的回调函数
	int		(*erase)(struct pstore_record *record);    // 删除后端存储记录的回调函数
};

/* Supported frontends */
/* 支持的前端 */
#define PSTORE_FLAGS_DMESG	BIT(0)  // 内核消息（dmesg）记录的标志位
#define PSTORE_FLAGS_CONSOLE	BIT(1)  // 控制台输出记录的标志位
#define PSTORE_FLAGS_FTRACE	BIT(2)  // 函数跟踪记录的标志位
#define PSTORE_FLAGS_PMSG	BIT(3)  // 持久消息记录的标志位

// 注册pstore后端
extern int pstore_register(struct pstore_info *);
// 注销pstore后端
extern void pstore_unregister(struct pstore_info *);

struct pstore_ftrace_record {
	unsigned long ip;         // 当前指令指针
	unsigned long parent_ip;  // 父函数的指令指针
	u64 ts;                   // 时间戳
};

/*
 * ftrace related stuff: Both backends and frontends need these so expose
 * them here.
 */
/*
 * 与ftrace相关的内容：由于后端和前端都需要这些内容，因此在此处公开。
 */

// 如果CPU数量小于等于2并且定义了CONFIG_ARM_THUMB
#if NR_CPUS <= 2 && defined(CONFIG_ARM_THUMB)
// IP地址中包含CPU编号的位数
#define PSTORE_CPU_IN_IP 0x1
// 如果CPU数量小于等于4并且定义了CONFIG_ARM
#elif NR_CPUS <= 4 && defined(CONFIG_ARM)
// IP地址中包含CPU编号的位数
#define PSTORE_CPU_IN_IP 0x3
#endif

#define TS_CPU_SHIFT 8	// 时间戳中CPU编号的位移量
// 用于从时间戳中提取CPU编号的掩码
#define TS_CPU_MASK (BIT(TS_CPU_SHIFT) - 1)

/*
 * If CPU number can be stored in IP, store it there, otherwise store it in
 * the time stamp. This means more timestamp resolution is available when
 * the CPU can be stored in the IP.
 */
/*
 * 如果CPU编号可以存储在IP地址中，则将其存储在那里，否则存储在时间戳中。
 * 这意味着当CPU可以存储在IP地址中时，时间戳的分辨率更高。
 */
#ifdef PSTORE_CPU_IN_IP
static inline void
pstore_ftrace_encode_cpu(struct pstore_ftrace_record *rec, unsigned int cpu)
{
	rec->ip |= cpu;	// 将CPU编号编码到IP地址中
}

static inline unsigned int
pstore_ftrace_decode_cpu(struct pstore_ftrace_record *rec)
{
	return rec->ip & PSTORE_CPU_IN_IP;	// 从IP地址中解码CPU编号
}

static inline u64
pstore_ftrace_read_timestamp(struct pstore_ftrace_record *rec)
{
	return rec->ts;	// 读取时间戳
}

static inline void
pstore_ftrace_write_timestamp(struct pstore_ftrace_record *rec, u64 val)
{
	rec->ts = val;	// 写入时间戳
}
#else
static inline void
pstore_ftrace_encode_cpu(struct pstore_ftrace_record *rec, unsigned int cpu)
{
	rec->ts &= ~(TS_CPU_MASK);	// 清除时间戳中的CPU编号部分
	rec->ts |= cpu;  // 在时间戳中编码CPU编号
}

static inline unsigned int
pstore_ftrace_decode_cpu(struct pstore_ftrace_record *rec)
{
	// 从时间戳中解码CPU编号
	return rec->ts & TS_CPU_MASK;
}

static inline u64
pstore_ftrace_read_timestamp(struct pstore_ftrace_record *rec)
{
	// 从时间戳中读取除CPU编号外的部分
	return rec->ts >> TS_CPU_SHIFT;
}

static inline void
pstore_ftrace_write_timestamp(struct pstore_ftrace_record *rec, u64 val)
{
	// 写入时间戳，同时保留CPU编号
	rec->ts = (rec->ts & TS_CPU_MASK) | (val << TS_CPU_SHIFT);
}
#endif

#endif /*_LINUX_PSTORE_H*/
