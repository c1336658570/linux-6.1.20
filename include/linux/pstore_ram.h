/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2010 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright (C) 2011 Kees Cook <keescook@chromium.org>
 * Copyright (C) 2011 Google, Inc.
 */

#ifndef __LINUX_PSTORE_RAM_H__
#define __LINUX_PSTORE_RAM_H__

#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pstore.h>
#include <linux/types.h>

/*
 * Choose whether access to the RAM zone requires locking or not.  If a zone
 * can be written to from different CPUs like with ftrace for example, then
 * PRZ_FLAG_NO_LOCK is used. For all other cases, locking is required.
 */
/*
 * 选择是否需要对RAM区域进行加锁。如果一个区域可以从不同的CPU写入，
 * 如使用ftrace那样，则使用PRZ_FLAG_NO_LOCK。对于所有其他情况，都需要加锁。
 */
#define PRZ_FLAG_NO_LOCK	BIT(0)	// 一个位标志，表示无需锁定的RAM区域。
/*
 * If a PRZ should only have a single-boot lifetime, this marks it as
 * getting wiped after its contents get copied out after boot.
 */
/*
 * 如果PRZ应该只在单次启动中存在，这个标志表示在内容在启动后被复制出来之后，
 * 将其擦除。
 */
#define PRZ_FLAG_ZAP_OLD	BIT(1)	 // 一个位标志，用于标记内容在引导后被复制出后应被擦除的PRZ。

struct persistent_ram_buffer;
struct rs_control;	// 前向声明Reed-Solomon控制结构，用于纠错编码处理。
/*
 * block_size: 这是每个数据块的大小。在纠错编码中，数据被分成多个块，每个块独立进行错误检测和修正。
 * ecc_size: 这是每个数据块所需的错误更正码的额外字节数。更多的ECC字节意味着能够检测和修正更多的错误。
 * symsize: 符号大小，通常用位（bit）表示。这决定了纠错算法处理的数据单位。例如，8位symsize意味着算法将数据以每8位进行一次处理。
 * poly: 这是一个生成多项式，用于Reed-Solomon编码。这个多项式决定了生成纠错码的方法。
 */
struct persistent_ram_ecc_info {
	int block_size;   // 块大小，通常指一个数据块的字节数。
	int ecc_size;     // ECC（错误更正码）大小，指每个数据块需要的额外字节数。
	int symsize;      // 符号大小，用于定义错误更正算法中处理的单位位数。
	int poly;         // 多项式，用于Reed-Solomon编码的生成多项式。
	uint16_t *par;    // 指向包含纠错编码参数的数组。
};

/**
 * struct persistent_ram_zone - Details of a persistent RAM zone (PRZ)
 *                              used as a pstore backend
 *
 * @paddr:	physical address of the mapped RAM area
 * @size:	size of mapping
 * @label:	unique name of this PRZ
 * @type:	frontend type for this PRZ
 * @flags:	holds PRZ_FLAGS_* bits
 *
 * @buffer_lock:
 *	locks access to @buffer "size" bytes and "start" offset
 * @buffer:
 *	pointer to actual RAM area managed by this PRZ
 * @buffer_size:
 *	bytes in @buffer->data (not including any trailing ECC bytes)
 *
 * @par_buffer:
 *	pointer into @buffer->data containing ECC bytes for @buffer->data
 * @par_header:
 *	pointer into @buffer->data containing ECC bytes for @buffer header
 *	(i.e. all fields up to @data)
 * @rs_decoder:
 *	RSLIB instance for doing ECC calculations
 * @corrected_bytes:
 *	ECC corrected bytes accounting since boot
 * @bad_blocks:
 *	ECC uncorrectable bytes accounting since boot
 * @ecc_info:
 *	ECC configuration details
 *
 * @old_log:
 *	saved copy of @buffer->data prior to most recent wipe
 * @old_log_size:
 *	bytes contained in @old_log
 *
 */
/**
 * struct persistent_ram_zone - Details of a persistent RAM zone (PRZ)
 *                              used as a pstore backend
 * struct persistent_ram_zone - 持久性RAM区域（PRZ）的详细信息，用作pstore后端
 *
 * @paddr:	physical address of the mapped RAM area
 * @paddr:	映射的RAM区域的物理地址
 * @size:	size of mapping
 * @size:	映射的大小
 * @label:	unique name of this PRZ
 * @label:	此PRZ的唯一名称
 * @type:	frontend type for this PRZ
 * @type:	此PRZ的前端类型
 * @flags:	holds PRZ_FLAGS_* bits
 * @flags:	持有PRZ_FLAGS_*位
 *
 * @buffer_lock:
 *	locks access to @buffer "size" bytes and "start" offset
 * @buffer_lock:
 *	锁定对@buffer的"大小"字节和"开始"偏移的访问
 * @buffer:
 *	pointer to actual RAM area managed by this PRZ
 * @buffer:
 *	指向由此PRZ管理的实际RAM区域的指针
 * @buffer_size:
 *	bytes in @buffer->data (not including any trailing ECC bytes)
 * @buffer_size:
 *	@buffer->data中的字节数（不包括任何尾随的ECC字节）
 *
 * @par_buffer:
 *	pointer into @buffer->data containing ECC bytes for @buffer->data
 * @par_buffer:
 *	指向@buffer->data中包含@buffer->data的ECC字节的指针
 * @par_header:
 *	pointer into @buffer->data containing ECC bytes for @buffer header
 *	(i.e. all fields up to @data)
 * @par_header:
 *	指向@buffer->data中包含@buffer头部的ECC字节的指针
 *	（即所有字段直到@data）
 * @rs_decoder:
 *	RSLIB instance for doing ECC calculations
 * @rs_decoder:
 *	用于进行ECC计算的RSLIB实例
 * @corrected_bytes:
 *	ECC corrected bytes accounting since boot
 * @corrected_bytes:
 *	自启动以来ECC纠正的字节数
 * @bad_blocks:
 *	ECC uncorrectable bytes accounting since boot
 * @bad_blocks:
 *	自启动以来ECC无法纠正的字节数
 * @ecc_info:
 *	ECC configuration details
 * @ecc_info:
 *	ECC配置细节
 *
 * @old_log:
 *	saved copy of @buffer->data prior to most recent wipe
 * @old_log:
 *	最近一次擦除之前@buffer->data的保存副本
 * @old_log_size:
 *	bytes contained in @old_log
 * @old_log_size:
 *	@old_log中包含的字节数
 */
struct persistent_ram_zone {
	phys_addr_t paddr;             // RAM区域的物理地址
	size_t size;                   // 映射的总大小
	void *vaddr;                   // 虚拟地址，通常是映射后的RAM区域的起始地址
	char *label;                   // 此PRZ的唯一标识符
	enum pstore_type_id type;      // 此PRZ对应的pstore类型
	u32 flags;                     // 控制标志位，使用PRZ_FLAG_*定义

	raw_spinlock_t buffer_lock;    // 保护buffer访问的自旋锁
	struct persistent_ram_buffer *buffer; // 指向实际RAM缓冲区的指针
	size_t buffer_size;            // buffer中有效数据的大小

	char *par_buffer;              // 指向用于ECC的数据的指针
	char *par_header;              // 指向用于ECC的头部数据的指针
	struct rs_control *rs_decoder; // 用于ECC解码的Reed-Solomon控制结构
	int corrected_bytes;           // 自启动以来纠正的字节数
	int bad_blocks;                // 自启动以来未能纠正的块数
	struct persistent_ram_ecc_info ecc_info; // ECC配置

	char *old_log;                 // 擦除前buffer数据的副本
	size_t old_log_size;           // old_log中的数据大小
};

/*
 * 创建一个新的持久性RAM区域。
 * @start: RAM区域的物理起始地址。
 * @size: RAM区域的大小。
 * @sig: 区域的签名，用于验证。
 * @ecc_info: 指向ECC信息结构的指针，用于错误校正。
 * @memtype: 内存类型，影响内存分配策略。
 * @flags: 区域的配置标志。
 * @label: 区域的标识符。
 * 返回值: 指向新创建的持久性RAM区域的指针。
 */
struct persistent_ram_zone *persistent_ram_new(phys_addr_t start, size_t size,
			u32 sig, struct persistent_ram_ecc_info *ecc_info,
			unsigned int memtype, u32 flags, char *label);
/*
 * 释放一个持久性RAM区域。
 * @prz: 指向需要释放的持久性RAM区域的指针。
 */
void persistent_ram_free(struct persistent_ram_zone *prz);
/*
 * 清除持久性RAM区域中的数据。
 * @prz: 指向需要清除的持久性RAM区域的指针。
 */
void persistent_ram_zap(struct persistent_ram_zone *prz);

/*
 * 向持久性RAM区域写入数据。
 * @prz: 指向持久性RAM区域的指针。
 * @s: 指向要写入的数据的指针。
 * @count: 要写入的字节数。
 * 返回值: 成功时返回写入的字节数，失败时返回负值错误代码。
 */
int persistent_ram_write(struct persistent_ram_zone *prz, const void *s,
			 unsigned int count);
/*
 * 从用户空间向持久性RAM区域写入数据。
 * @prz: 指向持久性RAM区域的指针。
 * @s: 用户空间中要写入的数据的指针。
 * @count: 要写入的字节数。
 * 返回值: 成功时返回写入的字节数，失败时返回负值错误代码。
 */
int persistent_ram_write_user(struct persistent_ram_zone *prz,
			      const void __user *s, unsigned int count);

/*
 * 保存持久性RAM区域中当前的数据，以便在下一次启动时可以恢复。
 * @prz: 指向持久性RAM区域的指针。
 */
void persistent_ram_save_old(struct persistent_ram_zone *prz);
/*
 * 获取保存的旧数据的大小。
 * @prz: 指向持久性RAM区域的指针。
 * 返回值: 旧数据的大小。
 */
size_t persistent_ram_old_size(struct persistent_ram_zone *prz);
/*
 * 获取指向保存的旧数据的指针。
 * @prz: 指向持久性RAM区域的指针。
 * 返回值: 指向旧数据的指针。
 */
void *persistent_ram_old(struct persistent_ram_zone *prz);
/*
 * 释放保存的旧数据。
 * @prz: 指向持久性RAM区域的指针。
 */
void persistent_ram_free_old(struct persistent_ram_zone *prz);
/*
 * 获取描述当前ECC状态的字符串。
 * @prz: 指向持久性RAM区域的指针。
 * @str: 用于存储状态描述的字符串的缓冲区。
 * @len: 缓冲区的大小。
 * 返回值: 写入缓冲区的字节数，或负值错误代码。
 */
ssize_t persistent_ram_ecc_string(struct persistent_ram_zone *prz,
	char *str, size_t len);

/*
 * Ramoops platform data
 * @mem_size	memory size for ramoops
 * @mem_address	physical memory address to contain ramoops
 */
/*
 * Ramoops platform data
 * Ramoops平台数据
 * @mem_size: memory size for ramoops
 * @mem_size: 为ramoops分配的内存大小
 * @mem_address: physical memory address to contain ramoops
 * @mem_address: 包含ramoops数据的物理内存地址
 */

/*
 * 定义一个标志位，用于指示是否为每个CPU分别保存ftrace数据。
 */
#define RAMOOPS_FLAG_FTRACE_PER_CPU	BIT(0)

struct ramoops_platform_data {
	unsigned long	mem_size;       // 分配给ramoops的内存大小。
	phys_addr_t	mem_address;     // ramoops数据的物理内存地址。
	unsigned int	mem_type;        // 内存类型，可能影响分配策略。
	unsigned long	record_size;     // 单个记录的大小。
	unsigned long	console_size;    // 为控制台日志分配的内存大小。
	unsigned long	ftrace_size;     // 为ftrace日志分配的内存大小。
	unsigned long	pmsg_size;       // 为pmsg日志分配的内存大小。
	int		max_reason;      // 可存储的最大错误原因数量。
	u32		flags;           // 配置标志，如RAMOOPS_FLAG_FTRACE_PER_CPU。
	struct persistent_ram_ecc_info ecc_info; // ECC配置信息，用于错误校正。
};

#endif
