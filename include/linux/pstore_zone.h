/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PSTORE_ZONE_H_
#define __PSTORE_ZONE_H_

#include <linux/types.h>

/*
 * 定义三种操作的函数指针类型：读、写、擦除。
 * 这些操作用于处理持久存储区域，函数参数包括数据缓冲区、大小和偏移量。
 */
typedef ssize_t (*pstore_zone_read_op)(char *, size_t, loff_t);
typedef ssize_t (*pstore_zone_write_op)(const char *, size_t, loff_t);
typedef ssize_t (*pstore_zone_erase_op)(size_t, loff_t);
/**
 * struct pstore_zone_info - pstore/zone back-end driver structure
 *
 * @owner:	Module which is responsible for this back-end driver.
 * @name:	Name of the back-end driver.
 * @total_size: The total size in bytes pstore/zone can use. It must be greater
 *		than 4096 and be multiple of 4096.
 * @kmsg_size:	The size of oops/panic zone. Zero means disabled, otherwise,
 *		it must be multiple of SECTOR_SIZE(512 Bytes).
 * @max_reason: Maximum kmsg dump reason to store.
 * @pmsg_size:	The size of pmsg zone which is the same as @kmsg_size.
 * @console_size:The size of console zone which is the same as @kmsg_size.
 * @ftrace_size:The size of ftrace zone which is the same as @kmsg_size.
 * @read:	The general read operation. Both of the function parameters
 *		@size and @offset are relative value to storage.
 *		On success, the number of bytes should be returned, others
 *		mean error.
 * @write:	The same as @read, but the following error number:
 *		-EBUSY means try to write again later.
 *		-ENOMSG means to try next zone.
 * @erase:	The general erase operation for device with special removing
 *		job. Both of the function parameters @size and @offset are
 *		relative value to storage.
 *		Return 0 on success and others on failure.
 * @panic_write:The write operation only used for panic case. It's optional
 *		if you do not care panic log. The parameters are relative
 *		value to storage.
 *		On success, the number of bytes should be returned, others
 *		excluding -ENOMSG mean error. -ENOMSG means to try next zone.
 */
/**
 * struct pstore_zone_info - pstore/zone后端驱动结构
 *
 * @owner:	负责此后端驱动的模块。
 * @name:	后端驱动的名称。
 * @total_size: pstore/zone可以使用的总字节大小。它必须大于4096字节且为4096的倍数。
 * @kmsg_size:	oops/panic区域的大小。零表示禁用，否则必须是SECTOR_SIZE(512字节)的倍数。
 * @max_reason:	存储的最大kmsg转储原因。
 * @pmsg_size:	pmsg区域的大小，与@kmsg_size相同。
 * @console_size: 控制台区域的大小，与@kmsg_size相同。
 * @ftrace_size: ftrace区域的大小，与@kmsg_size相同。
 * @read:	通用读操作。函数参数@size和@offset是相对于存储的相对值。
 * 		成功时应返回字节数，否则表示错误。
 * @write:	与@read相同，但以下错误号：
 *		-EBUSY表示稍后再尝试写入。
 *		-ENOMSG表示尝试下一个区域。
 * @erase:	具有特殊删除任务的设备的通用擦除操作。函数参数@size和@offset是相对于存储的相对值。
 *		成功返回0，失败返回其他值。
 * @panic_write: 仅用于紧急情况的写操作。如果您不关心紧急日志，则此操作是可选的。
 *		参数是相对于存储的相对值。
 *		成功时应返回字节数，除-ENOMSG外的其他值均表示错误。-ENOMSG表示尝试下一个区域。
 */
struct pstore_zone_info {
	struct module *owner;           // 此后端驱动的模块所有者。
	const char *name;               // 后端驱动的名称。

	unsigned long total_size;       // 总可用大小。
	unsigned long kmsg_size;        // oops/panic记录的大小。
	int max_reason;                 // 可接受的最大kmsg转储原因。
	unsigned long pmsg_size;        // pmsg记录的大小。
	unsigned long console_size;     // 控制台记录的大小。
	unsigned long ftrace_size;      // ftrace记录的大小。
	pstore_zone_read_op read;       // 读操作。
	pstore_zone_write_op write;     // 写操作。
	pstore_zone_erase_op erase;     // 擦除操作。
	pstore_zone_write_op panic_write; // 紧急情况下的写操作。
};

/*
 * 注册pstore/zone后端驱动。
 */
extern int register_pstore_zone(struct pstore_zone_info *info);
/*
 * 注销pstore/zone后端驱动。
 */
extern void unregister_pstore_zone(struct pstore_zone_info *info);

#endif
