/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PSTORE_BLK_H_
#define __PSTORE_BLK_H_

#include <linux/types.h>
#include <linux/pstore.h>
#include <linux/pstore_zone.h>

/**
 * struct pstore_device_info - back-end pstore/blk driver structure.
 *
 * @flags:	Refer to macro starting with PSTORE_FLAGS defined in
 *		linux/pstore.h. It means what front-ends this device support.
 *		Zero means all backends for compatible.
 * @zone:	The struct pstore_zone_info details.
 *
 */
/**
 * struct pstore_device_info - pstore/blk后端驱动结构。
 *
 * @flags:	参考在linux/pstore.h中定义的以PSTORE_FLAGS开头的宏。
 *          这表示此设备支持哪些前端。零表示所有后端兼容。
 * @zone:	struct pstore_zone_info的详细信息。
 */
struct pstore_device_info {
	unsigned int flags;       // 用于标识设备支持的前端的标志。
	struct pstore_zone_info zone; // 与设备关联的pstore区域信息。
};

/*
 * 注册一个pstore设备。
 * @dev: 指向需要注册的pstore_device_info结构的指针。
 * 返回值: 注册成功返回0，失败返回负值错误代码。
 */
int  register_pstore_device(struct pstore_device_info *dev);
/*
 * 注销一个pstore设备。
 * @dev: 指向已注册的pstore_device_info结构的指针。
 */
void unregister_pstore_device(struct pstore_device_info *dev);

/**
 * struct pstore_blk_config - the pstore_blk backend configuration
 *
 * @device:		Name of the desired block device
 * @max_reason:		Maximum kmsg dump reason to store to block device
 * @kmsg_size:		Total size of for kmsg dumps
 * @pmsg_size:		Total size of the pmsg storage area
 * @console_size:	Total size of the console storage area
 * @ftrace_size:	Total size for ftrace logging data (for all CPUs)
 */
/**
 * struct pstore_blk_config - pstore_blk后端的配置
 *
 * @device:		期望的块设备的名称
 * @max_reason:		存储到块设备的最大内核消息转储原因
 * @kmsg_size:		内核消息转储的总大小
 * @pmsg_size:		pmsg存储区的总大小
 * @console_size:	控制台存储区的总大小
 * @ftrace_size:	所有CPU的ftrace日志数据的总大小
 */
struct pstore_blk_config {
	char device[80];                     // 块设备的名称
	enum kmsg_dump_reason max_reason;    // 可接受的最大内核消息转储原因
	unsigned long kmsg_size;             // 内核消息转储的总大小
	unsigned long pmsg_size;             // pmsg存储区的总大小
	unsigned long console_size;          // 控制台存储区的总大小
	unsigned long ftrace_size;           // 所有CPU的ftrace日志数据的总大小
};

/**
 * pstore_blk_get_config - get a copy of the pstore_blk backend configuration
 *
 * @info:	The sturct pstore_blk_config to be filled in
 *
 * Failure returns negative error code, and success returns 0.
 */
/**
 * pstore_blk_get_config - 获取pstore_blk后端配置的副本
 *
 * @info:	需要填充的pstore_blk_config结构
 *
 * 失败返回负值错误代码，成功返回0。
 */
/*
 * 该函数用于获取pstore_blk后端的配置信息。
 * @info: 指向需要填充配置信息的pstore_blk_config结构体的指针。
 * 返回值: 成功时返回0，失败时返回负值错误代码。
 */
int pstore_blk_get_config(struct pstore_blk_config *info);

#endif
