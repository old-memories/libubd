#ifndef LIBUBD_PRIV_INC_H
#define LIBUBD_PRIV_INC_H

#include "ccan/list/list.h"
#include "ubd_cmd.h"
#include "libubd_uring.h"

#define	UBD_CONTROL_DEV	"/dev/ubd-control"

#define UBD_CTRL_DEV_URING_DEPTH 32

#define UBD_BLOCK_SIZE_ZC 4096

#define UBD_BLOCK_SIZE 512

#define	MAX_NR_HW_QUEUES 32
/* MAX_QD should be smaller than UBD_MAX_QUEUE_DEPTH */
#define	MAX_QD		1024
#define	RQ_MAX_BUF_SIZE	(1024 << 10)

#define UBDC_DEV	"/dev/ubdc"

struct ubdlib_ctrl_dev {
	int ctrl_dev_fd;

	struct ubdsrv_uring ring;

	struct ubdsrv_ctrl_dev_info  dev_info;
};

struct ubd_io {
	int                 result;
	unsigned int        tag;
	char               *buf_addr;
	struct list_node    io_list_entry;
};

struct ubdsrv_queue {
	int q_id;
	int q_depth;

	int cmd_inflight, tgt_io_inflight;
	
	int stopping;

	/*
	 * 1) ubdsrv_io_desc(iod)s are all stored in this buffer 
	 *    and the buffer is allocated by ubd_drv and mmaped by ubdsrv.
	 * 
	 * 2) ubd_drv writes the iod and ubdsrv reads(READ ONLY) it.
	 */
	char *io_cmd_buf;

	/*
	 * ring for submit io command to ubd driver
	 * ring depth == dev_info->queue_depth.
	 */
	struct ubdsrv_uring ring;

	struct ubdlib_ubdsrv *srv;

	struct list_head need_get_data_io_list;

	struct list_head need_commit_io_list;

	struct ubd_io ios[0];

};

struct ubdlib_ubdsrv {
	int                      ubdc_dev_fd;
	
	struct ubdlib_ctrl_dev	*ctrl_dev;

	struct ubdsrv_queue	*queues[MAX_NR_HW_QUEUES];
};

#endif