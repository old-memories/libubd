#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <syslog.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "ccan/list/list.h"
#include "libubd.h"
#include "ubd_cmd.h"
#include "libubd_priv.h"
#include "libubd_uring.h"

static inline void ubdsrv_get_iod(
		struct ubdsrv_queue *q, int tag, unsigned int last_cmd_op,
		struct libubd_io_desc *iod)
{
    const struct ubdsrv_io_desc * ubdsrv_iod = 
	   		(const struct ubdsrv_io_desc *)
            &(q->io_cmd_buf[tag * sizeof(struct ubdsrv_io_desc)]);

	unsigned short block_size = q->srv->ctrl_dev->dev_info.block_size;

	iod->op = ubdsrv_get_op(ubdsrv_iod);
	
	iod->need_buf_addr = (iod->op == UBD_IO_OP_READ)
			|| (iod->op == UBD_IO_OP_WRITE 
					&& last_cmd_op != UBD_IO_GET_DATA);

	iod->flags = ubdsrv_get_flags(ubdsrv_iod);
	iod->len = ubdsrv_iod->sectors * block_size;
	iod->off = ubdsrv_iod->start_sector * block_size;
}

static inline unsigned int ubdsrv_get_tag(
			unsigned long long user_data)
{
	return user_data & 0x7fffffff;
}

static inline unsigned int ubdsrv_get_cmd_op(
			unsigned long long user_data)
{
	return (user_data >> 32) & 0x7fffffff;
}

static inline unsigned long long ubdsrv_set_user_data(
			unsigned long tag, unsigned long cmd_op)
{
	return tag | (cmd_op << 32);
}

/*******************private io cmd func ********************************/

static inline unsigned prep_queue_io_cmd(struct ubdsrv_queue *q)
{
	struct ubdsrv_uring *ring = &q->ring;
	struct io_sq_ring *sq_ring = &ring->sq_ring;

	return *sq_ring->tail;
}

static inline void commit_queue_io_cmd(struct ubdsrv_queue *q, 
		unsigned tail)
{
	struct ubdsrv_uring *ring = &q->ring;
	struct io_sq_ring *sq_ring = &ring->sq_ring;

	atomic_store_release(sq_ring->tail, tail);
}

static inline void prep_io_cmd(struct io_uring_sqe *sqe,
		unsigned q_id, unsigned tag,
		unsigned long cmd_op,
		char* io_buf,
		int io_result)
{
	struct ubdsrv_io_cmd *cmd = (struct ubdsrv_io_cmd *)&sqe->cmd;

	/* io_buf MUST be provided by app for UBD_IO_GET_DATA */
	/* io_buf MAY be provided by app for UBD_IO_COMMIT_AND_FETCH_REQ */
	__WRITE_ONCE(cmd->addr, (__u64)io_buf);
	/* io_result is valid only for UBD_IO_COMMIT_AND_FETCH_REQ */
	__WRITE_ONCE(cmd->result, io_result);
	__WRITE_ONCE(cmd->tag, tag);
	__WRITE_ONCE(cmd->q_id, q_id);

	/* 0 is index of io_uring registered fd: dev->ubdc_dev_fd */
	__WRITE_ONCE(sqe->fd, 0);
	__WRITE_ONCE(sqe->user_data, ubdsrv_set_user_data(tag, cmd_op));
	__WRITE_ONCE(sqe->cmd_op, cmd_op);
	__WRITE_ONCE(sqe->cmd_len, sizeof(*cmd));
	__WRITE_ONCE(sqe->opcode, IORING_OP_URING_CMD);
}

/*
 * queue io command with @tag to ring
 *
 * fix me: batching submission
 */
static int queue_io_cmd(struct ubdsrv_queue *q, 
		unsigned tail, unsigned tag,
		unsigned long cmd_op,
		char* io_buf,
		int io_result)
{
	struct ubdsrv_uring *ring = &q->ring;
	struct io_sq_ring *sq_ring = &ring->sq_ring;
	unsigned index, next_tail = tail + 1;
	struct io_uring_sqe *sqe;

	if (next_tail == atomic_load_acquire(sq_ring->head))
		return -1;

	index = tail & ring->sq_ring_mask;
	/* IORING_SETUP_SQE128 */
	sqe = io_uring_get_sqe(ring, index, true);

	prep_io_cmd(sqe, q->q_id, tag, cmd_op,
			io_buf, io_result);
	
	sq_ring->array[index] = index;

	return 0;
}

static void ubdsrv_init_queue_io_cmds(struct ubdsrv_queue *q)
{
	struct ubdsrv_uring *ring = &q->ring;
	struct io_uring_sqe *sqe;
	int i;

	for (i = 0; i < ring->ring_depth; i++) {
		sqe = io_uring_get_sqe(ring, i, true);

		/* These fields should be written once, never change */
		__WRITE_ONCE(sqe->flags, IOSQE_FIXED_FILE);
		__WRITE_ONCE(sqe->ioprio, 0);
		__WRITE_ONCE(sqe->off, 0);
	}
}

/*******************private io cmd func ********************************/

/*******************private ctrl dev cmd func ********************************/

static inline void prep_ctrl_cmd(struct io_uring_sqe *sqe,
		struct ubdlib_ctrl_dev *ctrl_dev, 
		unsigned cmd_op, char *buf, int buf_len)
{
	struct ubdsrv_ctrl_dev_info *info = &ctrl_dev->dev_info;
	unsigned int dev_id = ctrl_dev->dev_info.dev_id;

	sqe->fd = ctrl_dev->ctrl_dev_fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = ubdsrv_set_user_data(dev_id, cmd_op);
	sqe->ioprio = 0;
	sqe->off = 0;
	sqe->cmd_op = cmd_op;
	sqe->cmd_len = sizeof(*info);
	
	if (buf) {
		info->addr = (__u64)buf;
		info->len = buf_len;
	}

	memcpy((void *)&sqe->cmd, info, sizeof(*info));
}

static int queue_ctrl_cmd(struct ubdlib_ctrl_dev *ctrl_dev, 
		unsigned int cmd_op,
		char *buf, int buf_len)
{
	struct ubdsrv_uring *ring = &ctrl_dev->ring;
	struct io_sq_ring *sq_ring = &ring->sq_ring;
	unsigned index, tail, next_tail;
	struct io_uring_sqe *sqe;

	next_tail = tail = *sq_ring->tail;
	next_tail++;

	if (next_tail == atomic_load_acquire(sq_ring->head))
		return -1;

	index = tail & ring->sq_ring_mask;
	
	/* IORING_SETUP_SQE128 */
	sqe = io_uring_get_sqe(ring, index, true);

	prep_ctrl_cmd(sqe, ctrl_dev, cmd_op, buf, buf_len);

	sq_ring->array[index] = index;
	
	tail = next_tail;

	atomic_store_release(sq_ring->tail, tail);

	return 0;
}

static int reap_ctrl_events(struct ubdsrv_uring *ring, int *cmd_res)
{
	struct io_cq_ring *cq_ring = &ring->cq_ring;
	struct io_uring_cqe *cqe;
	unsigned head, reaped = 0;
	unsigned int dev_id, cmd_op;

	head = *cq_ring->head;
	do {
		read_barrier();
		if (head == atomic_load_acquire(cq_ring->tail))
			break;
		
		cqe = &cq_ring->cqes[head & ring->cq_ring_mask];
		
		dev_id = ubdsrv_get_tag(cqe->user_data);
		cmd_op = ubdsrv_get_cmd_op(cqe->user_data);
		if(cmd_res)
			*cmd_res = cqe->res;
		
		if(cqe->res < 0)
			fprintf(stderr, "%s: ctrl cqe res %d "
					"dev_id %d cmd_op %d\n",
					__func__, cqe->res, dev_id, cmd_op);
		
		reaped++;
		head++;
	} while (1);

	if (reaped)
		atomic_store_release(cq_ring->head, head);
	return reaped;
}

static int handle_ctrl_cmd(struct ubdlib_ctrl_dev *ctrl_dev,
		unsigned cmd_op, char *buf, int buf_len, int *cmd_res)
{
	int ret, reapped = 0;

	ret = queue_ctrl_cmd(ctrl_dev, cmd_op, buf, buf_len);
	if (ret) {
		fprintf(stderr, "can't queue cmd %x\n", cmd_op);
		return ret;
	}

	ret = io_uring_enter(&ctrl_dev->ring, 1, 1, IORING_ENTER_GETEVENTS);
	if(ret < 0) {
		fprintf(stderr, "%s: io_uring_enter failed\n", __func__);
		return ret;
	}
	
	reapped = reap_ctrl_events(&ctrl_dev->ring, cmd_res);

	if(reapped > 1)
		fprintf(stderr, "%s: reap more than one ctrl cqe\n", __func__);
	
	return reapped - ret;
}

/*******************private ctrl dev cmd func ********************************/

/*******************private io_uring func ********************************/

/* TODO: mmap() failure handling */
static int ubdsrv_io_uring_setup(struct ubdsrv_uring *ring, 
		unsigned flags, unsigned int features, int depth,
		struct iovec *base, int nr_buf)
{
	struct io_sq_ring *sq_ring = &ring->sq_ring;
	struct io_cq_ring *cq_ring = &ring->cq_ring;
	struct io_uring_params p;
	int fd;
	void *ptr;
	struct rlimit rlim;
	int mut = (flags & IORING_SETUP_SQE128) ? 2 : 1;

	memset(&p, 0, sizeof(p));

	p.flags |= flags;
	p.features |=features;

	fd = io_uring_setup(depth, &p);
	if (fd < 0)
		return -1;

	ring->ring_depth = p.sq_entries;
	ring->ring_fd = fd;

	//io_uring_probe(fd);

	if (nr_buf) {
		/* setup fixed buffers */
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;

		/* ignore potential error, not needed on newer kernels */
		setrlimit(RLIMIT_MEMLOCK, &rlim);
		if(io_uring_register_buffers(ring, base, nr_buf) < 0)
			return -1;
	}

	ptr = mmap(0, p.sq_off.array + p.sq_entries * sizeof(__u32),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQ_RING);
	sq_ring->head = ptr + p.sq_off.head;
	sq_ring->tail = ptr + p.sq_off.tail;
	sq_ring->ring_mask = ptr + p.sq_off.ring_mask;
	sq_ring->ring_entries = ptr + p.sq_off.ring_entries;
	sq_ring->flags = ptr + p.sq_off.flags;
	sq_ring->array = ptr + p.sq_off.array;
	ring->sq_ring_mask = *sq_ring->ring_mask;

	ring->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe)*mut,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQES);

	ptr = mmap(0, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	cq_ring->head = ptr + p.cq_off.head;
	cq_ring->tail = ptr + p.cq_off.tail;
	cq_ring->ring_mask = ptr + p.cq_off.ring_mask;
	cq_ring->ring_entries = ptr + p.cq_off.ring_entries;
	cq_ring->cqes = ptr + p.cq_off.cqes;
	ring->cq_ring_mask = *cq_ring->ring_mask;

	fprintf(stdout, "%s: depth %u sqs %u/%x cqs %u/%x "
			"flags %u features %d\n",
			__func__, depth,
			p.sq_entries, ring->sq_ring_mask,
			p.cq_entries, ring->cq_ring_mask,
			p.flags, p.features);

	return 0;
}

/*******************private io_uring func ********************************/


static int ubdsrv_queue_cmd_buf_sz(struct ubdsrv_queue *q)
{
	int size =  q->q_depth * sizeof(struct ubdsrv_io_desc);
	unsigned int page_sz = getpagesize();

	return round_up(size, page_sz);
}

static void ubdsrv_queue_deinit(struct ubdsrv_queue *q)
{
	if (!q)
		return;

	if (q->ring.ring_fd >= 0) {
		io_uring_unregister_files(&q->ring);
		close(q->ring.ring_fd);
		q->ring.ring_fd = -1;
	}
	if (q->io_cmd_buf) {
		munmap(q->io_cmd_buf, ubdsrv_queue_cmd_buf_sz(q));
		q->io_cmd_buf = NULL;
	}
	q->srv->queues[q->q_id] = NULL;
	free(q);
}

static int ubdsrv_queue_init(struct ubdlib_ubdsrv *srv, int q_id)
{
	struct ubdsrv_queue *q = NULL;
	struct ubdlib_ctrl_dev *ctrl_dev = srv->ctrl_dev;
	int queue_depth = ctrl_dev->dev_info.queue_depth;
	int i, ret = -1;
	int io_cmd_buf_size;
	unsigned long io_cmd_buf_off;
	int queue_size = sizeof(struct ubdsrv_queue) 
			+ sizeof(struct ubd_io)
			* ctrl_dev->dev_info.queue_depth;
	
	q = calloc(1, queue_size);
	if (!q)
		return ret;
	
	srv->queues[q_id] = q;
	
	q->srv = srv;
	q->q_id = q_id;
	/* FIXME: depth has to be PO 2 */
	q->q_depth = queue_depth;
	q->ring.ring_fd = -1;

	list_head_init(&q->need_commit_io_list);
	list_head_init(&q->need_get_data_io_list);

	io_cmd_buf_size = ubdsrv_queue_cmd_buf_sz(q);
	io_cmd_buf_off = UBDSRV_CMD_BUF_OFFSET + q_id 
			* (UBD_MAX_QUEUE_DEPTH * sizeof(struct ubdsrv_io_desc));
	
	q->io_cmd_buf = mmap(0, io_cmd_buf_size, PROT_READ,
			MAP_SHARED | MAP_POPULATE, srv->ubdc_dev_fd, io_cmd_buf_off);
	if (q->io_cmd_buf == MAP_FAILED) {
		q->io_cmd_buf = NULL;
		goto fail;
	}
	
	for (i = 0; i < queue_depth; i++) {
		/* 
		 * 1) IO buffer for each request is allocated 
		 *    until application actually allocates it
		 * 
		 * 2) the first req to ubd_drv should not carry buf addr 
		 */
		q->ios[i].buf_addr = NULL;
		q->ios[i].tag = i;
	}

	ret = ubdsrv_io_uring_setup(&q->ring, IORING_SETUP_SQE128,
			IORING_FEAT_EXT_ARG ,queue_depth, NULL, 0);
	if (ret)
		goto fail;

	ret = io_uring_register_files(&q->ring, &srv->ubdc_dev_fd, 1);
	if (ret)
		goto fail;

	ubdsrv_init_queue_io_cmds(q);

	return ret;
 fail:
	ubdsrv_queue_deinit(q);
	return ret;
}

void ubdlib_set_io_buf_addr(struct ubdlib_ubdsrv *srv,
		int q_id, unsigned tag, char *io_buf_addr) 
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	q->ios[tag].buf_addr = io_buf_addr;
}

void ubdlib_complete_io_request(struct ubdlib_ubdsrv *srv,
		int q_id, int tag, int res)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	struct ubd_io *io = &q->ios[tag];

	DEBUG_OUTPUT(assert(q->tgt_io_inflight > 0));
	
	q->tgt_io_inflight -= 1;

	io->result = res;
	
	/* Mark this IO as free and ready for issuing to ubd driver */
	list_add_tail(&q->need_commit_io_list, &io->io_list_entry);
}

void ubdlib_need_get_data(struct ubdlib_ubdsrv *srv, int q_id,
		int tag)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	struct ubd_io *io = &q->ios[tag];

	q->tgt_io_inflight -= 1;
		
	list_add_tail(&q->need_get_data_io_list, &io->io_list_entry);
}

int ubdlib_ubdsrv_queue_is_done(struct ubdlib_ubdsrv *srv, int q_id)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	
	DEBUG_OUTPUT(fprintf(stdout, "%s: qid %d stop %d "
			"cmd inflight %d tgt io inflight %d\n",
			__func__, q_id, q->stopping,
			q->cmd_inflight, q->tgt_io_inflight));

	return q->stopping 
			&& (!q->cmd_inflight && !q->tgt_io_inflight);
}

int ubdlib_reap_io_events(struct ubdlib_ubdsrv *srv, int q_id,
		void (*handle_io_event)(
				struct ubdlib_ubdsrv *srv,
				int q_id,
				int tag,
				const struct libubd_io_desc *iod,
				void *data),
			void *data)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	struct ubdsrv_uring *ring = &q->ring;
	struct io_cq_ring *cq_ring = &ring->cq_ring;
	struct io_uring_cqe *cqe;
	struct libubd_io_desc iod;
	unsigned head;
	unsigned reaped = 0;
	int tag;
	unsigned last_cmd_op;

	head = *cq_ring->head;
	do {
		read_barrier();
		if (head == atomic_load_acquire(cq_ring->tail))
			break;
		cqe = &cq_ring->cqes[head & ring->cq_ring_mask];
		reaped++;

		DEBUG_OUTPUT(assert(q->cmd_inflight > 0));
		
		q->cmd_inflight -= 1;

		tag = ubdsrv_get_tag(cqe->user_data);
		last_cmd_op = ubdsrv_get_cmd_op(cqe->user_data);
		
		/* must first check whether ubd_drv is stopped */
		if(cqe->res == UBD_IO_RES_ABORT) {
			q->stopping = 1;
			
			DEBUG_OUTPUT(fprintf(stdout, 
					"%s: get UBD_IO_RES_ABORT on tag %d, "
					"stop q_id %d now\n",
					__func__, tag, q_id));
			
			/* this io won't be issued any more */		
			head++;
			continue;
		}
		
		/* only let app handle valid ubd io */
		if (cqe->res < 0) {
			fprintf(stderr, "%s: io cqe res %d "
					"tag %d cmd_op %d\n",
					__func__, cqe->res, 
					tag, last_cmd_op);
			/* this io won't be issued any more */		
			head++;
			continue;
		}

		q->tgt_io_inflight += 1;

		ubdsrv_get_iod(q, tag, last_cmd_op, &iod);

		if (handle_io_event)
			handle_io_event(srv, q_id, tag, &iod, data);
		head++;
	} while (1);

	if (reaped)
		atomic_store_release(cq_ring->head, head);
	return reaped;
}

/* only used in the first round */
int ubdlib_fetch_io_requests(struct ubdlib_ubdsrv *srv, int q_id)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	int tail = prep_queue_io_cmd(q);
	unsigned int cnt;

	for (cnt = 0; cnt < q->q_depth; cnt++) {		
		if (queue_io_cmd(q, tail + cnt, cnt, 
				UBD_IO_FETCH_REQ, NULL, 0) < 0){
			/* the sq_ring may be full */
			fprintf(stderr, "%s: sq_ring is full\n", __func__);
			break;
		}
	}
	
	q->cmd_inflight += cnt;
	
	commit_queue_io_cmd(q, tail + cnt);

	return cnt;
}

/*
 * Issue all available commands to /dev/ubdcN  and the exact cmd is figured
 * out in queue_io_cmd with help of each io->status.
 *
 * todo: queue io commands with batching
 */
int ubdlib_commit_fetch_io_requests(struct ubdlib_ubdsrv *srv, int q_id)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	int tail = prep_queue_io_cmd(q);
	unsigned int cnt = 0;
	struct ubd_io *io, *io_next;

	list_for_each_safe(&q->need_get_data_io_list,
			io, io_next, io_list_entry) {		
		
		if(queue_io_cmd(q, tail + cnt, io->tag,
				UBD_IO_GET_DATA, io->buf_addr, 0) < 0) {
			/* the sq_ring may be full */
			fprintf(stderr, "%s: sq_ring is full\n", __func__);
			break;
		}

		cnt++;
		list_del_init(&io->io_list_entry);			
	}

	list_for_each_safe(&q->need_commit_io_list,
			io, io_next, io_list_entry) {

		if(queue_io_cmd(q, tail + cnt, io->tag,
				UBD_IO_COMMIT_AND_FETCH_REQ, 
				io->buf_addr, io->result) < 0) {
			/* the sq_ring may be full */
			fprintf(stderr, "%s: sq_ring is full\n", __func__);
			break;
		}

		cnt++;
		list_del_init(&io->io_list_entry);			
	}

	if(!list_empty(&q->need_get_data_io_list) ||
			!list_empty(&q->need_commit_io_list))
		fprintf(stderr, "%s: io lists of q_id %d are not empty\n",
				__func__, q->q_id);

	if (cnt > 0) {
		q->cmd_inflight += cnt;
		commit_queue_io_cmd(q, tail + cnt);
	}

	return cnt;
}

int ubdlib_io_uring_enter(struct ubdlib_ubdsrv *srv, int q_id, 
		unsigned int to_submit, unsigned int min_complete,
		unsigned int flags)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	
	return io_uring_enter(&q->ring, to_submit, min_complete,
			flags | IORING_ENTER_GETEVENTS);
}

int ubdlib_io_uring_enter_timeout(struct ubdlib_ubdsrv *srv, int q_id, 
		unsigned int to_submit, unsigned int min_complete,
		unsigned int flags, unsigned int timeout_usec)
{
	struct ubdsrv_queue *q = srv->queues[q_id];
	
	return io_uring_enter_timeout(&q->ring, to_submit, min_complete,
			flags | IORING_ENTER_GETEVENTS|IORING_ENTER_EXT_ARG,
			timeout_usec);
}

void ubdlib_ubdsrv_deinit(struct ubdlib_ubdsrv *srv)
{
	int nr_queues = srv->ctrl_dev->dev_info.nr_hw_queues;
	int i;

	for (i = 0; i < nr_queues; i++)
		ubdsrv_queue_deinit(srv->queues[i]);

	if (srv->ubdc_dev_fd >= 0) {
		close(srv->ubdc_dev_fd);
		srv->ubdc_dev_fd = -1;
	}
	free(srv);
}

struct ubdlib_ubdsrv *ubdlib_ubdsrv_init(struct ubdlib_ctrl_dev *ctrl_dev)
{
	struct ubdlib_ubdsrv *srv;
	int nr_queues = ctrl_dev->dev_info.nr_hw_queues;
	int dev_id = ctrl_dev->dev_info.dev_id;
	char buf[64];
	int i;

	srv = calloc(1, sizeof(*srv));
	if(!srv)
		return NULL;

	srv->ctrl_dev = ctrl_dev;
	srv->ubdc_dev_fd = -1;

	snprintf(buf, 64, "%s%d", UBDC_DEV, dev_id);
	srv->ubdc_dev_fd = open(buf, O_RDWR);
	if (srv->ubdc_dev_fd < 0)
		goto init_fail;

	for (i = 0; i < nr_queues; i++) {
		if (ubdsrv_queue_init(srv, i))
			goto init_fail;
	}

	return srv;
init_fail:
	ubdlib_ubdsrv_deinit(srv);
	return NULL;
}

int ubdlib_get_ctrl_nr_queues(struct ubdlib_ctrl_dev *ctrl_dev)
{
	return ctrl_dev->dev_info.nr_hw_queues;
}

int ubdlib_get_ctrl_dev_id(struct ubdlib_ctrl_dev *ctrl_dev)
{
	return ctrl_dev->dev_info.dev_id;
}

/* 
 * close io_uring(only for control-path), ctrl_dev_fd(/dev/ubd-control)
 * and free ctrl_dev
 */
void ubdlib_ctrl_dev_deinit(struct ubdlib_ctrl_dev *ctrl_dev)
{
	if(!ctrl_dev)
		return;

	if(ctrl_dev->ring.ring_fd >= 0) {
		close(ctrl_dev->ring.ring_fd);
		ctrl_dev->ring.ring_fd = -1;
	}

	if(ctrl_dev->ctrl_dev_fd >= 0) {
		close(ctrl_dev->ctrl_dev_fd);
		ctrl_dev->ctrl_dev_fd = -1;
	}

	free(ctrl_dev);
}

/*
 * dev_id: -1 means we ask ubd_drv to allocate one free id
 * init ctrl_dev(for send CONTROL reqs such as UBD_CMD_START_DEV)
 */
struct ubdlib_ctrl_dev *ubdlib_ctrl_dev_init(
                int dev_id,
                unsigned short nr_queues,
                unsigned short queue_depth,
                unsigned long long dev_size, 
                unsigned int rq_max_buf_size,
                bool zcopy)
{
	struct ubdlib_ctrl_dev         *ctrl_dev;
        struct ubdsrv_ctrl_dev_info    *info;

        ctrl_dev = calloc(1, sizeof(*ctrl_dev));
        if (!ctrl_dev)
		return NULL;

	ctrl_dev->ctrl_dev_fd = -1;
	ctrl_dev->ring.ring_fd = -1;
	
	ctrl_dev->ctrl_dev_fd = open(UBD_CONTROL_DEV, O_RDWR);
	if(ctrl_dev->ctrl_dev_fd < 0) {
		fprintf(stderr, "%s: Cannot open ubd control dev(%s). "
				"Please ensure that ubd kernel mod is loaded "
				"and root privilege is acquired.\n",
				__func__, UBD_CONTROL_DEV);
		goto init_fail;
	}
	
        info = &ctrl_dev->dev_info;

	if (zcopy)
		info->flags = (1ULL << UBD_F_SUPPORT_ZERO_COPY);

	if (!nr_queues || nr_queues > MAX_NR_HW_QUEUES)
		nr_queues = MAX_NR_HW_QUEUES;
        
        if (!queue_depth || queue_depth > MAX_QD)
		queue_depth = MAX_QD;
        
        if(!rq_max_buf_size || rq_max_buf_size > RQ_MAX_BUF_SIZE)
                rq_max_buf_size = RQ_MAX_BUF_SIZE;

	info->dev_id = dev_id;
	info->nr_hw_queues = nr_queues;
	info->queue_depth = queue_depth;
	info->block_size = zcopy ? UBD_BLOCK_SIZE_ZC : UBD_BLOCK_SIZE;
	info->rq_max_blocks = rq_max_buf_size / info->block_size;
    info->dev_blocks = dev_size / info->block_size;
	

	/* this uring is only for ctrl commands, not IO commands */
	if (ubdsrv_io_uring_setup(&ctrl_dev->ring, IORING_SETUP_SQE128, 
			0, UBD_CTRL_DEV_URING_DEPTH, NULL, 0))
		goto init_fail;
		
	return ctrl_dev;

init_fail:
	ubdlib_ctrl_dev_deinit(ctrl_dev);
	
	return NULL;
}

int ubdlib_dev_add(struct ubdlib_ctrl_dev *ctrl_dev)
{
	int ret;
	int cmd_res = 0;
	int number = ctrl_dev->dev_info.dev_id;

	ret = handle_ctrl_cmd(ctrl_dev, UBD_CMD_ADD_DEV,
			(char *)&ctrl_dev->dev_info,
			sizeof(ctrl_dev->dev_info), &cmd_res);
	if (ret < 0)
		fprintf(stderr, "%s: can't add dev %d, cmd res %d\n",
				__func__, number, cmd_res);
	
	return ret;
}

int ubdlib_dev_start(struct ubdlib_ctrl_dev *ctrl_dev)
{
	int ret;
	int cmd_res = 0;
	int number = ctrl_dev->dev_info.dev_id;

	ret = handle_ctrl_cmd(ctrl_dev, UBD_CMD_START_DEV, NULL, 0, &cmd_res);
	if (ret < 0)
		fprintf(stderr, "%s: can't start dev %d, cmd res %d\n",
				__func__, number, cmd_res);
	
	return ret;
}

/* get updated dev_info(will be stored in ctrl_dev) from ubd_drv */
int ubdlib_dev_get_info(struct ubdlib_ctrl_dev *ctrl_dev)
{
	int ret;
	int cmd_res = 0;
	int number = ctrl_dev->dev_info.dev_id;

	ret = handle_ctrl_cmd(ctrl_dev, UBD_CMD_GET_DEV_INFO,
			(char *)&ctrl_dev->dev_info,
			sizeof(ctrl_dev->dev_info), &cmd_res);
	if (ret < 0)
		fprintf(stderr, "%s: can't get dev(id: %d) info, cmd res %d, "
				"device may not exist\n", __func__, number, cmd_res);	
	return ret;
}

int ubdlib_dev_stop(struct ubdlib_ctrl_dev *ctrl_dev)
{
	int ret;
	int cmd_res = 0;
	int number = ctrl_dev->dev_info.dev_id;

	ret = handle_ctrl_cmd(ctrl_dev, UBD_CMD_STOP_DEV, NULL, 0, &cmd_res);
	if (ret < 0)
		fprintf(stderr, "%s: can't stop dev %d, cmd res %d\n",
				__func__, number, cmd_res);
	
	return ret;
}

int ubdlib_dev_del(struct ubdlib_ctrl_dev *ctrl_dev)
{
	int ret;
	int cmd_res;
	int number = ctrl_dev->dev_info.dev_id;
	
	ret = handle_ctrl_cmd(ctrl_dev, UBD_CMD_DEL_DEV, NULL, 0, &cmd_res);
	if (ret < 0)
		fprintf(stderr, "%s: can't delete dev %d, cmd res %d\n",
				__func__, number, cmd_res);
	
	return ret;
}
