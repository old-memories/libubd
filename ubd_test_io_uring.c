#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <liburing.h>

#include "libubd.h"
#include "ubd_cmd.h"

#define DEF_NR_Q 1

#define MAX_NR_Q 4

#define DEF_QD 64

#define MAX_QD 64

#define TEST_RQ_MAX_BUF_SIZE (1024 * 1024)

#define UBDSRV_URING_TIMEOUT_US 1000 * 1000 * 1

#define UBDSRV_START_TIMEOUT_S 3

struct ubd_test_data {
    int backing_file_fd;
    int nr_queues;
    int queue_depth;
    void *io_buf;
};

struct ubd_test_queue_ring_data {
    struct io_uring *ring;
    int io_uring_submit_nr;
};

struct ubd_test_srv_queue_thread_data {
    struct ubdlib_ubdsrv *srv;
    int q_id;
    int dev_id;
    pthread_t tid;
    struct io_uring ring;
};

static char test_exe[256];

static int ubdsrv_started;

static volatile sig_atomic_t keep_running = 1;

static struct ubd_test_data test_data = {
    .backing_file_fd = -1
};

static void *test_get_io_buf(int q_id, int tag)
{
    int nr_queues = test_data.nr_queues;
    int queue_depth = test_data.queue_depth;

    unsigned int idx = (q_id * nr_queues + tag) * TEST_RQ_MAX_BUF_SIZE;

    assert(queue_depth > tag);

    return test_data.io_buf + idx;
}

static void test_io_uring_submit_and_complete(struct ubdlib_ubdsrv *srv,
        int q_id, struct ubd_test_queue_ring_data *ring_data)
{
    int i, ret;
    int to_submit = ring_data->io_uring_submit_nr;
    struct io_uring_cqe *cqe;
    struct io_uring *ring = ring_data->ring;

    ret = io_uring_submit(ring);
    if(ret < 0) {
        fprintf(stderr, "%s: Error in submission: %s\n",
                __func__, strerror(-ret));
        exit(1);
    }

    for(i = 0; i < to_submit; i++) {
        ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0) {
            fprintf(stderr, "%s: Error waiting for completion: %s\n",
                    __func__, strerror(-ret));
            exit(1);
        }
        /* Now that we have the CQE, let's process the data */
        if (cqe->res < 0)
            fprintf(stderr, "%s: Error in async operation: %s\n",
                    __func__, strerror(-cqe->res));

        DEBUG_OUTPUT(fprintf(stdout, 
                "%s: complete req, q_id %d tag %d res %d\n",
                __func__, q_id, (int)cqe->user_data, cqe->res));

        ubdlib_complete_io_request(srv, q_id, 
                cqe->user_data, cqe->res);
        
        io_uring_cqe_seen(ring, cqe);
    }
}

static void test_submit_io_uring(struct ubdlib_ubdsrv *srv,
        int q_id,
        int tag,
        const struct libubd_io_desc *iod,
        void *data)
{
    struct ubd_test_queue_ring_data *ring_data = data;
    struct io_uring *ring = ring_data->ring;
    int fd = test_data.backing_file_fd;
    int io_uring_submit_nr = ring_data->io_uring_submit_nr;

    DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d tag %d "
            "io opcode %d len %d off %lld "
            "flags %d need_buf_addr %d\n",
            __func__, q_id, tag,
            iod->op, iod->len, iod->off, iod->flags, 
            iod->need_buf_addr));

    switch(iod->op) {
    case UBD_IO_OP_READ:
        assert(iod->need_buf_addr == 1);
        assert(iod->len <= TEST_RQ_MAX_BUF_SIZE);

        ubdlib_set_io_buf_addr(srv, q_id, tag, test_get_io_buf(q_id, tag));
        
        /* Get an SQE */
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        /* Setup a read operation */
        io_uring_prep_read(sqe, fd, test_get_io_buf(q_id, tag), 
                iod->len, iod->off);
        /* Set user data */
        sqe->user_data = tag;
        io_uring_submit_nr++;
        break;
    case UBD_IO_OP_WRITE:
        assert(iod->len <= TEST_RQ_MAX_BUF_SIZE);

        if(iod->need_buf_addr) {
            ubdlib_set_io_buf_addr(srv, q_id, tag, test_get_io_buf(q_id, tag));
            ubdlib_need_get_data(srv, q_id, tag);
            DEBUG_OUTPUT(fprintf(stdout, 
                    "%s: set buf for WRITE req, q_id %d tag %d\n",
                    __func__, q_id, tag));
        } else {           
            /* Get an SQE */
            struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
            /* Setup a write operation */
            io_uring_prep_write(sqe, fd, test_get_io_buf(q_id, tag), 
                    iod->len, iod->off);            
            /* Set user data */
            sqe->user_data = tag;
            io_uring_submit_nr++;
        }
        break;
    default:
        fprintf(stdout, "%s: op %d not supported, q_id %d tag %d\n",
                __func__, iod->op, q_id, tag);
        ubdlib_complete_io_request(srv, q_id, tag, 0);
        break;    
    }

    ring_data->io_uring_submit_nr = io_uring_submit_nr;

}

static void ubd_test_sig_handler(int sig)
{
	if (sig == SIGINT) {
		fprintf(stdout, "%s: got SIGINT signal\n", __func__);
	}
    keep_running = 0;
}

static int open_backing_file(char *backing_file, int flags,
        unsigned long long *dev_size)
{
	unsigned long long bytes;
	struct stat st;
	int fd = -1;

	if (!backing_file || !dev_size)
		return -1;

    fd = open(backing_file, flags);
	if (fd < 0) {
		fprintf(stderr, "%s: backing file %s can't be opened: %s\n",
                __func__, backing_file, strerror(errno));
		return -2;
	}

	if (fstat(fd, &st) < 0)
		return -2;

	if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;
	} else if (S_ISREG(st.st_mode)) {
		bytes = st.st_size;
	} else {
        bytes = 0;
	}

    *dev_size = bytes;

	return fd;
}

void *ubdsrv_queue_loop(void *data)
{
    struct ubd_test_srv_queue_thread_data *queue_thread_data = data;
    struct ubdlib_ubdsrv *srv = queue_thread_data->srv;
    int dev_id = queue_thread_data->dev_id;
    int q_id = queue_thread_data->q_id;
    int to_submit, submitted, reapped;
    char pthread_name[32];
    
    struct ubd_test_queue_ring_data ring_data = {
        .io_uring_submit_nr = 0,
        .ring = &queue_thread_data->ring
    };

    snprintf(pthread_name, 32, "ubd%d_q%d_thread",
            dev_id, q_id);

    pthread_setname_np(pthread_self(), pthread_name);

    fprintf(stdout, "start ubdsrv queue %d thread %ld %s\n",
            q_id, syscall(SYS_gettid), pthread_name);
	
    to_submit = ubdlib_fetch_io_requests(srv, q_id);

	do {
        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d to_submit %d\n",
				__func__, q_id, to_submit));

        if (ubdlib_ubdsrv_queue_is_done(srv, q_id))
			break;
		
        submitted = ubdlib_io_uring_enter(srv, q_id,
                to_submit, 1, 0);

        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d submitted %d\n",
				__func__, q_id, submitted));
		
        /* For each io request, call test_submit_io_uring() and queue a sqe
         * if necessary.
         */
        reapped = ubdlib_reap_io_events(srv, q_id,
                test_submit_io_uring, NULL, &ring_data);
	    
        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d reapped %d\n",
				__func__, q_id, reapped));
        
        /* Now we get sqes queued, let's submit them and wait for cqes */
        if(ring_data.io_uring_submit_nr > 0)
            test_io_uring_submit_and_complete(srv, q_id, &ring_data);
        
        ring_data.io_uring_submit_nr = 0;
        
        to_submit = ubdlib_commit_fetch_io_requests(srv, q_id);
	} while (1);
	
	fprintf(stdout, "%s: queue %d exited.\n",
				__func__, q_id);

	return NULL;
}

void *ubdsrv_loop(void *data)
{
    struct ubdlib_ctrl_dev *ctrl_dev = data;
    struct ubdlib_ubdsrv *srv = NULL;
    int nr_queues = ubdlib_get_ctrl_nr_queues(ctrl_dev);
    struct ubd_test_srv_queue_thread_data *queue_thread_data_arr;
    int i;
    int dev_id;
    char pthread_name[32];

    queue_thread_data_arr = calloc(nr_queues, sizeof(*queue_thread_data_arr));

    assert(queue_thread_data_arr);

    dev_id = ubdlib_get_ctrl_dev_id(ctrl_dev);

    snprintf(pthread_name, 32, "ubd%d_thread", dev_id);

    pthread_setname_np(pthread_self(), pthread_name);

    fprintf(stdout, "start ubdsrv thread %ld %s\n",
            syscall(SYS_gettid), pthread_name);
    
    srv = ubdlib_ubdsrv_init(ctrl_dev);
    if(!srv)
        exit(1);

    for (i = 0; i < nr_queues; i++) {
        queue_thread_data_arr[i].dev_id = dev_id;
        queue_thread_data_arr[i].q_id = i;
        queue_thread_data_arr[i].srv = srv;
        
        io_uring_queue_init(MAX_QD, &queue_thread_data_arr[i].ring, 0);
        
        pthread_create(&queue_thread_data_arr[i].tid, NULL, 
			ubdsrv_queue_loop, &queue_thread_data_arr[i]);
    }

	fprintf(stdout, "%s: all ubdsrv_queue_loop running\n", __func__);

    ubdsrv_started = 1;

	for(i = 0; i < nr_queues; i++) {
		pthread_join(queue_thread_data_arr[i].tid, NULL);
		fprintf(stdout, "%s: thread of q_id %d joined\n", 
				__func__, i);
        io_uring_queue_exit(&queue_thread_data_arr[i].ring);
	}

	fprintf(stdout, "%s: all ubdsrv_queue_loop exited\n", __func__);
	
	ubdlib_ubdsrv_deinit(srv);


    free(queue_thread_data_arr);

    return NULL;
}

static const struct option longopts[] = {
    { "dev_id",		1,	NULL, 'n' },
    { "nr_queues",             1,      NULL, 'q' },
    { "queue_depth",              1,      NULL, 'd' },
    { "backing_file",		1,	NULL, 'f' },
    { "help",		0,	NULL, 'h' },
    { NULL }
};

static void test_usage(char *exe)
{
    fprintf(stdout, "%s: -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH "
            "-f BACKING_FILE\n,",
            exe);
}

int main(int argc, char **argv)
{    
    struct ubdlib_ctrl_dev *ctrl_dev;
    int ret = 0;
    int cnt = 0;
    pthread_t ubdsrv_tid;
    int dev_id = -1;
	unsigned short nr_queues = DEF_NR_Q;
	unsigned short queue_depth = DEF_QD;
    char *backing_file = NULL;
    unsigned long long dev_size = 0;
    int opt;

    strncpy(test_exe, argv[0], 256);
    
    if(argc < 2) {
        fprintf(stderr, "%s: must provide args\n", argv[0]);
        exit(1);
    }

	while ((opt = getopt_long(argc, argv, "n:q:d:f:h",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			dev_id = strtol(optarg, NULL, 10);
			break;
		case 'q':
			nr_queues = strtol(optarg, NULL, 10);
			break;
		case 'd':
			queue_depth = strtol(optarg, NULL, 10);
			break;
		case 'f':
			backing_file = strdup(optarg);
			break;
        case 'h':
        default:
            test_usage(test_exe);
            exit(0);
		}
	}

    if(nr_queues > MAX_NR_Q)
        nr_queues = MAX_NR_Q;
    
    if(queue_depth > MAX_QD)
        queue_depth = MAX_QD;

    if((test_data.backing_file_fd = open_backing_file(
                backing_file, O_RDWR|O_DIRECT, &dev_size)) < 0) {
        fprintf(stderr, "%s: failed to open backing file %s",
                __func__, backing_file);
        exit(1);
    }

    assert(!posix_memalign(&test_data.io_buf, getpagesize(),
            nr_queues * queue_depth * TEST_RQ_MAX_BUF_SIZE));
        
    test_data.nr_queues = nr_queues;
    test_data.queue_depth = queue_depth;
    
    ctrl_dev = ubdlib_ctrl_dev_init(dev_id, nr_queues, queue_depth, dev_size,
            TEST_RQ_MAX_BUF_SIZE, false);
    if(!ctrl_dev)
        exit(1);

    ret = ubdlib_dev_add(ctrl_dev);
    if(ret)
        exit(1);

    pthread_create(&ubdsrv_tid, NULL, ubdsrv_loop, ctrl_dev);

    do {
        usleep(100000);
        cnt++;
	} while (!ubdsrv_started && cnt < UBDSRV_START_TIMEOUT_S * 10);

    ret = ubdlib_dev_start(ctrl_dev);
    if(ret)
        exit(1);

    fprintf(stdout, "---------------------------\n"
            "ubdsrv is running now.\n"
            "dev_id %d, nr_queues %d, depth %d, dev_size %lld, "
            "rq_max_buf_size %d\n"
            "---------------------------\n",
            ubdlib_get_ctrl_dev_id(ctrl_dev),
            nr_queues,
            queue_depth,
            dev_size,
            TEST_RQ_MAX_BUF_SIZE);

    
    if (signal(SIGINT, ubd_test_sig_handler) == SIG_ERR)
		exit(1);
    
    while(keep_running)
        usleep(1 * 1000 * 1000);
    
    fprintf(stdout, "---------------------------\n"
            "get CTRL-C signal, ubd_test is exiting now...\n"
            "---------------------------\n");
  
    ret = ubdlib_dev_get_info(ctrl_dev);
    if(ret)
        exit(1);

    ret = ubdlib_dev_stop(ctrl_dev);
    if(ret)
        exit(1);

    pthread_join(ubdsrv_tid, NULL);

    free(test_data.io_buf);

    close(test_data.backing_file_fd);

    fprintf(stdout, "%s: ubdsrv exited.\n", __func__);

    ret = ubdlib_dev_del(ctrl_dev);

    fprintf(stdout, "---------------------------\n"
            "%s: kernel ubd resources have been released.\n"
            "---------------------------\n"
            , __func__);

    ubdlib_ctrl_dev_deinit(ctrl_dev);

    fprintf(stdout, "%s: %s: exited.\n", argv[0], __func__);

    return 0;
}