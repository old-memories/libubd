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

struct ubd_test_srv_queue_thread_data {
    struct ubdlib_ubdsrv *srv;
    int q_id;
    int dev_id;
    pthread_t tid;
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

static void test_hande_io(struct ubdlib_ubdsrv *srv,
        int q_id,
        int tag,
        const struct libubd_io_desc *iod,
        void *data)
{
    int ret = 0;

    assert(data == NULL);

    DEBUG_OUTPUT(fprintf(stdout, "%s: io opcode %d len %d off %lld "
            "flags %d need_buf_addr %d\n", __func__, 
            iod->op, iod->len, iod->off, iod->flags, 
            iod->need_buf_addr));

    switch(iod->op) {
    case UBD_IO_OP_READ:
        assert(iod->need_buf_addr == 1);
        assert(iod->len <= TEST_RQ_MAX_BUF_SIZE);

        ubdlib_set_io_buf_addr(srv, q_id, tag, test_get_io_buf(q_id, tag));
        
        ret = pread(test_data.backing_file_fd, test_get_io_buf(q_id, tag), 
                iod->len, iod->off);
        if(ret < 0)
            fprintf(stderr, "%s: read failed on q_id %d tag %d "
                    "fd %d io opcode %d len %d off %lld flags %d "
                    ", errno %s\n",
                    __func__, q_id, tag,
                    test_data.backing_file_fd,
                    iod->op, iod->len, iod->off, iod->flags,
                    strerror(errno));
        
        DEBUG_OUTPUT(fprintf(stdout, 
                "%s: complete READ req, q_id %d tag %d\n",
                __func__, q_id, tag));

        ubdlib_complete_io_request(srv, q_id, tag, ret);
        break;
    case UBD_IO_OP_WRITE:
        assert(iod->len <= TEST_RQ_MAX_BUF_SIZE);

        /* ubd_drv issues a WRITE req, so ubdsrv provides buf addr now */
        if(iod->need_buf_addr) {
            ubdlib_set_io_buf_addr(srv, q_id, tag, test_get_io_buf(q_id, tag));
            ubdlib_need_get_data(srv, q_id, tag);
            /* will return to ubd_drv to copy data from biovec to user buf */
            DEBUG_OUTPUT(fprintf(stdout, 
                    "%s: set buf for WRITE req, q_id %d tag %d\n",
                    __func__, q_id, tag));
        } else {           
            ret = pwrite(test_data.backing_file_fd, test_get_io_buf(q_id, tag),
                    iod->len, iod->off);
            if(ret < 0)
                fprintf(stderr, "%s: write failed on q_id %d tag %d "
                        "fd %d io opcode %d len %d off %lld flags %d "
                        ", errno %s\n",
                        __func__, q_id, tag,
                        test_data.backing_file_fd,
                        iod->op, iod->len, iod->off, iod->flags,
                        strerror(errno));
            
            DEBUG_OUTPUT(fprintf(stdout, 
                    "%s: complete WRITE req, q_id %d tag %d\n",
                    __func__, q_id, tag)); 
            
            ubdlib_complete_io_request(srv, q_id, tag, ret);
        }
        break;
    default:
        fprintf(stdout, "%s: op %d not supported, q_id %d tag %d\n",
                __func__, iod->op, q_id, tag);
        ubdlib_complete_io_request(srv, q_id, tag, 0);
        break;    
    }
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

    snprintf(pthread_name, 32, "ubdsrv%d_queue%d_thread",
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
		
        reapped = ubdlib_reap_io_events(srv, q_id,
                test_hande_io, NULL, NULL);
	    
        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d reapped %d\n",
				__func__, q_id, reapped));
        
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

    snprintf(pthread_name, 32, "ubdsrv%d_thread", dev_id);

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

        pthread_create(&queue_thread_data_arr[i].tid, NULL, 
			ubdsrv_queue_loop, &queue_thread_data_arr[i]);
    }

	fprintf(stdout, "%s: all ubdsrv_queue_loop running\n", __func__);

    ubdsrv_started = 1;

	for(i = 0; i < nr_queues; i++) {
		pthread_join(queue_thread_data_arr[i].tid, NULL);
		fprintf(stdout, "%s: thread of q_id %d joined\n", 
				__func__, i);
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