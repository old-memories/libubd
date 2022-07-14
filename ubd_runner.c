#include <stdio.h>
#include <string.h>
#include <stdbool.h>
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

#include "ccan/list/list.h"
#include "libubd.h"
#include "ubd_cmd.h"
#include "ubd_aio.h"

#define DEF_NR_Q 1

#define MAX_NR_Q 32

#define DEF_NR_IO_THREADS 64

#define DEF_QD 64

#define MAX_QD 128

#define DEF_RQ_MAX_BUF_SIZE (1024 * 1024)

#define MAX_RQ_MAX_BUF_SIZE (1024 * 1024)

#define UBDSRV_URING_TIMEOUT_US 10

#define UBDSRV_START_TIMEOUT_S 3

struct ubd_runner_data {
    int backing_file_fd;
    struct ubd_aio_io_wq *io_wqs;
    int nr_io_wqs;
    int queue_depth;
    unsigned int rq_max_buf_size;
    void *io_buf;
    pthread_spinlock_t *locks;
    struct list_head *io_processed_lists;
};

struct ubd_runner_io_work_data {
    int q_id;
    int tag;
    int res;
    struct ubdlib_ubdsrv *srv;
    struct libubd_io_desc iod;
    struct list_node entry;
};

struct ubd_runner_srv_queue_thread_data {
    int dev_id;
    int q_id;
    pthread_t tid;
    struct ubdlib_ubdsrv *srv;
};

static char runner_exe[256];

static int ubdsrv_started;

static volatile sig_atomic_t keep_running = 1;

static struct ubd_runner_data runner_data = {
    .backing_file_fd = -1
};

static void *runner_get_io_buf(int q_id, int tag)
{
    int nr_queues = runner_data.nr_io_wqs;
    int queue_depth = runner_data.queue_depth;
    int rq_max_buf_size = runner_data.rq_max_buf_size;

    unsigned int idx = (q_id * nr_queues + tag) * rq_max_buf_size;

    assert(queue_depth > tag);

    return runner_data.io_buf + idx;
}

static void runner_complete_io_fn(void *data, int rc)
{

}

static int runner_handle_io_fn(void *data)
{
    struct ubd_runner_io_work_data *io_work_data = data;
    struct libubd_io_desc *iod = &io_work_data->iod;
    struct ubdlib_ubdsrv * srv = io_work_data->srv;
    int q_id = io_work_data->q_id;
    int tag = io_work_data->tag;
    int ret = 0;

    DEBUG_OUTPUT(fprintf(stdout, 
            "%s: handle req, type %s q_id %d tag %d\n",
            __func__,
            iod->op == UBD_IO_OP_READ ? "READ" : "WRITE",
            q_id, tag));

    switch(iod->op) {
    case UBD_IO_OP_WRITE:

        ret = pwrite(runner_data.backing_file_fd,
                runner_get_io_buf(q_id, tag), iod->len, iod->off);
        if(ret < 0)
            fprintf(stderr, "%s: write failed on q_id %d tag %d, errno %s\n",
                    __func__, q_id, tag, strerror(errno));

        break;
    case UBD_IO_OP_READ:

        ret = pread(runner_data.backing_file_fd,
                runner_get_io_buf(q_id, tag), iod->len, iod->off);
        if(ret < 0)
            fprintf(stderr, "%s: read failed on q_id %d tag %d, errno %s\n",
                    __func__, q_id, tag, strerror(errno));

        ubdlib_set_io_buf_addr(srv, q_id, tag, runner_get_io_buf(q_id, tag));

        break;       
    default:
        fprintf(stdout, "%s: op %d not supported, q_id %d tag %d\n",
                __func__, iod->op, q_id, tag);
        break;    
    }

    DEBUG_OUTPUT(fprintf(stdout, 
            "%s: complete req, type %s q_id %d tag %d\n",
            __func__,
            iod->op == UBD_IO_OP_READ ? "READ" : "WRITE",
            q_id, tag));

    io_work_data->res = ret;

    pthread_spin_lock(&runner_data.locks[q_id]);
    list_add_tail(&runner_data.io_processed_lists[q_id], &io_work_data->entry);
    pthread_spin_unlock(&runner_data.locks[q_id]);

    assert(!ubdlib_issue_eventfd_io(srv, q_id));
    
    return 0;
}

static void runner_handle_eventfd_io(struct ubdlib_ubdsrv *srv, 
        int q_id, void *data)
{
	struct ubd_runner_io_work_data *io_worker_data, *io_worker_data_next;

	DEBUG_OUTPUT(fprintf(stdout, "%s: start handle io_processed_lists for q_id %d\n",
            __func__, q_id));
    
    pthread_spin_lock(&runner_data.locks[q_id]);
    list_for_each_safe(&runner_data.io_processed_lists[q_id],
			io_worker_data, io_worker_data_next, entry) {		
		
        ubdlib_complete_io_request(srv, q_id, io_worker_data->tag, io_worker_data->res);

		list_del_init(&io_worker_data->entry);

        free(io_worker_data);
	}
    pthread_spin_unlock(&runner_data.locks[q_id]);

    DEBUG_OUTPUT(fprintf(stdout, "%s: finish handle io_processed_lists for q_id %d\n",
            __func__, q_id));
}

static void runner_submit_io(struct ubdlib_ubdsrv *srv,
        int q_id,
        int tag,
        const struct libubd_io_desc *iod,
        void *data)
{
    struct ubd_aio_io_wq *io_wq = data;
    struct ubd_runner_io_work_data *io_work_data;


    DEBUG_OUTPUT(fprintf(stdout, 
            "%s: io opcode %d len %d off %lld "
            "flags %d need_buf_addr %d\n", 
            __func__, iod->op, iod->len, 
            iod->off, iod->flags, 
            iod->need_buf_addr));

    switch(iod->op) {
    case UBD_IO_OP_WRITE:
        if(iod->need_buf_addr) {
            ubdlib_set_io_buf_addr(srv, q_id, tag, runner_get_io_buf(q_id, tag));

            ubdlib_need_get_data(srv, q_id, tag);
            
            DEBUG_OUTPUT(fprintf(stdout, "%s: set buf for WRITE req, "
                    "q_id %d tag %d\n", __func__, q_id, tag));
            break;
        } else {
            /* 
             * ubd_drv issues the WRITE req again and data buf is fulfilled 
             * so fallthrough to next case to queue an io work
             */
        }
    case UBD_IO_OP_READ:
        
        io_work_data = calloc(1, sizeof(*io_work_data));

        assert(io_work_data);

        /* must save iod because io is handled async */
        memcpy(&io_work_data->iod, iod, sizeof(*iod));

        io_work_data->q_id = q_id;
        io_work_data->srv = srv;
        io_work_data->tag = tag;
        io_work_data->res = 0;
        list_node_init(&io_work_data->entry);

        ubd_aio_queue_io(io_wq, io_work_data,
                runner_handle_io_fn, runner_complete_io_fn);
            
        DEBUG_OUTPUT(fprintf(stdout, "%s: io queued, q_id %d tag %d\n",
                __func__, q_id, tag));

        break;
    default:
        fprintf(stdout, "%s: op %d not supported, q_id %d tag %d\n",
                __func__, iod->op, q_id, tag);

        ubdlib_complete_io_request(srv, q_id, tag, 0);
        
        break;    
    }
}

void *ubdsrv_queue_loop(void *data)
{
    struct ubd_runner_srv_queue_thread_data *queue_thread_data = data;
    struct ubdlib_ubdsrv *srv = queue_thread_data->srv;
    int dev_id = queue_thread_data->dev_id;
    int q_id = queue_thread_data->q_id;
    int to_submit, submitted, reapped;
    char pthread_name[32];

    snprintf(pthread_name, 32, "ubd%d_q%d_thread",
            dev_id, q_id);

    pthread_setname_np(pthread_self(), pthread_name);

    fprintf(stdout, "start ubdsrv queue %d thread %ld %s\n",
            q_id, syscall(SYS_gettid), pthread_name);
	
    to_submit = ubdlib_fetch_io_requests(srv, q_id);

    DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d to_submit %d\n",
			__func__, q_id, to_submit));

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
                runner_submit_io, runner_handle_eventfd_io, &runner_data.io_wqs[q_id]);

        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d reapped %d\n",
			    __func__, q_id, reapped));

        to_submit = ubdlib_commit_fetch_io_requests(srv, q_id);
	} while (1);
	
	fprintf(stdout, "%s: queue %d exited.\n", __func__, q_id);

	return NULL;
}

void *ubdsrv_loop(void *data)
{
    struct ubdlib_ctrl_dev *ctrl_dev = data;
    struct ubdlib_ubdsrv *srv = NULL;
    int nr_queues = ubdlib_get_ctrl_nr_queues(ctrl_dev);
    struct ubd_runner_srv_queue_thread_data *queue_thread_data_arr;
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
 
    assert(srv);
    
    for (i = 0; i < nr_queues; i++) {
        queue_thread_data_arr[i].dev_id = dev_id;
        queue_thread_data_arr[i].q_id = i;
        queue_thread_data_arr[i].srv = srv;

        pthread_create(&queue_thread_data_arr[i].tid, NULL, 
			ubdsrv_queue_loop, &queue_thread_data_arr[i]);
    }

	fprintf(stdout, "%s: all ubdsrv_queue_loop running\n", __func__);

    ubdsrv_started = 1;

	/*
 	 * Now STOP DEV ctrl command has been sent to /dev/ubd-control
 	 * (1)wait until all pending fetch commands are canceled
	 * (2)wait until all per queue threads have been exited 
	 */
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

static void ubd_runner_sig_handler(int sig)
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

static const struct option longopts[] = {
    { "dev_id",		1,	NULL, 'n' },
    { "nr_queues",             1,      NULL, 'q' },
    { "queue_depth",              1,      NULL, 'd' },
    { "nr_io_threads",              1,      NULL, 't' },
    { "rq_max_buf_size",		1,	NULL, 's' },
    { "backing_file",		1,	NULL, 'f' },
    { "help",		0,	NULL, 'h' },
    { NULL }
};

static void runner_usage(char *exe)
{
    fprintf(stdout, "%s: -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH "
            "-t NR_IO_THREADS -s RQ_MAX_BUF_SIZE -f BACKING_FILE\n,",
            exe);
}

int main(int argc, char **argv)
{    
    struct ubdlib_ctrl_dev *ctrl_dev;
    int cnt = 0;
    pthread_t ubdsrv_tid;
    int dev_id = -1;
	unsigned short nr_queues = DEF_NR_Q;
	unsigned short queue_depth = DEF_QD;
    int nr_io_threads = DEF_NR_IO_THREADS;
    unsigned int rq_max_buf_size = DEF_RQ_MAX_BUF_SIZE;
    char *backing_file = NULL;
    unsigned long long dev_size = 0;
	int opt;
    int i;

    strncpy(runner_exe, argv[0], 256);
    
    if(argc < 2) {
        fprintf(stderr, "%s: must provide args\n", argv[0]);
        exit(1);
    }

	while ((opt = getopt_long(argc, argv, "n:q:d:t:s:f:h",
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
		case 't':
			nr_io_threads = strtol(optarg, NULL, 10);
			break;
		case 's':
			rq_max_buf_size = strtol(optarg, NULL, 10);
			break;
		case 'f':
			backing_file = strdup(optarg);
			break;
        case 'h':
        default:
            runner_usage(runner_exe);
            exit(0);
		}
	}

    if(nr_queues > MAX_NR_Q)
        nr_queues = MAX_NR_Q;
    
    if(queue_depth > MAX_QD)
        queue_depth = MAX_QD;
    
    if(rq_max_buf_size > MAX_RQ_MAX_BUF_SIZE)
        rq_max_buf_size = MAX_RQ_MAX_BUF_SIZE;

    if((runner_data.backing_file_fd = open_backing_file(
                backing_file, O_RDWR|O_DIRECT, &dev_size)) < 0) {
        fprintf(stderr, "%s: failed to open backing file %s",
                __func__, backing_file);
        exit(1);
    }
    
    runner_data.locks = calloc(nr_queues, sizeof(*runner_data.locks));
    
    runner_data.io_processed_lists = calloc(nr_queues, sizeof(*runner_data.io_processed_lists));

    assert(runner_data.locks);
    assert(runner_data.io_processed_lists);

    for(i = 0; i < nr_queues; i++) {
        pthread_spin_init(&runner_data.locks[i], PTHREAD_PROCESS_PRIVATE);
        list_head_init(&runner_data.io_processed_lists[i]);
    }

    assert(!posix_memalign(&runner_data.io_buf, getpagesize(),
            nr_queues * queue_depth * rq_max_buf_size));

    runner_data.nr_io_wqs = nr_queues;
    runner_data.queue_depth = queue_depth;
    runner_data.rq_max_buf_size = rq_max_buf_size;

    ctrl_dev = ubdlib_ctrl_dev_init(dev_id, nr_queues, queue_depth,
            dev_size, rq_max_buf_size, false);
    
    assert(ctrl_dev);

    assert(!ubdlib_dev_add(ctrl_dev));

    pthread_create(&ubdsrv_tid, NULL, ubdsrv_loop, ctrl_dev);

    do {
        usleep(100000);
        cnt++;
	} while (!ubdsrv_started && cnt < UBDSRV_START_TIMEOUT_S * 10);

    runner_data.io_wqs = ubd_aio_setup_io_work_queue(nr_queues, nr_io_threads);
    assert(runner_data.io_wqs);

    assert(!ubdlib_dev_start(ctrl_dev));

    fprintf(stdout, "---------------------------\n"
        "ubdsrv is running now.\n"
        "dev_id %d, nr_queues %d, depth %d, nr_io_threads %d "
        "backing_file %s, dev_size %lld, "
        "rq_max_buf_size %d\n"
        "---------------------------\n",
        ubdlib_get_ctrl_dev_id(ctrl_dev),
        nr_queues,
        queue_depth,
        nr_io_threads,
        backing_file,
        dev_size,
        rq_max_buf_size);

    assert(signal(SIGINT, ubd_runner_sig_handler) != SIG_ERR);
    
    while(keep_running)
        usleep(1 * 1000 * 1000);
    
    fprintf(stdout, "---------------------------\n"
            "get CTRL-C signal, noob is exiting now...\n"
            "---------------------------\n");    

    assert(!ubdlib_dev_get_info(ctrl_dev));

    assert(!ubdlib_dev_stop(ctrl_dev));

    pthread_join(ubdsrv_tid, NULL);

    ubd_aio_cleanup_io_work_queue(runner_data.io_wqs, runner_data.nr_io_wqs);

    for(i = 0; i < nr_queues; i++)
        pthread_spin_destroy(&runner_data.locks[i]);
    
    free(runner_data.locks);

    free(runner_data.io_processed_lists);

    free(runner_data.io_buf);

    fprintf(stdout, "%s: ubdsrv exited.\n", __func__);

    assert(!ubdlib_dev_del(ctrl_dev));

    fprintf(stdout, "---------------------------\n"
            "%s: kernel ubd resources have been released.\n"
            "---------------------------\n"
            , __func__);

    ubdlib_ctrl_dev_deinit(ctrl_dev);

    close(runner_data.backing_file_fd);
    
    free(backing_file);

    fprintf(stdout, "%s: %s: exited.\n", argv[0], __func__);


    return 0;
}