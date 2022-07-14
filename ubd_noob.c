#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/types.h>

#include "libubd.h"
#include "ubd_cmd.h"

#define NR_Q 1

#define QD 1

#define DEV_SIZE (250ULL * 1024 * 1024 * 1024)

#define NOOB_RQ_MAX_BUF_SIZE (1024 * 1024)

#define UBDSRV_START_TIMEOUT_S 3

static int ubdsrv_started;

static char noob_write_buf[NOOB_RQ_MAX_BUF_SIZE];

static char noob_read_buf[NOOB_RQ_MAX_BUF_SIZE];

static volatile sig_atomic_t keep_running = 1;

struct ubd_noob_srv_queue_thread_data {
    struct ubdlib_ubdsrv *srv;
    int q_id;
    int dev_id;
};

static void noob_hande_io(struct ubdlib_ubdsrv *srv,
        int q_id,
        int tag,
        const struct libubd_io_desc *iod,
        void *data)
{
    assert(data == NULL);

    DEBUG_OUTPUT(fprintf(stdout, "%s: io opcode %d len %d off %lld "
            "flags %d need_buf_addr %d\n", __func__, 
            iod->op, iod->len, iod->off, iod->flags, 
            iod->need_buf_addr));

    switch(iod->op) {
    case UBD_IO_OP_READ:
        assert(iod->need_buf_addr == 1);
        assert(iod->len <= NOOB_RQ_MAX_BUF_SIZE);

        /* always read all zeros from noob */
        ubdlib_set_io_buf_addr(srv, q_id, tag, noob_read_buf);
        
        /* noob does not handle any actual io */
        DEBUG_OUTPUT(fprintf(stdout, 
                "%s: complete READ req, q_id %d tag %d\n",
                __func__, q_id, tag));

        ubdlib_complete_io_request(srv, q_id, tag, 0);
        break;
    case UBD_IO_OP_WRITE:
        assert(iod->len <= NOOB_RQ_MAX_BUF_SIZE);

        /* ubd_drv issues a WRITE req, so ubdsrv provides buf addr now */
        if(iod->need_buf_addr) {
            ubdlib_set_io_buf_addr(srv, q_id, tag, noob_write_buf);
            ubdlib_need_get_data(srv, q_id, tag);
            /* will return to ubd_drv to copy data from biovec to user buf */
            DEBUG_OUTPUT(fprintf(stdout, 
                    "%s: set buf for WRITE req, q_id %d tag %d\n",
                    __func__, q_id, tag));
        } else {
            /* noob does not handle any actual io */
            ubdlib_complete_io_request(srv, q_id, tag, 0);
        
            DEBUG_OUTPUT(fprintf(stdout, 
                    "%s: complete WRITE req, q_id %d tag %d\n",
                    __func__, q_id, tag));
        }
        break;
    default:
        fprintf(stdout, "%s: op %d not supported, q_id %d tag %d\n",
                __func__, iod->op, q_id, tag);
        /* noob does not handle any actual io */
        ubdlib_complete_io_request(srv, q_id, tag, 0);
        break;    
    }
}

static void ubd_noob_sig_handler(int sig)
{
	if (sig == SIGINT) {
		fprintf(stdout, "%s: got SIGINT signal\n", __func__);
	}
    keep_running = 0;
}

void *ubdsrv_queue_loop(void *data)
{
    struct ubd_noob_srv_queue_thread_data *queue_thread_data = data;
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

    /* the first round submission to make ubd_drv ready */
    to_submit = ubdlib_fetch_io_requests(srv, q_id);

	do {
        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d to_submit %d\n",
				__func__, q_id, to_submit));
		/* 
         * UBD_IO_RES_ABORT has been sent to ubdsrv and
         * no inflight tgt_io/ubd_cmd exists
         */
        if (ubdlib_ubdsrv_queue_is_done(srv, q_id))
			break;
		
        submitted = ubdlib_io_uring_enter(srv, q_id,
                to_submit, 1, 0);

        DEBUG_OUTPUT(fprintf(stdout, "%s: q_id %d submitted %d\n",
				__func__, q_id, submitted));
		
        reapped = ubdlib_reap_io_events(srv, q_id,
                noob_hande_io, NULL, NULL);
	    
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
    pthread_t tid[NR_Q];
    struct ubd_noob_srv_queue_thread_data queue_thread_data_arr[NR_Q];
    int i;
    int dev_id;
    char pthread_name[32];

    assert(NR_Q == nr_queues);

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
        /* run ubdsrv_queue_loop in each new thread per queue */
        pthread_create(&tid[i], NULL, 
			ubdsrv_queue_loop, &queue_thread_data_arr[i]);
    }

	fprintf(stdout, "%s: all ubdsrv_queue_loop running\n", __func__);

    ubdsrv_started = 1;

	/*
 	 * The ubdsrv is going to exit now:
 	 * (1) wait until all pending fetch commands are canceled
	 * (2) wait until all per queue threads have been exited 
	 */
	for(i = 0; i < nr_queues; i++) {
		pthread_join(tid[i], NULL);
		fprintf(stdout, "%s: thread of q_id %d joined\n", 
				__func__, i);
	}

	fprintf(stdout, "%s: all ubdsrv_queue_loop exited\n", __func__);
	
	ubdlib_ubdsrv_deinit(srv);
    return NULL;
}

int main(int argc, char **argv)
{    
    struct ubdlib_ctrl_dev *ctrl_dev;
    int ret = 0;
    int cnt = 0;
    pthread_t ubdsrv_tid;
    
    if(argc > 1) {
        fprintf(stderr, "%s: do not accept args\n", argv[0]);
        exit(1);
    }
    /* 
     * A ctrl_dev includes information of the ubd device
     * (nr_queues, depth, dev_size...)
     * ctrl-cmds(such as UBD_CMD_ADD_DEV) are releated to this ctrl_dev
     */
    ctrl_dev = ubdlib_ctrl_dev_init(-1, NR_Q, QD, DEV_SIZE,
            NOOB_RQ_MAX_BUF_SIZE, false);
    if(!ctrl_dev)
        exit(1);
    /* 
     * send UBD_CMD_ADD_DEV control command to ubd_drv to setup
     * kernel resources such ubd_io_desc's pages, cdev(/dev/ubdcN) 
     * and blk-mq bdev(/dev/ubdbN)
     */
    ret = ubdlib_dev_add(ctrl_dev);
    if(ret)
        exit(1);

    /* start the ubdsrv loop */
    pthread_create(&ubdsrv_tid, NULL, ubdsrv_loop, ctrl_dev);

    /* 
     * wait for ubdsrv becoming ready: the ubdsrv loop should submit
     * sqes to /dev/ubdcN
     * 
     * When every io request of driver gets its own sqe queued, we think
     * /dev/ubdbN is ready to start
     */
    do {
        usleep(100000);
        cnt++;
	} while (!ubdsrv_started && cnt < UBDSRV_START_TIMEOUT_S * 10);


   /*
    * Now every io request of driver must get its own sqe queued
    * 
    * in current process context, not in pthread created,
    * sent UBD_CMD_START_DEV command to /dev/ubd-control with device id,
    * which will cause ubd driver to expose /dev/ubdbN(can handle requests now)
    * 
    * After this moment, ubdsrv can get io requests from kernel
    */
    ret = ubdlib_dev_start(ctrl_dev);
    if(ret)
        exit(1);

    fprintf(stdout, "---------------------------\n"
            "ubdsrv is running now.\n"
            "dev_id %d, nr_queues %d, depth %d, dev_size %lld, "
            "rq_max_buf_size %d\n"
            "---------------------------\n",
            ubdlib_get_ctrl_dev_id(ctrl_dev),
            NR_Q,
            QD,
            DEV_SIZE,
            NOOB_RQ_MAX_BUF_SIZE);

    if (signal(SIGINT, ubd_noob_sig_handler) == SIG_ERR)
		exit(1);
    
    /* do nothing in demo... */
    while(keep_running)
        usleep(1 * 1000 * 1000);
    
    fprintf(stdout, "---------------------------\n"
            "get CTRL-C signal, noob is exiting now...\n"
            "---------------------------\n");

    /* 
     * send UBD_CMD_GET_DEV_INFO command to /dev/ubd-control with 
     * device id provided in order to update device info and ensure
     * that device to be deleted actually exists.
     */  
    ret = ubdlib_dev_get_info(ctrl_dev);
    if(ret)
        exit(1);
    /* 
     * send UBD_CMD_STOP_DEV command to /dev/ubd-control with device id provided.
     * After ubd_drv gets this command, it freezes(del_gendisk) /dev/ubdbN
     * 
     * (del_gendisk() will block until all inflight blk-mq reqs complete)
     * 
     * ubd_drv commits all cqes with cqe->res set to UBD_IO_RES_ABORT
     * 
     */
    ret = ubdlib_dev_stop(ctrl_dev);
    if(ret)
        exit(1);
    /* 
     * 1) The ubdsrv queue loop figures out that it is done and exit
     * 
     * 2) The ubdsrv loop joins all queue threads, 
     *    closes /dev/ubdcN and exits itself.
     * 
     * 2) Now ubdsrv pthread is exited, join it
     */
    pthread_join(ubdsrv_tid, NULL);

    fprintf(stdout, "%s: ubdsrv exited.\n", __func__);

    /* 
     * send UBD_CMD_DEL_DEV command to /dev/ubd-control. After ubd_drv gets
     * this command, all kernel resources(bdev and cdev) will be released.
     */
    ret = ubdlib_dev_del(ctrl_dev);

    fprintf(stdout, "---------------------------\n"
            "%s: kernel ubd resources have been released.\n"
            "---------------------------\n"
            , __func__);

    ubdlib_ctrl_dev_deinit(ctrl_dev);

    fprintf(stdout, "%s: %s: exited.\n", argv[0], __func__);

    return 0;
}