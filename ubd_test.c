#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/resource.h>

#include "libubd.h"
#include "ubd_cmd.h"

#define NR_Q 1

#define QD 32

#define DEV_SIZE (250ULL * 1024 * 1024 * 1024)

#define TEST_RQ_MAX_BUF_SIZE (1024 * 1024)

#define UBDSRV_START_TIMEOUT_S 3

static volatile sig_atomic_t keep_running = 1;

static int test_add_and_del()
{    
    struct ubdlib_ctrl_dev *ctrl_dev;
    int ret = 0;

    /* 
     * A ctrl_dev includes information of the ubd device
     * (nr_queues, depth, dev_size...)
     * ctrl-cmds(such as UBD_CMD_ADD_DEV) are releated to this ctrl_dev
     */
    ctrl_dev = ubdlib_ctrl_dev_init(-1, NR_Q, QD, DEV_SIZE,
            TEST_RQ_MAX_BUF_SIZE, false);
    if(!ctrl_dev)
        exit(1);
    /* 
     * send UBD_CMD_ADD_DEV control command to ubd_drv to setup
     * kernel resources such asio_desc pages, cdev(/dev/ubdcN) 
     * and blk-mq bdev(/dev/ubdbN)
     */
    ret = ubdlib_dev_add(ctrl_dev);
    if(ret)
        exit(1);

    /* 
     * send UBD_CMD_DEL_DEV command to /dev/ubd-control. After ubd_drv gets
     * this command, all kernel resources(bdev and cdev) will be released.
     */
    ret = ubdlib_dev_del(ctrl_dev);
    if(ret)
        exit(1);
        
    ubdlib_ctrl_dev_deinit(ctrl_dev);
    return 0;
}

int main(int argc, char **argv)
{    
    int ret = 0;
    
    if(argc > 1) {
        fprintf(stderr, "%s: do not accept args\n", argv[0]);
        exit(1);
    }

    fprintf(stdout, "start test...\n");
    
    ret = test_add_and_del();
    if(ret)
        fprintf(stdout, "test_add_and_del failed.\n");

    return 0;
}