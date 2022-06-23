/* This is header of a very simple aio framework */

#ifndef UBD_AIO_INC_H
#define UBD_AIO_INC_H

#include <pthread.h>

#include "ccan/list/list.h"

typedef int(*ubd_aio_io_work_fn_t)(void *data);
typedef void(*ubd_aio_io_done_fn_t)(void *data, int rc);

struct ubd_aio_io_work {
    
    ubd_aio_io_work_fn_t work_fn;
	ubd_aio_io_done_fn_t done_fn;
    void *data;
    struct list_node entry;
};

struct ubd_aio_io_wq {
    int q_id;
    int nr_io_wq_threads;
    pthread_t *io_wq_threads;
    pthread_cond_t io_cond;
    pthread_mutex_t io_lock;
    struct list_head io_queue;
};

/* queue an io into work queue */
int ubd_aio_queue_io(struct ubd_aio_io_wq *io_wq, 
        void *data,
        ubd_aio_io_work_fn_t work_fn,
		ubd_aio_io_done_fn_t done_fn);

/* stop and exit all io work threads */
void ubd_aio_cleanup_io_work_queue(struct ubd_aio_io_wq *io_wqs,
        int nr_io_wqs);

struct ubd_aio_io_wq *ubd_aio_setup_io_work_queue(int nr_io_wqs, 
        int nr_io_wq_threads);

#endif