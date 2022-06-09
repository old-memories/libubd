#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "ubd_aio.h"

static void _cleanup_io_work(void *arg)
{
	free(arg);
}

static void _cleanup_mutex_lock(void *arg)
{
	pthread_mutex_unlock(arg);
}

int ubd_aio_queue_io(struct ubd_aio_io_wq *io_wq, 
        void *data,
        ubd_aio_io_work_fn_t work_fn,
		ubd_aio_io_done_fn_t done_fn)
{
	struct ubd_aio_io_work *work;

	work = calloc(1, sizeof(*work));

    assert(work);

	work->work_fn = work_fn;
	work->done_fn = done_fn;
	work->data = data;
	list_node_init(&work->entry);

	/* cleanup push/pop not _really_ required here atm */
	pthread_cleanup_push(_cleanup_mutex_lock, &io_wq->io_lock);
	pthread_mutex_lock(&io_wq->io_lock);

	list_add_tail(&io_wq->io_queue, &work->entry);
	pthread_cond_signal(&io_wq->io_cond); // TODO: conditional

	pthread_mutex_unlock(&io_wq->io_lock);
	pthread_cleanup_pop(0);

	return 0;
}

static void *io_wq_thread_loop(void *data)
{
	
    struct ubd_aio_io_wq *io_wq = data;
    struct ubd_aio_io_work *work;
	int ret;
    char *pthread_name;

    asprintf(&pthread_name, "queue_%d_io_wq_thread", io_wq->q_id);

    pthread_setname_np(pthread_self(), pthread_name);

    fprintf(stdout, "start ubd_aio_io_wq thread %ld %s\n",
            syscall(SYS_gettid), pthread_name);

    free(pthread_name);

	while (1) {

		pthread_cleanup_push(_cleanup_mutex_lock, &io_wq->io_lock);
		pthread_mutex_lock(&io_wq->io_lock);

		while (list_empty(&io_wq->io_queue)) {
			pthread_cond_wait(&io_wq->io_cond,
					  &io_wq->io_lock);
		}

		work = list_first_entry(&io_wq->io_queue, struct ubd_aio_io_work,
					entry);
		list_del(&work->entry);

		pthread_mutex_unlock(&io_wq->io_lock);
		pthread_cleanup_pop(0);

		/* kick start I/O request */
		data = work->data;
		pthread_cleanup_push(_cleanup_io_work, work);

		ret = work->work_fn(data);
		work->done_fn(data, ret);
        
        /* call _cleanup_io_work now */
		pthread_cleanup_pop(1); 
	}
    return NULL;
}

static void cancel_io_work_queue_threads(struct ubd_aio_io_wq *io_wq)
{
    int ret, i;
    void *join_retval;
    pthread_t tid;
    
    if (!io_wq->io_wq_threads) {
		return;
	}

	for (i = 0; i < io_wq->nr_io_wq_threads; i++) {
		tid = io_wq->io_wq_threads[i];
        if (!tid)
            continue;

        ret = pthread_cancel(tid);
        if (ret) {
            fprintf(stderr, "%s: pthread_cancel failed "
            "on tid %ld with value %d\n",
                    __func__, tid, ret);
            assert(0);
        }

        ret = pthread_join(tid, &join_retval);
        if (ret) {
            fprintf(stderr, "%s: pthread_join failed "
            "on tid %ld with value %d\n",
                    __func__, tid, ret);
            assert(0);
        }

        if (join_retval != PTHREAD_CANCELED) {
            fprintf(stderr, "%s: unexpected join retval: "
                    "%p on tid %ld\n",
                    __func__, join_retval, tid);
            assert(0);
        }
	}

    if(!io_wq->io_wq_threads) {
        free(io_wq->io_wq_threads);
        io_wq->io_wq_threads = NULL;
        io_wq->nr_io_wq_threads = 0;
    }
}

void ubd_aio_cleanup_io_work_queue(struct ubd_aio_io_wq *io_wqs,
        int nr_io_wqs)
{
    int i;

    for(i = 0; i < nr_io_wqs; i++) {
        
        assert(list_empty(&io_wqs[i].io_queue));
        
        cancel_io_work_queue_threads(&io_wqs[i]);
        
        assert(!pthread_mutex_destroy(&io_wqs[i].io_lock));
        
        assert(!pthread_cond_destroy(&io_wqs[i].io_cond));

    }

    free(io_wqs);
}

struct ubd_aio_io_wq *ubd_aio_setup_io_work_queue(int nr_io_wqs, 
        int nr_io_wq_threads)
{
    struct ubd_aio_io_wq *io_wqs;
    int i, j;
    
    io_wqs = calloc(nr_io_wqs, sizeof(*io_wqs));

    assert(io_wqs);

    for(i = 0; i < nr_io_wqs; i++) {
        io_wqs[i].q_id = i;
        
        list_head_init(&io_wqs[i].io_queue);

        assert(!pthread_mutex_init(&io_wqs[i].io_lock, NULL));

        assert(!pthread_cond_init(&io_wqs[i].io_cond, NULL));

        io_wqs[i].io_wq_threads = 
                calloc(nr_io_wq_threads, sizeof(pthread_t));
        
        assert(io_wqs[i].io_wq_threads);

        io_wqs[i].nr_io_wq_threads = nr_io_wq_threads;
        
        for(j = 0; j < nr_io_wq_threads; j++)
            pthread_create(&io_wqs[i].io_wq_threads[j],
                    NULL, io_wq_thread_loop, &io_wqs[i]);
    }

    return io_wqs;
}