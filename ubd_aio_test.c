#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "ubd_aio.h"

#define NR_IO_WQS 4

#define NR_IO_WQ_THREADS 4

#define NR_IO_WORKS 1 << 5

int work_id[NR_IO_WORKS];

int work_done[NR_IO_WORKS];

int test_work_fn(void *data)
{
    int id = *(int *)data;

    fprintf(stdout, "work on id %d tid %ld\n",
            id, syscall(SYS_gettid));
    
    return 1;
}

void test_done_fn(void *data, int ret)
{
    int id = *(int *)data;
    work_done[id] = ret;
}

int main() {
    struct ubd_aio_io_wq *io_wqs;
    int i;

    io_wqs = ubd_aio_setup_io_work_queue(NR_IO_WQS, NR_IO_WQ_THREADS);

    usleep(1000 * 100);

    assert(io_wqs);

    for(i = 0; i < NR_IO_WORKS; i++) {
        work_id[i] = i;
        ubd_aio_queue_io(&io_wqs[i % NR_IO_WQ_THREADS],
                &work_id[i], test_work_fn, test_done_fn);
    }

    usleep(1000 * 50 * NR_IO_WORKS);

    ubd_aio_cleanup_io_work_queue(io_wqs, NR_IO_WQS);

    for(i = 0; i < NR_IO_WORKS; i++) {
        if(!work_done[i])
            fprintf(stdout, "work %d not done!\n", i);
    }

    return 0;
}