#ifndef LIBUBD_URING_INC_H
#define LIBUBD_URING_INC_H

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#define timeval linux_timeval
#include <linux/time.h>
#undef timeval

#include "io_uring.h"

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;
};

struct ubdsrv_uring {
	unsigned sq_ring_mask, cq_ring_mask;
	int ring_fd, ring_depth;
	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct io_cq_ring cq_ring;
};

static inline struct io_uring_sqe *io_uring_get_sqe(struct ubdsrv_uring *r,
		int idx, int is_sqe128)
{
	if (is_sqe128)
		return  &r->sqes[idx << 1];
	return  &r->sqes[idx];
}

/********* part of following code is stolen from t/io_uring.c *****/
static inline int io_uring_enter_timeout(struct ubdsrv_uring *r, unsigned int to_submit,
        unsigned int min_complete, unsigned int flags, unsigned long timeout_usec)
{
    struct __kernel_timespec ts = {
        .tv_nsec = (timeout_usec % 1000000) * 1000,
        .tv_sec = timeout_usec / 1000000
    };
  
    struct io_uring_getevents_arg arg = {
        .ts = (unsigned long) &ts
    };
  
    return syscall(__NR_io_uring_enter, r->ring_fd, to_submit,
            min_complete, flags, &arg, sizeof(arg));
}


/********* part of following code is stolen from t/io_uring.c *****/
static inline int io_uring_enter(struct ubdsrv_uring *r, unsigned int to_submit,
			  unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_io_uring_enter, r->ring_fd, to_submit,
			min_complete, flags, NULL, 0);
}

static inline int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p->flags |= IORING_SETUP_CQSIZE;
	p->cq_entries = entries;

	return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_register_buffers(struct ubdsrv_uring *r,
		struct iovec *iovecs, int nr_vecs)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_REGISTER_BUFFERS, iovecs, nr_vecs);
}

static inline int io_uring_unregister_buffers(struct ubdsrv_uring *r)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_UNREGISTER_BUFFERS, NULL, 0);
}

static inline int io_uring_register_files(struct ubdsrv_uring *r,
		int *fds, int nr_fds)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_REGISTER_FILES, fds, nr_fds);
}

static inline int io_uring_unregister_files(struct ubdsrv_uring *r)
{
	return syscall(__NR_io_uring_register, r->ring_fd,
			IORING_UNREGISTER_FILES, NULL, 0);
}

#endif