#ifndef LIBUBD_INC_H
#define LIBUBD_INC_H

/* from fio */

#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif

#ifdef DEBUG
#define DEBUG_OUTPUT(s) s
#else
#define DEBUG_OUTPUT(s)
#endif

#define round_up(val, rnd) \
	(((val) + (rnd - 1)) & ~(rnd - 1))

#define __READ_ONCE(x)  (*(const volatile typeof(x) *)&(x))
#define __WRITE_ONCE(x, val)                                            \
do {                                                                    \
        *(volatile typeof(x) *)&(x) = (val);                            \
} while (0)

/************ arch **************/
#ifdef __cplusplus
#define atomic_add(p, v)						\
	std::atomic_fetch_add(p, (v))
#define atomic_sub(p, v)						\
	std::atomic_fetch_sub(p, (v))
#define atomic_load_relaxed(p)					\
	std::atomic_load_explicit(p,				\
			     std::memory_order_relaxed)
#define atomic_load_acquire(p)					\
	std::atomic_load_explicit(p,				\
			     std::memory_order_acquire)
#define atomic_store_release(p, v)				\
	std::atomic_store_explicit(p, (v),			\
			     std::memory_order_release)
#else
#define atomic_add(p, v)					\
	atomic_fetch_add((_Atomic typeof(*(p)) *)(p), v)
#define atomic_sub(p, v)					\
	atomic_fetch_sub((_Atomic typeof(*(p)) *)(p), v)
#define atomic_load_relaxed(p)					\
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p),	\
			     memory_order_relaxed)
#define atomic_load_acquire(p)					\
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p),	\
			     memory_order_acquire)
#define atomic_store_release(p, v)				\
	atomic_store_explicit((_Atomic typeof(*(p)) *)(p), (v),	\
			      memory_order_release)
#endif

/* just for x86_64 */
#if defined(__i386__)
#define read_barrier()            __asm__ __volatile__("": : :"memory")
#elif defined(__x86_64__)
#define read_barrier()            __asm__ __volatile__("": : :"memory")
#elif defined(__aarch64__)
#define read_barrier()   do { __sync_synchronize(); } while (0)
#elif defined(__powerpc__) || defined(__powerpc64__) || defined(__ppc__)
#define read_barrier()       __asm__ __volatile__ ("sync" : : : "memory")
#elif defined(__s390x__) || defined(__s390__)
#define read_barrier()       asm volatile("bcr 15,0" : : : "memory")
#endif

struct libubd_io_desc {
    unsigned int op;
    unsigned int flags;
    int need_buf_addr;
    unsigned int len;
    unsigned long long off;
};

struct ubdlib_ctrl_dev;

struct ubdlib_ubdsrv;

void ubdlib_set_io_buf_addr(struct ubdlib_ubdsrv *srv,
		int q_id, unsigned tag, char *io_buf_addr);

void ubdlib_complete_io_request(struct ubdlib_ubdsrv *srv,
		int q_id, int tag, int res);

void ubdlib_need_get_data(struct ubdlib_ubdsrv *srv, int q_id,
		int tag);

int ubdlib_ubdsrv_queue_is_done(struct ubdlib_ubdsrv *srv, int q_id);

int ubdlib_reap_io_events(struct ubdlib_ubdsrv *srv, int q_id,
		void (*handle_io_event)(
				struct ubdlib_ubdsrv *srv,
				int q_id,
				int tag,
				const struct libubd_io_desc *iod,
				void *data),
			void *data);

int ubdlib_fetch_io_requests(struct ubdlib_ubdsrv *srv, int q_id);

int ubdlib_commit_fetch_io_requests(struct ubdlib_ubdsrv *srv, int q_id);

int ubdlib_io_uring_enter(struct ubdlib_ubdsrv *srv, int q_id, 
		unsigned int to_submit, unsigned int min_complete,
		unsigned int flags);

int ubdlib_io_uring_enter_timeout(struct ubdlib_ubdsrv *srv, int q_id, 
		unsigned int to_submit, unsigned int min_complete,
		unsigned int flags, unsigned int timeout_usec);

void ubdlib_ubdsrv_deinit(struct ubdlib_ubdsrv *srv);

struct ubdlib_ubdsrv *ubdlib_ubdsrv_init(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_get_ctrl_dev_id(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_get_ctrl_nr_queues(struct ubdlib_ctrl_dev *ctrl_dev);

void ubdlib_ctrl_dev_deinit(struct ubdlib_ctrl_dev *ctrl_dev);

struct ubdlib_ctrl_dev *ubdlib_ctrl_dev_init(
                int dev_id,
                unsigned short nr_queues,
                unsigned short queue_depth,
                unsigned long long dev_size, 
                unsigned int rq_max_buf_size,
                bool zcopy);

int ubdlib_dev_add(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_dev_start(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_dev_get_info(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_dev_stop(struct ubdlib_ctrl_dev *ctrl_dev);

int ubdlib_dev_del(struct ubdlib_ctrl_dev *ctrl_dev);

#endif