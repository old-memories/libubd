# Userspace block driver(ubd) Library

## Introduction

- libubd_library.so: the shared library

- ubd_aio_test_binary: test ubd aio framework

- ubd_noob_binary: a very simple ubd target. 
    It handles IOs one by one per ubd queue.
    and only supports simple IO handling logic.
    For READ requests, it behaves like /dev/zero;
    For WRITE requests, it behaves like /dev/null.

- ubd_test_binary: more complicated than ubd_noob_binary.
    It still handles IOs one by one per ubd queue.
    It has a backing file(O_DIRECT) and data is READ/WRITTEN from/into this file.
    This target allocates internal data buffer itself.

- ubd_test_io_uring_binary: It is based on ubd_test_binary, but replaces pread/pwrite by liburing APIs.
    Therefore, with iodepth > 1, liburing can batch IO requests and IOPS is higher.

- ubd_runner_binary: a much more complicated ubd target.
    It handles IOs in per ubd queue's work threads
    asynchronously.

## Quick start

### environment:
- Linux kernel: https://github.com/old-memories/linux/commits/v5.17-ubd-dev-mq-ubuf
- cmake
- liburing


### how to build libubd and examples:
- cmake .

- sudo ./ubd_noob_binary

- sudo ./ubd_test_binary -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH -f BACKING_FILE

- sudo ./ubd_runner_binary -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH -t NR_IO_THREADS -s RQ_MAX_BUF_SIZE -f BACKING_FILE

- explanation on args of ubd_test_binary and ubd_runner_binary
    - DEV_ID: a number X identifies the ubd device: /dev/ubdbX and /dev/udbdcX

    - NR_HW_QUEUES: number of queues in ubd, which is equal to nr_hw_queues in blk_mq_tag_set

    - QUEUE_DEPTH: number of IOs per queue in ubd, which is equal to queue_depth in blk_mq_tag_set

    - NR_IO_THREADS: number of io workers(threads) per queue in ubd

    - RQ_MAX_BUF_SIZE: the max size of one IO request's buffer, which is also set by blk_queue_max_hw_sectors() in blk-mq

    - BACKING_FILE: absolute path of the file(opened as O_DIRECT) to serve as storage backend of ubd_runner

- NOTE THAT user should press CTRL-C to gracefully exit ubd_noob_binary or ubd_runner_binary.

### how to test ubd_noob and ubd_runner

- After running the executable(root privilege), you should find /dev/ubdbX and /dev/ubdcX. X is the DEV_ID you assigned before, otherwise ubd will automatically assign one DEV_ID for you. Note that if you open one more executable then, you should find more devices such as /dev/ubdb(X+1) and /dev/ubdc(X+1).

- You can write or read to /dev/ubdbX to issue IO requests to ubd_noob and ubd_runner.
For example: 
    - dd if=/dev/zero of=/dev/ubdb0 count=1 bs=4096
    - dd if=/dev/ubdb0 of=/dev/null count=1 bs=4096
    - test with fio and set filename=/dev/ubdb0 in config file
