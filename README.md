# Userspace block driver(ubd) Library

## Introduction

- libubd_library.so: the shared library

- ubd_test_binary: test adding and deleting of ubd ctrl device

- ubd_aio_test_binary: test ubd aio framework

- ubd_noob_binary: a very simple ubd target. 
    It handles IOs one by one per ubd queue.
    and only supports simple IO handling logic.
    For READ requests, it behaves like /dev/zero;
    For WRITE requests, it behaves like /dev/null.

- ubd_runner_binary: a more complicated ubd target.
    It handles IOs in per ubd queue's work threads
    asynchronously.
    It has a backing file(O_DIRECT) and data is READ/WRITTEN from/into this file.
    This target allocates internal data buffer itself.

## Quick start

### environment:
- Linux kernel: https://github.com/old-memories/linux/commits/v5.17-ubd-dev-mq-ubuf
- cmake

### how to build libubd and examples:
- cmake .
- sudo build/ubd_noob_binary
- sudo build/ubd_runner_binary -n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH -t NR_IO_THREADS -s RQ_MAX_BUF_SIZE -f BACKING_FILE
- NOTE THAT user should press CTRL-C to gracefully exit ubd_noob_binary or ubd_runner_binary.
