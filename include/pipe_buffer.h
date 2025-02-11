#pragma once
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>

void alloc_pipes(int *pipefd, int flags)
{
    int ret = pipe2(pipefd, flags);
    if (ret < 0) {
        perror("pipe2");
        exit(-1);
    }
}

void write_pipe(int fd, char *buf, size_t sz)
{
    int ret = write(fd, buf, sz);
    if (ret < 0) {
        perror("write(pipes)");
        exit(-1);
    }
}

void resize_pipe(int fd, size_t nr_slots)
{
    int ret = fcntl(fd, F_SETPIPE_SZ, nr_slots << 12);
    if (ret < 0) {
        perror("fcntl(fd, F_SETPIPE_SZ, nr_slots << 12)");
        exit(-1);
    }
}

int write_pipe_no_err(int fd, char *buf, size_t sz)
{
    int ret = write(fd, buf, sz);
    return ret;
}

void read_pipe(int fd, char *buf, size_t sz)
{
    int ret = read(fd, buf, sz);
    if (ret < 0) {
        perror("read(pipes)");
        exit(-1);
    }
}

int read_pipe_no_err(int fd, char *buf, size_t sz)
{
    int ret = read(fd, buf, sz);
    return ret;
}