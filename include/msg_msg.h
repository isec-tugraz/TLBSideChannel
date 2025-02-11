#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>

int make_queue(key_t key, int msgflg)
{
    int result;
    if ((result = msgget(key, msgflg)) == -1) {
        perror("msgget");
        exit(-1);
    }
    return result;
}

int cleanup_queue_no_err(key_t key)
{
    return msgctl(key, IPC_RMID, 0);
}

int cleanup_queue(key_t key)
{
    int result;
    if ((result = msgctl(key, IPC_RMID, 0)) == -1) {
        perror("msgctl");
        exit(-1);
    }
    return result;
}

typedef struct {
  long mtype;
  char mtext[1];
} msg;

void send_msg(int msqid, void *msgp, size_t msgsz, int msgflg)
{
    if (msgsnd(msqid, msgp, msgsz, msgflg) == -1) {
        perror("msgsnd");
        exit(-1);
    }
    return;
}

void send_msg_no_err(int msqid, void *msgp, size_t msgsz, int msgflg)
{
    msgsnd(msqid, msgp, msgsz, msgflg);
}

ssize_t get_msg(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    ssize_t ret;
    ret = msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
    if (ret < 0) {
        perror("msgrcv");
        exit(-1);
    }
    return ret;
}

ssize_t get_msg_no_err(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
}