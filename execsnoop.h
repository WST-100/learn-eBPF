#ifndef EXECSNOOP_H_
#define EXECSNOOP_H_

#define TASK_COMM_LEN 16

struct event
{
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};

#endif