// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "pid.h"

int setrlimit(int resource, int* rlim)
{
    return 0;
}

pid_t getpid(void)
{
    return g_pid;
}
