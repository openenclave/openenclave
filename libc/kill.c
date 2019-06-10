// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <sys/types.h>

/* Panic since there is no support for POSIX signals yet. */
int kill(pid_t pid, int sig)
{
    assert("kill(): panic" == NULL);
    return -1;
}
