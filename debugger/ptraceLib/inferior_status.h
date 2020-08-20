// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _INFERIOR_STATUS_H_
#define _INFERIOR_STATUS_H_

#include <pthread.h>
#include <stdint.h>

typedef enum _sgx_inferior_flags
{
    SGX_INFERIOR_SINGLE_STEP = 0X1
} sgx_inferior_flags_t;

int sgx_track_inferior(pid_t pid);

int sgx_untrack_inferior(pid_t pid);

int sgx_get_inferior_flags(pid_t pid, int64_t* flags);

int sgx_set_inferior_flags(pid_t pid, int64_t flags);

#endif
