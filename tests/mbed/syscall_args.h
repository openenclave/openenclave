// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef struct _syscall_args
{
    char* path;
    int flags;
    int mode;
    int fd;
    void* ptr;
    int ret;
    int len;
} syscall_args_t;
